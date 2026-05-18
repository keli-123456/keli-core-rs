use std::sync::Arc;

use serde::{Deserialize, Serialize};
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

const MIN_QUIC_CONNECTION_LIMIT: usize = 128;
const MAX_QUIC_CONNECTION_LIMIT: usize = 8192;
const QUIC_CONNECTIONS_PER_CPU: usize = 128;
const QUIC_RESERVED_FDS: usize = 1024;
const QUIC_FDS_PER_CONNECTION: usize = 4;
const QUIC_MEMORY_MIB_PER_CONNECTION: usize = 8;
const MIN_QUIC_PER_LISTENER_SOFT_LIMIT: usize = 256;
const QUIC_PER_LISTENER_BURST_MULTIPLIER: usize = 2;

pub type QuicConnectionPermit = OwnedSemaphorePermit;

#[derive(Clone, Debug)]
pub struct SharedQuicConnectionLimiter {
    inner: Arc<QuicConnectionLimiter>,
}

#[derive(Debug)]
struct QuicConnectionLimiter {
    slots: Arc<Semaphore>,
    total_limit: usize,
    listener_count: usize,
    cpu_count: usize,
    memory_limit_mib: Option<usize>,
    fd_limit: Option<usize>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuicResourceSnapshot {
    pub total_limit: usize,
    pub active_connections: usize,
    pub available_connections: usize,
    pub listener_count: usize,
    pub per_listener_soft_limit: usize,
    pub cpu_count: usize,
    pub memory_limit_mib: Option<usize>,
    pub fd_limit: Option<usize>,
}

impl SharedQuicConnectionLimiter {
    pub fn for_listener_count(listener_count: usize) -> Self {
        let listener_count = listener_count.max(1);
        let cpu_count = available_parallelism_count();
        let memory_limit_mib = memory_limit_mib();
        let fd_limit = open_file_soft_limit();
        let total_limit = quic_connection_limit_from_env().unwrap_or_else(|| {
            quic_connection_limit_from_resources(cpu_count, memory_limit_mib, fd_limit)
        });
        Self {
            inner: Arc::new(QuicConnectionLimiter {
                slots: Arc::new(Semaphore::new(total_limit)),
                total_limit,
                listener_count,
                cpu_count,
                memory_limit_mib,
                fd_limit,
            }),
        }
    }

    pub fn standalone() -> Self {
        Self::for_listener_count(1)
    }

    pub fn try_acquire(&self) -> Option<QuicConnectionPermit> {
        self.inner.slots.clone().try_acquire_owned().ok()
    }

    pub fn total_limit(&self) -> usize {
        self.inner.total_limit
    }

    pub fn listener_count(&self) -> usize {
        self.inner.listener_count
    }

    pub fn per_listener_soft_limit(&self) -> usize {
        let even_share = self.inner.total_limit / self.inner.listener_count.max(1);
        let soft_limit = even_share
            .saturating_mul(QUIC_PER_LISTENER_BURST_MULTIPLIER)
            .max(MIN_QUIC_PER_LISTENER_SOFT_LIMIT);
        soft_limit.clamp(64, self.inner.total_limit)
    }

    pub fn snapshot(&self) -> QuicResourceSnapshot {
        let available_connections = self.inner.slots.available_permits();
        QuicResourceSnapshot {
            total_limit: self.inner.total_limit,
            active_connections: self.inner.total_limit.saturating_sub(available_connections),
            available_connections,
            listener_count: self.inner.listener_count,
            per_listener_soft_limit: self.per_listener_soft_limit(),
            cpu_count: self.inner.cpu_count,
            memory_limit_mib: self.inner.memory_limit_mib,
            fd_limit: self.inner.fd_limit,
        }
    }
}

fn quic_connection_limit_from_env() -> Option<usize> {
    std::env::var("KELI_CORE_QUIC_MAX_CONNECTIONS")
        .ok()
        .or_else(|| std::env::var("KELI_CORE_HY2_MAX_CONNECTIONS").ok())
        .and_then(|value| value.trim().parse::<usize>().ok())
        .map(|value| value.clamp(64, MAX_QUIC_CONNECTION_LIMIT))
}

fn quic_connection_limit_from_resources(
    cpu_count: usize,
    memory_limit_mib: Option<usize>,
    fd_limit: Option<usize>,
) -> usize {
    let cpu_target = cpu_count
        .max(1)
        .saturating_mul(QUIC_CONNECTIONS_PER_CPU)
        .max(MIN_QUIC_CONNECTION_LIMIT);
    let memory_target = memory_limit_mib
        .map(|mib| mib / QUIC_MEMORY_MIB_PER_CONNECTION)
        .filter(|target| *target > 0)
        .unwrap_or(MAX_QUIC_CONNECTION_LIMIT);
    let fd_target = fd_limit
        .map(|limit| limit.saturating_sub(QUIC_RESERVED_FDS) / QUIC_FDS_PER_CONNECTION)
        .filter(|target| *target > 0)
        .unwrap_or(MAX_QUIC_CONNECTION_LIMIT);
    cpu_target
        .min(memory_target)
        .min(fd_target)
        .min(MAX_QUIC_CONNECTION_LIMIT)
        .clamp(MIN_QUIC_CONNECTION_LIMIT, MAX_QUIC_CONNECTION_LIMIT)
}

pub(crate) fn available_parallelism_count() -> usize {
    std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(4)
        .max(1)
}

pub(crate) fn memory_limit_mib() -> Option<usize> {
    let host_memory = proc_meminfo_total_mib();
    match cgroup_memory_limit_mib() {
        Some(cgroup_limit) => Some(host_memory.map_or(cgroup_limit, |host| host.min(cgroup_limit))),
        None => host_memory,
    }
}

#[cfg(target_os = "linux")]
fn proc_meminfo_total_mib() -> Option<usize> {
    let content = std::fs::read_to_string("/proc/meminfo").ok()?;
    parse_proc_meminfo_total_mib(&content)
}

#[cfg(not(target_os = "linux"))]
fn proc_meminfo_total_mib() -> Option<usize> {
    None
}

#[cfg(target_os = "linux")]
fn cgroup_memory_limit_mib() -> Option<usize> {
    let value = std::fs::read_to_string("/sys/fs/cgroup/memory.max").ok()?;
    parse_cgroup_memory_limit_mib(&value)
}

#[cfg(not(target_os = "linux"))]
fn cgroup_memory_limit_mib() -> Option<usize> {
    None
}

#[cfg(target_os = "linux")]
pub(crate) fn open_file_soft_limit() -> Option<usize> {
    let content = std::fs::read_to_string("/proc/self/limits").ok()?;
    parse_proc_limits_open_files(&content)
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn open_file_soft_limit() -> Option<usize> {
    None
}

#[cfg(any(target_os = "linux", test))]
fn parse_proc_meminfo_total_mib(content: &str) -> Option<usize> {
    content.lines().find_map(|line| {
        let rest = line.strip_prefix("MemTotal:")?;
        let kib = rest.split_whitespace().next()?.parse::<usize>().ok()?;
        Some(kib / 1024)
    })
}

#[cfg(any(target_os = "linux", test))]
fn parse_cgroup_memory_limit_mib(value: &str) -> Option<usize> {
    let trimmed = value.trim();
    if trimmed.eq_ignore_ascii_case("max") {
        return None;
    }
    let bytes = trimmed.parse::<usize>().ok()?;
    Some(bytes / 1024 / 1024)
}

#[cfg(any(target_os = "linux", test))]
fn parse_proc_limits_open_files(content: &str) -> Option<usize> {
    content.lines().find_map(|line| {
        if !line.starts_with("Max open files") {
            return None;
        }
        line.split_whitespace().nth(3)?.parse::<usize>().ok()
    })
}

#[cfg(test)]
mod tests {
    use super::{
        parse_cgroup_memory_limit_mib, parse_proc_limits_open_files, parse_proc_meminfo_total_mib,
        quic_connection_limit_from_resources, SharedQuicConnectionLimiter,
    };

    #[test]
    fn quic_connection_limit_scales_with_machine_resources() {
        assert_eq!(
            quic_connection_limit_from_resources(1, Some(64_000), Some(1_000_000)),
            128
        );
        assert_eq!(
            quic_connection_limit_from_resources(4, Some(64_000), Some(1_000_000)),
            512
        );
        assert_eq!(
            quic_connection_limit_from_resources(16, Some(64_000), Some(1_000_000)),
            2048
        );
        assert_eq!(
            quic_connection_limit_from_resources(128, Some(64_000), Some(1_000_000)),
            8000
        );
    }

    #[test]
    fn quic_connection_limit_respects_memory_and_fd_caps() {
        assert_eq!(
            quic_connection_limit_from_resources(16, Some(2048), Some(1_000_000)),
            256
        );
        assert_eq!(
            quic_connection_limit_from_resources(16, Some(64_000), Some(4096)),
            768
        );
    }

    #[test]
    fn shared_quic_limiter_tracks_active_connections_across_clones() {
        let limiter = SharedQuicConnectionLimiter::for_listener_count(3);
        let clone = limiter.clone();
        let permit = clone.try_acquire().expect("permit");

        let snapshot = limiter.snapshot();
        assert_eq!(snapshot.listener_count, 3);
        assert!(snapshot.per_listener_soft_limit >= snapshot.total_limit / snapshot.listener_count);
        assert!(snapshot.per_listener_soft_limit <= snapshot.total_limit);
        assert_eq!(snapshot.active_connections, 1);
        assert_eq!(
            snapshot.available_connections,
            snapshot.total_limit.saturating_sub(1)
        );

        drop(permit);
        assert_eq!(limiter.snapshot().active_connections, 0);
    }

    #[test]
    fn per_listener_soft_limit_allows_burst_above_even_share() {
        let limiter = SharedQuicConnectionLimiter::for_listener_count(5);
        let snapshot = limiter.snapshot();
        assert!(snapshot.per_listener_soft_limit >= 256.min(snapshot.total_limit));
        assert!(snapshot.per_listener_soft_limit > snapshot.total_limit / snapshot.listener_count);
    }

    #[test]
    fn parses_linux_resource_files() {
        assert_eq!(
            parse_proc_meminfo_total_mib("MemTotal:        4096000 kB\n"),
            Some(4000)
        );
        assert_eq!(parse_cgroup_memory_limit_mib("max\n"), None);
        assert_eq!(parse_cgroup_memory_limit_mib("4294967296\n"), Some(4096));
        assert_eq!(
            parse_proc_limits_open_files(
                "Limit                     Soft Limit           Hard Limit           Units\nMax open files            1048576              1048576              files\n"
            ),
            Some(1_048_576)
        );
    }
}
