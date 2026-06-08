use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock};
#[cfg(any(target_os = "linux", test))]
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::abuse::ClientFailureBackoffSnapshot;
use crate::dns::{dns_metrics_snapshot, DnsMetricsSnapshot};
use crate::quic_resources::QuicResourceSnapshot;

const USER_DELTA_DURATION_BUCKETS_MS: [u64; 10] = [1, 5, 10, 25, 50, 100, 250, 500, 1000, 5000];
#[cfg(target_os = "linux")]
const PROCESS_OPEN_FD_CACHE_TTL: Duration = Duration::from_secs(15);
#[cfg(any(target_os = "linux", test))]
const PROCESS_CPU_CACHE_TTL: Duration = Duration::from_secs(1);

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreMetricsSnapshot {
    pub keli_core_user_delta_apply_total: u64,
    pub keli_core_user_delta_apply_error_total: u64,
    pub keli_core_user_delta_incremental_total: u64,
    pub keli_core_user_delta_full_snapshot_total: u64,
    pub keli_core_user_delta_revision_mismatch_total: u64,
    pub keli_core_user_delta_current_revision_missing_total: u64,
    pub keli_core_user_delta_apply_duration_ms: CoreDurationMetrics,
    pub keli_core_user_delta_active_users: BTreeMap<String, usize>,
    pub keli_core_tls_handshake_failure_total: u64,
    pub keli_core_tls_handshake_backoff_reject_total: u64,
    pub keli_core_tls_handshake_backoff_active_ips: usize,
    pub keli_core_tls_handshake_backoff_blocked_ips: usize,
    pub keli_core_tcp_auth_failure_total: u64,
    pub keli_core_tcp_auth_backoff_reject_total: u64,
    pub keli_core_tcp_auth_backoff_active_ips: usize,
    pub keli_core_tcp_auth_backoff_blocked_ips: usize,
    pub keli_core_hy2_udp_active_sessions: usize,
    pub keli_core_hy2_udp_session_limit: usize,
    #[serde(default)]
    pub keli_core_connection_error_total: BTreeMap<String, u64>,
    #[serde(default)]
    pub keli_core_connection_active_total: usize,
    #[serde(default)]
    pub keli_core_connection_active_blocking: usize,
    #[serde(default)]
    pub keli_core_connection_active_async: usize,
    #[serde(default)]
    pub keli_core_tcp_accept_worker_threads: usize,
    #[serde(default)]
    pub keli_core_tcp_accept_blocking_thread_budget: usize,
    #[serde(default)]
    pub keli_core_udp_relay_active: BTreeMap<String, usize>,
    #[serde(default)]
    pub keli_core_udp_relay_finished_total: BTreeMap<String, u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keli_core_process_open_fds: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keli_core_process_rss_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keli_core_process_peak_rss_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keli_core_process_anonymous_rss_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keli_core_process_file_rss_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keli_core_process_data_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keli_core_process_threads: Option<usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keli_core_process_cpu_percent_x100: Option<u64>,
    #[serde(default)]
    pub keli_core_shared_user_pool_buckets: usize,
    #[serde(default)]
    pub keli_core_shared_user_pool_active: usize,
    #[serde(default)]
    pub keli_core_shared_user_pool_stale: usize,
    #[serde(default)]
    pub keli_core_native_relay_active: BTreeMap<String, usize>,
    #[serde(default)]
    pub keli_core_async_relay_active: BTreeMap<String, usize>,
    #[serde(default)]
    pub keli_core_detached_blocking_relay_active: BTreeMap<String, usize>,
    #[serde(default)]
    pub keli_core_native_relay_workers: usize,
    #[serde(default)]
    pub keli_core_native_relay_idle: usize,
    #[serde(default)]
    pub keli_core_native_relay_pending: usize,
    #[serde(default)]
    pub keli_core_native_relay_label_soft_limit: usize,
    #[serde(default)]
    pub keli_core_native_relay_pending_by_label: BTreeMap<String, usize>,
    #[serde(default)]
    pub keli_core_native_relay_queue_wait_ms_by_label: BTreeMap<String, u64>,
    #[serde(default)]
    pub keli_core_tcp_relay_half_close_timeout_total: u64,
    #[serde(default)]
    pub keli_core_tcp_relay_uplink_only_timeout_total: u64,
    #[serde(default)]
    pub keli_core_tcp_relay_downlink_only_timeout_total: u64,
    pub keli_core_dns: DnsMetricsSnapshot,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keli_core_quic_resource: Option<QuicResourceSnapshot>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreDurationMetrics {
    pub count: u64,
    pub total_ms: u64,
    pub last_ms: u64,
    pub max_ms: u64,
    pub buckets: BTreeMap<String, u64>,
}

#[derive(Debug, Default)]
pub struct CoreMetrics {
    snapshot: CoreMetricsSnapshot,
}

impl CoreMetrics {
    pub fn snapshot(&self) -> CoreMetricsSnapshot {
        self.snapshot.clone()
    }

    pub fn snapshot_with_quic_resource(
        &self,
        quic_resource: Option<QuicResourceSnapshot>,
    ) -> CoreMetricsSnapshot {
        self.snapshot_with_runtime_metrics(quic_resource, None, None)
    }

    pub fn snapshot_with_runtime_metrics(
        &self,
        quic_resource: Option<QuicResourceSnapshot>,
        tls_handshake: Option<ClientFailureBackoffSnapshot>,
        tcp_auth: Option<ClientFailureBackoffSnapshot>,
    ) -> CoreMetricsSnapshot {
        let mut snapshot = self.snapshot();
        snapshot.keli_core_dns = dns_metrics_snapshot();
        snapshot.keli_core_quic_resource = quic_resource;
        if let Some(tls_handshake) = tls_handshake {
            snapshot.keli_core_tls_handshake_failure_total = tls_handshake.failure_total;
            snapshot.keli_core_tls_handshake_backoff_reject_total =
                tls_handshake.backoff_reject_total;
            snapshot.keli_core_tls_handshake_backoff_active_ips = tls_handshake.active_ips;
            snapshot.keli_core_tls_handshake_backoff_blocked_ips = tls_handshake.blocked_ips;
        }
        if let Some(tcp_auth) = tcp_auth {
            snapshot.keli_core_tcp_auth_failure_total = tcp_auth.failure_total;
            snapshot.keli_core_tcp_auth_backoff_reject_total = tcp_auth.backoff_reject_total;
            snapshot.keli_core_tcp_auth_backoff_active_ips = tcp_auth.active_ips;
            snapshot.keli_core_tcp_auth_backoff_blocked_ips = tcp_auth.blocked_ips;
        }
        snapshot.keli_core_hy2_udp_active_sessions = crate::hysteria2::hy2_active_udp_sessions();
        snapshot.keli_core_hy2_udp_session_limit =
            crate::hysteria2::hy2_udp_session_limit_for_metrics();
        snapshot.keli_core_connection_error_total = connection_error_metrics_snapshot();
        let connection_workers = crate::service::connection_worker_metrics_snapshot();
        snapshot.keli_core_connection_active_total = connection_workers.active_total;
        snapshot.keli_core_connection_active_blocking = connection_workers.active_blocking;
        snapshot.keli_core_connection_active_async = connection_workers.active_async;
        let tcp_accept = crate::service::tcp_accept_runtime_metrics_snapshot();
        snapshot.keli_core_tcp_accept_worker_threads = tcp_accept.worker_threads;
        snapshot.keli_core_tcp_accept_blocking_thread_budget = tcp_accept.blocking_thread_budget;
        snapshot.keli_core_udp_relay_active = udp_relay_active_snapshot();
        snapshot.keli_core_udp_relay_finished_total = udp_relay_finished_snapshot();
        snapshot.keli_core_process_open_fds = process_open_fd_count();
        let process = process_resource_snapshot();
        snapshot.keli_core_process_rss_bytes = process.rss_bytes;
        snapshot.keli_core_process_peak_rss_bytes = process.peak_rss_bytes;
        snapshot.keli_core_process_anonymous_rss_bytes = process.anonymous_rss_bytes;
        snapshot.keli_core_process_file_rss_bytes = process.file_rss_bytes;
        snapshot.keli_core_process_data_bytes = process.data_bytes;
        snapshot.keli_core_process_threads = process.threads;
        snapshot.keli_core_process_cpu_percent_x100 = process.cpu_percent_x100;
        let shared_users = crate::user::shared_core_user_pool_snapshot();
        snapshot.keli_core_shared_user_pool_buckets = shared_users.buckets;
        snapshot.keli_core_shared_user_pool_active = shared_users.active;
        snapshot.keli_core_shared_user_pool_stale = shared_users.stale;
        let relay = crate::stream::relay_scheduler_metrics_snapshot();
        snapshot.keli_core_native_relay_active = relay.active_native;
        snapshot.keli_core_async_relay_active = relay.active_async;
        snapshot.keli_core_detached_blocking_relay_active = relay.active_detached_blocking;
        snapshot.keli_core_native_relay_workers = relay.native_worker_count;
        snapshot.keli_core_native_relay_idle = relay.native_idle_count;
        snapshot.keli_core_native_relay_pending = relay.native_pending_count;
        snapshot.keli_core_native_relay_label_soft_limit = relay.native_label_soft_limit;
        snapshot.keli_core_native_relay_pending_by_label = relay.native_pending_by_label;
        snapshot.keli_core_native_relay_queue_wait_ms_by_label =
            relay.native_queue_wait_ms_by_label;
        snapshot.keli_core_tcp_relay_half_close_timeout_total =
            relay.tcp_relay_half_close_timeout_total;
        snapshot.keli_core_tcp_relay_uplink_only_timeout_total =
            relay.tcp_relay_uplink_only_timeout_total;
        snapshot.keli_core_tcp_relay_downlink_only_timeout_total =
            relay.tcp_relay_downlink_only_timeout_total;
        snapshot
    }

    pub fn record_user_delta_success(
        &mut self,
        node_tag: &str,
        full_snapshot: bool,
        duration_ms: u64,
        active_users: usize,
    ) {
        self.record_user_delta_attempt(full_snapshot, duration_ms);
        self.snapshot
            .keli_core_user_delta_active_users
            .insert(node_tag.to_string(), active_users);
    }

    pub fn record_user_delta_error(
        &mut self,
        full_snapshot: bool,
        duration_ms: u64,
        message: &str,
    ) {
        self.record_user_delta_attempt(full_snapshot, duration_ms);
        self.snapshot.keli_core_user_delta_apply_error_total = self
            .snapshot
            .keli_core_user_delta_apply_error_total
            .saturating_add(1);
        if is_revision_mismatch(message) {
            self.snapshot.keli_core_user_delta_revision_mismatch_total = self
                .snapshot
                .keli_core_user_delta_revision_mismatch_total
                .saturating_add(1);
        }
        if is_current_revision_missing(message) {
            self.snapshot
                .keli_core_user_delta_current_revision_missing_total = self
                .snapshot
                .keli_core_user_delta_current_revision_missing_total
                .saturating_add(1);
        }
    }

    fn record_user_delta_attempt(&mut self, full_snapshot: bool, duration_ms: u64) {
        self.snapshot.keli_core_user_delta_apply_total = self
            .snapshot
            .keli_core_user_delta_apply_total
            .saturating_add(1);
        if full_snapshot {
            self.snapshot.keli_core_user_delta_full_snapshot_total = self
                .snapshot
                .keli_core_user_delta_full_snapshot_total
                .saturating_add(1);
        } else {
            self.snapshot.keli_core_user_delta_incremental_total = self
                .snapshot
                .keli_core_user_delta_incremental_total
                .saturating_add(1);
        }
        self.snapshot
            .keli_core_user_delta_apply_duration_ms
            .record(duration_ms);
    }
}

impl CoreDurationMetrics {
    fn record(&mut self, duration_ms: u64) {
        self.count = self.count.saturating_add(1);
        self.total_ms = self.total_ms.saturating_add(duration_ms);
        self.last_ms = duration_ms;
        self.max_ms = self.max_ms.max(duration_ms);
        for bucket in USER_DELTA_DURATION_BUCKETS_MS {
            if duration_ms <= bucket {
                let key = format!("le_{bucket}");
                *self.buckets.entry(key).or_default() += 1;
            }
        }
        *self.buckets.entry("le_inf".to_string()).or_default() += 1;
    }
}

fn is_revision_mismatch(message: &str) -> bool {
    message.contains("revision mismatch")
}

fn is_current_revision_missing(message: &str) -> bool {
    message.contains("current <missing>") || message.contains("full snapshot required")
}

pub fn record_connection_error(protocol: &'static str, scope: &'static str, reason: &'static str) {
    let key = connection_error_key(protocol, scope, reason);
    let mut metrics = connection_error_metrics()
        .lock()
        .expect("connection error metrics poisoned");
    let counter = metrics.entry(key).or_default();
    *counter = counter.saturating_add(1);
}

pub(crate) struct UdpRelayMetricsGuard {
    key: String,
}

impl UdpRelayMetricsGuard {
    pub(crate) fn new(protocol: &str, scope: &str) -> Self {
        let key = udp_relay_key(protocol, scope);
        let mut metrics = udp_relay_active()
            .lock()
            .expect("udp relay active metrics poisoned");
        let counter = metrics.entry(key.clone()).or_default();
        *counter = counter.saturating_add(1);
        Self { key }
    }
}

impl Drop for UdpRelayMetricsGuard {
    fn drop(&mut self) {
        let mut metrics = udp_relay_active()
            .lock()
            .expect("udp relay active metrics poisoned");
        if let Some(counter) = metrics.get_mut(&self.key) {
            *counter = counter.saturating_sub(1);
            if *counter == 0 {
                metrics.remove(&self.key);
            }
        }
    }
}

pub(crate) fn record_udp_relay_finished(protocol: &str, scope: &str, status: &str) {
    let key = format!(
        "{}.{}",
        udp_relay_key(protocol, scope),
        sanitize_connection_error_part(status)
    );
    let mut metrics = udp_relay_finished()
        .lock()
        .expect("udp relay finished metrics poisoned");
    let counter = metrics.entry(key).or_default();
    *counter = counter.saturating_add(1);
}

fn connection_error_metrics_snapshot() -> BTreeMap<String, u64> {
    connection_error_metrics()
        .lock()
        .expect("connection error metrics poisoned")
        .clone()
}

fn connection_error_metrics() -> &'static Mutex<BTreeMap<String, u64>> {
    static METRICS: OnceLock<Mutex<BTreeMap<String, u64>>> = OnceLock::new();
    METRICS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn udp_relay_active_snapshot() -> BTreeMap<String, usize> {
    udp_relay_active()
        .lock()
        .expect("udp relay active metrics poisoned")
        .clone()
}

fn udp_relay_finished_snapshot() -> BTreeMap<String, u64> {
    udp_relay_finished()
        .lock()
        .expect("udp relay finished metrics poisoned")
        .clone()
}

fn udp_relay_active() -> &'static Mutex<BTreeMap<String, usize>> {
    static METRICS: OnceLock<Mutex<BTreeMap<String, usize>>> = OnceLock::new();
    METRICS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn udp_relay_finished() -> &'static Mutex<BTreeMap<String, u64>> {
    static METRICS: OnceLock<Mutex<BTreeMap<String, u64>>> = OnceLock::new();
    METRICS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn udp_relay_key(protocol: &str, scope: &str) -> String {
    format!(
        "{}.{}",
        sanitize_connection_error_part(protocol),
        sanitize_connection_error_part(scope)
    )
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct ProcessResourceSnapshot {
    rss_bytes: Option<u64>,
    peak_rss_bytes: Option<u64>,
    anonymous_rss_bytes: Option<u64>,
    file_rss_bytes: Option<u64>,
    data_bytes: Option<u64>,
    threads: Option<usize>,
    cpu_percent_x100: Option<u64>,
}

#[cfg(any(target_os = "linux", test))]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ProcessCpuSample {
    total_jiffies: u64,
}

fn process_resource_snapshot() -> ProcessResourceSnapshot {
    let mut snapshot = read_process_status_snapshot().unwrap_or_default();
    snapshot.cpu_percent_x100 = process_cpu_percent_x100();
    snapshot
}

#[cfg(target_os = "linux")]
fn read_process_status_snapshot() -> Option<ProcessResourceSnapshot> {
    let content = std::fs::read_to_string("/proc/self/status").ok()?;
    parse_linux_process_status(&content)
}

#[cfg(not(target_os = "linux"))]
fn read_process_status_snapshot() -> Option<ProcessResourceSnapshot> {
    None
}

#[cfg(any(target_os = "linux", test))]
fn parse_linux_process_status(input: &str) -> Option<ProcessResourceSnapshot> {
    let mut snapshot = ProcessResourceSnapshot::default();
    for line in input.lines() {
        if let Some(value) = linux_status_kib_value(line, "VmRSS:") {
            snapshot.rss_bytes = Some(value.saturating_mul(1024));
        } else if let Some(value) = linux_status_kib_value(line, "VmHWM:") {
            snapshot.peak_rss_bytes = Some(value.saturating_mul(1024));
        } else if let Some(value) = linux_status_kib_value(line, "RssAnon:") {
            snapshot.anonymous_rss_bytes = Some(value.saturating_mul(1024));
        } else if let Some(value) = linux_status_kib_value(line, "RssFile:") {
            snapshot.file_rss_bytes = Some(value.saturating_mul(1024));
        } else if let Some(value) = linux_status_kib_value(line, "VmData:") {
            snapshot.data_bytes = Some(value.saturating_mul(1024));
        } else if let Some(value) = linux_status_plain_value(line, "Threads:") {
            snapshot.threads = Some(value as usize);
        }
    }
    (snapshot != ProcessResourceSnapshot::default()).then_some(snapshot)
}

#[cfg(any(target_os = "linux", test))]
fn linux_status_kib_value(line: &str, key: &str) -> Option<u64> {
    let rest = line.trim_start().strip_prefix(key)?;
    rest.split_whitespace().next()?.parse::<u64>().ok()
}

#[cfg(any(target_os = "linux", test))]
fn linux_status_plain_value(line: &str, key: &str) -> Option<u64> {
    let rest = line.trim_start().strip_prefix(key)?;
    rest.split_whitespace().next()?.parse::<u64>().ok()
}

#[cfg(target_os = "linux")]
fn process_cpu_percent_x100() -> Option<u64> {
    static CACHE: OnceLock<Mutex<Option<(Instant, ProcessCpuSample)>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(None));
    let mut cached = cache.lock().expect("process cpu cache poisoned");
    cached_process_cpu_percent_x100(
        Instant::now(),
        &mut cached,
        read_process_cpu_sample,
        process_clock_ticks_per_second,
    )
}

#[cfg(not(target_os = "linux"))]
fn process_cpu_percent_x100() -> Option<u64> {
    None
}

#[cfg(any(target_os = "linux", test))]
fn cached_process_cpu_percent_x100<ReadSample, ReadClock>(
    now: Instant,
    cached: &mut Option<(Instant, ProcessCpuSample)>,
    read_sample: ReadSample,
    read_clock_ticks: ReadClock,
) -> Option<u64>
where
    ReadSample: FnOnce() -> Option<ProcessCpuSample>,
    ReadClock: FnOnce() -> Option<u64>,
{
    let sample = read_sample()?;
    let Some((last, previous)) = *cached else {
        *cached = Some((now, sample));
        return None;
    };
    if now.duration_since(last) < PROCESS_CPU_CACHE_TTL {
        return None;
    }
    *cached = Some((now, sample));
    let elapsed = now.duration_since(last).as_secs_f64();
    if elapsed <= 0.0 {
        return None;
    }
    let clock_ticks = read_clock_ticks()? as f64;
    if clock_ticks <= 0.0 {
        return None;
    }
    let delta = sample.total_jiffies.saturating_sub(previous.total_jiffies);
    Some((((delta as f64 / clock_ticks) / elapsed) * 100.0 * 100.0).round() as u64)
}

#[cfg(target_os = "linux")]
fn read_process_cpu_sample() -> Option<ProcessCpuSample> {
    let content = std::fs::read_to_string("/proc/self/stat").ok()?;
    parse_linux_process_stat(&content)
}

#[cfg(target_os = "linux")]
fn parse_linux_process_stat(input: &str) -> Option<ProcessCpuSample> {
    let close = input.rfind(')')?;
    let fields = input
        .get(close + 1..)?
        .split_whitespace()
        .collect::<Vec<_>>();
    let user_jiffies = fields.get(11)?.parse::<u64>().ok()?;
    let system_jiffies = fields.get(12)?.parse::<u64>().ok()?;
    Some(ProcessCpuSample {
        total_jiffies: user_jiffies.saturating_add(system_jiffies),
    })
}

#[cfg(target_os = "linux")]
fn process_clock_ticks_per_second() -> Option<u64> {
    let ticks = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    (ticks > 0).then_some(ticks as u64)
}

#[cfg(target_os = "linux")]
fn process_open_fd_count() -> Option<usize> {
    static CACHE: OnceLock<Mutex<Option<(Instant, Option<usize>)>>> = OnceLock::new();
    let cache = CACHE.get_or_init(|| Mutex::new(None));
    let mut cached = cache.lock().expect("process open fd cache poisoned");
    cached_process_open_fd_count(Instant::now(), &mut cached, read_process_open_fd_count)
}

#[cfg(target_os = "linux")]
fn read_process_open_fd_count() -> Option<usize> {
    std::fs::read_dir("/proc/self/fd")
        .ok()
        .map(|entries| entries.filter_map(Result::ok).count())
}

#[cfg(target_os = "linux")]
fn cached_process_open_fd_count<F>(
    now: Instant,
    cached: &mut Option<(Instant, Option<usize>)>,
    read: F,
) -> Option<usize>
where
    F: FnOnce() -> Option<usize>,
{
    if let Some((last, value)) = *cached {
        if now.duration_since(last) < PROCESS_OPEN_FD_CACHE_TTL {
            return value;
        }
    }
    let value = read();
    *cached = Some((now, value));
    value
}

#[cfg(not(target_os = "linux"))]
fn process_open_fd_count() -> Option<usize> {
    None
}

fn connection_error_key(protocol: &str, scope: &str, reason: &str) -> String {
    format!(
        "{}.{}.{}",
        sanitize_connection_error_part(protocol),
        sanitize_connection_error_part(scope),
        sanitize_connection_error_part(reason)
    )
}

fn sanitize_connection_error_part(value: &str) -> String {
    value
        .chars()
        .map(|ch| match ch {
            'a'..='z' | '0'..='9' | '_' | '-' => ch,
            'A'..='Z' => ch.to_ascii_lowercase(),
            _ => '_',
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    #[cfg(target_os = "linux")]
    use super::{cached_process_open_fd_count, PROCESS_OPEN_FD_CACHE_TTL};
    use crate::abuse::ClientFailureBackoffSnapshot;
    use crate::metrics::{
        record_connection_error, record_udp_relay_finished, CoreMetrics, UdpRelayMetricsGuard,
    };
    use crate::quic_resources::QuicResourceSnapshot;

    #[test]
    fn records_user_delta_success_without_user_labels() {
        let mut metrics = CoreMetrics::default();

        metrics.record_user_delta_success("panel|proxy|1", false, 12, 260_000);

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.keli_core_user_delta_apply_total, 1);
        assert_eq!(snapshot.keli_core_user_delta_incremental_total, 1);
        assert_eq!(snapshot.keli_core_user_delta_full_snapshot_total, 0);
        assert_eq!(
            snapshot.keli_core_user_delta_active_users["panel|proxy|1"],
            260_000
        );
        assert_eq!(snapshot.keli_core_user_delta_apply_duration_ms.count, 1);
        assert_eq!(
            snapshot.keli_core_user_delta_apply_duration_ms.buckets["le_25"],
            1
        );
        assert!(!snapshot
            .keli_core_user_delta_active_users
            .contains_key("user-a"));
    }

    #[test]
    fn records_revision_and_missing_current_errors() {
        let mut metrics = CoreMetrics::default();

        metrics.record_user_delta_error(
            false,
            2,
            "revision mismatch for inbound panel|proxy|1: current <missing>, base 1; full snapshot required",
        );

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.keli_core_user_delta_apply_total, 1);
        assert_eq!(snapshot.keli_core_user_delta_apply_error_total, 1);
        assert_eq!(snapshot.keli_core_user_delta_revision_mismatch_total, 1);
        assert_eq!(
            snapshot.keli_core_user_delta_current_revision_missing_total,
            1
        );
    }

    #[test]
    fn snapshots_include_quic_resource_without_user_labels() {
        let metrics = CoreMetrics::default();

        let snapshot = metrics.snapshot_with_quic_resource(Some(QuicResourceSnapshot {
            total_limit: 4096,
            active_connections: 12,
            available_connections: 4084,
            listener_count: 2,
            per_listener_soft_limit: 2048,
            cpu_count: 4,
            memory_limit_mib: Some(4096),
            fd_limit: Some(1_048_576),
        }));

        let quic = snapshot
            .keli_core_quic_resource
            .expect("quic resource metrics");
        assert_eq!(quic.total_limit, 4096);
        assert_eq!(quic.active_connections, 12);
        assert_eq!(quic.listener_count, 2);
    }

    #[test]
    fn snapshots_include_abuse_backoff_metrics_without_ip_labels() {
        let metrics = CoreMetrics::default();

        let snapshot = metrics.snapshot_with_runtime_metrics(
            None,
            Some(ClientFailureBackoffSnapshot {
                failure_total: 7,
                backoff_reject_total: 2,
                active_ips: 3,
                blocked_ips: 1,
            }),
            Some(ClientFailureBackoffSnapshot {
                failure_total: 11,
                backoff_reject_total: 4,
                active_ips: 5,
                blocked_ips: 2,
            }),
        );

        assert_eq!(snapshot.keli_core_tls_handshake_failure_total, 7);
        assert_eq!(snapshot.keli_core_tls_handshake_backoff_reject_total, 2);
        assert_eq!(snapshot.keli_core_tls_handshake_backoff_active_ips, 3);
        assert_eq!(snapshot.keli_core_tls_handshake_backoff_blocked_ips, 1);
        assert_eq!(snapshot.keli_core_tcp_auth_failure_total, 11);
        assert_eq!(snapshot.keli_core_tcp_auth_backoff_reject_total, 4);
        assert_eq!(snapshot.keli_core_tcp_auth_backoff_active_ips, 5);
        assert_eq!(snapshot.keli_core_tcp_auth_backoff_blocked_ips, 2);
    }

    #[test]
    fn snapshots_include_dns_metrics_without_host_labels() {
        let metrics = CoreMetrics::default();
        let dns = crate::dns::dns_metrics_snapshot();

        let snapshot = metrics.snapshot_with_runtime_metrics(None, None, None);

        assert_eq!(snapshot.keli_core_dns, dns);
    }

    #[test]
    fn snapshots_include_hy2_udp_session_metrics_without_user_labels() {
        let metrics = CoreMetrics::default();

        let snapshot = metrics.snapshot_with_runtime_metrics(None, None, None);

        assert_eq!(snapshot.keli_core_hy2_udp_active_sessions, 0);
        assert!(snapshot.keli_core_hy2_udp_session_limit >= 64);
    }

    #[test]
    fn snapshots_include_connection_error_metrics_without_dynamic_labels() {
        let metrics = CoreMetrics::default();

        record_connection_error("VLESS", "tcp relay", "upstream timeout");

        let snapshot = metrics.snapshot_with_runtime_metrics(None, None, None);
        assert_eq!(
            snapshot.keli_core_connection_error_total["vless.tcp_relay.upstream_timeout"],
            1
        );
        assert!(!snapshot
            .keli_core_connection_error_total
            .contains_key("user-a"));
    }

    #[test]
    fn snapshots_include_udp_relay_metrics_without_dynamic_labels() {
        let metrics = CoreMetrics::default();

        {
            let _guard = UdpRelayMetricsGuard::new("Trojan", "tls websocket udp");
            let snapshot = metrics.snapshot_with_runtime_metrics(None, None, None);
            assert_eq!(
                snapshot.keli_core_udp_relay_active["trojan.tls_websocket_udp"],
                1
            );
        }
        record_udp_relay_finished("Trojan", "tls websocket udp", "ok");

        let snapshot = metrics.snapshot_with_runtime_metrics(None, None, None);
        assert!(!snapshot
            .keli_core_udp_relay_active
            .contains_key("trojan.tls_websocket_udp"));
        assert_eq!(
            snapshot.keli_core_udp_relay_finished_total["trojan.tls_websocket_udp.ok"],
            1
        );
        assert!(!snapshot
            .keli_core_udp_relay_finished_total
            .contains_key("user-a"));
    }

    #[test]
    fn snapshots_include_detached_blocking_relay_active_counts() {
        let metrics = CoreMetrics::default();
        let _guard = crate::stream::DetachedBlockingRelayMetricsGuard::new("keli-core-test-relay");

        let snapshot = metrics.snapshot_with_runtime_metrics(None, None, None);

        assert_eq!(
            snapshot.keli_core_detached_blocking_relay_active["keli-core-test-relay"],
            1
        );
    }

    #[test]
    fn snapshots_include_relay_scheduler_counts() {
        let metrics = CoreMetrics::default();
        let _native_guard =
            crate::stream::NativeRelayMetricsGuard::new("keli-core-test-native-relay");
        let _guard = crate::stream::AsyncRelayMetricsGuard::new("keli-core-test-async-relay");

        let snapshot = metrics.snapshot_with_runtime_metrics(None, None, None);

        assert_eq!(
            snapshot.keli_core_native_relay_active["keli-core-test-native-relay"],
            1
        );
        assert_eq!(
            snapshot.keli_core_async_relay_active["keli-core-test-async-relay"],
            1
        );
        assert!(snapshot.keli_core_native_relay_workers <= 1024);
        assert!(snapshot.keli_core_native_relay_idle <= snapshot.keli_core_native_relay_workers);
        assert!(
            snapshot.keli_core_tcp_relay_half_close_timeout_total
                >= snapshot.keli_core_tcp_relay_downlink_only_timeout_total
        );
        assert!(
            snapshot.keli_core_tcp_relay_half_close_timeout_total
                >= snapshot.keli_core_tcp_relay_uplink_only_timeout_total
        );
    }

    #[test]
    fn snapshots_include_tcp_accept_runtime_budget() {
        let metrics = CoreMetrics::default();

        let snapshot = metrics.snapshot_with_runtime_metrics(None, None, None);

        assert!(snapshot.keli_core_tcp_accept_worker_threads >= 2);
        assert!(snapshot.keli_core_tcp_accept_blocking_thread_budget >= 16);
    }

    #[test]
    fn snapshots_include_process_and_connection_resource_metrics() {
        let metrics = CoreMetrics::default();

        let snapshot = metrics.snapshot_with_runtime_metrics(None, None, None);

        assert_eq!(
            snapshot.keli_core_connection_active_total,
            snapshot
                .keli_core_connection_active_blocking
                .saturating_add(snapshot.keli_core_connection_active_async)
        );
        #[cfg(target_os = "linux")]
        assert!(snapshot.keli_core_process_open_fds.is_some());
        #[cfg(target_os = "linux")]
        {
            assert!(snapshot.keli_core_process_rss_bytes.is_some());
            assert!(snapshot.keli_core_process_peak_rss_bytes.is_some());
            assert!(snapshot.keli_core_process_threads.is_some());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn process_open_fd_count_reuses_recent_cached_sample() {
        let start = Instant::now();
        let mut cached = None;
        let mut reads = 0;

        let first = cached_process_open_fd_count(start, &mut cached, || {
            reads += 1;
            Some(41)
        });
        let second =
            cached_process_open_fd_count(start + Duration::from_secs(1), &mut cached, || {
                reads += 1;
                Some(99)
            });
        let third =
            cached_process_open_fd_count(start + PROCESS_OPEN_FD_CACHE_TTL, &mut cached, || {
                reads += 1;
                Some(99)
            });

        assert_eq!(first, Some(41));
        assert_eq!(second, Some(41));
        assert_eq!(third, Some(99));
        assert_eq!(reads, 2);
    }

    #[test]
    fn parses_linux_proc_status_resource_metrics() {
        let snapshot = super::parse_linux_process_status(
            "Name:\tkelinode\n\
             VmHWM:\t  950952 kB\n\
             VmRSS:\t  809384 kB\n\
             RssAnon:\t  800708 kB\n\
             RssFile:\t    8676 kB\n\
             VmData:\t  928356 kB\n\
             Threads:\t64\n",
        )
        .expect("process status snapshot");

        assert_eq!(snapshot.rss_bytes, Some(809_384 * 1024));
        assert_eq!(snapshot.peak_rss_bytes, Some(950_952 * 1024));
        assert_eq!(snapshot.anonymous_rss_bytes, Some(800_708 * 1024));
        assert_eq!(snapshot.file_rss_bytes, Some(8_676 * 1024));
        assert_eq!(snapshot.data_bytes, Some(928_356 * 1024));
        assert_eq!(snapshot.threads, Some(64));
    }

    #[test]
    fn calculates_process_cpu_percent_x100_between_samples() {
        let mut cached = None;
        let first = super::cached_process_cpu_percent_x100(
            Instant::now(),
            &mut cached,
            || Some(super::ProcessCpuSample { total_jiffies: 100 }),
            || Some(100),
        );
        let second = super::cached_process_cpu_percent_x100(
            Instant::now() + Duration::from_secs(2),
            &mut cached,
            || Some(super::ProcessCpuSample { total_jiffies: 150 }),
            || Some(100),
        );

        assert_eq!(first, None);
        assert_eq!(second, Some(2_500));
    }
}
