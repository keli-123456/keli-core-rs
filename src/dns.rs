use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpStream, ToSocketAddrs, UdpSocket};
use std::sync::atomic::{AtomicU16, AtomicU64, Ordering};
use std::sync::mpsc;
use std::sync::{Mutex, OnceLock, RwLock};
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::config::{DnsConfig, DnsServerConfig};
use crate::routing::{is_private_ip, route_targets_match};

static DNS_CONFIG: OnceLock<RwLock<DnsConfig>> = OnceLock::new();
static DNS_QUERY_ID: AtomicU16 = AtomicU16::new(1);
static DNS_POSITIVE_CACHE: OnceLock<Mutex<HashMap<DnsCacheKey, DnsPositiveCacheEntry>>> =
    OnceLock::new();
static DNS_NEGATIVE_CACHE: OnceLock<Mutex<HashMap<DnsCacheKey, DnsNegativeCacheEntry>>> =
    OnceLock::new();
static GOOGLEVIDEO_FALLBACK_CACHE: OnceLock<Mutex<Option<GoogleVideoFallbackEntry>>> =
    OnceLock::new();
static TCP_CONNECT_FAILURE_BACKOFF: OnceLock<Mutex<HashMap<DnsCacheKey, TcpConnectFailureEntry>>> =
    OnceLock::new();
static DNS_RESOLVE_TOTAL: AtomicU64 = AtomicU64::new(0);
static DNS_SYSTEM_QUERY_TOTAL: AtomicU64 = AtomicU64::new(0);
static DNS_CONFIGURED_QUERY_TOTAL: AtomicU64 = AtomicU64::new(0);
static DNS_POSITIVE_CACHE_HIT_TOTAL: AtomicU64 = AtomicU64::new(0);
static DNS_NEGATIVE_CACHE_HIT_TOTAL: AtomicU64 = AtomicU64::new(0);
static DNS_RESOLVE_ERROR_TOTAL: AtomicU64 = AtomicU64::new(0);
static DNS_PRIVATE_IP_FILTER_TOTAL: AtomicU64 = AtomicU64::new(0);
static DNS_PRIVATE_IP_BLOCK_TOTAL: AtomicU64 = AtomicU64::new(0);
static TCP_CONNECT_BACKOFF_REJECT_TOTAL: AtomicU64 = AtomicU64::new(0);
const DNS_POSITIVE_CACHE_TTL: Duration = Duration::from_secs(30);
const DNS_NEGATIVE_CACHE_TTL: Duration = Duration::from_secs(15);
const GOOGLEVIDEO_FALLBACK_CACHE_TTL: Duration = Duration::from_secs(30);
const DNS_POSITIVE_CACHE_MAX_ENTRIES: usize = 8192;
const DNS_NEGATIVE_CACHE_MAX_ENTRIES: usize = 4096;
const TCP_CONNECT_FAILURE_THRESHOLD: u32 = 3;
const TCP_CONNECT_FAILURE_WINDOW: Duration = Duration::from_secs(10);
const TCP_CONNECT_FAILURE_BLOCK_DURATION: Duration = Duration::from_secs(5);
const TCP_CONNECT_FAILURE_MAX_ENTRIES: usize = 8192;
const TCP_RACE_MAX_CONCURRENT: usize = 4;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DnsMetricsSnapshot {
    pub keli_core_dns_resolve_total: u64,
    pub keli_core_dns_system_query_total: u64,
    pub keli_core_dns_configured_query_total: u64,
    pub keli_core_dns_positive_cache_hit_total: u64,
    pub keli_core_dns_negative_cache_hit_total: u64,
    pub keli_core_dns_resolve_error_total: u64,
    pub keli_core_dns_private_ip_filter_total: u64,
    pub keli_core_dns_private_ip_block_total: u64,
    #[serde(default)]
    pub keli_core_tcp_connect_backoff_reject_total: u64,
    #[serde(default)]
    pub keli_core_tcp_connect_backoff_active_targets: usize,
}

#[derive(Clone, Debug, Eq, Hash, PartialEq)]
struct DnsCacheKey {
    host: String,
    port: u16,
}

#[derive(Clone, Debug)]
struct DnsPositiveCacheEntry {
    expires_at: Instant,
    addrs: Vec<SocketAddr>,
}

#[derive(Clone, Debug)]
struct DnsNegativeCacheEntry {
    expires_at: Instant,
    kind: io::ErrorKind,
    message: String,
}

#[derive(Clone, Debug)]
struct GoogleVideoFallbackEntry {
    expires_at: Instant,
    ips: Vec<IpAddr>,
}

#[derive(Clone, Debug)]
struct TcpConnectFailureEntry {
    failures: u32,
    window_started: Instant,
    blocked_until: Option<Instant>,
}

pub fn configure(config: DnsConfig) {
    let lock = DNS_CONFIG.get_or_init(|| RwLock::new(DnsConfig::default()));
    *lock.write().expect("dns config lock poisoned") = config;
    clear_positive_cache();
    clear_negative_cache();
    clear_googlevideo_fallback_cache();
    clear_tcp_connect_failure_backoff();
}

pub fn dns_metrics_snapshot() -> DnsMetricsSnapshot {
    DnsMetricsSnapshot {
        keli_core_dns_resolve_total: DNS_RESOLVE_TOTAL.load(Ordering::Relaxed),
        keli_core_dns_system_query_total: DNS_SYSTEM_QUERY_TOTAL.load(Ordering::Relaxed),
        keli_core_dns_configured_query_total: DNS_CONFIGURED_QUERY_TOTAL.load(Ordering::Relaxed),
        keli_core_dns_positive_cache_hit_total: DNS_POSITIVE_CACHE_HIT_TOTAL
            .load(Ordering::Relaxed),
        keli_core_dns_negative_cache_hit_total: DNS_NEGATIVE_CACHE_HIT_TOTAL
            .load(Ordering::Relaxed),
        keli_core_dns_resolve_error_total: DNS_RESOLVE_ERROR_TOTAL.load(Ordering::Relaxed),
        keli_core_dns_private_ip_filter_total: DNS_PRIVATE_IP_FILTER_TOTAL.load(Ordering::Relaxed),
        keli_core_dns_private_ip_block_total: DNS_PRIVATE_IP_BLOCK_TOTAL.load(Ordering::Relaxed),
        keli_core_tcp_connect_backoff_reject_total: TCP_CONNECT_BACKOFF_REJECT_TOTAL
            .load(Ordering::Relaxed),
        keli_core_tcp_connect_backoff_active_targets: tcp_connect_backoff_active_targets(),
    }
}

pub fn connect_tcp(host: &str, port: u16, timeout: Duration) -> io::Result<TcpStream> {
    let backoff_key = dns_cache_key(host, port);
    if let Some(error) = tcp_connect_backoff_error(&backoff_key, Instant::now()) {
        return Err(error);
    }
    let addrs = resolve_socket_addrs(host, port, timeout)?;
    match connect_tcp_addrs(&addrs, timeout) {
        Ok(stream) => {
            record_tcp_connect_success(&backoff_key);
            tune_tcp_stream(&stream);
            Ok(stream)
        }
        Err(error) => {
            record_tcp_connect_failure(&backoff_key, &error);
            Err(error)
        }
    }
}

pub async fn connect_tcp_tokio(
    host: &str,
    port: u16,
    timeout: Duration,
) -> io::Result<tokio::net::TcpStream> {
    let backoff_key = dns_cache_key(host, port);
    if let Some(error) = tcp_connect_backoff_error(&backoff_key, Instant::now()) {
        return Err(error);
    }
    let addrs = resolve_socket_addrs_tokio(host, port, timeout).await?;
    match connect_tcp_addrs_tokio(&addrs, timeout).await {
        Ok(stream) => {
            record_tcp_connect_success(&backoff_key);
            tune_tokio_tcp_stream(&stream);
            Ok(stream)
        }
        Err(error) => {
            record_tcp_connect_failure(&backoff_key, &error);
            Err(error)
        }
    }
}

fn connect_tcp_addrs(addrs: &[SocketAddr], timeout: Duration) -> io::Result<TcpStream> {
    let addrs = happy_eyeballs_order(addrs, current_query_strategy_prefers_ipv6(), 1);
    if addrs.len() <= 1 {
        return connect_tcp_addrs_sequential(&addrs, timeout);
    }
    connect_tcp_addrs_race(&addrs, timeout)
}

fn connect_tcp_addrs_sequential(
    addrs: &[SocketAddr],
    attempt_timeout: Duration,
) -> io::Result<TcpStream> {
    let mut last_error = None;
    for addr in addrs {
        match TcpStream::connect_timeout(addr, attempt_timeout) {
            Ok(stream) => return Ok(stream),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "target did not resolve to any socket address",
        )
    }))
}

async fn connect_tcp_addrs_tokio(
    addrs: &[SocketAddr],
    timeout: Duration,
) -> io::Result<tokio::net::TcpStream> {
    let addrs = happy_eyeballs_order(addrs, current_query_strategy_prefers_ipv6(), 1);
    if addrs.len() <= 1 {
        return connect_tcp_addrs_tokio_sequential(&addrs, timeout).await;
    }
    connect_tcp_addrs_tokio_race(&addrs, timeout).await
}

async fn connect_tcp_addrs_tokio_sequential(
    addrs: &[SocketAddr],
    attempt_timeout: Duration,
) -> io::Result<tokio::net::TcpStream> {
    let mut last_error = None;
    for addr in addrs {
        match tokio::time::timeout(attempt_timeout, tokio::net::TcpStream::connect(addr)).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(error)) => last_error = Some(error),
            Err(_) => {
                last_error = Some(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "target connect timed out",
                ));
            }
        }
    }
    Err(last_error.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "target did not resolve to any socket address",
        )
    }))
}

fn connect_tcp_addrs_race(addrs: &[SocketAddr], timeout: Duration) -> io::Result<TcpStream> {
    let deadline = Instant::now() + timeout;
    let (tx, rx) = mpsc::channel();
    let mut next = 0;
    let mut active = 0;
    let mut last_error = None;
    spawn_tcp_race_attempts(addrs, timeout, &tx, &mut next, &mut active);

    loop {
        let Some(remaining) = remaining_until(deadline) else {
            return Err(tcp_connect_timeout_error());
        };
        match rx.recv_timeout(remaining) {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(error)) => {
                active = active.saturating_sub(1);
                last_error = Some(error);
                spawn_tcp_race_attempts(addrs, timeout, &tx, &mut next, &mut active);
                if active == 0 && next >= addrs.len() {
                    return Err(last_error.unwrap_or_else(no_socket_addr_error));
                }
            }
            Err(mpsc::RecvTimeoutError::Timeout) => return Err(tcp_connect_timeout_error()),
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                return Err(last_error.unwrap_or_else(no_socket_addr_error));
            }
        }
    }
}

fn spawn_tcp_race_attempts(
    addrs: &[SocketAddr],
    timeout: Duration,
    tx: &mpsc::Sender<io::Result<TcpStream>>,
    next: &mut usize,
    active: &mut usize,
) {
    while *next < addrs.len() && *active < tcp_race_max_concurrent() {
        let addr = addrs[*next];
        let tx = tx.clone();
        thread::spawn(move || {
            let _ = tx.send(TcpStream::connect_timeout(&addr, timeout));
        });
        *next += 1;
        *active += 1;
        if tcp_race_try_delay() > Duration::ZERO {
            break;
        }
    }
}

async fn connect_tcp_addrs_tokio_race(
    addrs: &[SocketAddr],
    timeout: Duration,
) -> io::Result<tokio::net::TcpStream> {
    let deadline = Instant::now() + timeout;
    let (tx, mut rx) = tokio::sync::mpsc::channel(addrs.len());
    let mut next = 0;
    let mut active = 0usize;
    let mut last_error = None;
    spawn_tcp_race_attempts_tokio(addrs, timeout, &tx, &mut next, &mut active);

    loop {
        let Some(remaining) = remaining_until(deadline) else {
            return Err(tcp_connect_timeout_error());
        };
        match tokio::time::timeout(remaining, rx.recv()).await {
            Ok(Some(Ok(stream))) => return Ok(stream),
            Ok(Some(Err(error))) => {
                active = active.saturating_sub(1);
                last_error = Some(error);
                spawn_tcp_race_attempts_tokio(addrs, timeout, &tx, &mut next, &mut active);
                if active == 0 && next >= addrs.len() {
                    return Err(last_error.unwrap_or_else(no_socket_addr_error));
                }
            }
            Ok(None) => return Err(last_error.unwrap_or_else(no_socket_addr_error)),
            Err(_) => return Err(tcp_connect_timeout_error()),
        }
    }
}

fn spawn_tcp_race_attempts_tokio(
    addrs: &[SocketAddr],
    timeout: Duration,
    tx: &tokio::sync::mpsc::Sender<io::Result<tokio::net::TcpStream>>,
    next: &mut usize,
    active: &mut usize,
) {
    while *next < addrs.len() && *active < tcp_race_max_concurrent() {
        let addr = addrs[*next];
        let tx = tx.clone();
        tokio::spawn(async move {
            let result =
                match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(addr)).await {
                    Ok(Ok(stream)) => Ok(stream),
                    Ok(Err(error)) => Err(error),
                    Err(_) => Err(tcp_connect_timeout_error()),
                };
            let _ = tx.send(result).await;
        });
        *next += 1;
        *active += 1;
        if tcp_race_try_delay() > Duration::ZERO {
            break;
        }
    }
}

fn remaining_until(deadline: Instant) -> Option<Duration> {
    let now = Instant::now();
    if now >= deadline {
        None
    } else {
        Some(deadline.duration_since(now))
    }
}

fn no_socket_addr_error() -> io::Error {
    io::Error::new(
        io::ErrorKind::AddrNotAvailable,
        "target did not resolve to any socket address",
    )
}

fn tcp_connect_timeout_error() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "target connect timed out")
}

fn tcp_race_try_delay() -> Duration {
    Duration::ZERO
}

fn tcp_race_max_concurrent() -> usize {
    TCP_RACE_MAX_CONCURRENT
}

fn happy_eyeballs_order(
    addrs: &[SocketAddr],
    prioritize_ipv6: bool,
    interleave: usize,
) -> Vec<SocketAddr> {
    if addrs.len() <= 1 {
        return addrs.to_vec();
    }
    let mut ipv4 = Vec::new();
    let mut ipv6 = Vec::new();
    for addr in addrs {
        if addr.is_ipv4() {
            ipv4.push(*addr);
        } else {
            ipv6.push(*addr);
        }
    }
    if ipv4.is_empty() || ipv6.is_empty() {
        return addrs.to_vec();
    }

    let interleave = interleave.max(1);
    let mut ordered = Vec::with_capacity(addrs.len());
    let mut ipv4_index = 0;
    let mut ipv6_index = 0;
    let mut turn_count = 0usize;
    let mut ipv4_turn = !prioritize_ipv6;
    while ipv4_index < ipv4.len() && ipv6_index < ipv6.len() {
        if ipv4_turn {
            ordered.push(ipv4[ipv4_index]);
            ipv4_index += 1;
        } else {
            ordered.push(ipv6[ipv6_index]);
            ipv6_index += 1;
        }
        turn_count += 1;
        if turn_count == interleave {
            ipv4_turn = !ipv4_turn;
            turn_count = 0;
        }
    }
    ordered.extend_from_slice(&ipv4[ipv4_index..]);
    ordered.extend_from_slice(&ipv6[ipv6_index..]);
    ordered
}

fn tune_tcp_stream(stream: &TcpStream) {
    let _ = stream.set_nodelay(true);
    #[cfg(any(target_os = "android", target_os = "linux"))]
    {
        let _ = socket2::SockRef::from(stream).set_tcp_quickack(true);
    }
}

fn tune_tokio_tcp_stream(stream: &tokio::net::TcpStream) {
    let _ = stream.set_nodelay(true);
    #[cfg(any(target_os = "android", target_os = "linux"))]
    {
        let _ = stream.set_quickack(true);
    }
}

pub fn resolve_socket_addr(host: &str, port: u16, timeout: Duration) -> io::Result<SocketAddr> {
    resolve_socket_addrs(host, port, timeout)?
        .into_iter()
        .next()
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "target did not resolve to any socket address",
            )
        })
}

pub async fn resolve_socket_addr_tokio(
    host: &str,
    port: u16,
    timeout: Duration,
) -> io::Result<SocketAddr> {
    resolve_socket_addrs_tokio(host, port, timeout)
        .await?
        .into_iter()
        .next()
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "target did not resolve to any socket address",
            )
        })
}

pub async fn resolve_socket_addrs_tokio(
    host: &str,
    port: u16,
    timeout: Duration,
) -> io::Result<Vec<SocketAddr>> {
    if let Some(addr) = literal_socket_addr(host, port) {
        DNS_RESOLVE_TOTAL.fetch_add(1, Ordering::Relaxed);
        let config = current_config();
        let result = filter_private_addrs(host, port, vec![addr], &config);
        if result.is_err() {
            DNS_RESOLVE_ERROR_TOTAL.fetch_add(1, Ordering::Relaxed);
        }
        return result;
    }

    let host = host.to_string();
    tokio::task::spawn_blocking(move || resolve_socket_addrs(&host, port, timeout))
        .await
        .map_err(|error| {
            io::Error::new(
                io::ErrorKind::Other,
                format!("dns resolve task failed: {error}"),
            )
        })?
}

pub fn resolve_socket_addrs(
    host: &str,
    port: u16,
    timeout: Duration,
) -> io::Result<Vec<SocketAddr>> {
    DNS_RESOLVE_TOTAL.fetch_add(1, Ordering::Relaxed);
    if let Some(addr) = literal_socket_addr(host, port) {
        let config = current_config();
        let result = filter_private_addrs(host, port, vec![addr], &config);
        if result.is_err() {
            DNS_RESOLVE_ERROR_TOTAL.fetch_add(1, Ordering::Relaxed);
        }
        return result;
    }

    let host = host.trim().trim_matches(['[', ']']);
    let cache_key = dns_cache_key(host, port);
    if let Some(addrs) = cached_positive_addrs(&cache_key) {
        return Ok(addrs);
    }
    if let Some(error) = cached_negative_error(&cache_key) {
        DNS_RESOLVE_ERROR_TOTAL.fetch_add(1, Ordering::Relaxed);
        return Err(error);
    }
    let config = current_config();
    let result = if config.servers.is_empty() {
        DNS_SYSTEM_QUERY_TOTAL.fetch_add(1, Ordering::Relaxed);
        system_resolve(host, port)
    } else {
        DNS_CONFIGURED_QUERY_TOTAL.fetch_add(1, Ordering::Relaxed);
        let servers = select_servers(&config, host);
        let query_types = query_types(&config.query_strategy);
        let mut last_error = None;
        let mut resolved = None;
        'outer: for server in servers {
            for qtype in &query_types {
                match query_dns_server(&server, host, *qtype, timeout) {
                    Ok(ips) if !ips.is_empty() => {
                        resolved = Some(
                            ips.into_iter()
                                .map(|ip| SocketAddr::new(ip, port))
                                .collect::<Vec<_>>(),
                        );
                        break 'outer;
                    }
                    Ok(_) => {}
                    Err(error) => last_error = Some(error),
                }
            }
        }

        resolved.map(Ok).unwrap_or_else(|| {
            Err(last_error.unwrap_or_else(|| {
                io::Error::new(
                    io::ErrorKind::AddrNotAvailable,
                    "configured dns servers returned no target address",
                )
            }))
        })
    };

    match result {
        Ok(addrs) => match filter_private_addrs(host, port, addrs, &config) {
            Ok(addrs) => {
                remove_negative_cache_entry(&cache_key);
                record_positive_cache(&cache_key, &addrs);
                record_googlevideo_fallback(host, &addrs);
                Ok(addrs)
            }
            Err(error) => {
                DNS_RESOLVE_ERROR_TOTAL.fetch_add(1, Ordering::Relaxed);
                Err(error)
            }
        },
        Err(error) => {
            DNS_RESOLVE_ERROR_TOTAL.fetch_add(1, Ordering::Relaxed);
            remove_negative_cache_entry(&cache_key);
            remove_positive_cache_entry(&cache_key);
            if let Some(addrs) = googlevideo_fallback_addrs(host, port) {
                record_positive_cache(&cache_key, &addrs);
                return Ok(addrs);
            }
            if !is_googlevideo_host(host) {
                record_negative_cache(&cache_key, &error);
            }
            Err(error)
        }
    }
}

fn dns_cache_key(host: &str, port: u16) -> DnsCacheKey {
    DnsCacheKey {
        host: host.trim().trim_matches(['[', ']']).to_ascii_lowercase(),
        port,
    }
}

fn tcp_connect_failure_backoff() -> &'static Mutex<HashMap<DnsCacheKey, TcpConnectFailureEntry>> {
    TCP_CONNECT_FAILURE_BACKOFF.get_or_init(|| Mutex::new(HashMap::new()))
}

fn tcp_connect_backoff_error(key: &DnsCacheKey, now: Instant) -> Option<io::Error> {
    let mut entries = tcp_connect_failure_backoff()
        .lock()
        .expect("tcp connect failure backoff poisoned");
    let entry = entries.get_mut(key)?;
    let Some(blocked_until) = entry.blocked_until else {
        return None;
    };
    if now < blocked_until {
        TCP_CONNECT_BACKOFF_REJECT_TOTAL.fetch_add(1, Ordering::Relaxed);
        return Some(io::Error::new(
            io::ErrorKind::TimedOut,
            format!(
                "target {}:{} is temporarily backed off after repeated connect failures",
                key.host, key.port
            ),
        ));
    }
    entry.failures = 0;
    entry.window_started = now;
    entry.blocked_until = None;
    None
}

fn record_tcp_connect_success(key: &DnsCacheKey) {
    tcp_connect_failure_backoff()
        .lock()
        .expect("tcp connect failure backoff poisoned")
        .remove(key);
}

fn record_tcp_connect_failure(key: &DnsCacheKey, error: &io::Error) {
    record_tcp_connect_failure_error_at(key, error, Instant::now());
}

#[cfg(test)]
fn record_tcp_connect_failure_at(key: &DnsCacheKey, now: Instant) {
    let error = io::Error::new(io::ErrorKind::ConnectionRefused, "target connect failed");
    record_tcp_connect_failure_error_at(key, &error, now);
}

fn record_tcp_connect_failure_error_at(key: &DnsCacheKey, error: &io::Error, now: Instant) {
    if is_transient_tcp_connect_error(error) {
        return;
    }
    let mut entries = tcp_connect_failure_backoff()
        .lock()
        .expect("tcp connect failure backoff poisoned");
    if entries.len() >= TCP_CONNECT_FAILURE_MAX_ENTRIES {
        entries.retain(|_, entry| !entry.is_expired(now));
    }
    let entry = entries
        .entry(key.clone())
        .or_insert_with(|| TcpConnectFailureEntry {
            failures: 0,
            window_started: now,
            blocked_until: None,
        });
    let in_window = now
        .checked_duration_since(entry.window_started)
        .map(|elapsed| elapsed <= TCP_CONNECT_FAILURE_WINDOW)
        .unwrap_or(false);
    if !in_window {
        entry.failures = 0;
        entry.window_started = now;
        entry.blocked_until = None;
    }
    entry.failures = entry.failures.saturating_add(1);
    if entry.failures >= TCP_CONNECT_FAILURE_THRESHOLD {
        entry.blocked_until = Some(now + TCP_CONNECT_FAILURE_BLOCK_DURATION);
    }
}

fn is_transient_tcp_connect_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    )
}

fn clear_tcp_connect_failure_backoff() {
    if let Some(cache) = TCP_CONNECT_FAILURE_BACKOFF.get() {
        cache
            .lock()
            .expect("tcp connect failure backoff poisoned")
            .clear();
    }
}

fn tcp_connect_backoff_active_targets() -> usize {
    let now = Instant::now();
    tcp_connect_failure_backoff()
        .lock()
        .expect("tcp connect failure backoff poisoned")
        .values()
        .filter(|entry| {
            entry
                .blocked_until
                .is_some_and(|blocked_until| now < blocked_until)
        })
        .count()
}

impl TcpConnectFailureEntry {
    fn is_expired(&self, now: Instant) -> bool {
        if let Some(blocked_until) = self.blocked_until {
            return now >= blocked_until
                && now
                    .checked_duration_since(blocked_until)
                    .map(|elapsed| elapsed > TCP_CONNECT_FAILURE_WINDOW)
                    .unwrap_or(false);
        }
        now.checked_duration_since(self.window_started)
            .map(|elapsed| elapsed > TCP_CONNECT_FAILURE_WINDOW * 2)
            .unwrap_or(false)
    }
}

fn filter_private_addrs(
    host: &str,
    port: u16,
    addrs: Vec<SocketAddr>,
    config: &DnsConfig,
) -> io::Result<Vec<SocketAddr>> {
    if !config.block_private_ips || private_ip_target_allowed(host, port, config) {
        return Ok(addrs);
    }
    let private_count = addrs.iter().filter(|addr| is_private_ip(addr.ip())).count();
    let public_addrs = addrs
        .into_iter()
        .filter(|addr| !is_private_ip(addr.ip()))
        .collect::<Vec<_>>();
    if private_count > 0 {
        DNS_PRIVATE_IP_FILTER_TOTAL.fetch_add(private_count as u64, Ordering::Relaxed);
    }
    if public_addrs.is_empty() {
        DNS_PRIVATE_IP_BLOCK_TOTAL.fetch_add(1, Ordering::Relaxed);
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("dns private ip blocked for {host}"),
        ));
    }
    Ok(public_addrs)
}

fn private_ip_target_allowed(host: &str, port: u16, config: &DnsConfig) -> bool {
    !config.private_ip_allowlist.is_empty()
        && route_targets_match(&config.private_ip_allowlist, host, port, "")
}

fn clear_positive_cache() {
    if let Some(cache) = DNS_POSITIVE_CACHE.get() {
        cache.lock().expect("dns positive cache poisoned").clear();
    }
}

fn clear_negative_cache() {
    if let Some(cache) = DNS_NEGATIVE_CACHE.get() {
        cache.lock().expect("dns negative cache poisoned").clear();
    }
}

fn clear_googlevideo_fallback_cache() {
    if let Some(cache) = GOOGLEVIDEO_FALLBACK_CACHE.get() {
        *cache.lock().expect("googlevideo fallback cache poisoned") = None;
    }
}

fn positive_cache() -> &'static Mutex<HashMap<DnsCacheKey, DnsPositiveCacheEntry>> {
    DNS_POSITIVE_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn negative_cache() -> &'static Mutex<HashMap<DnsCacheKey, DnsNegativeCacheEntry>> {
    DNS_NEGATIVE_CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

fn googlevideo_fallback_cache() -> &'static Mutex<Option<GoogleVideoFallbackEntry>> {
    GOOGLEVIDEO_FALLBACK_CACHE.get_or_init(|| Mutex::new(None))
}

fn cached_positive_addrs(key: &DnsCacheKey) -> Option<Vec<SocketAddr>> {
    let now = Instant::now();
    let mut cache = positive_cache()
        .lock()
        .expect("dns positive cache poisoned");
    let Some(entry) = cache.get(key) else {
        return None;
    };
    if now >= entry.expires_at {
        cache.remove(key);
        return None;
    }
    DNS_POSITIVE_CACHE_HIT_TOTAL.fetch_add(1, Ordering::Relaxed);
    Some(entry.addrs.clone())
}

fn cached_negative_error(key: &DnsCacheKey) -> Option<io::Error> {
    let now = Instant::now();
    let mut cache = negative_cache()
        .lock()
        .expect("dns negative cache poisoned");
    let Some(entry) = cache.get(key) else {
        return None;
    };
    if now >= entry.expires_at {
        cache.remove(key);
        return None;
    }
    DNS_NEGATIVE_CACHE_HIT_TOTAL.fetch_add(1, Ordering::Relaxed);
    Some(io::Error::new(entry.kind, entry.message.clone()))
}

fn record_positive_cache(key: &DnsCacheKey, addrs: &[SocketAddr]) {
    if addrs.is_empty() {
        return;
    }
    let mut cache = positive_cache()
        .lock()
        .expect("dns positive cache poisoned");
    if cache.len() >= DNS_POSITIVE_CACHE_MAX_ENTRIES {
        let now = Instant::now();
        cache.retain(|_, entry| entry.expires_at > now);
        if cache.len() >= DNS_POSITIVE_CACHE_MAX_ENTRIES {
            if let Some(first) = cache.keys().next().cloned() {
                cache.remove(&first);
            }
        }
    }
    cache.insert(
        key.clone(),
        DnsPositiveCacheEntry {
            expires_at: Instant::now() + DNS_POSITIVE_CACHE_TTL,
            addrs: addrs.to_vec(),
        },
    );
}

fn record_googlevideo_fallback(host: &str, addrs: &[SocketAddr]) {
    if !is_googlevideo_host(host) || addrs.is_empty() {
        return;
    }
    let ips = addrs.iter().map(|addr| addr.ip()).collect::<Vec<_>>();
    *googlevideo_fallback_cache()
        .lock()
        .expect("googlevideo fallback cache poisoned") = Some(GoogleVideoFallbackEntry {
        expires_at: Instant::now() + GOOGLEVIDEO_FALLBACK_CACHE_TTL,
        ips,
    });
}

fn googlevideo_fallback_addrs(host: &str, port: u16) -> Option<Vec<SocketAddr>> {
    if !is_googlevideo_host(host) {
        return None;
    }
    let now = Instant::now();
    let mut cache = googlevideo_fallback_cache()
        .lock()
        .expect("googlevideo fallback cache poisoned");
    let Some(entry) = cache.as_ref() else {
        return None;
    };
    if now >= entry.expires_at {
        *cache = None;
        return None;
    }
    let addrs = entry
        .ips
        .iter()
        .copied()
        .map(|ip| SocketAddr::new(ip, port))
        .collect::<Vec<_>>();
    if addrs.is_empty() {
        None
    } else {
        Some(addrs)
    }
}

fn is_googlevideo_host(host: &str) -> bool {
    let host = host
        .trim()
        .trim_matches(['[', ']'])
        .trim_end_matches('.')
        .to_ascii_lowercase();
    host == "googlevideo.com" || host.ends_with(".googlevideo.com")
}

fn record_negative_cache(key: &DnsCacheKey, error: &io::Error) {
    let mut cache = negative_cache()
        .lock()
        .expect("dns negative cache poisoned");
    if cache.len() >= DNS_NEGATIVE_CACHE_MAX_ENTRIES {
        let now = Instant::now();
        cache.retain(|_, entry| entry.expires_at > now);
        if cache.len() >= DNS_NEGATIVE_CACHE_MAX_ENTRIES {
            if let Some(first) = cache.keys().next().cloned() {
                cache.remove(&first);
            }
        }
    }
    cache.insert(
        key.clone(),
        DnsNegativeCacheEntry {
            expires_at: Instant::now() + DNS_NEGATIVE_CACHE_TTL,
            kind: error.kind(),
            message: error.to_string(),
        },
    );
}

fn remove_positive_cache_entry(key: &DnsCacheKey) {
    if let Some(cache) = DNS_POSITIVE_CACHE.get() {
        cache
            .lock()
            .expect("dns positive cache poisoned")
            .remove(key);
    }
}

fn remove_negative_cache_entry(key: &DnsCacheKey) {
    if let Some(cache) = DNS_NEGATIVE_CACHE.get() {
        cache
            .lock()
            .expect("dns negative cache poisoned")
            .remove(key);
    }
}

fn current_config() -> DnsConfig {
    DNS_CONFIG
        .get_or_init(|| RwLock::new(DnsConfig::default()))
        .read()
        .expect("dns config lock poisoned")
        .clone()
}

fn select_servers(config: &DnsConfig, host: &str) -> Vec<DnsServerConfig> {
    let matched = config
        .servers
        .iter()
        .filter(|server| {
            !server.domains.is_empty() && route_targets_match(&server.domains, host, 0, "")
        })
        .cloned()
        .collect::<Vec<_>>();
    if !matched.is_empty() {
        return matched;
    }
    config
        .servers
        .iter()
        .filter(|server| server.domains.is_empty())
        .cloned()
        .collect()
}

fn query_types(strategy: &str) -> Vec<u16> {
    match query_strategy_key(strategy).as_str() {
        "useipv6" | "ipv6" => vec![28],
        "useipv6v4" | "ipv6v4" => vec![28, 1],
        "asis" | "useip" | "useipv4v6" | "ipv4v6" => vec![1, 28],
        _ => vec![1],
    }
}

fn current_query_strategy_prefers_ipv6() -> bool {
    query_strategy_prefers_ipv6(&current_config().query_strategy)
}

fn query_strategy_prefers_ipv6(strategy: &str) -> bool {
    matches!(
        query_strategy_key(strategy).as_str(),
        "useipv6" | "ipv6" | "useipv6v4" | "ipv6v4"
    )
}

fn query_strategy_key(strategy: &str) -> String {
    strategy
        .trim()
        .chars()
        .filter(|ch| *ch != '_' && *ch != '-')
        .flat_map(char::to_lowercase)
        .collect()
}

fn query_dns_server(
    server: &DnsServerConfig,
    host: &str,
    qtype: u16,
    timeout: Duration,
) -> io::Result<Vec<IpAddr>> {
    let query_id = DNS_QUERY_ID.fetch_add(1, Ordering::Relaxed);
    let query = encode_query(query_id, host, qtype)?;
    let response = match dns_server_endpoint(&server.address)? {
        DnsServerEndpoint::Udp(server_addr) => query_udp_dns(server_addr, &query, timeout)?,
        DnsServerEndpoint::Tcp(server_addr) => query_tcp_dns(server_addr, &query, timeout)?,
    };
    parse_response(&response, query_id, qtype)
}

enum DnsServerEndpoint {
    Udp(SocketAddr),
    Tcp(SocketAddr),
}

fn dns_server_endpoint(address: &str) -> io::Result<DnsServerEndpoint> {
    let address = address.trim();
    if let Some(rest) = address.strip_prefix("tcp://") {
        return Ok(DnsServerEndpoint::Tcp(dns_server_addr(rest)?));
    }
    if let Some(rest) = address.strip_prefix("udp://") {
        return Ok(DnsServerEndpoint::Udp(dns_server_addr(rest)?));
    }
    if address.contains("://") {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "only udp and tcp dns server addresses are supported",
        ));
    }
    Ok(DnsServerEndpoint::Udp(dns_server_addr(address)?))
}

fn dns_server_addr(address: &str) -> io::Result<SocketAddr> {
    let address = address.trim();
    if let Ok(addr) = address.parse::<SocketAddr>() {
        return Ok(addr);
    }
    let host = address.trim_matches(['[', ']']);
    (host, 53).to_socket_addrs()?.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "dns server did not resolve to any socket address",
        )
    })
}

fn query_udp_dns(server_addr: SocketAddr, query: &[u8], timeout: Duration) -> io::Result<Vec<u8>> {
    let bind_addr = match server_addr {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    };
    let socket = UdpSocket::bind(bind_addr)?;
    socket.set_read_timeout(Some(timeout))?;
    socket.set_write_timeout(Some(timeout))?;
    socket.send_to(query, server_addr)?;

    let mut response = vec![0u8; 4096];
    let (read, _) = socket.recv_from(&mut response)?;
    response.truncate(read);
    Ok(response)
}

fn query_tcp_dns(server_addr: SocketAddr, query: &[u8], timeout: Duration) -> io::Result<Vec<u8>> {
    let mut stream = TcpStream::connect_timeout(&server_addr, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    let len = u16::try_from(query.len())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "dns tcp query is too large"))?;
    stream.write_all(&len.to_be_bytes())?;
    stream.write_all(query)?;

    let mut len = [0u8; 2];
    stream.read_exact(&mut len)?;
    let response_len = u16::from_be_bytes(len) as usize;
    let mut response = vec![0u8; response_len];
    stream.read_exact(&mut response)?;
    Ok(response)
}

fn system_resolve(host: &str, port: u16) -> io::Result<Vec<SocketAddr>> {
    (host, port).to_socket_addrs().map(|addrs| addrs.collect())
}

fn literal_socket_addr(host: &str, port: u16) -> Option<SocketAddr> {
    host.trim()
        .trim_matches(['[', ']'])
        .parse::<IpAddr>()
        .ok()
        .map(|ip| SocketAddr::new(ip, port))
}

fn encode_query(query_id: u16, host: &str, qtype: u16) -> io::Result<Vec<u8>> {
    let mut output = Vec::with_capacity(512);
    output.extend_from_slice(&query_id.to_be_bytes());
    output.extend_from_slice(&0x0100u16.to_be_bytes());
    output.extend_from_slice(&1u16.to_be_bytes());
    output.extend_from_slice(&0u16.to_be_bytes());
    output.extend_from_slice(&0u16.to_be_bytes());
    output.extend_from_slice(&0u16.to_be_bytes());
    for label in host.trim_end_matches('.').split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "dns query host label is invalid",
            ));
        }
        output.push(label.len() as u8);
        output.extend_from_slice(label.as_bytes());
    }
    output.push(0);
    output.extend_from_slice(&qtype.to_be_bytes());
    output.extend_from_slice(&1u16.to_be_bytes());
    Ok(output)
}

fn parse_response(input: &[u8], query_id: u16, qtype: u16) -> io::Result<Vec<IpAddr>> {
    if input.len() < 12 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "dns response is too short",
        ));
    }
    if u16::from_be_bytes([input[0], input[1]]) != query_id {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "dns response id mismatch",
        ));
    }
    let flags = u16::from_be_bytes([input[2], input[3]]);
    if flags & 0x8000 == 0 || flags & 0x000f != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "dns response indicates failure",
        ));
    }
    let question_count = u16::from_be_bytes([input[4], input[5]]) as usize;
    let answer_count = u16::from_be_bytes([input[6], input[7]]) as usize;
    let mut offset = 12;
    for _ in 0..question_count {
        read_name(input, &mut offset)?;
        if input.len().saturating_sub(offset) < 4 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated dns question",
            ));
        }
        offset += 4;
    }

    let mut ips = Vec::new();
    for _ in 0..answer_count {
        read_name(input, &mut offset)?;
        if input.len().saturating_sub(offset) < 10 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated dns answer",
            ));
        }
        let answer_type = u16::from_be_bytes([input[offset], input[offset + 1]]);
        let class = u16::from_be_bytes([input[offset + 2], input[offset + 3]]);
        let data_len = u16::from_be_bytes([input[offset + 8], input[offset + 9]]) as usize;
        offset += 10;
        if input.len().saturating_sub(offset) < data_len {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated dns answer data",
            ));
        }
        if class == 1 && answer_type == qtype {
            match (answer_type, data_len) {
                (1, 4) => {
                    ips.push(IpAddr::V4(Ipv4Addr::new(
                        input[offset],
                        input[offset + 1],
                        input[offset + 2],
                        input[offset + 3],
                    )));
                }
                (28, 16) => {
                    let mut bytes = [0u8; 16];
                    bytes.copy_from_slice(&input[offset..offset + 16]);
                    ips.push(IpAddr::V6(Ipv6Addr::from(bytes)));
                }
                _ => {}
            }
        }
        offset += data_len;
    }
    Ok(ips)
}

fn read_name(input: &[u8], offset: &mut usize) -> io::Result<()> {
    let mut cursor = *offset;
    let mut jumped = false;
    for _ in 0..128 {
        let Some(&len) = input.get(cursor) else {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated dns name",
            ));
        };
        if len & 0xc0 == 0xc0 {
            if input.get(cursor + 1).is_none() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated dns name pointer",
                ));
            }
            if !jumped {
                *offset = cursor + 2;
            }
            let pointer = (((len & 0x3f) as usize) << 8) | input[cursor + 1] as usize;
            cursor = pointer;
            jumped = true;
            continue;
        }
        if len == 0 {
            if !jumped {
                *offset = cursor + 1;
            }
            return Ok(());
        }
        cursor += 1 + usize::from(len);
        if cursor > input.len() {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "truncated dns label",
            ));
        }
        if !jumped {
            *offset = cursor;
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "dns name compression loop",
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::TcpListener;
    use std::thread;

    #[test]
    fn parses_dns_a_response() {
        let query = encode_query(7, "example.com", 1).expect("query");
        let mut response = Vec::new();
        response.extend_from_slice(&7u16.to_be_bytes());
        response.extend_from_slice(&0x8180u16.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&0u16.to_be_bytes());
        response.extend_from_slice(&query[12..]);
        response.extend_from_slice(&[0xc0, 0x0c]);
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&1u16.to_be_bytes());
        response.extend_from_slice(&60u32.to_be_bytes());
        response.extend_from_slice(&4u16.to_be_bytes());
        response.extend_from_slice(&[203, 0, 113, 9]);

        let ips = parse_response(&response, 7, 1).expect("response");
        assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(203, 0, 113, 9))]);
    }

    #[test]
    fn resolves_with_configured_dns_server() {
        let _guard = crate::test_support::network_test_lock();
        let dns = UdpSocket::bind("127.0.0.1:0").expect("dns bind");
        dns.set_read_timeout(Some(Duration::from_secs(2)))
            .expect("dns timeout");
        let dns_addr = dns.local_addr().expect("dns addr");
        let server = thread::spawn(move || {
            let mut packet = [0u8; 512];
            let (read, peer) = dns.recv_from(&mut packet).expect("dns recv");
            assert!(read > 12);
            let query_id = u16::from_be_bytes([packet[0], packet[1]]);
            let mut response = Vec::new();
            response.extend_from_slice(&query_id.to_be_bytes());
            response.extend_from_slice(&0x8180u16.to_be_bytes());
            response.extend_from_slice(&1u16.to_be_bytes());
            response.extend_from_slice(&1u16.to_be_bytes());
            response.extend_from_slice(&0u16.to_be_bytes());
            response.extend_from_slice(&0u16.to_be_bytes());
            response.extend_from_slice(&packet[12..read]);
            response.extend_from_slice(&[0xc0, 0x0c]);
            response.extend_from_slice(&1u16.to_be_bytes());
            response.extend_from_slice(&1u16.to_be_bytes());
            response.extend_from_slice(&30u32.to_be_bytes());
            response.extend_from_slice(&4u16.to_be_bytes());
            response.extend_from_slice(&[198, 51, 100, 8]);
            dns.send_to(&response, peer).expect("dns response");
        });

        configure(DnsConfig {
            servers: vec![DnsServerConfig {
                address: dns_addr.to_string(),
                domains: vec!["domain:example.com".to_string()],
            }],
            query_strategy: "UseIPv4".to_string(),
            ..DnsConfig::default()
        });
        let addrs =
            resolve_socket_addrs("api.example.com", 443, Duration::from_secs(2)).expect("resolve");
        assert_eq!(addrs, vec!["198.51.100.8:443".parse().unwrap()]);
        server.join().expect("server");
        configure(DnsConfig::default());
    }

    #[test]
    fn resolves_with_configured_tcp_dns_server() {
        let _guard = crate::test_support::network_test_lock();
        let dns = TcpListener::bind("127.0.0.1:0").expect("dns bind");
        let dns_addr = dns.local_addr().expect("dns addr");
        let server = thread::spawn(move || {
            let (mut stream, _) = dns.accept().expect("dns accept");
            let mut len = [0u8; 2];
            stream.read_exact(&mut len).expect("dns query len");
            let mut packet = vec![0u8; u16::from_be_bytes(len) as usize];
            stream.read_exact(&mut packet).expect("dns query");
            let query_id = u16::from_be_bytes([packet[0], packet[1]]);
            let mut response = Vec::new();
            response.extend_from_slice(&query_id.to_be_bytes());
            response.extend_from_slice(&0x8180u16.to_be_bytes());
            response.extend_from_slice(&1u16.to_be_bytes());
            response.extend_from_slice(&1u16.to_be_bytes());
            response.extend_from_slice(&0u16.to_be_bytes());
            response.extend_from_slice(&0u16.to_be_bytes());
            response.extend_from_slice(&packet[12..]);
            response.extend_from_slice(&[0xc0, 0x0c]);
            response.extend_from_slice(&1u16.to_be_bytes());
            response.extend_from_slice(&1u16.to_be_bytes());
            response.extend_from_slice(&30u32.to_be_bytes());
            response.extend_from_slice(&4u16.to_be_bytes());
            response.extend_from_slice(&[203, 0, 113, 12]);
            let response_len = u16::try_from(response.len()).expect("response len");
            stream
                .write_all(&response_len.to_be_bytes())
                .expect("write response len");
            stream.write_all(&response).expect("write response");
        });

        configure(DnsConfig {
            servers: vec![DnsServerConfig {
                address: format!("tcp://{dns_addr}"),
                domains: vec!["domain:example.net".to_string()],
            }],
            query_strategy: "UseIPv4".to_string(),
            ..DnsConfig::default()
        });
        let addrs =
            resolve_socket_addrs("api.example.net", 443, Duration::from_secs(2)).expect("resolve");
        assert_eq!(addrs, vec!["203.0.113.12:443".parse().unwrap()]);
        server.join().expect("server");
        configure(DnsConfig::default());
    }

    #[test]
    fn blocks_private_dns_answers_when_enabled() {
        let _guard = crate::test_support::network_test_lock();
        let before = dns_metrics_snapshot();
        let (dns_addr, server) = spawn_udp_a_dns([127, 0, 0, 1]);
        configure(DnsConfig {
            servers: vec![DnsServerConfig {
                address: dns_addr.to_string(),
                domains: vec!["domain:rebind.example".to_string()],
            }],
            query_strategy: "UseIPv4".to_string(),
            block_private_ips: true,
            ..DnsConfig::default()
        });

        let error = resolve_socket_addrs("api.rebind.example", 443, Duration::from_secs(2))
            .expect_err("private answer should be blocked");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(error.to_string().contains("private ip blocked"));
        let after = dns_metrics_snapshot();
        assert!(
            after.keli_core_dns_configured_query_total
                > before.keli_core_dns_configured_query_total
        );
        assert!(
            after.keli_core_dns_private_ip_filter_total
                > before.keli_core_dns_private_ip_filter_total
        );
        assert!(
            after.keli_core_dns_private_ip_block_total
                > before.keli_core_dns_private_ip_block_total
        );
        assert!(after.keli_core_dns_resolve_error_total > before.keli_core_dns_resolve_error_total);

        server.join().expect("server");
        configure(DnsConfig::default());
    }

    #[test]
    fn private_dns_answer_allowlist_preserves_compatibility() {
        let _guard = crate::test_support::network_test_lock();
        let (dns_addr, server) = spawn_udp_a_dns([127, 0, 0, 1]);
        configure(DnsConfig {
            servers: vec![DnsServerConfig {
                address: dns_addr.to_string(),
                domains: vec!["domain:internal.example".to_string()],
            }],
            query_strategy: "UseIPv4".to_string(),
            block_private_ips: true,
            private_ip_allowlist: vec!["domain:internal.example".to_string()],
        });

        let addrs = resolve_socket_addrs("api.internal.example", 443, Duration::from_secs(2))
            .expect("allowlisted private answer");
        assert_eq!(addrs, vec!["127.0.0.1:443".parse().unwrap()]);

        server.join().expect("server");
        configure(DnsConfig::default());
    }

    #[test]
    fn blocks_private_literal_targets_when_enabled() {
        let _guard = crate::test_support::network_test_lock();
        let before = dns_metrics_snapshot();
        configure(DnsConfig {
            block_private_ips: true,
            ..DnsConfig::default()
        });

        let error = resolve_socket_addrs("127.0.0.1", 443, Duration::from_millis(1))
            .expect_err("private literal should be blocked");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        let after = dns_metrics_snapshot();
        assert!(
            after.keli_core_dns_private_ip_block_total
                > before.keli_core_dns_private_ip_block_total
        );

        configure(DnsConfig::default());
    }

    #[tokio::test]
    async fn async_blocks_private_literal_targets_when_enabled() {
        let _guard = crate::test_support::network_test_lock();
        let before = dns_metrics_snapshot();
        configure(DnsConfig {
            block_private_ips: true,
            ..DnsConfig::default()
        });

        let error = resolve_socket_addrs_tokio("127.0.0.1", 443, Duration::from_millis(1))
            .await
            .expect_err("private literal should be blocked");
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        let after = dns_metrics_snapshot();
        assert!(
            after.keli_core_dns_private_ip_block_total
                > before.keli_core_dns_private_ip_block_total
        );

        configure(DnsConfig::default());
    }

    #[tokio::test]
    async fn async_resolves_literal_ips_without_dns_lookup() {
        let _guard = crate::test_support::network_test_lock();
        configure(DnsConfig {
            servers: vec![DnsServerConfig {
                address: "udp://192.0.2.1:53".to_string(),
                domains: Vec::new(),
            }],
            query_strategy: "UseIPv4".to_string(),
            ..DnsConfig::default()
        });

        let ipv4 = resolve_socket_addrs_tokio("127.0.0.1", 443, Duration::from_millis(1))
            .await
            .expect("ipv4 literal");
        assert_eq!(ipv4, vec!["127.0.0.1:443".parse().unwrap()]);

        let ipv6 = resolve_socket_addrs_tokio("[::1]", 443, Duration::from_millis(1))
            .await
            .expect("ipv6 literal");
        assert_eq!(ipv6, vec!["[::1]:443".parse().unwrap()]);

        configure(DnsConfig::default());
    }

    fn spawn_udp_a_dns(ip: [u8; 4]) -> (SocketAddr, thread::JoinHandle<()>) {
        let dns = UdpSocket::bind("127.0.0.1:0").expect("dns bind");
        dns.set_read_timeout(Some(Duration::from_secs(2)))
            .expect("dns timeout");
        let dns_addr = dns.local_addr().expect("dns addr");
        let server = thread::spawn(move || {
            let mut packet = [0u8; 512];
            let (read, peer) = dns.recv_from(&mut packet).expect("dns recv");
            assert!(read > 12);
            let query_id = u16::from_be_bytes([packet[0], packet[1]]);
            let mut response = Vec::new();
            response.extend_from_slice(&query_id.to_be_bytes());
            response.extend_from_slice(&0x8180u16.to_be_bytes());
            response.extend_from_slice(&1u16.to_be_bytes());
            response.extend_from_slice(&1u16.to_be_bytes());
            response.extend_from_slice(&0u16.to_be_bytes());
            response.extend_from_slice(&0u16.to_be_bytes());
            response.extend_from_slice(&packet[12..read]);
            response.extend_from_slice(&[0xc0, 0x0c]);
            response.extend_from_slice(&1u16.to_be_bytes());
            response.extend_from_slice(&1u16.to_be_bytes());
            response.extend_from_slice(&30u32.to_be_bytes());
            response.extend_from_slice(&4u16.to_be_bytes());
            response.extend_from_slice(&ip);
            dns.send_to(&response, peer).expect("dns response");
        });
        (dns_addr, server)
    }

    fn spawn_udp_googlevideo_dns_then_failure(ip: [u8; 4]) -> (SocketAddr, thread::JoinHandle<()>) {
        let dns = UdpSocket::bind("127.0.0.1:0").expect("dns bind");
        dns.set_read_timeout(Some(Duration::from_secs(2)))
            .expect("dns timeout");
        let dns_addr = dns.local_addr().expect("dns addr");
        let server = thread::spawn(move || {
            for index in 0..2 {
                let mut packet = [0u8; 512];
                let (read, peer) = dns.recv_from(&mut packet).expect("dns recv");
                assert!(read > 12);
                let query_id = u16::from_be_bytes([packet[0], packet[1]]);
                let mut response = Vec::new();
                response.extend_from_slice(&query_id.to_be_bytes());
                if index == 0 {
                    response.extend_from_slice(&0x8180u16.to_be_bytes());
                    response.extend_from_slice(&1u16.to_be_bytes());
                    response.extend_from_slice(&1u16.to_be_bytes());
                    response.extend_from_slice(&0u16.to_be_bytes());
                    response.extend_from_slice(&0u16.to_be_bytes());
                    response.extend_from_slice(&packet[12..read]);
                    response.extend_from_slice(&[0xc0, 0x0c]);
                    response.extend_from_slice(&1u16.to_be_bytes());
                    response.extend_from_slice(&1u16.to_be_bytes());
                    response.extend_from_slice(&30u32.to_be_bytes());
                    response.extend_from_slice(&4u16.to_be_bytes());
                    response.extend_from_slice(&ip);
                } else {
                    response.extend_from_slice(&0x8183u16.to_be_bytes());
                    response.extend_from_slice(&1u16.to_be_bytes());
                    response.extend_from_slice(&0u16.to_be_bytes());
                    response.extend_from_slice(&0u16.to_be_bytes());
                    response.extend_from_slice(&0u16.to_be_bytes());
                    response.extend_from_slice(&packet[12..read]);
                }
                dns.send_to(&response, peer).expect("dns response");
            }
        });
        (dns_addr, server)
    }

    fn spawn_udp_dns_failures(count: usize) -> (SocketAddr, thread::JoinHandle<()>) {
        let dns = UdpSocket::bind("127.0.0.1:0").expect("dns bind");
        dns.set_read_timeout(Some(Duration::from_secs(2)))
            .expect("dns timeout");
        let dns_addr = dns.local_addr().expect("dns addr");
        let server = thread::spawn(move || {
            for _ in 0..count {
                let mut packet = [0u8; 512];
                let (read, peer) = dns.recv_from(&mut packet).expect("dns recv");
                assert!(read > 12);
                let query_id = u16::from_be_bytes([packet[0], packet[1]]);
                let mut response = Vec::new();
                response.extend_from_slice(&query_id.to_be_bytes());
                response.extend_from_slice(&0x8183u16.to_be_bytes());
                response.extend_from_slice(&1u16.to_be_bytes());
                response.extend_from_slice(&0u16.to_be_bytes());
                response.extend_from_slice(&0u16.to_be_bytes());
                response.extend_from_slice(&0u16.to_be_bytes());
                response.extend_from_slice(&packet[12..read]);
                dns.send_to(&response, peer).expect("dns response");
            }
        });
        (dns_addr, server)
    }

    #[test]
    fn googlevideo_dns_failure_reuses_recent_googlevideo_address() {
        let _guard = crate::test_support::network_test_lock();
        let (dns_addr, server) = spawn_udp_googlevideo_dns_then_failure([203, 0, 113, 9]);
        configure(DnsConfig {
            servers: vec![DnsServerConfig {
                address: dns_addr.to_string(),
                domains: Vec::new(),
            }],
            query_strategy: "UseIPv4".to_string(),
            block_private_ips: false,
            private_ip_allowlist: Vec::new(),
        });

        let first = resolve_socket_addrs(
            "rr4---sn-o097znzd.googlevideo.com",
            443,
            Duration::from_secs(2),
        )
        .expect("first googlevideo resolve");
        assert_eq!(first, vec!["203.0.113.9:443".parse().unwrap()]);

        let second = resolve_socket_addrs(
            "rr5---sn-5hneknek.googlevideo.com",
            443,
            Duration::from_secs(2),
        )
        .expect("failed googlevideo host should fall back to recent googlevideo address");
        assert_eq!(second, vec!["203.0.113.9:443".parse().unwrap()]);

        server.join().expect("dns server");
        configure(DnsConfig::default());
    }

    #[test]
    fn googlevideo_dns_failure_without_fallback_is_not_negative_cached() {
        let _guard = crate::test_support::network_test_lock();
        let (dns_addr, server) = spawn_udp_dns_failures(2);
        configure(DnsConfig {
            servers: vec![DnsServerConfig {
                address: dns_addr.to_string(),
                domains: Vec::new(),
            }],
            query_strategy: "UseIPv4".to_string(),
            block_private_ips: false,
            private_ip_allowlist: Vec::new(),
        });

        let first = resolve_socket_addrs(
            "rr5---sn-5hneknek.googlevideo.com",
            443,
            Duration::from_secs(2),
        )
        .expect_err("first googlevideo failure");
        assert_eq!(first.kind(), io::ErrorKind::InvalidData);

        let second = resolve_socket_addrs(
            "rr5---sn-5hneknek.googlevideo.com",
            443,
            Duration::from_secs(2),
        )
        .expect_err("second googlevideo failure should query dns again");
        assert_eq!(second.kind(), io::ErrorKind::InvalidData);

        server
            .join()
            .expect("dns server should receive both queries");
        configure(DnsConfig::default());
    }

    #[test]
    fn negative_dns_cache_reuses_recent_failures_and_clears_on_configure() {
        let _guard = crate::test_support::network_test_lock();
        let before = dns_metrics_snapshot();
        let key = DnsCacheKey {
            host: "missing.example.test".to_string(),
            port: 443,
        };
        record_negative_cache(
            &key,
            &io::Error::new(io::ErrorKind::AddrNotAvailable, "no answer"),
        );

        let cached = cached_negative_error(&key).expect("cached error");
        assert_eq!(cached.kind(), io::ErrorKind::AddrNotAvailable);
        assert_eq!(cached.to_string(), "no answer");
        let after = dns_metrics_snapshot();
        assert!(
            after.keli_core_dns_negative_cache_hit_total
                > before.keli_core_dns_negative_cache_hit_total
        );

        configure(DnsConfig::default());
        assert!(cached_negative_error(&key).is_none());
    }

    #[test]
    fn positive_dns_cache_reuses_recent_answers_and_clears_on_configure() {
        let _guard = crate::test_support::network_test_lock();
        let before = dns_metrics_snapshot();
        let key = DnsCacheKey {
            host: "cached.example.test".to_string(),
            port: 443,
        };
        let addrs = vec![
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10)), 443),
            SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 443),
        ];
        record_positive_cache(&key, &addrs);

        assert_eq!(cached_positive_addrs(&key), Some(addrs));
        let after = dns_metrics_snapshot();
        assert!(
            after.keli_core_dns_positive_cache_hit_total
                > before.keli_core_dns_positive_cache_hit_total
        );

        configure(DnsConfig::default());
        assert!(cached_positive_addrs(&key).is_none());
    }

    #[test]
    fn tcp_connect_addrs_falls_back_to_later_address() {
        let _guard = crate::test_support::network_test_lock();
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind listener");
        let good = listener.local_addr().expect("listener addr");
        let bad_port = {
            let unused = TcpListener::bind(("127.0.0.1", 0)).expect("bind unused");
            unused.local_addr().expect("unused addr").port()
        };
        let bad = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), bad_port);
        let accepted = thread::spawn(move || listener.accept().expect("accept"));

        let stream =
            connect_tcp_addrs(&[bad, good], Duration::from_secs(2)).expect("fallback connect");

        assert_eq!(stream.peer_addr().expect("peer addr"), good);
        let _ = accepted.join().expect("join accept");
    }

    #[tokio::test]
    async fn async_tcp_connect_addrs_falls_back_to_later_address() {
        let _guard = crate::test_support::network_test_lock();
        let listener = TcpListener::bind(("127.0.0.1", 0)).expect("bind listener");
        let good = listener.local_addr().expect("listener addr");
        let bad_port = {
            let unused = TcpListener::bind(("127.0.0.1", 0)).expect("bind unused");
            unused.local_addr().expect("unused addr").port()
        };
        let bad = SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), bad_port);
        let accepted = thread::spawn(move || listener.accept().expect("accept"));

        let stream = connect_tcp_addrs_tokio(&[bad, good], Duration::from_secs(2))
            .await
            .expect("fallback connect");

        assert_eq!(stream.peer_addr().expect("peer addr"), good);
        let _ = accepted.join().expect("join accept");
    }

    #[test]
    fn tcp_happy_eyeballs_defaults_match_go_xray() {
        assert_eq!(tcp_race_try_delay(), Duration::ZERO);
        assert_eq!(tcp_race_max_concurrent(), 4);
    }

    #[test]
    fn tcp_happy_eyeballs_order_interleaves_ipv4_and_ipv6_like_go() {
        let v6_a = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 443);
        let v6_b = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 8443);
        let v4_a = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)), 443);
        let v4_b = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)), 443);
        let v4_c = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 3)), 443);

        let ordered = happy_eyeballs_order(&[v6_a, v6_b, v4_a, v4_b, v4_c], false, 1);

        assert_eq!(ordered, vec![v4_a, v6_a, v4_b, v6_b, v4_c]);
    }

    #[test]
    fn tcp_happy_eyeballs_order_can_prioritize_ipv6_like_go() {
        let v6_a = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 443);
        let v6_b = SocketAddr::new(IpAddr::V6(Ipv6Addr::LOCALHOST), 8443);
        let v4_a = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 1)), 443);
        let v4_b = SocketAddr::new(IpAddr::V4(Ipv4Addr::new(198, 51, 100, 2)), 443);

        let ordered = happy_eyeballs_order(&[v4_a, v4_b, v6_a, v6_b], true, 1);

        assert_eq!(ordered, vec![v6_a, v4_a, v6_b, v4_b]);
    }

    #[test]
    fn dns_query_strategy_order_matches_go_ip_strategy() {
        assert_eq!(query_types("UseIPv4"), vec![1]);
        assert_eq!(query_types("UseIPv6"), vec![28]);
        assert_eq!(query_types("UseIPv4v6"), vec![1, 28]);
        assert_eq!(query_types("UseIPv6v4"), vec![28, 1]);
        assert_eq!(query_types("use-ipv6-v4"), vec![28, 1]);
        assert!(query_strategy_prefers_ipv6("UseIPv6v4"));
        assert!(!query_strategy_prefers_ipv6("UseIPv4v6"));
    }

    #[test]
    fn tcp_connect_backoff_blocks_repeated_target_failures() {
        let _guard = crate::test_support::network_test_lock();
        clear_tcp_connect_failure_backoff();
        let key = dns_cache_key("156.246.66.34", 80);
        let now = Instant::now();

        record_tcp_connect_failure_at(&key, now);
        record_tcp_connect_failure_at(&key, now + Duration::from_secs(1));
        assert!(tcp_connect_backoff_error(&key, now + Duration::from_secs(2)).is_none());

        record_tcp_connect_failure_at(&key, now + Duration::from_secs(2));
        let error = tcp_connect_backoff_error(&key, now + Duration::from_secs(3))
            .expect("target should be temporarily backed off");
        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        assert!(
            error.to_string().contains("temporarily backed off"),
            "unexpected backoff error: {error}"
        );

        assert!(tcp_connect_backoff_error(&key, now + Duration::from_secs(8)).is_none());
        clear_tcp_connect_failure_backoff();
    }

    #[test]
    fn tcp_connect_backoff_metrics_count_rejects_without_host_labels() {
        let _guard = crate::test_support::network_test_lock();
        clear_tcp_connect_failure_backoff();
        let before = dns_metrics_snapshot();
        let key = dns_cache_key("203.0.113.80", 443);
        let now = Instant::now();

        record_tcp_connect_failure_at(&key, now);
        record_tcp_connect_failure_at(&key, now + Duration::from_secs(1));
        record_tcp_connect_failure_at(&key, now + Duration::from_secs(2));
        let error = tcp_connect_backoff_error(&key, now + Duration::from_secs(3))
            .expect("target should be temporarily backed off");

        assert_eq!(error.kind(), io::ErrorKind::TimedOut);
        let after = dns_metrics_snapshot();
        assert!(
            after.keli_core_tcp_connect_backoff_reject_total
                > before.keli_core_tcp_connect_backoff_reject_total
        );
        assert_eq!(after.keli_core_tcp_connect_backoff_active_targets, 1);
        clear_tcp_connect_failure_backoff();
    }

    #[test]
    fn tcp_connect_backoff_ignores_transient_timeouts() {
        let _guard = crate::test_support::network_test_lock();
        clear_tcp_connect_failure_backoff();
        let key = dns_cache_key("dns.huhu.icu", 22223);
        let now = Instant::now();
        let timeout = io::Error::new(io::ErrorKind::TimedOut, "target connect timed out");

        record_tcp_connect_failure_error_at(&key, &timeout, now);
        record_tcp_connect_failure_error_at(&key, &timeout, now + Duration::from_secs(1));
        record_tcp_connect_failure_error_at(&key, &timeout, now + Duration::from_secs(2));

        assert!(tcp_connect_backoff_error(&key, now + Duration::from_secs(3)).is_none());
        clear_tcp_connect_failure_backoff();
    }

    #[test]
    fn tcp_connect_success_clears_target_backoff() {
        let _guard = crate::test_support::network_test_lock();
        clear_tcp_connect_failure_backoff();
        let key = dns_cache_key("[2607:f358:1a:e::d4d9:5831]", 443);
        let now = Instant::now();

        record_tcp_connect_failure_at(&key, now);
        record_tcp_connect_failure_at(&key, now + Duration::from_secs(1));
        record_tcp_connect_failure_at(&key, now + Duration::from_secs(2));
        assert!(tcp_connect_backoff_error(&key, now + Duration::from_secs(3)).is_some());

        record_tcp_connect_success(&key);
        assert!(tcp_connect_backoff_error(&key, now + Duration::from_secs(4)).is_none());
        clear_tcp_connect_failure_backoff();
    }
}
