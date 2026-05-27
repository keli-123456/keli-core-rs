use std::collections::HashMap;
use std::fmt;
use std::future::Future;
use std::hash::{Hash, Hasher};
use std::io;
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime};

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde::{Deserialize, Serialize};

use crate::abuse::{ClientFailureBackoff, ClientFailureBackoffSnapshot};
use crate::anytls::{AnyTlsServer, AnyTlsServerConfig};
use crate::config::{CoreConfig, InboundConfig, PolicyConfig, TransportConfig, ValidationError};
use crate::grpc::{
    run_grpc_listener, GrpcHunkReader, GrpcHunkWriter, GrpcStreamHandler, GrpcTlsConfig,
};
use crate::http_proxy::{HttpProxyServer, HttpProxyServerConfig};
use crate::httpupgrade::{accept_httpupgrade, accept_httpupgrade_tls};
use crate::hysteria2::{Hysteria2ObfsConfig, Hysteria2Server, Hysteria2ServerConfig};
use crate::limits::{
    DeviceLimitOnlineRecord, DeviceLimitSnapshot, UserBandwidthLimiters, UserSessionTracker,
};
use crate::mieru::{MieruServer, MieruServerConfig};
use crate::naive::{NaiveServer, NaiveServerConfig};
use crate::protocol::Protocol;
use crate::quic_resources::{QuicResourceSnapshot, SharedQuicConnectionLimiter};
use crate::reality::{
    decode_reality_private_key, decode_short_id, generate_reality_temporary_certificate,
    handle_reality_preface, RealityAuthConfig, RealityGatewayConfig, RealityGatewayResult,
};
use crate::shadowsocks::{ShadowsocksServer, ShadowsocksServerConfig};
use crate::socket_bind::bind_dual_stack_tcp_listener;
use crate::socks5::{Socks5Server, Socks5ServerConfig};
use crate::tls::{
    classify_tls_handshake_error, relay_tls_stream, TlsAcceptor, TlsConnection,
    TlsHandshakeErrorClass,
};
use crate::traffic::{SharedTrafficRegistry, TrafficDelta, TrafficRegistry};
use crate::trojan::{TrojanServer, TrojanServerConfig};
use crate::tuic::{TuicServer, TuicServerConfig};
use crate::user::{CoreUser, CoreUserDelta, CoreUserDeltaResult};
use crate::vless::{VlessServer, VlessServerConfig};
use crate::vmess::{VmessServer, VmessServerConfig};

const CONNECTION_WORKER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(3);
#[cfg(test)]
const MAX_CONNECTION_WORKERS_PER_LISTENER: usize = 256;
#[cfg(windows)]
const DEFAULT_CONNECTION_WORKER_STACK_KIB: usize = 2048;
#[cfg(not(windows))]
const DEFAULT_CONNECTION_WORKER_STACK_KIB: usize = 2048;
const MIN_CONNECTION_WORKER_STACK_KIB: usize = 256;
const MAX_CONNECTION_WORKER_STACK_KIB: usize = 8192;
const QUIC_RUNTIME_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(3);
static TCP_ACCEPT_RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ListenerStatus {
    pub tag: String,
    pub protocol: Protocol,
    pub local_addr: SocketAddr,
}

#[derive(Debug)]
pub enum CoreServiceError {
    InvalidConfig(ValidationError),
    Bind { tag: String, source: io::Error },
    UnsupportedFeature { tag: String, message: String },
    UnsupportedProtocol { tag: String, protocol: Protocol },
}

impl fmt::Display for CoreServiceError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CoreServiceError::InvalidConfig(error) => {
                write!(formatter, "invalid core config: {error}")
            }
            CoreServiceError::Bind { tag, source } => {
                write!(formatter, "failed to bind inbound {tag}: {source}")
            }
            CoreServiceError::UnsupportedFeature { tag, message } => {
                write!(formatter, "inbound {tag} unsupported feature: {message}")
            }
            CoreServiceError::UnsupportedProtocol { tag, protocol } => {
                write!(
                    formatter,
                    "inbound {tag} protocol {protocol:?} is not implemented in keli-core-rs yet"
                )
            }
        }
    }
}

impl std::error::Error for CoreServiceError {}

#[derive(Debug)]
pub struct CoreService {
    config: CoreConfig,
    listeners: Vec<ListenerHandle>,
    traffic: SharedTrafficRegistry,
    sessions: UserSessionTracker,
    bandwidth: UserBandwidthLimiters,
    quic_connections: Option<SharedQuicConnectionLimiter>,
    tls_failures: ClientFailureBackoff,
    user_revisions: HashMap<String, String>,
    user_fingerprints: HashMap<String, UserFingerprintState>,
    stopped: bool,
}

#[derive(Debug)]
struct ListenerHandle {
    status: ListenerStatus,
    runtime: ListenerRuntime,
    stop: Arc<AtomicBool>,
    workers: ConnectionWorkerGroup,
    join: Option<JoinHandle<()>>,
}

#[derive(Clone, Debug)]
enum ListenerRuntime {
    Socks(Socks5Server),
    Http(HttpProxyServer),
    Vless(VlessServer),
    Vmess(VmessServer),
    Trojan(TrojanServer),
    Shadowsocks(ShadowsocksServer),
    AnyTls(AnyTlsServer),
    Tuic(TuicServer),
    Hysteria2(Hysteria2Server),
    Mieru(MieruServer),
    Naive(NaiveServer),
}

impl ListenerRuntime {
    fn replace_users(&self, users: Vec<CoreUser>) {
        match self {
            ListenerRuntime::Socks(server) => server.replace_users(users),
            ListenerRuntime::Http(server) => server.replace_users(users),
            ListenerRuntime::Vless(server) => server.replace_users(users),
            ListenerRuntime::Vmess(server) => server.replace_users(users),
            ListenerRuntime::Trojan(server) => server.replace_users(users),
            ListenerRuntime::Shadowsocks(server) => server.replace_users(users),
            ListenerRuntime::AnyTls(server) => server.replace_users(users),
            ListenerRuntime::Tuic(server) => server.replace_users(users),
            ListenerRuntime::Hysteria2(server) => server.replace_users(users),
            ListenerRuntime::Mieru(server) => server.replace_users(users),
            ListenerRuntime::Naive(server) => server.replace_users(users),
        }
    }

    fn replace_routes(&self, routes: Vec<crate::RouteRule>) {
        match self {
            ListenerRuntime::Socks(server) => server.replace_routes(routes),
            ListenerRuntime::Http(server) => server.replace_routes(routes),
            ListenerRuntime::Vless(server) => server.replace_routes(routes),
            ListenerRuntime::Vmess(server) => server.replace_routes(routes),
            ListenerRuntime::Trojan(server) => server.replace_routes(routes),
            ListenerRuntime::Shadowsocks(server) => server.replace_routes(routes),
            ListenerRuntime::AnyTls(server) => server.replace_routes(routes),
            ListenerRuntime::Tuic(server) => server.replace_routes(routes),
            ListenerRuntime::Hysteria2(server) => server.replace_routes(routes),
            ListenerRuntime::Mieru(server) => server.replace_routes(routes),
            ListenerRuntime::Naive(server) => server.replace_routes(routes),
        }
    }

    fn apply_user_delta(&self, delta: &CoreUserDelta) -> CoreUserDeltaResult {
        match self {
            ListenerRuntime::Socks(server) => server.apply_user_delta(delta),
            ListenerRuntime::Http(server) => server.apply_user_delta(delta),
            ListenerRuntime::Vless(server) => server.apply_user_delta(delta),
            ListenerRuntime::Vmess(server) => server.apply_user_delta(delta),
            ListenerRuntime::Trojan(server) => server.apply_user_delta(delta),
            ListenerRuntime::Shadowsocks(server) => server.apply_user_delta(delta),
            ListenerRuntime::AnyTls(server) => server.apply_user_delta(delta),
            ListenerRuntime::Tuic(server) => server.apply_user_delta(delta),
            ListenerRuntime::Hysteria2(server) => server.apply_user_delta(delta),
            ListenerRuntime::Mieru(server) => server.apply_user_delta(delta),
            ListenerRuntime::Naive(server) => server.apply_user_delta(delta),
        }
    }
}

impl CoreService {
    pub fn start(config: CoreConfig) -> Result<Self, CoreServiceError> {
        config.validate().map_err(CoreServiceError::InvalidConfig)?;
        validate_unique_listener_binds(&config.inbounds)
            .map_err(CoreServiceError::InvalidConfig)?;
        crate::dns::configure(config.dns.clone());
        let connect_timeout = outbound_connect_timeout(&config.policy);
        let connection_idle = connection_idle_timeout(&config.policy);
        let uplink_only = uplink_only_timeout(&config.policy);
        let downlink_only = downlink_only_timeout(&config.policy);
        let sniffing_cache = sniffing_cache_timeout(&config.policy);
        let active_config = config_without_users(&config);
        let user_fingerprints = user_fingerprints_for_inbounds(&config.inbounds);

        let traffic = TrafficRegistry::shared();
        let sessions = UserSessionTracker::default();
        let bandwidth = UserBandwidthLimiters::default();
        let tls_failures = ClientFailureBackoff::tls_handshake();
        let quic_listener_count = config
            .inbounds
            .iter()
            .filter(|inbound| inbound_binds_quic(inbound))
            .count();
        let quic_connections = (quic_listener_count > 0)
            .then(|| SharedQuicConnectionLimiter::for_listener_count(quic_listener_count));
        if let Some(limiter) = &quic_connections {
            let snapshot = limiter.snapshot();
            crate::logging::emit_legacy_line(&format!(
                "INFO  core   quic resources auto total={} listeners={} per_listener_soft={} cpu={} mem_limit_mib={} fd_limit={}",
                snapshot.total_limit,
                snapshot.listener_count,
                snapshot.per_listener_soft_limit,
                snapshot.cpu_count,
                snapshot
                    .memory_limit_mib
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "unknown".to_string()),
                snapshot
                    .fd_limit
                    .map(|value| value.to_string())
                    .unwrap_or_else(|| "unknown".to_string())
            ));
        }
        let mut listeners = Vec::new();
        for inbound in config.inbounds {
            let routes = active_config.resolved_inbound_routes(&inbound);
            let handle = match inbound.protocol {
                Protocol::Socks => start_socks_listener(
                    &inbound,
                    routes.clone(),
                    connect_timeout,
                    traffic.clone(),
                    sessions.clone(),
                    bandwidth.clone(),
                )?,
                Protocol::Http => start_http_listener(
                    &inbound,
                    routes.clone(),
                    connect_timeout,
                    traffic.clone(),
                    sessions.clone(),
                    bandwidth.clone(),
                )?,
                Protocol::Vless => start_vless_listener(
                    &inbound,
                    routes.clone(),
                    connect_timeout,
                    connection_idle,
                    uplink_only,
                    downlink_only,
                    traffic.clone(),
                    sessions.clone(),
                    bandwidth.clone(),
                    tls_failures.clone(),
                )?,
                Protocol::Vmess => start_vmess_listener(
                    &inbound,
                    routes.clone(),
                    connect_timeout,
                    traffic.clone(),
                    sessions.clone(),
                    bandwidth.clone(),
                    tls_failures.clone(),
                )?,
                Protocol::Trojan => start_trojan_listener(
                    &inbound,
                    routes.clone(),
                    connect_timeout,
                    connection_idle,
                    uplink_only,
                    downlink_only,
                    sniffing_cache,
                    traffic.clone(),
                    sessions.clone(),
                    bandwidth.clone(),
                    tls_failures.clone(),
                )?,
                Protocol::Shadowsocks => start_shadowsocks_listener(
                    &inbound,
                    routes.clone(),
                    connect_timeout,
                    traffic.clone(),
                    sessions.clone(),
                    bandwidth.clone(),
                )?,
                Protocol::AnyTls => start_anytls_listener(
                    &inbound,
                    routes.clone(),
                    connect_timeout,
                    traffic.clone(),
                    sessions.clone(),
                    bandwidth.clone(),
                    tls_failures.clone(),
                )?,
                Protocol::Tuic => start_tuic_listener(
                    &inbound,
                    routes.clone(),
                    connect_timeout,
                    traffic.clone(),
                    sessions.clone(),
                    bandwidth.clone(),
                    quic_connections
                        .as_ref()
                        .expect("quic limiter should exist for tuic")
                        .clone(),
                )?,
                Protocol::Hysteria2 => start_hysteria2_listener(
                    &inbound,
                    routes.clone(),
                    connect_timeout,
                    traffic.clone(),
                    sessions.clone(),
                    bandwidth.clone(),
                    quic_connections
                        .as_ref()
                        .expect("quic limiter should exist for hysteria2")
                        .clone(),
                )?,
                Protocol::Mieru => start_mieru_listener(
                    &inbound,
                    routes.clone(),
                    connect_timeout,
                    traffic.clone(),
                    sessions.clone(),
                    bandwidth.clone(),
                )?,
                Protocol::Naive => start_naive_listener(
                    &inbound,
                    routes.clone(),
                    connect_timeout,
                    traffic.clone(),
                    sessions.clone(),
                    bandwidth.clone(),
                    tls_failures.clone(),
                    if naive_uses_quic(&inbound) {
                        Some(
                            quic_connections
                                .as_ref()
                                .expect("quic limiter should exist for naive h3")
                                .clone(),
                        )
                    } else {
                        None
                    },
                )?,
            };
            listeners.push(handle);
        }

        Ok(Self {
            config: active_config,
            listeners,
            traffic,
            sessions,
            bandwidth,
            quic_connections,
            tls_failures,
            user_revisions: HashMap::new(),
            user_fingerprints,
            stopped: false,
        })
    }

    pub fn listeners(&self) -> Vec<ListenerStatus> {
        self.listeners
            .iter()
            .map(|handle| handle.status.clone())
            .collect()
    }

    pub fn quic_resource_snapshot(&self) -> Option<QuicResourceSnapshot> {
        self.quic_connections
            .as_ref()
            .map(SharedQuicConnectionLimiter::snapshot)
    }

    pub fn tls_failure_snapshot(&self) -> ClientFailureBackoffSnapshot {
        self.tls_failures.snapshot()
    }

    pub fn tcp_auth_failure_snapshot(&self) -> ClientFailureBackoffSnapshot {
        tcp_auth_failure_backoff().snapshot()
    }

    pub fn drain_traffic(&self, minimum_bytes: u64) -> Vec<TrafficDelta> {
        self.traffic.drain_minimum(minimum_bytes)
    }

    pub fn requeue_traffic(&self, records: Vec<TrafficDelta>) {
        self.traffic.add_deltas(records);
    }

    pub fn apply_device_limit_snapshot(&self, snapshot: DeviceLimitSnapshot) {
        self.sessions.apply_device_limit_snapshot(snapshot);
    }

    pub fn commit_device_limit_report(&self, records: &[DeviceLimitOnlineRecord]) {
        self.sessions.commit_device_limit_report(records);
    }

    pub fn can_update_users(&self, config: &CoreConfig) -> bool {
        config_eq_without_users(&self.config, config)
    }

    pub fn can_update_routes(&self, config: &CoreConfig) -> bool {
        config_eq_without_users_routes_and_outbounds(&self.config, config)
    }

    pub fn update_users(&mut self, config: CoreConfig) {
        for inbound in &config.inbounds {
            if let Some(handle) = self
                .listeners
                .iter()
                .find(|handle| handle.status.tag == inbound.tag)
            {
                let fingerprint = UserFingerprintState::from_users(&inbound.users);
                if self.user_fingerprints.get(&inbound.tag) != Some(&fingerprint) {
                    handle.runtime.replace_users(inbound.users.clone());
                    self.user_revisions.remove(&inbound.tag);
                    self.user_fingerprints
                        .insert(inbound.tag.clone(), fingerprint);
                }
            }
        }
        self.config = config_without_users(&config);
    }

    pub fn update_routes_and_users(&mut self, config: CoreConfig) {
        let active_config = config_without_users(&config);
        for inbound in &config.inbounds {
            if let Some(handle) = self
                .listeners
                .iter()
                .find(|handle| handle.status.tag == inbound.tag)
            {
                let fingerprint = UserFingerprintState::from_users(&inbound.users);
                if self.user_fingerprints.get(&inbound.tag) != Some(&fingerprint) {
                    handle.runtime.replace_users(inbound.users.clone());
                    self.user_revisions.remove(&inbound.tag);
                    self.user_fingerprints
                        .insert(inbound.tag.clone(), fingerprint);
                }
                handle
                    .runtime
                    .replace_routes(active_config.resolved_inbound_routes(inbound));
            }
        }
        self.config = active_config;
    }

    pub fn update_routes(&mut self, config: CoreConfig) {
        let active_config = config_without_users(&config);
        for inbound in &active_config.inbounds {
            if let Some(handle) = self
                .listeners
                .iter()
                .find(|handle| handle.status.tag == inbound.tag)
            {
                handle
                    .runtime
                    .replace_routes(active_config.resolved_inbound_routes(inbound));
            }
        }
        self.config = active_config;
    }

    pub fn apply_user_delta(
        &mut self,
        node_tag: &str,
        delta: &CoreUserDelta,
    ) -> Result<CoreUserDeltaResult, String> {
        let handle = self
            .listeners
            .iter()
            .find(|handle| handle.status.tag == node_tag)
            .ok_or_else(|| format!("unknown inbound node_tag {node_tag}"))?;
        if delta.full.is_none() {
            if let Some(base_revision) = delta.base_revision.as_deref() {
                if let Some(current_revision) = self.user_revisions.get(node_tag) {
                    if current_revision != base_revision {
                        return Err(format!(
                            "revision mismatch for inbound {node_tag}: current {current_revision}, base {base_revision}"
                        ));
                    }
                } else {
                    return Err(format!(
                        "revision mismatch for inbound {node_tag}: current <missing>, base {base_revision}; full snapshot required"
                    ));
                }
            }
        }
        let result = handle.runtime.apply_user_delta(delta);
        self.user_fingerprints
            .entry(node_tag.to_string())
            .or_default()
            .apply_delta(delta);
        if let Some(revision) = delta.revision.as_ref() {
            self.user_revisions
                .insert(node_tag.to_string(), revision.clone());
        } else if delta.full.is_some() {
            self.user_revisions.remove(node_tag);
        }
        Ok(result)
    }

    pub fn stop(&mut self) {
        if self.stopped {
            return;
        }
        self.stopped = true;
        for handle in &self.listeners {
            handle.stop.store(true, Ordering::SeqCst);
            let _ = TcpStream::connect(handle.status.local_addr);
        }
        self.bandwidth.close_all_connections();

        for handle in &mut self.listeners {
            if let Some(join) = handle.join.take() {
                let _ = join.join();
            }
            if !handle
                .workers
                .join_timeout(CONNECTION_WORKER_SHUTDOWN_TIMEOUT)
            {
                let worker_snapshot = format_connection_worker_snapshot(handle.workers.snapshot());
                let relay_snapshot = crate::stream::format_relay_scheduler_metrics(
                    crate::stream::relay_scheduler_metrics_snapshot(),
                );
                crate::logging::emit_legacy_line(&format!(
                    "WARN  core   listener worker shutdown timed out tag={} protocol={:?} {} {}",
                    handle.status.tag, handle.status.protocol, worker_snapshot, relay_snapshot
                ));
            }
        }
    }
}

impl Drop for CoreService {
    fn drop(&mut self) {
        self.stop();
    }
}

fn config_without_users(config: &CoreConfig) -> CoreConfig {
    CoreConfig {
        instance_id: config.instance_id.clone(),
        log_level: config.log_level.clone(),
        dns: config.dns.clone(),
        policy: config.policy.clone(),
        inbounds: config.inbounds.iter().map(inbound_without_users).collect(),
        outbounds: config.outbounds.clone(),
        routes: config.routes.clone(),
        stats: config.stats.clone(),
    }
}

fn inbound_without_users(inbound: &InboundConfig) -> InboundConfig {
    InboundConfig {
        tag: inbound.tag.clone(),
        protocol: inbound.protocol.clone(),
        listen: inbound.listen.clone(),
        port: inbound.port,
        users: Vec::new(),
        cipher: inbound.cipher.clone(),
        flow: inbound.flow.clone(),
        padding_scheme: inbound.padding_scheme.clone(),
        transport: inbound.transport.clone(),
        tls: inbound.tls.clone(),
        sniffing: inbound.sniffing.clone(),
        routes: inbound.routes.clone(),
    }
}

fn config_eq_without_users(left: &CoreConfig, right: &CoreConfig) -> bool {
    left.instance_id == right.instance_id
        && left.log_level == right.log_level
        && left.dns == right.dns
        && left.policy == right.policy
        && left.outbounds == right.outbounds
        && left.routes == right.routes
        && left.stats == right.stats
        && inbounds_eq_without_users(&left.inbounds, &right.inbounds)
}

fn config_eq_without_users_routes_and_outbounds(left: &CoreConfig, right: &CoreConfig) -> bool {
    left.instance_id == right.instance_id
        && left.log_level == right.log_level
        && left.dns == right.dns
        && left.policy == right.policy
        && left.stats == right.stats
        && inbounds_eq_without_users_routes(&left.inbounds, &right.inbounds)
}

fn inbounds_eq_without_users(left: &[InboundConfig], right: &[InboundConfig]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right.iter())
            .all(|(left, right)| inbound_eq_without_users(left, right))
}

fn inbounds_eq_without_users_routes(left: &[InboundConfig], right: &[InboundConfig]) -> bool {
    left.len() == right.len()
        && left
            .iter()
            .zip(right.iter())
            .all(|(left, right)| inbound_eq_without_users_routes(left, right))
}

fn inbound_eq_without_users(left: &InboundConfig, right: &InboundConfig) -> bool {
    inbound_eq_without_users_routes(left, right) && left.routes == right.routes
}

fn inbound_eq_without_users_routes(left: &InboundConfig, right: &InboundConfig) -> bool {
    left.tag == right.tag
        && left.protocol == right.protocol
        && left.listen == right.listen
        && left.port == right.port
        && left.cipher == right.cipher
        && left.flow == right.flow
        && left.padding_scheme == right.padding_scheme
        && left.transport == right.transport
        && left.tls == right.tls
        && left.sniffing == right.sniffing
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
struct UserFingerprintState {
    users: HashMap<String, u64>,
}

impl UserFingerprintState {
    fn from_users(users: &[CoreUser]) -> Self {
        Self {
            users: users
                .iter()
                .filter(|user| !user.is_empty())
                .map(|user| (user.uuid.clone(), user_fingerprint(user)))
                .collect(),
        }
    }

    fn apply_delta(&mut self, delta: &CoreUserDelta) {
        if let Some(full) = delta.full.as_ref() {
            *self = Self::from_users(full);
            return;
        }
        for user in delta.added.iter().chain(delta.updated.iter()) {
            if user.is_empty() {
                continue;
            }
            self.users.insert(user.uuid.clone(), user_fingerprint(user));
        }
        for uuid in &delta.deleted {
            self.users.remove(uuid);
        }
    }
}

fn user_fingerprints_for_inbounds(
    inbounds: &[InboundConfig],
) -> HashMap<String, UserFingerprintState> {
    inbounds
        .iter()
        .map(|inbound| {
            (
                inbound.tag.clone(),
                UserFingerprintState::from_users(&inbound.users),
            )
        })
        .collect()
}

fn user_fingerprint(user: &CoreUser) -> u64 {
    let mut hasher = std::collections::hash_map::DefaultHasher::new();
    user.id.hash(&mut hasher);
    user.uuid.hash(&mut hasher);
    user.password.hash(&mut hasher);
    user.email.hash(&mut hasher);
    user.speed_limit.hash(&mut hasher);
    user.device_limit.hash(&mut hasher);
    hasher.finish()
}

fn outbound_connect_timeout(policy: &PolicyConfig) -> Duration {
    outbound_connect_timeout_from_env(
        std::env::var("KELI_CORE_OUTBOUND_CONNECT_TIMEOUT_SECS").ok(),
        policy.connect_timeout_secs,
    )
}

fn connection_idle_timeout(policy: &PolicyConfig) -> Duration {
    Duration::from_secs(policy.connection_idle_secs.max(1))
}

fn uplink_only_timeout(policy: &PolicyConfig) -> Duration {
    Duration::from_secs(policy.uplink_only_secs.max(1))
}

fn downlink_only_timeout(policy: &PolicyConfig) -> Duration {
    Duration::from_secs(policy.downlink_only_secs.max(1))
}

fn sniffing_cache_timeout(policy: &PolicyConfig) -> Duration {
    Duration::from_millis(policy.sniffing_cache_millis.max(1))
}

fn outbound_connect_timeout_from_env(value: Option<String>, default_secs: u64) -> Duration {
    value
        .as_deref()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|seconds| *seconds > 0)
        .map(|seconds| Duration::from_secs(seconds.clamp(1, 60)))
        .unwrap_or_else(|| Duration::from_secs(default_secs.clamp(1, 60)))
}

fn start_grpc_transport_listener(
    inbound: &InboundConfig,
    protocol: Protocol,
    handler: GrpcStreamHandler,
    listener_runtime: ListenerRuntime,
) -> Result<ListenerHandle, CoreServiceError> {
    let listen = resolve_listen_addr(&inbound.listen, inbound.port).map_err(|source| {
        CoreServiceError::Bind {
            tag: inbound.tag.clone(),
            source,
        }
    })?;
    let listener =
        bind_dual_stack_tcp_listener(listen).map_err(|source| CoreServiceError::Bind {
            tag: inbound.tag.clone(),
            source,
        })?;
    listener
        .set_nonblocking(true)
        .map_err(|source| CoreServiceError::Bind {
            tag: inbound.tag.clone(),
            source,
        })?;
    let local_addr = listener
        .local_addr()
        .map_err(|source| CoreServiceError::Bind {
            tag: inbound.tag.clone(),
            source,
        })?;
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(quic_runtime_worker_threads())
        .thread_name("keli-core-hysteria2")
        .enable_all()
        .build()
        .map_err(|source| CoreServiceError::Bind {
            tag: inbound.tag.clone(),
            source,
        })?;
    let listener = {
        let _guard = runtime.enter();
        tokio::net::TcpListener::from_std(listener).map_err(|source| CoreServiceError::Bind {
            tag: inbound.tag.clone(),
            source,
        })?
    };
    let tls = inbound.tls.as_ref().map(|tls| GrpcTlsConfig {
        cert_file: tls.cert_file.clone().unwrap_or_default(),
        key_file: tls.key_file.clone().unwrap_or_default(),
        server_name: tls.server_name.clone(),
        alpn: tls.alpn.clone(),
        reject_unknown_sni: tls.reject_unknown_sni,
    });
    let service_name = inbound
        .transport
        .service_name
        .clone()
        .unwrap_or_else(|| "GunService".to_string());
    let stop = Arc::new(AtomicBool::new(false));
    let stop_for_thread = stop.clone();
    let workers = ConnectionWorkerGroup::new();
    let join = thread::spawn(move || {
        let _ = runtime.block_on(run_grpc_listener(
            listener,
            stop_for_thread,
            service_name,
            tls,
            handler,
        ));
    });

    Ok(ListenerHandle {
        status: ListenerStatus {
            tag: inbound.tag.clone(),
            protocol,
            local_addr,
        },
        runtime: listener_runtime,
        stop,
        workers,
        join: Some(join),
    })
}

fn start_vmess_listener(
    inbound: &InboundConfig,
    routes: Vec<crate::RouteRule>,
    connect_timeout: Duration,
    traffic: SharedTrafficRegistry,
    sessions: UserSessionTracker,
    bandwidth: UserBandwidthLimiters,
    tls_failures: ClientFailureBackoff,
) -> Result<ListenerHandle, CoreServiceError> {
    let listen = resolve_listen_addr(&inbound.listen, inbound.port).map_err(|source| {
        CoreServiceError::Bind {
            tag: inbound.tag.clone(),
            source,
        }
    })?;
    let server = VmessServer::with_shared_limits(
        VmessServerConfig {
            node_tag: inbound.tag.clone(),
            listen,
            users: inbound.users.clone(),
            routes,
            connect_timeout,
        },
        traffic,
        sessions,
        bandwidth,
    );
    if inbound.transport.network.trim() == "grpc" {
        let grpc_server = server.clone();
        let handler: GrpcStreamHandler =
            Arc::new(move |reader: GrpcHunkReader, writer: GrpcHunkWriter| {
                if let Err(error) = grpc_server.handle_split_client(reader, writer) {
                    eprintln!("vmess grpc stream failed: {error}");
                }
            });
        return start_grpc_transport_listener(
            inbound,
            Protocol::Vmess,
            handler,
            ListenerRuntime::Vmess(server),
        );
    }
    let listener =
        bind_dual_stack_tcp_listener(listen).map_err(|source| CoreServiceError::Bind {
            tag: inbound.tag.clone(),
            source,
        })?;
    listener
        .set_nonblocking(true)
        .map_err(|source| CoreServiceError::Bind {
            tag: inbound.tag.clone(),
            source,
        })?;
    let local_addr = listener
        .local_addr()
        .map_err(|source| CoreServiceError::Bind {
            tag: inbound.tag.clone(),
            source,
        })?;
    let stop = Arc::new(AtomicBool::new(false));
    let stop_for_thread = stop.clone();
    let workers = ConnectionWorkerGroup::new();
    let workers_for_thread = workers.clone();
    let network = inbound.transport.network.trim().to_string();
    let websocket_path = inbound.transport.path.clone();
    let httpupgrade_host = inbound.transport.host.clone();
    let tls_acceptor = tls_acceptor_for(inbound)?;
    let tag = inbound.tag.clone();
    let runtime_server = server.clone();
    let join = spawn_tcp_accept_loop(
        listener,
        stop_for_thread,
        workers_for_thread,
        move |stream| {
            let server = server.clone();
            let network = network.clone();
            let websocket_path = websocket_path.clone();
            let httpupgrade_host = httpupgrade_host.clone();
            let tls_acceptor = tls_acceptor.clone();
            let tls_failures = tls_failures.clone();
            let tag = tag.clone();
            let _ = handle_tcp_connection_with_failure_backoff(stream, move |stream| {
                if let Some(acceptor) = tls_acceptor {
                    accept_tls_connection(
                        &acceptor,
                        stream,
                        Protocol::Vmess,
                        &tag,
                        &tls_failures,
                        connect_timeout,
                    )
                    .and_then(|client| match network.as_str() {
                        "ws" => {
                            server.handle_tls_websocket_client(client, websocket_path.as_deref())
                        }
                        "httpupgrade" => accept_httpupgrade_tls(
                            client,
                            websocket_path.as_deref(),
                            httpupgrade_host.as_deref(),
                        )
                        .and_then(|client| server.handle_tls_client(client)),
                        _ => server.handle_tls_client(client),
                    })
                } else if network == "ws" {
                    server.handle_websocket_client(stream, websocket_path.as_deref())
                } else if network == "httpupgrade" {
                    accept_httpupgrade(
                        stream,
                        websocket_path.as_deref(),
                        httpupgrade_host.as_deref(),
                    )
                    .and_then(|stream| server.handle_tcp_client(stream))
                } else {
                    server.handle_tcp_client(stream)
                }
            });
        },
    );

    Ok(ListenerHandle {
        status: ListenerStatus {
            tag: inbound.tag.clone(),
            protocol: Protocol::Vmess,
            local_addr,
        },
        runtime: ListenerRuntime::Vmess(runtime_server),
        stop,
        workers,
        join: Some(join),
    })
}

fn start_hysteria2_listener(
    inbound: &InboundConfig,
    routes: Vec<crate::RouteRule>,
    connect_timeout: Duration,
    traffic: SharedTrafficRegistry,
    sessions: UserSessionTracker,
    bandwidth: UserBandwidthLimiters,
    quic_connections: SharedQuicConnectionLimiter,
) -> Result<ListenerHandle, CoreServiceError> {
    let listen = resolve_listen_addr(&inbound.listen, inbound.port).map_err(|source| {
        CoreServiceError::Bind {
            tag: inbound.tag.clone(),
            source,
        }
    })?;
    let tls = inbound.tls.as_ref().ok_or_else(|| CoreServiceError::Bind {
        tag: inbound.tag.clone(),
        source: io::Error::new(io::ErrorKind::InvalidInput, "hysteria2 requires tls config"),
    })?;
    let server = Hysteria2Server::with_shared_limits_and_quic(
        Hysteria2ServerConfig {
            node_tag: inbound.tag.clone(),
            listen,
            users: inbound.users.clone(),
            routes,
            cert_file: tls.cert_file.clone().unwrap_or_default(),
            key_file: tls.key_file.clone().unwrap_or_default(),
            server_name: tls.server_name.clone(),
            alpn: tls.alpn.clone(),
            reject_unknown_sni: tls.reject_unknown_sni,
            connect_timeout,
            up_mbps: inbound.transport.up_mbps,
            down_mbps: inbound.transport.down_mbps,
            ignore_client_bandwidth: inbound.transport.ignore_client_bandwidth,
            congestion_control: inbound.transport.congestion_control.clone(),
            obfs: hysteria2_obfs_config(&inbound.transport),
        },
        traffic,
        sessions,
        bandwidth,
        quic_connections,
    );
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(quic_runtime_worker_threads())
        .thread_name("keli-core-hysteria2")
        .enable_all()
        .build()
        .map_err(|source| CoreServiceError::Bind {
            tag: inbound.tag.clone(),
            source,
        })?;
    let endpoint = {
        let _guard = runtime.enter();
        server.bind().map_err(|source| CoreServiceError::Bind {
            tag: inbound.tag.clone(),
            source,
        })?
    };
    let local_addr = endpoint
        .local_addr()
        .map_err(|source| CoreServiceError::Bind {
            tag: inbound.tag.clone(),
            source,
        })?;

    let stop = Arc::new(AtomicBool::new(false));
    let stop_for_thread = stop.clone();
    let workers = ConnectionWorkerGroup::new();
    let runtime_server = server.clone();
    let join = thread::spawn(move || {
        runtime.block_on(server.run(endpoint, stop_for_thread));
        runtime.shutdown_timeout(QUIC_RUNTIME_SHUTDOWN_TIMEOUT);
    });

    Ok(ListenerHandle {
        status: ListenerStatus {
            tag: inbound.tag.clone(),
            protocol: Protocol::Hysteria2,
            local_addr,
        },
        runtime: ListenerRuntime::Hysteria2(runtime_server),
        stop,
        workers,
        join: Some(join),
    })
}

fn hysteria2_obfs_config(transport: &TransportConfig) -> Option<Hysteria2ObfsConfig> {
    let kind = transport.obfs.as_deref().unwrap_or("").trim();
    let password = transport.obfs_password.as_deref().unwrap_or("").trim();
    if kind.is_empty() && password.is_empty() {
        return None;
    }
    Some(Hysteria2ObfsConfig {
        kind: kind.to_string(),
        password: password.to_string(),
    })
}

fn start_tuic_listener(
    inbound: &InboundConfig,
    routes: Vec<crate::RouteRule>,
    connect_timeout: Duration,
    traffic: SharedTrafficRegistry,
    sessions: UserSessionTracker,
    bandwidth: UserBandwidthLimiters,
    quic_connections: SharedQuicConnectionLimiter,
) -> Result<ListenerHandle, CoreServiceError> {
    let listen = resolve_listen_addr(&inbound.listen, inbound.port).map_err(|source| {
        CoreServiceError::Bind {
            tag: inbound.tag.clone(),
            source,
        }
    })?;
    let tls = inbound.tls.as_ref().ok_or_else(|| CoreServiceError::Bind {
        tag: inbound.tag.clone(),
        source: io::Error::new(io::ErrorKind::InvalidInput, "tuic requires tls config"),
    })?;
    let server = TuicServer::with_shared_limits_and_quic(
        TuicServerConfig {
            node_tag: inbound.tag.clone(),
            listen,
            users: inbound.users.clone(),
            routes,
            cert_file: tls.cert_file.clone().unwrap_or_default(),
            key_file: tls.key_file.clone().unwrap_or_default(),
            server_name: tls.server_name.clone(),
            alpn: tls.alpn.clone(),
            reject_unknown_sni: tls.reject_unknown_sni,
            congestion_control: inbound.transport.congestion_control.clone(),
            connect_timeout,
        },
        traffic,
        sessions,
        bandwidth,
        quic_connections,
    );
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(quic_runtime_worker_threads())
        .thread_name("keli-core-tuic")
        .enable_all()
        .build()
        .map_err(|source| CoreServiceError::Bind {
            tag: inbound.tag.clone(),
            source,
        })?;
    let endpoint = {
        let _guard = runtime.enter();
        server.bind().map_err(|source| CoreServiceError::Bind {
            tag: inbound.tag.clone(),
            source,
        })?
    };
    let local_addr = endpoint
        .local_addr()
        .map_err(|source| CoreServiceError::Bind {
            tag: inbound.tag.clone(),
            source,
        })?;

    let stop = Arc::new(AtomicBool::new(false));
    let stop_for_thread = stop.clone();
    let workers = ConnectionWorkerGroup::new();
    let runtime_server = server.clone();
    let join = thread::spawn(move || {
        runtime.block_on(server.run(endpoint, stop_for_thread));
        runtime.shutdown_timeout(QUIC_RUNTIME_SHUTDOWN_TIMEOUT);
    });

    Ok(ListenerHandle {
        status: ListenerStatus {
            tag: inbound.tag.clone(),
            protocol: Protocol::Tuic,
            local_addr,
        },
        runtime: ListenerRuntime::Tuic(runtime_server),
        stop,
        workers,
        join: Some(join),
    })
}

fn start_anytls_listener(
    inbound: &InboundConfig,
    routes: Vec<crate::RouteRule>,
    connect_timeout: Duration,
    traffic: SharedTrafficRegistry,
    sessions: UserSessionTracker,
    bandwidth: UserBandwidthLimiters,
    tls_failures: ClientFailureBackoff,
) -> Result<ListenerHandle, CoreServiceError> {
    let listen = resolve_listen_addr(&inbound.listen, inbound.port).map_err(|source| {
        CoreServiceError::Bind {
            tag: inbound.tag.clone(),
            source,
        }
    })?;
    let server = AnyTlsServer::with_shared_limits(
        AnyTlsServerConfig {
            node_tag: inbound.tag.clone(),
            listen,
            users: inbound.users.clone(),
            routes,
            connect_timeout,
            padding_scheme: inbound.padding_scheme.clone(),
        },
        traffic,
        sessions,
        bandwidth,
    );
    let listener =
        bind_dual_stack_tcp_listener(listen).map_err(|source| CoreServiceError::Bind {
            tag: inbound.tag.clone(),
            source,
        })?;
    listener
        .set_nonblocking(true)
        .map_err(|source| CoreServiceError::Bind {
            tag: inbound.tag.clone(),
            source,
        })?;
    let local_addr = listener
        .local_addr()
        .map_err(|source| CoreServiceError::Bind {
            tag: inbound.tag.clone(),
            source,
        })?;
    let stop = Arc::new(AtomicBool::new(false));
    let stop_for_thread = stop.clone();
    let workers = ConnectionWorkerGroup::new();
    let workers_for_thread = workers.clone();
    let tls_acceptor = tls_acceptor_for(inbound)?;
    let tag = inbound.tag.clone();
    let runtime_server = server.clone();
    let join = spawn_tcp_accept_loop(
        listener,
        stop_for_thread,
        workers_for_thread,
        move |stream| {
            let server = server.clone();
            let tls_acceptor = tls_acceptor.clone();
            let tls_failures = tls_failures.clone();
            let tag = tag.clone();
            let _ = handle_tcp_connection_with_failure_backoff(stream, move |stream| {
                if let Some(acceptor) = tls_acceptor {
                    accept_tls_connection(
                        &acceptor,
                        stream,
                        Protocol::AnyTls,
                        &tag,
                        &tls_failures,
                        connect_timeout,
                    )
                    .and_then(local_bridge_for_tls)
                    .and_then(|stream| server.handle_tcp_client(stream))
                } else {
                    server.handle_tcp_client(stream)
                }
            });
        },
    );

    Ok(ListenerHandle {
        status: ListenerStatus {
            tag: inbound.tag.clone(),
            protocol: Protocol::AnyTls,
            local_addr,
        },
        runtime: ListenerRuntime::AnyTls(runtime_server),
        stop,
        workers,
        join: Some(join),
    })
}

fn local_bridge_for_tls(tls: TlsConnection) -> io::Result<TcpStream> {
    let local_listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0)))?;
    let local_addr = local_listener.local_addr()?;
    let local_client = TcpStream::connect(local_addr)?;
    let (local_plain, _) = local_listener.accept()?;

    let _ = crate::stream::spawn_named_native_blocking_relay("keli-core-tls-bridge", move || {
        let _ = relay_tls_stream(tls, local_plain, None);
    })?;

    Ok(local_client)
}

fn accept_tls_connection(
    acceptor: &TlsAcceptor,
    stream: TcpStream,
    protocol: Protocol,
    tag: &str,
    failures: &ClientFailureBackoff,
    connect_timeout: Duration,
) -> io::Result<TlsConnection> {
    let peer_ip = stream.peer_addr().ok().map(|addr| addr.ip());
    if let Some(ip) = peer_ip {
        if failures.is_blocked(ip) {
            let _ = stream.shutdown(std::net::Shutdown::Both);
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "tls handshake backoff active",
            ));
        }
    }
    match acceptor.accept_with_timeout(stream, connect_timeout) {
        Ok(client) => {
            if let Some(ip) = peer_ip {
                failures.record_success(ip);
            }
            Ok(client)
        }
        Err(error) => {
            let class = classify_tls_handshake_error(&error);
            if !matches!(class, TlsHandshakeErrorClass::ClientClosed) {
                if let Some(ip) = peer_ip {
                    failures.record_failure(ip);
                }
                crate::logging::emit_legacy_line(&format!(
                    "WARN  tls    handshake failed protocol={protocol:?} tag={tag} class={class:?} error={error}"
                ));
            }
            Err(error)
        }
    }
}

async fn accept_tls_connection_async(
    acceptor: &TlsAcceptor,
    stream: tokio::net::TcpStream,
    protocol: Protocol,
    tag: &str,
    failures: &ClientFailureBackoff,
    connect_timeout: Duration,
) -> io::Result<(
    tokio_rustls::server::TlsStream<tokio::net::TcpStream>,
    Option<std::net::IpAddr>,
)> {
    let peer_ip = stream.peer_addr().ok().map(|addr| addr.ip());
    if let Some(ip) = peer_ip {
        if failures.is_blocked(ip) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "tls handshake backoff active",
            ));
        }
    }
    let tls_acceptor = tokio_rustls::TlsAcceptor::from(acceptor.server_config());
    match tokio::time::timeout(connect_timeout, tls_acceptor.accept(stream)).await {
        Ok(Ok(client)) => {
            if let Some(ip) = peer_ip {
                failures.record_success(ip);
            }
            Ok((client, peer_ip))
        }
        Ok(Err(error)) => {
            let class = classify_tls_handshake_error(&error);
            if !matches!(class, TlsHandshakeErrorClass::ClientClosed) {
                if let Some(ip) = peer_ip {
                    failures.record_failure(ip);
                }
                crate::logging::emit_legacy_line(&format!(
                    "WARN  tls    handshake failed protocol={protocol:?} tag={tag} class={class:?} error={error}"
                ));
            }
            Err(error)
        }
        Err(_) => {
            let error = io::Error::new(io::ErrorKind::TimedOut, "tls handshake timed out");
            if let Some(ip) = peer_ip {
                failures.record_failure(ip);
            }
            crate::logging::emit_legacy_line(&format!(
                "WARN  tls    handshake failed protocol={protocol:?} tag={tag} class={:?} error={error}",
                TlsHandshakeErrorClass::Io
            ));
            Err(error)
        }
    }
}

fn handle_tcp_connection_with_failure_backoff<F>(stream: TcpStream, handler: F) -> io::Result<()>
where
    F: FnOnce(TcpStream) -> io::Result<()>,
{
    let peer_ip = stream.peer_addr().ok().map(|addr| addr.ip());
    let failures = tcp_auth_failure_backoff();
    if let Some(ip) = peer_ip {
        if failures.is_blocked(ip) {
            let _ = stream.shutdown(std::net::Shutdown::Both);
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "tcp auth backoff active",
            ));
        }
    }
    let result = handler(stream);
    match result {
        Ok(()) => {
            if let Some(ip) = peer_ip {
                failures.record_success(ip);
            }
            Ok(())
        }
        Err(error) => {
            if let Some(ip) = peer_ip {
                if should_record_tcp_auth_failure(&error) {
                    failures.record_failure(ip);
                }
            }
            Err(error)
        }
    }
}

async fn handle_tcp_connection_with_failure_backoff_async<F, Fut>(
    stream: tokio::net::TcpStream,
    handler: F,
) -> io::Result<()>
where
    F: FnOnce(tokio::net::TcpStream) -> Fut,
    Fut: Future<Output = io::Result<()>>,
{
    let peer_ip = stream.peer_addr().ok().map(|addr| addr.ip());
    let failures = tcp_auth_failure_backoff();
    if let Some(ip) = peer_ip {
        if failures.is_blocked(ip) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "tcp auth backoff active",
            ));
        }
    }
    let result = handler(stream).await;
    match result {
        Ok(()) => {
            if let Some(ip) = peer_ip {
                failures.record_success(ip);
            }
            Ok(())
        }
        Err(error) => {
            if let Some(ip) = peer_ip {
                if should_record_tcp_auth_failure(&error) {
                    failures.record_failure(ip);
                }
            }
            Err(error)
        }
    }
}

fn tcp_auth_failure_backoff() -> &'static ClientFailureBackoff {
    static BACKOFF: OnceLock<ClientFailureBackoff> = OnceLock::new();
    BACKOFF.get_or_init(ClientFailureBackoff::tcp_auth)
}

fn should_record_tcp_auth_failure(error: &io::Error) -> bool {
    if error.kind() != io::ErrorKind::PermissionDenied {
        return false;
    }
    let text = error.to_string().to_ascii_lowercase();
    if text.contains("target blocked")
        || text.contains("blocked by route")
        || text.contains("route")
        || text.contains("device limit")
    {
        return false;
    }
    text.contains("auth")
        || text.contains("unknown")
        || text.contains("password")
        || text.contains("credential")
        || text.contains("token")
        || text.contains("username")
        || text.contains("replayed")
        || text.contains("user")
}

fn start_shadowsocks_listener(
    inbound: &InboundConfig,
    routes: Vec<crate::RouteRule>,
    connect_timeout: Duration,
    traffic: SharedTrafficRegistry,
    sessions: UserSessionTracker,
    bandwidth: UserBandwidthLimiters,
) -> Result<ListenerHandle, CoreServiceError> {
    let listen = resolve_listen_addr(&inbound.listen, inbound.port).map_err(|source| {
        CoreServiceError::Bind {
            tag: inbound.tag.clone(),
            source,
        }
    })?;
    let server = ShadowsocksServer::with_shared_limits(
        ShadowsocksServerConfig {
            node_tag: inbound.tag.clone(),
            listen,
            method: inbound.cipher.clone().unwrap_or_default(),
            users: inbound.users.clone(),
            routes,
            connect_timeout,
        },
        traffic,
        sessions,
        bandwidth,
    );
    let listener =
        bind_dual_stack_tcp_listener(listen).map_err(|source| CoreServiceError::Bind {
            tag: inbound.tag.clone(),
            source,
        })?;
    listener
        .set_nonblocking(true)
        .map_err(|source| CoreServiceError::Bind {
            tag: inbound.tag.clone(),
            source,
        })?;
    let local_addr = listener
        .local_addr()
        .map_err(|source| CoreServiceError::Bind {
            tag: inbound.tag.clone(),
            source,
        })?;
    let udp = if shadowsocks_udp_enabled(&inbound.transport) {
        let udp = server
            .bind_udp(local_addr)
            .map_err(|source| CoreServiceError::Bind {
                tag: inbound.tag.clone(),
                source,
            })?;
        udp.set_read_timeout(Some(Duration::from_millis(100)))
            .map_err(|source| CoreServiceError::Bind {
                tag: inbound.tag.clone(),
                source,
            })?;
        Some(udp)
    } else {
        None
    };

    let stop = Arc::new(AtomicBool::new(false));
    let stop_for_thread = stop.clone();
    let workers = ConnectionWorkerGroup::new();
    if let Some(udp) = udp {
        let server = server.clone();
        let stop_for_udp = stop.clone();
        if !workers.spawn(move || {
            let _ = server.serve_udp(udp, stop_for_udp);
        }) {
            return Err(CoreServiceError::Bind {
                tag: inbound.tag.clone(),
                source: io::Error::new(
                    io::ErrorKind::Other,
                    "failed to spawn shadowsocks udp worker",
                ),
            });
        }
    }
    let workers_for_thread = workers.clone();
    let runtime_server = server.clone();
    let join = spawn_tcp_accept_loop(
        listener,
        stop_for_thread,
        workers_for_thread,
        move |stream| {
            let server = server.clone();
            let _ = handle_tcp_connection_with_failure_backoff(stream, move |stream| {
                server.handle_tcp_client(stream)
            });
        },
    );

    Ok(ListenerHandle {
        status: ListenerStatus {
            tag: inbound.tag.clone(),
            protocol: Protocol::Shadowsocks,
            local_addr,
        },
        runtime: ListenerRuntime::Shadowsocks(runtime_server),
        stop,
        workers,
        join: Some(join),
    })
}

fn shadowsocks_udp_enabled(transport: &TransportConfig) -> bool {
    transport
        .network
        .split(',')
        .map(str::trim)
        .any(|item| item.eq_ignore_ascii_case("udp"))
}

fn start_trojan_listener(
    inbound: &InboundConfig,
    routes: Vec<crate::RouteRule>,
    connect_timeout: Duration,
    connection_idle: Duration,
    uplink_only: Duration,
    downlink_only: Duration,
    sniffing_cache: Duration,
    traffic: SharedTrafficRegistry,
    sessions: UserSessionTracker,
    bandwidth: UserBandwidthLimiters,
    tls_failures: ClientFailureBackoff,
) -> Result<ListenerHandle, CoreServiceError> {
    let listen = resolve_listen_addr(&inbound.listen, inbound.port).map_err(|source| {
        CoreServiceError::Bind {
            tag: inbound.tag.clone(),
            source,
        }
    })?;
    let server = TrojanServer::with_shared_limits(
        TrojanServerConfig {
            node_tag: inbound.tag.clone(),
            listen,
            users: inbound.users.clone(),
            routes,
            connect_timeout,
            connection_idle,
            uplink_only,
            downlink_only,
            sniffing: inbound.sniffing.clone(),
            sniffing_cache,
        },
        traffic,
        sessions,
        bandwidth,
    );
    if inbound.transport.network.trim() == "grpc" {
        let grpc_server = server.clone();
        let handler: GrpcStreamHandler =
            Arc::new(move |reader: GrpcHunkReader, writer: GrpcHunkWriter| {
                if let Err(error) = grpc_server.handle_split_client(reader, writer) {
                    eprintln!("trojan grpc stream failed: {error}");
                }
            });
        return start_grpc_transport_listener(
            inbound,
            Protocol::Trojan,
            handler,
            ListenerRuntime::Trojan(server),
        );
    }
    let listener =
        bind_dual_stack_tcp_listener(listen).map_err(|source| CoreServiceError::Bind {
            tag: inbound.tag.clone(),
            source,
        })?;
    listener
        .set_nonblocking(true)
        .map_err(|source| CoreServiceError::Bind {
            tag: inbound.tag.clone(),
            source,
        })?;
    let local_addr = listener
        .local_addr()
        .map_err(|source| CoreServiceError::Bind {
            tag: inbound.tag.clone(),
            source,
        })?;

    let stop = Arc::new(AtomicBool::new(false));
    let stop_for_thread = stop.clone();
    let workers = ConnectionWorkerGroup::new();
    let workers_for_thread = workers.clone();
    let network = inbound.transport.network.trim().to_string();
    let websocket_path = inbound.transport.path.clone();
    let httpupgrade_host = inbound.transport.host.clone();
    let tls_acceptor = tls_acceptor_for(inbound)?;
    let tag = inbound.tag.clone();
    let runtime_server = server.clone();
    if let Some(tls_acceptor_async) = tls_acceptor.clone().filter(|_| network == "ws") {
        let join = spawn_async_tcp_accept_loop(
            listener,
            stop_for_thread,
            workers_for_thread,
            move |stream| {
                let server = server.clone();
                let websocket_path = websocket_path.clone();
                let tls_acceptor = tls_acceptor_async.clone();
                let tls_failures = tls_failures.clone();
                let tag = tag.clone();
                async move {
                    let _ = handle_tcp_connection_with_failure_backoff_async(
                        stream,
                        move |stream| async move {
                            let (client, peer_ip) = accept_tls_connection_async(
                                &tls_acceptor,
                                stream,
                                Protocol::Trojan,
                                &tag,
                                &tls_failures,
                                connect_timeout,
                            )
                            .await?;
                            server
                                .handle_tls_websocket_client_async(
                                    client,
                                    peer_ip,
                                    websocket_path.as_deref(),
                                )
                                .await
                        },
                    )
                    .await;
                }
            },
        );

        return Ok(ListenerHandle {
            status: ListenerStatus {
                tag: inbound.tag.clone(),
                protocol: Protocol::Trojan,
                local_addr,
            },
            runtime: ListenerRuntime::Trojan(runtime_server),
            stop,
            workers,
            join: Some(join),
        });
    }
    let join = spawn_tcp_accept_loop(
        listener,
        stop_for_thread,
        workers_for_thread,
        move |stream| {
            let server = server.clone();
            let network = network.clone();
            let websocket_path = websocket_path.clone();
            let httpupgrade_host = httpupgrade_host.clone();
            let tls_acceptor = tls_acceptor.clone();
            let tls_failures = tls_failures.clone();
            let tag = tag.clone();
            let _ = handle_tcp_connection_with_failure_backoff(stream, move |stream| {
                if let Some(acceptor) = tls_acceptor {
                    accept_tls_connection(
                        &acceptor,
                        stream,
                        Protocol::Trojan,
                        &tag,
                        &tls_failures,
                        connect_timeout,
                    )
                    .and_then(|client| match network.as_str() {
                        "ws" => {
                            server.handle_tls_websocket_client(client, websocket_path.as_deref())
                        }
                        "httpupgrade" => accept_httpupgrade_tls(
                            client,
                            websocket_path.as_deref(),
                            httpupgrade_host.as_deref(),
                        )
                        .and_then(|client| server.handle_tls_client(client)),
                        _ => server.handle_tls_client(client),
                    })
                } else if network == "ws" {
                    server.handle_websocket_client(stream, websocket_path.as_deref())
                } else if network == "httpupgrade" {
                    accept_httpupgrade(
                        stream,
                        websocket_path.as_deref(),
                        httpupgrade_host.as_deref(),
                    )
                    .and_then(|stream| server.handle_tcp_client(stream))
                } else {
                    server.handle_tcp_client(stream)
                }
            });
        },
    );

    Ok(ListenerHandle {
        status: ListenerStatus {
            tag: inbound.tag.clone(),
            protocol: Protocol::Trojan,
            local_addr,
        },
        runtime: ListenerRuntime::Trojan(runtime_server),
        stop,
        workers,
        join: Some(join),
    })
}

fn vless_transport_is_tcp(network: &str) -> bool {
    let network = network.trim();
    network.is_empty() || network == "tcp"
}

fn start_vless_listener(
    inbound: &InboundConfig,
    routes: Vec<crate::RouteRule>,
    connect_timeout: Duration,
    connection_idle: Duration,
    uplink_only: Duration,
    downlink_only: Duration,
    traffic: SharedTrafficRegistry,
    sessions: UserSessionTracker,
    bandwidth: UserBandwidthLimiters,
    tls_failures: ClientFailureBackoff,
) -> Result<ListenerHandle, CoreServiceError> {
    let listen = resolve_listen_addr(&inbound.listen, inbound.port).map_err(|source| {
        CoreServiceError::Bind {
            tag: inbound.tag.clone(),
            source,
        }
    })?;
    let server = VlessServer::with_shared_limits(
        VlessServerConfig {
            node_tag: inbound.tag.clone(),
            listen,
            users: inbound.users.clone(),
            routes,
            flow: inbound.flow.clone(),
            connect_timeout,
            connection_idle,
            uplink_only,
            downlink_only,
        },
        traffic,
        sessions,
        bandwidth,
    );
    if inbound.transport.network.trim() == "grpc" {
        let grpc_server = server.clone();
        let handler: GrpcStreamHandler =
            Arc::new(move |reader: GrpcHunkReader, writer: GrpcHunkWriter| {
                if let Err(error) = grpc_server.handle_split_client(reader, writer) {
                    eprintln!("vless grpc stream failed: {error}");
                }
            });
        return start_grpc_transport_listener(
            inbound,
            Protocol::Vless,
            handler,
            ListenerRuntime::Vless(server),
        );
    }
    if inbound
        .tls
        .as_ref()
        .and_then(|tls| tls.reality.as_ref())
        .is_some()
    {
        return start_vless_reality_listener(inbound, listen, server, connect_timeout);
    }
    let listener =
        bind_dual_stack_tcp_listener(listen).map_err(|source| CoreServiceError::Bind {
            tag: inbound.tag.clone(),
            source,
        })?;
    listener
        .set_nonblocking(true)
        .map_err(|source| CoreServiceError::Bind {
            tag: inbound.tag.clone(),
            source,
        })?;
    let local_addr = listener
        .local_addr()
        .map_err(|source| CoreServiceError::Bind {
            tag: inbound.tag.clone(),
            source,
        })?;

    let stop = Arc::new(AtomicBool::new(false));
    let stop_for_thread = stop.clone();
    let workers = ConnectionWorkerGroup::new();
    let workers_for_thread = workers.clone();
    let network = inbound.transport.network.trim().to_string();
    let websocket_path = inbound.transport.path.clone();
    let httpupgrade_host = inbound.transport.host.clone();
    let tls_acceptor = tls_acceptor_for(inbound)?;
    let tag = inbound.tag.clone();
    let runtime_server = server.clone();
    if let Some(tls_acceptor) = tls_acceptor.clone() {
        if network == "ws" {
            let join = spawn_async_tcp_accept_loop(
                listener,
                stop_for_thread,
                workers_for_thread,
                move |stream| {
                    let server = server.clone();
                    let websocket_path = websocket_path.clone();
                    let tls_acceptor = tls_acceptor.clone();
                    let tls_failures = tls_failures.clone();
                    let tag = tag.clone();
                    async move {
                        let _ = handle_tcp_connection_with_failure_backoff_async(
                            stream,
                            move |stream| async move {
                                let (client, peer_ip) = accept_tls_connection_async(
                                    &tls_acceptor,
                                    stream,
                                    Protocol::Vless,
                                    &tag,
                                    &tls_failures,
                                    connect_timeout,
                                )
                                .await?;
                                server
                                    .handle_tls_websocket_client_async(
                                        client,
                                        peer_ip,
                                        websocket_path.as_deref(),
                                    )
                                    .await
                            },
                        )
                        .await;
                    }
                },
            );

            return Ok(ListenerHandle {
                status: ListenerStatus {
                    tag: inbound.tag.clone(),
                    protocol: Protocol::Vless,
                    local_addr,
                },
                runtime: ListenerRuntime::Vless(runtime_server),
                stop,
                workers,
                join: Some(join),
            });
        }
        if vless_transport_is_tcp(&network) && inbound.flow.trim() == "xtls-rprx-vision" {
            let join = spawn_async_tcp_accept_loop(
                listener,
                stop_for_thread,
                workers_for_thread,
                move |stream| {
                    let server = server.clone();
                    let tls_acceptor = tls_acceptor.clone();
                    let tls_failures = tls_failures.clone();
                    let tag = tag.clone();
                    async move {
                        let _ = handle_tcp_connection_with_failure_backoff_async(
                            stream,
                            move |stream| async move {
                                let (client, peer_ip) = accept_tls_connection_async(
                                    &tls_acceptor,
                                    stream,
                                    Protocol::Vless,
                                    &tag,
                                    &tls_failures,
                                    connect_timeout,
                                )
                                .await?;
                                server.handle_tls_client_async(client, peer_ip).await
                            },
                        )
                        .await;
                    }
                },
            );

            return Ok(ListenerHandle {
                status: ListenerStatus {
                    tag: inbound.tag.clone(),
                    protocol: Protocol::Vless,
                    local_addr,
                },
                runtime: ListenerRuntime::Vless(runtime_server),
                stop,
                workers,
                join: Some(join),
            });
        }
    }
    if tls_acceptor.is_none() && vless_transport_is_tcp(&network) {
        let join = spawn_async_tcp_accept_loop(
            listener,
            stop_for_thread,
            workers_for_thread,
            move |stream| {
                let server = server.clone();
                async move {
                    let _ = server.handle_tcp_client_async(stream).await;
                }
            },
        );

        return Ok(ListenerHandle {
            status: ListenerStatus {
                tag: inbound.tag.clone(),
                protocol: Protocol::Vless,
                local_addr,
            },
            runtime: ListenerRuntime::Vless(runtime_server),
            stop,
            workers,
            join: Some(join),
        });
    }

    let join = spawn_tcp_accept_loop(
        listener,
        stop_for_thread,
        workers_for_thread,
        move |stream| {
            let server = server.clone();
            let network = network.clone();
            let websocket_path = websocket_path.clone();
            let httpupgrade_host = httpupgrade_host.clone();
            let tls_acceptor = tls_acceptor.clone();
            let tls_failures = tls_failures.clone();
            let tag = tag.clone();
            let _ = handle_tcp_connection_with_failure_backoff(stream, move |stream| {
                if let Some(acceptor) = tls_acceptor {
                    accept_tls_connection(
                        &acceptor,
                        stream,
                        Protocol::Vless,
                        &tag,
                        &tls_failures,
                        connect_timeout,
                    )
                    .and_then(|client| match network.as_str() {
                        "ws" => {
                            server.handle_tls_websocket_client(client, websocket_path.as_deref())
                        }
                        "httpupgrade" => accept_httpupgrade_tls(
                            client,
                            websocket_path.as_deref(),
                            httpupgrade_host.as_deref(),
                        )
                        .and_then(|client| server.handle_tls_client(client)),
                        _ => server.handle_tls_client(client),
                    })
                } else if network == "ws" {
                    server.handle_websocket_client(stream, websocket_path.as_deref())
                } else if network == "httpupgrade" {
                    accept_httpupgrade(
                        stream,
                        websocket_path.as_deref(),
                        httpupgrade_host.as_deref(),
                    )
                    .and_then(|stream| server.handle_tcp_client(stream))
                } else {
                    server.handle_tcp_client(stream)
                }
            });
        },
    );

    Ok(ListenerHandle {
        status: ListenerStatus {
            tag: inbound.tag.clone(),
            protocol: Protocol::Vless,
            local_addr,
        },
        runtime: ListenerRuntime::Vless(runtime_server),
        stop,
        workers,
        join: Some(join),
    })
}

fn start_socks_listener(
    inbound: &InboundConfig,
    routes: Vec<crate::RouteRule>,
    connect_timeout: Duration,
    traffic: SharedTrafficRegistry,
    sessions: UserSessionTracker,
    bandwidth: UserBandwidthLimiters,
) -> Result<ListenerHandle, CoreServiceError> {
    let listen = resolve_listen_addr(&inbound.listen, inbound.port).map_err(|source| {
        CoreServiceError::Bind {
            tag: inbound.tag.clone(),
            source,
        }
    })?;
    let server = Socks5Server::with_shared_limits(
        Socks5ServerConfig {
            node_tag: inbound.tag.clone(),
            listen,
            users: inbound.users.clone(),
            routes,
            connect_timeout,
        },
        traffic,
        sessions,
        bandwidth,
    );
    let listener =
        bind_dual_stack_tcp_listener(listen).map_err(|source| CoreServiceError::Bind {
            tag: inbound.tag.clone(),
            source,
        })?;
    listener
        .set_nonblocking(true)
        .map_err(|source| CoreServiceError::Bind {
            tag: inbound.tag.clone(),
            source,
        })?;
    let local_addr = listener
        .local_addr()
        .map_err(|source| CoreServiceError::Bind {
            tag: inbound.tag.clone(),
            source,
        })?;

    let stop = Arc::new(AtomicBool::new(false));
    let stop_for_thread = stop.clone();
    let workers = ConnectionWorkerGroup::new();
    let workers_for_thread = workers.clone();
    let runtime_server = server.clone();
    let join = spawn_tcp_accept_loop(
        listener,
        stop_for_thread,
        workers_for_thread,
        move |stream| {
            let server = server.clone();
            let _ = handle_tcp_connection_with_failure_backoff(stream, move |stream| {
                server.handle_tcp_client(stream)
            });
        },
    );

    Ok(ListenerHandle {
        status: ListenerStatus {
            tag: inbound.tag.clone(),
            protocol: Protocol::Socks,
            local_addr,
        },
        runtime: ListenerRuntime::Socks(runtime_server),
        stop,
        workers,
        join: Some(join),
    })
}

fn start_mieru_listener(
    inbound: &InboundConfig,
    routes: Vec<crate::RouteRule>,
    connect_timeout: Duration,
    traffic: SharedTrafficRegistry,
    sessions: UserSessionTracker,
    bandwidth: UserBandwidthLimiters,
) -> Result<ListenerHandle, CoreServiceError> {
    let listen = resolve_listen_addr(&inbound.listen, inbound.port).map_err(|source| {
        CoreServiceError::Bind {
            tag: inbound.tag.clone(),
            source,
        }
    })?;
    let server = MieruServer::with_shared_limits(
        MieruServerConfig {
            node_tag: inbound.tag.clone(),
            listen,
            users: inbound.users.clone(),
            routes,
            connect_timeout,
        },
        traffic,
        sessions,
        bandwidth,
    );
    let listener =
        bind_dual_stack_tcp_listener(listen).map_err(|source| CoreServiceError::Bind {
            tag: inbound.tag.clone(),
            source,
        })?;
    listener
        .set_nonblocking(true)
        .map_err(|source| CoreServiceError::Bind {
            tag: inbound.tag.clone(),
            source,
        })?;
    let local_addr = listener
        .local_addr()
        .map_err(|source| CoreServiceError::Bind {
            tag: inbound.tag.clone(),
            source,
        })?;

    let stop = Arc::new(AtomicBool::new(false));
    let stop_for_thread = stop.clone();
    let workers = ConnectionWorkerGroup::new();
    let workers_for_thread = workers.clone();
    let runtime_server = server.clone();
    let join = spawn_tcp_accept_loop(
        listener,
        stop_for_thread,
        workers_for_thread,
        move |stream| {
            let server = server.clone();
            let _ = handle_tcp_connection_with_failure_backoff(stream, move |stream| {
                server.handle_tcp_client(stream)
            });
        },
    );

    Ok(ListenerHandle {
        status: ListenerStatus {
            tag: inbound.tag.clone(),
            protocol: Protocol::Mieru,
            local_addr,
        },
        runtime: ListenerRuntime::Mieru(runtime_server),
        stop,
        workers,
        join: Some(join),
    })
}

fn start_naive_listener(
    inbound: &InboundConfig,
    routes: Vec<crate::RouteRule>,
    connect_timeout: Duration,
    traffic: SharedTrafficRegistry,
    sessions: UserSessionTracker,
    bandwidth: UserBandwidthLimiters,
    tls_failures: ClientFailureBackoff,
    quic_connections: Option<SharedQuicConnectionLimiter>,
) -> Result<ListenerHandle, CoreServiceError> {
    let listen = resolve_listen_addr(&inbound.listen, inbound.port).map_err(|source| {
        CoreServiceError::Bind {
            tag: inbound.tag.clone(),
            source,
        }
    })?;
    let tls = inbound.tls.as_ref().ok_or_else(|| CoreServiceError::Bind {
        tag: inbound.tag.clone(),
        source: io::Error::new(io::ErrorKind::InvalidInput, "naive requires tls config"),
    })?;
    let mut server = NaiveServer::with_shared_limits_and_backoff(
        NaiveServerConfig {
            node_tag: inbound.tag.clone(),
            listen,
            users: inbound.users.clone(),
            routes,
            cert_file: tls.cert_file.clone().unwrap_or_default(),
            key_file: tls.key_file.clone().unwrap_or_default(),
            server_name: tls.server_name.clone(),
            alpn: tls.alpn.clone(),
            reject_unknown_sni: tls.reject_unknown_sni,
            connect_timeout,
        },
        traffic,
        sessions,
        bandwidth,
        tls_failures,
        tcp_auth_failure_backoff().clone(),
    )
    .map_err(|source| CoreServiceError::Bind {
        tag: inbound.tag.clone(),
        source,
    })?;
    if let Some(quic_connections) = quic_connections {
        server = server.with_quic_connection_limiter(quic_connections);
    }
    if naive_uses_quic(inbound) {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(quic_runtime_worker_threads())
            .thread_name("keli-core-naive-quic")
            .enable_all()
            .build()
            .map_err(|source| CoreServiceError::Bind {
                tag: inbound.tag.clone(),
                source,
            })?;
        let endpoint = {
            let _guard = runtime.enter();
            server
                .bind_quic()
                .map_err(|source| CoreServiceError::Bind {
                    tag: inbound.tag.clone(),
                    source,
                })?
        };
        let local_addr = endpoint
            .local_addr()
            .map_err(|source| CoreServiceError::Bind {
                tag: inbound.tag.clone(),
                source,
            })?;
        let stop = Arc::new(AtomicBool::new(false));
        let stop_for_thread = stop.clone();
        let workers = ConnectionWorkerGroup::new();
        let runtime_server = server.clone();
        let join = thread::Builder::new()
            .name("keli-core-naive-quic".to_string())
            .spawn(move || {
                runtime.block_on(server.run_quic(endpoint, stop_for_thread));
                runtime.shutdown_timeout(QUIC_RUNTIME_SHUTDOWN_TIMEOUT);
            })
            .map_err(|source| CoreServiceError::Bind {
                tag: inbound.tag.clone(),
                source,
            })?;

        return Ok(ListenerHandle {
            status: ListenerStatus {
                tag: inbound.tag.clone(),
                protocol: Protocol::Naive,
                local_addr,
            },
            runtime: ListenerRuntime::Naive(runtime_server),
            stop,
            workers,
            join: Some(join),
        });
    }
    let listener = server.bind().map_err(|source| CoreServiceError::Bind {
        tag: inbound.tag.clone(),
        source,
    })?;
    listener
        .set_nonblocking(true)
        .map_err(|source| CoreServiceError::Bind {
            tag: inbound.tag.clone(),
            source,
        })?;
    let local_addr = listener
        .local_addr()
        .map_err(|source| CoreServiceError::Bind {
            tag: inbound.tag.clone(),
            source,
        })?;

    let stop = Arc::new(AtomicBool::new(false));
    let stop_for_thread = stop.clone();
    let workers = ConnectionWorkerGroup::new();
    let workers_for_thread = workers.clone();
    let runtime_server = server.clone();
    let join = spawn_async_tcp_accept_loop(
        listener,
        stop_for_thread,
        workers_for_thread,
        move |stream| {
            let server = server.clone();
            async move {
                let _ = server.handle_tcp_client(stream).await;
            }
        },
    );

    Ok(ListenerHandle {
        status: ListenerStatus {
            tag: inbound.tag.clone(),
            protocol: Protocol::Naive,
            local_addr,
        },
        runtime: ListenerRuntime::Naive(runtime_server),
        stop,
        workers,
        join: Some(join),
    })
}

fn start_http_listener(
    inbound: &InboundConfig,
    routes: Vec<crate::RouteRule>,
    connect_timeout: Duration,
    traffic: SharedTrafficRegistry,
    sessions: UserSessionTracker,
    bandwidth: UserBandwidthLimiters,
) -> Result<ListenerHandle, CoreServiceError> {
    let listen = resolve_listen_addr(&inbound.listen, inbound.port).map_err(|source| {
        CoreServiceError::Bind {
            tag: inbound.tag.clone(),
            source,
        }
    })?;
    let server = HttpProxyServer::with_shared_limits(
        HttpProxyServerConfig {
            node_tag: inbound.tag.clone(),
            listen,
            users: inbound.users.clone(),
            routes,
            connect_timeout,
        },
        traffic,
        sessions,
        bandwidth,
    );
    let listener =
        bind_dual_stack_tcp_listener(listen).map_err(|source| CoreServiceError::Bind {
            tag: inbound.tag.clone(),
            source,
        })?;
    listener
        .set_nonblocking(true)
        .map_err(|source| CoreServiceError::Bind {
            tag: inbound.tag.clone(),
            source,
        })?;
    let local_addr = listener
        .local_addr()
        .map_err(|source| CoreServiceError::Bind {
            tag: inbound.tag.clone(),
            source,
        })?;

    let stop = Arc::new(AtomicBool::new(false));
    let stop_for_thread = stop.clone();
    let workers = ConnectionWorkerGroup::new();
    let workers_for_thread = workers.clone();
    let runtime_server = server.clone();
    let join = spawn_tcp_accept_loop(
        listener,
        stop_for_thread,
        workers_for_thread,
        move |stream| {
            let server = server.clone();
            let _ = handle_tcp_connection_with_failure_backoff(stream, move |stream| {
                server.handle_tcp_client(stream)
            });
        },
    );

    Ok(ListenerHandle {
        status: ListenerStatus {
            tag: inbound.tag.clone(),
            protocol: Protocol::Http,
            local_addr,
        },
        runtime: ListenerRuntime::Http(runtime_server),
        stop,
        workers,
        join: Some(join),
    })
}

fn start_vless_reality_listener(
    inbound: &InboundConfig,
    listen: SocketAddr,
    server: VlessServer,
    connect_timeout: Duration,
) -> Result<ListenerHandle, CoreServiceError> {
    let gateway = reality_gateway_config(inbound, connect_timeout)?;
    let listener =
        bind_dual_stack_tcp_listener(listen).map_err(|source| CoreServiceError::Bind {
            tag: inbound.tag.clone(),
            source,
        })?;
    listener
        .set_nonblocking(true)
        .map_err(|source| CoreServiceError::Bind {
            tag: inbound.tag.clone(),
            source,
        })?;
    let local_addr = listener
        .local_addr()
        .map_err(|source| CoreServiceError::Bind {
            tag: inbound.tag.clone(),
            source,
        })?;

    let stop = Arc::new(AtomicBool::new(false));
    let stop_for_thread = stop.clone();
    let workers = ConnectionWorkerGroup::new();
    let workers_for_thread = workers.clone();
    let runtime_server = server.clone();
    let join = spawn_tcp_accept_loop(
        listener,
        stop_for_thread,
        workers_for_thread,
        move |stream| {
            let gateway = reality_gateway_for_connection(&gateway);
            let server = server.clone();
            handle_vless_reality_connection(stream, gateway, server, connect_timeout);
        },
    );

    Ok(ListenerHandle {
        status: ListenerStatus {
            tag: inbound.tag.clone(),
            protocol: Protocol::Vless,
            local_addr,
        },
        runtime: ListenerRuntime::Vless(runtime_server),
        stop,
        workers,
        join: Some(join),
    })
}

fn handle_vless_reality_connection(
    stream: TcpStream,
    gateway: RealityGatewayConfig,
    server: VlessServer,
    connect_timeout: Duration,
) {
    let trace = reality_trace_enabled();
    let peer = stream
        .peer_addr()
        .map(|addr| addr.to_string())
        .unwrap_or_else(|_| "<unknown>".to_string());
    if trace {
        eprintln!("keli-core-rs reality trace: accepted peer={peer}");
    }
    let handshake_timeout = connect_timeout;
    let _ = stream.set_read_timeout(Some(handshake_timeout));
    let _ = stream.set_write_timeout(Some(handshake_timeout));
    let result = handle_reality_preface(stream, &gateway);
    match result {
        Ok(RealityGatewayResult::Authenticated(authenticated)) => {
            if trace {
                eprintln!(
                    "keli-core-rs reality trace: authenticated peer={peer} sni={}",
                    authenticated.auth.server_name
                );
            }
            let acceptor = match reality_tls_acceptor(
                &authenticated.auth.auth_key,
                &authenticated.auth.server_name,
            ) {
                Ok(acceptor) => acceptor,
                Err(error) => {
                    if trace {
                        eprintln!(
                            "keli-core-rs reality trace: certificate error peer={peer} error={error}"
                        );
                    }
                    return;
                }
            };
            let client = match acceptor
                .accept_stream_with_timeout(authenticated.stream, handshake_timeout)
            {
                Ok(client) => {
                    if trace {
                        eprintln!("keli-core-rs reality trace: tls accepted peer={peer}");
                    }
                    client
                }
                Err(error) => {
                    if trace {
                        eprintln!(
                                "keli-core-rs reality trace: tls accept error peer={peer} error={error}"
                            );
                    }
                    return;
                }
            };
            if let Err(error) = server.handle_tls_client(client) {
                if trace {
                    eprintln!("keli-core-rs reality trace: vless error peer={peer} error={error}");
                }
            } else if trace {
                eprintln!("keli-core-rs reality trace: vless finished peer={peer}");
            }
        }
        Ok(RealityGatewayResult::Fallback { reason, .. }) => {
            if trace {
                eprintln!("keli-core-rs reality trace: fallback peer={peer} reason={reason}");
            }
        }
        Err(error) => {
            if trace {
                eprintln!("keli-core-rs reality trace: preface error peer={peer} error={error}");
            }
        }
    }
}

fn reality_gateway_for_connection(template: &RealityGatewayConfig) -> RealityGatewayConfig {
    let mut gateway = template.clone();
    gateway.auth.now = SystemTime::now();
    gateway
}

fn reality_trace_enabled() -> bool {
    std::env::var_os("KELI_CORE_REALITY_TRACE").is_some()
}

fn reality_tls_acceptor(auth_key: &[u8; 32], server_name: &str) -> io::Result<TlsAcceptor> {
    let certificate = generate_reality_temporary_certificate(auth_key, server_name)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
    TlsAcceptor::from_der_reality_ed25519(
        vec![CertificateDer::from(certificate.certificate_der)],
        PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certificate.private_key_der)),
        &[],
    )
}

fn reality_gateway_config(
    inbound: &InboundConfig,
    connect_timeout: Duration,
) -> Result<RealityGatewayConfig, CoreServiceError> {
    let tls = inbound.tls.as_ref().ok_or_else(|| CoreServiceError::Bind {
        tag: inbound.tag.clone(),
        source: io::Error::new(io::ErrorKind::InvalidInput, "vless reality requires tls"),
    })?;
    let reality = tls.reality.as_ref().ok_or_else(|| CoreServiceError::Bind {
        tag: inbound.tag.clone(),
        source: io::Error::new(
            io::ErrorKind::InvalidInput,
            "vless reality requires reality config",
        ),
    })?;
    let private_key = decode_reality_private_key(&reality.private_key).map_err(|error| {
        CoreServiceError::Bind {
            tag: inbound.tag.clone(),
            source: io::Error::new(io::ErrorKind::InvalidInput, error),
        }
    })?;
    let short_id = decode_short_id(&reality.short_id).map_err(|error| CoreServiceError::Bind {
        tag: inbound.tag.clone(),
        source: io::Error::new(io::ErrorKind::InvalidInput, error),
    })?;
    let server_name = tls.server_name.trim().to_string();
    let dest = reality_dest(&reality.dest, reality.server_port);

    Ok(RealityGatewayConfig {
        auth: RealityAuthConfig {
            private_key,
            server_names: std::collections::HashSet::from([server_name]),
            short_ids: std::collections::HashSet::from([short_id]),
            max_time_diff: None,
            now: SystemTime::now(),
        },
        dest,
        connect_timeout,
        probe_dest_on_auth: false,
    })
}

fn reality_dest(dest: &str, server_port: Option<u16>) -> String {
    let dest = dest.trim();
    if has_explicit_port(dest) {
        return dest.to_string();
    }
    match (dest.contains(':'), server_port) {
        (true, Some(port)) => format!("[{dest}]:{port}"),
        (_, Some(port)) => format!("{dest}:{port}"),
        _ => dest.to_string(),
    }
}

fn has_explicit_port(dest: &str) -> bool {
    let dest = dest.trim();
    if let Some(rest) = dest.strip_prefix('[') {
        return rest
            .split_once("]:")
            .and_then(|(_, port)| port.parse::<u16>().ok())
            .is_some();
    }
    if dest.matches(':').count() > 1 {
        return false;
    }
    dest.rsplit_once(':')
        .and_then(|(_, port)| port.parse::<u16>().ok())
        .is_some()
}

#[derive(Debug, Clone)]
struct ConnectionWorkerGroup {
    state: Arc<ConnectionWorkerGroupState>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct ConnectionWorkerGroupSnapshot {
    active_total: usize,
    active_blocking: usize,
    active_async: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ConnectionWorkerKind {
    Blocking,
    Async,
}

#[derive(Debug, Default)]
struct ConnectionWorkerCounts {
    active_blocking: usize,
    active_async: usize,
}

#[derive(Debug)]
struct ConnectionWorkerGroupState {
    counts: Mutex<ConnectionWorkerCounts>,
    finished: Condvar,
}

impl ConnectionWorkerGroup {
    fn new() -> Self {
        Self {
            state: Arc::new(ConnectionWorkerGroupState {
                counts: Mutex::new(ConnectionWorkerCounts::default()),
                finished: Condvar::new(),
            }),
        }
    }

    fn spawn<F>(&self, task: F) -> bool
    where
        F: FnOnce() + Send + 'static,
    {
        if !self.state.acquire(ConnectionWorkerKind::Blocking) {
            return false;
        }

        let state = Arc::clone(&self.state);
        let job = move || {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(task));
            state.release(ConnectionWorkerKind::Blocking);
        };

        if thread::Builder::new()
            .name("keli-core-connection".to_string())
            .stack_size(connection_worker_stack_size())
            .spawn(job)
            .is_ok()
        {
            true
        } else {
            self.state.release(ConnectionWorkerKind::Blocking);
            false
        }
    }

    fn spawn_async<F>(&self, future: F) -> bool
    where
        F: Future<Output = ()> + Send + 'static,
    {
        if !self.state.acquire(ConnectionWorkerKind::Async) {
            return false;
        }

        let guard = ConnectionWorkerAsyncGuard {
            state: Arc::clone(&self.state),
        };
        tokio::spawn(async move {
            let _guard = guard;
            future.await;
        });
        true
    }

    fn join_timeout(&self, timeout: Duration) -> bool {
        self.state.wait_until_idle_timeout(timeout)
    }

    fn snapshot(&self) -> ConnectionWorkerGroupSnapshot {
        self.state.snapshot()
    }
}

fn format_connection_worker_snapshot(snapshot: ConnectionWorkerGroupSnapshot) -> String {
    format!(
        "connection_active_total={} connection_active_blocking={} connection_active_async={}",
        snapshot.active_total, snapshot.active_blocking, snapshot.active_async
    )
}

struct ConnectionWorkerAsyncGuard {
    state: Arc<ConnectionWorkerGroupState>,
}

impl Drop for ConnectionWorkerAsyncGuard {
    fn drop(&mut self) {
        self.state.release(ConnectionWorkerKind::Async);
    }
}

impl ConnectionWorkerGroupState {
    fn acquire(&self, kind: ConnectionWorkerKind) -> bool {
        let mut counts = self.counts.lock().expect("worker group lock poisoned");
        match kind {
            ConnectionWorkerKind::Blocking => counts.active_blocking += 1,
            ConnectionWorkerKind::Async => counts.active_async += 1,
        }
        true
    }

    fn release(&self, kind: ConnectionWorkerKind) {
        let mut counts = self.counts.lock().expect("worker group lock poisoned");
        match kind {
            ConnectionWorkerKind::Blocking => {
                counts.active_blocking = counts.active_blocking.saturating_sub(1);
            }
            ConnectionWorkerKind::Async => {
                counts.active_async = counts.active_async.saturating_sub(1);
            }
        }
        if counts.active_blocking == 0 && counts.active_async == 0 {
            self.finished.notify_all();
        }
    }

    fn snapshot(&self) -> ConnectionWorkerGroupSnapshot {
        let counts = self.counts.lock().expect("worker group lock poisoned");
        ConnectionWorkerGroupSnapshot {
            active_total: counts.active_blocking + counts.active_async,
            active_blocking: counts.active_blocking,
            active_async: counts.active_async,
        }
    }

    fn wait_until_idle_timeout(&self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        let mut counts = self.counts.lock().expect("worker group lock poisoned");
        while counts.active_blocking + counts.active_async > 0 {
            let now = Instant::now();
            if now >= deadline {
                return false;
            }
            let remaining = deadline.saturating_duration_since(now);
            let (next_counts, wait_result) = self
                .finished
                .wait_timeout(counts, remaining)
                .expect("worker group lock poisoned");
            counts = next_counts;
            if wait_result.timed_out() && counts.active_blocking + counts.active_async > 0 {
                return false;
            }
        }
        true
    }
}

fn inbound_binds_quic(inbound: &InboundConfig) -> bool {
    matches!(inbound.protocol, Protocol::Hysteria2 | Protocol::Tuic) || naive_uses_quic(inbound)
}

fn naive_uses_quic(inbound: &InboundConfig) -> bool {
    inbound.protocol == Protocol::Naive
        && (inbound
            .transport
            .network
            .trim()
            .eq_ignore_ascii_case("quic")
            || inbound.tls.as_ref().is_some_and(|tls| {
                tls.alpn
                    .iter()
                    .any(|value| value.trim().eq_ignore_ascii_case("h3"))
            }))
}

fn connection_worker_stack_size() -> usize {
    connection_worker_stack_size_from_env(
        std::env::var("KELI_CORE_CONNECTION_WORKER_STACK_KIB").ok(),
    )
}

fn connection_worker_stack_size_from_env(value: Option<String>) -> usize {
    let stack_kib = value
        .and_then(|value| value.trim().parse::<usize>().ok())
        .unwrap_or(DEFAULT_CONNECTION_WORKER_STACK_KIB)
        .clamp(
            MIN_CONNECTION_WORKER_STACK_KIB,
            MAX_CONNECTION_WORKER_STACK_KIB,
        );
    stack_kib * 1024
}

fn spawn_connection_worker<F>(workers: &ConnectionWorkerGroup, task: F) -> bool
where
    F: FnOnce() + Send + 'static,
{
    workers.spawn(task)
}

fn spawn_async_connection_worker<F>(workers: &ConnectionWorkerGroup, future: F) -> bool
where
    F: Future<Output = ()> + Send + 'static,
{
    workers.spawn_async(future)
}

fn spawn_tcp_accept_loop<F>(
    listener: TcpListener,
    stop: Arc<AtomicBool>,
    workers: ConnectionWorkerGroup,
    handler: F,
) -> JoinHandle<()>
where
    F: Fn(TcpStream) + Send + Sync + 'static,
{
    let handler = Arc::new(handler);
    thread::Builder::new()
        .name("keli-core-tcp-accept".to_string())
        .spawn(move || {
            let Ok(runtime) = tcp_accept_runtime() else {
                return;
            };
            let _ = runtime.block_on(async move {
                let listener = tokio::net::TcpListener::from_std(listener)?;
                while !stop.load(Ordering::SeqCst) {
                    match tokio::time::timeout(Duration::from_millis(100), listener.accept()).await
                    {
                        Ok(Ok((stream, _))) => {
                            if stop.load(Ordering::SeqCst) {
                                break;
                            }
                            if let Ok(stream) = stream.into_std() {
                                let _ = stream.set_nonblocking(false);
                                let _ = stream.set_nodelay(true);
                                let handler = Arc::clone(&handler);
                                spawn_connection_worker(&workers, move || handler(stream));
                            }
                        }
                        Ok(Err(_)) => break,
                        Err(_) => {}
                    }
                }
                Ok::<(), io::Error>(())
            });
        })
        .expect("failed to spawn tcp accept thread")
}

fn spawn_async_tcp_accept_loop<F, Fut>(
    listener: TcpListener,
    stop: Arc<AtomicBool>,
    workers: ConnectionWorkerGroup,
    handler: F,
) -> JoinHandle<()>
where
    F: Fn(tokio::net::TcpStream) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let handler = Arc::new(handler);
    thread::Builder::new()
        .name("keli-core-tcp-accept".to_string())
        .spawn(move || {
            let Ok(runtime) = tcp_accept_runtime() else {
                return;
            };
            let _ = runtime.block_on(async move {
                let listener = tokio::net::TcpListener::from_std(listener)?;
                while !stop.load(Ordering::SeqCst) {
                    match tokio::time::timeout(Duration::from_millis(100), listener.accept()).await
                    {
                        Ok(Ok((stream, _))) => {
                            if stop.load(Ordering::SeqCst) {
                                break;
                            }
                            let _ = stream.set_nodelay(true);
                            let handler = Arc::clone(&handler);
                            let future = handler(stream);
                            spawn_async_connection_worker(&workers, future);
                        }
                        Ok(Err(_)) => break,
                        Err(_) => {}
                    }
                }
                Ok::<(), io::Error>(())
            });
        })
        .expect("failed to spawn async tcp accept thread")
}

fn tcp_accept_runtime() -> io::Result<&'static tokio::runtime::Runtime> {
    if let Some(runtime) = TCP_ACCEPT_RUNTIME.get() {
        return Ok(runtime);
    }

    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(tcp_accept_worker_threads())
        .thread_name("keli-core-tcp-accept")
        .enable_io()
        .enable_time()
        .build()?;
    match TCP_ACCEPT_RUNTIME.set(runtime) {
        Ok(()) => Ok(TCP_ACCEPT_RUNTIME
            .get()
            .expect("tcp accept runtime initialized")),
        Err(_) => Ok(TCP_ACCEPT_RUNTIME
            .get()
            .expect("tcp accept runtime initialized by another thread")),
    }
}

fn tcp_accept_worker_threads() -> usize {
    std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(4)
        .clamp(2, 8)
}

fn quic_runtime_worker_threads() -> usize {
    if let Ok(value) = std::env::var("KELI_CORE_QUIC_WORKERS") {
        if let Ok(parsed) = value.trim().parse::<usize>() {
            return parsed.clamp(1, 64);
        }
    }
    std::thread::available_parallelism()
        .map(|parallelism| {
            let threads = usize::from(parallelism);
            (threads + 1) / 2
        })
        .unwrap_or(2)
        .clamp(2, 8)
}

fn tls_acceptor_for(inbound: &InboundConfig) -> Result<Option<TlsAcceptor>, CoreServiceError> {
    let Some(tls) = inbound.tls.as_ref() else {
        return Ok(None);
    };
    let cert_file = tls.cert_file.as_deref().unwrap_or_default();
    let key_file = tls.key_file.as_deref().unwrap_or_default();
    TlsAcceptor::from_files_with_sni_policy(
        cert_file,
        key_file,
        &tls.alpn,
        &tls.server_name,
        tls.reject_unknown_sni,
    )
    .map(Some)
    .map_err(|source| CoreServiceError::Bind {
        tag: inbound.tag.clone(),
        source,
    })
}

#[derive(Clone, Debug)]
struct ListenerBindSpec {
    tag: String,
    protocol: Protocol,
    network: &'static str,
    addr: SocketAddr,
}

fn validate_unique_listener_binds(inbounds: &[InboundConfig]) -> Result<(), ValidationError> {
    let mut seen = Vec::<ListenerBindSpec>::new();
    for inbound in inbounds {
        for spec in listener_bind_specs(inbound)? {
            if let Some(existing) = seen.iter().find(|existing| {
                existing.network == spec.network && listen_addrs_conflict(existing.addr, spec.addr)
            }) {
                return Err(ValidationError::new(format!(
                    "duplicate {} listen {} for inbound {} ({:?}) conflicts with {} ({:?}); change one node server port or listen address",
                    spec.network,
                    spec.addr,
                    spec.tag,
                    spec.protocol,
                    existing.tag,
                    existing.protocol
                )));
            }
            seen.push(spec);
        }
    }
    Ok(())
}

fn listener_bind_specs(inbound: &InboundConfig) -> Result<Vec<ListenerBindSpec>, ValidationError> {
    let addr = resolve_listen_addr(&inbound.listen, inbound.port).map_err(|error| {
        ValidationError::new(format!(
            "inbound {} listen {}:{} did not resolve: {}",
            inbound.tag, inbound.listen, inbound.port, error
        ))
    })?;
    let mut specs = Vec::with_capacity(2);
    if protocol_binds_tcp(inbound) {
        specs.push(ListenerBindSpec {
            tag: inbound.tag.clone(),
            protocol: inbound.protocol.clone(),
            network: "tcp",
            addr,
        });
    }
    if protocol_binds_udp(inbound) {
        specs.push(ListenerBindSpec {
            tag: inbound.tag.clone(),
            protocol: inbound.protocol.clone(),
            network: "udp",
            addr,
        });
    }
    Ok(specs)
}

fn protocol_binds_tcp(inbound: &InboundConfig) -> bool {
    matches!(
        inbound.protocol,
        Protocol::Socks
            | Protocol::Http
            | Protocol::Vless
            | Protocol::Vmess
            | Protocol::Trojan
            | Protocol::Shadowsocks
            | Protocol::AnyTls
            | Protocol::Mieru
    ) || (inbound.protocol == Protocol::Naive && !naive_uses_quic(inbound))
}

fn protocol_binds_udp(inbound: &InboundConfig) -> bool {
    inbound_binds_quic(inbound)
        || (inbound.protocol == Protocol::Shadowsocks
            && shadowsocks_udp_enabled(&inbound.transport))
}

fn listen_addrs_conflict(left: SocketAddr, right: SocketAddr) -> bool {
    left.port() == right.port()
        && (left.ip() == right.ip() || left.ip().is_unspecified() || right.ip().is_unspecified())
}

fn resolve_listen_addr(listen: &str, port: u16) -> io::Result<SocketAddr> {
    let listen = match listen.trim() {
        "" | "0.0.0.0" | "::" | "[::]" => "::",
        value => value,
    };
    (listen, port).to_socket_addrs()?.next().ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "listen address did not resolve",
        )
    })
}

#[cfg(test)]
mod tests {
    use base64::engine::general_purpose::STANDARD as BASE64_STANDARD;
    use base64::Engine;
    use bytes::Buf;
    use quinn::crypto::rustls::QuicClientConfig;
    use rustls::pki_types::CertificateDer;
    use rustls::{ClientConfig, RootCertStore};
    use sha2::{Digest, Sha224};
    use std::fs;
    use std::future::poll_fn;
    use std::io::{self, Read, Write};
    use std::net::{Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::sync::{mpsc, Arc};
    use std::thread;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use crate::config::{
        CoreConfig, DnsConfig, InboundConfig, OutboundConfig, OutboundTlsConfig,
        OutboundTransportConfig, PolicyConfig, RealityConfig, SniffingConfig, StatsConfig,
        TlsConfig, TransportConfig,
    };
    use crate::protocol::Protocol;
    use crate::service::CoreService;
    use crate::socks5::SocksTarget;
    use crate::tls::TlsAcceptor;
    use crate::user::{CoreUser, CoreUserDelta};
    use crate::vless::connect_vless_tcp_outbound;

    use super::reality_tls_acceptor;

    #[test]
    fn wildcard_listen_defaults_to_dual_stack_ipv6_unspecified() {
        assert_eq!(
            super::resolve_listen_addr("", 443).expect("empty listen"),
            SocketAddr::from((Ipv6Addr::UNSPECIFIED, 443))
        );
        assert_eq!(
            super::resolve_listen_addr("0.0.0.0", 443).expect("ipv4 wildcard"),
            SocketAddr::from((Ipv6Addr::UNSPECIFIED, 443))
        );
        assert_eq!(
            super::resolve_listen_addr("[::]", 443).expect("bracketed ipv6 wildcard"),
            SocketAddr::from((Ipv6Addr::UNSPECIFIED, 443))
        );
        assert_eq!(
            super::resolve_listen_addr("127.0.0.1", 443).expect("explicit ipv4"),
            SocketAddr::from((Ipv4Addr::LOCALHOST, 443))
        );
    }

    #[test]
    fn vless_empty_transport_defaults_to_tcp() {
        assert!(super::vless_transport_is_tcp(""));
        assert!(super::vless_transport_is_tcp("tcp"));
        assert!(super::vless_transport_is_tcp(" tcp "));
        assert!(!super::vless_transport_is_tcp("ws"));
        assert!(!super::vless_transport_is_tcp("httpupgrade"));
    }

    #[test]
    fn outbound_connect_timeout_defaults_and_clamps_env_value() {
        assert_eq!(
            super::outbound_connect_timeout_from_env(None, 15),
            Duration::from_secs(15)
        );
        assert_eq!(
            super::outbound_connect_timeout_from_env(Some("0".to_string()), 15),
            Duration::from_secs(15)
        );
        assert_eq!(
            super::outbound_connect_timeout_from_env(Some("2".to_string()), 15),
            Duration::from_secs(2)
        );
        assert_eq!(
            super::outbound_connect_timeout_from_env(Some("999".to_string()), 15),
            Duration::from_secs(60)
        );
        assert_eq!(
            super::outbound_connect_timeout_from_env(None, 4),
            Duration::from_secs(4)
        );
    }

    #[test]
    fn connection_worker_stack_defaults_and_clamps_env_value() {
        #[cfg(windows)]
        let expected_default = 2048 * 1024;
        #[cfg(not(windows))]
        let expected_default = 2048 * 1024;
        assert_eq!(
            super::connection_worker_stack_size_from_env(None),
            expected_default
        );
        assert_eq!(
            super::connection_worker_stack_size_from_env(Some("128".to_string())),
            256 * 1024
        );
        assert_eq!(
            super::connection_worker_stack_size_from_env(Some("2048".to_string())),
            2048 * 1024
        );
        assert_eq!(
            super::connection_worker_stack_size_from_env(Some("99999".to_string())),
            8192 * 1024
        );
    }

    #[test]
    fn listener_bind_validation_rejects_duplicate_tcp_port() {
        let inbounds = vec![
            bind_validation_inbound("node-a|vless", Protocol::Vless, "127.0.0.1", 25001, "tcp"),
            bind_validation_inbound("node-b|trojan", Protocol::Trojan, "127.0.0.1", 25001, "tcp"),
        ];

        let error = super::validate_unique_listener_binds(&inbounds)
            .expect_err("duplicate tcp bind should fail")
            .to_string();

        assert!(error.contains("duplicate tcp listen"));
        assert!(error.contains("25001"));
        assert!(error.contains("node-a|vless"));
        assert!(error.contains("node-b|trojan"));
    }

    #[test]
    fn listener_bind_validation_rejects_duplicate_naive_tcp_port() {
        let inbounds = vec![
            bind_validation_inbound("node-a|vless", Protocol::Vless, "127.0.0.1", 25005, "tcp"),
            bind_validation_inbound("node-b|naive", Protocol::Naive, "127.0.0.1", 25005, "tcp"),
        ];

        let error = super::validate_unique_listener_binds(&inbounds)
            .expect_err("naive h2 tcp bind should conflict with another tcp listener")
            .to_string();

        assert!(error.contains("duplicate tcp listen"));
        assert!(error.contains("25005"));
        assert!(error.contains("node-a|vless"));
        assert!(error.contains("node-b|naive"));
    }

    #[test]
    fn listener_bind_validation_treats_wildcard_as_conflicting_with_explicit_ip() {
        let inbounds = vec![
            bind_validation_inbound("node-a|vless", Protocol::Vless, "0.0.0.0", 25002, "tcp"),
            bind_validation_inbound("node-b|socks", Protocol::Socks, "127.0.0.1", 25002, "tcp"),
        ];

        let error = super::validate_unique_listener_binds(&inbounds)
            .expect_err("wildcard and explicit tcp bind should conflict")
            .to_string();

        assert!(error.contains("duplicate tcp listen"));
        assert!(error.contains("25002"));
    }

    #[test]
    fn listener_bind_validation_allows_same_port_for_tcp_and_udp() {
        let inbounds = vec![
            bind_validation_inbound("node-a|vless", Protocol::Vless, "127.0.0.1", 25003, "tcp"),
            bind_validation_inbound(
                "node-a|hysteria2",
                Protocol::Hysteria2,
                "127.0.0.1",
                25003,
                "udp",
            ),
        ];

        super::validate_unique_listener_binds(&inbounds)
            .expect("tcp and udp listeners may share a numeric port");
    }

    #[test]
    fn listener_bind_validation_rejects_duplicate_udp_port() {
        let inbounds = vec![
            bind_validation_inbound(
                "node-a|shadowsocks",
                Protocol::Shadowsocks,
                "127.0.0.1",
                25004,
                "tcp,udp",
            ),
            bind_validation_inbound(
                "node-b|hysteria2",
                Protocol::Hysteria2,
                "127.0.0.1",
                25004,
                "udp",
            ),
        ];

        let error = super::validate_unique_listener_binds(&inbounds)
            .expect_err("duplicate udp bind should fail")
            .to_string();

        assert!(error.contains("duplicate udp listen"));
        assert!(error.contains("25004"));
    }

    #[test]
    fn listener_bind_validation_treats_naive_h3_as_udp() {
        let mut naive_h3 = bind_validation_inbound(
            "node-a|naive-h3",
            Protocol::Naive,
            "127.0.0.1",
            25006,
            "tcp",
        );
        naive_h3.tls = Some(TlsConfig {
            server_name: "localhost".to_string(),
            cert_file: Some("cert.pem".to_string()),
            key_file: Some("key.pem".to_string()),
            alpn: vec!["h3".to_string()],
            reject_unknown_sni: false,
            reality: None,
        });

        super::validate_unique_listener_binds(&[
            bind_validation_inbound("node-b|vless", Protocol::Vless, "127.0.0.1", 25006, "tcp"),
            naive_h3.clone(),
        ])
        .expect("naive h3 udp and vless tcp may share a numeric port");

        let error = super::validate_unique_listener_binds(&[
            bind_validation_inbound(
                "node-b|hysteria2",
                Protocol::Hysteria2,
                "127.0.0.1",
                25006,
                "udp",
            ),
            naive_h3,
        ])
        .expect_err("naive h3 should conflict with another udp listener")
        .to_string();

        assert!(error.contains("duplicate udp listen"));
        assert!(error.contains("25006"));
    }

    #[test]
    fn connection_worker_group_waits_for_submitted_jobs() {
        let group = super::ConnectionWorkerGroup::new();
        let completed = Arc::new(AtomicBool::new(false));
        let completed_for_worker = completed.clone();
        let (release_tx, release_rx) = mpsc::channel();

        assert!(group.spawn(move || {
            release_rx.recv().expect("release worker");
            completed_for_worker.store(true, Ordering::SeqCst);
        }));

        let group_for_waiter = group.clone();
        let (joined_tx, joined_rx) = mpsc::channel();
        let waiter = thread::spawn(move || {
            assert!(group_for_waiter.join_timeout(Duration::from_secs(2)));
            joined_tx.send(()).expect("send joined");
        });

        assert!(joined_rx.recv_timeout(Duration::from_millis(50)).is_err());
        release_tx.send(()).expect("release");
        joined_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("worker group joined");
        waiter.join().expect("waiter thread");
        assert!(completed.load(Ordering::SeqCst));
    }

    #[test]
    fn connection_worker_group_timeout_does_not_block_shutdown() {
        let group = super::ConnectionWorkerGroup::new();
        let (release_tx, release_rx) = mpsc::channel();

        assert!(group.spawn(move || {
            release_rx.recv().expect("release worker");
        }));

        let start = Instant::now();
        assert!(!group.join_timeout(Duration::from_millis(50)));
        assert!(start.elapsed() < Duration::from_secs(1));

        release_tx.send(()).expect("release");
        assert!(group.join_timeout(Duration::from_secs(2)));
    }

    #[test]
    fn connection_worker_group_releases_panicking_jobs() {
        let group = super::ConnectionWorkerGroup::new();
        assert!(group.spawn(|| panic!("worker panic should be contained")));
        assert!(group.join_timeout(Duration::from_secs(2)));

        let completed = Arc::new(AtomicBool::new(false));
        let completed_for_worker = completed.clone();
        assert!(group.spawn(move || {
            completed_for_worker.store(true, Ordering::SeqCst);
        }));
        assert!(group.join_timeout(Duration::from_secs(2)));
        assert!(completed.load(Ordering::SeqCst));
    }

    #[test]
    fn connection_worker_group_handles_bursts() {
        let group = super::ConnectionWorkerGroup::new();
        let (completed_tx, completed_rx) = mpsc::channel();

        for index in 0..64 {
            let completed_tx = completed_tx.clone();
            assert!(group.spawn(move || {
                completed_tx.send(index).expect("send completion");
            }));
        }
        drop(completed_tx);

        assert!(group.join_timeout(Duration::from_secs(2)));
        let mut completed = completed_rx.try_iter().collect::<Vec<_>>();
        completed.sort_unstable();

        assert_eq!(completed, (0..64).collect::<Vec<_>>());
    }

    #[test]
    fn connection_worker_group_reports_async_and_blocking_activity() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(1)
            .enable_time()
            .build()
            .expect("test runtime");
        runtime.block_on(async {
            let group = super::ConnectionWorkerGroup::new();
            let (blocking_release_tx, blocking_release_rx) = mpsc::channel();
            assert!(group.spawn(move || {
                let _ = blocking_release_rx.recv();
            }));

            let async_release = Arc::new(AtomicBool::new(false));
            let async_release_for_task = async_release.clone();
            assert!(group.spawn_async(async move {
                while !async_release_for_task.load(Ordering::SeqCst) {
                    tokio::time::sleep(Duration::from_millis(5)).await;
                }
            }));

            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                let snapshot = group.snapshot();
                if snapshot.active_blocking == 1 && snapshot.active_async == 1 {
                    assert_eq!(snapshot.active_total, 2);
                    break;
                }
                if Instant::now() >= deadline {
                    panic!("connection scheduler did not report active async and blocking workers");
                }
                tokio::time::sleep(Duration::from_millis(5)).await;
            }

            blocking_release_tx
                .send(())
                .expect("release blocking worker");
            async_release.store(true, Ordering::SeqCst);
            assert!(group.join_timeout(Duration::from_secs(2)));
            let snapshot = group.snapshot();
            assert_eq!(snapshot.active_total, 0);
            assert_eq!(snapshot.active_blocking, 0);
            assert_eq!(snapshot.active_async, 0);
        });
    }

    #[test]
    fn connection_worker_snapshot_formats_low_cardinality_fields() {
        let snapshot = super::ConnectionWorkerGroupSnapshot {
            active_total: 3,
            active_blocking: 1,
            active_async: 2,
        };
        assert_eq!(
            super::format_connection_worker_snapshot(snapshot),
            "connection_active_total=3 connection_active_blocking=1 connection_active_async=2"
        );
    }

    #[test]
    fn connection_worker_group_does_not_cap_long_connections_at_legacy_pool_size() {
        let group = super::ConnectionWorkerGroup::new();
        let started = Arc::new(AtomicUsize::new(0));
        let mut releases = Vec::new();

        for _ in 0..=super::MAX_CONNECTION_WORKERS_PER_LISTENER {
            let (release_tx, release_rx) = mpsc::channel();
            let started_for_worker = started.clone();
            releases.push(release_tx);
            assert!(group.spawn(move || {
                started_for_worker.fetch_add(1, Ordering::SeqCst);
                let _ = release_rx.recv();
            }));
        }

        let deadline = Instant::now() + Duration::from_secs(5);
        while started.load(Ordering::SeqCst) <= super::MAX_CONNECTION_WORKERS_PER_LISTENER {
            if Instant::now() >= deadline {
                panic!(
                    "expected more than {} long-lived connection workers to start",
                    super::MAX_CONNECTION_WORKERS_PER_LISTENER
                );
            }
            thread::sleep(Duration::from_millis(10));
        }

        for release in releases {
            let _ = release.send(());
        }
        assert!(group.join_timeout(Duration::from_secs(5)));
    }

    fn user() -> CoreUser {
        CoreUser {
            id: 1,
            uuid: "user-a".to_string(),
            password: None,
            email: None,
            speed_limit: 0,
            device_limit: 0,
        }
    }

    fn free_port() -> u16 {
        TcpListener::bind("127.0.0.1:0")
            .expect("bind free port")
            .local_addr()
            .expect("free port addr")
            .port()
    }

    fn free_udp_port() -> u16 {
        UdpSocket::bind("127.0.0.1:0")
            .expect("bind free udp port")
            .local_addr()
            .expect("free udp port addr")
            .port()
    }

    fn config(port: u16) -> CoreConfig {
        CoreConfig {
            instance_id: "node-a".to_string(),
            log_level: "info".to_string(),
            dns: DnsConfig::default(),
            policy: PolicyConfig::default(),
            inbounds: vec![InboundConfig {
                tag: "panel|socks|1".to_string(),
                protocol: Protocol::Socks,
                listen: "127.0.0.1".to_string(),
                port,
                users: vec![user()],
                cipher: None,
                flow: String::new(),
                padding_scheme: Vec::new(),
                transport: TransportConfig::default(),
                tls: None,
                sniffing: SniffingConfig::default(),
                routes: Vec::new(),
            }],
            outbounds: vec![OutboundConfig {
                tag: "direct".to_string(),
                protocol: "freedom".to_string(),
                method: None,
                alter_id: None,
                address: None,
                port: None,
                username: None,
                password: None,
                tls: None,
                transport: None,
            }],
            routes: Vec::new(),
            stats: StatsConfig::default(),
        }
    }

    #[test]
    fn service_does_not_retain_full_users_in_static_config() {
        let mut config = config(free_port());
        config.inbounds[0].users = (0..1024)
            .map(|index| CoreUser {
                id: index,
                uuid: format!("user-{index:04}"),
                password: None,
                email: Some(format!("user-{index:04}@example.test")),
                speed_limit: 0,
                device_limit: 0,
            })
            .collect();

        let mut service = CoreService::start(config).expect("service start");

        assert!(service.config.inbounds[0].users.is_empty());
        let result = service
            .apply_user_delta(
                "panel|socks|1",
                &CoreUserDelta {
                    added: vec![CoreUser {
                        id: 2048,
                        uuid: "new-user".to_string(),
                        password: None,
                        email: Some("new-user@example.test".to_string()),
                        speed_limit: 0,
                        device_limit: 0,
                    }],
                    revision: Some("rev-2".to_string()),
                    ..CoreUserDelta::default()
                },
            )
            .expect("delta apply");

        assert_eq!(result.added, 1);
        assert_eq!(result.active_users, 1025);
        assert!(service.config.inbounds[0].users.is_empty());
        service.stop();
    }

    fn bind_validation_inbound(
        tag: &str,
        protocol: Protocol,
        listen: &str,
        port: u16,
        network: &str,
    ) -> InboundConfig {
        InboundConfig {
            tag: tag.to_string(),
            protocol,
            listen: listen.to_string(),
            port,
            users: vec![user()],
            cipher: None,
            flow: String::new(),
            padding_scheme: Vec::new(),
            transport: TransportConfig {
                network: network.to_string(),
                ..TransportConfig::default()
            },
            tls: None,
            sniffing: SniffingConfig::default(),
            routes: Vec::new(),
        }
    }

    fn vless_reality_config(port: u16) -> CoreConfig {
        vless_reality_config_with_dest(port, "www.example.com:443".to_string(), None)
    }

    fn vless_reality_config_with_dest(
        port: u16,
        dest: String,
        server_port: Option<u16>,
    ) -> CoreConfig {
        CoreConfig {
            instance_id: "node-a".to_string(),
            log_level: "info".to_string(),
            dns: DnsConfig::default(),
            policy: PolicyConfig::default(),
            inbounds: vec![InboundConfig {
                tag: "panel|vless|reality|1".to_string(),
                protocol: Protocol::Vless,
                listen: "127.0.0.1".to_string(),
                port,
                users: vec![user()],
                cipher: None,
                flow: "xtls-rprx-vision".to_string(),
                padding_scheme: Vec::new(),
                transport: TransportConfig::default(),
                tls: Some(TlsConfig {
                    server_name: "www.example.com".to_string(),
                    cert_file: None,
                    key_file: None,
                    alpn: Vec::new(),
                    reject_unknown_sni: false,
                    reality: Some(RealityConfig {
                        dest,
                        server_port,
                        private_key: "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc".to_string(),
                        short_id: "6ba85179e30d4fc2".to_string(),
                        xver: 0,
                        mldsa65_seed: None,
                    }),
                }),
                sniffing: SniffingConfig::default(),
                routes: Vec::new(),
            }],
            outbounds: vec![OutboundConfig {
                tag: "direct".to_string(),
                protocol: "freedom".to_string(),
                method: None,
                alter_id: None,
                address: None,
                port: None,
                username: None,
                password: None,
                tls: None,
                transport: None,
            }],
            routes: Vec::new(),
            stats: StatsConfig::default(),
        }
    }

    fn uuid_bytes(value: &str) -> [u8; 16] {
        let compact = value.replace('-', "");
        let mut bytes = [0u8; 16];
        for (index, byte) in bytes.iter_mut().enumerate() {
            *byte = u8::from_str_radix(&compact[index * 2..index * 2 + 2], 16).expect("uuid byte");
        }
        bytes
    }

    fn vless_tcp_request_for_user(uuid: &str, target: std::net::SocketAddr) -> Vec<u8> {
        let mut request = Vec::new();
        request.push(0x00);
        request.extend_from_slice(&uuid_bytes(uuid));
        request.push(0x00);
        request.push(0x01);
        request.extend_from_slice(&target.port().to_be_bytes());
        request.push(0x01);
        request.extend_from_slice(
            &target
                .ip()
                .to_string()
                .parse::<std::net::Ipv4Addr>()
                .expect("ipv4")
                .octets(),
        );
        request
    }

    struct EchoServer {
        addr: SocketAddr,
        stop: Arc<AtomicBool>,
        handle: Option<thread::JoinHandle<()>>,
    }

    impl EchoServer {
        fn start() -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").expect("echo bind");
            listener.set_nonblocking(true).expect("echo nonblocking");
            let addr = listener.local_addr().expect("echo addr");
            let stop = Arc::new(AtomicBool::new(false));
            let stop_for_thread = stop.clone();
            let handle = thread::spawn(move || {
                while !stop_for_thread.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
                            let mut buffer = [0u8; 1];
                            if stream.read_exact(&mut buffer).is_ok() {
                                let _ = stream.write_all(&buffer);
                            }
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(5));
                        }
                        Err(_) => break,
                    }
                }
            });
            Self {
                addr,
                stop,
                handle: Some(handle),
            }
        }
    }

    impl Drop for EchoServer {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            let _ = TcpStream::connect(self.addr);
            if let Some(handle) = self.handle.take() {
                let _ = handle.join();
            }
        }
    }

    struct GreetingServer {
        addr: SocketAddr,
        stop: Arc<AtomicBool>,
        handle: Option<thread::JoinHandle<()>>,
    }

    impl GreetingServer {
        fn start(payload: &'static [u8]) -> Self {
            let listener = TcpListener::bind("127.0.0.1:0").expect("greeting bind");
            listener
                .set_nonblocking(true)
                .expect("greeting nonblocking");
            let addr = listener.local_addr().expect("greeting addr");
            let stop = Arc::new(AtomicBool::new(false));
            let stop_for_thread = stop.clone();
            let handle = thread::spawn(move || {
                while !stop_for_thread.load(Ordering::SeqCst) {
                    match listener.accept() {
                        Ok((mut stream, _)) => {
                            let _ = stream.write_all(payload);
                        }
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            thread::sleep(Duration::from_millis(5));
                        }
                        Err(_) => break,
                    }
                }
            });
            Self {
                addr,
                stop,
                handle: Some(handle),
            }
        }
    }

    impl Drop for GreetingServer {
        fn drop(&mut self) {
            self.stop.store(true, Ordering::SeqCst);
            let _ = TcpStream::connect(self.addr);
            if let Some(handle) = self.handle.take() {
                let _ = handle.join();
            }
        }
    }

    fn vless_auth_succeeds(server_addr: SocketAddr, uuid: &str, target: SocketAddr) -> bool {
        let Ok(mut stream) = TcpStream::connect(server_addr) else {
            return false;
        };
        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
        if stream
            .write_all(&vless_tcp_request_for_user(uuid, target))
            .is_err()
        {
            return false;
        }
        if stream.write_all(b"x").is_err() {
            return false;
        }
        let mut response = [0u8; 3];
        stream.read_exact(&mut response).is_ok() && response == [0x00, 0x00, b'x']
    }

    fn vless_auth_succeeds_eventually(
        server_addr: SocketAddr,
        uuid: &str,
        target: SocketAddr,
    ) -> bool {
        for _ in 0..50 {
            if vless_auth_succeeds(server_addr, uuid, target) {
                return true;
            }
            thread::sleep(Duration::from_millis(20));
        }
        false
    }

    fn trojan_auth_succeeds(server_addr: SocketAddr, password: &str, target: SocketAddr) -> bool {
        let Ok(mut stream) = TcpStream::connect(server_addr) else {
            return false;
        };
        let _ = stream.set_read_timeout(Some(Duration::from_secs(2)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(2)));
        if stream
            .write_all(&trojan_request_with_password(password, target))
            .is_err()
        {
            return false;
        }
        if stream.write_all(b"x").is_err() {
            return false;
        }
        let mut response = [0u8; 1];
        stream.read_exact(&mut response).is_ok() && response == *b"x"
    }

    fn trojan_auth_succeeds_eventually(
        server_addr: SocketAddr,
        password: &str,
        target: SocketAddr,
    ) -> bool {
        for _ in 0..50 {
            if trojan_auth_succeeds(server_addr, password, target) {
                return true;
            }
            thread::sleep(Duration::from_millis(20));
        }
        false
    }

    fn trojan_request_with_password(password: &str, target: SocketAddr) -> Vec<u8> {
        let mut input = trojan_password_hash(password).into_bytes();
        input.extend_from_slice(b"\r\n");
        input.push(0x01);
        input.push(0x01);
        input.extend_from_slice(
            &target
                .ip()
                .to_string()
                .parse::<std::net::Ipv4Addr>()
                .expect("ipv4")
                .octets(),
        );
        input.extend_from_slice(&target.port().to_be_bytes());
        input.extend_from_slice(b"\r\n");
        input
    }

    fn trojan_password_hash(password: &str) -> String {
        let mut hasher = Sha224::new();
        hasher.update(password.as_bytes());
        hasher
            .finalize()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    fn io_other(error: impl std::fmt::Debug) -> io::Error {
        io::Error::new(io::ErrorKind::Other, format!("{error:?}"))
    }

    fn quic_client_endpoint(cert_der: CertificateDer<'static>) -> quinn::Endpoint {
        let mut roots = RootCertStore::empty();
        roots.add(cert_der).expect("root cert");
        let mut crypto = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        crypto.alpn_protocols = vec![b"h3".to_vec()];
        let mut client_config =
            quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(crypto).unwrap()));
        let mut transport = quinn::TransportConfig::default();
        transport
            .datagram_receive_buffer_size(Some(1024 * 1024))
            .datagram_send_buffer_size(1024 * 1024);
        client_config.transport_config(Arc::new(transport));
        let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(client_config);
        endpoint
    }

    async fn hy2_auth_succeeds(
        server_addr: SocketAddr,
        cert_der: CertificateDer<'static>,
        password: &str,
    ) -> bool {
        matches!(
            tokio::time::timeout(
                Duration::from_secs(3),
                hy2_auth_status(server_addr, cert_der, password)
            )
            .await,
            Ok(Some(233))
        )
    }

    async fn hy2_auth_status(
        server_addr: SocketAddr,
        cert_der: CertificateDer<'static>,
        password: &str,
    ) -> Option<u16> {
        let client_endpoint = quic_client_endpoint(cert_der);
        let connecting = client_endpoint.connect(server_addr, "localhost").ok()?;
        let connection = connecting.await.ok()?;
        let status = hy2_authenticate_status(&connection, password).await.ok();
        connection.close(0u32.into(), b"probe done");
        status
    }

    async fn hy2_authenticate_status(
        connection: &quinn::Connection,
        password: &str,
    ) -> io::Result<u16> {
        let quic = h3_quinn::Connection::new(connection.clone());
        let (mut h3_connection, mut send_request) =
            h3::client::new(quic).await.map_err(io_other)?;
        let driver = tokio::spawn(async move {
            let _ = poll_fn(|cx| h3_connection.poll_close(cx)).await;
        });
        let request = http::Request::builder()
            .method(http::Method::POST)
            .uri("https://hysteria/auth")
            .header("Hysteria-Auth", password)
            .header("Hysteria-CC-RX", "0")
            .body(())
            .expect("auth request");
        let mut stream = send_request.send_request(request).await.map_err(io_other)?;
        stream.finish().await.map_err(io_other)?;
        let response = stream.recv_response().await.map_err(io_other)?;
        let status = response.status().as_u16();
        drop(send_request);
        driver.abort();
        Ok(status)
    }

    async fn naive_h3_connect_round_trip(
        server_addr: SocketAddr,
        cert_der: CertificateDer<'static>,
        target: SocketAddr,
        username: &str,
        password: &str,
    ) -> io::Result<Vec<u8>> {
        let client_endpoint = quic_client_endpoint(cert_der);
        let connecting = client_endpoint
            .connect(server_addr, "localhost")
            .map_err(io_other)?;
        let connection = connecting.await.map_err(io_other)?;
        let quic = h3_quinn::Connection::new(connection.clone());
        let (mut h3_connection, mut send_request) =
            h3::client::new(quic).await.map_err(io_other)?;
        let driver = tokio::spawn(async move {
            let _ = poll_fn(|cx| h3_connection.poll_close(cx)).await;
        });
        let auth = BASE64_STANDARD.encode(format!("{username}:{password}"));
        let request = http::Request::builder()
            .method(http::Method::CONNECT)
            .uri(format!("https://{target}"))
            .header("proxy-authorization", format!("Basic {auth}"))
            .body(())
            .expect("naive h3 request");
        let mut stream = send_request.send_request(request).await.map_err(io_other)?;
        stream.finish().await.map_err(io_other)?;
        let response = stream.recv_response().await.map_err(io_other)?;
        if response.status() != http::StatusCode::OK {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("naive h3 status {}", response.status()),
            ));
        }
        let mut output = Vec::new();
        while output.is_empty() {
            let Some(mut chunk) = stream.recv_data().await.map_err(io_other)? else {
                break;
            };
            let len = chunk.remaining();
            output.extend_from_slice(&chunk.copy_to_bytes(len));
        }
        connection.close(0u32.into(), b"probe done");
        drop(send_request);
        driver.abort();
        Ok(output)
    }

    fn tuic_auth_command_for(
        connection: &quinn::Connection,
        uuid: &str,
        password: &str,
    ) -> Vec<u8> {
        let uuid = uuid_bytes(uuid);
        let mut token = [0u8; 32];
        connection
            .export_keying_material(&mut token, &uuid, password.as_bytes())
            .expect("token");
        let mut command = vec![0x05, 0x00];
        command.extend_from_slice(&uuid);
        command.extend_from_slice(&token);
        command
    }

    fn tuic_connect_command(addr: SocketAddr) -> Vec<u8> {
        let mut command = vec![0x05, 0x01, 0x01];
        let ip = addr
            .ip()
            .to_string()
            .parse::<Ipv4Addr>()
            .expect("ipv4 echo addr");
        command.extend_from_slice(&ip.octets());
        command.extend_from_slice(&addr.port().to_be_bytes());
        command
    }

    async fn tuic_tcp_probe(
        server_addr: SocketAddr,
        cert_der: CertificateDer<'static>,
        uuid: &str,
        password: &str,
        echo_addr: SocketAddr,
    ) -> bool {
        tokio::time::timeout(
            Duration::from_secs(4),
            tuic_tcp_probe_inner(server_addr, cert_der, uuid, password, echo_addr),
        )
        .await
        .unwrap_or(false)
    }

    async fn tuic_tcp_probe_eventually(
        server_addr: SocketAddr,
        cert_der: CertificateDer<'static>,
        uuid: &str,
        password: &str,
        echo_addr: SocketAddr,
    ) -> bool {
        let deadline = tokio::time::Instant::now() + Duration::from_secs(5);
        loop {
            if tuic_tcp_probe(server_addr, cert_der.clone(), uuid, password, echo_addr).await {
                return true;
            }
            if tokio::time::Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    async fn tuic_tcp_probe_inner(
        server_addr: SocketAddr,
        cert_der: CertificateDer<'static>,
        uuid: &str,
        password: &str,
        echo_addr: SocketAddr,
    ) -> bool {
        let client_endpoint = quic_client_endpoint(cert_der);
        let connection = match client_endpoint.connect(server_addr, "localhost") {
            Ok(connecting) => match connecting.await {
                Ok(connection) => connection,
                Err(_) => return false,
            },
            Err(_) => return false,
        };
        let mut auth = match connection.open_uni().await {
            Ok(auth) => auth,
            Err(_) => return false,
        };
        if auth
            .write_all(&tuic_auth_command_for(&connection, uuid, password))
            .await
            .is_err()
        {
            return false;
        }
        if auth.finish().is_err() {
            return false;
        }
        let (mut send, mut recv) = match connection.open_bi().await {
            Ok(streams) => streams,
            Err(_) => return false,
        };
        if send
            .write_all(&tuic_connect_command(echo_addr))
            .await
            .is_err()
        {
            return false;
        }
        if send.write_all(b"x").await.is_err() {
            return false;
        }
        if send.finish().is_err() {
            return false;
        }
        let mut echoed = [0u8; 1];
        let read_result =
            tokio::time::timeout(Duration::from_secs(2), recv.read_exact(&mut echoed)).await;
        connection.close(0u32.into(), b"probe done");
        matches!(read_result, Ok(Ok(_)) if echoed == *b"x")
    }

    fn quic_tls_config(cert: &TestCert) -> TlsConfig {
        TlsConfig {
            server_name: "localhost".to_string(),
            cert_file: Some(cert.cert_path.to_string_lossy().to_string()),
            key_file: Some(cert.key_path.to_string_lossy().to_string()),
            alpn: vec!["h3".to_string()],
            reject_unknown_sni: false,
            reality: None,
        }
    }

    fn core_user(id: u64, uuid: &str, password: Option<&str>) -> CoreUser {
        CoreUser {
            id,
            uuid: uuid.to_string(),
            password: password.map(ToString::to_string),
            email: None,
            speed_limit: 0,
            device_limit: 0,
        }
    }

    fn quic_inbound(
        tag: &str,
        protocol: Protocol,
        network: &str,
        port: u16,
        users: Vec<CoreUser>,
        cert: &TestCert,
    ) -> InboundConfig {
        InboundConfig {
            tag: tag.to_string(),
            protocol,
            listen: "127.0.0.1".to_string(),
            port,
            users,
            cipher: None,
            flow: String::new(),
            padding_scheme: Vec::new(),
            transport: TransportConfig {
                network: network.to_string(),
                ..TransportConfig::default()
            },
            tls: Some(quic_tls_config(cert)),
            sniffing: SniffingConfig::default(),
            routes: Vec::new(),
        }
    }

    fn run_grpc_vless_client(
        proxy_addr: std::net::SocketAddr,
        echo_addr: std::net::SocketAddr,
        cert_der: Option<CertificateDer<'static>>,
    ) {
        let outbound = OutboundConfig {
            tag: "vless-grpc-out".to_string(),
            protocol: "vless".to_string(),
            method: None,
            alter_id: None,
            address: Some(proxy_addr.ip().to_string()),
            port: Some(proxy_addr.port()),
            username: Some("11111111-1111-1111-1111-111111111111".to_string()),
            password: None,
            tls: cert_der.map(|_| OutboundTlsConfig {
                server_name: "localhost".to_string(),
                allow_insecure: true,
                alpn: vec!["h2".to_string()],
            }),
            transport: Some(OutboundTransportConfig {
                network: "grpc".to_string(),
                service_name: Some("GunService".to_string()),
                host: Some("localhost".to_string()),
                ..OutboundTransportConfig::default()
            }),
        };
        let target = SocksTarget {
            host: echo_addr.ip().to_string(),
            port: echo_addr.port(),
        };
        let mut stream = connect_vless_tcp_outbound(&outbound, &target, Duration::from_secs(2))
            .expect("connect vless grpc outbound");
        stream.write_all(b"ping").expect("write grpc payload");
        let mut response = [0u8; 4];
        stream
            .read_exact(&mut response)
            .expect("read grpc response");
        assert_eq!(&response, b"ping");
        stream.shutdown(Shutdown::Both).expect("close grpc bridge");
    }

    struct TestCert {
        cert_path: PathBuf,
        key_path: PathBuf,
        cert_der: CertificateDer<'static>,
    }

    impl Drop for TestCert {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.cert_path);
            let _ = fs::remove_file(&self.key_path);
        }
    }

    fn test_cert(label: &str) -> TestCert {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("self signed cert");
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let dir = std::env::temp_dir();
        let cert_path = dir.join(format!("keli-core-rs-grpc-{label}-{nanos}.crt"));
        let key_path = dir.join(format!("keli-core-rs-grpc-{label}-{nanos}.key"));
        fs::write(&cert_path, cert.cert.pem()).expect("write cert");
        fs::write(&key_path, cert.key_pair.serialize_pem()).expect("write key");
        TestCert {
            cert_path,
            key_path,
            cert_der: cert.cert.der().clone(),
        }
    }

    #[test]
    fn tls_handshake_backoff_rejects_blocked_peer_before_handshake() {
        let cert = test_cert("tls-backoff");
        let acceptor =
            TlsAcceptor::from_files(&cert.cert_path, &cert.key_path, &[]).expect("tls acceptor");
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind tls listener");
        let addr = listener.local_addr().expect("local addr");
        let _client = TcpStream::connect(addr).expect("connect tls listener");
        let (server, peer) = listener.accept().expect("accept tls peer");
        let failures =
            crate::abuse::ClientFailureBackoff::new(crate::abuse::ClientFailureBackoffPolicy {
                threshold: 1,
                window: Duration::from_secs(30),
                block_duration: Duration::from_secs(30),
                max_entries: 16,
            });
        failures.record_failure(peer.ip());

        let error = match super::accept_tls_connection(
            &acceptor,
            server,
            Protocol::Vless,
            "tls-backoff-test",
            &failures,
            Duration::from_secs(4),
        ) {
            Ok(_) => panic!("blocked peer should fail before TLS handshake"),
            Err(error) => error,
        };

        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
        assert!(error.to_string().contains("backoff"));
    }

    #[test]
    fn tcp_auth_backoff_only_records_auth_like_permission_failures() {
        assert!(super::should_record_tcp_auth_failure(&io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unknown vless user",
        )));
        assert!(super::should_record_tcp_auth_failure(&io::Error::new(
            io::ErrorKind::PermissionDenied,
            "invalid vmess auth id",
        )));
        assert!(super::should_record_tcp_auth_failure(&io::Error::new(
            io::ErrorKind::PermissionDenied,
            "proxy authentication required",
        )));
        assert!(!super::should_record_tcp_auth_failure(&io::Error::new(
            io::ErrorKind::PermissionDenied,
            "target blocked by route",
        )));
        assert!(!super::should_record_tcp_auth_failure(&io::Error::new(
            io::ErrorKind::PermissionDenied,
            "device limit reached for user",
        )));
        assert!(!super::should_record_tcp_auth_failure(&io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid request",
        )));
    }

    #[test]
    fn starts_socks_listener_from_core_config() {
        let echo = TcpListener::bind("127.0.0.1:0").expect("echo bind");
        let echo_addr = echo.local_addr().expect("echo addr");
        let echo_thread = thread::spawn(move || {
            let (mut stream, _) = echo.accept().expect("echo accept");
            let mut bytes = [0u8; 4];
            stream.read_exact(&mut bytes).expect("echo read");
            stream.write_all(&bytes).expect("echo write");
        });

        let mut service = CoreService::start(config(free_port())).expect("service start");
        let socks_addr = service.listeners()[0].local_addr;

        let mut client = TcpStream::connect(socks_addr).expect("client connect");
        client
            .write_all(&[
                0x05, 0x01, 0x02, 0x01, 0x06, b'u', b's', b'e', b'r', b'-', b'a', 0x06, b'u', b's',
                b'e', b'r', b'-', b'a', 0x05, 0x01, 0x00, 0x01,
            ])
            .expect("client greeting");
        client
            .write_all(
                &echo_addr
                    .ip()
                    .to_string()
                    .parse::<std::net::Ipv4Addr>()
                    .expect("ipv4")
                    .octets(),
            )
            .expect("client target ip");
        client
            .write_all(&echo_addr.port().to_be_bytes())
            .expect("client target port");

        let mut response = [0u8; 14];
        client.read_exact(&mut response).expect("client response");
        client.write_all(b"ping").expect("client payload");
        let mut echoed = [0u8; 4];
        client.read_exact(&mut echoed).expect("client echo");
        assert_eq!(&echoed, b"ping");
        drop(client);

        echo_thread.join().expect("echo thread");
        for _ in 0..50 {
            let records = service.drain_traffic(1);
            if !records.is_empty() {
                assert_eq!(records[0].upload, 4);
                assert_eq!(records[0].download, 4);
                service.stop();
                return;
            }
            thread::sleep(Duration::from_millis(10));
        }
        service.stop();
        panic!("traffic was not recorded");
    }

    #[test]
    fn starts_mieru_listener_from_core_config() {
        let mut config = config(free_port());
        config.inbounds[0].tag = "panel|mieru|1".to_string();
        config.inbounds[0].protocol = Protocol::Mieru;
        config.inbounds[0].transport.network = "tcp".to_string();

        let mut service = CoreService::start(config).expect("service start");
        let listeners = service.listeners();

        assert_eq!(listeners.len(), 1);
        assert_eq!(listeners[0].protocol, Protocol::Mieru);
        service.stop();
    }

    #[test]
    fn naive_requires_tls_config() {
        let mut config = config(free_port());
        config.inbounds[0].protocol = Protocol::Naive;

        let error = CoreService::start(config).expect_err("naive without tls should fail");

        assert!(error.to_string().contains("tls"));
    }

    #[test]
    fn starts_vmess_listener_from_core_config() {
        let mut config = config(free_port());
        config.inbounds[0].tag = "panel|vmess|1".to_string();
        config.inbounds[0].protocol = Protocol::Vmess;
        config.inbounds[0].users[0].uuid = "11111111-1111-1111-1111-111111111111".to_string();

        let mut service = CoreService::start(config).expect("service start");
        let listeners = service.listeners();

        assert_eq!(listeners.len(), 1);
        assert_eq!(listeners[0].protocol, Protocol::Vmess);
        service.stop();
    }

    #[test]
    fn starts_vless_listener_from_core_config() {
        let mut config = config(free_port());
        config.inbounds[0].tag = "panel|vless|1".to_string();
        config.inbounds[0].protocol = Protocol::Vless;
        config.inbounds[0].users[0].uuid = "11111111-1111-1111-1111-111111111111".to_string();

        let mut service = CoreService::start(config).expect("service start");
        let listeners = service.listeners();

        assert_eq!(listeners.len(), 1);
        assert_eq!(listeners[0].protocol, Protocol::Vless);
        service.stop();
    }

    #[test]
    fn starts_vless_reality_listener_from_core_config() {
        let mut service =
            CoreService::start(vless_reality_config(free_port())).expect("service start");
        let listeners = service.listeners();

        assert_eq!(listeners.len(), 1);
        assert_eq!(listeners[0].protocol, Protocol::Vless);
        service.stop();
    }

    #[test]
    fn builds_reality_tls_acceptor_from_authenticated_key() {
        let acceptor = reality_tls_acceptor(&[0x42; 32], "www.example.test");

        assert!(acceptor.is_ok());
    }

    #[test]
    fn vless_reality_refreshes_auth_time_per_connection() {
        let config = vless_reality_config(free_port());
        let mut gateway =
            super::reality_gateway_config(&config.inbounds[0], Duration::from_secs(15))
                .expect("reality gateway config");
        gateway.auth.now = UNIX_EPOCH + Duration::from_secs(1);

        let refreshed = super::reality_gateway_for_connection(&gateway);
        let now = SystemTime::now();
        let diff = now
            .duration_since(refreshed.auth.now)
            .or_else(|_| refreshed.auth.now.duration_since(now))
            .expect("time diff");

        assert_eq!(refreshed.auth.private_key, gateway.auth.private_key);
        assert_eq!(refreshed.auth.short_ids, gateway.auth.short_ids);
        assert!(diff < Duration::from_secs(5));
    }

    #[test]
    fn vless_reality_uses_xray_default_without_time_diff_limit() {
        let config = vless_reality_config(free_port());
        let gateway = super::reality_gateway_config(&config.inbounds[0], Duration::from_secs(15))
            .expect("reality gateway config");

        assert!(gateway.auth.max_time_diff.is_none());
    }

    #[test]
    fn vless_reality_listener_falls_back_to_dest_for_invalid_preface() {
        let fallback = TcpListener::bind("127.0.0.1:0").expect("fallback bind");
        let fallback_addr = fallback.local_addr().expect("fallback addr");
        let (captured_tx, captured_rx) = mpsc::channel();
        let fallback_thread = thread::spawn(move || {
            let (mut stream, _) = fallback.accept().expect("fallback accept");
            let mut captured = Vec::new();
            stream.read_to_end(&mut captured).expect("fallback read");
            captured_tx.send(captured).expect("captured send");
            stream.write_all(b"fallback-ok").expect("fallback write");
        });

        let mut service = CoreService::start(vless_reality_config_with_dest(
            free_port(),
            fallback_addr.ip().to_string(),
            Some(fallback_addr.port()),
        ))
        .expect("service start");
        let reality_addr = service.listeners()[0].local_addr;

        let mut client = TcpStream::connect(reality_addr).expect("client connect");
        client.write_all(b"hello").expect("write preface");
        client.write_all(b"-world").expect("write payload");
        client
            .shutdown(std::net::Shutdown::Write)
            .expect("shutdown write");
        let mut response = Vec::new();
        client.read_to_end(&mut response).expect("read response");

        assert_eq!(response, b"fallback-ok");
        service.stop();
        fallback_thread.join().expect("fallback thread");
        assert_eq!(captured_rx.recv().expect("captured"), b"hello-world");
    }

    #[test]
    fn starts_vless_httpupgrade_listener_from_core_config() {
        let mut config = config(free_port());
        config.inbounds[0].tag = "panel|vless|1".to_string();
        config.inbounds[0].protocol = Protocol::Vless;
        config.inbounds[0].users[0].uuid = "11111111-1111-1111-1111-111111111111".to_string();
        config.inbounds[0].transport.network = "httpupgrade".to_string();
        config.inbounds[0].transport.path = Some("/edge".to_string());
        config.inbounds[0].transport.host = Some("example.test".to_string());

        let mut service = CoreService::start(config).expect("service start");
        let listeners = service.listeners();

        assert_eq!(listeners.len(), 1);
        assert_eq!(listeners[0].protocol, Protocol::Vless);
        service.stop();
    }

    #[test]
    fn proxies_vless_grpc_and_records_traffic() {
        let echo = TcpListener::bind("127.0.0.1:0").expect("echo bind");
        let echo_addr = echo.local_addr().expect("echo addr");
        let echo_thread = thread::spawn(move || {
            let (mut stream, _) = echo.accept().expect("echo accept");
            let mut bytes = [0u8; 4];
            stream.read_exact(&mut bytes).expect("echo read");
            stream.write_all(&bytes).expect("echo write");
        });

        let mut config = config(free_port());
        config.inbounds[0].tag = "panel|vless|1".to_string();
        config.inbounds[0].protocol = Protocol::Vless;
        config.inbounds[0].users[0].uuid = "11111111-1111-1111-1111-111111111111".to_string();
        config.inbounds[0].transport.network = "grpc".to_string();
        config.inbounds[0].transport.service_name = Some("GunService".to_string());
        let mut service = CoreService::start(config).expect("service start");
        let grpc_addr = service.listeners()[0].local_addr;
        thread::sleep(Duration::from_millis(50));

        run_grpc_vless_client(grpc_addr, echo_addr, None);
        echo_thread.join().expect("echo thread");

        for _ in 0..100 {
            let records = service.drain_traffic(1);
            if !records.is_empty() {
                assert_eq!(records[0].upload, 4);
                assert_eq!(records[0].download, 4);
                service.stop();
                return;
            }
            thread::sleep(Duration::from_millis(20));
        }
        service.stop();
        panic!("traffic was not recorded");
    }

    #[test]
    fn proxies_vless_grpc_tls_and_records_traffic() {
        let cert = test_cert("vless");
        let echo = TcpListener::bind("127.0.0.1:0").expect("echo bind");
        let echo_addr = echo.local_addr().expect("echo addr");
        let echo_thread = thread::spawn(move || {
            let (mut stream, _) = echo.accept().expect("echo accept");
            let mut bytes = [0u8; 4];
            stream.read_exact(&mut bytes).expect("echo read");
            stream.write_all(&bytes).expect("echo write");
        });

        let mut config = config(free_port());
        config.inbounds[0].tag = "panel|vless|1".to_string();
        config.inbounds[0].protocol = Protocol::Vless;
        config.inbounds[0].users[0].uuid = "11111111-1111-1111-1111-111111111111".to_string();
        config.inbounds[0].transport.network = "grpc".to_string();
        config.inbounds[0].transport.service_name = Some("GunService".to_string());
        config.inbounds[0].tls = Some(crate::config::TlsConfig {
            server_name: "localhost".to_string(),
            cert_file: Some(cert.cert_path.to_string_lossy().to_string()),
            key_file: Some(cert.key_path.to_string_lossy().to_string()),
            alpn: Vec::new(),
            reject_unknown_sni: true,
            reality: None,
        });
        let mut service = CoreService::start(config).expect("service start");
        let grpc_addr = service.listeners()[0].local_addr;
        thread::sleep(Duration::from_millis(50));

        run_grpc_vless_client(grpc_addr, echo_addr, Some(cert.cert_der.clone()));
        echo_thread.join().expect("echo thread");

        for _ in 0..100 {
            let records = service.drain_traffic(1);
            if !records.is_empty() {
                assert_eq!(records[0].upload, 4);
                assert_eq!(records[0].download, 4);
                service.stop();
                return;
            }
            thread::sleep(Duration::from_millis(20));
        }
        service.stop();
        panic!("traffic was not recorded");
    }

    #[test]
    fn starts_trojan_listener_from_core_config() {
        let mut config = config(free_port());
        config.inbounds[0].tag = "panel|trojan|1".to_string();
        config.inbounds[0].protocol = Protocol::Trojan;

        let mut service = CoreService::start(config).expect("service start");
        let listeners = service.listeners();

        assert_eq!(listeners.len(), 1);
        assert_eq!(listeners[0].protocol, Protocol::Trojan);
        service.stop();
    }

    #[test]
    fn apply_user_delta_targets_one_inbound_without_rebinding_or_cross_affecting() {
        let echo = EchoServer::start();
        let old_vless_uuid = "11111111-1111-1111-1111-111111111111";
        let new_vless_uuid = "22222222-2222-2222-2222-222222222222";
        let mut vless_user = user();
        vless_user.uuid = old_vless_uuid.to_string();
        let mut trojan_user = user();
        trojan_user.id = 2;
        trojan_user.uuid = "trojan-password".to_string();

        let mut config = config(free_port());
        config.inbounds[0].tag = "panel|vless|1".to_string();
        config.inbounds[0].protocol = Protocol::Vless;
        config.inbounds[0].users = vec![vless_user.clone()];
        let mut trojan_inbound = config.inbounds[0].clone();
        trojan_inbound.tag = "panel|trojan|1".to_string();
        trojan_inbound.protocol = Protocol::Trojan;
        trojan_inbound.port = free_port();
        trojan_inbound.users = vec![trojan_user.clone()];
        config.inbounds.push(trojan_inbound);

        let mut service = CoreService::start(config).expect("service start");
        let before = service.listeners();
        let vless_addr = before
            .iter()
            .find(|listener| listener.tag == "panel|vless|1")
            .expect("vless listener")
            .local_addr;
        let trojan_addr = before
            .iter()
            .find(|listener| listener.tag == "panel|trojan|1")
            .expect("trojan listener")
            .local_addr;

        assert!(vless_auth_succeeds_eventually(
            vless_addr,
            old_vless_uuid,
            echo.addr
        ));
        assert!(trojan_auth_succeeds_eventually(
            trojan_addr,
            "trojan-password",
            echo.addr
        ));

        let mut added = vless_user.clone();
        added.id = 3;
        added.uuid = new_vless_uuid.to_string();
        added.speed_limit = 1024;
        added.device_limit = 2;
        let result = service
            .apply_user_delta(
                "panel|vless|1",
                &CoreUserDelta {
                    added: vec![added],
                    deleted: vec![old_vless_uuid.to_string()],
                    revision: Some("rev-2".to_string()),
                    ..CoreUserDelta::default()
                },
            )
            .expect("delta apply");

        assert_eq!(result.added, 1);
        assert_eq!(result.deleted, 1);
        assert_eq!(result.active_users, 1);
        assert_eq!(service.listeners(), before);
        assert!(!vless_auth_succeeds(vless_addr, old_vless_uuid, echo.addr));
        assert!(vless_auth_succeeds_eventually(
            vless_addr,
            new_vless_uuid,
            echo.addr
        ));
        assert!(
            trojan_auth_succeeds_eventually(trojan_addr, "trojan-password", echo.addr),
            "ApplyUserDelta for VLESS must not alter the Trojan inbound"
        );

        service.stop();
    }

    #[test]
    fn apply_user_delta_targets_hysteria2_without_rebinding_or_affecting_tuic() {
        let _network_guard = crate::test_support::network_test_lock();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let echo = EchoServer::start();
            let cert = test_cert("service-hy2-tuic-delta");
            let hy2_tag = "panel|hysteria|1";
            let tuic_tag = "panel|tuic|1";
            let old_hy2_uuid = "hy2-password";
            let new_hy2_uuid = "hy2-user-b";
            let tuic_uuid = "11111111-1111-1111-1111-111111111111";
            let hy2_user = core_user(10, old_hy2_uuid, None);
            let tuic_user = core_user(20, tuic_uuid, Some("tuic-password"));

            let mut config = config(free_port());
            config.inbounds = vec![
                quic_inbound(
                    hy2_tag,
                    Protocol::Hysteria2,
                    "hysteria",
                    free_port(),
                    vec![hy2_user.clone()],
                    &cert,
                ),
                quic_inbound(
                    tuic_tag,
                    Protocol::Tuic,
                    "tuic",
                    free_port(),
                    vec![tuic_user.clone()],
                    &cert,
                ),
            ];

            let mut service = CoreService::start(config).expect("service start");
            let before = service.listeners();
            let hy2_addr = before
                .iter()
                .find(|listener| listener.tag == hy2_tag)
                .expect("hy2 listener")
                .local_addr;
            let tuic_addr = before
                .iter()
                .find(|listener| listener.tag == tuic_tag)
                .expect("tuic listener")
                .local_addr;

            tokio::time::sleep(Duration::from_millis(100)).await;
            assert!(hy2_auth_succeeds(hy2_addr, cert.cert_der.clone(), old_hy2_uuid).await);
            assert!(
                tuic_tcp_probe_eventually(
                    tuic_addr,
                    cert.cert_der.clone(),
                    tuic_uuid,
                    "tuic-password",
                    echo.addr
                )
                .await
            );

            let mut added = core_user(11, new_hy2_uuid, Some("secret-b"));
            added.speed_limit = 2048;
            added.device_limit = 2;
            let result = service
                .apply_user_delta(
                    hy2_tag,
                    &CoreUserDelta {
                        added: vec![added],
                        deleted: vec![old_hy2_uuid.to_string()],
                        revision: Some("hy2-rev-2".to_string()),
                        ..CoreUserDelta::default()
                    },
                )
                .expect("hy2 delta apply");

            assert_eq!(result.added, 1);
            assert_eq!(result.deleted, 1);
            assert_eq!(result.active_users, 1);
            assert_eq!(service.listeners(), before);
            assert!(
                !hy2_auth_succeeds(hy2_addr, cert.cert_der.clone(), old_hy2_uuid).await,
                "deleted HY2 user must not authenticate after delta"
            );
            assert!(
                hy2_auth_succeeds(hy2_addr, cert.cert_der.clone(), "secret-b").await,
                "added HY2 user must authenticate after delta"
            );
            assert!(
                tuic_tcp_probe_eventually(
                    tuic_addr,
                    cert.cert_der.clone(),
                    tuic_uuid,
                    "tuic-password",
                    echo.addr
                )
                .await,
                "ApplyUserDelta for HY2 must not alter the TUIC inbound"
            );

            service.stop();
        });
    }

    #[test]
    fn apply_user_delta_targets_tuic_without_rebinding_or_affecting_hysteria2() {
        let _network_guard = crate::test_support::network_test_lock();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let echo = EchoServer::start();
            let cert = test_cert("service-tuic-hy2-delta");
            let hy2_tag = "panel|hysteria|1";
            let tuic_tag = "panel|tuic|1";
            let hy2_uuid = "hy2-password";
            let old_tuic_uuid = "11111111-1111-1111-1111-111111111111";
            let new_tuic_uuid = "22222222-2222-2222-2222-222222222222";
            let hy2_user = core_user(10, hy2_uuid, None);
            let tuic_user = core_user(20, old_tuic_uuid, Some("tuic-password"));

            let mut config = config(free_port());
            config.inbounds = vec![
                quic_inbound(
                    hy2_tag,
                    Protocol::Hysteria2,
                    "hysteria",
                    free_port(),
                    vec![hy2_user.clone()],
                    &cert,
                ),
                quic_inbound(
                    tuic_tag,
                    Protocol::Tuic,
                    "tuic",
                    free_port(),
                    vec![tuic_user.clone()],
                    &cert,
                ),
            ];

            let mut service = CoreService::start(config).expect("service start");
            let before = service.listeners();
            let hy2_addr = before
                .iter()
                .find(|listener| listener.tag == hy2_tag)
                .expect("hy2 listener")
                .local_addr;
            let tuic_addr = before
                .iter()
                .find(|listener| listener.tag == tuic_tag)
                .expect("tuic listener")
                .local_addr;

            tokio::time::sleep(Duration::from_millis(100)).await;
            assert!(hy2_auth_succeeds(hy2_addr, cert.cert_der.clone(), hy2_uuid).await);
            assert!(
                tuic_tcp_probe_eventually(
                    tuic_addr,
                    cert.cert_der.clone(),
                    old_tuic_uuid,
                    "tuic-password",
                    echo.addr
                )
                .await
            );

            let mut added = core_user(21, new_tuic_uuid, Some("secret-b"));
            added.speed_limit = 4096;
            added.device_limit = 3;
            let result = service
                .apply_user_delta(
                    tuic_tag,
                    &CoreUserDelta {
                        added: vec![added],
                        deleted: vec![old_tuic_uuid.to_string()],
                        revision: Some("tuic-rev-2".to_string()),
                        ..CoreUserDelta::default()
                    },
                )
                .expect("tuic delta apply");

            assert_eq!(result.added, 1);
            assert_eq!(result.deleted, 1);
            assert_eq!(result.active_users, 1);
            assert_eq!(service.listeners(), before);
            assert!(
                !tuic_tcp_probe(
                    tuic_addr,
                    cert.cert_der.clone(),
                    old_tuic_uuid,
                    "tuic-password",
                    echo.addr
                )
                .await,
                "deleted TUIC user must not authenticate after delta"
            );
            assert!(
                tuic_tcp_probe_eventually(
                    tuic_addr,
                    cert.cert_der.clone(),
                    new_tuic_uuid,
                    "secret-b",
                    echo.addr
                )
                .await,
                "added TUIC user must authenticate after delta"
            );
            assert!(
                hy2_auth_succeeds(hy2_addr, cert.cert_der.clone(), hy2_uuid).await,
                "ApplyUserDelta for TUIC must not alter the HY2 inbound"
            );

            service.stop();
        });
    }

    #[test]
    fn starts_shadowsocks_listener_from_core_config() {
        let mut config = config(free_port());
        config.inbounds[0].tag = "panel|shadowsocks|1".to_string();
        config.inbounds[0].protocol = Protocol::Shadowsocks;
        config.inbounds[0].cipher = Some("aes-128-gcm".to_string());

        let mut service = CoreService::start(config).expect("service start");
        let listeners = service.listeners();

        assert_eq!(listeners.len(), 1);
        assert_eq!(listeners[0].protocol, Protocol::Shadowsocks);
        service.stop();
    }

    #[test]
    fn starts_anytls_listener_from_core_config() {
        let mut config = config(free_port());
        config.inbounds[0].tag = "panel|anytls|1".to_string();
        config.inbounds[0].protocol = Protocol::AnyTls;

        let mut service = CoreService::start(config).expect("service start");
        let listeners = service.listeners();

        assert_eq!(listeners.len(), 1);
        assert_eq!(listeners[0].protocol, Protocol::AnyTls);
        service.stop();
    }

    #[test]
    fn starts_naive_listener_from_core_config() {
        let cert = test_cert("naive");
        let mut config = config(free_port());
        config.inbounds[0].tag = "panel|naive|1".to_string();
        config.inbounds[0].protocol = Protocol::Naive;
        config.inbounds[0].tls = Some(TlsConfig {
            server_name: "localhost".to_string(),
            cert_file: Some(cert.cert_path.to_string_lossy().to_string()),
            key_file: Some(cert.key_path.to_string_lossy().to_string()),
            alpn: Vec::new(),
            reject_unknown_sni: false,
            reality: None,
        });

        let mut service = CoreService::start(config).expect("service start");
        let listeners = service.listeners();

        assert_eq!(listeners.len(), 1);
        assert_eq!(listeners[0].protocol, Protocol::Naive);
        service.stop();
    }

    #[test]
    fn starts_naive_h3_listener_from_core_config() {
        let cert = test_cert("naive-h3");
        let mut config = config(free_udp_port());
        config.inbounds[0].tag = "panel|naive-h3|1".to_string();
        config.inbounds[0].protocol = Protocol::Naive;
        config.inbounds[0].transport = TransportConfig {
            network: "quic".to_string(),
            ..TransportConfig::default()
        };
        config.inbounds[0].tls = Some(TlsConfig {
            server_name: "localhost".to_string(),
            cert_file: Some(cert.cert_path.to_string_lossy().to_string()),
            key_file: Some(cert.key_path.to_string_lossy().to_string()),
            alpn: vec!["h3".to_string()],
            reject_unknown_sni: false,
            reality: None,
        });

        let mut service = CoreService::start(config).expect("service start");
        let listeners = service.listeners();

        assert_eq!(listeners.len(), 1);
        assert_eq!(listeners[0].protocol, Protocol::Naive);
        service.stop();
    }

    #[test]
    fn naive_h3_listener_proxies_tcp_and_records_traffic() {
        let cert = test_cert("naive-h3-proxy");
        let greeting = GreetingServer::start(b"x");
        let mut config = config(free_udp_port());
        config.inbounds[0].tag = "panel|naive-h3|1".to_string();
        config.inbounds[0].protocol = Protocol::Naive;
        config.inbounds[0].transport = TransportConfig {
            network: "quic".to_string(),
            ..TransportConfig::default()
        };
        config.inbounds[0].tls = Some(TlsConfig {
            server_name: "localhost".to_string(),
            cert_file: Some(cert.cert_path.to_string_lossy().to_string()),
            key_file: Some(cert.key_path.to_string_lossy().to_string()),
            alpn: vec!["h3".to_string()],
            reject_unknown_sni: false,
            reality: None,
        });
        let mut service = CoreService::start(config).expect("service start");
        let server_addr = service.listeners()[0].local_addr;
        thread::sleep(Duration::from_millis(50));

        let runtime = tokio::runtime::Runtime::new().expect("runtime");
        let output = runtime
            .block_on(naive_h3_connect_round_trip(
                server_addr,
                cert.cert_der.clone(),
                greeting.addr,
                "user-a",
                "user-a",
            ))
            .expect("naive h3 proxy");

        assert_eq!(output, b"x");
        let mut traffic = Vec::new();
        for _ in 0..50 {
            traffic = service.drain_traffic(1);
            if !traffic.is_empty() {
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(traffic.len(), 1);
        assert_eq!(traffic[0].user_id, Some(1));
        assert_eq!(traffic[0].upload, 0);
        assert_eq!(traffic[0].download, 1);
        service.stop();
    }

    #[test]
    fn naive_h3_listener_handles_repeated_client_reconnects() {
        let cert = test_cert("naive-h3-reconnect");
        let greeting = GreetingServer::start(b"r");
        let mut config = config(free_udp_port());
        config.inbounds[0].tag = "panel|naive-h3|1".to_string();
        config.inbounds[0].protocol = Protocol::Naive;
        config.inbounds[0].transport = TransportConfig {
            network: "quic".to_string(),
            ..TransportConfig::default()
        };
        config.inbounds[0].tls = Some(TlsConfig {
            server_name: "localhost".to_string(),
            cert_file: Some(cert.cert_path.to_string_lossy().to_string()),
            key_file: Some(cert.key_path.to_string_lossy().to_string()),
            alpn: vec!["h3".to_string()],
            reject_unknown_sni: false,
            reality: None,
        });
        let mut service = CoreService::start(config).expect("service start");
        let server_addr = service.listeners()[0].local_addr;
        thread::sleep(Duration::from_millis(50));

        let runtime = tokio::runtime::Runtime::new().expect("runtime");
        for _ in 0..5 {
            let output = runtime
                .block_on(naive_h3_connect_round_trip(
                    server_addr,
                    cert.cert_der.clone(),
                    greeting.addr,
                    "user-a",
                    "user-a",
                ))
                .expect("naive h3 reconnect");
            assert_eq!(output, b"r");
            thread::sleep(Duration::from_millis(10));
        }

        let mut traffic = Vec::new();
        for _ in 0..50 {
            traffic = service.drain_traffic(1);
            if !traffic.is_empty() {
                break;
            }
            thread::sleep(Duration::from_millis(20));
        }
        assert_eq!(traffic.len(), 1);
        assert_eq!(traffic[0].user_id, Some(1));
        assert_eq!(traffic[0].upload, 0);
        assert_eq!(traffic[0].download, 5);
        service.stop();
    }

    #[test]
    fn starts_http_listener_from_core_config() {
        let mut config = config(free_port());
        config.inbounds[0].tag = "panel|http|1".to_string();
        config.inbounds[0].protocol = Protocol::Http;

        let mut service = CoreService::start(config).expect("service start");
        let listeners = service.listeners();

        assert_eq!(listeners.len(), 1);
        assert_eq!(listeners[0].protocol, Protocol::Http);
        service.stop();
    }
}
