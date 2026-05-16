use std::collections::{HashMap, VecDeque};
use std::fmt;
use std::future::Future;
use std::io;
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime};

use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer};
use serde::{Deserialize, Serialize};

use crate::anytls::{AnyTlsServer, AnyTlsServerConfig};
use crate::config::{CoreConfig, InboundConfig, TransportConfig, ValidationError};
use crate::grpc::{
    run_grpc_listener, GrpcHunkReader, GrpcHunkWriter, GrpcStreamHandler, GrpcTlsConfig,
};
use crate::http_proxy::{HttpProxyServer, HttpProxyServerConfig};
use crate::httpupgrade::{accept_httpupgrade, accept_httpupgrade_tls};
use crate::hysteria2::{Hysteria2ObfsConfig, Hysteria2Server, Hysteria2ServerConfig};
use crate::limits::{UserBandwidthLimiters, UserSessionTracker};
use crate::mieru::{MieruServer, MieruServerConfig};
use crate::protocol::Protocol;
use crate::quic_resources::{QuicResourceSnapshot, SharedQuicConnectionLimiter};
use crate::reality::{
    decode_reality_private_key, decode_short_id, generate_reality_temporary_certificate,
    handle_reality_preface, RealityAuthConfig, RealityGatewayConfig, RealityGatewayResult,
};
use crate::shadowsocks::{ShadowsocksServer, ShadowsocksServerConfig};
use crate::socket_bind::bind_dual_stack_tcp_listener;
use crate::socks5::{Socks5Server, Socks5ServerConfig};
use crate::tls::{relay_tls_stream, TlsAcceptor, TlsConnection};
use crate::traffic::{SharedTrafficRegistry, TrafficDelta, TrafficRegistry};
use crate::trojan::{TrojanServer, TrojanServerConfig};
use crate::tuic::{TuicServer, TuicServerConfig};
use crate::user::{CoreUser, CoreUserDelta, CoreUserDeltaResult};
use crate::vless::{VlessServer, VlessServerConfig};
use crate::vmess::{VmessServer, VmessServerConfig};

const MAX_CONNECTION_WORKERS_PER_LISTENER: usize = 1024;
const MIN_AUTO_CONNECTION_WORKERS: usize = 32;
const CONNECTION_WORKERS_PER_CPU: usize = 64;
const CONNECTION_WORKER_MEMORY_MIB: usize = 4;
const CONNECTION_WORKER_RESERVED_FDS: usize = 512;
const CONNECTION_WORKER_FDS_PER_CONN: usize = 2;
const CONNECTION_WORKER_IDLE_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECTION_WORKER_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(3);
const DEFAULT_OUTBOUND_CONNECT_TIMEOUT_SECS: u64 = 3;
const QUIC_RUNTIME_SHUTDOWN_TIMEOUT: Duration = Duration::from_secs(3);
static TCP_ACCEPT_RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
static CONNECTION_WORKER_POOL: OnceLock<ConnectionWorkerPool> = OnceLock::new();

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
    bandwidth: UserBandwidthLimiters,
    quic_connections: Option<SharedQuicConnectionLimiter>,
    user_revisions: HashMap<String, String>,
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
        }
    }
}

impl CoreService {
    pub fn start(config: CoreConfig) -> Result<Self, CoreServiceError> {
        config.validate().map_err(CoreServiceError::InvalidConfig)?;
        validate_unique_listener_binds(&config.inbounds)
            .map_err(CoreServiceError::InvalidConfig)?;
        crate::dns::configure(config.dns.clone());
        let active_config = config_without_users(&config);

        let traffic = TrafficRegistry::shared();
        let sessions = UserSessionTracker::default();
        let bandwidth = UserBandwidthLimiters::default();
        let quic_listener_count = config
            .inbounds
            .iter()
            .filter(|inbound| is_quic_protocol(&inbound.protocol))
            .count();
        let quic_connections = (quic_listener_count > 0)
            .then(|| SharedQuicConnectionLimiter::for_listener_count(quic_listener_count));
        if let Some(limiter) = &quic_connections {
            let snapshot = limiter.snapshot();
            println!(
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
            );
        }
        let mut listeners = Vec::new();
        for inbound in config.inbounds {
            let routes = active_config.resolved_inbound_routes(&inbound);
            let handle = match inbound.protocol {
                Protocol::Socks => start_socks_listener(
                    &inbound,
                    routes.clone(),
                    traffic.clone(),
                    sessions.clone(),
                    bandwidth.clone(),
                )?,
                Protocol::Http => start_http_listener(
                    &inbound,
                    routes.clone(),
                    traffic.clone(),
                    sessions.clone(),
                    bandwidth.clone(),
                )?,
                Protocol::Vless => start_vless_listener(
                    &inbound,
                    routes.clone(),
                    traffic.clone(),
                    sessions.clone(),
                    bandwidth.clone(),
                )?,
                Protocol::Vmess => start_vmess_listener(
                    &inbound,
                    routes.clone(),
                    traffic.clone(),
                    sessions.clone(),
                    bandwidth.clone(),
                )?,
                Protocol::Trojan => start_trojan_listener(
                    &inbound,
                    routes.clone(),
                    traffic.clone(),
                    sessions.clone(),
                    bandwidth.clone(),
                )?,
                Protocol::Shadowsocks => start_shadowsocks_listener(
                    &inbound,
                    routes.clone(),
                    traffic.clone(),
                    sessions.clone(),
                    bandwidth.clone(),
                )?,
                Protocol::AnyTls => start_anytls_listener(
                    &inbound,
                    routes.clone(),
                    traffic.clone(),
                    sessions.clone(),
                    bandwidth.clone(),
                )?,
                Protocol::Tuic => start_tuic_listener(
                    &inbound,
                    routes.clone(),
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
                    traffic.clone(),
                    sessions.clone(),
                    bandwidth.clone(),
                )?,
                _ => {
                    return Err(CoreServiceError::UnsupportedProtocol {
                        tag: inbound.tag,
                        protocol: inbound.protocol,
                    });
                }
            };
            listeners.push(handle);
        }

        Ok(Self {
            config: active_config,
            listeners,
            traffic,
            bandwidth,
            quic_connections,
            user_revisions: HashMap::new(),
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

    pub fn drain_traffic(&self, minimum_bytes: u64) -> Vec<TrafficDelta> {
        self.traffic.drain_minimum(minimum_bytes)
    }

    pub fn requeue_traffic(&self, records: Vec<TrafficDelta>) {
        self.traffic.add_deltas(records);
    }

    pub fn can_update_users(&self, config: &CoreConfig) -> bool {
        config_without_users(&self.config) == config_without_users(config)
    }

    pub fn update_users(&mut self, config: CoreConfig) {
        for inbound in &config.inbounds {
            if let Some(handle) = self
                .listeners
                .iter()
                .find(|handle| handle.status.tag == inbound.tag)
            {
                handle.runtime.replace_users(inbound.users.clone());
            }
        }
        self.user_revisions.clear();
        self.config = config_without_users(&config);
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
                eprintln!(
                    "WARN  core   listener worker shutdown timed out tag={} protocol={:?}",
                    handle.status.tag, handle.status.protocol
                );
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
    let mut config = config.clone();
    for inbound in &mut config.inbounds {
        inbound.users.clear();
    }
    config
}

fn outbound_connect_timeout() -> Duration {
    outbound_connect_timeout_from_env(std::env::var("KELI_CORE_OUTBOUND_CONNECT_TIMEOUT_SECS").ok())
}

fn outbound_connect_timeout_from_env(value: Option<String>) -> Duration {
    value
        .as_deref()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|seconds| *seconds > 0)
        .map(|seconds| Duration::from_secs(seconds.clamp(1, 60)))
        .unwrap_or_else(|| Duration::from_secs(DEFAULT_OUTBOUND_CONNECT_TIMEOUT_SECS))
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
    let server = VmessServer::with_shared_limits(
        VmessServerConfig {
            node_tag: inbound.tag.clone(),
            listen,
            users: inbound.users.clone(),
            routes,
            connect_timeout: outbound_connect_timeout(),
        },
        traffic,
        sessions,
        bandwidth,
    );
    if inbound.transport.network.trim() == "grpc" {
        let grpc_server = server.clone();
        let handler: GrpcStreamHandler =
            Arc::new(move |reader: GrpcHunkReader, writer: GrpcHunkWriter| {
                let _ = grpc_server.handle_split_client(reader, writer);
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
            let result = if let Some(acceptor) = tls_acceptor {
                acceptor
                    .accept(stream)
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
            };
            let _ = result;
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
            connect_timeout: outbound_connect_timeout(),
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
            connect_timeout: outbound_connect_timeout(),
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
    let server = AnyTlsServer::with_shared_limits(
        AnyTlsServerConfig {
            node_tag: inbound.tag.clone(),
            listen,
            users: inbound.users.clone(),
            routes,
            connect_timeout: outbound_connect_timeout(),
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
    let runtime_server = server.clone();
    let join = spawn_tcp_accept_loop(
        listener,
        stop_for_thread,
        workers_for_thread,
        move |stream| {
            let server = server.clone();
            let tls_acceptor = tls_acceptor.clone();
            let result = if let Some(acceptor) = tls_acceptor {
                acceptor
                    .accept(stream)
                    .and_then(local_bridge_for_tls)
                    .and_then(|stream| server.handle_tcp_client(stream))
            } else {
                server.handle_tcp_client(stream)
            };
            let _ = result;
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

    let _ = crate::stream::spawn_native_blocking_relay(move || {
        let _ = relay_tls_stream(tls, local_plain, None);
    })?;

    Ok(local_client)
}

fn start_shadowsocks_listener(
    inbound: &InboundConfig,
    routes: Vec<crate::RouteRule>,
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
            connect_timeout: outbound_connect_timeout(),
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
            let _ = server.handle_tcp_client(stream);
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
    let server = TrojanServer::with_shared_limits(
        TrojanServerConfig {
            node_tag: inbound.tag.clone(),
            listen,
            users: inbound.users.clone(),
            routes,
            connect_timeout: outbound_connect_timeout(),
        },
        traffic,
        sessions,
        bandwidth,
    );
    if inbound.transport.network.trim() == "grpc" {
        let grpc_server = server.clone();
        let handler: GrpcStreamHandler =
            Arc::new(move |reader: GrpcHunkReader, writer: GrpcHunkWriter| {
                let _ = grpc_server.handle_split_client(reader, writer);
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
            let result = if let Some(acceptor) = tls_acceptor {
                acceptor
                    .accept(stream)
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
            };
            let _ = result;
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

fn start_vless_listener(
    inbound: &InboundConfig,
    routes: Vec<crate::RouteRule>,
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
    let server = VlessServer::with_shared_limits(
        VlessServerConfig {
            node_tag: inbound.tag.clone(),
            listen,
            users: inbound.users.clone(),
            routes,
            flow: inbound.flow.clone(),
            connect_timeout: outbound_connect_timeout(),
        },
        traffic,
        sessions,
        bandwidth,
    );
    if inbound.transport.network.trim() == "grpc" {
        let grpc_server = server.clone();
        let handler: GrpcStreamHandler =
            Arc::new(move |reader: GrpcHunkReader, writer: GrpcHunkWriter| {
                let _ = grpc_server.handle_split_client(reader, writer);
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
        return start_vless_reality_listener(inbound, listen, server);
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
    let runtime_server = server.clone();
    if tls_acceptor.is_none() && network == "tcp" {
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
            let result = if let Some(acceptor) = tls_acceptor {
                acceptor
                    .accept(stream)
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
            };
            let _ = result;
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
            connect_timeout: outbound_connect_timeout(),
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
            let _ = server.handle_tcp_client(stream);
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
            connect_timeout: outbound_connect_timeout(),
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
            let _ = server.handle_tcp_client(stream);
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

fn start_http_listener(
    inbound: &InboundConfig,
    routes: Vec<crate::RouteRule>,
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
            connect_timeout: outbound_connect_timeout(),
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
            let _ = server.handle_tcp_client(stream);
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
) -> Result<ListenerHandle, CoreServiceError> {
    let gateway = reality_gateway_config(inbound)?;
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
            let trace = reality_trace_enabled();
            let peer = stream
                .peer_addr()
                .map(|addr| addr.to_string())
                .unwrap_or_else(|_| "<unknown>".to_string());
            if trace {
                eprintln!("keli-core-rs reality trace: accepted peer={peer}");
            }
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
                    let client = match acceptor.accept_stream(authenticated.stream) {
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
                            eprintln!(
                                "keli-core-rs reality trace: vless error peer={peer} error={error}"
                            );
                        }
                    } else if trace {
                        eprintln!("keli-core-rs reality trace: vless finished peer={peer}");
                    }
                }
                Ok(RealityGatewayResult::Fallback { reason, .. }) => {
                    if trace {
                        eprintln!(
                            "keli-core-rs reality trace: fallback peer={peer} reason={reason}"
                        );
                    }
                }
                Err(error) => {
                    if trace {
                        eprintln!(
                            "keli-core-rs reality trace: preface error peer={peer} error={error}"
                        );
                    }
                }
            }
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
        connect_timeout: outbound_connect_timeout(),
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

type ConnectionWorkerJob = Box<dyn FnOnce() + Send + 'static>;

#[derive(Debug, Clone)]
struct ConnectionWorkerGroup {
    state: Arc<ConnectionWorkerGroupState>,
}

#[derive(Debug)]
struct ConnectionWorkerGroupState {
    active: Mutex<usize>,
    finished: Condvar,
}

struct ConnectionWorkerPool {
    queue: Mutex<VecDeque<ConnectionWorkerJob>>,
    ready: Condvar,
    worker_count: std::sync::atomic::AtomicUsize,
    idle_count: std::sync::atomic::AtomicUsize,
    pending_count: std::sync::atomic::AtomicUsize,
    max_workers: usize,
}

impl std::fmt::Debug for ConnectionWorkerPool {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConnectionWorkerPool")
            .field("worker_count", &self.worker_count.load(Ordering::Relaxed))
            .field("idle_count", &self.idle_count.load(Ordering::Relaxed))
            .field("pending_count", &self.pending_count.load(Ordering::Relaxed))
            .field("max_workers", &self.max_workers)
            .finish_non_exhaustive()
    }
}

impl ConnectionWorkerGroup {
    fn new() -> Self {
        Self {
            state: Arc::new(ConnectionWorkerGroupState {
                active: Mutex::new(0),
                finished: Condvar::new(),
            }),
        }
    }

    fn spawn<F>(&self, task: F) -> bool
    where
        F: FnOnce() + Send + 'static,
    {
        if !self.state.acquire() {
            return false;
        }

        let state = Arc::clone(&self.state);
        let job = Box::new(move || {
            let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(task));
            state.release();
        });

        if connection_worker_pool().submit(job) {
            true
        } else {
            self.state.release();
            false
        }
    }

    fn spawn_async<F>(&self, future: F) -> bool
    where
        F: Future<Output = ()> + Send + 'static,
    {
        if !self.state.acquire() {
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
}

struct ConnectionWorkerAsyncGuard {
    state: Arc<ConnectionWorkerGroupState>,
}

impl Drop for ConnectionWorkerAsyncGuard {
    fn drop(&mut self) {
        self.state.release();
    }
}

impl ConnectionWorkerGroupState {
    fn acquire(&self) -> bool {
        let mut active = self.active.lock().expect("worker group lock poisoned");
        if *active >= MAX_CONNECTION_WORKERS_PER_LISTENER {
            return false;
        }
        *active += 1;
        true
    }

    fn release(&self) {
        let mut active = self.active.lock().expect("worker group lock poisoned");
        *active = active.saturating_sub(1);
        if *active == 0 {
            self.finished.notify_all();
        }
    }

    fn wait_until_idle_timeout(&self, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        let mut active = self.active.lock().expect("worker group lock poisoned");
        while *active > 0 {
            let now = Instant::now();
            if now >= deadline {
                return false;
            }
            let remaining = deadline.saturating_duration_since(now);
            let (next_active, wait_result) = self
                .finished
                .wait_timeout(active, remaining)
                .expect("worker group lock poisoned");
            active = next_active;
            if wait_result.timed_out() && *active > 0 {
                return false;
            }
        }
        true
    }
}

impl ConnectionWorkerPool {
    fn new() -> Self {
        let max_workers = connection_worker_threads();
        println!(
            "INFO  core   connection workers auto max={} stack_kib={} cpu={} mem_limit_mib={} fd_limit={}",
            max_workers,
            connection_worker_stack_size() / 1024,
            available_parallelism_count(),
            memory_limit_mib()
                .map(|value| value.to_string())
                .unwrap_or_else(|| "unknown".to_string()),
            open_file_soft_limit()
                .map(|value| value.to_string())
                .unwrap_or_else(|| "unknown".to_string())
        );
        Self {
            queue: Mutex::new(VecDeque::new()),
            ready: Condvar::new(),
            worker_count: std::sync::atomic::AtomicUsize::new(0),
            idle_count: std::sync::atomic::AtomicUsize::new(0),
            pending_count: std::sync::atomic::AtomicUsize::new(0),
            max_workers,
        }
    }

    fn submit(&'static self, job: ConnectionWorkerJob) -> bool {
        if !self.ensure_worker_available() {
            return false;
        }

        self.pending_count.fetch_add(1, Ordering::Relaxed);
        {
            let mut queue = self
                .queue
                .lock()
                .expect("connection worker queue lock poisoned");
            queue.push_back(job);
        }
        self.ready.notify_one();
        self.spawn_extra_worker_if_needed();
        true
    }

    fn ensure_worker_available(&'static self) -> bool {
        if self.worker_count.load(Ordering::Acquire) > 0 {
            return true;
        }
        self.spawn_worker()
    }

    fn spawn_extra_worker_if_needed(&'static self) {
        let pending = self.pending_count.load(Ordering::Relaxed);
        let idle = self.idle_count.load(Ordering::Relaxed);
        if pending > idle {
            let _ = self.spawn_worker();
        }
    }

    fn spawn_worker(&'static self) -> bool {
        loop {
            let current = self.worker_count.load(Ordering::Acquire);
            if current >= self.max_workers {
                return current > 0;
            }
            if self
                .worker_count
                .compare_exchange(current, current + 1, Ordering::AcqRel, Ordering::Acquire)
                .is_err()
            {
                continue;
            }
            let pool = self;
            let spawned = thread::Builder::new()
                .name("keli-core-connection-worker".to_string())
                .stack_size(connection_worker_stack_size())
                .spawn(move || pool.run_worker());
            if spawned.is_ok() {
                return true;
            }
            self.worker_count.fetch_sub(1, Ordering::AcqRel);
            return false;
        }
    }

    fn run_worker(&'static self) {
        loop {
            let Some(job) = self.wait_for_job() else {
                self.worker_count.fetch_sub(1, Ordering::AcqRel);
                break;
            };
            self.pending_count.fetch_sub(1, Ordering::Relaxed);
            job();
        }
    }

    fn wait_for_job(&'static self) -> Option<ConnectionWorkerJob> {
        let mut queue = self
            .queue
            .lock()
            .expect("connection worker queue lock poisoned");
        loop {
            if let Some(job) = queue.pop_front() {
                return Some(job);
            }

            self.idle_count.fetch_add(1, Ordering::Relaxed);
            let (next_queue, wait_result) = self
                .ready
                .wait_timeout(queue, CONNECTION_WORKER_IDLE_TIMEOUT)
                .expect("connection worker queue lock poisoned");
            self.idle_count.fetch_sub(1, Ordering::Relaxed);
            queue = next_queue;

            if wait_result.timed_out()
                && queue.is_empty()
                && self.pending_count.load(Ordering::Acquire) == 0
            {
                return None;
            }
        }
    }
}

fn connection_worker_pool() -> &'static ConnectionWorkerPool {
    CONNECTION_WORKER_POOL.get_or_init(ConnectionWorkerPool::new)
}

fn is_quic_protocol(protocol: &Protocol) -> bool {
    matches!(protocol, Protocol::Hysteria2 | Protocol::Tuic)
}

fn connection_worker_threads() -> usize {
    if let Ok(value) = std::env::var("KELI_CORE_CONNECTION_WORKERS") {
        if let Ok(parsed) = value.trim().parse::<usize>() {
            return parsed.clamp(4, MAX_CONNECTION_WORKERS_PER_LISTENER);
        }
    }
    connection_worker_threads_from_resources(
        available_parallelism_count(),
        memory_limit_mib(),
        open_file_soft_limit(),
    )
}

fn connection_worker_stack_size() -> usize {
    256 * 1024
}

fn available_parallelism_count() -> usize {
    std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(4)
        .max(1)
}

fn connection_worker_threads_from_resources(
    cpu_count: usize,
    memory_limit_mib: Option<usize>,
    open_file_soft_limit: Option<usize>,
) -> usize {
    let cpu_target = cpu_count
        .max(1)
        .saturating_mul(CONNECTION_WORKERS_PER_CPU)
        .max(MIN_AUTO_CONNECTION_WORKERS);
    let memory_target = memory_limit_mib
        .map(|mib| mib / CONNECTION_WORKER_MEMORY_MIB)
        .filter(|target| *target > 0)
        .unwrap_or(MAX_CONNECTION_WORKERS_PER_LISTENER);
    let fd_target = open_file_soft_limit
        .map(|limit| {
            limit.saturating_sub(CONNECTION_WORKER_RESERVED_FDS) / CONNECTION_WORKER_FDS_PER_CONN
        })
        .filter(|target| *target > 0)
        .unwrap_or(MAX_CONNECTION_WORKERS_PER_LISTENER);
    let resource_cap = cpu_target
        .min(memory_target)
        .min(fd_target)
        .min(MAX_CONNECTION_WORKERS_PER_LISTENER);
    resource_cap.clamp(
        MIN_AUTO_CONNECTION_WORKERS.min(resource_cap),
        MAX_CONNECTION_WORKERS_PER_LISTENER,
    )
}

fn memory_limit_mib() -> Option<usize> {
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
fn open_file_soft_limit() -> Option<usize> {
    let content = std::fs::read_to_string("/proc/self/limits").ok()?;
    parse_proc_limits_open_files(&content)
}

#[cfg(not(target_os = "linux"))]
fn open_file_soft_limit() -> Option<usize> {
    None
}

fn parse_proc_meminfo_total_mib(content: &str) -> Option<usize> {
    for line in content.lines() {
        let Some(rest) = line.strip_prefix("MemTotal:") else {
            continue;
        };
        let kb = rest.split_whitespace().next()?.parse::<usize>().ok()?;
        return Some(kb / 1024);
    }
    None
}

fn parse_cgroup_memory_limit_mib(content: &str) -> Option<usize> {
    let value = content.trim();
    if value.is_empty() || value == "max" {
        return None;
    }
    let bytes = value.parse::<usize>().ok()?;
    Some(bytes / 1024 / 1024)
}

fn parse_proc_limits_open_files(content: &str) -> Option<usize> {
    for line in content.lines() {
        let Some(rest) = line.strip_prefix("Max open files") else {
            continue;
        };
        let mut parts = rest.split_whitespace();
        let soft = parts.next()?;
        if soft == "unlimited" {
            return Some(
                MAX_CONNECTION_WORKERS_PER_LISTENER * CONNECTION_WORKER_FDS_PER_CONN
                    + CONNECTION_WORKER_RESERVED_FDS,
            );
        }
        return soft.parse::<usize>().ok();
    }
    None
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
    )
}

fn protocol_binds_udp(inbound: &InboundConfig) -> bool {
    matches!(inbound.protocol, Protocol::Hysteria2 | Protocol::Tuic)
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
    use bytes::Bytes;
    use quinn::crypto::rustls::QuicClientConfig;
    use rustls::pki_types::{CertificateDer, ServerName};
    use rustls::{ClientConfig, RootCertStore};
    use sha2::{Digest, Sha224};
    use std::fs;
    use std::future::poll_fn;
    use std::io::{self, Read, Write};
    use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{mpsc, Arc};
    use std::thread;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use crate::config::{
        CoreConfig, DnsConfig, InboundConfig, OutboundConfig, RealityConfig, SniffingConfig,
        StatsConfig, TlsConfig, TransportConfig,
    };
    use crate::grpc::{decode_hunk_message, encode_grpc_hunk, take_grpc_message};
    use crate::protocol::Protocol;
    use crate::service::CoreService;
    use crate::user::{CoreUser, CoreUserDelta};

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
    fn outbound_connect_timeout_defaults_and_clamps_env_value() {
        assert_eq!(
            super::outbound_connect_timeout_from_env(None),
            Duration::from_secs(super::DEFAULT_OUTBOUND_CONNECT_TIMEOUT_SECS)
        );
        assert_eq!(
            super::outbound_connect_timeout_from_env(Some("0".to_string())),
            Duration::from_secs(super::DEFAULT_OUTBOUND_CONNECT_TIMEOUT_SECS)
        );
        assert_eq!(
            super::outbound_connect_timeout_from_env(Some("2".to_string())),
            Duration::from_secs(2)
        );
        assert_eq!(
            super::outbound_connect_timeout_from_env(Some("999".to_string())),
            Duration::from_secs(60)
        );
    }

    #[test]
    fn connection_worker_count_scales_with_cpu_when_resources_allow() {
        assert_eq!(
            super::connection_worker_threads_from_resources(4, Some(4096), Some(100_000)),
            256
        );
        assert_eq!(
            super::connection_worker_threads_from_resources(32, Some(128_000), Some(1_000_000)),
            super::MAX_CONNECTION_WORKERS_PER_LISTENER
        );
    }

    #[test]
    fn connection_worker_count_respects_memory_and_fd_caps() {
        assert_eq!(
            super::connection_worker_threads_from_resources(8, Some(512), Some(100_000)),
            128
        );
        assert_eq!(
            super::connection_worker_threads_from_resources(32, Some(8192), Some(4096)),
            1024
        );
    }

    #[test]
    fn connection_worker_count_handles_small_resource_limits() {
        assert_eq!(
            super::connection_worker_threads_from_resources(4, Some(64), Some(100_000)),
            16
        );
        assert_eq!(
            super::connection_worker_threads_from_resources(4, Some(4096), Some(600)),
            44
        );
    }

    #[test]
    fn parses_linux_memory_and_open_file_limits() {
        assert_eq!(
            super::parse_proc_meminfo_total_mib(
                "MemTotal:        3984384 kB\nMemFree:          1000 kB\n"
            ),
            Some(3891)
        );
        assert_eq!(
            super::parse_cgroup_memory_limit_mib("536870912\n"),
            Some(512)
        );
        assert_eq!(super::parse_cgroup_memory_limit_mib("max\n"), None);
        assert_eq!(
            super::parse_proc_limits_open_files(
                "Limit                     Soft Limit           Hard Limit           Units\nMax open files            1048576              1048576              files\n"
            ),
            Some(1_048_576)
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

    trait AsyncIo: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}

    impl<T> AsyncIo for T where T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}

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

    fn config(port: u16) -> CoreConfig {
        CoreConfig {
            instance_id: "node-a".to_string(),
            log_level: "info".to_string(),
            dns: DnsConfig::default(),
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

    fn vless_tcp_request(target: std::net::SocketAddr) -> Vec<u8> {
        vless_tcp_request_for_user("11111111-1111-1111-1111-111111111111", target)
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
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async move {
            let stream = tokio::net::TcpStream::connect(proxy_addr)
                .await
                .expect("grpc connect");
            let stream: Box<dyn AsyncIo> = if let Some(cert_der) = cert_der {
                let mut roots = RootCertStore::empty();
                roots.add(cert_der).expect("root cert");
                let config = ClientConfig::builder()
                    .with_root_certificates(roots)
                    .with_no_client_auth();
                let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
                let server_name = ServerName::try_from("localhost")
                    .expect("server name")
                    .to_owned();
                let tls = connector
                    .connect(server_name, stream)
                    .await
                    .expect("tls connect");
                Box::new(tls)
            } else {
                Box::new(stream)
            };
            let (mut client, connection) =
                h2::client::handshake(stream).await.expect("h2 handshake");
            tokio::spawn(async move {
                let _ = connection.await;
            });

            let request = http::Request::builder()
                .method("POST")
                .uri("/GunService/Tun")
                .header("content-type", "application/grpc")
                .body(())
                .expect("grpc request");
            let (response, mut send) = client.send_request(request, false).expect("send request");
            send.send_data(
                Bytes::from(encode_grpc_hunk(&vless_tcp_request(echo_addr))),
                false,
            )
            .expect("send vless request");
            send.send_data(Bytes::from(encode_grpc_hunk(b"ping")), true)
                .expect("send vless payload");

            let response = response.await.expect("grpc response");
            assert_eq!(response.status(), http::StatusCode::OK);
            let mut body = response.into_body();
            let mut frames = Vec::new();
            let mut plain = Vec::new();
            while plain.len() < 6 {
                let chunk = body
                    .data()
                    .await
                    .expect("grpc data")
                    .expect("grpc data chunk");
                let len = chunk.len();
                frames.extend_from_slice(&chunk);
                let _ = body.flow_control().release_capacity(len);
                while let Some(message) = take_grpc_message(&mut frames).expect("grpc frame") {
                    plain.extend_from_slice(&decode_hunk_message(&message).expect("grpc hunk"));
                }
            }
            assert_eq!(&plain[..2], &[0x00, 0x00]);
            assert_eq!(&plain[2..6], b"ping");
        });
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
    fn rejects_external_sidecar_protocols() {
        let mut config = config(free_port());
        config.inbounds[0].protocol = Protocol::Naive;

        let error = CoreService::start(config).expect_err("naive should not start in core");

        assert!(error.to_string().contains("external sidecar"));
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
            super::reality_gateway_config(&config.inbounds[0]).expect("reality gateway config");
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
        let gateway =
            super::reality_gateway_config(&config.inbounds[0]).expect("reality gateway config");

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

        run_grpc_vless_client(grpc_addr, echo_addr, None);
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

        run_grpc_vless_client(grpc_addr, echo_addr, Some(cert.cert_der.clone()));
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
