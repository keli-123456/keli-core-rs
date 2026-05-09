use std::collections::VecDeque;
use std::fmt;
use std::io;
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Condvar, Mutex, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, SystemTime};

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
use crate::reality::{
    decode_reality_private_key, decode_short_id, generate_reality_temporary_certificate,
    handle_reality_preface, RealityAuthConfig, RealityGatewayConfig, RealityGatewayResult,
};
use crate::shadowsocks::{ShadowsocksServer, ShadowsocksServerConfig};
use crate::socks5::{Socks5Server, Socks5ServerConfig};
use crate::tls::TlsAcceptor;
use crate::traffic::{TrafficDelta, TrafficRegistry};
use crate::trojan::{TrojanServer, TrojanServerConfig};
use crate::tuic::{TuicServer, TuicServerConfig};
use crate::user::CoreUser;
use crate::vless::{VlessServer, VlessServerConfig};
use crate::vmess::{VmessServer, VmessServerConfig};

const MAX_CONNECTION_WORKERS_PER_LISTENER: usize = 4096;
const CONNECTION_WORKER_IDLE_TIMEOUT: Duration = Duration::from_secs(30);
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
    traffic: Arc<Mutex<TrafficRegistry>>,
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
}

impl CoreService {
    pub fn start(config: CoreConfig) -> Result<Self, CoreServiceError> {
        config.validate().map_err(CoreServiceError::InvalidConfig)?;
        crate::dns::configure(config.dns.clone());
        let active_config = config.clone();

        let traffic = Arc::new(Mutex::new(TrafficRegistry::default()));
        let sessions = UserSessionTracker::default();
        let bandwidth = UserBandwidthLimiters::default();
        let mut listeners = Vec::new();
        let routes = config.resolved_routes();

        for inbound in config.inbounds {
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
                )?,
                Protocol::Hysteria2 => start_hysteria2_listener(
                    &inbound,
                    routes.clone(),
                    traffic.clone(),
                    sessions.clone(),
                    bandwidth.clone(),
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
        })
    }

    pub fn listeners(&self) -> Vec<ListenerStatus> {
        self.listeners
            .iter()
            .map(|handle| handle.status.clone())
            .collect()
    }

    pub fn drain_traffic(&self, minimum_bytes: u64) -> Vec<TrafficDelta> {
        self.traffic
            .lock()
            .expect("traffic registry lock poisoned")
            .drain_minimum(minimum_bytes)
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
        self.config = config;
    }

    pub fn stop(&mut self) {
        for handle in &self.listeners {
            handle.stop.store(true, Ordering::SeqCst);
            let _ = TcpStream::connect(handle.status.local_addr);
        }

        for handle in &mut self.listeners {
            if let Some(join) = handle.join.take() {
                let _ = join.join();
            }
            handle.workers.join();
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
        std::net::TcpListener::bind(listen).map_err(|source| CoreServiceError::Bind {
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
    let runtime = tokio::runtime::Builder::new_current_thread()
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
    traffic: Arc<Mutex<TrafficRegistry>>,
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
            connect_timeout: Duration::from_secs(10),
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
    traffic: Arc<Mutex<TrafficRegistry>>,
    sessions: UserSessionTracker,
    bandwidth: UserBandwidthLimiters,
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
    let server = Hysteria2Server::with_shared_limits(
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
            connect_timeout: Duration::from_secs(10),
            up_mbps: inbound.transport.up_mbps,
            down_mbps: inbound.transport.down_mbps,
            ignore_client_bandwidth: inbound.transport.ignore_client_bandwidth,
            obfs: hysteria2_obfs_config(&inbound.transport),
        },
        traffic,
        sessions,
        bandwidth,
    );
    let runtime = tokio::runtime::Builder::new_current_thread()
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
    traffic: Arc<Mutex<TrafficRegistry>>,
    sessions: UserSessionTracker,
    bandwidth: UserBandwidthLimiters,
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
    let server = TuicServer::with_shared_limits(
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
            connect_timeout: Duration::from_secs(10),
        },
        traffic,
        sessions,
        bandwidth,
    );
    let runtime = tokio::runtime::Builder::new_current_thread()
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
    traffic: Arc<Mutex<TrafficRegistry>>,
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
            connect_timeout: Duration::from_secs(10),
            padding_scheme: inbound.padding_scheme.clone(),
        },
        traffic,
        sessions,
        bandwidth,
    );
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
            protocol: Protocol::AnyTls,
            local_addr,
        },
        runtime: ListenerRuntime::AnyTls(runtime_server),
        stop,
        workers,
        join: Some(join),
    })
}

fn start_shadowsocks_listener(
    inbound: &InboundConfig,
    routes: Vec<crate::RouteRule>,
    traffic: Arc<Mutex<TrafficRegistry>>,
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
            connect_timeout: Duration::from_secs(10),
        },
        traffic,
        sessions,
        bandwidth,
    );
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
    traffic: Arc<Mutex<TrafficRegistry>>,
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
            connect_timeout: Duration::from_secs(10),
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
    traffic: Arc<Mutex<TrafficRegistry>>,
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
            connect_timeout: Duration::from_secs(10),
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
    traffic: Arc<Mutex<TrafficRegistry>>,
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
            connect_timeout: Duration::from_secs(10),
        },
        traffic,
        sessions,
        bandwidth,
    );
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
    traffic: Arc<Mutex<TrafficRegistry>>,
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
            connect_timeout: Duration::from_secs(10),
        },
        traffic,
        sessions,
        bandwidth,
    );
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
    traffic: Arc<Mutex<TrafficRegistry>>,
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
            connect_timeout: Duration::from_secs(10),
        },
        traffic,
        sessions,
        bandwidth,
    );
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
    let listener = TcpListener::bind(listen).map_err(|source| CoreServiceError::Bind {
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
            let gateway = gateway.clone();
            let server = server.clone();
            let result = handle_reality_preface(stream, &gateway);
            if let Ok(RealityGatewayResult::Authenticated(mut authenticated)) = result {
                let _ = authenticated.read_dest_handshake(8, Duration::from_secs(5));
                if let Ok(acceptor) = reality_tls_acceptor(
                    &authenticated.auth.auth_key,
                    &authenticated.auth.server_name,
                ) {
                    if let Ok(client) = acceptor.accept_stream(authenticated.stream) {
                        let _ = server.handle_tls_client(client);
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

fn reality_tls_acceptor(auth_key: &[u8; 32], server_name: &str) -> io::Result<TlsAcceptor> {
    let certificate = generate_reality_temporary_certificate(auth_key, server_name)
        .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error.to_string()))?;
    TlsAcceptor::from_der(
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
            max_time_diff: Some(Duration::from_secs(30)),
            now: SystemTime::now(),
        },
        dest,
        connect_timeout: Duration::from_secs(10),
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

    fn join(&self) {
        self.state.wait_until_idle();
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

    fn wait_until_idle(&self) {
        let mut active = self.active.lock().expect("worker group lock poisoned");
        while *active > 0 {
            active = self
                .finished
                .wait(active)
                .expect("worker group lock poisoned");
        }
    }
}

impl ConnectionWorkerPool {
    fn new() -> Self {
        Self {
            queue: Mutex::new(VecDeque::new()),
            ready: Condvar::new(),
            worker_count: std::sync::atomic::AtomicUsize::new(0),
            idle_count: std::sync::atomic::AtomicUsize::new(0),
            pending_count: std::sync::atomic::AtomicUsize::new(0),
            max_workers: connection_worker_threads(),
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

fn connection_worker_threads() -> usize {
    std::thread::available_parallelism()
        .map(usize::from)
        .unwrap_or(4)
        .saturating_mul(128)
        .clamp(256, MAX_CONNECTION_WORKERS_PER_LISTENER)
}

fn connection_worker_stack_size() -> usize {
    512 * 1024
}

fn spawn_connection_worker<F>(workers: &ConnectionWorkerGroup, task: F) -> bool
where
    F: FnOnce() + Send + 'static,
{
    workers.spawn(task)
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

fn resolve_listen_addr(listen: &str, port: u16) -> io::Result<SocketAddr> {
    let listen = match listen.trim() {
        "" => "0.0.0.0",
        "::" => "::",
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
    use rustls::pki_types::{CertificateDer, ServerName};
    use rustls::{ClientConfig, RootCertStore};
    use std::fs;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::{mpsc, Arc};
    use std::thread;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use crate::config::{
        CoreConfig, DnsConfig, InboundConfig, OutboundConfig, RealityConfig, SniffingConfig,
        StatsConfig, TlsConfig, TransportConfig,
    };
    use crate::grpc::{decode_hunk_message, encode_grpc_hunk, take_grpc_message};
    use crate::protocol::Protocol;
    use crate::service::CoreService;
    use crate::user::CoreUser;

    use super::reality_tls_acceptor;

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
            group_for_waiter.join();
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
    fn connection_worker_group_releases_panicking_jobs() {
        let group = super::ConnectionWorkerGroup::new();
        assert!(group.spawn(|| panic!("worker panic should be contained")));
        group.join();

        let completed = Arc::new(AtomicBool::new(false));
        let completed_for_worker = completed.clone();
        assert!(group.spawn(move || {
            completed_for_worker.store(true, Ordering::SeqCst);
        }));
        group.join();
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

        group.join();
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
        let mut request = Vec::new();
        request.push(0x00);
        request.extend_from_slice(&uuid_bytes("11111111-1111-1111-1111-111111111111"));
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
