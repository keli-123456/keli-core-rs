use std::fmt;
use std::io;
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

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
use crate::protocol::Protocol;
use crate::shadowsocks::{ShadowsocksServer, ShadowsocksServerConfig};
use crate::socks5::{Socks5Server, Socks5ServerConfig};
use crate::tls::TlsAcceptor;
use crate::traffic::{TrafficDelta, TrafficRegistry};
use crate::trojan::{TrojanServer, TrojanServerConfig};
use crate::tuic::{TuicServer, TuicServerConfig};
use crate::vless::{VlessServer, VlessServerConfig};
use crate::vmess::{VmessServer, VmessServerConfig};

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
    listeners: Vec<ListenerHandle>,
    traffic: Arc<Mutex<TrafficRegistry>>,
}

#[derive(Debug)]
struct ListenerHandle {
    status: ListenerStatus,
    stop: Arc<AtomicBool>,
    workers: Arc<Mutex<Vec<JoinHandle<()>>>>,
    join: Option<JoinHandle<()>>,
}

impl CoreService {
    pub fn start(config: CoreConfig) -> Result<Self, CoreServiceError> {
        config.validate().map_err(CoreServiceError::InvalidConfig)?;

        let traffic = Arc::new(Mutex::new(TrafficRegistry::default()));
        let sessions = UserSessionTracker::default();
        let bandwidth = UserBandwidthLimiters::default();
        let mut listeners = Vec::new();

        for inbound in config.inbounds {
            let handle = match inbound.protocol {
                Protocol::Socks => start_socks_listener(
                    &inbound,
                    config.routes.clone(),
                    traffic.clone(),
                    sessions.clone(),
                    bandwidth.clone(),
                )?,
                Protocol::Http => start_http_listener(
                    &inbound,
                    config.routes.clone(),
                    traffic.clone(),
                    sessions.clone(),
                    bandwidth.clone(),
                )?,
                Protocol::Vless => start_vless_listener(
                    &inbound,
                    config.routes.clone(),
                    traffic.clone(),
                    sessions.clone(),
                    bandwidth.clone(),
                )?,
                Protocol::Vmess => start_vmess_listener(
                    &inbound,
                    config.routes.clone(),
                    traffic.clone(),
                    sessions.clone(),
                    bandwidth.clone(),
                )?,
                Protocol::Trojan => start_trojan_listener(
                    &inbound,
                    config.routes.clone(),
                    traffic.clone(),
                    sessions.clone(),
                    bandwidth.clone(),
                )?,
                Protocol::Shadowsocks => start_shadowsocks_listener(
                    &inbound,
                    config.routes.clone(),
                    traffic.clone(),
                    sessions.clone(),
                    bandwidth.clone(),
                )?,
                Protocol::AnyTls => start_anytls_listener(
                    &inbound,
                    config.routes.clone(),
                    traffic.clone(),
                    sessions.clone(),
                    bandwidth.clone(),
                )?,
                Protocol::Tuic => start_tuic_listener(
                    &inbound,
                    config.routes.clone(),
                    traffic.clone(),
                    sessions.clone(),
                    bandwidth.clone(),
                )?,
                Protocol::Hysteria2 => start_hysteria2_listener(
                    &inbound,
                    config.routes.clone(),
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

        Ok(Self { listeners, traffic })
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

    pub fn stop(&mut self) {
        for handle in &self.listeners {
            handle.stop.store(true, Ordering::SeqCst);
            let _ = TcpStream::connect(handle.status.local_addr);
        }

        for handle in &mut self.listeners {
            if let Some(join) = handle.join.take() {
                let _ = join.join();
            }
            join_workers(&handle.workers);
        }
    }
}

impl Drop for CoreService {
    fn drop(&mut self) {
        self.stop();
    }
}

fn start_grpc_transport_listener(
    inbound: &InboundConfig,
    protocol: Protocol,
    handler: GrpcStreamHandler,
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
    let workers = Arc::new(Mutex::new(Vec::new()));
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
        let server = server.clone();
        let handler: GrpcStreamHandler =
            Arc::new(move |reader: GrpcHunkReader, writer: GrpcHunkWriter| {
                let _ = server.handle_split_client(reader, writer);
            });
        return start_grpc_transport_listener(inbound, Protocol::Vmess, handler);
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
    let workers = Arc::new(Mutex::new(Vec::new()));
    let workers_for_thread = workers.clone();
    let network = inbound.transport.network.trim().to_string();
    let websocket_path = inbound.transport.path.clone();
    let httpupgrade_host = inbound.transport.host.clone();
    let tls_acceptor = tls_acceptor_for(inbound)?;
    let join = thread::spawn(move || {
        while !stop_for_thread.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((stream, _)) => {
                    let server = server.clone();
                    let network = network.clone();
                    let websocket_path = websocket_path.clone();
                    let httpupgrade_host = httpupgrade_host.clone();
                    let tls_acceptor = tls_acceptor.clone();
                    let worker = thread::spawn(move || {
                        let result = if let Some(acceptor) = tls_acceptor {
                            acceptor
                                .accept(stream)
                                .and_then(|client| match network.as_str() {
                                    "ws" => server.handle_tls_websocket_client(
                                        client,
                                        websocket_path.as_deref(),
                                    ),
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
                    });
                    workers_for_thread
                        .lock()
                        .expect("worker list lock poisoned")
                        .push(worker);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
    });

    Ok(ListenerHandle {
        status: ListenerStatus {
            tag: inbound.tag.clone(),
            protocol: Protocol::Vmess,
            local_addr,
        },
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
    let workers = Arc::new(Mutex::new(Vec::new()));
    let join = thread::spawn(move || {
        runtime.block_on(server.run(endpoint, stop_for_thread));
    });

    Ok(ListenerHandle {
        status: ListenerStatus {
            tag: inbound.tag.clone(),
            protocol: Protocol::Hysteria2,
            local_addr,
        },
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
    let workers = Arc::new(Mutex::new(Vec::new()));
    let join = thread::spawn(move || {
        runtime.block_on(server.run(endpoint, stop_for_thread));
    });

    Ok(ListenerHandle {
        status: ListenerStatus {
            tag: inbound.tag.clone(),
            protocol: Protocol::Tuic,
            local_addr,
        },
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
    let workers = Arc::new(Mutex::new(Vec::new()));
    let workers_for_thread = workers.clone();
    let join = thread::spawn(move || {
        while !stop_for_thread.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((stream, _)) => {
                    let server = server.clone();
                    let worker = thread::spawn(move || {
                        let _ = server.handle_tcp_client(stream);
                    });
                    workers_for_thread
                        .lock()
                        .expect("worker list lock poisoned")
                        .push(worker);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
    });

    Ok(ListenerHandle {
        status: ListenerStatus {
            tag: inbound.tag.clone(),
            protocol: Protocol::AnyTls,
            local_addr,
        },
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

    let stop = Arc::new(AtomicBool::new(false));
    let stop_for_thread = stop.clone();
    let workers = Arc::new(Mutex::new(Vec::new()));
    let workers_for_thread = workers.clone();
    let join = thread::spawn(move || {
        while !stop_for_thread.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((stream, _)) => {
                    let server = server.clone();
                    let worker = thread::spawn(move || {
                        let _ = server.handle_tcp_client(stream);
                    });
                    workers_for_thread
                        .lock()
                        .expect("worker list lock poisoned")
                        .push(worker);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
    });

    Ok(ListenerHandle {
        status: ListenerStatus {
            tag: inbound.tag.clone(),
            protocol: Protocol::Shadowsocks,
            local_addr,
        },
        stop,
        workers,
        join: Some(join),
    })
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
        let server = server.clone();
        let handler: GrpcStreamHandler =
            Arc::new(move |reader: GrpcHunkReader, writer: GrpcHunkWriter| {
                let _ = server.handle_split_client(reader, writer);
            });
        return start_grpc_transport_listener(inbound, Protocol::Trojan, handler);
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
    let workers = Arc::new(Mutex::new(Vec::new()));
    let workers_for_thread = workers.clone();
    let network = inbound.transport.network.trim().to_string();
    let websocket_path = inbound.transport.path.clone();
    let httpupgrade_host = inbound.transport.host.clone();
    let tls_acceptor = tls_acceptor_for(inbound)?;
    let join = thread::spawn(move || {
        while !stop_for_thread.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((stream, _)) => {
                    let server = server.clone();
                    let network = network.clone();
                    let websocket_path = websocket_path.clone();
                    let httpupgrade_host = httpupgrade_host.clone();
                    let tls_acceptor = tls_acceptor.clone();
                    let worker = thread::spawn(move || {
                        let result = if let Some(acceptor) = tls_acceptor {
                            acceptor
                                .accept(stream)
                                .and_then(|client| match network.as_str() {
                                    "ws" => server.handle_tls_websocket_client(
                                        client,
                                        websocket_path.as_deref(),
                                    ),
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
                    });
                    workers_for_thread
                        .lock()
                        .expect("worker list lock poisoned")
                        .push(worker);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
    });

    Ok(ListenerHandle {
        status: ListenerStatus {
            tag: inbound.tag.clone(),
            protocol: Protocol::Trojan,
            local_addr,
        },
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
            connect_timeout: Duration::from_secs(10),
        },
        traffic,
        sessions,
        bandwidth,
    );
    if inbound.transport.network.trim() == "grpc" {
        let server = server.clone();
        let handler: GrpcStreamHandler =
            Arc::new(move |reader: GrpcHunkReader, writer: GrpcHunkWriter| {
                let _ = server.handle_split_client(reader, writer);
            });
        return start_grpc_transport_listener(inbound, Protocol::Vless, handler);
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
    let workers = Arc::new(Mutex::new(Vec::new()));
    let workers_for_thread = workers.clone();
    let network = inbound.transport.network.trim().to_string();
    let websocket_path = inbound.transport.path.clone();
    let httpupgrade_host = inbound.transport.host.clone();
    let tls_acceptor = tls_acceptor_for(inbound)?;
    let join = thread::spawn(move || {
        while !stop_for_thread.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((stream, _)) => {
                    let server = server.clone();
                    let network = network.clone();
                    let websocket_path = websocket_path.clone();
                    let httpupgrade_host = httpupgrade_host.clone();
                    let tls_acceptor = tls_acceptor.clone();
                    let worker = thread::spawn(move || {
                        let result = if let Some(acceptor) = tls_acceptor {
                            acceptor
                                .accept(stream)
                                .and_then(|client| match network.as_str() {
                                    "ws" => server.handle_tls_websocket_client(
                                        client,
                                        websocket_path.as_deref(),
                                    ),
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
                    });
                    workers_for_thread
                        .lock()
                        .expect("worker list lock poisoned")
                        .push(worker);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
    });

    Ok(ListenerHandle {
        status: ListenerStatus {
            tag: inbound.tag.clone(),
            protocol: Protocol::Vless,
            local_addr,
        },
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
    let workers = Arc::new(Mutex::new(Vec::new()));
    let workers_for_thread = workers.clone();
    let join = thread::spawn(move || {
        while !stop_for_thread.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((stream, _)) => {
                    let server = server.clone();
                    let worker = thread::spawn(move || {
                        let _ = server.handle_tcp_client(stream);
                    });
                    workers_for_thread
                        .lock()
                        .expect("worker list lock poisoned")
                        .push(worker);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
    });

    Ok(ListenerHandle {
        status: ListenerStatus {
            tag: inbound.tag.clone(),
            protocol: Protocol::Socks,
            local_addr,
        },
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
    let workers = Arc::new(Mutex::new(Vec::new()));
    let workers_for_thread = workers.clone();
    let join = thread::spawn(move || {
        while !stop_for_thread.load(Ordering::SeqCst) {
            match listener.accept() {
                Ok((stream, _)) => {
                    let server = server.clone();
                    let worker = thread::spawn(move || {
                        let _ = server.handle_tcp_client(stream);
                    });
                    workers_for_thread
                        .lock()
                        .expect("worker list lock poisoned")
                        .push(worker);
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(10));
                }
                Err(_) => break,
            }
        }
    });

    Ok(ListenerHandle {
        status: ListenerStatus {
            tag: inbound.tag.clone(),
            protocol: Protocol::Http,
            local_addr,
        },
        stop,
        workers,
        join: Some(join),
    })
}

fn join_workers(workers: &Arc<Mutex<Vec<JoinHandle<()>>>>) {
    loop {
        let worker = workers.lock().expect("worker list lock poisoned").pop();
        match worker {
            Some(worker) => {
                let _ = worker.join();
            }
            None => break,
        }
    }
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
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::thread;
    use std::time::Duration;

    use crate::config::{
        CoreConfig, InboundConfig, OutboundConfig, SniffingConfig, StatsConfig, TransportConfig,
    };
    use crate::grpc::{decode_hunk_message, encode_grpc_hunk, take_grpc_message};
    use crate::protocol::Protocol;
    use crate::service::CoreService;
    use crate::user::CoreUser;

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
            inbounds: vec![InboundConfig {
                tag: "panel|socks|1".to_string(),
                protocol: Protocol::Socks,
                listen: "127.0.0.1".to_string(),
                port,
                users: vec![user()],
                cipher: None,
                transport: TransportConfig::default(),
                tls: None,
                sniffing: SniffingConfig::default(),
            }],
            outbounds: vec![OutboundConfig {
                tag: "direct".to_string(),
                protocol: "freedom".to_string(),
                address: None,
                port: None,
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

    fn run_grpc_vless_client(proxy_addr: std::net::SocketAddr, echo_addr: std::net::SocketAddr) {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async move {
            let stream = tokio::net::TcpStream::connect(proxy_addr)
                .await
                .expect("grpc connect");
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

        run_grpc_vless_client(grpc_addr, echo_addr);
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
