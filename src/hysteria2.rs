use std::collections::HashMap;
use std::env;
use std::hash::{Hash, Hasher};
use std::io;
use std::net::{IpAddr, Shutdown, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use bytes::Bytes;
use quinn::crypto::rustls::QuicServerConfig;
use quinn::Runtime;
use socket2::SockRef;
use tokio::io::{AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::UdpSocket;
use tokio::sync::{OwnedSemaphorePermit, Semaphore};

use crate::limits::{
    sync_user_limit_delta, BandwidthLimiter, DeviceLimitPolicy, UserBandwidthLimiters,
    UserSessionGuard, UserSessionTracker,
};
use crate::quic_resources::{
    available_parallelism_count, memory_limit_mib, open_file_soft_limit, QuicConnectionPermit,
    SharedQuicConnectionLimiter,
};
use crate::quic_tuning::{
    apply_proxy_quic_transport_defaults, apply_quic_congestion_control, bind_quic_udp_socket,
    proxy_quic_tuning_snapshot, server_endpoint_with_tuned_udp_socket, tune_quic_udp_socket,
};
use crate::routing::RouteDecision;
use crate::salamander::SalamanderUdpSocket;
use crate::socks5::SocksTarget;
use crate::tls::server_config_from_files;
use crate::traffic::{SharedTrafficRegistry, TrafficRegistry};
use crate::user::{CoreUser, CoreUserDelta, CoreUserDeltaResult, UserStore};
use crate::RouteDispatcher;
use crate::{connect_tcp_outbound_tokio, send_udp_outbound_tokio};

const TCP_REQUEST_ID: u64 = 0x401;
const RESPONSE_OK: u8 = 0x00;
const RESPONSE_ERROR: u8 = 0x01;
const UDP_DATAGRAM_BUFFER_SIZE: usize = 1024 * 1024;
const UDP_PACKET_BUFFER_SIZE: usize = 64 * 1024;
const STREAM_TRAFFIC_FLUSH_BYTES: u64 = 1024 * 1024;
const UDP_TRAFFIC_FLUSH_BYTES: u64 = 64 * 1024;
const UDP_FRAGMENT_IDLE_TIMEOUT_MS: u64 = 10_000;
const UDP_MAX_FRAGMENT_SETS: usize = 4096;
const UDP_MAX_REASSEMBLED_BYTES: usize = UDP_PACKET_BUFFER_SIZE;
const UDP_SESSION_IDLE_TIMEOUT_MS: u64 = 20_000;
const UDP_SESSION_CLEANUP_INTERVAL_MS: u64 = 5_000;
const UDP_MAX_SESSIONS_PER_CONNECTION: usize = 64;
const UDP_GLOBAL_SESSIONS_PER_CPU: usize = 96;
const UDP_GLOBAL_MIN_SESSIONS: usize = 96;
const UDP_GLOBAL_MAX_SESSIONS: usize = 4096;
const UDP_GLOBAL_RESERVED_FDS: usize = 1024;
const UDP_GLOBAL_FDS_PER_SESSION: usize = 1;
const UDP_GLOBAL_MEMORY_MIB_PER_SESSION: usize = 8;
const HY2_ERROR_LOG_INTERVAL_MS: u64 = 60_000;
const HY2_STOP_POLL_INTERVAL_MS: u64 = 250;
const HY2_INVALID_AUTH_BACKOFF_THRESHOLD: u32 = 4;
const HY2_INVALID_AUTH_BACKOFF_WINDOW: Duration = Duration::from_secs(30);
const HY2_INVALID_AUTH_BACKOFF_DURATION: Duration = Duration::from_secs(60);
const HY2_INVALID_AUTH_BACKOFF_MAX_ENTRIES: usize = 4096;
const HY2_INVALID_AUTH_BACKOFF_SHARDS: usize = 16;
const HY2_PREAUTH_LIMIT_ENV: &str = "KELI_CORE_HY2_PREAUTH_CONNECTIONS";
const HY2_PREAUTH_MIN: usize = 32;
const HY2_PREAUTH_MAX: usize = 4096;
const HY2_AUTH_TIMEOUT_SECS_ENV: &str = "KELI_CORE_HY2_AUTH_TIMEOUT_SECS";
const DEFAULT_HY2_AUTH_TIMEOUT_SECS: u64 = 10;
const HY2_RELAY_IO_TIMEOUT_SECS_ENV: &str = "KELI_CORE_HY2_RELAY_IO_TIMEOUT_SECS";
const DEFAULT_HY2_RELAY_IO_TIMEOUT_SECS: u64 = 15;
const HY2_SOFTWARE_BANDWIDTH_LIMIT_MAX_MBPS_ENV: &str =
    "KELI_CORE_HY2_SOFTWARE_BANDWIDTH_LIMIT_MAX_MBPS";
const DEFAULT_HY2_SOFTWARE_BANDWIDTH_LIMIT_MAX_MBPS: u32 = 200;
const HY2_ROUTE_SLOW_LOG_MS: u128 = 1_000;
const ROUTE_TRACE_ENV: &str = "KELI_CORE_ROUTE_TRACE";
const QUIC_ENDPOINT_STOP_WAIT: Duration = Duration::from_secs(3);
static HY2_ACTIVE_UDP_SESSIONS: AtomicUsize = AtomicUsize::new(0);
static HY2_UDP_SESSION_LIMIT: OnceLock<usize> = OnceLock::new();

struct Hy2ConnectionPermit {
    _global: QuicConnectionPermit,
    _listener: OwnedSemaphorePermit,
}

#[derive(Clone, Debug)]
pub struct Hysteria2ServerConfig {
    pub node_tag: String,
    pub listen: SocketAddr,
    pub users: Vec<CoreUser>,
    pub routes: Vec<crate::RouteRule>,
    pub cert_file: String,
    pub key_file: String,
    pub server_name: String,
    pub alpn: Vec<String>,
    pub reject_unknown_sni: bool,
    pub connect_timeout: Duration,
    pub up_mbps: u32,
    pub down_mbps: u32,
    pub ignore_client_bandwidth: bool,
    pub congestion_control: String,
    pub obfs: Option<Hysteria2ObfsConfig>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hysteria2ObfsConfig {
    pub kind: String,
    pub password: String,
}

#[derive(Clone, Debug)]
pub struct Hysteria2Server {
    config: Hysteria2ServerConfig,
    users: UserStore,
    router: RouteDispatcher,
    traffic: SharedTrafficRegistry,
    sessions: UserSessionTracker,
    bandwidth: UserBandwidthLimiters,
    quic_connections: SharedQuicConnectionLimiter,
    listener_connections: Arc<Semaphore>,
    listener_connection_limit: usize,
    preauth_connections: Arc<Semaphore>,
    preauth_connection_limit: usize,
    last_quic_limit_log_ms: Arc<AtomicU64>,
    auth_backoff: Arc<Hysteria2AuthBackoff>,
}

impl Hysteria2Server {
    pub fn new(config: Hysteria2ServerConfig) -> Self {
        Self::with_shared_limits(
            config,
            TrafficRegistry::shared(),
            UserSessionTracker::default(),
            UserBandwidthLimiters::default(),
        )
    }

    pub fn with_shared_limits(
        config: Hysteria2ServerConfig,
        traffic: SharedTrafficRegistry,
        sessions: UserSessionTracker,
        bandwidth: UserBandwidthLimiters,
    ) -> Self {
        Self::with_shared_limits_and_quic(
            config,
            traffic,
            sessions,
            bandwidth,
            SharedQuicConnectionLimiter::standalone(),
        )
    }

    pub fn with_shared_limits_and_quic(
        mut config: Hysteria2ServerConfig,
        traffic: SharedTrafficRegistry,
        sessions: UserSessionTracker,
        bandwidth: UserBandwidthLimiters,
        quic_connections: SharedQuicConnectionLimiter,
    ) -> Self {
        let users =
            UserStore::from_keyed_users(&config.users, |user| user.credential().to_string());
        let router =
            RouteDispatcher::with_connect_timeout(config.routes.clone(), config.connect_timeout);
        config.users.clear();
        config.routes.clear();
        let listener_connection_limit = quic_connections.per_listener_soft_limit();
        let preauth_connection_limit = hy2_preauth_connection_limit(listener_connection_limit);
        Self {
            router,
            config,
            users,
            traffic,
            sessions,
            bandwidth,
            quic_connections,
            listener_connections: Arc::new(Semaphore::new(listener_connection_limit)),
            listener_connection_limit,
            preauth_connections: Arc::new(Semaphore::new(preauth_connection_limit)),
            preauth_connection_limit,
            last_quic_limit_log_ms: Arc::new(AtomicU64::new(0)),
            auth_backoff: Arc::new(Hysteria2AuthBackoff::default()),
        }
    }

    pub fn bind(&self) -> io::Result<quinn::Endpoint> {
        let alpn = if self.config.alpn.is_empty() {
            vec!["h3".to_string()]
        } else {
            self.config.alpn.clone()
        };
        let server_crypto = server_config_from_files(
            &self.config.cert_file,
            &self.config.key_file,
            &alpn,
            &self.config.server_name,
            self.config.reject_unknown_sni,
        )?;
        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
            QuicServerConfig::try_from(server_crypto).map_err(io_other)?,
        ));
        let mut transport = quinn::TransportConfig::default();
        apply_proxy_quic_transport_defaults(&mut transport);
        apply_quic_congestion_control(
            &mut transport,
            &self.config.congestion_control,
            "bbr",
            "hysteria2",
        )?;
        let resource = self.quic_connections.snapshot();
        crate::logging::emit_legacy_line(&format!(
            "INFO  core   hysteria2 shared quic limit total={} active={} listeners={} per_listener_soft={} listener_limit={} preauth_limit={}",
            resource.total_limit,
            resource.active_connections,
            resource.listener_count,
            resource.per_listener_soft_limit,
            self.listener_connection_limit,
            self.preauth_connection_limit
        ));
        let tuning = proxy_quic_tuning_snapshot();
        crate::logging::emit_legacy_line(&format!(
            "INFO  core   hysteria2 quic tuning stream_window_mib={} conn_window_mib={} max_streams={} udp_socket_buffer_mib={} initial_rtt_ms={} idle_timeout_secs={}",
            tuning.stream_receive_window_mib,
            tuning.receive_window_mib,
            tuning.max_concurrent_streams,
            tuning.udp_socket_buffer_mib,
            tuning.initial_rtt_ms,
            tuning.max_idle_timeout_secs
        ));
        transport
            .datagram_receive_buffer_size(Some(UDP_DATAGRAM_BUFFER_SIZE))
            .datagram_send_buffer_size(UDP_DATAGRAM_BUFFER_SIZE);
        server_config.transport_config(Arc::new(transport));
        let Some(obfs) = self.config.obfs.as_ref() else {
            return server_endpoint_with_tuned_udp_socket(server_config, self.config.listen);
        };
        if !obfs.kind.eq_ignore_ascii_case("salamander") {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "hysteria2 only supports salamander obfs",
            ));
        }

        let socket = bind_quic_udp_socket(self.config.listen)?;
        tune_quic_udp_socket(&socket);
        let runtime = Arc::new(quinn::TokioRuntime);
        let socket = runtime.wrap_udp_socket(socket)?;
        let socket = Arc::new(SalamanderUdpSocket::new(
            socket,
            obfs.password.as_bytes().to_vec(),
        )?);
        quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            Some(server_config),
            socket,
            runtime,
        )
    }

    pub async fn run(self, endpoint: quinn::Endpoint, stop: Arc<AtomicBool>) {
        loop {
            if stop.load(Ordering::SeqCst) {
                endpoint.close(0u32.into(), b"shutdown");
                break;
            }
            tokio::select! {
                incoming = endpoint.accept() => {
                    let Some(incoming) = incoming else {
                        break;
                    };
                    let Some(preauth_slot) = self.try_acquire_preauth_slot() else {
                        incoming.refuse();
                        self.log_preauth_limit_reached();
                        continue;
                    };
                    let Some(connection_slot) = self.try_acquire_connection_slot() else {
                        drop(preauth_slot);
                        self.log_quic_limit_reached();
                        continue;
                    };
                    let server = self.clone();
                    tokio::spawn(async move {
                        let _connection_slot = connection_slot;
                        if let Err(error) = server.handle_incoming(incoming, preauth_slot).await {
                            log_hysteria2_error("connection", &error);
                        }
                    });
                }
                _ = tokio::time::sleep(Duration::from_millis(HY2_STOP_POLL_INTERVAL_MS)) => {}
            }
        }
        let _ = tokio::time::timeout(QUIC_ENDPOINT_STOP_WAIT, endpoint.wait_idle()).await;
    }

    pub fn drain_traffic(&self, minimum_bytes: u64) -> Vec<crate::traffic::TrafficDelta> {
        self.traffic.drain_minimum(minimum_bytes)
    }

    pub fn replace_users(&self, users: Vec<CoreUser>) {
        self.bandwidth.sync_users(&users);
        self.users
            .replace_keyed_users(users, |user| user.credential().to_string());
    }

    pub fn replace_routes(&self, routes: Vec<crate::RouteRule>) {
        self.router.replace_routes(routes);
    }

    pub fn apply_user_delta(&self, delta: &CoreUserDelta) -> CoreUserDeltaResult {
        sync_delta_bandwidth(&self.bandwidth, &self.sessions, delta);
        self.users
            .apply_keyed_delta(delta, |user| user.credential().to_string())
    }

    fn user_for_auth(&self, auth: &str) -> Option<Arc<CoreUser>> {
        self.users.get_arc(auth)
    }

    fn try_acquire_connection_slot(&self) -> Option<Hy2ConnectionPermit> {
        let global = self.quic_connections.try_acquire()?;
        let listener = self.listener_connections.clone().try_acquire_owned().ok()?;
        Some(Hy2ConnectionPermit {
            _global: global,
            _listener: listener,
        })
    }

    fn try_acquire_preauth_slot(&self) -> Option<OwnedSemaphorePermit> {
        self.preauth_connections.clone().try_acquire_owned().ok()
    }

    fn log_preauth_limit_reached(&self) {
        let now = now_millis();
        let last = self.last_quic_limit_log_ms.load(Ordering::Relaxed);
        if now.saturating_sub(last) < HY2_ERROR_LOG_INTERVAL_MS {
            return;
        }
        if self
            .last_quic_limit_log_ms
            .compare_exchange(last, now, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        crate::logging::emit_legacy_line(&format!(
            "WARN  core   hysteria2 preauth limit reached limit={}",
            self.preauth_connection_limit
        ));
    }

    fn log_quic_limit_reached(&self) {
        let now = now_millis();
        let last = self.last_quic_limit_log_ms.load(Ordering::Relaxed);
        if now.saturating_sub(last) < HY2_ERROR_LOG_INTERVAL_MS {
            return;
        }
        if self
            .last_quic_limit_log_ms
            .compare_exchange(last, now, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return;
        }
        let resource = self.quic_connections.snapshot();
        crate::logging::emit_legacy_line(&format!(
            "WARN  core   hysteria2 quic limit reached total={} active={} listener_limit={}",
            resource.total_limit, resource.active_connections, self.listener_connection_limit
        ));
    }

    async fn handle_incoming(
        &self,
        incoming: quinn::Incoming,
        preauth_slot: OwnedSemaphorePermit,
    ) -> io::Result<()> {
        let client_ip = incoming.remote_address().ip();
        if self.router.source_ip_blocked(Some(client_ip)) {
            incoming.refuse();
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "source ip blocked by route",
            ));
        }
        if self.auth_backoff.is_blocked(client_ip) {
            incoming.refuse();
            return Ok(());
        }

        let connecting = incoming.accept().map_err(io_other)?;
        let connection = match tokio::time::timeout(hy2_auth_timeout(), connecting).await {
            Ok(Ok(connection)) => connection,
            Ok(Err(error)) => return Err(io_other(error)),
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "hysteria2 handshake timed out",
                ));
            }
        };

        let auth =
            match tokio::time::timeout(hy2_auth_timeout(), self.authenticate_http3(&connection))
                .await
            {
                Ok(Ok(auth)) => {
                    self.auth_backoff.record_success(client_ip);
                    auth
                }
                Ok(Err(error)) => {
                    if should_record_hysteria2_auth_backoff(&error) {
                        self.auth_backoff.record_invalid(client_ip);
                        connection.close(0u32.into(), b"invalid auth");
                    } else {
                        connection.close(0u32.into(), b"auth failed");
                    }
                    return Err(error);
                }
                Err(_) => {
                    connection.close(0u32.into(), b"auth timeout");
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "hysteria2 authentication timed out",
                    ));
                }
            };
        drop(preauth_slot);
        let _session = self.acquire_user_session(auth.user.as_ref(), Some(client_ip))?;
        let bandwidth = self.connection_limiters(
            self.bandwidth.limiter_for(Some(auth.user.as_ref())),
            self.bandwidth.limiter_for_limited(Some(auth.user.as_ref())),
            auth.client_rx_bps,
        );
        let udp_sessions = Arc::new(Mutex::new(HashMap::new()));
        let udp_server = self.clone();
        let udp_connection = connection.clone();
        let udp_user_uuid = auth.user.uuid.clone();
        let udp_user_id = auth.user.id;
        let udp_bandwidth = bandwidth.clone();
        tokio::spawn(async move {
            let _ = udp_server
                .handle_udp_datagrams(
                    udp_connection,
                    udp_user_uuid,
                    udp_user_id,
                    udp_bandwidth,
                    udp_sessions,
                    client_ip,
                )
                .await;
        });

        loop {
            let revoke_watch = bandwidth.clone();
            tokio::select! {
                stream = connection.accept_bi() => match stream {
                    Ok(stream) => {
                        let server = self.clone();
                        let user_uuid = auth.user.uuid.clone();
                        let user_id = auth.user.id;
                        let bandwidth = bandwidth.clone();
                        tokio::spawn(async move {
                            if let Err(error) = server
                                .handle_tcp_stream(stream, user_uuid, user_id, bandwidth, client_ip)
                                .await
                            {
                                log_hysteria2_error("tcp relay", &error);
                            }
                        });
                    }
                    Err(quinn::ConnectionError::ApplicationClosed { .. })
                    | Err(quinn::ConnectionError::LocallyClosed)
                    | Err(quinn::ConnectionError::ConnectionClosed(_)) => return Ok(()),
                    Err(error) => return Err(io_other(error)),
                },
                _ = revoke_watch.wait_revoked() => {
                    connection.close(0u32.into(), b"user revoked");
                    return Ok(());
                }
            }
        }
    }

    async fn authenticate_http3(
        &self,
        connection: &quinn::Connection,
    ) -> io::Result<Hysteria2Auth> {
        let mut h3_connection = h3::server::builder()
            .build::<_, bytes::Bytes>(h3_quinn::Connection::new(connection.clone()))
            .await
            .map_err(io_other)?;

        loop {
            let Some(resolver) = h3_connection.accept().await.map_err(io_other)? else {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "hysteria2 connection closed before authentication",
                ));
            };
            let (request, mut stream) = resolver.resolve_request().await.map_err(io_other)?;
            if request.method() != http::Method::POST || request.uri().path() != "/auth" {
                send_h3_status(&mut stream, 404).await?;
                continue;
            }

            let auth = request
                .headers()
                .get("hysteria-auth")
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default();
            let Some(user) = self.user_for_auth(auth) else {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "invalid hysteria2 authentication",
                ));
            };
            let client_rx_bps = request
                .headers()
                .get("hysteria-cc-rx")
                .and_then(|value| value.to_str().ok())
                .and_then(parse_hysteria_rx_header);

            let response = http::Response::builder()
                .status(http::StatusCode::from_u16(233).map_err(io_other)?)
                .header("Hysteria-UDP", "true")
                .header("Hysteria-TCP", "true")
                .header("Hysteria-CC-RX", self.response_cc_rx())
                .body(())
                .map_err(io_other)?;
            stream.send_response(response).await.map_err(io_other)?;
            stream.finish().await.map_err(io_other)?;
            let retained_connection = connection.clone();
            tokio::spawn(async move {
                retained_connection.closed().await;
                drop(h3_connection);
            });
            return Ok(Hysteria2Auth {
                user,
                client_rx_bps,
            });
        }
    }

    async fn handle_tcp_stream(
        &self,
        (mut send, mut recv): (quinn::SendStream, quinn::RecvStream),
        user_uuid: String,
        user_id: u64,
        bandwidth: DirectionalLimiters,
        client_ip: IpAddr,
    ) -> io::Result<()> {
        let target = read_tcp_target(&mut recv).await?;
        let decision = self.router.decide_tcp(&target.host, target.port, &[]);
        let remote = match &decision {
            RouteDecision::Direct => {
                match crate::dns::connect_tcp_tokio(
                    &target.host,
                    target.port,
                    self.config.connect_timeout,
                )
                .await
                {
                    Ok(stream) => stream,
                    Err(error) if error.kind() == io::ErrorKind::TimedOut => {
                        write_tcp_response(&mut send, RESPONSE_ERROR, "connect timed out").await?;
                        let _ = send.finish();
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            format!(
                                "tcp connect timed out target={}:{}",
                                target.host, target.port
                            ),
                        ));
                    }
                    Err(error) => {
                        write_tcp_response(&mut send, RESPONSE_ERROR, "connect failed").await?;
                        let _ = send.finish();
                        return Err(io::Error::new(
                            error.kind(),
                            format!(
                                "tcp connect failed target={}:{} error={error}",
                                target.host, target.port
                            ),
                        ));
                    }
                }
            }
            RouteDecision::Outbound(outbound) => {
                let started = Instant::now();
                match connect_tcp_outbound_tokio(outbound, &target, self.config.connect_timeout)
                    .await
                {
                    Ok(stream) => {
                        log_hysteria2_route_outbound_connected(
                            &self.config.node_tag,
                            outbound,
                            &target,
                            started.elapsed(),
                        );
                        stream
                    }
                    Err(error) => {
                        let response = if error.kind() == io::ErrorKind::TimedOut {
                            "connect timed out"
                        } else {
                            "connect failed"
                        };
                        write_tcp_response(&mut send, RESPONSE_ERROR, response).await?;
                        let _ = send.finish();
                        return Err(annotate_hysteria2_route_outbound_error(
                            &self.config.node_tag,
                            outbound,
                            &target,
                            started.elapsed(),
                            error,
                        ));
                    }
                }
            }
            RouteDecision::Block => {
                write_tcp_response(&mut send, RESPONSE_ERROR, "target blocked").await?;
                let _ = send.finish();
                return Ok(());
            }
            RouteDecision::UnsupportedOutbound(tag) => {
                write_tcp_response(&mut send, RESPONSE_ERROR, "outbound route not implemented")
                    .await?;
                let _ = send.finish();
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!("outbound route {tag} is not implemented"),
                ));
            }
        };

        write_tcp_response(&mut send, RESPONSE_OK, "").await?;
        let upload_traffic = self.traffic.clone();
        let upload_node_tag = self.config.node_tag.clone();
        let upload_user_uuid = user_uuid.clone();
        let mut upload_client_ip = Some(client_ip);
        let download_traffic = self.traffic.clone();
        let download_node_tag = self.config.node_tag.clone();
        let download_user_uuid = user_uuid;
        relay_streams(
            &mut recv,
            &mut send,
            remote,
            bandwidth,
            move |bytes| {
                upload_traffic.add_with_user_id(
                    upload_node_tag.clone(),
                    upload_user_uuid.clone(),
                    Some(user_id),
                    bytes,
                    0,
                    upload_client_ip.take(),
                );
            },
            move |bytes| {
                download_traffic.add_with_user_id(
                    download_node_tag.clone(),
                    download_user_uuid.clone(),
                    Some(user_id),
                    0,
                    bytes,
                    None,
                );
            },
        )
        .await?;
        Ok(())
    }

    async fn handle_udp_datagrams(
        &self,
        connection: quinn::Connection,
        user_uuid: String,
        user_id: u64,
        bandwidth: DirectionalLimiters,
        sessions: Arc<Mutex<HashMap<u32, Arc<UdpRelaySession>>>>,
        client_ip: IpAddr,
    ) -> io::Result<()> {
        let mut fragments = UdpFragmentStore::default();
        let mut cleanup =
            tokio::time::interval(Duration::from_millis(UDP_SESSION_CLEANUP_INTERVAL_MS));
        cleanup.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        loop {
            let datagram = tokio::select! {
                datagram = connection.read_datagram() => match datagram {
                    Ok(datagram) => datagram,
                    Err(quinn::ConnectionError::ApplicationClosed { .. })
                    | Err(quinn::ConnectionError::LocallyClosed)
                    | Err(quinn::ConnectionError::ConnectionClosed(_)) => return Ok(()),
                    Err(error) => return Err(io_other(error)),
                },
                _ = bandwidth.wait_revoked() => return Ok(()),
                _ = cleanup.tick() => {
                    let now_ms = now_millis();
                    fragments.prune_expired(now_ms);
                    prune_udp_sessions(&sessions, now_ms);
                    continue;
                },
            };
            let Ok(message) = parse_udp_datagram(&datagram) else {
                continue;
            };
            let Some(message) = fragments.push(message)? else {
                continue;
            };
            let _ = self
                .handle_udp_message(
                    &connection,
                    &user_uuid,
                    user_id,
                    bandwidth.clone(),
                    &sessions,
                    client_ip,
                    message,
                )
                .await;
        }
    }

    async fn handle_udp_message(
        &self,
        connection: &quinn::Connection,
        user_uuid: &str,
        user_id: u64,
        bandwidth: DirectionalLimiters,
        sessions: &Arc<Mutex<HashMap<u32, Arc<UdpRelaySession>>>>,
        client_ip: IpAddr,
        message: UdpDatagram,
    ) -> io::Result<()> {
        let decision = if self.router.is_empty() {
            RouteDecision::Direct
        } else {
            self.router
                .decide_udp(&message.target.host, message.target.port, &message.data)
        };
        let outbound = match &decision {
            RouteDecision::Direct => None,
            RouteDecision::Outbound(outbound) => Some(outbound),
            RouteDecision::Block => return Ok(()),
            RouteDecision::UnsupportedOutbound(tag) => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!("outbound route {tag} is not implemented"),
                ));
            }
        };

        let has_data_limits = bandwidth.has_data_limits();
        if let Some(outbound) = outbound {
            if has_data_limits && !bandwidth.wait_upload(message.data.len()).await {
                return Ok(());
            }
            match send_udp_outbound_tokio(
                outbound,
                &message.target,
                &message.data,
                self.config.connect_timeout,
            )
            .await
            {
                Ok((source, response)) => {
                    if has_data_limits && !bandwidth.wait_download(response.len()).await {
                        return Ok(());
                    }
                    let address = format_socket_addr(&source);
                    if !send_udp_datagram_fragments(
                        connection,
                        message.session_id,
                        message.packet_id,
                        &address,
                        &response,
                    )
                    .await?
                    {
                        return Ok(());
                    }
                    self.traffic.add_with_user_id(
                        self.config.node_tag.clone(),
                        user_uuid.to_string(),
                        Some(user_id),
                        message.data.len() as u64,
                        response.len() as u64,
                        Some(client_ip),
                    );
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    self.traffic.add_with_user_id(
                        self.config.node_tag.clone(),
                        user_uuid.to_string(),
                        Some(user_id),
                        message.data.len() as u64,
                        0,
                        Some(client_ip),
                    );
                }
                Err(error) => return Err(error),
            }
            return Ok(());
        }

        let (session, target_addr) = self
            .get_udp_session(
                connection,
                user_uuid,
                user_id,
                sessions,
                message.session_id,
                &message.target,
                &bandwidth,
                client_ip,
            )
            .await?;
        if has_data_limits && !bandwidth.wait_upload(message.data.len()).await {
            return Ok(());
        }
        session.socket.send_to(&message.data, target_addr).await?;
        session.add_upload(message.data.len() as u64);
        Ok(())
    }

    async fn get_udp_session(
        &self,
        connection: &quinn::Connection,
        user_uuid: &str,
        user_id: u64,
        sessions: &Arc<Mutex<HashMap<u32, Arc<UdpRelaySession>>>>,
        session_id: u32,
        target: &SocksTarget,
        bandwidth: &DirectionalLimiters,
        client_ip: IpAddr,
    ) -> io::Result<(Arc<UdpRelaySession>, SocketAddr)> {
        let existing = {
            sessions
                .lock()
                .expect("hysteria2 udp session lock poisoned")
                .get(&session_id)
                .cloned()
        };
        if let Some(session) = existing {
            session.touch();
            if session.target == *target {
                let target_addr = session.target_addr;
                return Ok((session, target_addr));
            }
            let target_addr = resolve_udp_target(target, self.config.connect_timeout).await?;
            return Ok((session, target_addr));
        }

        make_room_for_udp_session(sessions);
        let target_addr = resolve_udp_target(target, self.config.connect_timeout).await?;
        let permit = UdpSessionPermit::try_acquire().ok_or_else(|| {
            io::Error::new(io::ErrorKind::Other, "hysteria2 udp session limit reached")
        })?;
        let socket = Arc::new(bind_udp_socket(target_addr.ip()).await?);
        let session = Arc::new(UdpRelaySession {
            socket,
            target: target.clone(),
            target_addr,
            _permit: permit,
            next_packet_id: AtomicU16::new(0),
            traffic: self.traffic.clone(),
            node_tag: self.config.node_tag.clone(),
            user_uuid: user_uuid.to_string(),
            user_id,
            client_ip,
            closed: AtomicBool::new(false),
            last_active_ms: AtomicU64::new(now_millis()),
            pending_upload: AtomicU64::new(0),
            pending_download: AtomicU64::new(0),
        });
        {
            let mut sessions = sessions
                .lock()
                .expect("hysteria2 udp session lock poisoned");
            if let Some(existing) = sessions.get(&session_id) {
                drop(session);
                existing.touch();
                if existing.target == *target {
                    return Ok((existing.clone(), existing.target_addr));
                }
                return Ok((existing.clone(), target_addr));
            }
            sessions.insert(session_id, session.clone());
        }

        let receiver = session.clone();
        let connection = connection.clone();
        let bandwidth = bandwidth.clone();
        tokio::spawn(async move {
            let _ = receive_udp_replies(session_id, receiver, connection, bandwidth).await;
        });
        Ok((session, target_addr))
    }

    fn response_cc_rx(&self) -> String {
        if self.config.ignore_client_bandwidth {
            return "auto".to_string();
        }
        mbps_to_bytes_per_second(self.config.down_mbps)
            .map(|value| value.to_string())
            .unwrap_or_else(|| "0".to_string())
    }

    fn connection_limiters(
        &self,
        user_revocation: Option<Arc<BandwidthLimiter>>,
        user_limiter: Option<Arc<BandwidthLimiter>>,
        client_rx_bps: Option<u64>,
    ) -> DirectionalLimiters {
        let mut revoke = Vec::new();
        let mut upload = Vec::new();
        let mut download = Vec::new();
        if let Some(limiter) = user_revocation {
            revoke.push(limiter);
        }
        if let Some(limiter) = user_limiter {
            upload.push(limiter.clone());
            download.push(limiter);
        }
        if !self.config.ignore_client_bandwidth {
            if let Some(server_down_bps) = enforced_hy2_bandwidth_bps(self.config.down_mbps) {
                upload.push(Arc::new(BandwidthLimiter::new(server_down_bps)));
            }
            let server_up_bps = enforced_hy2_bandwidth_bps(self.config.up_mbps);
            if server_up_bps.is_some() {
                if let Some(download_bps) = min_nonzero(server_up_bps, client_rx_bps) {
                    download.push(Arc::new(BandwidthLimiter::new(download_bps)));
                }
            }
        }
        DirectionalLimiters {
            revoke,
            upload,
            download,
        }
    }

    fn acquire_user_session(
        &self,
        user: &CoreUser,
        client_ip: Option<IpAddr>,
    ) -> io::Result<Option<UserSessionGuard>> {
        self.sessions
            .try_acquire_for_node_ip_with_policy(
                &self.config.node_tag,
                Some(user),
                client_ip,
                DeviceLimitPolicy {
                    udp_rebind_tolerant: true,
                },
            )
            .map_err(|error| io::Error::new(io::ErrorKind::PermissionDenied, error.to_string()))
    }
}

fn sync_delta_bandwidth(
    bandwidth: &UserBandwidthLimiters,
    sessions: &UserSessionTracker,
    delta: &CoreUserDelta,
) {
    sync_user_limit_delta(bandwidth, sessions, delta);
}

#[derive(Clone, Debug)]
struct Hysteria2Auth {
    user: Arc<CoreUser>,
    client_rx_bps: Option<u64>,
}

#[derive(Clone, Debug, Default)]
struct DirectionalLimiters {
    revoke: Vec<Arc<BandwidthLimiter>>,
    upload: Vec<Arc<BandwidthLimiter>>,
    download: Vec<Arc<BandwidthLimiter>>,
}

impl DirectionalLimiters {
    fn has_data_limits(&self) -> bool {
        !self.upload.is_empty() || !self.download.is_empty()
    }

    fn is_revoked(&self) -> bool {
        self.revoke.iter().any(|limiter| limiter.is_revoked())
    }

    async fn wait_revoked(&self) {
        if self.revoke.is_empty() {
            std::future::pending::<()>().await;
        }

        let mut single = None;
        let mut count = 0usize;
        for limiter in &self.revoke {
            count = count.saturating_add(1);
            single = Some(limiter);
            if count > 1 {
                break;
            }
        }
        if count == 1 {
            if let Some(limiter) = single {
                limiter.wait_revoked().await;
                return;
            }
        }

        while !self.is_revoked() {
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    async fn wait_upload(&self, bytes: usize) -> bool {
        for limiter in &self.upload {
            if !limiter.wait_for_async(bytes).await {
                return false;
            }
        }
        true
    }

    async fn wait_download(&self, bytes: usize) -> bool {
        for limiter in &self.download {
            if !limiter.wait_for_async(bytes).await {
                return false;
            }
        }
        true
    }
}

#[derive(Debug)]
struct UdpRelaySession {
    socket: Arc<UdpSocket>,
    target: SocksTarget,
    target_addr: SocketAddr,
    _permit: UdpSessionPermit,
    next_packet_id: AtomicU16,
    traffic: SharedTrafficRegistry,
    node_tag: String,
    user_uuid: String,
    user_id: u64,
    client_ip: IpAddr,
    closed: AtomicBool,
    last_active_ms: AtomicU64,
    pending_upload: AtomicU64,
    pending_download: AtomicU64,
}

impl UdpRelaySession {
    fn touch(&self) {
        self.last_active_ms.store(now_millis(), Ordering::Relaxed);
    }

    fn is_idle(&self, now_ms: u64) -> bool {
        now_ms.saturating_sub(self.last_active_ms.load(Ordering::Relaxed))
            >= UDP_SESSION_IDLE_TIMEOUT_MS
    }

    fn close(&self) {
        self.closed.store(true, Ordering::Release);
        self.flush_traffic();
    }

    fn is_closed(&self) -> bool {
        self.closed.load(Ordering::Acquire)
    }

    fn add_upload(&self, bytes: u64) {
        self.touch();
        self.add_pending(&self.pending_upload, bytes);
    }

    fn add_download(&self, bytes: u64) {
        self.touch();
        self.add_pending(&self.pending_download, bytes);
    }

    fn add_pending(&self, counter: &AtomicU64, bytes: u64) {
        if bytes == 0 {
            return;
        }
        let pending = counter
            .fetch_add(bytes, Ordering::Relaxed)
            .saturating_add(bytes);
        if pending >= UDP_TRAFFIC_FLUSH_BYTES {
            self.flush_traffic();
        }
    }

    fn flush_traffic(&self) {
        let upload = self.pending_upload.swap(0, Ordering::AcqRel);
        let download = self.pending_download.swap(0, Ordering::AcqRel);
        if upload == 0 && download == 0 {
            return;
        }
        self.traffic.add_with_user_id(
            self.node_tag.clone(),
            self.user_uuid.clone(),
            Some(self.user_id),
            upload,
            download,
            Some(self.client_ip),
        );
    }
}

impl Drop for UdpRelaySession {
    fn drop(&mut self) {
        self.flush_traffic();
    }
}

#[derive(Debug)]
struct UdpSessionPermit;

impl UdpSessionPermit {
    fn try_acquire() -> Option<Self> {
        let limit = hy2_udp_session_limit();
        loop {
            let active = HY2_ACTIVE_UDP_SESSIONS.load(Ordering::Acquire);
            if active >= limit {
                return None;
            }
            if HY2_ACTIVE_UDP_SESSIONS
                .compare_exchange(active, active + 1, Ordering::AcqRel, Ordering::Acquire)
                .is_ok()
            {
                return Some(Self);
            }
        }
    }
}

impl Drop for UdpSessionPermit {
    fn drop(&mut self) {
        HY2_ACTIVE_UDP_SESSIONS.fetch_sub(1, Ordering::AcqRel);
    }
}

fn hy2_udp_session_limit() -> usize {
    *HY2_UDP_SESSION_LIMIT.get_or_init(|| {
        if let Ok(value) = std::env::var("KELI_CORE_HY2_UDP_SESSIONS") {
            if let Ok(parsed) = value.trim().parse::<usize>() {
                return parsed.clamp(64, UDP_GLOBAL_MAX_SESSIONS);
            }
        }
        hy2_udp_session_limit_from_resources(
            available_parallelism_count(),
            memory_limit_mib(),
            open_file_soft_limit(),
        )
    })
}

pub(crate) fn hy2_udp_session_limit_for_metrics() -> usize {
    hy2_udp_session_limit()
}

pub(crate) fn hy2_active_udp_sessions() -> usize {
    HY2_ACTIVE_UDP_SESSIONS.load(Ordering::Acquire)
}

fn hy2_udp_session_limit_from_resources(
    cpu_count: usize,
    memory_limit_mib: Option<usize>,
    fd_limit: Option<usize>,
) -> usize {
    let cpu_target = cpu_count.max(1).saturating_mul(UDP_GLOBAL_SESSIONS_PER_CPU);
    let memory_target = memory_limit_mib
        .map(|mib| mib / UDP_GLOBAL_MEMORY_MIB_PER_SESSION)
        .filter(|target| *target > 0)
        .unwrap_or(UDP_GLOBAL_MAX_SESSIONS);
    let fd_target = fd_limit
        .map(|limit| limit.saturating_sub(UDP_GLOBAL_RESERVED_FDS) / UDP_GLOBAL_FDS_PER_SESSION)
        .filter(|target| *target > 0)
        .unwrap_or(UDP_GLOBAL_MAX_SESSIONS);
    cpu_target
        .min(memory_target)
        .min(fd_target)
        .min(UDP_GLOBAL_MAX_SESSIONS)
        .max(UDP_GLOBAL_MIN_SESSIONS)
}

fn prune_udp_sessions(
    sessions: &Arc<Mutex<HashMap<u32, Arc<UdpRelaySession>>>>,
    now_ms: u64,
) -> usize {
    let mut removed = 0usize;
    let mut sessions = sessions
        .lock()
        .expect("hysteria2 udp session lock poisoned");
    sessions.retain(|_, session| {
        if session.is_idle(now_ms) {
            session.close();
            removed = removed.saturating_add(1);
            false
        } else {
            true
        }
    });
    removed
}

fn make_room_for_udp_session(sessions: &Arc<Mutex<HashMap<u32, Arc<UdpRelaySession>>>>) {
    let needs_room = {
        let sessions = sessions
            .lock()
            .expect("hysteria2 udp session lock poisoned");
        sessions.len() >= UDP_MAX_SESSIONS_PER_CONNECTION
    };
    if !needs_room {
        return;
    }

    let now_ms = now_millis();
    let _ = prune_udp_sessions(sessions, now_ms);
    let mut sessions = sessions
        .lock()
        .expect("hysteria2 udp session lock poisoned");
    while sessions.len() >= UDP_MAX_SESSIONS_PER_CONNECTION {
        let Some(oldest_id) = sessions
            .iter()
            .min_by_key(|(_, session)| session.last_active_ms.load(Ordering::Relaxed))
            .map(|(id, _)| *id)
        else {
            break;
        };
        if let Some(session) = sessions.remove(&oldest_id) {
            session.close();
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct UdpDatagram {
    session_id: u32,
    packet_id: u16,
    fragment_id: u8,
    fragment_count: u8,
    target: SocksTarget,
    data: Vec<u8>,
}

impl UdpDatagram {
    fn is_single_fragment(&self) -> bool {
        self.fragment_id == 0 && self.fragment_count == 1
    }
}

#[derive(Debug, Default)]
struct UdpFragmentStore {
    fragments: HashMap<(u32, u16), UdpFragmentSet>,
}

#[derive(Debug)]
struct UdpFragmentSet {
    target: SocksTarget,
    parts: Vec<Option<Vec<u8>>>,
    created_ms: u64,
    received_bytes: usize,
}

impl UdpFragmentStore {
    fn push(&mut self, message: UdpDatagram) -> io::Result<Option<UdpDatagram>> {
        self.push_with_now(message, None)
    }

    fn push_with_now(
        &mut self,
        message: UdpDatagram,
        now_ms: Option<u64>,
    ) -> io::Result<Option<UdpDatagram>> {
        if message.fragment_count == 0 || message.fragment_id >= message.fragment_count {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid hysteria2 udp fragment index",
            ));
        }
        if message.is_single_fragment() {
            return Ok(Some(message));
        }

        let now_ms = now_ms.unwrap_or_else(now_millis);
        self.prune_expired(now_ms);
        let key = (message.session_id, message.packet_id);
        let count = message.fragment_count as usize;
        let index = message.fragment_id as usize;
        if !self.fragments.contains_key(&key) && self.fragments.len() >= UDP_MAX_FRAGMENT_SETS {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "too many incomplete hysteria2 udp fragment groups",
            ));
        }
        let set = self.fragments.entry(key).or_insert_with(|| UdpFragmentSet {
            target: message.target.clone(),
            parts: vec![None; count],
            created_ms: now_ms,
            received_bytes: 0,
        });
        if set.parts.len() != count || set.target != message.target {
            self.fragments.remove(&key);
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "mismatched hysteria2 udp fragment group",
            ));
        }
        if let Some(previous) = set.parts[index].take() {
            set.received_bytes = set.received_bytes.saturating_sub(previous.len());
        }
        if set.received_bytes.saturating_add(message.data.len()) > UDP_MAX_REASSEMBLED_BYTES {
            self.fragments.remove(&key);
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "hysteria2 udp fragment group is too large",
            ));
        }
        set.received_bytes = set.received_bytes.saturating_add(message.data.len());
        set.parts[index] = Some(message.data);
        if !set.parts.iter().all(Option::is_some) {
            return Ok(None);
        }

        let set = self.fragments.remove(&key).expect("fragment set exists");
        let mut data = Vec::with_capacity(set.received_bytes);
        for part in set.parts {
            data.extend_from_slice(&part.expect("all fragments present"));
        }
        Ok(Some(UdpDatagram {
            session_id: key.0,
            packet_id: key.1,
            fragment_id: 0,
            fragment_count: 1,
            target: set.target,
            data,
        }))
    }

    fn prune_expired(&mut self, now_ms: u64) -> usize {
        let before = self.fragments.len();
        self.fragments
            .retain(|_, set| now_ms.saturating_sub(set.created_ms) < UDP_FRAGMENT_IDLE_TIMEOUT_MS);
        before.saturating_sub(self.fragments.len())
    }
}

async fn bind_udp_socket(target_ip: IpAddr) -> io::Result<UdpSocket> {
    let bind_addr = match target_ip {
        IpAddr::V4(_) => "0.0.0.0:0",
        IpAddr::V6(_) => "[::]:0",
    };
    UdpSocket::bind(bind_addr).await
}

async fn resolve_udp_target(target: &SocksTarget, timeout: Duration) -> io::Result<SocketAddr> {
    crate::dns::resolve_socket_addr_tokio(&target.host, target.port, timeout).await
}

async fn receive_udp_replies(
    session_id: u32,
    session: Arc<UdpRelaySession>,
    connection: quinn::Connection,
    bandwidth: DirectionalLimiters,
) -> io::Result<()> {
    let mut buffer = vec![0u8; UDP_PACKET_BUFFER_SIZE];
    let has_data_limits = bandwidth.has_data_limits();
    loop {
        if session.is_closed() {
            return Ok(());
        }
        let (read, peer) = tokio::select! {
            result = session.socket.recv_from(&mut buffer) => result?,
            _ = connection.closed() => return Ok(()),
            _ = bandwidth.wait_revoked() => return Ok(()),
            _ = tokio::time::sleep(Duration::from_millis(UDP_SESSION_CLEANUP_INTERVAL_MS)) => {
                if session.is_closed() || session.is_idle(now_millis()) {
                    session.close();
                    return Ok(());
                }
                continue;
            }
        };
        if has_data_limits && !bandwidth.wait_download(read).await {
            return Ok(());
        }
        let packet_id = session.next_packet_id.fetch_add(1, Ordering::Relaxed);
        let address = format_socket_addr(&peer);
        if !send_udp_datagram_fragments(
            &connection,
            session_id,
            packet_id,
            &address,
            &buffer[..read],
        )
        .await?
        {
            continue;
        }
        session.add_download(read as u64);
    }
}

async fn send_udp_datagram_fragments(
    connection: &quinn::Connection,
    session_id: u32,
    packet_id: u16,
    address: &str,
    data: &[u8],
) -> io::Result<bool> {
    let Some(max_size) = connection.max_datagram_size() else {
        return Ok(false);
    };
    let header_len = encode_udp_datagram(session_id, packet_id, 0, 1, address, &[])?.len();
    let max_payload = max_size.saturating_sub(header_len);
    if max_payload == 0 {
        return Ok(false);
    }
    let fragment_count = data.len().saturating_add(max_payload - 1) / max_payload;
    if fragment_count == 0 || fragment_count > u8::MAX as usize {
        return Ok(false);
    }
    let fragment_count = fragment_count as u8;
    for (fragment_id, chunk) in data.chunks(max_payload).enumerate() {
        let datagram = encode_udp_datagram(
            session_id,
            packet_id,
            fragment_id as u8,
            fragment_count,
            address,
            chunk,
        )?;
        if datagram.len() > max_size {
            return Ok(false);
        }
        connection
            .send_datagram_wait(Bytes::from(datagram))
            .await
            .map_err(io_other)?;
    }
    Ok(true)
}

async fn send_h3_status<S, B>(
    stream: &mut h3::server::RequestStream<S, B>,
    status: u16,
) -> io::Result<()>
where
    S: h3::quic::BidiStream<B>,
    B: bytes::Buf,
{
    let response = http::Response::builder()
        .status(http::StatusCode::from_u16(status).map_err(io_other)?)
        .body(())
        .map_err(io_other)?;
    stream.send_response(response).await.map_err(io_other)?;
    stream.finish().await.map_err(io_other)
}

async fn read_tcp_target(stream: &mut quinn::RecvStream) -> io::Result<SocksTarget> {
    let first = read_varint(stream).await?;
    // Xray-style Hysteria wraps TCP streams with a 0x401 frame marker before
    // the protocol-level request. Official/native clients may send the
    // request body directly, so accept both forms.
    let address_len = if first == TCP_REQUEST_ID {
        read_varint(stream).await?
    } else {
        first
    };
    if address_len == 0 || address_len > 4096 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid hysteria2 address length",
        ));
    }
    let mut address = vec![0u8; address_len as usize];
    read_exact(stream, &mut address).await?;
    let address = String::from_utf8(address)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid hysteria2 address"))?;
    let padding_len = read_varint(stream).await?;
    if padding_len > 4096 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid hysteria2 padding length",
        ));
    }
    if padding_len > 0 {
        let mut padding = vec![0u8; padding_len as usize];
        read_exact(stream, &mut padding).await?;
    }
    parse_target_address(&address)
}

fn parse_target_address(address: &str) -> io::Result<SocksTarget> {
    if let Some(rest) = address.strip_prefix('[') {
        let Some(end) = rest.find(']') else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid hysteria2 ipv6 address",
            ));
        };
        let host = &rest[..end];
        let port = rest[end + 1..]
            .strip_prefix(':')
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing port"))?;
        return Ok(SocksTarget {
            host: host.to_string(),
            port: parse_port(port)?,
        });
    }

    let Some((host, port)) = address.rsplit_once(':') else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "hysteria2 target missing port",
        ));
    };
    if host.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "hysteria2 target host is empty",
        ));
    }
    Ok(SocksTarget {
        host: host.to_string(),
        port: parse_port(port)?,
    })
}

fn parse_port(value: &str) -> io::Result<u16> {
    value.parse::<u16>().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "hysteria2 target port is invalid",
        )
    })
}

fn parse_udp_datagram(input: &[u8]) -> io::Result<UdpDatagram> {
    if input.len() < 8 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "hysteria2 udp datagram is too short",
        ));
    }
    let session_id = u32::from_be_bytes(input[0..4].try_into().expect("fixed slice"));
    let packet_id = u16::from_be_bytes(input[4..6].try_into().expect("fixed slice"));
    let fragment_id = input[6];
    let fragment_count = input[7];
    let mut offset = 8usize;

    let address_len = read_varint_from(input, &mut offset)?;
    if address_len == 0 || address_len > 4096 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid hysteria2 udp address length",
        ));
    }
    let address_len = address_len as usize;
    if input.len().saturating_sub(offset) < address_len {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "truncated hysteria2 udp address",
        ));
    }
    let address = std::str::from_utf8(&input[offset..offset + address_len])
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid hysteria2 udp address"))?;
    offset += address_len;

    Ok(UdpDatagram {
        session_id,
        packet_id,
        fragment_id,
        fragment_count,
        target: parse_target_address(address)?,
        data: input[offset..].to_vec(),
    })
}

fn encode_udp_datagram(
    session_id: u32,
    packet_id: u16,
    fragment_id: u8,
    fragment_count: u8,
    address: &str,
    data: &[u8],
) -> io::Result<Vec<u8>> {
    if address.is_empty() || address.len() > 4096 || data.len() > UDP_PACKET_BUFFER_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid hysteria2 udp datagram field length",
        ));
    }
    let mut output = Vec::with_capacity(8 + address.len() + data.len() + 8);
    output.extend_from_slice(&session_id.to_be_bytes());
    output.extend_from_slice(&packet_id.to_be_bytes());
    output.push(fragment_id);
    output.push(fragment_count);
    output.extend_from_slice(&encode_varint(address.len() as u64)?);
    output.extend_from_slice(address.as_bytes());
    output.extend_from_slice(data);
    Ok(output)
}

fn format_socket_addr(addr: &SocketAddr) -> String {
    match addr.ip() {
        IpAddr::V4(ip) => format!("{ip}:{}", addr.port()),
        IpAddr::V6(ip) => format!("[{ip}]:{}", addr.port()),
    }
}

fn parse_hysteria_rx_header(value: &str) -> Option<u64> {
    value.trim().parse::<u64>().ok().filter(|value| *value > 0)
}

fn mbps_to_bytes_per_second(mbps: u32) -> Option<u64> {
    if mbps == 0 {
        return None;
    }
    Some(
        (mbps as u64)
            .saturating_mul(1024 * 1024)
            .saturating_div(8)
            .max(1),
    )
}

fn enforced_hy2_bandwidth_bps(mbps: u32) -> Option<u64> {
    if mbps == 0 || mbps > hy2_software_bandwidth_limit_max_mbps() {
        return None;
    }
    mbps_to_bytes_per_second(mbps)
}

fn hy2_software_bandwidth_limit_max_mbps() -> u32 {
    env::var(HY2_SOFTWARE_BANDWIDTH_LIMIT_MAX_MBPS_ENV)
        .ok()
        .and_then(|value| value.trim().parse::<u32>().ok())
        .map(|value| value.min(10_000))
        .unwrap_or(DEFAULT_HY2_SOFTWARE_BANDWIDTH_LIMIT_MAX_MBPS)
}

fn min_nonzero(left: Option<u64>, right: Option<u64>) -> Option<u64> {
    match (left, right) {
        (Some(left), Some(right)) => Some(left.min(right)),
        (Some(value), None) | (None, Some(value)) => Some(value),
        (None, None) => None,
    }
}

async fn write_tcp_response(
    send: &mut quinn::SendStream,
    status: u8,
    message: &str,
) -> io::Result<()> {
    let mut response = Vec::with_capacity(1 + 16 + message.len());
    response.push(status);
    append_varint(&mut response, message.len() as u64)?;
    if !message.is_empty() {
        response.extend_from_slice(message.as_bytes());
    }
    append_varint(&mut response, 0)?;
    send.write_all(&response).await.map_err(io_other)
}

async fn relay_streams(
    recv: &mut quinn::RecvStream,
    send: &mut quinn::SendStream,
    remote: tokio::net::TcpStream,
    bandwidth: DirectionalLimiters,
    mut on_upload: impl FnMut(u64),
    mut on_download: impl FnMut(u64),
) -> io::Result<(u64, u64)> {
    if !bandwidth.has_data_limits() {
        return relay_streams_unlimited(recv, send, remote, on_upload, on_download).await;
    }

    let upload_remote_shutdown = clone_tokio_tcp_stream_for_shutdown(&remote)?;
    let download_remote_shutdown = clone_tokio_tcp_stream_for_shutdown(&remote)?;
    let (mut remote_read, mut remote_write) = remote.into_split();
    let upload = async {
        let bandwidth = bandwidth.clone();
        let mut total = 0u64;
        let mut pending = 0u64;
        let mut buffer = [0u8; 16 * 1024];
        loop {
            let revoke_watch = bandwidth.clone();
            let read_result = tokio::select! {
                read = recv.read(&mut buffer) => read.map_err(io_other),
                _ = revoke_watch.wait_revoked() => {
                    flush_pending_traffic(&mut pending, &mut on_upload);
                    let _ = remote_write.shutdown().await;
                    close_tcp_socket(&upload_remote_shutdown);
                    return Ok::<u64, io::Error>(total);
                }
            };
            let read = match read_result {
                Ok(read) => read,
                Err(error) => {
                    flush_pending_traffic(&mut pending, &mut on_upload);
                    let _ = remote_write.shutdown().await;
                    close_tcp_socket(&upload_remote_shutdown);
                    return Err(error);
                }
            };
            let Some(read) = read else {
                flush_pending_traffic(&mut pending, &mut on_upload);
                let _ = remote_write.shutdown().await;
                return Ok::<u64, io::Error>(total);
            };
            if !bandwidth.wait_upload(read).await {
                flush_pending_traffic(&mut pending, &mut on_upload);
                let _ = remote_write.shutdown().await;
                close_tcp_socket(&upload_remote_shutdown);
                return Ok::<u64, io::Error>(total);
            }
            if let Err(error) = hy2_write_all_fast(&mut remote_write, &buffer[..read]).await {
                flush_pending_traffic(&mut pending, &mut on_upload);
                let _ = remote_write.shutdown().await;
                close_tcp_socket(&upload_remote_shutdown);
                return Err(error);
            }
            total = total.saturating_add(read as u64);
            pending = pending.saturating_add(read as u64);
            if pending >= STREAM_TRAFFIC_FLUSH_BYTES {
                on_upload(pending);
                pending = 0;
            }
        }
    };
    let download = async {
        let bandwidth = bandwidth.clone();
        let mut total = 0u64;
        let mut pending = 0u64;
        let mut buffer = [0u8; 16 * 1024];
        loop {
            let revoke_watch = bandwidth.clone();
            let read_result = tokio::select! {
                read = remote_read.read(&mut buffer) => read,
                _ = revoke_watch.wait_revoked() => {
                    flush_pending_traffic(&mut pending, &mut on_download);
                    let _ = send.finish();
                    close_tcp_socket(&download_remote_shutdown);
                    return Ok::<u64, io::Error>(total);
                }
            };
            let read = match read_result {
                Ok(read) => read,
                Err(error) => {
                    flush_pending_traffic(&mut pending, &mut on_download);
                    let _ = send.finish();
                    close_tcp_socket(&download_remote_shutdown);
                    return Err(error);
                }
            };
            if read == 0 {
                flush_pending_traffic(&mut pending, &mut on_download);
                let _ = send.finish();
                close_tcp_socket(&download_remote_shutdown);
                return Ok::<u64, io::Error>(total);
            }
            if !bandwidth.wait_download(read).await {
                flush_pending_traffic(&mut pending, &mut on_download);
                let _ = send.finish();
                close_tcp_socket(&download_remote_shutdown);
                return Ok::<u64, io::Error>(total);
            }
            if let Err(error) = hy2_write_all_fast(send, &buffer[..read]).await {
                flush_pending_traffic(&mut pending, &mut on_download);
                let _ = send.finish();
                close_tcp_socket(&download_remote_shutdown);
                return Err(error);
            }
            total = total.saturating_add(read as u64);
            pending = pending.saturating_add(read as u64);
            if pending >= STREAM_TRAFFIC_FLUSH_BYTES {
                on_download(pending);
                pending = 0;
            }
        }
    };
    tokio::try_join!(upload, download)
}

async fn relay_streams_unlimited(
    recv: &mut quinn::RecvStream,
    send: &mut quinn::SendStream,
    remote: tokio::net::TcpStream,
    mut on_upload: impl FnMut(u64),
    mut on_download: impl FnMut(u64),
) -> io::Result<(u64, u64)> {
    let upload_remote_shutdown = clone_tokio_tcp_stream_for_shutdown(&remote)?;
    let download_remote_shutdown = clone_tokio_tcp_stream_for_shutdown(&remote)?;
    let (mut remote_read, mut remote_write) = remote.into_split();
    let upload = async {
        let mut total = 0u64;
        let mut pending = 0u64;
        let mut buffer = [0u8; 16 * 1024];
        loop {
            let read_result = recv.read(&mut buffer).await.map_err(io_other);
            let Some(read) = (match read_result {
                Ok(read) => read,
                Err(error) => {
                    flush_pending_traffic(&mut pending, &mut on_upload);
                    let _ = remote_write.shutdown().await;
                    close_tcp_socket(&upload_remote_shutdown);
                    return Err(error);
                }
            }) else {
                flush_pending_traffic(&mut pending, &mut on_upload);
                let _ = remote_write.shutdown().await;
                return Ok::<u64, io::Error>(total);
            };
            if let Err(error) =
                hy2_write_all_with_timeout(&mut remote_write, &buffer[..read], "upload").await
            {
                flush_pending_traffic(&mut pending, &mut on_upload);
                let _ = remote_write.shutdown().await;
                close_tcp_socket(&upload_remote_shutdown);
                return Err(error);
            }
            total = total.saturating_add(read as u64);
            pending = pending.saturating_add(read as u64);
            if pending >= STREAM_TRAFFIC_FLUSH_BYTES {
                on_upload(pending);
                pending = 0;
            }
        }
    };
    let download = async {
        let mut total = 0u64;
        let mut pending = 0u64;
        let mut buffer = [0u8; 16 * 1024];
        loop {
            let read = match remote_read.read(&mut buffer).await {
                Ok(read) => read,
                Err(error) => {
                    flush_pending_traffic(&mut pending, &mut on_download);
                    let _ = send.finish();
                    close_tcp_socket(&download_remote_shutdown);
                    return Err(error);
                }
            };
            if read == 0 {
                flush_pending_traffic(&mut pending, &mut on_download);
                let _ = send.finish();
                close_tcp_socket(&download_remote_shutdown);
                return Ok::<u64, io::Error>(total);
            }
            if let Err(error) = hy2_write_all_with_timeout(send, &buffer[..read], "download").await
            {
                flush_pending_traffic(&mut pending, &mut on_download);
                let _ = send.finish();
                close_tcp_socket(&download_remote_shutdown);
                return Err(error);
            }
            total = total.saturating_add(read as u64);
            pending = pending.saturating_add(read as u64);
            if pending >= STREAM_TRAFFIC_FLUSH_BYTES {
                on_download(pending);
                pending = 0;
            }
        }
    };
    tokio::try_join!(upload, download)
}

fn flush_pending_traffic(pending: &mut u64, on_traffic: &mut impl FnMut(u64)) {
    if *pending == 0 {
        return;
    }
    on_traffic(*pending);
    *pending = 0;
}

fn clone_tokio_tcp_stream_for_shutdown(socket: &tokio::net::TcpStream) -> io::Result<TcpStream> {
    Ok(TcpStream::from(SockRef::from(socket).try_clone()?))
}

fn close_tcp_socket(socket: &TcpStream) {
    let _ = socket.shutdown(Shutdown::Both);
}

async fn hy2_write_all_with_timeout<W>(
    writer: &mut W,
    buffer: &[u8],
    direction: &'static str,
) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    match tokio::time::timeout(hy2_relay_io_timeout(), writer.write_all(buffer)).await {
        Ok(result) => result,
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("hysteria2 {direction} write timed out"),
        )),
    }
}

async fn hy2_write_all_fast<W>(writer: &mut W, buffer: &[u8]) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    writer.write_all(buffer).await.map_err(io_other)
}

fn hy2_auth_timeout() -> Duration {
    env_duration_seconds(HY2_AUTH_TIMEOUT_SECS_ENV, DEFAULT_HY2_AUTH_TIMEOUT_SECS)
}

fn hy2_preauth_connection_limit(listener_connection_limit: usize) -> usize {
    if let Ok(value) = env::var(HY2_PREAUTH_LIMIT_ENV) {
        if let Ok(parsed) = value.trim().parse::<usize>() {
            return parsed.clamp(8, listener_connection_limit.max(8));
        }
    }
    (listener_connection_limit / 2)
        .clamp(HY2_PREAUTH_MIN, HY2_PREAUTH_MAX)
        .min(listener_connection_limit)
        .max(8)
}

fn hy2_relay_io_timeout() -> Duration {
    static TIMEOUT: OnceLock<Duration> = OnceLock::new();
    *TIMEOUT.get_or_init(|| {
        env_duration_seconds(
            HY2_RELAY_IO_TIMEOUT_SECS_ENV,
            DEFAULT_HY2_RELAY_IO_TIMEOUT_SECS,
        )
    })
}

fn env_duration_seconds(name: &str, default_seconds: u64) -> Duration {
    let seconds = env::var(name)
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|seconds| *seconds > 0)
        .unwrap_or(default_seconds);
    Duration::from_secs(seconds)
}

async fn read_varint(stream: &mut quinn::RecvStream) -> io::Result<u64> {
    let mut first = [0u8; 1];
    read_exact(stream, &mut first).await?;
    let tag = first[0] >> 6;
    let len = 1usize << tag;
    let mut bytes = [0u8; 8];
    bytes[0] = first[0] & 0b0011_1111;
    if len > 1 {
        read_exact(stream, &mut bytes[1..len]).await?;
    }
    Ok(match len {
        1 => bytes[0] as u64,
        2 => u16::from_be_bytes([bytes[0], bytes[1]]) as u64,
        4 => u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64,
        8 => u64::from_be_bytes(bytes),
        _ => unreachable!("QUIC varint lengths are fixed"),
    })
}

fn read_varint_from(input: &[u8], offset: &mut usize) -> io::Result<u64> {
    if *offset >= input.len() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "missing QUIC varint",
        ));
    }
    let first = input[*offset];
    let tag = first >> 6;
    let len = 1usize << tag;
    if input.len().saturating_sub(*offset) < len {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "truncated QUIC varint",
        ));
    }
    let mut bytes = [0u8; 8];
    bytes[0] = first & 0b0011_1111;
    if len > 1 {
        bytes[1..len].copy_from_slice(&input[*offset + 1..*offset + len]);
    }
    *offset += len;
    Ok(match len {
        1 => bytes[0] as u64,
        2 => u16::from_be_bytes([bytes[0], bytes[1]]) as u64,
        4 => u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as u64,
        8 => u64::from_be_bytes(bytes),
        _ => unreachable!("QUIC varint lengths are fixed"),
    })
}

fn encode_varint(value: u64) -> io::Result<Vec<u8>> {
    let mut output = Vec::with_capacity(8);
    append_varint(&mut output, value)?;
    Ok(output)
}

fn append_varint(output: &mut Vec<u8>, value: u64) -> io::Result<()> {
    if value < 2u64.pow(6) {
        output.push(value as u8);
    } else if value < 2u64.pow(14) {
        output.extend_from_slice(&((0b01u16 << 14) | value as u16).to_be_bytes());
    } else if value < 2u64.pow(30) {
        output.extend_from_slice(&((0b10u32 << 30) | value as u32).to_be_bytes());
    } else if value < 2u64.pow(62) {
        output.extend_from_slice(&((0b11u64 << 62) | value).to_be_bytes());
    } else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "value too large for QUIC varint",
        ));
    }
    Ok(())
}

async fn read_exact(stream: &mut quinn::RecvStream, output: &mut [u8]) -> io::Result<()> {
    stream.read_exact(output).await.map_err(io_other)
}

fn io_other(error: impl std::fmt::Debug) -> io::Error {
    io::Error::new(io::ErrorKind::Other, format!("{error:?}"))
}

#[derive(Debug)]
struct Hysteria2AuthBackoff {
    shards: Vec<Mutex<HashMap<IpAddr, Hysteria2AuthBackoffEntry>>>,
}

#[derive(Debug)]
struct Hysteria2AuthBackoffEntry {
    failures: u32,
    window_started: Instant,
    blocked_until: Option<Instant>,
}

impl Hysteria2AuthBackoff {
    fn new() -> Self {
        let shards = (0..HY2_INVALID_AUTH_BACKOFF_SHARDS)
            .map(|_| Mutex::new(HashMap::new()))
            .collect();
        Self { shards }
    }

    fn is_blocked(&self, ip: IpAddr) -> bool {
        self.is_blocked_at(ip, Instant::now())
    }

    fn record_invalid(&self, ip: IpAddr) {
        self.record_invalid_at(ip, Instant::now());
    }

    fn record_success(&self, ip: IpAddr) {
        let mut entries = self
            .shard(ip)
            .lock()
            .expect("hysteria2 auth backoff state poisoned");
        entries.remove(&ip);
    }

    fn is_blocked_at(&self, ip: IpAddr, now: Instant) -> bool {
        let mut entries = self
            .shard(ip)
            .lock()
            .expect("hysteria2 auth backoff state poisoned");
        let Some(entry) = entries.get_mut(&ip) else {
            return false;
        };
        let Some(blocked_until) = entry.blocked_until else {
            return false;
        };
        if now < blocked_until {
            return true;
        }
        entry.failures = 0;
        entry.window_started = now;
        entry.blocked_until = None;
        false
    }

    fn record_invalid_at(&self, ip: IpAddr, now: Instant) {
        let mut entries = self
            .shard(ip)
            .lock()
            .expect("hysteria2 auth backoff state poisoned");
        if entries.len() >= self.max_entries_per_shard() {
            entries.retain(|_, entry| !entry.is_expired(now));
            if entries.len() >= self.max_entries_per_shard() {
                if let Some(first) = entries.keys().next().copied() {
                    entries.remove(&first);
                }
            }
        }
        let entry = entries.entry(ip).or_insert(Hysteria2AuthBackoffEntry {
            failures: 0,
            window_started: now,
            blocked_until: None,
        });
        let in_window = now
            .checked_duration_since(entry.window_started)
            .map(|elapsed| elapsed <= HY2_INVALID_AUTH_BACKOFF_WINDOW)
            .unwrap_or(false);
        if !in_window {
            entry.failures = 0;
            entry.window_started = now;
            entry.blocked_until = None;
        }
        entry.failures = entry.failures.saturating_add(1);
        if entry.failures >= HY2_INVALID_AUTH_BACKOFF_THRESHOLD {
            entry.blocked_until = Some(now + HY2_INVALID_AUTH_BACKOFF_DURATION);
        }
    }

    fn shard(&self, ip: IpAddr) -> &Mutex<HashMap<IpAddr, Hysteria2AuthBackoffEntry>> {
        let index = self.shard_index(ip);
        &self.shards[index]
    }

    fn shard_index(&self, ip: IpAddr) -> usize {
        let mut hasher = std::collections::hash_map::DefaultHasher::new();
        ip.hash(&mut hasher);
        (hasher.finish() as usize) % self.shards.len()
    }

    fn max_entries_per_shard(&self) -> usize {
        HY2_INVALID_AUTH_BACKOFF_MAX_ENTRIES
            .div_ceil(self.shards.len())
            .max(1)
    }
}

impl Default for Hysteria2AuthBackoff {
    fn default() -> Self {
        Self::new()
    }
}

impl Hysteria2AuthBackoffEntry {
    fn is_expired(&self, now: Instant) -> bool {
        if let Some(blocked_until) = self.blocked_until {
            return now >= blocked_until
                && now
                    .checked_duration_since(blocked_until)
                    .map(|elapsed| elapsed > HY2_INVALID_AUTH_BACKOFF_WINDOW)
                    .unwrap_or(false);
        }
        now.checked_duration_since(self.window_started)
            .map(|elapsed| elapsed > HY2_INVALID_AUTH_BACKOFF_WINDOW * 2)
            .unwrap_or(false)
    }
}

fn log_hysteria2_error(scope: &'static str, error: &io::Error) {
    let text = error.to_string();
    let class = classify_hysteria2_error_text(error, &text);
    crate::metrics::record_connection_error("hysteria2", scope, class.label());
    if class == Hysteria2ErrorClass::ExpectedClose {
        return;
    }
    let Some(suppressed) = should_log_hysteria2_error(scope, class) else {
        return;
    };
    let level = class.log_level();
    let label = class.label();
    let suppressed = if suppressed == 0 {
        String::new()
    } else {
        format!(" suppressed={suppressed}")
    };
    crate::logging::emit_legacy_line(&format!(
        "{level} core   hysteria2 {scope} {label}{suppressed}: {text}"
    ));
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
enum Hysteria2ErrorClass {
    ExpectedClose,
    InvalidAuth,
    InvalidRequest,
    TargetFailure,
    Timeout,
    Transport,
    Other,
}

impl Hysteria2ErrorClass {
    fn label(self) -> &'static str {
        match self {
            Self::ExpectedClose => "closed",
            Self::InvalidAuth => "invalid-auth",
            Self::InvalidRequest => "invalid-request",
            Self::TargetFailure => "target-failure",
            Self::Timeout => "timeout",
            Self::Transport => "transport",
            Self::Other => "error",
        }
    }

    fn log_level(self) -> &'static str {
        match self {
            Self::InvalidAuth
            | Self::InvalidRequest
            | Self::TargetFailure
            | Self::Timeout
            | Self::Transport => "WARN",
            Self::ExpectedClose | Self::Other => "ERROR",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct Hysteria2ErrorLogKey {
    scope: &'static str,
    class: Hysteria2ErrorClass,
}

#[derive(Default)]
struct Hysteria2ErrorLogState {
    last_ms: u64,
    suppressed: u64,
}

fn should_log_hysteria2_error(scope: &'static str, class: Hysteria2ErrorClass) -> Option<u64> {
    static STATE: OnceLock<Mutex<HashMap<Hysteria2ErrorLogKey, Hysteria2ErrorLogState>>> =
        OnceLock::new();
    let now = now_millis();
    let mut states = STATE
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .expect("hysteria2 error log state poisoned");
    hysteria2_error_log_decision_at(&mut states, scope, class, now)
}

fn hysteria2_error_log_decision_at(
    states: &mut HashMap<Hysteria2ErrorLogKey, Hysteria2ErrorLogState>,
    scope: &'static str,
    class: Hysteria2ErrorClass,
    now: u64,
) -> Option<u64> {
    let key = Hysteria2ErrorLogKey { scope, class };
    let state = states.entry(key).or_default();
    if state.last_ms != 0 && now.saturating_sub(state.last_ms) < HY2_ERROR_LOG_INTERVAL_MS {
        state.suppressed = state.suppressed.saturating_add(1);
        return None;
    }
    let suppressed = std::mem::take(&mut state.suppressed);
    state.last_ms = now;
    Some(suppressed)
}

#[cfg(test)]
fn is_expected_hysteria2_close(error: &io::Error) -> bool {
    is_expected_hysteria2_close_text(&error.to_string())
}

fn is_expected_hysteria2_close_text(text: &str) -> bool {
    text.contains("Stopped(0)")
        || text.contains("LocallyClosed")
        || text.contains("ApplicationClose(0x0)")
        || text.contains("ApplicationClosed")
        || text.contains("ConnectionClosed(ConnectionClose")
        || text.contains("connection closed before authentication")
        || text.contains("FinishedEarly(0)")
        || text.contains("Broken pipe")
        || text.contains("Connection reset by peer")
        || text.contains("Reset(0)")
        || text.contains("Reset(")
        || text.contains("sending stopped by peer")
        || text.contains("got two control streams")
}

#[cfg(test)]
fn is_hysteria2_timeout(error: &io::Error) -> bool {
    is_hysteria2_timeout_text(error, &error.to_string())
}

fn is_hysteria2_timeout_text(error: &io::Error, text: &str) -> bool {
    if error.kind() == io::ErrorKind::TimedOut {
        return true;
    }
    text == "Timeout"
        || text.contains("TimedOut")
        || text.contains("ConnectionError(Timeout)")
        || text.contains("timed out")
}

#[cfg(test)]
fn classify_hysteria2_error(error: &io::Error) -> Hysteria2ErrorClass {
    classify_hysteria2_error_text(error, &error.to_string())
}

fn classify_hysteria2_error_text(error: &io::Error, text: &str) -> Hysteria2ErrorClass {
    if is_expected_hysteria2_close_text(text) {
        return Hysteria2ErrorClass::ExpectedClose;
    }
    if text.contains("invalid hysteria2 authentication") || text.contains("authentication failed") {
        return Hysteria2ErrorClass::InvalidAuth;
    }
    if text.contains("invalid hysteria2 tcp request id")
        || text.contains("invalid hysteria2 udp")
        || text.contains("invalid hysteria2 address")
        || text.contains("invalid hysteria2 padding")
        || text.contains("hysteria2 target missing port")
    {
        return Hysteria2ErrorClass::InvalidRequest;
    }
    if is_hysteria2_timeout_text(error, text) {
        return Hysteria2ErrorClass::Timeout;
    }
    if text.contains("tcp connect failed")
        || text.contains("tcp outbound connect failed")
        || text.contains("route outbound failed")
        || text.contains("dns response indicates failure")
        || text.contains("configured dns servers returned no target address")
        || text.contains("Connection refused")
        || text.contains("Network is unreachable")
        || text.contains("No route to host")
    {
        return Hysteria2ErrorClass::TargetFailure;
    }
    if text.contains("Connection reset")
        || text.contains("ConnectionReset")
        || text.contains("Reset")
        || text.contains("Broken pipe")
        || text.contains("FinishedEarly")
        || text.contains("connection lost")
        || text.contains("Connection lost")
        || text.contains("RemoteTerminate")
        || text.contains("H3_REQUEST_CANCELLED")
        || text.contains("got two control streams")
    {
        return Hysteria2ErrorClass::Transport;
    }
    Hysteria2ErrorClass::Other
}

fn annotate_hysteria2_route_outbound_error(
    node_tag: &str,
    outbound: &crate::config::OutboundConfig,
    target: &SocksTarget,
    elapsed: Duration,
    error: io::Error,
) -> io::Error {
    let endpoint = hysteria2_outbound_endpoint(outbound);
    io::Error::new(
        error.kind(),
        format!(
            "route outbound failed node_tag={} outbound={} protocol={} endpoint={} target={}:{} elapsed_ms={} error={}",
            hysteria2_log_field(node_tag),
            hysteria2_log_field(&outbound.tag),
            hysteria2_log_field(&outbound.protocol),
            hysteria2_log_field(&endpoint),
            hysteria2_log_field(&target.host),
            target.port,
            elapsed.as_millis(),
            hysteria2_log_message(&error.to_string())
        ),
    )
}

fn log_hysteria2_route_outbound_connected(
    node_tag: &str,
    outbound: &crate::config::OutboundConfig,
    target: &SocksTarget,
    elapsed: Duration,
) {
    if elapsed.as_millis() < HY2_ROUTE_SLOW_LOG_MS && !route_trace_enabled() {
        return;
    }
    let endpoint = hysteria2_outbound_endpoint(outbound);
    crate::logging::emit_legacy_line(&format!(
        "INFO  core   hysteria2 route outbound connected node_tag={} outbound={} protocol={} endpoint={} target={}:{} elapsed_ms={}",
        hysteria2_log_field(node_tag),
        hysteria2_log_field(&outbound.tag),
        hysteria2_log_field(&outbound.protocol),
        hysteria2_log_field(&endpoint),
        hysteria2_log_field(&target.host),
        target.port,
        elapsed.as_millis()
    ));
}

fn route_trace_enabled() -> bool {
    env::var_os(ROUTE_TRACE_ENV).is_some()
}

fn hysteria2_outbound_endpoint(outbound: &crate::config::OutboundConfig) -> String {
    let host = outbound
        .address
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("-");
    match outbound.port {
        Some(port) => format!("{host}:{port}"),
        None => format!("{host}:-"),
    }
}

fn hysteria2_log_field(value: &str) -> String {
    value
        .chars()
        .map(|ch| {
            if ch.is_ascii_control() || ch.is_whitespace() {
                '_'
            } else {
                ch
            }
        })
        .collect()
}

fn hysteria2_log_message(value: &str) -> String {
    value
        .chars()
        .map(|ch| if ch.is_ascii_control() { ' ' } else { ch })
        .collect()
}

fn is_hysteria2_invalid_auth_error(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::PermissionDenied
        && error
            .to_string()
            .contains("invalid hysteria2 authentication")
}

fn should_record_hysteria2_auth_backoff(error: &io::Error) -> bool {
    is_hysteria2_invalid_auth_error(error)
}

fn now_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::future::poll_fn;
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64};
    use std::time::{SystemTime, UNIX_EPOCH};

    use quinn::crypto::rustls::QuicClientConfig;
    use rustls::pki_types::CertificateDer;

    use crate::config::{OutboundConfig, RouteAction, RouteRule};

    use super::*;

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
        let cert_path = dir.join(format!("keli-core-rs-hy2-{label}-{nanos}.crt"));
        let key_path = dir.join(format!("keli-core-rs-hy2-{label}-{nanos}.key"));
        fs::write(&cert_path, cert.cert.pem()).expect("write cert");
        fs::write(&key_path, cert.key_pair.serialize_pem()).expect("write key");
        TestCert {
            cert_path,
            key_path,
            cert_der: cert.cert.der().clone(),
        }
    }

    fn user() -> CoreUser {
        CoreUser {
            id: 1,
            uuid: "hy2-password".to_string(),
            password: None,
            email: None,
            speed_limit: 0,
            device_limit: 0,
        }
    }

    fn user_b() -> CoreUser {
        CoreUser {
            id: 2,
            uuid: "hy2-user-b".to_string(),
            password: Some("secret-b".to_string()),
            email: None,
            speed_limit: 0,
            device_limit: 0,
        }
    }

    fn client_endpoint(cert_der: CertificateDer<'static>) -> quinn::Endpoint {
        let mut roots = rustls::RootCertStore::empty();
        roots.add(cert_der).expect("root cert");
        let mut crypto = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        crypto.alpn_protocols = vec![b"h3".to_vec()];
        let mut client_config =
            quinn::ClientConfig::new(Arc::new(QuicClientConfig::try_from(crypto).unwrap()));
        let mut transport = quinn::TransportConfig::default();
        transport
            .datagram_receive_buffer_size(Some(UDP_DATAGRAM_BUFFER_SIZE))
            .datagram_send_buffer_size(UDP_DATAGRAM_BUFFER_SIZE);
        client_config.transport_config(Arc::new(transport));
        let mut endpoint = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(client_config);
        endpoint
    }

    fn server(cert: &TestCert, listen: SocketAddr) -> Hysteria2Server {
        Hysteria2Server::new(Hysteria2ServerConfig {
            node_tag: "panel|hysteria|1".to_string(),
            listen,
            users: vec![user()],
            routes: Vec::new(),
            cert_file: cert.cert_path.to_string_lossy().to_string(),
            key_file: cert.key_path.to_string_lossy().to_string(),
            server_name: "localhost".to_string(),
            alpn: vec!["h3".to_string()],
            reject_unknown_sni: false,
            connect_timeout: Duration::from_secs(3),
            up_mbps: 0,
            down_mbps: 0,
            ignore_client_bandwidth: false,
            congestion_control: String::new(),
            obfs: None,
        })
    }

    fn server_with_bandwidth(
        cert: &TestCert,
        listen: SocketAddr,
        up_mbps: u32,
        down_mbps: u32,
        ignore_client_bandwidth: bool,
    ) -> Hysteria2Server {
        let mut server = server(cert, listen);
        server.config.up_mbps = up_mbps;
        server.config.down_mbps = down_mbps;
        server.config.ignore_client_bandwidth = ignore_client_bandwidth;
        server
    }

    #[test]
    fn server_clone_does_not_duplicate_full_user_list() {
        let cert = test_cert("clone-users");
        let server = Hysteria2Server::new(Hysteria2ServerConfig {
            node_tag: "panel|hysteria|1".to_string(),
            listen: "127.0.0.1:0".parse().expect("addr"),
            users: vec![user()],
            routes: vec![RouteRule {
                action: RouteAction::Block,
                targets: vec!["domain:blocked.example".to_string()],
                outbound: None,
            }],
            cert_file: cert.cert_path.to_string_lossy().to_string(),
            key_file: cert.key_path.to_string_lossy().to_string(),
            server_name: "localhost".to_string(),
            alpn: vec!["h3".to_string()],
            reject_unknown_sni: false,
            connect_timeout: Duration::from_secs(3),
            up_mbps: 0,
            down_mbps: 0,
            ignore_client_bandwidth: false,
            congestion_control: String::new(),
            obfs: None,
        });

        assert_eq!(server.users.len(), 1);
        assert!(server.config.users.is_empty());
        assert!(server.config.routes.is_empty());
        assert!(server.clone().config.users.is_empty());
        assert!(server.clone().config.routes.is_empty());
        assert!(matches!(
            server.router.decide("blocked.example"),
            RouteDecision::Block
        ));
    }

    #[test]
    fn replaces_users_without_rebuilding_hysteria2_server() {
        let cert = test_cert("replace-users");
        let server = server(&cert, "127.0.0.1:0".parse().expect("addr"));

        server.replace_users(vec![user_b()]);

        assert!(server.user_for_auth("hy2-password").is_none());
        let user = server
            .user_for_auth("secret-b")
            .expect("new user should authenticate");
        assert_eq!(user.uuid, "hy2-user-b");
    }

    #[test]
    fn apply_user_delta_updates_hysteria2_users() {
        let cert = test_cert("user-delta");
        let server = server(&cert, "127.0.0.1:0".parse().expect("addr"));
        let mut updated = user();
        updated.password = Some("rotated-hy2".to_string());
        updated.speed_limit = 123;
        updated.device_limit = 3;

        let result = server.apply_user_delta(&CoreUserDelta {
            added: vec![user_b()],
            updated: vec![updated.clone()],
            ..CoreUserDelta::default()
        });

        assert_eq!(result.added, 1);
        assert_eq!(result.updated, 1);
        assert_eq!(result.active_users, 2);
        assert!(server.user_for_auth("hy2-password").is_none());
        let user = server
            .user_for_auth("rotated-hy2")
            .expect("updated user should authenticate");
        assert_eq!(user.speed_limit, 123);
        assert_eq!(user.device_limit, 3);
        assert!(server.user_for_auth("secret-b").is_some());

        let result = server.apply_user_delta(&CoreUserDelta {
            deleted: vec![updated.uuid.clone()],
            ..CoreUserDelta::default()
        });

        assert_eq!(result.deleted, 1);
        assert_eq!(result.active_users, 1);
        assert!(server.user_for_auth("rotated-hy2").is_none());
        assert!(server.user_for_auth("secret-b").is_some());
    }

    #[test]
    fn directional_limiters_observe_user_revocation() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let limiter = Arc::new(BandwidthLimiter::unlimited());
            let limits = DirectionalLimiters {
                revoke: vec![limiter.clone()],
                upload: Vec::new(),
                download: Vec::new(),
            };
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_millis(25)).await;
                limiter.revoke();
            });

            tokio::time::timeout(Duration::from_secs(1), limits.wait_revoked())
                .await
                .expect("revocation should wake waiter");
        });
    }

    #[test]
    fn unlimited_hysteria2_user_keeps_revoke_out_of_data_limiters() {
        let cert = test_cert("hy2-unlimited-fast-path");
        let server = server(&cert, "127.0.0.1:0".parse().expect("addr"));
        let user = user();

        let limits = server.connection_limiters(
            server.bandwidth.limiter_for(Some(&user)),
            server.bandwidth.limiter_for_limited(Some(&user)),
            None,
        );

        assert_eq!(limits.revoke.len(), 1);
        assert!(limits.upload.is_empty());
        assert!(limits.download.is_empty());
    }

    #[test]
    fn high_hysteria2_bandwidth_hint_does_not_force_software_limiters() {
        let cert = test_cert("hy2-high-bandwidth-fast-path");
        let server = server_with_bandwidth(
            &cert,
            "127.0.0.1:0".parse().expect("addr"),
            1000,
            1000,
            false,
        );
        let user = user();

        let limits = server.connection_limiters(
            server.bandwidth.limiter_for(Some(&user)),
            server.bandwidth.limiter_for_limited(Some(&user)),
            Some(mbps_to_bytes_per_second(1000).expect("client rx")),
        );

        assert_eq!(limits.revoke.len(), 1);
        assert!(
            limits.upload.is_empty(),
            "1000 Mbps HY2 bandwidth should stay a congestion hint, not force per-packet limiter"
        );
        assert!(
            limits.download.is_empty(),
            "1000 Mbps HY2 bandwidth should stay a congestion hint, not force per-packet limiter"
        );
    }

    #[test]
    fn low_hysteria2_bandwidth_still_uses_software_limiters() {
        let cert = test_cert("hy2-low-bandwidth-limiter");
        let server =
            server_with_bandwidth(&cert, "127.0.0.1:0".parse().expect("addr"), 100, 80, false);
        let user = user();

        let limits = server.connection_limiters(
            server.bandwidth.limiter_for(Some(&user)),
            server.bandwidth.limiter_for_limited(Some(&user)),
            Some(mbps_to_bytes_per_second(60).expect("client rx")),
        );

        assert_eq!(limits.revoke.len(), 1);
        assert_eq!(limits.upload.len(), 1);
        assert_eq!(limits.download.len(), 1);
    }

    #[test]
    fn user_speed_limit_still_applies_when_hysteria2_bandwidth_hint_is_high() {
        let cert = test_cert("hy2-user-speed-limit");
        let server = server_with_bandwidth(
            &cert,
            "127.0.0.1:0".parse().expect("addr"),
            1000,
            1000,
            false,
        );
        let mut user = user();
        user.speed_limit = 1024;

        let limits = server.connection_limiters(
            server.bandwidth.limiter_for(Some(&user)),
            server.bandwidth.limiter_for_limited(Some(&user)),
            None,
        );

        assert_eq!(limits.revoke.len(), 1);
        assert_eq!(limits.upload.len(), 1);
        assert_eq!(limits.download.len(), 1);
    }

    #[test]
    fn apply_user_delta_changes_hysteria2_auth_without_rebinding_listener() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let cert = test_cert("user-delta-auth");
            let echo = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("echo bind");
            let echo_addr = echo.local_addr().expect("echo addr");
            let echo_task = tokio::spawn(async move {
                let (mut stream, _) = echo.accept().await.expect("echo accept");
                let mut byte = [0u8; 1];
                stream.read_exact(&mut byte).await.expect("echo read");
                stream.write_all(&byte).await.expect("echo write");
            });
            let server = server(&cert, "127.0.0.1:0".parse().expect("addr"));
            let endpoint = server.bind().expect("hy2 bind");
            let local_addr = endpoint.local_addr().expect("local addr");
            let stop = Arc::new(AtomicBool::new(false));
            let server_task = tokio::spawn(server.clone().run(endpoint, stop.clone()));

            let first_endpoint = client_endpoint(cert.cert_der.clone());
            let connection = first_endpoint
                .connect(local_addr, "localhost")
                .expect("connect old")
                .await
                .expect("old connection");
            assert_eq!(
                authenticate_status(&connection, "hy2-password")
                    .await
                    .expect("old auth status"),
                233
            );
            connection.close(0u32.into(), b"done");
            first_endpoint.wait_idle().await;

            let result = server.apply_user_delta(&CoreUserDelta {
                added: vec![user_b()],
                deleted: vec![user().uuid],
                ..CoreUserDelta::default()
            });

            assert_eq!(result.added, 1);
            assert_eq!(result.deleted, 1);
            assert_eq!(result.active_users, 1);

            let rejected_endpoint = client_endpoint(cert.cert_der.clone());
            let rejected = rejected_endpoint
                .connect(local_addr, "localhost")
                .expect("connect rejected")
                .await
                .expect("rejected connection");
            assert!(!matches!(
                authenticate_status(&rejected, "hy2-password").await,
                Ok(233)
            ));
            rejected.close(0u32.into(), b"done");
            rejected_endpoint.wait_idle().await;

            let accepted_endpoint = client_endpoint(cert.cert_der.clone());
            let accepted = accepted_endpoint
                .connect(local_addr, "localhost")
                .expect("connect accepted")
                .await
                .expect("accepted connection");
            assert_eq!(
                authenticate_status(&accepted, "secret-b")
                    .await
                    .expect("new auth status"),
                233
            );
            assert_eq!(
                proxy_tcp_once(accepted.clone(), echo_addr, b"z").await,
                b"z"
            );
            accepted.close(0u32.into(), b"done");
            accepted_endpoint.wait_idle().await;

            stop.store(true, Ordering::SeqCst);
            server_task.await.expect("server task");
            echo_task.await.expect("echo task");
        });
    }

    #[test]
    fn deleting_hysteria2_user_closes_existing_connection_and_reports_tail() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let cert = test_cert("delete-existing-connection");
            let echo = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("echo bind");
            let echo_addr = echo.local_addr().expect("echo addr");
            let echo_task = tokio::spawn(async move {
                let (mut stream, _) = echo.accept().await.expect("echo accept");
                let mut byte = [0u8; 1];
                stream.read_exact(&mut byte).await.expect("echo read");
                stream.write_all(&byte).await.expect("echo write");
            });
            let server = server(&cert, "127.0.0.1:0".parse().expect("addr"));
            let endpoint = server.bind().expect("hy2 bind");
            let local_addr = endpoint.local_addr().expect("local addr");
            let stop = Arc::new(AtomicBool::new(false));
            let server_task = tokio::spawn(server.clone().run(endpoint, stop.clone()));

            let client_endpoint = client_endpoint(cert.cert_der.clone());
            let connection = client_endpoint
                .connect(local_addr, "localhost")
                .expect("connect")
                .await
                .expect("connection");
            assert_eq!(
                authenticate_status(&connection, "hy2-password")
                    .await
                    .expect("auth status"),
                233
            );
            assert_eq!(
                proxy_tcp_once(connection.clone(), echo_addr, b"x").await,
                b"x"
            );

            let result = server.apply_user_delta(&CoreUserDelta {
                deleted: vec![user().uuid],
                ..CoreUserDelta::default()
            });
            assert_eq!(result.deleted, 1);
            tokio::time::timeout(Duration::from_secs(2), connection.closed())
                .await
                .expect("deleted HY2 user connection should be closed");

            let records = server.drain_traffic(1);
            assert_eq!(records.len(), 1);
            assert_eq!(records[0].node_tag, "panel|hysteria|1");
            assert_eq!(records[0].user_uuid, user().uuid);
            assert_eq!(records[0].user_id, Some(1));
            assert_eq!(records[0].upload, 1);
            assert_eq!(records[0].download, 1);

            connection.close(0u32.into(), b"done");
            client_endpoint.wait_idle().await;
            stop.store(true, Ordering::SeqCst);
            server_task.await.expect("server task");
            echo_task.await.expect("echo task");
        });
    }

    async fn authenticate(connection: &quinn::Connection) {
        let (udp, _) = authenticate_with_rx(connection, "0").await;
        assert_eq!(udp.as_deref(), Some("true"));
    }

    async fn authenticate_proxy_connection(connection: &quinn::Connection) {
        let quic = h3_quinn::Connection::new(connection.clone());
        let (mut h3_connection, mut send_request) = h3::client::new(quic).await.expect("h3 client");
        let (authenticated, stop_driver) = tokio::sync::oneshot::channel::<()>();
        let driver = tokio::spawn(async move {
            tokio::select! {
                _ = poll_fn(|cx| h3_connection.poll_close(cx)) => {}
                _ = stop_driver => {
                    std::mem::forget(h3_connection);
                }
            }
        });
        let request = http::Request::builder()
            .method(http::Method::POST)
            .uri("https://hysteria/auth")
            .header("Hysteria-Auth", "hy2-password")
            .header("Hysteria-CC-RX", "0")
            .body(())
            .expect("auth request");
        let mut stream = send_request
            .send_request(request)
            .await
            .expect("send auth request");
        stream.finish().await.expect("finish auth request");
        let response = stream.recv_response().await.expect("auth response");
        assert_eq!(response.status().as_u16(), 233);
        std::mem::forget(send_request);
        let _ = authenticated.send(());
        driver.await.expect("h3 driver");
    }

    async fn authenticate_status(
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

    async fn authenticate_with_rx(
        connection: &quinn::Connection,
        client_rx: &str,
    ) -> (Option<String>, Option<String>) {
        let quic = h3_quinn::Connection::new(connection.clone());
        let (mut h3_connection, mut send_request) = h3::client::new(quic).await.expect("h3 client");
        let driver = tokio::spawn(async move {
            let _ = poll_fn(|cx| h3_connection.poll_close(cx)).await;
        });
        let request = http::Request::builder()
            .method(http::Method::POST)
            .uri("https://hysteria/auth")
            .header("Hysteria-Auth", "hy2-password")
            .header("Hysteria-CC-RX", client_rx)
            .body(())
            .expect("auth request");
        let mut stream = send_request
            .send_request(request)
            .await
            .expect("send auth request");
        stream.finish().await.expect("finish auth request");
        let response = stream.recv_response().await.expect("auth response");
        assert_eq!(response.status().as_u16(), 233);
        let udp = response
            .headers()
            .get("Hysteria-UDP")
            .and_then(|value| value.to_str().ok())
            .map(ToString::to_string);
        let cc_rx = response
            .headers()
            .get("Hysteria-CC-RX")
            .and_then(|value| value.to_str().ok())
            .map(ToString::to_string);
        drop(send_request);
        driver.abort();
        (udp, cc_rx)
    }

    async fn proxy_tcp_once(
        connection: quinn::Connection,
        echo_addr: SocketAddr,
        payload: &'static [u8],
    ) -> Vec<u8> {
        let (mut send, mut recv) = connection.open_bi().await.expect("connect stream");
        send.write_all(&tcp_request(echo_addr))
            .await
            .expect("tcp request");
        let mut status = [0u8; 1];
        recv.read_exact(&mut status).await.expect("response status");
        assert_eq!(status[0], RESPONSE_OK);
        assert_eq!(read_varint(&mut recv).await.expect("message len"), 0);
        assert_eq!(read_varint(&mut recv).await.expect("padding len"), 0);

        send.write_all(payload).await.expect("payload");
        send.finish().expect("finish payload");
        let mut echoed = vec![0u8; payload.len()];
        recv.read_exact(&mut echoed).await.expect("echoed payload");
        echoed
    }

    fn tcp_request(addr: SocketAddr) -> Vec<u8> {
        let address = format_socket_addr(&addr);
        let mut request = Vec::new();
        request.extend_from_slice(&encode_varint(address.len() as u64).expect("addr len"));
        request.extend_from_slice(address.as_bytes());
        request.extend_from_slice(&encode_varint(0).expect("padding len"));
        request
    }

    fn tcp_request_with_frame(addr: SocketAddr) -> Vec<u8> {
        let mut request = encode_varint(TCP_REQUEST_ID).expect("request id");
        request.extend_from_slice(&tcp_request(addr));
        request
    }

    fn udp_request(session_id: u32, packet_id: u16, addr: SocketAddr, payload: &[u8]) -> Vec<u8> {
        encode_udp_datagram(
            session_id,
            packet_id,
            0,
            1,
            &format_socket_addr(&addr),
            payload,
        )
        .expect("udp datagram")
    }

    #[test]
    fn parses_target_addresses() {
        assert_eq!(
            parse_target_address("example.com:443").unwrap(),
            SocksTarget {
                host: "example.com".to_string(),
                port: 443
            }
        );
        assert_eq!(
            parse_target_address("[::1]:443").unwrap(),
            SocksTarget {
                host: "::1".to_string(),
                port: 443
            }
        );
    }

    #[test]
    fn encodes_quic_varints() {
        assert_eq!(encode_varint(0x3f).unwrap(), vec![0x3f]);
        assert_eq!(encode_varint(0x401).unwrap(), vec![0x44, 0x01]);
    }

    #[test]
    fn parses_hysteria2_udp_datagrams() {
        let address = "[::1]:53";
        let encoded = encode_udp_datagram(7, 11, 0, 1, address, b"dns").unwrap();
        let parsed = parse_udp_datagram(&encoded).unwrap();

        assert_eq!(encoded[8], address.len() as u8);
        assert_eq!(&encoded[9 + address.len()..], b"dns");
        assert_eq!(parsed.session_id, 7);
        assert_eq!(parsed.packet_id, 11);
        assert_eq!(parsed.fragment_id, 0);
        assert_eq!(parsed.fragment_count, 1);
        assert_eq!(
            parsed.target,
            SocksTarget {
                host: "::1".to_string(),
                port: 53
            }
        );
        assert_eq!(parsed.data, b"dns");
    }

    #[test]
    fn reassembles_hysteria2_udp_fragments() {
        let mut fragments = UdpFragmentStore::default();
        let first =
            parse_udp_datagram(&encode_udp_datagram(7, 12, 0, 2, "127.0.0.1:53", b"he").unwrap())
                .unwrap();
        let second =
            parse_udp_datagram(&encode_udp_datagram(7, 12, 1, 2, "127.0.0.1:53", b"llo").unwrap())
                .unwrap();

        assert!(fragments.push_with_now(first, Some(100)).unwrap().is_none());
        let message = fragments
            .push_with_now(second, Some(101))
            .unwrap()
            .expect("complete fragmented message");

        assert_eq!(message.session_id, 7);
        assert_eq!(message.packet_id, 12);
        assert_eq!(message.fragment_id, 0);
        assert_eq!(message.fragment_count, 1);
        assert_eq!(message.data, b"hello");
    }

    #[test]
    fn expires_stale_hysteria2_udp_fragments() {
        let mut fragments = UdpFragmentStore::default();
        let first =
            parse_udp_datagram(&encode_udp_datagram(7, 12, 0, 2, "127.0.0.1:53", b"he").unwrap())
                .unwrap();

        assert!(fragments.push_with_now(first, Some(100)).unwrap().is_none());
        assert_eq!(
            fragments.prune_expired(100 + UDP_FRAGMENT_IDLE_TIMEOUT_MS + 1),
            1
        );
        assert!(fragments.fragments.is_empty());
    }

    #[test]
    fn rejects_oversized_hysteria2_udp_fragment_group() {
        let mut fragments = UdpFragmentStore::default();
        let first = UdpDatagram {
            session_id: 7,
            packet_id: 12,
            fragment_id: 0,
            fragment_count: 2,
            target: SocksTarget {
                host: "127.0.0.1".to_string(),
                port: 53,
            },
            data: vec![0u8; UDP_MAX_REASSEMBLED_BYTES],
        };
        let second = UdpDatagram {
            fragment_id: 1,
            data: vec![0u8; 1],
            ..first.clone()
        };

        assert!(fragments.push_with_now(first, Some(100)).unwrap().is_none());
        let error = fragments
            .push_with_now(second, Some(101))
            .expect_err("oversized fragment group should fail");
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert!(fragments.fragments.is_empty());
    }

    #[test]
    fn advertises_hysteria2_bandwidth_negotiation_headers() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let cert = test_cert("bandwidth");
            let server =
                server_with_bandwidth(&cert, "127.0.0.1:0".parse().unwrap(), 100, 80, false);
            let endpoint = server.bind().expect("hy2 bind");
            let server_addr = endpoint.local_addr().expect("server addr");
            let stop = Arc::new(AtomicBool::new(false));
            let server_task = tokio::spawn(server.clone().run(endpoint, stop.clone()));

            let client_endpoint = client_endpoint(cert.cert_der.clone());
            let connection = client_endpoint
                .connect(server_addr, "localhost")
                .expect("connect")
                .await
                .expect("connection");
            let (_, cc_rx) = authenticate_with_rx(&connection, "999999999").await;
            let expected = mbps_to_bytes_per_second(80).unwrap().to_string();

            assert_eq!(cc_rx.as_deref(), Some(expected.as_str()));

            connection.close(0u32.into(), b"done");
            stop.store(true, Ordering::SeqCst);
            server_task.await.expect("server task");
        });
    }

    #[test]
    fn ignore_client_bandwidth_advertises_auto_cc_rx() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let cert = test_cert("ignore-bandwidth");
            let server = server_with_bandwidth(&cert, "127.0.0.1:0".parse().unwrap(), 0, 0, true);
            let endpoint = server.bind().expect("hy2 bind");
            let server_addr = endpoint.local_addr().expect("server addr");
            let stop = Arc::new(AtomicBool::new(false));
            let server_task = tokio::spawn(server.clone().run(endpoint, stop.clone()));

            let client_endpoint = client_endpoint(cert.cert_der.clone());
            let connection = client_endpoint
                .connect(server_addr, "localhost")
                .expect("connect")
                .await
                .expect("connection");
            let (_, cc_rx) = authenticate_with_rx(&connection, "999999999").await;

            assert_eq!(cc_rx.as_deref(), Some("auto"));

            connection.close(0u32.into(), b"done");
            stop.store(true, Ordering::SeqCst);
            server_task.await.expect("server task");
        });
    }

    #[test]
    fn proxies_hysteria2_tcp_and_records_user_traffic() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let cert = test_cert("tcp");
            let echo = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("echo bind");
            let echo_addr = echo.local_addr().expect("echo addr");
            let echo_task = tokio::spawn(async move {
                let (mut stream, _) = echo.accept().await.expect("echo accept");
                let mut bytes = [0u8; 4];
                stream.read_exact(&mut bytes).await.expect("echo read");
                stream.write_all(&bytes).await.expect("echo write");
            });

            let server = server(&cert, "127.0.0.1:0".parse().unwrap());
            let endpoint = server.bind().expect("hy2 bind");
            let server_addr = endpoint.local_addr().expect("server addr");
            let stop = Arc::new(AtomicBool::new(false));
            let server_task = tokio::spawn(server.clone().run(endpoint, stop.clone()));

            let client_endpoint = client_endpoint(cert.cert_der.clone());
            let connection = client_endpoint
                .connect(server_addr, "localhost")
                .expect("connect")
                .await
                .expect("connection");
            authenticate(&connection).await;

            let (mut send, mut recv) = connection.open_bi().await.expect("connect stream");
            send.write_all(&tcp_request_with_frame(echo_addr))
                .await
                .expect("tcp request");
            let mut status = [0u8; 1];
            recv.read_exact(&mut status).await.expect("response status");
            assert_eq!(status[0], RESPONSE_OK);
            assert_eq!(read_varint(&mut recv).await.expect("message len"), 0);
            assert_eq!(read_varint(&mut recv).await.expect("padding len"), 0);

            send.write_all(b"ping").await.expect("payload");
            let mut echoed = [0u8; 4];
            recv.read_exact(&mut echoed).await.expect("echoed payload");
            assert_eq!(&echoed, b"ping");

            send.finish().expect("finish payload");
            tokio::time::sleep(Duration::from_millis(50)).await;
            let records = server.drain_traffic(1);
            assert_eq!(records.len(), 1);
            assert_eq!(records[0].node_tag, "panel|hysteria|1");
            assert_eq!(records[0].user_uuid, "hy2-password");
            assert_eq!(records[0].user_id, Some(1));
            assert_eq!(records[0].upload, 4);
            assert_eq!(records[0].download, 4);

            connection.close(0u32.into(), b"done");
            echo_task.await.expect("echo task");

            tokio::time::sleep(Duration::from_millis(50)).await;
            let records = server.drain_traffic(1);
            assert!(records.is_empty());

            stop.store(true, Ordering::SeqCst);
            server_task.await.expect("server task");
        });
    }

    #[test]
    fn proxies_multiple_hysteria2_tcp_streams_on_one_connection() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let cert = test_cert("tcp-mux");
            let echo = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("echo bind");
            let echo_addr = echo.local_addr().expect("echo addr");
            let echo_task = tokio::spawn(async move {
                let mut handlers = Vec::new();
                for _ in 0..2 {
                    let (mut stream, _) = echo.accept().await.expect("echo accept");
                    handlers.push(tokio::spawn(async move {
                        let mut bytes = [0u8; 4];
                        stream.read_exact(&mut bytes).await.expect("echo read");
                        stream.write_all(&bytes).await.expect("echo write");
                    }));
                }
                for handler in handlers {
                    handler.await.expect("echo handler");
                }
            });

            let server = server(&cert, "127.0.0.1:0".parse().unwrap());
            let endpoint = server.bind().expect("hy2 bind");
            let server_addr = endpoint.local_addr().expect("server addr");
            let stop = Arc::new(AtomicBool::new(false));
            let server_task = tokio::spawn(server.clone().run(endpoint, stop.clone()));

            let client_endpoint = client_endpoint(cert.cert_der.clone());
            let connection = client_endpoint
                .connect(server_addr, "localhost")
                .expect("connect")
                .await
                .expect("connection");
            authenticate_proxy_connection(&connection).await;

            let first = proxy_tcp_once(connection.clone(), echo_addr, b"ping");
            let second = proxy_tcp_once(connection.clone(), echo_addr, b"pong");
            let (first, second) = tokio::join!(first, second);

            assert_eq!(&first, b"ping");
            assert_eq!(&second, b"pong");

            connection.close(0u32.into(), b"done");
            echo_task.await.expect("echo task");

            tokio::time::sleep(Duration::from_millis(50)).await;
            let records = server.drain_traffic(1);
            assert_eq!(records.len(), 1);
            assert_eq!(records[0].upload, 8);
            assert_eq!(records[0].download, 8);

            stop.store(true, Ordering::SeqCst);
            server_task.await.expect("server task");
        });
    }

    #[test]
    fn proxies_hysteria2_udp_and_records_user_traffic() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let cert = test_cert("udp");
            let echo = tokio::net::UdpSocket::bind("127.0.0.1:0")
                .await
                .expect("echo bind");
            let echo_addr = echo.local_addr().expect("echo addr");
            let echo_task = tokio::spawn(async move {
                let mut buffer = [0u8; 16];
                let (read, peer) = echo.recv_from(&mut buffer).await.expect("echo recv");
                echo.send_to(&buffer[..read], peer)
                    .await
                    .expect("echo send");
            });

            let server = server(&cert, "127.0.0.1:0".parse().unwrap());
            let endpoint = server.bind().expect("hy2 bind");
            let server_addr = endpoint.local_addr().expect("server addr");
            let stop = Arc::new(AtomicBool::new(false));
            let server_task = tokio::spawn(server.clone().run(endpoint, stop.clone()));

            let client_endpoint = client_endpoint(cert.cert_der.clone());
            let connection = client_endpoint
                .connect(server_addr, "localhost")
                .expect("connect")
                .await
                .expect("connection");
            authenticate(&connection).await;

            connection
                .send_datagram_wait(Bytes::from(udp_request(9, 1, echo_addr, b"pong")))
                .await
                .expect("send udp datagram");
            let response = tokio::time::timeout(Duration::from_secs(3), connection.read_datagram())
                .await
                .expect("udp response timeout")
                .expect("udp response");
            let response = parse_udp_datagram(&response).expect("response datagram");

            assert_eq!(response.session_id, 9);
            assert_eq!(response.fragment_id, 0);
            assert_eq!(response.fragment_count, 1);
            assert_eq!(response.data, b"pong");
            assert_eq!(response.target.host, "127.0.0.1");
            assert_eq!(response.target.port, echo_addr.port());

            connection.close(0u32.into(), b"done");
            echo_task.await.expect("echo task");

            tokio::time::sleep(Duration::from_millis(50)).await;
            let records = server.drain_traffic(1);
            assert_eq!(records.len(), 1);
            assert_eq!(records[0].node_tag, "panel|hysteria|1");
            assert_eq!(records[0].user_uuid, "hy2-password");
            assert_eq!(records[0].user_id, Some(1));
            assert_eq!(records[0].upload, 4);
            assert_eq!(records[0].download, 4);

            stop.store(true, Ordering::SeqCst);
            server_task.await.expect("server task");
        });
    }

    #[test]
    fn hysteria2_udp_session_batches_traffic_and_flushes_tail() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let traffic = TrafficRegistry::shared();
            let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("udp bind"));
            let session = Arc::new(UdpRelaySession {
                socket,
                target: SocksTarget {
                    host: "127.0.0.1".to_string(),
                    port: 53,
                },
                target_addr: "127.0.0.1:53".parse().expect("target addr"),
                _permit: UdpSessionPermit::try_acquire().expect("udp session permit"),
                next_packet_id: AtomicU16::new(0),
                traffic: traffic.clone(),
                node_tag: "node-a".to_string(),
                user_uuid: "user-a".to_string(),
                user_id: 42,
                client_ip: "127.0.0.2".parse().expect("client ip"),
                closed: AtomicBool::new(false),
                last_active_ms: AtomicU64::new(now_millis()),
                pending_upload: AtomicU64::new(0),
                pending_download: AtomicU64::new(0),
            });

            session.add_upload(UDP_TRAFFIC_FLUSH_BYTES - 1);
            assert!(traffic.drain_all().is_empty());

            session.add_upload(1);
            let records = traffic.drain_all();
            assert_eq!(records.len(), 1);
            assert_eq!(records[0].node_tag, "node-a");
            assert_eq!(records[0].user_uuid, "user-a");
            assert_eq!(records[0].user_id, Some(42));
            assert_eq!(records[0].upload, UDP_TRAFFIC_FLUSH_BYTES);
            assert_eq!(records[0].download, 0);
            assert_eq!(records[0].online_ips, vec!["127.0.0.2"]);

            session.add_download(7);
            assert!(traffic.drain_all().is_empty());

            drop(session);
            let records = traffic.drain_all();
            assert_eq!(records.len(), 1);
            assert_eq!(records[0].upload, 0);
            assert_eq!(records[0].download, 7);
            assert_eq!(records[0].user_id, Some(42));
        });
    }

    #[test]
    fn prunes_idle_hysteria2_udp_sessions_and_flushes_tail() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let traffic = TrafficRegistry::shared();
            let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("udp bind"));
            let session = Arc::new(UdpRelaySession {
                socket,
                target: SocksTarget {
                    host: "127.0.0.1".to_string(),
                    port: 53,
                },
                target_addr: "127.0.0.1:53".parse().expect("target addr"),
                _permit: UdpSessionPermit::try_acquire().expect("udp session permit"),
                next_packet_id: AtomicU16::new(0),
                traffic: traffic.clone(),
                node_tag: "node-a".to_string(),
                user_uuid: "user-a".to_string(),
                user_id: 42,
                client_ip: "127.0.0.2".parse().expect("client ip"),
                closed: AtomicBool::new(false),
                last_active_ms: AtomicU64::new(
                    now_millis().saturating_sub(UDP_SESSION_IDLE_TIMEOUT_MS + 1),
                ),
                pending_upload: AtomicU64::new(7),
                pending_download: AtomicU64::new(11),
            });
            let sessions = Arc::new(Mutex::new(HashMap::from([(9, session.clone())])));

            assert_eq!(prune_udp_sessions(&sessions, now_millis()), 1);
            assert!(sessions.lock().expect("sessions lock").is_empty());
            assert!(session.is_closed());
            let records = traffic.drain_all();
            assert_eq!(records.len(), 1);
            assert_eq!(records[0].upload, 7);
            assert_eq!(records[0].download, 11);
            assert_eq!(records[0].user_id, Some(42));
        });
    }

    #[test]
    fn hysteria2_udp_sessions_evict_oldest_when_per_connection_limit_is_full() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let traffic = TrafficRegistry::shared();
            let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("udp bind"));
            let now = now_millis();
            let mut entries = HashMap::new();
            for id in 0..UDP_MAX_SESSIONS_PER_CONNECTION as u32 {
                entries.insert(
                    id,
                    Arc::new(UdpRelaySession {
                        socket: socket.clone(),
                        target: SocksTarget {
                            host: "127.0.0.1".to_string(),
                            port: 53,
                        },
                        target_addr: "127.0.0.1:53".parse().expect("target addr"),
                        _permit: UdpSessionPermit::try_acquire().expect("udp session permit"),
                        next_packet_id: AtomicU16::new(0),
                        traffic: traffic.clone(),
                        node_tag: "node-a".to_string(),
                        user_uuid: "user-a".to_string(),
                        user_id: 42,
                        client_ip: "127.0.0.2".parse().expect("client ip"),
                        closed: AtomicBool::new(false),
                        last_active_ms: AtomicU64::new(now.saturating_add(id as u64)),
                        pending_upload: AtomicU64::new(0),
                        pending_download: AtomicU64::new(0),
                    }),
                );
            }
            let oldest = entries.get(&0).expect("oldest session").clone();
            let sessions = Arc::new(Mutex::new(entries));

            make_room_for_udp_session(&sessions);

            let sessions = sessions.lock().expect("sessions lock");
            assert_eq!(sessions.len(), UDP_MAX_SESSIONS_PER_CONNECTION - 1);
            assert!(!sessions.contains_key(&0));
            assert!(oldest.is_closed());
        });
    }

    #[test]
    fn hysteria2_udp_session_limit_scales_with_machine_resources() {
        assert_eq!(
            super::hy2_udp_session_limit_from_resources(1, Some(64_000), Some(100_000)),
            96
        );
        assert_eq!(
            super::hy2_udp_session_limit_from_resources(4, Some(64_000), Some(100_000)),
            384
        );
        assert_eq!(
            super::hy2_udp_session_limit_from_resources(64, Some(64_000), Some(100_000)),
            4096
        );
        assert_eq!(
            super::hy2_udp_session_limit_from_resources(16, Some(1024), Some(100_000)),
            128
        );
        assert_eq!(
            super::hy2_udp_session_limit_from_resources(16, Some(64_000), Some(1500)),
            476
        );
    }

    #[test]
    fn hysteria2_preauth_limit_scales_below_connection_limit() {
        assert_eq!(super::hy2_preauth_connection_limit(64), 32);
        assert_eq!(super::hy2_preauth_connection_limit(195), 97);
        assert_eq!(super::hy2_preauth_connection_limit(978), 489);
        assert_eq!(super::hy2_preauth_connection_limit(1024), 512);
        assert_eq!(super::hy2_preauth_connection_limit(3914), 1957);
        assert_eq!(super::hy2_preauth_connection_limit(7934), 3967);
    }

    #[test]
    fn hysteria2_log_filter_treats_client_closes_as_expected() {
        for message in [
            "Stopped(0)",
            "LocallyClosed",
            "ApplicationClose(0x0)",
            "ConnectionClosed(ConnectionClose { error_code: APPLICATION_ERROR, frame_type: None, reason: b\"\" })",
            "hysteria2 connection closed before authentication",
            "Reset(268)",
            "sending stopped by peer: error 0",
            "Local { error: Application { code: H3_STREAM_CREATION_ERROR, reason: \"got two control streams\" } }",
        ] {
            let error = io::Error::new(io::ErrorKind::Other, message);
            assert!(
                is_expected_hysteria2_close(&error),
                "message should be treated as expected close: {message}"
            );
        }

        let timeout = io::Error::new(
            io::ErrorKind::TimedOut,
            "tcp connect timed out target=example.com:443",
        );
        assert!(!is_expected_hysteria2_close(&timeout));
        assert!(is_hysteria2_timeout(&timeout));

        let quinn_timeout = io::Error::new(io::ErrorKind::Other, "TimedOut");
        assert!(is_hysteria2_timeout(&quinn_timeout));

        assert_eq!(
            classify_hysteria2_error(&io::Error::new(
                io::ErrorKind::PermissionDenied,
                "invalid hysteria2 authentication",
            )),
            Hysteria2ErrorClass::InvalidAuth
        );
        assert_eq!(
            classify_hysteria2_error(&io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid hysteria2 tcp request id",
            )),
            Hysteria2ErrorClass::InvalidRequest
        );
        assert_eq!(
            classify_hysteria2_error(&io::Error::new(
                io::ErrorKind::InvalidData,
                "hysteria2 target missing port",
            )),
            Hysteria2ErrorClass::InvalidRequest
        );
        assert_eq!(
            classify_hysteria2_error(&quinn_timeout),
            Hysteria2ErrorClass::Timeout
        );
        assert_eq!(
            classify_hysteria2_error(&io::Error::new(
                io::ErrorKind::Other,
                "TransportError(Error { code: PROTOCOL_VIOLATION, frame: None, reason: \"authentication failed\" })",
            )),
            Hysteria2ErrorClass::InvalidAuth
        );
        assert_eq!(
            classify_hysteria2_error(&io::Error::new(
                io::ErrorKind::Other,
                "tcp connect failed target=example.com:443 error=dns response indicates failure",
            )),
            Hysteria2ErrorClass::TargetFailure
        );
        assert_eq!(
            classify_hysteria2_error(&io::Error::new(
                io::ErrorKind::ConnectionRefused,
                "tcp connect failed target=example.com:443 error=Connection refused (os error 111)",
            )),
            Hysteria2ErrorClass::TargetFailure
        );
        assert_eq!(
            classify_hysteria2_error(&io::Error::new(io::ErrorKind::Other, "connection lost")),
            Hysteria2ErrorClass::Transport
        );
        assert_eq!(
            classify_hysteria2_error(&io::Error::new(io::ErrorKind::Other, "Timeout")),
            Hysteria2ErrorClass::Timeout
        );
        assert_eq!(
            classify_hysteria2_error(&io::Error::new(io::ErrorKind::BrokenPipe, "Broken pipe")),
            Hysteria2ErrorClass::ExpectedClose
        );
        assert_eq!(
            classify_hysteria2_error(&io::Error::new(io::ErrorKind::Other, "FinishedEarly(0)")),
            Hysteria2ErrorClass::ExpectedClose
        );
        assert_eq!(
            classify_hysteria2_error(&io::Error::new(io::ErrorKind::Other, "Reset(268)")),
            Hysteria2ErrorClass::ExpectedClose
        );
    }

    #[test]
    fn hysteria2_error_log_decision_reports_suppressed_count_for_single_summary_line() {
        let mut states = HashMap::new();

        assert_eq!(
            super::hysteria2_error_log_decision_at(
                &mut states,
                "connection",
                Hysteria2ErrorClass::Timeout,
                1_000,
            ),
            Some(0)
        );
        assert_eq!(
            super::hysteria2_error_log_decision_at(
                &mut states,
                "connection",
                Hysteria2ErrorClass::Timeout,
                1_001,
            ),
            None
        );
        assert_eq!(
            super::hysteria2_error_log_decision_at(
                &mut states,
                "connection",
                Hysteria2ErrorClass::Timeout,
                61_000,
            ),
            Some(1)
        );
    }

    #[test]
    fn hysteria2_route_outbound_errors_include_safe_context() {
        let outbound = OutboundConfig {
            tag: "tw".to_string(),
            protocol: "socks".to_string(),
            method: None,
            alter_id: None,
            address: Some("dns.huhu.icu".to_string()),
            port: Some(22223),
            username: Some("secret-user".to_string()),
            password: Some("secret-pass".to_string()),
            tls: None,
            transport: None,
        };
        let target = SocksTarget {
            host: "chatgpt.com".to_string(),
            port: 443,
        };
        let error = super::annotate_hysteria2_route_outbound_error(
            "panel|hy2|1",
            &outbound,
            &target,
            Duration::from_millis(1234),
            io::Error::new(io::ErrorKind::TimedOut, "connection timed out"),
        );
        let text = error.to_string();

        assert!(text.contains("route outbound failed"));
        assert!(text.contains("node_tag=panel|hy2|1"));
        assert!(text.contains("outbound=tw"));
        assert!(text.contains("protocol=socks"));
        assert!(text.contains("endpoint=dns.huhu.icu:22223"));
        assert!(text.contains("target=chatgpt.com:443"));
        assert!(text.contains("elapsed_ms=1234"));
        assert!(!text.contains("secret-user"));
        assert!(!text.contains("secret-pass"));
        assert_eq!(
            classify_hysteria2_error(&error),
            Hysteria2ErrorClass::Timeout
        );
    }

    #[test]
    fn hysteria2_invalid_auth_backoff_blocks_repeated_bad_auth() {
        let backoff = Hysteria2AuthBackoff::default();
        let ip: IpAddr = "203.0.113.8".parse().expect("ip");
        let start = Instant::now();

        for offset in 0..HY2_INVALID_AUTH_BACKOFF_THRESHOLD - 1 {
            backoff.record_invalid_at(ip, start + Duration::from_millis(u64::from(offset)));
            assert!(
                !backoff.is_blocked_at(ip, start + Duration::from_millis(u64::from(offset) + 1)),
                "backoff should not trigger before threshold"
            );
        }

        backoff.record_invalid_at(ip, start + Duration::from_secs(1));
        assert!(backoff.is_blocked_at(ip, start + Duration::from_secs(2)));
        assert!(!backoff.is_blocked_at(
            ip,
            start + Duration::from_secs(2) + HY2_INVALID_AUTH_BACKOFF_DURATION
        ));
    }

    #[test]
    fn hysteria2_invalid_auth_backoff_clears_after_success() {
        let backoff = Hysteria2AuthBackoff::default();
        let ip: IpAddr = "203.0.113.9".parse().expect("ip");
        let start = Instant::now();

        for offset in 0..HY2_INVALID_AUTH_BACKOFF_THRESHOLD {
            backoff.record_invalid_at(ip, start + Duration::from_millis(u64::from(offset)));
        }
        assert!(backoff.is_blocked_at(ip, start + Duration::from_secs(2)));

        backoff.record_success(ip);
        assert!(!backoff.is_blocked_at(ip, start + Duration::from_secs(3)));
    }

    #[test]
    fn hysteria2_invalid_auth_backoff_caps_each_shard() {
        let backoff = Hysteria2AuthBackoff::default();
        let start = Instant::now();
        let shard = 0;
        let limit = backoff.max_entries_per_shard();
        let mut inserted = 0usize;

        'outer: for third in 0..=255u8 {
            for fourth in 0..=255u8 {
                let ip = IpAddr::from([198, 51, third, fourth]);
                if backoff.shard_index(ip) != shard {
                    continue;
                }
                backoff.record_invalid_at(ip, start);
                inserted += 1;
                if inserted >= limit + 8 {
                    break 'outer;
                }
            }
        }

        assert!(
            inserted >= limit + 8,
            "test did not find enough IPs for the selected shard"
        );
        let entries = backoff.shards[shard]
            .lock()
            .expect("hysteria2 auth backoff state poisoned");
        assert!(entries.len() <= limit);
    }

    #[test]
    fn hysteria2_auth_backoff_policy_ignores_timeouts() {
        assert!(should_record_hysteria2_auth_backoff(&io::Error::new(
            io::ErrorKind::PermissionDenied,
            "invalid hysteria2 authentication",
        )));
        assert!(!should_record_hysteria2_auth_backoff(&io::Error::new(
            io::ErrorKind::TimedOut,
            "hysteria2 handshake timed out",
        )));
        assert!(!should_record_hysteria2_auth_backoff(&io::Error::new(
            io::ErrorKind::TimedOut,
            "hysteria2 authentication timed out",
        )));
    }

    #[test]
    fn hysteria2_auth_timeout_default_is_not_rust_only_three_second_gate() {
        assert_eq!(DEFAULT_HY2_AUTH_TIMEOUT_SECS, 10);
    }
}
