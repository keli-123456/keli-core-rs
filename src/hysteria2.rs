use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use bytes::Bytes;
use quinn::crypto::rustls::QuicServerConfig;
use quinn::Runtime;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;

use crate::limits::{
    sync_user_limit_delta, BandwidthLimiter, UserBandwidthLimiters, UserSessionGuard,
    UserSessionTracker,
};
use crate::routing::{route_protocol_labels, RouteDecision, RouteMatcher};
use crate::salamander::SalamanderUdpSocket;
use crate::socks5::SocksTarget;
use crate::tls::server_config_from_files;
use crate::traffic::{SharedTrafficRegistry, TrafficRegistry};
use crate::user::{CoreUser, CoreUserDelta, CoreUserDeltaResult, UserStore};
use crate::{connect_tcp_outbound_tokio, send_udp_outbound_tokio};

const TCP_REQUEST_ID: u64 = 0x401;
const RESPONSE_OK: u8 = 0x00;
const RESPONSE_ERROR: u8 = 0x01;
const UDP_DATAGRAM_BUFFER_SIZE: usize = 1024 * 1024;
const UDP_PACKET_BUFFER_SIZE: usize = 64 * 1024;

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
    router: RouteMatcher,
    traffic: SharedTrafficRegistry,
    sessions: UserSessionTracker,
    bandwidth: UserBandwidthLimiters,
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
        let users =
            UserStore::from_keyed_users(&config.users, |user| user.credential().to_string());
        Self {
            router: RouteMatcher::new(config.routes.clone()),
            config,
            users,
            traffic,
            sessions,
            bandwidth,
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
        transport
            .datagram_receive_buffer_size(Some(UDP_DATAGRAM_BUFFER_SIZE))
            .datagram_send_buffer_size(UDP_DATAGRAM_BUFFER_SIZE);
        server_config.transport_config(Arc::new(transport));
        let Some(obfs) = self.config.obfs.as_ref() else {
            return quinn::Endpoint::server(server_config, self.config.listen);
        };
        if !obfs.kind.eq_ignore_ascii_case("salamander") {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "hysteria2 only supports salamander obfs",
            ));
        }

        let socket = std::net::UdpSocket::bind(self.config.listen)?;
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
                    let server = self.clone();
                    tokio::spawn(async move {
                        if let Err(error) = server.handle_incoming(incoming).await {
                            eprintln!("hysteria2 connection error: {error}");
                        }
                    });
                }
                _ = tokio::time::sleep(Duration::from_millis(20)) => {}
            }
        }
        endpoint.wait_idle().await;
    }

    pub fn drain_traffic(&self, minimum_bytes: u64) -> Vec<crate::traffic::TrafficDelta> {
        self.traffic.drain_minimum(minimum_bytes)
    }

    pub fn replace_users(&self, users: Vec<CoreUser>) {
        self.bandwidth.sync_users(&users);
        self.users
            .replace_keyed_users(users, |user| user.credential().to_string());
    }

    pub fn apply_user_delta(&self, delta: &CoreUserDelta) -> CoreUserDeltaResult {
        sync_delta_bandwidth(&self.bandwidth, &self.sessions, delta);
        self.users
            .apply_keyed_delta(delta, |user| user.credential().to_string())
    }

    fn user_for_auth(&self, auth: &str) -> Option<CoreUser> {
        self.users.get(auth)
    }

    async fn handle_incoming(&self, incoming: quinn::Incoming) -> io::Result<()> {
        let connection = incoming.await.map_err(io_other)?;
        let client_ip = connection.remote_address().ip();
        let auth = self.authenticate_http3(&connection).await?;
        let _session = self.acquire_user_session(&auth.user, Some(client_ip))?;
        let bandwidth = self.connection_limiters(
            self.bandwidth.limiter_for(Some(&auth.user)),
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
                                eprintln!("hysteria2 tcp stream error: {error}");
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
                send_h3_status(&mut stream, 404).await?;
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
        let request_id = read_varint(&mut recv).await?;
        if request_id != TCP_REQUEST_ID {
            write_tcp_response(&mut send, RESPONSE_ERROR, "unsupported request").await?;
            let _ = send.finish();
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid hysteria2 tcp request id",
            ));
        }

        let target = read_tcp_target(&mut recv).await?;
        let decision = self.router.decide_target(&target.host, target.port, "tcp");
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
                        return Err(error);
                    }
                    Err(error) => {
                        write_tcp_response(&mut send, RESPONSE_ERROR, "connect failed").await?;
                        let _ = send.finish();
                        return Err(error);
                    }
                }
            }
            RouteDecision::Outbound(outbound) => {
                match connect_tcp_outbound_tokio(outbound, &target, self.config.connect_timeout)
                    .await
                {
                    Ok(stream) => stream,
                    Err(error) => {
                        write_tcp_response(&mut send, RESPONSE_ERROR, "connect failed").await?;
                        let _ = send.finish();
                        return Err(error);
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
        loop {
            let revoke_watch = bandwidth.clone();
            let datagram = tokio::select! {
                datagram = connection.read_datagram() => match datagram {
                    Ok(datagram) => datagram,
                    Err(quinn::ConnectionError::ApplicationClosed { .. })
                    | Err(quinn::ConnectionError::LocallyClosed)
                    | Err(quinn::ConnectionError::ConnectionClosed(_)) => return Ok(()),
                    Err(error) => return Err(io_other(error)),
                },
                _ = revoke_watch.wait_revoked() => return Ok(()),
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
        let protocol_labels = route_protocol_labels("udp", &message.data);
        let decision =
            self.router
                .decide_target(&message.target.host, message.target.port, &protocol_labels);
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

        if let Some(outbound) = outbound {
            if !bandwidth.wait_upload(message.data.len()).await {
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
                    if !bandwidth.wait_download(response.len()).await {
                        return Ok(());
                    }
                    let address = format_socket_addr(&source);
                    let datagram = encode_udp_datagram(
                        message.session_id,
                        message.packet_id,
                        0,
                        1,
                        &address,
                        &response,
                    )?;
                    if let Some(max_size) = connection.max_datagram_size() {
                        if datagram.len() <= max_size {
                            connection
                                .send_datagram_wait(Bytes::from(datagram))
                                .await
                                .map_err(io_other)?;
                        }
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
                bandwidth.clone(),
                client_ip,
            )
            .await?;
        if !bandwidth.wait_upload(message.data.len()).await {
            return Ok(());
        }
        session.socket.send_to(&message.data, target_addr).await?;
        self.traffic.add_with_user_id(
            self.config.node_tag.clone(),
            user_uuid.to_string(),
            Some(user_id),
            message.data.len() as u64,
            0,
            Some(client_ip),
        );
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
        bandwidth: DirectionalLimiters,
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
            if session.target == *target {
                return Ok((session.clone(), session.target_addr));
            }
            let target_addr = resolve_udp_target(target, self.config.connect_timeout).await?;
            return Ok((session, target_addr));
        }

        let target_addr = resolve_udp_target(target, self.config.connect_timeout).await?;
        let socket = Arc::new(bind_udp_socket(target_addr.ip()).await?);
        let session = Arc::new(UdpRelaySession {
            socket,
            target: target.clone(),
            target_addr,
            next_packet_id: AtomicU16::new(0),
        });
        {
            let mut sessions = sessions
                .lock()
                .expect("hysteria2 udp session lock poisoned");
            if let Some(existing) = sessions.get(&session_id) {
                if existing.target == *target {
                    return Ok((existing.clone(), existing.target_addr));
                }
                return Ok((existing.clone(), target_addr));
            }
            sessions.insert(session_id, session.clone());
        }

        let receiver = session.clone();
        let connection = connection.clone();
        let node_tag = self.config.node_tag.clone();
        let user_uuid = user_uuid.to_string();
        let traffic = self.traffic.clone();
        tokio::spawn(async move {
            let _ = receive_udp_replies(
                session_id, receiver, connection, node_tag, user_uuid, user_id, traffic, bandwidth,
                client_ip,
            )
            .await;
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
        user_limiter: Option<Arc<BandwidthLimiter>>,
        client_rx_bps: Option<u64>,
    ) -> DirectionalLimiters {
        let mut upload = Vec::new();
        let mut download = Vec::new();
        if let Some(limiter) = user_limiter {
            upload.push(limiter.clone());
            download.push(limiter);
        }
        if !self.config.ignore_client_bandwidth {
            if let Some(server_down_bps) = mbps_to_bytes_per_second(self.config.down_mbps) {
                upload.push(Arc::new(BandwidthLimiter::new(server_down_bps)));
            }
            let server_up_bps = mbps_to_bytes_per_second(self.config.up_mbps);
            if let Some(download_bps) = min_nonzero(server_up_bps, client_rx_bps) {
                download.push(Arc::new(BandwidthLimiter::new(download_bps)));
            }
        }
        DirectionalLimiters { upload, download }
    }

    fn acquire_user_session(
        &self,
        user: &CoreUser,
        client_ip: Option<IpAddr>,
    ) -> io::Result<Option<UserSessionGuard>> {
        self.sessions
            .try_acquire_for_ip(Some(user), client_ip)
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
    user: CoreUser,
    client_rx_bps: Option<u64>,
}

#[derive(Clone, Debug, Default)]
struct DirectionalLimiters {
    upload: Vec<Arc<BandwidthLimiter>>,
    download: Vec<Arc<BandwidthLimiter>>,
}

impl DirectionalLimiters {
    fn is_empty(&self) -> bool {
        self.upload.is_empty() && self.download.is_empty()
    }

    fn is_revoked(&self) -> bool {
        self.upload
            .iter()
            .chain(self.download.iter())
            .any(|limiter| limiter.is_revoked())
    }

    async fn wait_revoked(&self) {
        if self.is_empty() {
            std::future::pending::<()>().await;
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
    next_packet_id: AtomicU16,
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
}

impl UdpFragmentStore {
    fn push(&mut self, message: UdpDatagram) -> io::Result<Option<UdpDatagram>> {
        if message.fragment_count == 0 || message.fragment_id >= message.fragment_count {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid hysteria2 udp fragment index",
            ));
        }
        if message.is_single_fragment() {
            return Ok(Some(message));
        }

        let key = (message.session_id, message.packet_id);
        let count = message.fragment_count as usize;
        let index = message.fragment_id as usize;
        let set = self.fragments.entry(key).or_insert_with(|| UdpFragmentSet {
            target: message.target.clone(),
            parts: vec![None; count],
        });
        if set.parts.len() != count || set.target != message.target {
            self.fragments.remove(&key);
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "mismatched hysteria2 udp fragment group",
            ));
        }
        set.parts[index] = Some(message.data);
        if !set.parts.iter().all(Option::is_some) {
            return Ok(None);
        }

        let set = self.fragments.remove(&key).expect("fragment set exists");
        let mut data = Vec::new();
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
    node_tag: String,
    user_uuid: String,
    user_id: u64,
    traffic: SharedTrafficRegistry,
    bandwidth: DirectionalLimiters,
    client_ip: IpAddr,
) -> io::Result<()> {
    let mut buffer = vec![0u8; UDP_PACKET_BUFFER_SIZE];
    loop {
        let revoke_watch = bandwidth.clone();
        let (read, peer) = tokio::select! {
            result = session.socket.recv_from(&mut buffer) => result?,
            _ = connection.closed() => return Ok(()),
            _ = revoke_watch.wait_revoked() => return Ok(()),
        };
        if !bandwidth.wait_download(read).await {
            return Ok(());
        }
        let packet_id = session.next_packet_id.fetch_add(1, Ordering::Relaxed);
        let address = format_socket_addr(&peer);
        let datagram = encode_udp_datagram(session_id, packet_id, 0, 1, &address, &buffer[..read])?;
        let Some(max_size) = connection.max_datagram_size() else {
            return Ok(());
        };
        if datagram.len() > max_size {
            continue;
        }
        connection
            .send_datagram_wait(Bytes::from(datagram))
            .await
            .map_err(io_other)?;
        traffic.add_with_user_id(
            node_tag.clone(),
            user_uuid.clone(),
            Some(user_id),
            0,
            read as u64,
            Some(client_ip),
        );
    }
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
    let address_len = read_varint(stream).await?;
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
    let address = String::from_utf8(input[offset..offset + address_len].to_vec())
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid hysteria2 udp address"))?;
    offset += address_len;

    Ok(UdpDatagram {
        session_id,
        packet_id,
        fragment_id,
        fragment_count,
        target: parse_target_address(&address)?,
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
    let (mut remote_read, mut remote_write) = remote.into_split();
    let upload = async {
        let bandwidth = bandwidth.clone();
        let mut total = 0u64;
        let mut buffer = [0u8; 16 * 1024];
        loop {
            let revoke_watch = bandwidth.clone();
            let read = tokio::select! {
                read = recv.read(&mut buffer) => read.map_err(io_other)?,
                _ = revoke_watch.wait_revoked() => {
                    let _ = remote_write.shutdown().await;
                    return Ok::<u64, io::Error>(total);
                }
            };
            let Some(read) = read else {
                let _ = remote_write.shutdown().await;
                return Ok::<u64, io::Error>(total);
            };
            if !bandwidth.wait_upload(read).await {
                let _ = remote_write.shutdown().await;
                return Ok::<u64, io::Error>(total);
            }
            remote_write.write_all(&buffer[..read]).await?;
            on_upload(read as u64);
            total = total.saturating_add(read as u64);
        }
    };
    let download = async {
        let bandwidth = bandwidth.clone();
        let mut total = 0u64;
        let mut buffer = [0u8; 16 * 1024];
        loop {
            let revoke_watch = bandwidth.clone();
            let read = tokio::select! {
                read = remote_read.read(&mut buffer) => read?,
                _ = revoke_watch.wait_revoked() => {
                    let _ = send.finish();
                    return Ok::<u64, io::Error>(total);
                }
            };
            if read == 0 {
                let _ = send.finish();
                return Ok::<u64, io::Error>(total);
            }
            if !bandwidth.wait_download(read).await {
                let _ = send.finish();
                return Ok::<u64, io::Error>(total);
            }
            send.write_all(&buffer[..read]).await.map_err(io_other)?;
            on_download(read as u64);
            total = total.saturating_add(read as u64);
        }
    };
    tokio::try_join!(upload, download)
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

#[cfg(test)]
mod tests {
    use std::fs;
    use std::future::poll_fn;
    use std::path::PathBuf;
    use std::sync::atomic::AtomicBool;
    use std::time::{SystemTime, UNIX_EPOCH};

    use quinn::crypto::rustls::QuicClientConfig;
    use rustls::pki_types::CertificateDer;

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
                upload: vec![limiter.clone()],
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
    fn apply_user_delta_changes_hysteria2_auth_without_rebinding_listener() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let cert = test_cert("user-delta-auth");
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
            accepted.close(0u32.into(), b"done");
            accepted_endpoint.wait_idle().await;

            stop.store(true, Ordering::SeqCst);
            server_task.await.expect("server task");
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
        let mut request = encode_varint(TCP_REQUEST_ID).expect("request id");
        request.extend_from_slice(&encode_varint(address.len() as u64).expect("addr len"));
        request.extend_from_slice(address.as_bytes());
        request.extend_from_slice(&encode_varint(0).expect("padding len"));
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

        assert!(fragments.push(first).unwrap().is_none());
        let message = fragments
            .push(second)
            .unwrap()
            .expect("complete fragmented message");

        assert_eq!(message.session_id, 7);
        assert_eq!(message.packet_id, 12);
        assert_eq!(message.fragment_id, 0);
        assert_eq!(message.fragment_count, 1);
        assert_eq!(message.data, b"hello");
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
            send.write_all(&tcp_request(echo_addr))
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

            tokio::time::sleep(Duration::from_millis(50)).await;
            let records = server.drain_traffic(1);
            assert_eq!(records.len(), 1);
            assert_eq!(records[0].node_tag, "panel|hysteria|1");
            assert_eq!(records[0].user_uuid, "hy2-password");
            assert_eq!(records[0].user_id, Some(1));
            assert_eq!(records[0].upload, 4);
            assert_eq!(records[0].download, 4);

            send.finish().expect("finish payload");
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
}
