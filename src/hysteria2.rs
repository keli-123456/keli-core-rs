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
use tokio::net::{lookup_host, UdpSocket};

use crate::limits::{
    BandwidthLimiter, UserBandwidthLimiters, UserSessionGuard, UserSessionTracker,
};
use crate::routing::{route_protocol_labels, RouteDecision, RouteMatcher};
use crate::salamander::SalamanderUdpSocket;
use crate::socks5::SocksTarget;
use crate::tls::server_config_from_files;
use crate::traffic::TrafficRegistry;
use crate::user::CoreUser;

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
    users: Arc<HashMap<String, CoreUser>>,
    router: RouteMatcher,
    traffic: Arc<Mutex<TrafficRegistry>>,
    sessions: UserSessionTracker,
    bandwidth: UserBandwidthLimiters,
}

impl Hysteria2Server {
    pub fn new(config: Hysteria2ServerConfig) -> Self {
        Self::with_shared_limits(
            config,
            Arc::new(Mutex::new(TrafficRegistry::default())),
            UserSessionTracker::default(),
            UserBandwidthLimiters::default(),
        )
    }

    pub fn with_shared_limits(
        config: Hysteria2ServerConfig,
        traffic: Arc<Mutex<TrafficRegistry>>,
        sessions: UserSessionTracker,
        bandwidth: UserBandwidthLimiters,
    ) -> Self {
        let users = config
            .users
            .iter()
            .filter(|user| !user.is_empty())
            .map(|user| (user.credential().to_string(), user.clone()))
            .collect();
        Self {
            router: RouteMatcher::new(config.routes.clone()),
            config,
            users: Arc::new(users),
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
                        let _ = server.handle_incoming(incoming).await;
                    });
                }
                _ = tokio::time::sleep(Duration::from_millis(20)) => {}
            }
        }
        endpoint.wait_idle().await;
    }

    pub fn drain_traffic(&self, minimum_bytes: u64) -> Vec<crate::traffic::TrafficDelta> {
        self.traffic
            .lock()
            .expect("traffic registry lock poisoned")
            .drain_minimum(minimum_bytes)
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
        let udp_bandwidth = bandwidth.clone();
        tokio::spawn(async move {
            let _ = udp_server
                .handle_udp_datagrams(
                    udp_connection,
                    udp_user_uuid,
                    udp_bandwidth,
                    udp_sessions,
                    client_ip,
                )
                .await;
        });

        loop {
            match connection.accept_bi().await {
                Ok(stream) => {
                    let server = self.clone();
                    let user_uuid = auth.user.uuid.clone();
                    let bandwidth = bandwidth.clone();
                    tokio::spawn(async move {
                        let _ = server
                            .handle_tcp_stream(stream, user_uuid, bandwidth, client_ip)
                            .await;
                    });
                }
                Err(quinn::ConnectionError::ApplicationClosed { .. })
                | Err(quinn::ConnectionError::LocallyClosed)
                | Err(quinn::ConnectionError::ConnectionClosed(_)) => return Ok(()),
                Err(error) => return Err(io_other(error)),
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
            let Some(user) = self.users.get(auth).cloned() else {
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
        let target = match &decision {
            RouteDecision::Direct | RouteDecision::Outbound(_) => {
                let routed = decision.apply_to_target(&target.host, target.port);
                SocksTarget {
                    host: routed.host,
                    port: routed.port,
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

        let remote = match tokio::time::timeout(
            self.config.connect_timeout,
            tokio::net::TcpStream::connect((target.host.as_str(), target.port)),
        )
        .await
        {
            Ok(Ok(stream)) => stream,
            Ok(Err(error)) => {
                write_tcp_response(&mut send, RESPONSE_ERROR, "connect failed").await?;
                let _ = send.finish();
                return Err(error);
            }
            Err(_) => {
                write_tcp_response(&mut send, RESPONSE_ERROR, "connect timed out").await?;
                let _ = send.finish();
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "target connect timed out",
                ));
            }
        };

        write_tcp_response(&mut send, RESPONSE_OK, "").await?;
        let (upload, download) = relay_streams(&mut recv, &mut send, remote, bandwidth).await?;
        self.traffic
            .lock()
            .expect("traffic registry lock poisoned")
            .add_with_ip(
                self.config.node_tag.clone(),
                user_uuid,
                upload,
                download,
                Some(client_ip),
            );
        Ok(())
    }

    async fn handle_udp_datagrams(
        &self,
        connection: quinn::Connection,
        user_uuid: String,
        bandwidth: DirectionalLimiters,
        sessions: Arc<Mutex<HashMap<u32, Arc<UdpRelaySession>>>>,
        client_ip: IpAddr,
    ) -> io::Result<()> {
        let mut fragments = UdpFragmentStore::default();
        loop {
            let datagram = match connection.read_datagram().await {
                Ok(datagram) => datagram,
                Err(quinn::ConnectionError::ApplicationClosed { .. })
                | Err(quinn::ConnectionError::LocallyClosed)
                | Err(quinn::ConnectionError::ConnectionClosed(_)) => return Ok(()),
                Err(error) => return Err(io_other(error)),
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
        bandwidth: DirectionalLimiters,
        sessions: &Arc<Mutex<HashMap<u32, Arc<UdpRelaySession>>>>,
        client_ip: IpAddr,
        message: UdpDatagram,
    ) -> io::Result<()> {
        let protocol_labels = route_protocol_labels("udp", &message.data);
        let decision =
            self.router
                .decide_target(&message.target.host, message.target.port, &protocol_labels);
        let target = match &decision {
            RouteDecision::Direct | RouteDecision::Outbound(_) => {
                let routed = decision.apply_to_target(&message.target.host, message.target.port);
                SocksTarget {
                    host: routed.host,
                    port: routed.port,
                }
            }
            RouteDecision::Block => return Ok(()),
            RouteDecision::UnsupportedOutbound(tag) => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!("outbound route {tag} is not implemented"),
                ));
            }
        };

        let target_addr = resolve_udp_target(&target, self.config.connect_timeout).await?;
        let session = self
            .get_udp_session(
                connection,
                user_uuid,
                sessions,
                message.session_id,
                target_addr,
                bandwidth.clone(),
                client_ip,
            )
            .await?;
        bandwidth.wait_upload(message.data.len());
        session.socket.send_to(&message.data, target_addr).await?;
        self.traffic
            .lock()
            .expect("traffic registry lock poisoned")
            .add_with_ip(
                self.config.node_tag.clone(),
                user_uuid.to_string(),
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
        sessions: &Arc<Mutex<HashMap<u32, Arc<UdpRelaySession>>>>,
        session_id: u32,
        target_addr: SocketAddr,
        bandwidth: DirectionalLimiters,
        client_ip: IpAddr,
    ) -> io::Result<Arc<UdpRelaySession>> {
        if let Some(session) = sessions
            .lock()
            .expect("hysteria2 udp session lock poisoned")
            .get(&session_id)
            .cloned()
        {
            return Ok(session);
        }

        let socket = Arc::new(bind_udp_socket(target_addr.ip()).await?);
        let session = Arc::new(UdpRelaySession {
            socket,
            next_packet_id: AtomicU16::new(0),
        });
        {
            let mut sessions = sessions
                .lock()
                .expect("hysteria2 udp session lock poisoned");
            if let Some(existing) = sessions.get(&session_id) {
                return Ok(existing.clone());
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
                session_id, receiver, connection, node_tag, user_uuid, traffic, bandwidth,
                client_ip,
            )
            .await;
        });
        Ok(session)
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
    fn wait_upload(&self, bytes: usize) {
        for limiter in &self.upload {
            limiter.wait_for(bytes);
        }
    }

    fn wait_download(&self, bytes: usize) {
        for limiter in &self.download {
            limiter.wait_for(bytes);
        }
    }
}

#[derive(Debug)]
struct UdpRelaySession {
    socket: Arc<UdpSocket>,
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
    match tokio::time::timeout(timeout, lookup_host((target.host.as_str(), target.port))).await {
        Ok(Ok(mut addresses)) => addresses.next().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "hysteria2 udp target has no address",
            )
        }),
        Ok(Err(error)) => Err(error),
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "hysteria2 udp target lookup timed out",
        )),
    }
}

async fn receive_udp_replies(
    session_id: u32,
    session: Arc<UdpRelaySession>,
    connection: quinn::Connection,
    node_tag: String,
    user_uuid: String,
    traffic: Arc<Mutex<TrafficRegistry>>,
    bandwidth: DirectionalLimiters,
    client_ip: IpAddr,
) -> io::Result<()> {
    let mut buffer = vec![0u8; UDP_PACKET_BUFFER_SIZE];
    loop {
        let (read, peer) = session.socket.recv_from(&mut buffer).await?;
        bandwidth.wait_download(read);
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
        traffic
            .lock()
            .expect("traffic registry lock poisoned")
            .add_with_ip(
                node_tag.clone(),
                user_uuid.clone(),
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
    send.write_all(&[status]).await.map_err(io_other)?;
    write_varint(send, message.len() as u64).await?;
    if !message.is_empty() {
        send.write_all(message.as_bytes()).await.map_err(io_other)?;
    }
    write_varint(send, 0).await
}

async fn relay_streams(
    recv: &mut quinn::RecvStream,
    send: &mut quinn::SendStream,
    remote: tokio::net::TcpStream,
    bandwidth: DirectionalLimiters,
) -> io::Result<(u64, u64)> {
    let (mut remote_read, mut remote_write) = remote.into_split();
    let upload = async {
        let mut total = 0u64;
        let mut buffer = [0u8; 16 * 1024];
        loop {
            let read = recv.read(&mut buffer).await.map_err(io_other)?;
            let Some(read) = read else {
                let _ = remote_write.shutdown().await;
                return Ok::<u64, io::Error>(total);
            };
            bandwidth.wait_upload(read);
            remote_write.write_all(&buffer[..read]).await?;
            total = total.saturating_add(read as u64);
        }
    };
    let download = async {
        let mut total = 0u64;
        let mut buffer = [0u8; 16 * 1024];
        loop {
            let read = remote_read.read(&mut buffer).await?;
            if read == 0 {
                let _ = send.finish();
                return Ok::<u64, io::Error>(total);
            }
            bandwidth.wait_download(read);
            send.write_all(&buffer[..read]).await.map_err(io_other)?;
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

async fn write_varint(send: &mut quinn::SendStream, value: u64) -> io::Result<()> {
    let bytes = encode_varint(value)?;
    send.write_all(&bytes).await.map_err(io_other)
}

fn encode_varint(value: u64) -> io::Result<Vec<u8>> {
    if value < 2u64.pow(6) {
        Ok(vec![value as u8])
    } else if value < 2u64.pow(14) {
        Ok(((0b01u16 << 14) | value as u16).to_be_bytes().to_vec())
    } else if value < 2u64.pow(30) {
        Ok(((0b10u32 << 30) | value as u32).to_be_bytes().to_vec())
    } else if value < 2u64.pow(62) {
        Ok(((0b11u64 << 62) | value).to_be_bytes().to_vec())
    } else {
        Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "value too large for QUIC varint",
        ))
    }
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

    async fn authenticate(connection: &quinn::Connection) {
        let (udp, _) = authenticate_with_rx(connection, "0").await;
        assert_eq!(udp.as_deref(), Some("true"));
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
            send.finish().expect("finish payload");
            let mut echoed = [0u8; 4];
            recv.read_exact(&mut echoed).await.expect("echoed payload");
            assert_eq!(&echoed, b"ping");
            connection.close(0u32.into(), b"done");
            echo_task.await.expect("echo task");

            tokio::time::sleep(Duration::from_millis(50)).await;
            let records = server.drain_traffic(1);
            assert_eq!(records.len(), 1);
            assert_eq!(records[0].node_tag, "panel|hysteria|1");
            assert_eq!(records[0].user_uuid, "hy2-password");
            assert_eq!(records[0].upload, 4);
            assert_eq!(records[0].download, 4);

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
            assert_eq!(records[0].upload, 4);
            assert_eq!(records[0].download, 4);

            stop.store(true, Ordering::SeqCst);
            server_task.await.expect("server task");
        });
    }
}
