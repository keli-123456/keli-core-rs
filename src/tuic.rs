use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::{AtomicBool, AtomicU16, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::time::Duration;

use bytes::Bytes;
use quinn::crypto::rustls::QuicServerConfig;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;

use crate::limits::{
    sync_user_limit_delta, BandwidthLimiter, UserBandwidthLimiters, UserSessionGuard,
    UserSessionTracker,
};
use crate::routing::{route_protocol_labels, RouteDecision, RouteMatcher};
use crate::socks5::SocksTarget;
use crate::tls::server_config_from_files;
use crate::traffic::{SharedTrafficRegistry, TrafficRegistry};
use crate::user::{apply_user_delta_to_keyed_map, CoreUser, CoreUserDelta, CoreUserDeltaResult};
use crate::{connect_tcp_outbound_tokio, send_udp_outbound_tokio};

const VERSION: u8 = 0x05;
const COMMAND_AUTHENTICATE: u8 = 0x00;
const COMMAND_CONNECT: u8 = 0x01;
const COMMAND_PACKET: u8 = 0x02;
const COMMAND_DISSOCIATE: u8 = 0x03;
const COMMAND_HEARTBEAT: u8 = 0x04;
const ATYP_DOMAIN: u8 = 0x00;
const ATYP_IPV4: u8 = 0x01;
const ATYP_IPV6: u8 = 0x02;
const ATYP_NONE: u8 = 0xff;
const UDP_DATAGRAM_BUFFER_SIZE: usize = 1024 * 1024;
const UDP_PACKET_BUFFER_SIZE: usize = 64 * 1024;

#[derive(Clone, Debug)]
pub struct TuicServerConfig {
    pub node_tag: String,
    pub listen: SocketAddr,
    pub users: Vec<CoreUser>,
    pub routes: Vec<crate::RouteRule>,
    pub cert_file: String,
    pub key_file: String,
    pub server_name: String,
    pub alpn: Vec<String>,
    pub reject_unknown_sni: bool,
    pub congestion_control: String,
    pub connect_timeout: Duration,
}

#[derive(Clone, Debug)]
pub struct TuicServer {
    config: TuicServerConfig,
    users: Arc<RwLock<HashMap<[u8; 16], CoreUser>>>,
    router: RouteMatcher,
    traffic: SharedTrafficRegistry,
    sessions: UserSessionTracker,
    bandwidth: UserBandwidthLimiters,
}

impl TuicServer {
    pub fn new(config: TuicServerConfig) -> Self {
        Self::with_shared_limits(
            config,
            TrafficRegistry::shared(),
            UserSessionTracker::default(),
            UserBandwidthLimiters::default(),
        )
    }

    pub fn with_shared_limits(
        config: TuicServerConfig,
        traffic: SharedTrafficRegistry,
        sessions: UserSessionTracker,
        bandwidth: UserBandwidthLimiters,
    ) -> Self {
        let users = tuic_user_map(&config.users);
        Self {
            router: RouteMatcher::new(config.routes.clone()),
            config,
            users: Arc::new(RwLock::new(users)),
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
        apply_tuic_congestion_control(&mut transport, &self.config.congestion_control)?;
        server_config.transport_config(Arc::new(transport));
        quinn::Endpoint::server(server_config, self.config.listen)
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
        self.traffic.drain_minimum(minimum_bytes)
    }

    pub fn replace_users(&self, users: Vec<CoreUser>) {
        self.bandwidth.sync_users(&users);
        let mut current = self.users.write().expect("tuic users lock poisoned");
        *current = tuic_user_map(&users);
    }

    pub fn apply_user_delta(&self, delta: &CoreUserDelta) -> CoreUserDeltaResult {
        sync_delta_bandwidth(&self.bandwidth, &self.sessions, delta);
        let mut current = self.users.write().expect("tuic users lock poisoned");
        apply_user_delta_to_keyed_map(&mut current, delta, |user| {
            parse_uuid_bytes(&user.uuid).ok()
        })
    }

    fn user_for_uuid(&self, uuid: &[u8; 16]) -> Option<CoreUser> {
        self.users
            .read()
            .expect("tuic users lock poisoned")
            .get(uuid)
            .cloned()
    }

    async fn handle_incoming(&self, incoming: quinn::Incoming) -> io::Result<()> {
        let connection = incoming.await.map_err(io_other)?;
        let client_ip = connection.remote_address().ip();
        let mut auth_stream = connection.accept_uni().await.map_err(io_other)?;
        let user = self.authenticate(&connection, &mut auth_stream).await?;
        let _session = self.acquire_user_session(&user, Some(client_ip))?;
        let revocation = self.bandwidth.limiter_for(Some(&user));
        let bandwidth = self.bandwidth.limiter_for_limited(Some(&user));
        let udp_sessions = Arc::new(Mutex::new(HashMap::new()));

        let datagram_server = self.clone();
        let datagram_connection = connection.clone();
        let datagram_user_uuid = user.uuid.clone();
        let datagram_user_id = user.id;
        let datagram_revocation = revocation.clone();
        let datagram_bandwidth = bandwidth.clone();
        let datagram_sessions = udp_sessions.clone();
        tokio::spawn(async move {
            let _ = datagram_server
                .handle_udp_datagrams(
                    datagram_connection,
                    datagram_user_uuid,
                    datagram_user_id,
                    datagram_revocation,
                    datagram_bandwidth,
                    datagram_sessions,
                    client_ip,
                )
                .await;
        });

        let uni_server = self.clone();
        let uni_connection = connection.clone();
        let uni_user_uuid = user.uuid.clone();
        let uni_user_id = user.id;
        let uni_revocation = revocation.clone();
        let uni_bandwidth = bandwidth.clone();
        let uni_sessions = udp_sessions.clone();
        tokio::spawn(async move {
            let _ = uni_server
                .handle_unidirectional_commands(
                    uni_connection,
                    uni_user_uuid,
                    uni_user_id,
                    uni_revocation,
                    uni_bandwidth,
                    uni_sessions,
                    client_ip,
                )
                .await;
        });

        loop {
            let stream = if let Some(limiter) = revocation.as_deref() {
                tokio::select! {
                    stream = connection.accept_bi() => stream,
                    _ = wait_limiter_revoke(limiter) => {
                        connection.close(0u32.into(), b"user revoked");
                        return Ok(());
                    }
                }
            } else {
                connection.accept_bi().await
            };
            match stream {
                Ok(stream) => {
                    let server = self.clone();
                    let user_uuid = user.uuid.clone();
                    let user_id = user.id;
                    let bandwidth = bandwidth.clone();
                    tokio::spawn(async move {
                        let _ = server
                            .handle_connect_stream(stream, user_uuid, user_id, bandwidth, client_ip)
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

    async fn authenticate(
        &self,
        connection: &quinn::Connection,
        stream: &mut quinn::RecvStream,
    ) -> io::Result<CoreUser> {
        let mut header = [0u8; 2];
        read_exact(stream, &mut header).await?;
        if header != [VERSION, COMMAND_AUTHENTICATE] {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "invalid tuic authentication command",
            ));
        }
        let mut uuid = [0u8; 16];
        let mut token = [0u8; 32];
        read_exact(stream, &mut uuid).await?;
        read_exact(stream, &mut token).await?;

        let Some(user) = self.user_for_uuid(&uuid) else {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "unknown tuic user",
            ));
        };
        if !tuic_token_matches(connection, &uuid, user.credential(), &token)? {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "invalid tuic token",
            ));
        }
        Ok(user)
    }

    async fn handle_connect_stream(
        &self,
        (mut send, mut recv): (quinn::SendStream, quinn::RecvStream),
        user_uuid: String,
        user_id: u64,
        bandwidth: Option<Arc<BandwidthLimiter>>,
        client_ip: IpAddr,
    ) -> io::Result<()> {
        let mut header = [0u8; 2];
        read_exact(&mut recv, &mut header).await?;
        if header != [VERSION, COMMAND_CONNECT] {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid tuic connect command",
            ));
        }
        let target = read_address(&mut recv).await?;
        let decision = self.router.decide_target(&target.host, target.port, "tcp");
        let remote = match &decision {
            RouteDecision::Direct => {
                crate::dns::connect_tcp_tokio(
                    &target.host,
                    target.port,
                    self.config.connect_timeout,
                )
                .await?
            }
            RouteDecision::Outbound(outbound) => {
                connect_tcp_outbound_tokio(outbound, &target, self.config.connect_timeout).await?
            }
            RouteDecision::Block => return Ok(()),
            RouteDecision::UnsupportedOutbound(tag) => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!("outbound route {tag} is not implemented"),
                ));
            }
        };

        let (upload, download) = relay_streams(&mut recv, &mut send, remote, bandwidth).await?;
        self.traffic.add_with_user_id(
            self.config.node_tag.clone(),
            user_uuid,
            Some(user_id),
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
        user_id: u64,
        revocation: Option<Arc<BandwidthLimiter>>,
        bandwidth: Option<Arc<BandwidthLimiter>>,
        sessions: Arc<Mutex<HashMap<u16, Arc<UdpRelaySession>>>>,
        client_ip: IpAddr,
    ) -> io::Result<()> {
        let mut fragments = UdpFragmentStore::default();
        loop {
            let datagram = if let Some(limiter) = revocation.as_deref() {
                tokio::select! {
                    datagram = connection.read_datagram() => datagram,
                    _ = wait_limiter_revoke(limiter) => return Ok(()),
                }
            } else {
                connection.read_datagram().await
            };
            let datagram = match datagram {
                Ok(datagram) => datagram,
                Err(quinn::ConnectionError::ApplicationClosed { .. })
                | Err(quinn::ConnectionError::LocallyClosed)
                | Err(quinn::ConnectionError::ConnectionClosed(_)) => return Ok(()),
                Err(error) => return Err(io_other(error)),
            };
            let Ok(command) = parse_udp_command(&datagram) else {
                continue;
            };
            self.handle_udp_command(
                &connection,
                &user_uuid,
                user_id,
                revocation.clone(),
                bandwidth.clone(),
                &sessions,
                &mut fragments,
                UdpReplyMode::Datagram,
                client_ip,
                command,
            )
            .await?;
        }
    }

    async fn handle_unidirectional_commands(
        &self,
        connection: quinn::Connection,
        user_uuid: String,
        user_id: u64,
        revocation: Option<Arc<BandwidthLimiter>>,
        bandwidth: Option<Arc<BandwidthLimiter>>,
        sessions: Arc<Mutex<HashMap<u16, Arc<UdpRelaySession>>>>,
        client_ip: IpAddr,
    ) -> io::Result<()> {
        let mut fragments = UdpFragmentStore::default();
        loop {
            let stream = if let Some(limiter) = revocation.as_deref() {
                tokio::select! {
                    stream = connection.accept_uni() => stream,
                    _ = wait_limiter_revoke(limiter) => return Ok(()),
                }
            } else {
                connection.accept_uni().await
            };
            let mut stream = match stream {
                Ok(stream) => stream,
                Err(quinn::ConnectionError::ApplicationClosed { .. })
                | Err(quinn::ConnectionError::LocallyClosed)
                | Err(quinn::ConnectionError::ConnectionClosed(_)) => return Ok(()),
                Err(error) => return Err(io_other(error)),
            };
            let command = stream
                .read_to_end(UDP_PACKET_BUFFER_SIZE + 512)
                .await
                .map_err(io_other)?;
            let Ok(command) = parse_udp_command(&command) else {
                continue;
            };
            self.handle_udp_command(
                &connection,
                &user_uuid,
                user_id,
                revocation.clone(),
                bandwidth.clone(),
                &sessions,
                &mut fragments,
                UdpReplyMode::UniStream,
                client_ip,
                command,
            )
            .await?;
        }
    }

    async fn handle_udp_command(
        &self,
        connection: &quinn::Connection,
        user_uuid: &str,
        user_id: u64,
        revocation: Option<Arc<BandwidthLimiter>>,
        bandwidth: Option<Arc<BandwidthLimiter>>,
        sessions: &Arc<Mutex<HashMap<u16, Arc<UdpRelaySession>>>>,
        fragments: &mut UdpFragmentStore,
        reply_mode: UdpReplyMode,
        client_ip: IpAddr,
        command: UdpCommand,
    ) -> io::Result<()> {
        match command {
            UdpCommand::Packet(packet) => match fragments.push(packet)? {
                Some(packet) => {
                    self.handle_udp_packet(
                        connection, user_uuid, user_id, revocation, bandwidth, sessions,
                        reply_mode, client_ip, packet,
                    )
                    .await
                }
                None => Ok(()),
            },
            UdpCommand::Dissociate(assoc_id) => {
                if let Some(session) = sessions
                    .lock()
                    .expect("tuic udp session lock poisoned")
                    .remove(&assoc_id)
                {
                    session.closed.store(true, Ordering::Relaxed);
                }
                Ok(())
            }
            UdpCommand::Heartbeat => Ok(()),
        }
    }

    async fn handle_udp_packet(
        &self,
        connection: &quinn::Connection,
        user_uuid: &str,
        user_id: u64,
        revocation: Option<Arc<BandwidthLimiter>>,
        bandwidth: Option<Arc<BandwidthLimiter>>,
        sessions: &Arc<Mutex<HashMap<u16, Arc<UdpRelaySession>>>>,
        reply_mode: UdpReplyMode,
        client_ip: IpAddr,
        packet: UdpPacket,
    ) -> io::Result<()> {
        if !packet.is_single_fragment() {
            return Ok(());
        }
        let Some(target) = packet.target else {
            return Ok(());
        };
        let protocol_labels = route_protocol_labels("udp", &packet.payload);
        let decision = self
            .router
            .decide_target(&target.host, target.port, &protocol_labels);
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
            if let Some(limiter) = bandwidth.as_deref() {
                if !limiter.wait_for(packet.payload.len()) {
                    return Ok(());
                }
            }
            match send_udp_outbound_tokio(
                outbound,
                &target,
                &packet.payload,
                self.config.connect_timeout,
            )
            .await
            {
                Ok((source, response)) => {
                    let response_target = socket_addr_to_target(&source);
                    let command = encode_udp_packet(
                        packet.assoc_id,
                        packet.packet_id,
                        1,
                        0,
                        Some(&response_target),
                        &response,
                    )?;
                    match reply_mode {
                        UdpReplyMode::Datagram => {
                            if let Some(max_size) = connection.max_datagram_size() {
                                if command.len() <= max_size {
                                    connection
                                        .send_datagram_wait(Bytes::from(command))
                                        .await
                                        .map_err(io_other)?;
                                }
                            }
                        }
                        UdpReplyMode::UniStream => {
                            let mut send = connection.open_uni().await.map_err(io_other)?;
                            send.write_all(&command).await.map_err(io_other)?;
                            let _ = send.finish();
                        }
                    }
                    self.traffic.add_with_user_id(
                        self.config.node_tag.clone(),
                        user_uuid.to_string(),
                        Some(user_id),
                        packet.payload.len() as u64,
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
                        packet.payload.len() as u64,
                        0,
                        Some(client_ip),
                    );
                }
                Err(error) => return Err(error),
            }
            return Ok(());
        }

        let target_addr = resolve_udp_target(&target, self.config.connect_timeout).await?;
        let session = self
            .get_udp_session(
                connection,
                user_uuid,
                user_id,
                sessions,
                packet.assoc_id,
                target_addr,
                revocation.clone(),
                bandwidth.clone(),
                reply_mode,
                client_ip,
            )
            .await?;
        if session.closed.load(Ordering::Relaxed) {
            return Ok(());
        }
        if let Some(limiter) = bandwidth.as_deref() {
            if !limiter.wait_for(packet.payload.len()) {
                return Ok(());
            }
        }
        session.socket.send_to(&packet.payload, target_addr).await?;
        self.traffic.add_with_user_id(
            self.config.node_tag.clone(),
            user_uuid.to_string(),
            Some(user_id),
            packet.payload.len() as u64,
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
        sessions: &Arc<Mutex<HashMap<u16, Arc<UdpRelaySession>>>>,
        assoc_id: u16,
        target_addr: SocketAddr,
        revocation: Option<Arc<BandwidthLimiter>>,
        bandwidth: Option<Arc<BandwidthLimiter>>,
        reply_mode: UdpReplyMode,
        client_ip: IpAddr,
    ) -> io::Result<Arc<UdpRelaySession>> {
        if let Some(session) = sessions
            .lock()
            .expect("tuic udp session lock poisoned")
            .get(&assoc_id)
            .cloned()
        {
            if !session.closed.load(Ordering::Relaxed) {
                return Ok(session);
            }
        }

        let socket = Arc::new(bind_udp_socket(target_addr.ip()).await?);
        let session = Arc::new(UdpRelaySession {
            socket,
            next_packet_id: AtomicU16::new(0),
            reply_mode,
            closed: AtomicBool::new(false),
        });
        {
            let mut sessions = sessions.lock().expect("tuic udp session lock poisoned");
            if let Some(existing) = sessions.get(&assoc_id) {
                if !existing.closed.load(Ordering::Relaxed) {
                    return Ok(existing.clone());
                }
            }
            sessions.insert(assoc_id, session.clone());
        }

        let receiver = session.clone();
        let connection = connection.clone();
        let node_tag = self.config.node_tag.clone();
        let user_uuid = user_uuid.to_string();
        let traffic = self.traffic.clone();
        let revocation = revocation.clone();
        let bandwidth = bandwidth.clone();
        tokio::spawn(async move {
            let _ = receive_udp_replies(
                assoc_id, receiver, connection, node_tag, user_uuid, user_id, traffic, revocation,
                bandwidth, client_ip,
            )
            .await;
        });
        Ok(session)
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum UdpReplyMode {
    Datagram,
    UniStream,
}

#[derive(Debug)]
struct UdpRelaySession {
    socket: Arc<UdpSocket>,
    next_packet_id: AtomicU16,
    reply_mode: UdpReplyMode,
    closed: AtomicBool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum UdpCommand {
    Packet(UdpPacket),
    Dissociate(u16),
    Heartbeat,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct UdpPacket {
    assoc_id: u16,
    packet_id: u16,
    fragment_total: u8,
    fragment_id: u8,
    target: Option<SocksTarget>,
    payload: Vec<u8>,
}

impl UdpPacket {
    fn is_single_fragment(&self) -> bool {
        self.fragment_total == 1 && self.fragment_id == 0
    }
}

#[derive(Debug, Default)]
struct UdpFragmentStore {
    fragments: HashMap<(u16, u16), UdpFragmentSet>,
}

#[derive(Debug)]
struct UdpFragmentSet {
    target: Option<SocksTarget>,
    parts: Vec<Option<Vec<u8>>>,
}

impl UdpFragmentStore {
    fn push(&mut self, packet: UdpPacket) -> io::Result<Option<UdpPacket>> {
        if packet.fragment_total == 0 || packet.fragment_id >= packet.fragment_total {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid tuic udp fragment index",
            ));
        }
        if packet.is_single_fragment() {
            return Ok(Some(packet));
        }

        let key = (packet.assoc_id, packet.packet_id);
        let count = packet.fragment_total as usize;
        let index = packet.fragment_id as usize;
        let set = self.fragments.entry(key).or_insert_with(|| UdpFragmentSet {
            target: None,
            parts: vec![None; count],
        });
        if set.parts.len() != count {
            self.fragments.remove(&key);
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "mismatched tuic udp fragment group",
            ));
        }
        if let Some(target) = packet.target {
            if let Some(existing) = &set.target {
                if existing != &target {
                    self.fragments.remove(&key);
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "mismatched tuic udp fragment target",
                    ));
                }
            }
            set.target = Some(target);
        }
        set.parts[index] = Some(packet.payload);
        if !set.parts.iter().all(Option::is_some) || set.target.is_none() {
            return Ok(None);
        }

        let set = self.fragments.remove(&key).expect("fragment set exists");
        let mut payload = Vec::new();
        for part in set.parts {
            payload.extend_from_slice(&part.expect("all fragments present"));
        }
        Ok(Some(UdpPacket {
            assoc_id: key.0,
            packet_id: key.1,
            fragment_total: 1,
            fragment_id: 0,
            target: set.target,
            payload,
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

async fn wait_limiter_revoke(limiter: &BandwidthLimiter) {
    limiter.wait_revoked().await;
}

async fn receive_udp_replies(
    assoc_id: u16,
    session: Arc<UdpRelaySession>,
    connection: quinn::Connection,
    node_tag: String,
    user_uuid: String,
    user_id: u64,
    traffic: SharedTrafficRegistry,
    revocation: Option<Arc<BandwidthLimiter>>,
    bandwidth: Option<Arc<BandwidthLimiter>>,
    client_ip: IpAddr,
) -> io::Result<()> {
    let mut buffer = vec![0u8; UDP_PACKET_BUFFER_SIZE];
    loop {
        if session.closed.load(Ordering::Relaxed) {
            return Ok(());
        }
        let result = tokio::select! {
            result = session.socket.recv_from(&mut buffer) => result,
            _ = connection.closed() => return Ok(()),
            _ = async {
                if let Some(limiter) = revocation.as_deref() {
                    wait_limiter_revoke(limiter).await;
                } else {
                    std::future::pending::<()>().await;
                }
            } => return Ok(()),
            _ = tokio::time::sleep(Duration::from_secs(1)) => continue,
        };
        let (read, peer) = result?;
        if let Some(limiter) = bandwidth.as_deref() {
            if !limiter.wait_for(read) {
                return Ok(());
            }
        }
        let packet_id = session.next_packet_id.fetch_add(1, Ordering::Relaxed);
        let target = socket_addr_to_target(&peer);
        let command = encode_udp_packet(assoc_id, packet_id, 1, 0, Some(&target), &buffer[..read])?;
        match session.reply_mode {
            UdpReplyMode::Datagram => {
                let Some(max_size) = connection.max_datagram_size() else {
                    return Ok(());
                };
                if command.len() > max_size {
                    continue;
                }
                connection
                    .send_datagram_wait(Bytes::from(command))
                    .await
                    .map_err(io_other)?;
            }
            UdpReplyMode::UniStream => {
                let mut send = connection.open_uni().await.map_err(io_other)?;
                send.write_all(&command).await.map_err(io_other)?;
                let _ = send.finish();
            }
        }
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

async fn relay_streams(
    recv: &mut quinn::RecvStream,
    send: &mut quinn::SendStream,
    remote: tokio::net::TcpStream,
    bandwidth: Option<Arc<BandwidthLimiter>>,
) -> io::Result<(u64, u64)> {
    let (mut remote_read, mut remote_write) = remote.into_split();
    let upload = async {
        let mut total = 0u64;
        let mut buffer = [0u8; 16 * 1024];
        loop {
            let read = if let Some(limiter) = bandwidth.as_deref() {
                tokio::select! {
                    read = recv.read(&mut buffer) => read.map_err(io_other)?,
                    _ = wait_limiter_revoke(limiter) => {
                        let _ = remote_write.shutdown().await;
                        return Ok::<u64, io::Error>(total);
                    }
                }
            } else {
                recv.read(&mut buffer).await.map_err(io_other)?
            };
            let Some(read) = read else {
                let _ = remote_write.shutdown().await;
                return Ok::<u64, io::Error>(total);
            };
            if let Some(limiter) = bandwidth.as_deref() {
                if !limiter.wait_for(read) {
                    let _ = remote_write.shutdown().await;
                    return Ok::<u64, io::Error>(total);
                }
            }
            remote_write.write_all(&buffer[..read]).await?;
            total = total.saturating_add(read as u64);
        }
    };
    let download = async {
        let mut total = 0u64;
        let mut buffer = [0u8; 16 * 1024];
        loop {
            let read = if let Some(limiter) = bandwidth.as_deref() {
                tokio::select! {
                    read = remote_read.read(&mut buffer) => read?,
                    _ = wait_limiter_revoke(limiter) => {
                        let _ = send.finish();
                        return Ok::<u64, io::Error>(total);
                    }
                }
            } else {
                remote_read.read(&mut buffer).await?
            };
            if read == 0 {
                let _ = send.finish();
                return Ok::<u64, io::Error>(total);
            }
            if let Some(limiter) = bandwidth.as_deref() {
                if !limiter.wait_for(read) {
                    let _ = send.finish();
                    return Ok::<u64, io::Error>(total);
                }
            }
            send.write_all(&buffer[..read]).await.map_err(io_other)?;
            total = total.saturating_add(read as u64);
        }
    };
    tokio::try_join!(upload, download)
}

async fn read_address(stream: &mut quinn::RecvStream) -> io::Result<SocksTarget> {
    let mut atyp = [0u8; 1];
    read_exact(stream, &mut atyp).await?;
    match atyp[0] {
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            read_exact(stream, &mut len).await?;
            let mut host = vec![0u8; len[0] as usize];
            read_exact(stream, &mut host).await?;
            let host = String::from_utf8(host)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid tuic domain"))?;
            let port = read_port(stream).await?;
            Ok(SocksTarget { host, port })
        }
        ATYP_IPV4 => {
            let mut bytes = [0u8; 4];
            read_exact(stream, &mut bytes).await?;
            let port = read_port(stream).await?;
            Ok(SocksTarget {
                host: Ipv4Addr::from(bytes).to_string(),
                port,
            })
        }
        ATYP_IPV6 => {
            let mut bytes = [0u8; 16];
            read_exact(stream, &mut bytes).await?;
            let port = read_port(stream).await?;
            Ok(SocksTarget {
                host: Ipv6Addr::from(bytes).to_string(),
                port,
            })
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported tuic address type",
        )),
    }
}

async fn read_port(stream: &mut quinn::RecvStream) -> io::Result<u16> {
    let mut bytes = [0u8; 2];
    read_exact(stream, &mut bytes).await?;
    Ok(u16::from_be_bytes(bytes))
}

fn parse_udp_command(input: &[u8]) -> io::Result<UdpCommand> {
    if input.len() < 2 || input[0] != VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid tuic udp command header",
        ));
    }
    match input[1] {
        COMMAND_PACKET => parse_udp_packet(input),
        COMMAND_DISSOCIATE => {
            if input.len() != 4 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid tuic dissociate command",
                ));
            }
            Ok(UdpCommand::Dissociate(u16::from_be_bytes([
                input[2], input[3],
            ])))
        }
        COMMAND_HEARTBEAT => {
            if input.len() == 2 {
                Ok(UdpCommand::Heartbeat)
            } else {
                Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid tuic heartbeat command",
                ))
            }
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported tuic udp command",
        )),
    }
}

fn parse_udp_packet(input: &[u8]) -> io::Result<UdpCommand> {
    if input.len() < 10 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "tuic udp packet command is too short",
        ));
    }
    let assoc_id = u16::from_be_bytes([input[2], input[3]]);
    let packet_id = u16::from_be_bytes([input[4], input[5]]);
    let fragment_total = input[6];
    let fragment_id = input[7];
    let payload_len = u16::from_be_bytes([input[8], input[9]]) as usize;
    let mut offset = 10usize;
    let target = parse_address_from(input, &mut offset)?;
    if input.len().saturating_sub(offset) != payload_len {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "tuic udp packet payload length mismatch",
        ));
    }
    Ok(UdpCommand::Packet(UdpPacket {
        assoc_id,
        packet_id,
        fragment_total,
        fragment_id,
        target,
        payload: input[offset..].to_vec(),
    }))
}

fn parse_address_from(input: &[u8], offset: &mut usize) -> io::Result<Option<SocksTarget>> {
    if *offset >= input.len() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "missing tuic address type",
        ));
    }
    let atyp = input[*offset];
    *offset += 1;
    match atyp {
        ATYP_NONE => Ok(None),
        ATYP_DOMAIN => {
            if *offset >= input.len() {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "missing tuic domain length",
                ));
            }
            let len = input[*offset] as usize;
            *offset += 1;
            if input.len().saturating_sub(*offset) < len + 2 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated tuic domain address",
                ));
            }
            let host = String::from_utf8(input[*offset..*offset + len].to_vec())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid tuic domain"))?;
            *offset += len;
            let port = read_port_from(input, offset)?;
            Ok(Some(SocksTarget { host, port }))
        }
        ATYP_IPV4 => {
            if input.len().saturating_sub(*offset) < 6 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated tuic ipv4 address",
                ));
            }
            let host = Ipv4Addr::new(
                input[*offset],
                input[*offset + 1],
                input[*offset + 2],
                input[*offset + 3],
            )
            .to_string();
            *offset += 4;
            let port = read_port_from(input, offset)?;
            Ok(Some(SocksTarget { host, port }))
        }
        ATYP_IPV6 => {
            if input.len().saturating_sub(*offset) < 18 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated tuic ipv6 address",
                ));
            }
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(&input[*offset..*offset + 16]);
            *offset += 16;
            let port = read_port_from(input, offset)?;
            Ok(Some(SocksTarget {
                host: Ipv6Addr::from(bytes).to_string(),
                port,
            }))
        }
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported tuic address type",
        )),
    }
}

fn read_port_from(input: &[u8], offset: &mut usize) -> io::Result<u16> {
    if input.len().saturating_sub(*offset) < 2 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "truncated tuic port",
        ));
    }
    let port = u16::from_be_bytes([input[*offset], input[*offset + 1]]);
    *offset += 2;
    Ok(port)
}

fn encode_udp_packet(
    assoc_id: u16,
    packet_id: u16,
    fragment_total: u8,
    fragment_id: u8,
    target: Option<&SocksTarget>,
    payload: &[u8],
) -> io::Result<Vec<u8>> {
    if payload.len() > u16::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "tuic udp packet payload is too large",
        ));
    }
    let address = encode_address(target)?;
    let mut output = Vec::with_capacity(10 + address.len() + payload.len());
    output.push(VERSION);
    output.push(COMMAND_PACKET);
    output.extend_from_slice(&assoc_id.to_be_bytes());
    output.extend_from_slice(&packet_id.to_be_bytes());
    output.push(fragment_total);
    output.push(fragment_id);
    output.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    output.extend_from_slice(&address);
    output.extend_from_slice(payload);
    Ok(output)
}

fn encode_address(target: Option<&SocksTarget>) -> io::Result<Vec<u8>> {
    let Some(target) = target else {
        return Ok(vec![ATYP_NONE]);
    };
    let mut output = Vec::new();
    if let Ok(ip) = target.host.parse::<IpAddr>() {
        match ip {
            IpAddr::V4(ip) => {
                output.push(ATYP_IPV4);
                output.extend_from_slice(&ip.octets());
            }
            IpAddr::V6(ip) => {
                output.push(ATYP_IPV6);
                output.extend_from_slice(&ip.octets());
            }
        }
    } else {
        if target.host.len() > u8::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "tuic domain is too long",
            ));
        }
        output.push(ATYP_DOMAIN);
        output.push(target.host.len() as u8);
        output.extend_from_slice(target.host.as_bytes());
    }
    output.extend_from_slice(&target.port.to_be_bytes());
    Ok(output)
}

fn socket_addr_to_target(addr: &SocketAddr) -> SocksTarget {
    SocksTarget {
        host: addr.ip().to_string(),
        port: addr.port(),
    }
}

async fn read_exact(stream: &mut quinn::RecvStream, output: &mut [u8]) -> io::Result<()> {
    stream.read_exact(output).await.map_err(io_other)
}

fn tuic_token_matches(
    connection: &quinn::Connection,
    uuid: &[u8; 16],
    credential: &str,
    token: &[u8; 32],
) -> io::Result<bool> {
    let mut expected = [0u8; 32];
    connection
        .export_keying_material(&mut expected, uuid, credential.as_bytes())
        .map_err(io_other)?;
    Ok(expected == *token)
}

fn parse_uuid_bytes(value: &str) -> io::Result<[u8; 16]> {
    let compact = value
        .chars()
        .filter(|value| *value != '-')
        .collect::<String>();
    if compact.len() != 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "tuic user uuid must be 16 bytes",
        ));
    }
    let mut output = [0u8; 16];
    for index in 0..16 {
        output[index] =
            u8::from_str_radix(&compact[index * 2..index * 2 + 2], 16).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "tuic user uuid is invalid")
            })?;
    }
    Ok(output)
}

fn tuic_user_map(users: &[CoreUser]) -> HashMap<[u8; 16], CoreUser> {
    users
        .iter()
        .filter_map(|user| {
            parse_uuid_bytes(&user.uuid)
                .ok()
                .map(|uuid| (uuid, user.clone()))
        })
        .collect()
}

fn io_other(error: impl std::fmt::Debug) -> io::Error {
    io::Error::new(io::ErrorKind::Other, format!("{error:?}"))
}

fn apply_tuic_congestion_control(
    transport: &mut quinn::TransportConfig,
    value: &str,
) -> io::Result<()> {
    match normalize_tuic_congestion_control(value).as_str() {
        "" | "cubic" => {
            transport
                .congestion_controller_factory(Arc::new(quinn::congestion::CubicConfig::default()));
            Ok(())
        }
        "bbr" => {
            transport
                .congestion_controller_factory(Arc::new(quinn::congestion::BbrConfig::default()));
            Ok(())
        }
        "new_reno" | "newreno" | "reno" => {
            transport.congestion_controller_factory(Arc::new(
                quinn::congestion::NewRenoConfig::default(),
            ));
            Ok(())
        }
        other => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unsupported tuic congestion_control {other}"),
        )),
    }
}

fn normalize_tuic_congestion_control(value: &str) -> String {
    value.trim().to_ascii_lowercase().replace(['-', ' '], "_")
}

#[cfg(test)]
mod tests {
    use std::fs;
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
        let cert_path = dir.join(format!("keli-core-rs-tuic-{label}-{nanos}.crt"));
        let key_path = dir.join(format!("keli-core-rs-tuic-{label}-{nanos}.key"));
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
            uuid: "11111111-1111-1111-1111-111111111111".to_string(),
            password: Some("tuic-password".to_string()),
            email: None,
            speed_limit: 0,
            device_limit: 0,
        }
    }

    fn user_b() -> CoreUser {
        CoreUser {
            id: 2,
            uuid: "22222222-2222-2222-2222-222222222222".to_string(),
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

    fn tuic_server(cert: &TestCert, listen: SocketAddr) -> TuicServer {
        TuicServer::new(TuicServerConfig {
            node_tag: "panel|tuic|1".to_string(),
            listen,
            users: vec![user()],
            routes: Vec::new(),
            cert_file: cert.cert_path.to_string_lossy().to_string(),
            key_file: cert.key_path.to_string_lossy().to_string(),
            server_name: "localhost".to_string(),
            alpn: vec!["h3".to_string()],
            reject_unknown_sni: false,
            congestion_control: String::new(),
            connect_timeout: Duration::from_secs(3),
        })
    }

    #[test]
    fn accepts_supported_tuic_congestion_controls() {
        for value in ["", "cubic", "bbr", "new_reno", "new-reno", "reno"] {
            let mut transport = quinn::TransportConfig::default();
            apply_tuic_congestion_control(&mut transport, value)
                .unwrap_or_else(|error| panic!("{value} should be supported: {error}"));
        }
    }

    #[test]
    fn rejects_unsupported_tuic_congestion_control() {
        let mut transport = quinn::TransportConfig::default();
        let error = apply_tuic_congestion_control(&mut transport, "brutal").unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::InvalidInput);
        assert!(error
            .to_string()
            .contains("unsupported tuic congestion_control"));
    }

    #[test]
    fn replaces_users_without_rebuilding_tuic_server() {
        let cert = test_cert("replace-users");
        let server = tuic_server(&cert, "127.0.0.1:0".parse().expect("addr"));
        let old_uuid = parse_uuid_bytes(&user().uuid).expect("old uuid");
        let new_user = user_b();
        let new_uuid = parse_uuid_bytes(&new_user.uuid).expect("new uuid");

        server.replace_users(vec![new_user]);

        assert!(server.user_for_uuid(&old_uuid).is_none());
        let user = server
            .user_for_uuid(&new_uuid)
            .expect("new user should authenticate");
        assert_eq!(user.uuid, "22222222-2222-2222-2222-222222222222");
        assert_eq!(user.credential(), "secret-b");
    }

    #[test]
    fn apply_user_delta_updates_tuic_users() {
        let cert = test_cert("user-delta");
        let server = tuic_server(&cert, "127.0.0.1:0".parse().expect("addr"));
        let mut updated = user();
        updated.password = Some("rotated-tuic".to_string());
        updated.speed_limit = 234;
        updated.device_limit = 6;
        let old_uuid = parse_uuid_bytes(&updated.uuid).expect("old uuid");
        let new_uuid = parse_uuid_bytes(&user_b().uuid).expect("new uuid");

        let result = server.apply_user_delta(&CoreUserDelta {
            added: vec![user_b()],
            updated: vec![updated.clone()],
            ..CoreUserDelta::default()
        });

        assert_eq!(result.added, 1);
        assert_eq!(result.updated, 1);
        assert_eq!(result.active_users, 2);
        let user = server
            .user_for_uuid(&old_uuid)
            .expect("updated tuic user should remain active");
        assert_eq!(user.credential(), "rotated-tuic");
        assert_eq!(user.speed_limit, 234);
        assert_eq!(user.device_limit, 6);
        assert!(server.user_for_uuid(&new_uuid).is_some());

        let result = server.apply_user_delta(&CoreUserDelta {
            deleted: vec![updated.uuid.clone()],
            ..CoreUserDelta::default()
        });

        assert_eq!(result.deleted, 1);
        assert_eq!(result.active_users, 1);
        assert!(server.user_for_uuid(&old_uuid).is_none());
        assert!(server.user_for_uuid(&new_uuid).is_some());
    }

    #[test]
    fn tuic_relay_waiter_observes_user_revocation() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let limiter = Arc::new(BandwidthLimiter::unlimited());
            tokio::spawn({
                let limiter = limiter.clone();
                async move {
                    tokio::time::sleep(Duration::from_millis(25)).await;
                    limiter.revoke();
                }
            });

            tokio::time::timeout(Duration::from_secs(1), wait_limiter_revoke(&limiter))
                .await
                .expect("revocation should wake waiter");
        });
    }

    #[test]
    fn unlimited_tuic_user_keeps_revoke_out_of_data_limiter() {
        let cert = test_cert("tuic-unlimited-fast-path");
        let server = tuic_server(&cert, "127.0.0.1:0".parse().expect("addr"));
        let user = user();

        let revocation = server.bandwidth.limiter_for(Some(&user));
        let bandwidth = server.bandwidth.limiter_for_limited(Some(&user));

        assert!(revocation.is_some());
        assert!(bandwidth.is_none());
        assert!(server.bandwidth.has_limiter_for(&user.uuid));
    }

    #[test]
    fn limited_tuic_user_uses_data_limiter() {
        let cert = test_cert("tuic-limited-path");
        let server = tuic_server(&cert, "127.0.0.1:0".parse().expect("addr"));
        let mut user = user();
        user.speed_limit = 10;

        let revocation = server
            .bandwidth
            .limiter_for(Some(&user))
            .expect("revocation limiter");
        let bandwidth = server
            .bandwidth
            .limiter_for_limited(Some(&user))
            .expect("data limiter");

        assert!(Arc::ptr_eq(&revocation, &bandwidth));
        assert!(bandwidth.bytes_per_second() > 0);
    }

    #[test]
    fn deleting_tuic_user_closes_existing_connection_and_reports_tail() {
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

            let server = tuic_server(&cert, "127.0.0.1:0".parse().unwrap());
            let endpoint = server.bind().expect("tuic bind");
            let server_addr = endpoint.local_addr().expect("server addr");
            let stop = Arc::new(AtomicBool::new(false));
            let server_task = tokio::spawn(server.clone().run(endpoint, stop.clone()));
            let client_endpoint = client_endpoint(cert.cert_der.clone());
            let connection = client_endpoint
                .connect(server_addr, "localhost")
                .expect("connect")
                .await
                .expect("connection");
            authenticate_client(&connection).await;

            let (mut send, mut recv) = connection.open_bi().await.expect("connect stream");
            send.write_all(&connect_command(echo_addr))
                .await
                .expect("connect command");
            send.write_all(b"x").await.expect("first payload");
            send.finish().expect("finish payload");
            let mut echoed = [0u8; 1];
            recv.read_exact(&mut echoed).await.expect("first echo");
            assert_eq!(echoed, *b"x");

            let result = server.apply_user_delta(&CoreUserDelta {
                deleted: vec![user().uuid],
                ..CoreUserDelta::default()
            });
            assert_eq!(result.deleted, 1);
            tokio::time::timeout(Duration::from_secs(2), connection.closed())
                .await
                .expect("deleted TUIC user connection should be closed");

            let records = server.drain_traffic(1);
            assert_eq!(records.len(), 1);
            assert_eq!(records[0].node_tag, "panel|tuic|1");
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

    fn auth_command_for(connection: &quinn::Connection, uuid: &str, password: &str) -> Vec<u8> {
        let uuid = parse_uuid_bytes(uuid).expect("uuid");
        let mut token = [0u8; 32];
        connection
            .export_keying_material(&mut token, &uuid, password.as_bytes())
            .expect("token");
        let mut command = vec![VERSION, COMMAND_AUTHENTICATE];
        command.extend_from_slice(&uuid);
        command.extend_from_slice(&token);
        command
    }

    fn auth_command(connection: &quinn::Connection) -> Vec<u8> {
        auth_command_for(connection, &user().uuid, "tuic-password")
    }

    fn connect_command(addr: SocketAddr) -> Vec<u8> {
        let target = socket_addr_to_target(&addr);
        let mut command = vec![VERSION, COMMAND_CONNECT];
        command.extend_from_slice(&encode_address(Some(&target)).expect("address"));
        command
    }

    async fn authenticate_client(connection: &quinn::Connection) {
        let mut auth = connection.open_uni().await.expect("auth stream");
        auth.write_all(&auth_command(connection))
            .await
            .expect("auth write");
        auth.finish().expect("auth finish");
    }

    async fn authenticate_client_with(
        connection: &quinn::Connection,
        uuid: &str,
        password: &str,
    ) -> bool {
        let mut auth = match connection.open_uni().await {
            Ok(auth) => auth,
            Err(_) => return false,
        };
        if auth
            .write_all(&auth_command_for(connection, uuid, password))
            .await
            .is_err()
        {
            return false;
        }
        auth.finish().is_ok()
    }

    async fn tuic_tcp_probe(
        server_addr: SocketAddr,
        cert_der: CertificateDer<'static>,
        uuid: &str,
        password: &str,
        echo_addr: SocketAddr,
    ) -> bool {
        let client_endpoint = client_endpoint(cert_der);
        let connection = match client_endpoint.connect(server_addr, "localhost") {
            Ok(connecting) => match connecting.await {
                Ok(connection) => connection,
                Err(_) => return false,
            },
            Err(_) => return false,
        };
        if !authenticate_client_with(&connection, uuid, password).await {
            return false;
        }
        let (mut send, mut recv) = match connection.open_bi().await {
            Ok(streams) => streams,
            Err(_) => return false,
        };
        if send.write_all(&connect_command(echo_addr)).await.is_err() {
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

    #[test]
    fn apply_user_delta_changes_tuic_auth_without_rebinding_listener() {
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
                for _ in 0..2 {
                    let (mut stream, _) = echo.accept().await.expect("echo accept");
                    let mut byte = [0u8; 1];
                    stream.read_exact(&mut byte).await.expect("echo read");
                    stream.write_all(&byte).await.expect("echo write");
                }
            });

            let server = tuic_server(&cert, "127.0.0.1:0".parse().unwrap());
            let endpoint = server.bind().expect("tuic bind");
            let server_addr = endpoint.local_addr().expect("server addr");
            let stop = Arc::new(AtomicBool::new(false));
            let server_task = tokio::spawn(server.clone().run(endpoint, stop.clone()));

            assert!(
                tuic_tcp_probe(
                    server_addr,
                    cert.cert_der.clone(),
                    &user().uuid,
                    "tuic-password",
                    echo_addr,
                )
                .await,
                "original tuic user should authenticate before delta"
            );

            let result = server.apply_user_delta(&CoreUserDelta {
                added: vec![user_b()],
                deleted: vec![user().uuid],
                ..CoreUserDelta::default()
            });

            assert_eq!(result.added, 1);
            assert_eq!(result.deleted, 1);
            assert_eq!(result.active_users, 1);
            assert!(
                !tuic_tcp_probe(
                    server_addr,
                    cert.cert_der.clone(),
                    &user().uuid,
                    "tuic-password",
                    echo_addr,
                )
                .await,
                "deleted tuic user should fail new authentication after delta"
            );
            assert!(
                tuic_tcp_probe(
                    server_addr,
                    cert.cert_der.clone(),
                    &user_b().uuid,
                    "secret-b",
                    echo_addr,
                )
                .await,
                "added tuic user should authenticate on the same listener after delta"
            );

            stop.store(true, Ordering::SeqCst);
            server_task.await.expect("server task");
            echo_task.await.expect("echo task");
        });
    }

    #[test]
    fn parses_uuid_bytes() {
        assert_eq!(
            parse_uuid_bytes("11111111-1111-1111-1111-111111111111").unwrap(),
            [0x11; 16]
        );
    }

    #[test]
    fn parses_tuic_udp_packet_commands() {
        let target = SocksTarget {
            host: "::1".to_string(),
            port: 53,
        };
        let encoded = encode_udp_packet(7, 11, 1, 0, Some(&target), b"dns").unwrap();
        let parsed = parse_udp_command(&encoded).unwrap();

        assert_eq!(
            parsed,
            UdpCommand::Packet(UdpPacket {
                assoc_id: 7,
                packet_id: 11,
                fragment_total: 1,
                fragment_id: 0,
                target: Some(target),
                payload: b"dns".to_vec(),
            })
        );
    }

    #[test]
    fn reassembles_tuic_udp_fragments() {
        let target = SocksTarget {
            host: "127.0.0.1".to_string(),
            port: 53,
        };
        let first =
            match parse_udp_command(&encode_udp_packet(7, 12, 2, 0, Some(&target), b"he").unwrap())
                .unwrap()
            {
                UdpCommand::Packet(packet) => packet,
                _ => panic!("expected packet"),
            };
        let second = match parse_udp_command(&encode_udp_packet(7, 12, 2, 1, None, b"llo").unwrap())
            .unwrap()
        {
            UdpCommand::Packet(packet) => packet,
            _ => panic!("expected packet"),
        };
        let mut fragments = UdpFragmentStore::default();

        assert!(fragments.push(second).unwrap().is_none());
        let packet = fragments
            .push(first)
            .unwrap()
            .expect("complete fragmented packet");

        assert_eq!(packet.assoc_id, 7);
        assert_eq!(packet.packet_id, 12);
        assert_eq!(packet.fragment_total, 1);
        assert_eq!(packet.fragment_id, 0);
        assert_eq!(packet.target, Some(target));
        assert_eq!(packet.payload, b"hello");
    }

    #[test]
    fn proxies_tuic_tcp_and_records_user_traffic() {
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

            let server = tuic_server(&cert, "127.0.0.1:0".parse().unwrap());
            let endpoint = server.bind().expect("tuic bind");
            let server_addr = endpoint.local_addr().expect("server addr");
            let stop = Arc::new(AtomicBool::new(false));
            let server_task = tokio::spawn(server.clone().run(endpoint, stop.clone()));

            let client_endpoint = client_endpoint(cert.cert_der.clone());
            let connection = client_endpoint
                .connect(server_addr, "localhost")
                .expect("connect")
                .await
                .expect("connection");
            authenticate_client(&connection).await;

            let (mut send, mut recv) = connection.open_bi().await.expect("connect stream");
            send.write_all(&connect_command(echo_addr))
                .await
                .expect("connect command");
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
            assert_eq!(records[0].node_tag, "panel|tuic|1");
            assert_eq!(records[0].user_uuid, "11111111-1111-1111-1111-111111111111");
            assert_eq!(records[0].user_id, Some(1));
            assert_eq!(records[0].upload, 4);
            assert_eq!(records[0].download, 4);

            stop.store(true, Ordering::SeqCst);
            server_task.await.expect("server task");
        });
    }

    #[test]
    fn proxies_tuic_udp_datagrams_and_records_user_traffic() {
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

            let server = tuic_server(&cert, "127.0.0.1:0".parse().unwrap());
            let endpoint = server.bind().expect("tuic bind");
            let server_addr = endpoint.local_addr().expect("server addr");
            let stop = Arc::new(AtomicBool::new(false));
            let server_task = tokio::spawn(server.clone().run(endpoint, stop.clone()));

            let client_endpoint = client_endpoint(cert.cert_der.clone());
            let connection = client_endpoint
                .connect(server_addr, "localhost")
                .expect("connect")
                .await
                .expect("connection");
            authenticate_client(&connection).await;

            let target = socket_addr_to_target(&echo_addr);
            let command = encode_udp_packet(12, 1, 1, 0, Some(&target), b"pong").unwrap();
            connection
                .send_datagram_wait(Bytes::from(command))
                .await
                .expect("send udp packet");
            let response = tokio::time::timeout(Duration::from_secs(3), connection.read_datagram())
                .await
                .expect("udp response timeout")
                .expect("udp response");
            let response = parse_udp_command(&response).expect("response command");

            let UdpCommand::Packet(packet) = response else {
                panic!("expected udp packet response");
            };
            assert_eq!(packet.assoc_id, 12);
            assert_eq!(packet.fragment_total, 1);
            assert_eq!(packet.fragment_id, 0);
            assert_eq!(packet.payload, b"pong");
            assert_eq!(
                packet.target,
                Some(SocksTarget {
                    host: "127.0.0.1".to_string(),
                    port: echo_addr.port()
                })
            );

            connection.close(0u32.into(), b"done");
            echo_task.await.expect("echo task");

            tokio::time::sleep(Duration::from_millis(50)).await;
            let records = server.drain_traffic(1);
            assert_eq!(records.len(), 1);
            assert_eq!(records[0].node_tag, "panel|tuic|1");
            assert_eq!(records[0].user_uuid, "11111111-1111-1111-1111-111111111111");
            assert_eq!(records[0].upload, 4);
            assert_eq!(records[0].download, 4);

            stop.store(true, Ordering::SeqCst);
            server_task.await.expect("server task");
        });
    }

    #[test]
    fn proxies_tuic_udp_unidirectional_streams_and_records_user_traffic() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("runtime");
        runtime.block_on(async {
            let cert = test_cert("udp-stream");
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

            let server = tuic_server(&cert, "127.0.0.1:0".parse().unwrap());
            let endpoint = server.bind().expect("tuic bind");
            let server_addr = endpoint.local_addr().expect("server addr");
            let stop = Arc::new(AtomicBool::new(false));
            let server_task = tokio::spawn(server.clone().run(endpoint, stop.clone()));

            let client_endpoint = client_endpoint(cert.cert_der.clone());
            let connection = client_endpoint
                .connect(server_addr, "localhost")
                .expect("connect")
                .await
                .expect("connection");
            authenticate_client(&connection).await;

            let target = socket_addr_to_target(&echo_addr);
            let command = encode_udp_packet(13, 1, 1, 0, Some(&target), b"quic").unwrap();
            let mut send = connection.open_uni().await.expect("packet stream");
            send.write_all(&command).await.expect("packet write");
            send.finish().expect("packet finish");

            let mut response_stream =
                tokio::time::timeout(Duration::from_secs(3), connection.accept_uni())
                    .await
                    .expect("udp response timeout")
                    .expect("udp response stream");
            let response = response_stream
                .read_to_end(UDP_PACKET_BUFFER_SIZE + 512)
                .await
                .expect("udp response read");
            let response = parse_udp_command(&response).expect("response command");

            let UdpCommand::Packet(packet) = response else {
                panic!("expected udp packet response");
            };
            assert_eq!(packet.assoc_id, 13);
            assert_eq!(packet.fragment_total, 1);
            assert_eq!(packet.fragment_id, 0);
            assert_eq!(packet.payload, b"quic");
            assert_eq!(
                packet.target,
                Some(SocksTarget {
                    host: "127.0.0.1".to_string(),
                    port: echo_addr.port()
                })
            );

            connection.close(0u32.into(), b"done");
            echo_task.await.expect("echo task");

            tokio::time::sleep(Duration::from_millis(50)).await;
            let records = server.drain_traffic(1);
            assert_eq!(records.len(), 1);
            assert_eq!(records[0].node_tag, "panel|tuic|1");
            assert_eq!(records[0].user_uuid, "11111111-1111-1111-1111-111111111111");
            assert_eq!(records[0].upload, 4);
            assert_eq!(records[0].download, 4);

            stop.store(true, Ordering::SeqCst);
            server_task.await.expect("server task");
        });
    }
}
