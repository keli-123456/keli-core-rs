use std::collections::HashMap;
use std::io::{self, IoSlice, Read, Write};
use std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket,
};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use arc_swap::ArcSwap;
use md5::Md5;
use sha2::{Digest, Sha256};

use crate::limits::{
    sync_user_limit_delta, BandwidthLimiter, UserBandwidthLimiters, UserSessionGuard,
    UserSessionTracker,
};
use crate::outbound::recv_udp_response;
use crate::socket_bind::bind_dual_stack_tcp_listener;
use crate::socks5::SocksTarget;
use crate::stream::{join_async_relay, spawn_async_relay};
use crate::traffic::{SharedTrafficRegistry, TrafficRegistry};
use crate::user::{
    apply_user_delta_to_keyed_arc_map, CoreUser, CoreUserDelta, CoreUserDeltaResult,
};
use crate::{send_udp_outbound, RouteDecision, RouteDispatcher};

const CMD_WASTE: u8 = 0;
const CMD_SYN: u8 = 1;
const CMD_PSH: u8 = 2;
const CMD_FIN: u8 = 3;
const CMD_SETTINGS: u8 = 4;
const CMD_UPDATE_PADDING_SCHEME: u8 = 6;
const CMD_SYNACK: u8 = 7;
const CMD_HEART_REQUEST: u8 = 8;
const CMD_HEART_RESPONSE: u8 = 9;
const CMD_SERVER_SETTINGS: u8 = 10;
const FRAME_HEADER_LEN: usize = 7;
const MAX_FRAME_PAYLOAD: usize = 0xffff;
const MAX_UDP_PACKET_SIZE: usize = 65_535;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;
const UOT_ATYP_IPV4: u8 = 0x00;
const UOT_ATYP_IPV6: u8 = 0x01;
const UOT_ATYP_DOMAIN: u8 = 0x02;
const UOT_MAGIC_DOMAIN: &str = "udp-over-tcp.arpa";

#[derive(Clone, Debug)]
pub struct AnyTlsServerConfig {
    pub node_tag: String,
    pub listen: SocketAddr,
    pub users: Vec<CoreUser>,
    pub routes: Vec<crate::RouteRule>,
    pub connect_timeout: Duration,
    pub padding_scheme: Vec<String>,
}

#[derive(Clone, Debug)]
pub struct AnyTlsServer {
    config: AnyTlsServerConfig,
    users: Arc<ArcSwap<HashMap<[u8; 32], Arc<CoreUser>>>>,
    user_updates: Arc<Mutex<()>>,
    router: RouteDispatcher,
    traffic: SharedTrafficRegistry,
    sessions: UserSessionTracker,
    bandwidth: UserBandwidthLimiters,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct FrameHeader {
    command: u8,
    stream_id: u32,
    len: usize,
}

#[derive(Debug)]
struct AnyTlsSession {
    user: Arc<CoreUser>,
    client_ip: Option<IpAddr>,
    writer: Arc<Mutex<TcpStream>>,
    remotes: HashMap<u32, AnyTlsRemote>,
    workers: Vec<tokio::task::JoinHandle<()>>,
    traffic: Arc<AnyTlsTrafficCounters>,
    bandwidth: Option<Arc<BandwidthLimiter>>,
    settings_done: bool,
}

#[derive(Debug, Default)]
struct AnyTlsTrafficCounters {
    upload: AtomicU64,
    download: AtomicU64,
}

impl AnyTlsTrafficCounters {
    fn add_upload(&self, bytes: u64) {
        self.upload.fetch_add(bytes, Ordering::Relaxed);
    }

    fn add_download(&self, bytes: u64) {
        self.download.fetch_add(bytes, Ordering::Relaxed);
    }

    fn add(&self, upload: u64, download: u64) {
        if upload > 0 {
            self.add_upload(upload);
        }
        if download > 0 {
            self.add_download(download);
        }
    }

    fn snapshot(&self) -> (u64, u64) {
        (
            self.upload.load(Ordering::Relaxed),
            self.download.load(Ordering::Relaxed),
        )
    }
}

#[derive(Debug)]
enum AnyTlsRemote {
    Tcp(TcpStream),
    Udp(AnyTlsUdpStream),
}

#[derive(Debug)]
struct AnyTlsUdpStream {
    target: Option<SocksTarget>,
    connect_mode: bool,
    pending: Vec<u8>,
    state: AnyTlsUdpRelayState,
}

#[derive(Debug)]
struct AnyTlsUdpRelayState {
    ipv4: Option<UdpSocket>,
    ipv6: Option<UdpSocket>,
    timeout: Duration,
}

impl AnyTlsServer {
    pub fn new(config: AnyTlsServerConfig) -> Self {
        Self::with_traffic(config, TrafficRegistry::shared())
    }

    pub fn with_traffic(config: AnyTlsServerConfig, traffic: SharedTrafficRegistry) -> Self {
        Self::with_shared_limits(
            config,
            traffic,
            UserSessionTracker::default(),
            UserBandwidthLimiters::default(),
        )
    }

    pub fn with_shared_limits(
        mut config: AnyTlsServerConfig,
        traffic: SharedTrafficRegistry,
        sessions: UserSessionTracker,
        bandwidth: UserBandwidthLimiters,
    ) -> Self {
        let users = anytls_user_map(&config.users);
        let router =
            RouteDispatcher::with_connect_timeout(config.routes.clone(), config.connect_timeout);
        config.users.clear();
        config.routes.clear();
        Self {
            router,
            config,
            users: Arc::new(ArcSwap::from_pointee(users)),
            user_updates: Arc::new(Mutex::new(())),
            traffic,
            sessions,
            bandwidth,
        }
    }

    pub fn bind(&self) -> io::Result<TcpListener> {
        bind_dual_stack_tcp_listener(self.config.listen)
    }

    pub fn handle_tcp_client(&self, mut client: TcpStream) -> io::Result<()> {
        let client_ip = client.peer_addr().ok().map(|addr| addr.ip());
        let user = self.read_auth(&mut client)?;
        let _session = self.acquire_user_session(&user, client_ip)?;
        let _connection = self
            .bandwidth
            .register_tcp_connection(Some(&user.uuid), &[&client])?;
        let writer = Arc::new(Mutex::new(client.try_clone()?));
        let mut session = AnyTlsSession {
            bandwidth: self.bandwidth.limiter_for_limited(Some(&user)),
            user,
            client_ip,
            writer,
            remotes: HashMap::new(),
            workers: Vec::new(),
            traffic: Arc::new(AnyTlsTrafficCounters::default()),
            settings_done: false,
        };

        let result = self.read_frames(&mut client, &mut session);
        for (_, remote) in session.remotes.drain() {
            if let AnyTlsRemote::Tcp(remote) = remote {
                let _ = remote.shutdown(Shutdown::Both);
            }
        }
        for worker in session.workers {
            let _ = join_async_relay(worker, "anytls downlink worker panicked");
        }
        let (upload, download) = session.traffic.snapshot();
        if upload > 0 || download > 0 {
            self.traffic.add_with_user_id(
                self.config.node_tag.clone(),
                session.user.uuid.clone(),
                Some(session.user.id),
                upload,
                download,
                session.client_ip,
            );
        }
        result
    }

    pub fn drain_traffic(&self, minimum_bytes: u64) -> Vec<crate::traffic::TrafficDelta> {
        self.traffic.drain_minimum(minimum_bytes)
    }

    pub fn replace_users(&self, users: Vec<CoreUser>) {
        self.bandwidth.sync_users(&users);
        let _guard = self
            .user_updates
            .lock()
            .expect("anytls users write lock poisoned");
        self.users.store(Arc::new(anytls_user_map(&users)));
    }

    pub fn replace_routes(&self, routes: Vec<crate::RouteRule>) {
        self.router.replace_routes(routes);
    }

    pub fn apply_user_delta(&self, delta: &CoreUserDelta) -> CoreUserDeltaResult {
        sync_delta_bandwidth(&self.bandwidth, &self.sessions, delta);
        let _guard = self
            .user_updates
            .lock()
            .expect("anytls users write lock poisoned");
        let mut current = self.users.load_full().as_ref().clone();
        let result = apply_user_delta_to_keyed_arc_map(&mut current, delta, |user| {
            Some(sha256(user.credential()))
        });
        self.users.store(Arc::new(current));
        result
    }

    fn user_for_password_hash(&self, password_hash: &[u8; 32]) -> Option<Arc<CoreUser>> {
        self.users.load().get(password_hash).cloned()
    }

    fn read_auth(&self, client: &mut TcpStream) -> io::Result<Arc<CoreUser>> {
        let mut auth = [0u8; 34];
        client.read_exact(&mut auth)?;
        let mut password_hash = [0u8; 32];
        password_hash.copy_from_slice(&auth[..32]);
        let Some(user) = self.user_for_password_hash(&password_hash) else {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "unknown anytls user",
            ));
        };
        let padding_len = u16::from_be_bytes([auth[32], auth[33]]) as usize;
        if padding_len > 0 {
            discard(client, padding_len)?;
        }
        Ok(user)
    }

    fn read_frames(&self, client: &mut TcpStream, session: &mut AnyTlsSession) -> io::Result<()> {
        loop {
            let header = match read_frame_header(client) {
                Ok(header) => header,
                Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
                Err(error) if error.kind() == io::ErrorKind::ConnectionReset => return Ok(()),
                Err(error) if error.kind() == io::ErrorKind::ConnectionAborted => return Ok(()),
                Err(error) => return Err(error),
            };
            let body = match read_frame_body(client, header.len) {
                Ok(body) => body,
                Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
                Err(error) if error.kind() == io::ErrorKind::ConnectionReset => return Ok(()),
                Err(error) if error.kind() == io::ErrorKind::ConnectionAborted => return Ok(()),
                Err(error) => return Err(error),
            };
            match header.command {
                CMD_WASTE => {}
                CMD_SETTINGS => {
                    if !session.settings_done {
                        self.handle_settings(session, &body)?;
                        session.settings_done = true;
                    }
                }
                CMD_HEART_REQUEST => {
                    write_frame(&session.writer, CMD_HEART_RESPONSE, 0, &[])?;
                }
                CMD_SYN => {
                    self.handle_syn(session, header.stream_id, body)?;
                }
                CMD_PSH => {
                    self.handle_psh(session, header.stream_id, body)?;
                }
                CMD_FIN => {
                    if let Some(remote) = session.remotes.remove(&header.stream_id) {
                        if let AnyTlsRemote::Tcp(remote) = remote {
                            let _ = remote.shutdown(Shutdown::Write);
                        }
                    }
                }
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "unsupported anytls frame command",
                    ));
                }
            }
        }
    }

    fn handle_settings(&self, session: &AnyTlsSession, body: &[u8]) -> io::Result<()> {
        let settings = parse_settings(body);
        if settings
            .get("v")
            .map(|value| value.trim() == "2")
            .unwrap_or(false)
        {
            write_frame(&session.writer, CMD_SERVER_SETTINGS, 0, b"v=2")?;
        }

        let scheme = padding_scheme_text(&self.config.padding_scheme);
        if scheme.is_empty() {
            return Ok(());
        }
        let Some(client_md5) = settings.get("padding-md5").map(|value| value.trim()) else {
            return Ok(());
        };
        if !client_md5.eq_ignore_ascii_case(&md5_hex(scheme.as_bytes())) {
            write_frame(
                &session.writer,
                CMD_UPDATE_PADDING_SCHEME,
                0,
                scheme.as_bytes(),
            )?;
        }
        Ok(())
    }

    fn handle_psh(
        &self,
        session: &mut AnyTlsSession,
        stream_id: u32,
        body: Vec<u8>,
    ) -> io::Result<()> {
        if body.is_empty() {
            return Ok(());
        }

        if let Some(remote) = session.remotes.remove(&stream_id) {
            match remote {
                AnyTlsRemote::Tcp(mut remote) => {
                    if let Some(limiter) = session.bandwidth.as_deref() {
                        if !limiter.wait_for(body.len()) {
                            return Ok(());
                        }
                    }
                    remote.write_all(&body)?;
                    session.traffic.add_upload(body.len() as u64);
                    session.remotes.insert(stream_id, AnyTlsRemote::Tcp(remote));
                }
                AnyTlsRemote::Udp(mut udp) => {
                    let keep_open = self.handle_udp_psh(session, stream_id, &mut udp, &body)?;
                    if keep_open {
                        session.remotes.insert(stream_id, AnyTlsRemote::Udp(udp));
                    }
                }
            }
            return Ok(());
        }

        let (target, consumed) = parse_socks_addr(&body)?;
        if is_uot_magic_target(&target) {
            let mut udp = AnyTlsUdpStream::new(self.config.connect_timeout);
            write_frame(&session.writer, CMD_SYNACK, stream_id, &[])?;
            let keep_open = if consumed < body.len() {
                self.handle_udp_psh(session, stream_id, &mut udp, &body[consumed..])?
            } else {
                true
            };
            if keep_open {
                session.remotes.insert(stream_id, AnyTlsRemote::Udp(udp));
            }
            return Ok(());
        }
        self.open_tcp_remote(session, stream_id, target, &body[consumed..])
    }

    fn handle_syn(
        &self,
        session: &mut AnyTlsSession,
        stream_id: u32,
        body: Vec<u8>,
    ) -> io::Result<()> {
        if body.is_empty() {
            write_frame(&session.writer, CMD_SYNACK, stream_id, &[])?;
            return Ok(());
        }

        let (target, consumed) = parse_socks_addr(&body)?;
        if is_uot_magic_target(&target) {
            let mut udp = AnyTlsUdpStream::new(self.config.connect_timeout);
            write_frame(&session.writer, CMD_SYNACK, stream_id, &[])?;
            let keep_open = if consumed < body.len() {
                self.handle_udp_psh(session, stream_id, &mut udp, &body[consumed..])?
            } else {
                true
            };
            if keep_open {
                session.remotes.insert(stream_id, AnyTlsRemote::Udp(udp));
            }
            return Ok(());
        }

        self.open_tcp_remote(session, stream_id, target, &body[consumed..])
    }

    fn open_tcp_remote(
        &self,
        session: &mut AnyTlsSession,
        stream_id: u32,
        target: SocksTarget,
        initial_payload: &[u8],
    ) -> io::Result<()> {
        let remote = self.router.connect_tcp(&target, initial_payload)?;
        let remote_read = remote.try_clone()?;
        remote_read.set_nonblocking(true)?;
        let writer = session.writer.clone();
        let traffic = session.traffic.clone();
        session.workers.push(spawn_async_relay(
            "keli-core-anytls-downlink",
            pump_downlink_async(stream_id, remote_read, writer, traffic),
        )?);
        session.remotes.insert(stream_id, AnyTlsRemote::Tcp(remote));
        write_frame(&session.writer, CMD_SYNACK, stream_id, &[])?;

        if !initial_payload.is_empty() {
            if let Some(limiter) = session.bandwidth.as_deref() {
                if !limiter.wait_for(initial_payload.len()) {
                    return Ok(());
                }
            }
            if let Some(AnyTlsRemote::Tcp(remote)) = session.remotes.get_mut(&stream_id) {
                remote.write_all(initial_payload)?;
                session.traffic.add_upload(initial_payload.len() as u64);
            }
        }

        Ok(())
    }

    fn handle_udp_psh(
        &self,
        session: &mut AnyTlsSession,
        stream_id: u32,
        udp: &mut AnyTlsUdpStream,
        body: &[u8],
    ) -> io::Result<bool> {
        udp.pending.extend_from_slice(body);
        if udp.target.is_none() {
            let Some((connect_mode, target, consumed)) = parse_uot_request(&udp.pending)? else {
                return Ok(true);
            };
            udp.connect_mode = connect_mode;
            udp.target = Some(target);
            udp.pending.drain(..consumed);
        }

        loop {
            let Some((target, payload, consumed)) =
                parse_uot_packet(&udp.pending, udp.connect_mode, udp.target.as_ref())?
            else {
                break;
            };
            let (upload, download) =
                self.forward_udp_packet(session, stream_id, udp, &target, &payload)?;
            session.traffic.add(upload, download);
            udp.pending.drain(..consumed);
        }

        Ok(true)
    }

    fn forward_udp_packet(
        &self,
        session: &AnyTlsSession,
        stream_id: u32,
        udp: &mut AnyTlsUdpStream,
        target: &SocksTarget,
        payload: &[u8],
    ) -> io::Result<(u64, u64)> {
        let decision = self.router.decide_udp(&target.host, target.port, payload);
        let outbound = match &decision {
            RouteDecision::Direct => None,
            RouteDecision::Outbound(outbound) => Some(outbound),
            RouteDecision::Block => return Ok((0, 0)),
            RouteDecision::UnsupportedOutbound(tag) => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!("outbound route {tag} is not implemented"),
                ));
            }
        };

        if let Some(limiter) = session.bandwidth.as_deref() {
            if !limiter.wait_for(payload.len()) {
                return Ok((0, 0));
            }
        }

        if let Some(outbound) = outbound {
            return match send_udp_outbound(outbound, target, payload, self.config.connect_timeout) {
                Ok((source, response)) => {
                    let packet = encode_uot_packet(udp.connect_mode, source, &response);
                    write_frame(&session.writer, CMD_PSH, stream_id, &packet)?;
                    Ok((payload.len() as u64, response.len() as u64))
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    Ok((payload.len() as u64, 0))
                }
                Err(error) => Err(error),
            };
        }

        let remote_addr = resolve_udp_target(&target)?;
        let socket = udp.state.socket_for(remote_addr)?;
        socket.send_to(payload, remote_addr)?;
        let mut response = vec![0u8; MAX_UDP_PACKET_SIZE];
        let download = match recv_udp_response(socket, &mut response) {
            Ok((read, source)) => {
                let packet = encode_uot_packet(udp.connect_mode, source, &response[..read]);
                write_frame(&session.writer, CMD_PSH, stream_id, &packet)?;
                read as u64
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                0
            }
            Err(error) => return Err(error),
        };

        Ok((payload.len() as u64, download))
    }

    fn acquire_user_session(
        &self,
        user: &CoreUser,
        client_ip: Option<IpAddr>,
    ) -> io::Result<Option<UserSessionGuard>> {
        match self
            .sessions
            .try_acquire_for_node_ip(&self.config.node_tag, Some(user), client_ip)
        {
            Ok(guard) => Ok(guard),
            Err(error) => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                error.to_string(),
            )),
        }
    }
}

fn sync_delta_bandwidth(
    bandwidth: &UserBandwidthLimiters,
    sessions: &UserSessionTracker,
    delta: &CoreUserDelta,
) {
    sync_user_limit_delta(bandwidth, sessions, delta);
}

async fn pump_downlink_async(
    stream_id: u32,
    remote: TcpStream,
    writer: Arc<Mutex<TcpStream>>,
    traffic: Arc<AnyTlsTrafficCounters>,
) {
    let mut remote = match tokio::net::TcpStream::from_std(remote) {
        Ok(remote) => remote,
        Err(_) => {
            let _ = write_frame(&writer, CMD_FIN, stream_id, &[]);
            return;
        }
    };
    let mut buffer = [0u8; 16 * 1024];
    loop {
        let read = match tokio::io::AsyncReadExt::read(&mut remote, &mut buffer).await {
            Ok(0) => break,
            Ok(read) => read,
            Err(_) => break,
        };
        traffic.add_download(read as u64);
        if write_frame(&writer, CMD_PSH, stream_id, &buffer[..read]).is_err() {
            return;
        }
    }
    let _ = write_frame(&writer, CMD_FIN, stream_id, &[]);
}

impl AnyTlsUdpStream {
    fn new(timeout: Duration) -> Self {
        Self {
            target: None,
            connect_mode: false,
            pending: Vec::new(),
            state: AnyTlsUdpRelayState::new(timeout),
        }
    }
}

impl AnyTlsUdpRelayState {
    fn new(timeout: Duration) -> Self {
        Self {
            ipv4: None,
            ipv6: None,
            timeout,
        }
    }

    fn socket_for(&mut self, remote: SocketAddr) -> io::Result<&UdpSocket> {
        let slot = if remote.is_ipv4() {
            &mut self.ipv4
        } else {
            &mut self.ipv6
        };
        if slot.is_none() {
            let socket = UdpSocket::bind(udp_bind_addr_for_remote(remote))?;
            socket.set_read_timeout(Some(self.timeout))?;
            *slot = Some(socket);
        }
        Ok(slot.as_ref().expect("udp socket initialized"))
    }
}

fn parse_uot_request(input: &[u8]) -> io::Result<Option<(bool, SocksTarget, usize)>> {
    if input.is_empty() {
        return Ok(None);
    }
    let connect_mode = input[0] != 0;
    let Some((target, consumed)) = parse_socks_or_uot_addr(&input[1..])? else {
        return Ok(None);
    };
    Ok(Some((connect_mode, target, consumed + 1)))
}

fn parse_uot_packet(
    input: &[u8],
    connect_mode: bool,
    default_target: Option<&SocksTarget>,
) -> io::Result<Option<(SocksTarget, Vec<u8>, usize)>> {
    if connect_mode {
        let Some(target) = default_target.cloned() else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "anytls uot connect packet missing target",
            ));
        };
        if input.len() < 2 {
            return Ok(None);
        }
        let len = u16::from_be_bytes([input[0], input[1]]) as usize;
        if input.len() < 2 + len {
            return Ok(None);
        }
        return Ok(Some((target, input[2..2 + len].to_vec(), 2 + len)));
    }

    let Some((target, consumed)) = parse_uot_or_socks_addr(input)? else {
        return Ok(None);
    };
    if input.len() < consumed + 2 {
        return Ok(None);
    }
    let len = u16::from_be_bytes([input[consumed], input[consumed + 1]]) as usize;
    let payload_offset = consumed + 2;
    if input.len() < payload_offset + len {
        return Ok(None);
    }
    Ok(Some((
        target,
        input[payload_offset..payload_offset + len].to_vec(),
        payload_offset + len,
    )))
}

fn parse_socks_or_uot_addr(input: &[u8]) -> io::Result<Option<(SocksTarget, usize)>> {
    match parse_socks_addr(input) {
        Ok(parsed) => Ok(Some(parsed)),
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => Ok(None),
        Err(_) => match parse_uot_addr(input) {
            Ok(parsed) => Ok(Some(parsed)),
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => Ok(None),
            Err(error) => Err(error),
        },
    }
}

fn parse_uot_or_socks_addr(input: &[u8]) -> io::Result<Option<(SocksTarget, usize)>> {
    match parse_uot_addr(input) {
        Ok(parsed) => Ok(Some(parsed)),
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => Ok(None),
        Err(_) => match parse_socks_addr(input) {
            Ok(parsed) => Ok(Some(parsed)),
            Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => Ok(None),
            Err(error) => Err(error),
        },
    }
}

fn parse_uot_addr(bytes: &[u8]) -> io::Result<(SocksTarget, usize)> {
    if bytes.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "empty anytls uot target",
        ));
    }

    let mut offset = 1usize;
    let host = match bytes[0] {
        UOT_ATYP_IPV4 => {
            if bytes.len() < offset + 4 + 2 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "uot ipv4 target",
                ));
            }
            let mut ip = [0u8; 4];
            ip.copy_from_slice(&bytes[offset..offset + 4]);
            offset += 4;
            Ipv4Addr::from(ip).to_string()
        }
        UOT_ATYP_IPV6 => {
            if bytes.len() < offset + 16 + 2 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "uot ipv6 target",
                ));
            }
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&bytes[offset..offset + 16]);
            offset += 16;
            Ipv6Addr::from(ip).to_string()
        }
        UOT_ATYP_DOMAIN => {
            if bytes.len() <= offset {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "uot domain len",
                ));
            }
            let len = bytes[offset] as usize;
            offset += 1;
            if bytes.len() < offset + len + 2 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "uot domain target",
                ));
            }
            let host = String::from_utf8(bytes[offset..offset + len].to_vec())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid uot domain"))?;
            offset += len;
            host
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported anytls uot address type",
            ));
        }
    };
    let port = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
    offset += 2;
    Ok((SocksTarget { host, port }, offset))
}

fn encode_uot_packet(connect_mode: bool, source: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(22 + payload.len());
    if !connect_mode {
        encode_uot_addr(source, &mut output);
    }
    output.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    output.extend_from_slice(payload);
    output
}

fn encode_uot_addr(source: SocketAddr, output: &mut Vec<u8>) {
    match source.ip() {
        IpAddr::V4(ip) => {
            output.push(UOT_ATYP_IPV4);
            output.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            output.push(UOT_ATYP_IPV6);
            output.extend_from_slice(&ip.octets());
        }
    }
    output.extend_from_slice(&source.port().to_be_bytes());
}

fn parse_settings(body: &[u8]) -> HashMap<String, String> {
    String::from_utf8_lossy(body)
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() {
                return None;
            }
            let (key, value) = line.split_once('=')?;
            Some((key.trim().to_string(), value.trim().to_string()))
        })
        .collect()
}

fn padding_scheme_text(lines: &[String]) -> String {
    lines
        .iter()
        .map(|line| line.trim())
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join("\n")
}

fn md5_hex(bytes: &[u8]) -> String {
    let digest = Md5::digest(bytes);
    let mut output = String::with_capacity(digest.len() * 2);
    for byte in digest {
        output.push(hex_digit(byte >> 4));
        output.push(hex_digit(byte & 0x0f));
    }
    output
}

fn hex_digit(value: u8) -> char {
    match value {
        0..=9 => (b'0' + value) as char,
        10..=15 => (b'a' + (value - 10)) as char,
        _ => unreachable!("hex nibble is always below 16"),
    }
}

fn read_frame_header<R: Read>(reader: &mut R) -> io::Result<FrameHeader> {
    let mut header = [0u8; FRAME_HEADER_LEN];
    reader.read_exact(&mut header)?;
    Ok(FrameHeader {
        command: header[0],
        stream_id: u32::from_be_bytes([header[1], header[2], header[3], header[4]]),
        len: u16::from_be_bytes([header[5], header[6]]) as usize,
    })
}

fn read_frame_body<R: Read>(reader: &mut R, len: usize) -> io::Result<Vec<u8>> {
    if len > MAX_FRAME_PAYLOAD {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "anytls frame payload too large",
        ));
    }
    let mut body = vec![0u8; len];
    reader.read_exact(&mut body)?;
    Ok(body)
}

fn write_frame(
    writer: &Arc<Mutex<TcpStream>>,
    command: u8,
    stream_id: u32,
    payload: &[u8],
) -> io::Result<()> {
    if payload.len() > MAX_FRAME_PAYLOAD {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "anytls frame payload too large",
        ));
    }
    let mut stream = writer.lock().expect("anytls writer lock poisoned");
    let header = [
        command,
        (stream_id >> 24) as u8,
        (stream_id >> 16) as u8,
        (stream_id >> 8) as u8,
        stream_id as u8,
        (payload.len() >> 8) as u8,
        payload.len() as u8,
    ];
    write_all_vectored(&mut *stream, &header, payload)?;
    stream.flush()
}

fn write_all_vectored<W: Write>(writer: &mut W, header: &[u8], payload: &[u8]) -> io::Result<()> {
    let mut header_written = 0usize;
    let mut payload_written = 0usize;
    while header_written < header.len() || payload_written < payload.len() {
        let written = if header_written < header.len() {
            let bufs = [
                IoSlice::new(&header[header_written..]),
                IoSlice::new(&payload[payload_written..]),
            ];
            writer.write_vectored(&bufs)?
        } else {
            writer.write(&payload[payload_written..])?
        };
        if written == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "failed to write anytls frame",
            ));
        }
        if header_written < header.len() {
            let header_remaining = header.len() - header_written;
            if written < header_remaining {
                header_written += written;
            } else {
                header_written = header.len();
                payload_written += written - header_remaining;
            }
        } else {
            payload_written += written;
        }
    }
    Ok(())
}

fn parse_socks_addr(bytes: &[u8]) -> io::Result<(SocksTarget, usize)> {
    if bytes.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "empty anytls target",
        ));
    }

    let mut offset = 1usize;
    let host = match bytes[0] {
        ATYP_IPV4 => {
            if bytes.len() < offset + 4 + 2 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "ipv4 target"));
            }
            let mut ip = [0u8; 4];
            ip.copy_from_slice(&bytes[offset..offset + 4]);
            offset += 4;
            Ipv4Addr::from(ip).to_string()
        }
        ATYP_DOMAIN => {
            if bytes.len() <= offset {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "domain len"));
            }
            let len = bytes[offset] as usize;
            offset += 1;
            if bytes.len() < offset + len + 2 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "domain target",
                ));
            }
            let host = String::from_utf8(bytes[offset..offset + len].to_vec())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid domain"))?;
            offset += len;
            host
        }
        ATYP_IPV6 => {
            if bytes.len() < offset + 16 + 2 {
                return Err(io::Error::new(io::ErrorKind::UnexpectedEof, "ipv6 target"));
            }
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&bytes[offset..offset + 16]);
            offset += 16;
            Ipv6Addr::from(ip).to_string()
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported anytls address type",
            ));
        }
    };
    let port = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
    offset += 2;
    Ok((SocksTarget { host, port }, offset))
}

fn resolve_udp_target(target: &SocksTarget) -> io::Result<SocketAddr> {
    crate::dns::resolve_socket_addr(&target.host, target.port, Duration::from_secs(5))
}

fn udp_bind_addr_for_remote(remote: SocketAddr) -> SocketAddr {
    match remote {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    }
}

fn is_uot_magic_target(target: &SocksTarget) -> bool {
    target.host.to_ascii_lowercase().contains(UOT_MAGIC_DOMAIN)
}

fn discard<R: Read>(reader: &mut R, len: usize) -> io::Result<()> {
    let mut remaining = len;
    let mut buffer = [0u8; 1024];
    while remaining > 0 {
        let take = remaining.min(buffer.len());
        reader.read_exact(&mut buffer[..take])?;
        remaining -= take;
    }
    Ok(())
}

fn sha256(password: &str) -> [u8; 32] {
    let digest = Sha256::digest(password.as_bytes());
    let mut output = [0u8; 32];
    output.copy_from_slice(&digest);
    output
}

fn anytls_user_map(users: &[CoreUser]) -> HashMap<[u8; 32], Arc<CoreUser>> {
    users
        .iter()
        .filter(|user| !user.is_empty())
        .map(|user| (sha256(user.credential()), Arc::new(user.clone())))
        .collect()
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream, UdpSocket};
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    use crate::anytls::{
        parse_socks_addr, read_frame_header, sha256, AnyTlsServer, AnyTlsServerConfig, ATYP_DOMAIN,
        ATYP_IPV4, CMD_FIN, CMD_HEART_REQUEST, CMD_HEART_RESPONSE, CMD_PSH, CMD_SERVER_SETTINGS,
        CMD_SETTINGS, CMD_SYNACK, CMD_UPDATE_PADDING_SCHEME, UOT_MAGIC_DOMAIN,
    };
    use crate::user::{CoreUser, CoreUserDelta};

    fn user() -> CoreUser {
        CoreUser {
            id: 1,
            uuid: "anytls-password".to_string(),
            password: None,
            email: None,
            speed_limit: 0,
            device_limit: 0,
        }
    }

    fn user_b() -> CoreUser {
        CoreUser {
            id: 2,
            uuid: "anytls-user-b".to_string(),
            password: Some("secret-b".to_string()),
            email: None,
            speed_limit: 0,
            device_limit: 0,
        }
    }

    fn server() -> AnyTlsServer {
        AnyTlsServer::new(AnyTlsServerConfig {
            node_tag: "panel|anytls|1".to_string(),
            listen: "127.0.0.1:0".parse().expect("listen addr"),
            users: vec![user()],
            routes: Vec::new(),
            connect_timeout: Duration::from_secs(3),
            padding_scheme: Vec::new(),
        })
    }

    fn server_with_padding() -> AnyTlsServer {
        AnyTlsServer::new(AnyTlsServerConfig {
            node_tag: "panel|anytls|1".to_string(),
            listen: "127.0.0.1:0".parse().expect("listen addr"),
            users: vec![user()],
            routes: Vec::new(),
            connect_timeout: Duration::from_secs(3),
            padding_scheme: vec!["stop=8".to_string(), "0=30-30".to_string()],
        })
    }

    #[test]
    fn replaces_users_without_rebuilding_anytls_server() {
        let server = server();

        server.replace_users(vec![user_b()]);

        assert!(server
            .user_for_password_hash(&sha256("anytls-password"))
            .is_none());
        let user = server
            .user_for_password_hash(&sha256("secret-b"))
            .expect("new user should authenticate");
        assert_eq!(user.uuid, "anytls-user-b");
    }

    #[test]
    fn apply_user_delta_updates_anytls_users() {
        let server = server();
        let mut updated = user();
        updated.password = Some("rotated-anytls".to_string());
        updated.speed_limit = 789;
        updated.device_limit = 9;

        let result = server.apply_user_delta(&CoreUserDelta {
            added: vec![user_b()],
            updated: vec![updated.clone()],
            ..CoreUserDelta::default()
        });

        assert_eq!(result.added, 1);
        assert_eq!(result.updated, 1);
        assert_eq!(result.active_users, 2);
        assert!(server
            .user_for_password_hash(&sha256("anytls-password"))
            .is_none());
        let user = server
            .user_for_password_hash(&sha256("rotated-anytls"))
            .expect("updated anytls user should authenticate");
        assert_eq!(user.speed_limit, 789);
        assert_eq!(user.device_limit, 9);
        assert!(server.user_for_password_hash(&sha256("secret-b")).is_some());

        let result = server.apply_user_delta(&CoreUserDelta {
            deleted: vec![updated.uuid.clone()],
            ..CoreUserDelta::default()
        });

        assert_eq!(result.deleted, 1);
        assert_eq!(result.active_users, 1);
        assert!(server
            .user_for_password_hash(&sha256("rotated-anytls"))
            .is_none());
        assert!(server.user_for_password_hash(&sha256("secret-b")).is_some());
    }

    #[test]
    fn apply_user_delta_changes_anytls_auth_without_rebinding_listener() {
        let echo = TcpListener::bind("127.0.0.1:0").expect("echo bind");
        let echo_addr = echo.local_addr().expect("echo addr");
        let echo_thread = thread::spawn(move || {
            for _ in 0..2 {
                let (mut stream, _) = echo.accept().expect("echo accept");
                let mut byte = [0u8; 1];
                stream.read_exact(&mut byte).expect("echo read");
                stream.write_all(&byte).expect("echo write");
            }
        });

        let server = server();
        let listener = server.bind().expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server_clone = server.clone();
        let server_thread = thread::spawn(move || {
            for _ in 0..3 {
                let (stream, _) = listener.accept().expect("accept");
                let _ = server_clone.handle_tcp_client(stream);
            }
        });

        assert!(
            anytls_tcp_probe(addr, "anytls-password", echo_addr),
            "original anytls user should authenticate before delta"
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
            !anytls_tcp_probe(addr, "anytls-password", echo_addr),
            "deleted anytls user should fail new authentication after delta"
        );
        assert!(
            anytls_tcp_probe(addr, "secret-b", echo_addr),
            "added anytls user should authenticate on the same listener after delta"
        );

        server_thread.join().expect("thread");
        echo_thread.join().expect("echo thread");
    }

    #[test]
    fn deleting_anytls_user_stops_existing_tcp_relay_on_next_payload_and_reports_tail() {
        let echo = TcpListener::bind("127.0.0.1:0").expect("echo bind");
        let echo_addr = echo.local_addr().expect("echo addr");
        let (second_payload_tx, second_payload_rx) = mpsc::channel();
        let echo_thread = thread::spawn(move || {
            let (mut stream, _) = echo.accept().expect("echo accept");
            stream
                .set_read_timeout(Some(Duration::from_millis(300)))
                .expect("echo timeout");
            let mut first = [0u8; 1];
            stream.read_exact(&mut first).expect("first payload");
            stream.write_all(&first).expect("first echo");
            let mut second = [0u8; 1];
            let received_second = stream.read_exact(&mut second).is_ok();
            second_payload_tx
                .send(received_second)
                .expect("send result");
        });

        let server = server();
        let listener = server.bind().expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server_clone = server.clone();
        let server_thread = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            server_clone.handle_tcp_client(stream)
        });

        let mut client = TcpStream::connect(addr).expect("client connect");
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .expect("client read timeout");
        client
            .set_write_timeout(Some(Duration::from_secs(1)))
            .expect("client write timeout");
        write_auth(&mut client, "anytls-password");
        write_frame(&mut client, CMD_PSH, 1, &ipv4_target(echo_addr));
        let (command, stream_id, body) = read_frame(&mut client);
        assert_eq!(command, CMD_SYNACK);
        assert_eq!(stream_id, 1);
        assert!(body.is_empty());
        write_frame(&mut client, CMD_PSH, 1, b"x");
        let (command, stream_id, body) = read_frame(&mut client);
        assert_eq!(command, CMD_PSH);
        assert_eq!(stream_id, 1);
        assert_eq!(body, b"x");

        let result = server.apply_user_delta(&CoreUserDelta {
            deleted: vec![user().uuid],
            ..CoreUserDelta::default()
        });
        assert_eq!(result.deleted, 1);

        let _ = try_write_frame(&mut client, CMD_PSH, 1, b"y");
        assert!(
            !second_payload_rx
                .recv_timeout(Duration::from_secs(2))
                .expect("echo result"),
            "deleted user's existing AnyTLS relay should stop forwarding new payload"
        );
        drop(client);
        server_thread.join().expect("thread").expect("serve once");
        echo_thread.join().expect("echo thread");

        let records = server.drain_traffic(1);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].node_tag, "panel|anytls|1");
        assert_eq!(records[0].user_uuid, user().uuid);
        assert_eq!(records[0].user_id, Some(1));
        assert_eq!(records[0].upload, 1);
        assert_eq!(records[0].download, 1);
    }

    fn write_auth(client: &mut TcpStream, password: &str) {
        client
            .write_all(&sha256(password))
            .expect("auth password hash");
        client.write_all(&0u16.to_be_bytes()).expect("auth padding");
    }

    fn write_frame(client: &mut TcpStream, command: u8, stream_id: u32, payload: &[u8]) {
        try_write_frame(client, command, stream_id, payload).expect("frame write");
    }

    fn try_write_frame(
        client: &mut TcpStream,
        command: u8,
        stream_id: u32,
        payload: &[u8],
    ) -> std::io::Result<()> {
        client.write_all(&[
            command,
            (stream_id >> 24) as u8,
            (stream_id >> 16) as u8,
            (stream_id >> 8) as u8,
            stream_id as u8,
            (payload.len() >> 8) as u8,
            payload.len() as u8,
        ])?;
        client.write_all(payload)
    }

    fn read_frame(client: &mut TcpStream) -> (u8, u32, Vec<u8>) {
        try_read_frame(client).expect("frame")
    }

    fn try_read_frame(client: &mut TcpStream) -> Option<(u8, u32, Vec<u8>)> {
        let header = read_frame_header(client).ok()?;
        let mut body = vec![0u8; header.len];
        client.read_exact(&mut body).ok()?;
        Some((header.command, header.stream_id, body))
    }

    fn anytls_tcp_probe(
        addr: std::net::SocketAddr,
        password: &str,
        echo_addr: std::net::SocketAddr,
    ) -> bool {
        let mut client = match TcpStream::connect(addr) {
            Ok(client) => client,
            Err(_) => return false,
        };
        let _ = client.set_read_timeout(Some(Duration::from_secs(1)));
        let _ = client.set_write_timeout(Some(Duration::from_secs(1)));
        if client.write_all(&sha256(password)).is_err() {
            return false;
        }
        if client.write_all(&0u16.to_be_bytes()).is_err() {
            return false;
        }
        if try_write_frame(&mut client, CMD_PSH, 1, &ipv4_target(echo_addr)).is_err() {
            return false;
        }
        let Some((command, stream_id, body)) = try_read_frame(&mut client) else {
            return false;
        };
        if command != CMD_SYNACK || stream_id != 1 || !body.is_empty() {
            return false;
        }
        if try_write_frame(&mut client, CMD_PSH, 1, b"x").is_err() {
            return false;
        }
        let Some((command, stream_id, body)) = try_read_frame(&mut client) else {
            return false;
        };
        let _ = try_write_frame(&mut client, CMD_FIN, 1, &[]);
        command == CMD_PSH && stream_id == 1 && body == b"x"
    }

    fn ipv4_target(target: std::net::SocketAddr) -> Vec<u8> {
        let mut body = vec![ATYP_IPV4];
        body.extend_from_slice(
            &target
                .ip()
                .to_string()
                .parse::<std::net::Ipv4Addr>()
                .expect("ipv4")
                .octets(),
        );
        body.extend_from_slice(&target.port().to_be_bytes());
        body
    }

    fn domain_target(host: &str, port: u16) -> Vec<u8> {
        let mut body = vec![ATYP_DOMAIN, host.len() as u8];
        body.extend_from_slice(host.as_bytes());
        body.extend_from_slice(&port.to_be_bytes());
        body
    }

    fn uot_connect_request(target: std::net::SocketAddr, payload: &[u8]) -> Vec<u8> {
        let mut body = vec![1];
        body.extend_from_slice(&ipv4_target(target));
        body.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        body.extend_from_slice(payload);
        body
    }

    fn uot_ipv4_addr(target: std::net::SocketAddr) -> Vec<u8> {
        let mut body = vec![0];
        body.extend_from_slice(
            &target
                .ip()
                .to_string()
                .parse::<std::net::Ipv4Addr>()
                .expect("ipv4")
                .octets(),
        );
        body.extend_from_slice(&target.port().to_be_bytes());
        body
    }

    fn uot_packet_request(target: std::net::SocketAddr, payload: &[u8]) -> Vec<u8> {
        let mut body = vec![0];
        body.extend_from_slice(&ipv4_target(target));
        body.extend_from_slice(&uot_ipv4_addr(target));
        body.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        body.extend_from_slice(payload);
        body
    }

    #[test]
    fn parses_domain_target() {
        let mut body = vec![ATYP_DOMAIN, 11];
        body.extend_from_slice(b"example.com");
        body.extend_from_slice(&443u16.to_be_bytes());

        let (target, consumed) = parse_socks_addr(&body).expect("target");

        assert_eq!(target.host, "example.com");
        assert_eq!(target.port, 443);
        assert_eq!(consumed, body.len());
    }

    #[test]
    fn replies_to_heartbeat() {
        let server = server();
        let listener = server.bind().expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server_clone = server.clone();
        let server_thread = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            server_clone.handle_tcp_client(stream)
        });

        let mut client = TcpStream::connect(addr).expect("client");
        write_auth(&mut client, "anytls-password");
        write_frame(&mut client, CMD_HEART_REQUEST, 0, &[]);
        let (command, _, body) = read_frame(&mut client);
        assert_eq!(command, CMD_HEART_RESPONSE);
        assert!(body.is_empty());
        drop(client);

        server_thread.join().expect("thread").expect("server");
    }

    #[test]
    fn sends_padding_scheme_update_when_client_md5_differs() {
        let server = server_with_padding();
        let listener = server.bind().expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server_clone = server.clone();
        let server_thread = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            server_clone.handle_tcp_client(stream)
        });

        let mut client = TcpStream::connect(addr).expect("client");
        write_auth(&mut client, "anytls-password");
        write_frame(
            &mut client,
            CMD_SETTINGS,
            0,
            b"v=2\nclient=test\npadding-md5=00000000000000000000000000000000",
        );

        let (command, _, body) = read_frame(&mut client);
        assert_eq!(command, CMD_SERVER_SETTINGS);
        assert_eq!(body, b"v=2");
        let (command, _, body) = read_frame(&mut client);
        assert_eq!(command, CMD_UPDATE_PADDING_SCHEME);
        assert_eq!(
            String::from_utf8(body).expect("padding body"),
            "stop=8\n0=30-30"
        );
        drop(client);

        server_thread.join().expect("thread").expect("server");
    }

    #[test]
    fn proxies_tcp_and_records_user_traffic() {
        let echo = TcpListener::bind("127.0.0.1:0").expect("echo bind");
        let echo_addr = echo.local_addr().expect("echo addr");
        let echo_thread = thread::spawn(move || {
            let (mut stream, _) = echo.accept().expect("echo accept");
            let mut bytes = [0u8; 4];
            stream.read_exact(&mut bytes).expect("echo read");
            stream.write_all(&bytes).expect("echo write");
        });

        let server = server();
        let listener = server.bind().expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server_clone = server.clone();
        let server_thread = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            server_clone.handle_tcp_client(stream)
        });

        let mut client = TcpStream::connect(addr).expect("client");
        write_auth(&mut client, "anytls-password");
        write_frame(&mut client, CMD_PSH, 1, &ipv4_target(echo_addr));
        let (command, stream_id, body) = read_frame(&mut client);
        assert_eq!(command, CMD_SYNACK);
        assert_eq!(stream_id, 1);
        assert!(body.is_empty());

        write_frame(&mut client, CMD_PSH, 1, b"ping");
        let (command, stream_id, body) = read_frame(&mut client);
        assert_eq!(command, CMD_PSH);
        assert_eq!(stream_id, 1);
        assert_eq!(body, b"ping");
        write_frame(&mut client, CMD_FIN, 1, &[]);
        drop(client);

        server_thread.join().expect("thread").expect("server");
        echo_thread.join().expect("echo thread");

        let records = server.drain_traffic(1);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].node_tag, "panel|anytls|1");
        assert_eq!(records[0].user_uuid, "anytls-password");
        assert_eq!(records[0].user_id, Some(1));
        assert_eq!(records[0].upload, 4);
        assert_eq!(records[0].download, 4);
    }

    #[test]
    fn tcp_downlink_uses_async_relay_scheduler() {
        let echo = TcpListener::bind("127.0.0.1:0").expect("echo bind");
        let echo_addr = echo.local_addr().expect("echo addr");
        let (finish_tx, finish_rx) = mpsc::channel();
        let echo_thread = thread::spawn(move || {
            let (mut stream, _) = echo.accept().expect("echo accept");
            let mut bytes = [0u8; 4];
            stream.read_exact(&mut bytes).expect("echo read");
            stream.write_all(&bytes).expect("echo write");
            let _ = finish_rx.recv_timeout(Duration::from_secs(2));
        });

        let server = server();
        let listener = server.bind().expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server_clone = server.clone();
        let server_thread = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            server_clone.handle_tcp_client(stream)
        });

        let mut client = TcpStream::connect(addr).expect("client");
        write_auth(&mut client, "anytls-password");
        write_frame(&mut client, CMD_PSH, 1, &ipv4_target(echo_addr));
        let (command, stream_id, body) = read_frame(&mut client);
        assert_eq!(command, CMD_SYNACK);
        assert_eq!(stream_id, 1);
        assert!(body.is_empty());

        write_frame(&mut client, CMD_PSH, 1, b"ping");
        let (command, stream_id, body) = read_frame(&mut client);
        assert_eq!(command, CMD_PSH);
        assert_eq!(stream_id, 1);
        assert_eq!(body, b"ping");

        let async_active = crate::stream::relay_scheduler_metrics_snapshot()
            .active_async
            .get("keli-core-anytls-downlink")
            .copied()
            .unwrap_or_default();
        assert!(
            async_active > 0,
            "AnyTLS TCP downlink should use async relay scheduler while the remote stream is open"
        );

        let _ = finish_tx.send(());
        write_frame(&mut client, CMD_FIN, 1, &[]);
        drop(client);

        server_thread.join().expect("thread").expect("server");
        echo_thread.join().expect("echo thread");
    }

    #[test]
    fn proxies_udp_over_tcp_and_records_user_traffic() {
        let echo = UdpSocket::bind("127.0.0.1:0").expect("echo bind");
        let echo_addr = echo.local_addr().expect("echo addr");
        let echo_thread = thread::spawn(move || {
            let mut bytes = [0u8; 1024];
            let (read, source) = echo.recv_from(&mut bytes).expect("echo read");
            assert_eq!(&bytes[..read], b"ping");
            echo.send_to(b"pong", source).expect("echo write");
        });

        let server = server();
        let listener = server.bind().expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server_clone = server.clone();
        let server_thread = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            server_clone.handle_tcp_client(stream)
        });

        let mut client = TcpStream::connect(addr).expect("client");
        client
            .set_read_timeout(Some(Duration::from_secs(3)))
            .expect("read timeout");
        write_auth(&mut client, "anytls-password");
        write_frame(&mut client, CMD_PSH, 1, &domain_target(UOT_MAGIC_DOMAIN, 0));
        let (command, stream_id, body) = read_frame(&mut client);
        assert_eq!(command, CMD_SYNACK);
        assert_eq!(stream_id, 1);
        assert!(body.is_empty());

        write_frame(
            &mut client,
            CMD_PSH,
            1,
            &uot_connect_request(echo_addr, b"ping"),
        );
        let (command, stream_id, body) = read_frame(&mut client);
        assert_eq!(command, CMD_PSH);
        assert_eq!(stream_id, 1);
        let mut expected = 4u16.to_be_bytes().to_vec();
        expected.extend_from_slice(b"pong");
        assert_eq!(body, expected);
        write_frame(&mut client, CMD_FIN, 1, &[]);
        drop(client);

        server_thread.join().expect("thread").expect("server");
        echo_thread.join().expect("echo thread");

        let records = server.drain_traffic(1);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].node_tag, "panel|anytls|1");
        assert_eq!(records[0].user_uuid, "anytls-password");
        assert_eq!(records[0].upload, 4);
        assert_eq!(records[0].download, 4);
    }

    #[test]
    fn proxies_udp_over_tcp_per_packet_destination() {
        let echo = UdpSocket::bind("127.0.0.1:0").expect("echo bind");
        let echo_addr = echo.local_addr().expect("echo addr");
        let echo_thread = thread::spawn(move || {
            let mut bytes = [0u8; 1024];
            let (read, source) = echo.recv_from(&mut bytes).expect("echo read");
            assert_eq!(&bytes[..read], b"ping");
            echo.send_to(b"pong", source).expect("echo write");
        });

        let server = server();
        let listener = server.bind().expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server_clone = server.clone();
        let server_thread = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            server_clone.handle_tcp_client(stream)
        });

        let mut client = TcpStream::connect(addr).expect("client");
        client
            .set_read_timeout(Some(Duration::from_secs(3)))
            .expect("read timeout");
        write_auth(&mut client, "anytls-password");
        write_frame(&mut client, CMD_PSH, 1, &domain_target(UOT_MAGIC_DOMAIN, 0));
        let (command, stream_id, _) = read_frame(&mut client);
        assert_eq!(command, CMD_SYNACK);
        assert_eq!(stream_id, 1);

        write_frame(
            &mut client,
            CMD_PSH,
            1,
            &uot_packet_request(echo_addr, b"ping"),
        );
        let (command, stream_id, body) = read_frame(&mut client);
        assert_eq!(command, CMD_PSH);
        assert_eq!(stream_id, 1);
        let mut expected = uot_ipv4_addr(echo_addr);
        expected.extend_from_slice(&4u16.to_be_bytes());
        expected.extend_from_slice(b"pong");
        assert_eq!(body, expected);
        drop(client);

        server_thread.join().expect("thread").expect("server");
        echo_thread.join().expect("echo thread");
    }
}
