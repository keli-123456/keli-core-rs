use std::io::{self, Read, Write};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, TcpListener, TcpStream, UdpSocket};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use sha2::{Digest, Sha224};

use crate::config::OutboundConfig;
use crate::limits::{
    BandwidthLimiter, UserBandwidthLimiters, UserSessionGuard, UserSessionTracker,
};
use crate::outbound::recv_udp_response;
use crate::socks5::SocksTarget;
use crate::stream::{copy_count_best_effort_limited, relay_tcp_streams_limited};
use crate::tls::{relay_tls_stream, TlsConnection};
use crate::traffic::TrafficRegistry;
use crate::user::{CoreUser, UserStore};
use crate::websocket::{accept_websocket, accept_websocket_tls, relay_websocket_tls_stream};
use crate::{
    connect_tcp_outbound, route_protocol_labels, send_udp_outbound, RouteDecision, RouteMatcher,
};

const COMMAND_TCP: u8 = 0x01;
const COMMAND_UDP_ASSOCIATE: u8 = 0x03;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;
const TROJAN_PASSWORD_HEX_LEN: usize = 56;
const MAX_UDP_PACKET_SIZE: usize = 65_535;

#[derive(Clone, Debug)]
pub struct TrojanServerConfig {
    pub node_tag: String,
    pub listen: SocketAddr,
    pub users: Vec<CoreUser>,
    pub routes: Vec<crate::RouteRule>,
    pub connect_timeout: Duration,
}

#[derive(Clone, Debug)]
pub struct TrojanServer {
    config: TrojanServerConfig,
    users: UserStore,
    router: RouteMatcher,
    traffic: Arc<Mutex<TrafficRegistry>>,
    sessions: UserSessionTracker,
    bandwidth: UserBandwidthLimiters,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct TrojanRequest {
    command: TrojanCommand,
    password_hash: String,
    user_uuid: String,
    target: SocksTarget,
    client_ip: Option<IpAddr>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum TrojanCommand {
    Tcp,
    UdpAssociate,
}

struct TrojanUdpRelayState {
    ipv4: Option<UdpSocket>,
    ipv6: Option<UdpSocket>,
    timeout: Duration,
}

impl TrojanServer {
    pub fn new(config: TrojanServerConfig) -> Self {
        Self::with_traffic(config, Arc::new(Mutex::new(TrafficRegistry::default())))
    }

    pub fn with_traffic(config: TrojanServerConfig, traffic: Arc<Mutex<TrafficRegistry>>) -> Self {
        Self::with_shared_limits(
            config,
            traffic,
            UserSessionTracker::default(),
            UserBandwidthLimiters::default(),
        )
    }

    pub fn with_shared_limits(
        config: TrojanServerConfig,
        traffic: Arc<Mutex<TrafficRegistry>>,
        sessions: UserSessionTracker,
        bandwidth: UserBandwidthLimiters,
    ) -> Self {
        let users = UserStore::from_keyed_users(&config.users, |user| {
            trojan_password_hash(user.credential())
        });
        Self {
            router: RouteMatcher::new(config.routes.clone()),
            config,
            users,
            traffic,
            sessions,
            bandwidth,
        }
    }

    pub fn bind(&self) -> io::Result<TcpListener> {
        TcpListener::bind(self.config.listen)
    }

    pub fn handle_tcp_client(&self, mut client: TcpStream) -> io::Result<()> {
        let client_ip = client.peer_addr().ok().map(|addr| addr.ip());
        let mut request = self.read_request(&mut client)?;
        request.client_ip = client_ip;
        let user = self.request_user(&request);
        let _session = self.acquire_user_session(user.as_ref(), client_ip)?;
        let bandwidth = self.bandwidth.limiter_for(user.as_ref());
        if request.command == TrojanCommand::UdpAssociate {
            return self.relay_udp_stream(client, request, bandwidth);
        }
        let remote =
            match self
                .router
                .decide_target(&request.target.host, request.target.port, "tcp")
            {
                RouteDecision::Direct => {
                    connect_target(&request.target, self.config.connect_timeout)?
                }
                RouteDecision::Outbound(outbound) => {
                    connect_tcp_outbound(&outbound, &request.target, self.config.connect_timeout)?
                }
                RouteDecision::Block => {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "target blocked by route",
                    ));
                }
                RouteDecision::UnsupportedOutbound(tag) => {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        format!("outbound route {tag} is not implemented"),
                    ));
                }
            };
        self.relay(client, remote, request, bandwidth)
    }

    pub fn handle_websocket_client(&self, client: TcpStream, path: Option<&str>) -> io::Result<()> {
        let client_ip = client.peer_addr().ok().map(|addr| addr.ip());
        let (reader, writer) = accept_websocket(client, path)?;
        self.handle_split_client_with_ip(reader, writer, client_ip)
    }

    pub fn handle_split_client<R, W>(&self, reader: R, writer: W) -> io::Result<()>
    where
        R: Read + Send + 'static,
        W: Write,
    {
        self.handle_split_client_with_ip(reader, writer, None)
    }

    fn handle_split_client_with_ip<R, W>(
        &self,
        mut reader: R,
        writer: W,
        client_ip: Option<IpAddr>,
    ) -> io::Result<()>
    where
        R: Read + Send + 'static,
        W: Write,
    {
        let mut request = self.read_request(&mut reader)?;
        request.client_ip = client_ip;
        let user = self.request_user(&request);
        let _session = self.acquire_user_session(user.as_ref(), client_ip)?;
        let bandwidth = self.bandwidth.limiter_for(user.as_ref());
        if request.command == TrojanCommand::UdpAssociate {
            return self.relay_udp_split(reader, writer, request, bandwidth);
        }
        let remote =
            match self
                .router
                .decide_target(&request.target.host, request.target.port, "tcp")
            {
                RouteDecision::Direct => {
                    connect_target(&request.target, self.config.connect_timeout)?
                }
                RouteDecision::Outbound(outbound) => {
                    connect_tcp_outbound(&outbound, &request.target, self.config.connect_timeout)?
                }
                RouteDecision::Block => {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "target blocked by route",
                    ));
                }
                RouteDecision::UnsupportedOutbound(tag) => {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        format!("outbound route {tag} is not implemented"),
                    ));
                }
            };
        self.relay_websocket(reader, writer, remote, request, bandwidth)
    }

    pub fn handle_tls_client(&self, mut client: TlsConnection) -> io::Result<()> {
        let client_ip = client.peer_addr().ok().map(|addr| addr.ip());
        let mut request = self.read_request(&mut client)?;
        request.client_ip = client_ip;
        let user = self.request_user(&request);
        let _session = self.acquire_user_session(user.as_ref(), client_ip)?;
        let bandwidth = self.bandwidth.limiter_for(user.as_ref());
        if request.command == TrojanCommand::UdpAssociate {
            return self.relay_udp_stream(client, request, bandwidth);
        }
        let remote =
            match self
                .router
                .decide_target(&request.target.host, request.target.port, "tcp")
            {
                RouteDecision::Direct => {
                    connect_target(&request.target, self.config.connect_timeout)?
                }
                RouteDecision::Outbound(outbound) => {
                    connect_tcp_outbound(&outbound, &request.target, self.config.connect_timeout)?
                }
                RouteDecision::Block => {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "target blocked by route",
                    ));
                }
                RouteDecision::UnsupportedOutbound(tag) => {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        format!("outbound route {tag} is not implemented"),
                    ));
                }
            };
        self.relay_tls(client, remote, request, bandwidth)
    }

    pub fn handle_tls_websocket_client(
        &self,
        client: TlsConnection,
        path: Option<&str>,
    ) -> io::Result<()> {
        let client_ip = client.peer_addr().ok().map(|addr| addr.ip());
        let mut websocket = accept_websocket_tls(client, path)?;
        let mut request = self.read_request(&mut websocket)?;
        request.client_ip = client_ip;
        let user = self.request_user(&request);
        let _session = self.acquire_user_session(user.as_ref(), client_ip)?;
        let bandwidth = self.bandwidth.limiter_for(user.as_ref());
        if request.command == TrojanCommand::UdpAssociate {
            return self.relay_udp_stream(websocket, request, bandwidth);
        }
        let remote =
            match self
                .router
                .decide_target(&request.target.host, request.target.port, "tcp")
            {
                RouteDecision::Direct => {
                    connect_target(&request.target, self.config.connect_timeout)?
                }
                RouteDecision::Outbound(outbound) => {
                    connect_tcp_outbound(&outbound, &request.target, self.config.connect_timeout)?
                }
                RouteDecision::Block => {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "target blocked by route",
                    ));
                }
                RouteDecision::UnsupportedOutbound(tag) => {
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        format!("outbound route {tag} is not implemented"),
                    ));
                }
            };
        self.relay_tls_websocket(websocket, remote, request, bandwidth)
    }

    pub fn drain_traffic(&self, minimum_bytes: u64) -> Vec<crate::traffic::TrafficDelta> {
        self.traffic
            .lock()
            .expect("traffic registry lock poisoned")
            .drain_minimum(minimum_bytes)
    }

    pub fn replace_users(&self, users: Vec<CoreUser>) {
        self.users
            .replace_keyed_users(users, |user| trojan_password_hash(user.credential()));
    }

    fn read_request<T>(&self, stream: &mut T) -> io::Result<TrojanRequest>
    where
        T: Read,
    {
        let mut hash = [0u8; TROJAN_PASSWORD_HEX_LEN];
        stream.read_exact(&mut hash)?;
        let password_hash = String::from_utf8(hash.to_vec()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidData, "invalid trojan password hash")
        })?;
        read_crlf(stream)?;

        let Some(user) = self.users.get(&password_hash) else {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "unknown trojan user",
            ));
        };

        let command = read_u8(stream)?;
        let command = match command {
            COMMAND_TCP => TrojanCommand::Tcp,
            COMMAND_UDP_ASSOCIATE => TrojanCommand::UdpAssociate,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "only trojan tcp and udp associate commands are supported",
                ));
            }
        };
        let target = read_trojan_target(stream)?;
        read_crlf(stream)?;

        Ok(TrojanRequest {
            command,
            password_hash,
            user_uuid: user.uuid.clone(),
            target,
            client_ip: None,
        })
    }

    fn relay(
        &self,
        client: TcpStream,
        remote: TcpStream,
        request: TrojanRequest,
        bandwidth: Option<Arc<BandwidthLimiter>>,
    ) -> io::Result<()> {
        let (upload, download) = relay_tcp_streams_limited(client, remote, bandwidth)?;
        self.traffic
            .lock()
            .expect("traffic registry lock poisoned")
            .add_with_ip(
                self.config.node_tag.clone(),
                request.user_uuid,
                upload,
                download,
                request.client_ip,
            );
        Ok(())
    }

    fn relay_websocket<R, W>(
        &self,
        mut reader: R,
        mut writer: W,
        remote: TcpStream,
        request: TrojanRequest,
        bandwidth: Option<Arc<BandwidthLimiter>>,
    ) -> io::Result<()>
    where
        R: Read + Send + 'static,
        W: Write,
    {
        let mut remote_write = remote.try_clone()?;
        let mut remote_read = remote;
        let upload_limiter = bandwidth.clone();
        let upload_thread = thread::spawn(move || {
            copy_count_best_effort_limited(
                &mut reader,
                &mut remote_write,
                upload_limiter.as_deref(),
            )
        });
        let download = copy_count_best_effort_limited(&mut remote_read, &mut writer, None);
        let upload = upload_thread
            .join()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "upload relay thread panicked"))?;
        self.traffic
            .lock()
            .expect("traffic registry lock poisoned")
            .add_with_ip(
                self.config.node_tag.clone(),
                request.user_uuid,
                upload,
                download,
                request.client_ip,
            );
        Ok(())
    }

    fn relay_tls(
        &self,
        client: TlsConnection,
        remote: TcpStream,
        request: TrojanRequest,
        bandwidth: Option<Arc<BandwidthLimiter>>,
    ) -> io::Result<()> {
        let (upload, download) = relay_tls_stream(client, remote, bandwidth)?;
        self.traffic
            .lock()
            .expect("traffic registry lock poisoned")
            .add_with_ip(
                self.config.node_tag.clone(),
                request.user_uuid,
                upload,
                download,
                request.client_ip,
            );
        Ok(())
    }

    fn relay_tls_websocket(
        &self,
        client: crate::websocket::WebSocketTlsStream,
        remote: TcpStream,
        request: TrojanRequest,
        bandwidth: Option<Arc<BandwidthLimiter>>,
    ) -> io::Result<()> {
        let (upload, download) = relay_websocket_tls_stream(client, remote, bandwidth)?;
        self.traffic
            .lock()
            .expect("traffic registry lock poisoned")
            .add_with_ip(
                self.config.node_tag.clone(),
                request.user_uuid,
                upload,
                download,
                request.client_ip,
            );
        Ok(())
    }

    fn relay_udp_stream<S>(
        &self,
        mut stream: S,
        request: TrojanRequest,
        bandwidth: Option<Arc<BandwidthLimiter>>,
    ) -> io::Result<()>
    where
        S: Read + Write,
    {
        let mut state = TrojanUdpRelayState::new(self.config.connect_timeout);
        let mut upload = 0u64;
        let mut download = 0u64;
        let result = loop {
            match read_trojan_udp_packet(&mut stream) {
                Ok((target, payload)) => {
                    match self.forward_udp_packet(
                        &mut state,
                        &mut stream,
                        &target,
                        &payload,
                        bandwidth.as_deref(),
                    ) {
                        Ok((sent, received)) => {
                            upload = upload.saturating_add(sent);
                            download = download.saturating_add(received);
                        }
                        Err(error) => break Err(error),
                    }
                }
                Err(error) if is_stream_closed(&error) => break Ok(()),
                Err(error) => break Err(error),
            }
        };
        self.record_traffic(request.user_uuid, upload, download, request.client_ip);
        result
    }

    fn relay_udp_split<R, W>(
        &self,
        mut reader: R,
        mut writer: W,
        request: TrojanRequest,
        bandwidth: Option<Arc<BandwidthLimiter>>,
    ) -> io::Result<()>
    where
        R: Read,
        W: Write,
    {
        let mut state = TrojanUdpRelayState::new(self.config.connect_timeout);
        let mut upload = 0u64;
        let mut download = 0u64;
        let result = loop {
            match read_trojan_udp_packet(&mut reader) {
                Ok((target, payload)) => {
                    match self.forward_udp_packet(
                        &mut state,
                        &mut writer,
                        &target,
                        &payload,
                        bandwidth.as_deref(),
                    ) {
                        Ok((sent, received)) => {
                            upload = upload.saturating_add(sent);
                            download = download.saturating_add(received);
                        }
                        Err(error) => break Err(error),
                    }
                }
                Err(error) if is_stream_closed(&error) => break Ok(()),
                Err(error) => break Err(error),
            }
        };
        self.record_traffic(request.user_uuid, upload, download, request.client_ip);
        result
    }

    fn forward_udp_packet<W>(
        &self,
        state: &mut TrojanUdpRelayState,
        writer: &mut W,
        target: &SocksTarget,
        payload: &[u8],
        bandwidth: Option<&BandwidthLimiter>,
    ) -> io::Result<(u64, u64)>
    where
        W: Write,
    {
        let protocol_labels = route_protocol_labels("udp", payload);
        let decision = self
            .router
            .decide_target(&target.host, target.port, &protocol_labels);
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

        if let Some(limiter) = bandwidth {
            limiter.wait_for(payload.len());
        }

        if let Some(outbound) = outbound {
            return match send_udp_outbound(outbound, target, payload, self.config.connect_timeout) {
                Ok((source, response)) => {
                    let packet = encode_trojan_udp_packet(source, &response);
                    writer.write_all(&packet)?;
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
        let udp = state.socket_for(remote_addr)?;
        udp.send_to(payload, remote_addr)?;
        let mut response = vec![0u8; MAX_UDP_PACKET_SIZE];
        let download = match recv_udp_response(udp, &mut response) {
            Ok((read, source)) => {
                let packet = encode_trojan_udp_packet(source, &response[..read]);
                writer.write_all(&packet)?;
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

    fn record_traffic(
        &self,
        user_uuid: String,
        upload: u64,
        download: u64,
        client_ip: Option<IpAddr>,
    ) {
        self.traffic
            .lock()
            .expect("traffic registry lock poisoned")
            .add_with_ip(
                self.config.node_tag.clone(),
                user_uuid,
                upload,
                download,
                client_ip,
            );
    }

    fn request_user(&self, request: &TrojanRequest) -> Option<CoreUser> {
        self.users.get(&request.password_hash)
    }

    fn acquire_user_session(
        &self,
        user: Option<&CoreUser>,
        client_ip: Option<IpAddr>,
    ) -> io::Result<Option<UserSessionGuard>> {
        match self.sessions.try_acquire_for_ip(user, client_ip) {
            Ok(guard) => Ok(guard),
            Err(error) => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                error.to_string(),
            )),
        }
    }
}

impl TrojanUdpRelayState {
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

pub fn trojan_password_hash(password: &str) -> String {
    let digest = Sha224::digest(password.as_bytes());
    hex_lower(&digest)
}

pub(crate) fn connect_trojan_tcp_outbound(
    outbound: &OutboundConfig,
    target: &SocksTarget,
    timeout: Duration,
) -> io::Result<TcpStream> {
    let server = trojan_outbound_server(outbound)?;
    let mut stream = connect_target(&server, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    let password = outbound
        .password
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "outbound password is required for trojan",
            )
        })?;
    write_trojan_tcp_request(&mut stream, password, target)?;
    Ok(stream)
}

fn trojan_outbound_server(outbound: &OutboundConfig) -> io::Result<SocksTarget> {
    let host = outbound
        .address
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "outbound address is required"))?
        .to_string();
    let port = outbound
        .port
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "outbound port is required"))?;
    Ok(SocksTarget { host, port })
}

fn write_trojan_tcp_request<W: Write>(
    writer: &mut W,
    password: &str,
    target: &SocksTarget,
) -> io::Result<()> {
    writer.write_all(trojan_password_hash(password).as_bytes())?;
    writer.write_all(b"\r\n")?;
    writer.write_all(&[COMMAND_TCP])?;
    write_trojan_target(writer, target)?;
    writer.write_all(b"\r\n")
}

fn write_trojan_target<W: Write>(writer: &mut W, target: &SocksTarget) -> io::Result<()> {
    if let Ok(ip) = target.host.parse::<Ipv4Addr>() {
        writer.write_all(&[ATYP_IPV4])?;
        writer.write_all(&ip.octets())?;
    } else if let Ok(ip) = target.host.parse::<Ipv6Addr>() {
        writer.write_all(&[ATYP_IPV6])?;
        writer.write_all(&ip.octets())?;
    } else {
        let host = target.host.trim().trim_matches(['[', ']']);
        if host.is_empty() || host.len() > u8::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "trojan target host is invalid",
            ));
        }
        writer.write_all(&[ATYP_DOMAIN, host.len() as u8])?;
        writer.write_all(host.as_bytes())?;
    }
    writer.write_all(&target.port.to_be_bytes())
}

fn read_trojan_target<R: Read>(reader: &mut R) -> io::Result<SocksTarget> {
    let host = match read_u8(reader)? {
        ATYP_IPV4 => {
            let mut bytes = [0u8; 4];
            reader.read_exact(&mut bytes)?;
            Ipv4Addr::from(bytes).to_string()
        }
        ATYP_DOMAIN => {
            let len = read_u8(reader)?;
            read_string(reader, usize::from(len))?
        }
        ATYP_IPV6 => {
            let mut bytes = [0u8; 16];
            reader.read_exact(&mut bytes)?;
            Ipv6Addr::from(bytes).to_string()
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported trojan address type",
            ));
        }
    };

    let mut port = [0u8; 2];
    reader.read_exact(&mut port)?;
    Ok(SocksTarget {
        host,
        port: u16::from_be_bytes(port),
    })
}

fn connect_target(target: &SocksTarget, timeout: Duration) -> io::Result<TcpStream> {
    crate::dns::connect_tcp(&target.host, target.port, timeout)
}

fn resolve_udp_target(target: &SocksTarget) -> io::Result<SocketAddr> {
    crate::dns::resolve_socket_addr(&target.host, target.port, Duration::from_secs(5))
}

fn read_trojan_udp_packet<R: Read>(reader: &mut R) -> io::Result<(SocksTarget, Vec<u8>)> {
    let target = read_trojan_target(reader)?;
    let mut len = [0u8; 2];
    reader.read_exact(&mut len)?;
    read_crlf(reader)?;
    let len = u16::from_be_bytes(len) as usize;
    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload)?;
    Ok((target, payload))
}

fn encode_trojan_udp_packet(source: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(22 + payload.len());
    match source.ip() {
        IpAddr::V4(ip) => {
            output.push(ATYP_IPV4);
            output.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            output.push(ATYP_IPV6);
            output.extend_from_slice(&ip.octets());
        }
    }
    output.extend_from_slice(&source.port().to_be_bytes());
    output.extend_from_slice(&(payload.len() as u16).to_be_bytes());
    output.extend_from_slice(b"\r\n");
    output.extend_from_slice(payload);
    output
}

fn udp_bind_addr_for_remote(remote: SocketAddr) -> SocketAddr {
    match remote {
        SocketAddr::V4(_) => SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
        SocketAddr::V6(_) => SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0),
    }
}

fn is_stream_closed(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::UnexpectedEof
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::BrokenPipe
    )
}

fn read_u8<R: Read>(reader: &mut R) -> io::Result<u8> {
    let mut byte = [0u8; 1];
    reader.read_exact(&mut byte)?;
    Ok(byte[0])
}

fn read_string<R: Read>(reader: &mut R, len: usize) -> io::Result<String> {
    let mut bytes = vec![0u8; len];
    reader.read_exact(&mut bytes)?;
    String::from_utf8(bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid utf-8"))
}

fn read_crlf<R: Read>(reader: &mut R) -> io::Result<()> {
    let mut crlf = [0u8; 2];
    reader.read_exact(&mut crlf)?;
    if crlf == [b'\r', b'\n'] {
        Ok(())
    } else {
        Err(io::Error::new(io::ErrorKind::InvalidData, "missing crlf"))
    }
}

fn hex_lower(bytes: &[u8]) -> String {
    let mut output = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
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

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::{Cursor, Read, Write};
    use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::thread;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use rustls::pki_types::{CertificateDer, ServerName};
    use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

    use crate::config::OutboundConfig;
    use crate::socks5::SocksTarget;
    use crate::tls::TlsAcceptor;
    use crate::trojan::{
        connect_trojan_tcp_outbound, trojan_password_hash, TrojanServer, TrojanServerConfig,
    };
    use crate::user::CoreUser;

    struct MemoryStream {
        input: Cursor<Vec<u8>>,
    }

    impl MemoryStream {
        fn new(input: Vec<u8>) -> Self {
            Self {
                input: Cursor::new(input),
            }
        }
    }

    impl Read for MemoryStream {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.input.read(buf)
        }
    }

    fn user() -> CoreUser {
        CoreUser {
            id: 1,
            uuid: "trojan-password".to_string(),
            password: None,
            email: None,
            speed_limit: 0,
            device_limit: 0,
        }
    }

    fn user_b() -> CoreUser {
        CoreUser {
            id: 2,
            uuid: "trojan-user-b".to_string(),
            password: Some("secret-b".to_string()),
            email: None,
            speed_limit: 0,
            device_limit: 0,
        }
    }

    fn server() -> TrojanServer {
        TrojanServer::new(TrojanServerConfig {
            node_tag: "panel|trojan|1".to_string(),
            listen: "127.0.0.1:0".parse().expect("listen addr"),
            users: vec![user()],
            routes: Vec::new(),
            connect_timeout: Duration::from_secs(3),
        })
    }

    fn trojan_request(target: std::net::SocketAddr) -> Vec<u8> {
        trojan_request_with_command(target, 0x01)
    }

    fn trojan_udp_associate_request(target: std::net::SocketAddr) -> Vec<u8> {
        trojan_request_with_command(target, 0x03)
    }

    fn trojan_request_with_command(target: std::net::SocketAddr, command: u8) -> Vec<u8> {
        trojan_request_with_password_and_command(target, "trojan-password", command)
    }

    fn trojan_request_with_password_and_command(
        target: std::net::SocketAddr,
        password: &str,
        command: u8,
    ) -> Vec<u8> {
        let mut input = trojan_password_hash(password).into_bytes();
        input.extend_from_slice(b"\r\n");
        input.push(command);
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

    fn trojan_udp_packet(target: SocketAddr, payload: &[u8]) -> Vec<u8> {
        let mut packet = vec![0x01];
        packet.extend_from_slice(
            &target
                .ip()
                .to_string()
                .parse::<std::net::Ipv4Addr>()
                .expect("ipv4")
                .octets(),
        );
        packet.extend_from_slice(&target.port().to_be_bytes());
        packet.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        packet.extend_from_slice(b"\r\n");
        packet.extend_from_slice(payload);
        packet
    }

    fn read_trojan_udp_packet<R: Read>(reader: &mut R) -> (SocketAddr, Vec<u8>) {
        let mut atyp = [0u8; 1];
        reader.read_exact(&mut atyp).expect("udp atyp");
        assert_eq!(atyp[0], 0x01);
        let mut ip = [0u8; 4];
        reader.read_exact(&mut ip).expect("udp ip");
        let mut port = [0u8; 2];
        reader.read_exact(&mut port).expect("udp port");
        let mut len = [0u8; 2];
        reader.read_exact(&mut len).expect("udp len");
        let mut crlf = [0u8; 2];
        reader.read_exact(&mut crlf).expect("udp crlf");
        assert_eq!(&crlf, b"\r\n");
        let mut payload = vec![0u8; u16::from_be_bytes(len) as usize];
        reader.read_exact(&mut payload).expect("udp payload");
        (
            SocketAddr::new(
                std::net::Ipv4Addr::from(ip).into(),
                u16::from_be_bytes(port),
            ),
            payload,
        )
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
        let cert_path = dir.join(format!("keli-core-rs-{label}-{nanos}.crt"));
        let key_path = dir.join(format!("keli-core-rs-{label}-{nanos}.key"));
        fs::write(&cert_path, cert.cert.pem()).expect("write cert");
        fs::write(&key_path, cert.key_pair.serialize_pem()).expect("write key");
        TestCert {
            cert_path,
            key_path,
            cert_der: cert.cert.der().clone(),
        }
    }

    fn tls_client(
        addr: std::net::SocketAddr,
        cert_der: CertificateDer<'static>,
    ) -> StreamOwned<ClientConnection, TcpStream> {
        let mut roots = RootCertStore::empty();
        roots.add(cert_der).expect("root cert");
        let config = ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let server_name = ServerName::try_from("localhost")
            .expect("server name")
            .to_owned();
        let connection = ClientConnection::new(Arc::new(config), server_name).expect("client tls");
        let socket = TcpStream::connect(addr).expect("client connect");
        StreamOwned::new(connection, socket)
    }

    fn websocket_request(path: &str) -> Vec<u8> {
        format!(
            "GET {path} HTTP/1.1\r\nHost: example.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
        )
        .into_bytes()
    }

    fn masked_frame(payload: &[u8]) -> Vec<u8> {
        let mask = [1u8, 2, 3, 4];
        let mut frame = vec![0x82, 0x80 | payload.len() as u8];
        frame.extend_from_slice(&mask);
        for (index, byte) in payload.iter().enumerate() {
            frame.push(*byte ^ mask[index % 4]);
        }
        frame
    }

    fn read_websocket_response<R: Read>(stream: &mut R) -> String {
        let mut bytes = Vec::new();
        let mut byte = [0u8; 1];
        while !bytes.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte).expect("response byte");
            bytes.push(byte[0]);
        }
        String::from_utf8(bytes).expect("response utf8")
    }

    fn read_binary_frame<R: Read>(stream: &mut R) -> Vec<u8> {
        let mut header = [0u8; 2];
        stream.read_exact(&mut header).expect("frame header");
        assert_eq!(header[0] & 0x0f, 0x02);
        assert_eq!(header[1] & 0x80, 0);
        let len = match header[1] & 0x7f {
            126 => {
                let mut extended = [0u8; 2];
                stream.read_exact(&mut extended).expect("frame len");
                u16::from_be_bytes(extended) as usize
            }
            127 => {
                let mut extended = [0u8; 8];
                stream.read_exact(&mut extended).expect("frame len");
                u64::from_be_bytes(extended) as usize
            }
            len => len as usize,
        };
        let mut payload = vec![0u8; len];
        stream.read_exact(&mut payload).expect("frame payload");
        payload
    }

    #[test]
    fn hashes_trojan_password_with_sha224_hex() {
        assert_eq!(
            trojan_password_hash(""),
            "d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f"
        );
    }

    #[test]
    fn parses_trojan_tcp_request() {
        let server = server();
        let mut input = trojan_password_hash("trojan-password").into_bytes();
        input.extend_from_slice(b"\r\n");
        input.push(0x01);
        input.push(0x03);
        input.push(11);
        input.extend_from_slice(b"example.com");
        input.extend_from_slice(&443u16.to_be_bytes());
        input.extend_from_slice(b"\r\n");
        let mut stream = MemoryStream::new(input);

        let request = server.read_request(&mut stream).expect("request");

        assert_eq!(request.user_uuid, "trojan-password");
        assert_eq!(request.target.host, "example.com");
        assert_eq!(request.target.port, 443);
    }

    #[test]
    fn rejects_unknown_trojan_user() {
        let server = server();
        let mut input = trojan_password_hash("wrong-password").into_bytes();
        input.extend_from_slice(b"\r\n");
        let mut stream = MemoryStream::new(input);

        let error = server
            .read_request(&mut stream)
            .expect_err("unknown user should fail");

        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn replaces_users_without_rebuilding_trojan_server() {
        let server = server();
        let target: std::net::SocketAddr = "127.0.0.1:443".parse().expect("addr");

        server.replace_users(vec![user_b()]);

        let mut old_stream = MemoryStream::new(trojan_request(target));
        let error = server
            .read_request(&mut old_stream)
            .expect_err("old user should fail after replacement");
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);

        let mut new_stream = MemoryStream::new(trojan_request_with_password_and_command(
            target, "secret-b", 0x01,
        ));
        let request = server
            .read_request(&mut new_stream)
            .expect("new user should authenticate");
        assert_eq!(request.user_uuid, "trojan-user-b");
    }

    #[test]
    fn trojan_tcp_outbound_writes_request_and_relays_plain_stream() {
        let proxy = TcpListener::bind("127.0.0.1:0").expect("proxy bind");
        let proxy_addr = proxy.local_addr().expect("proxy addr");
        let proxy_thread = thread::spawn(move || {
            let (mut stream, _) = proxy.accept().expect("proxy accept");
            let server = server();
            let request = server.read_request(&mut stream).expect("trojan request");
            assert_eq!(
                request.password_hash,
                trojan_password_hash("trojan-password")
            );
            assert_eq!(request.target.host, "example.com");
            assert_eq!(request.target.port, 443);
            let mut payload = [0u8; 4];
            stream.read_exact(&mut payload).expect("payload");
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong").expect("response");
        });

        let outbound = OutboundConfig {
            tag: "trojan-out".to_string(),
            protocol: "trojan".to_string(),
            method: None,
            address: Some(proxy_addr.ip().to_string()),
            port: Some(proxy_addr.port()),
            username: None,
            password: Some("trojan-password".to_string()),
        };
        let target = SocksTarget {
            host: "example.com".to_string(),
            port: 443,
        };
        let mut stream = connect_trojan_tcp_outbound(&outbound, &target, Duration::from_secs(2))
            .expect("connect outbound");
        stream.write_all(b"ping").expect("write payload");
        let mut response = [0u8; 4];
        stream.read_exact(&mut response).expect("read response");
        assert_eq!(&response, b"pong");
        proxy_thread.join().expect("proxy thread");
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
        let listener = server.bind().expect("trojan bind");
        let trojan_addr = listener.local_addr().expect("trojan addr");
        let server_clone = server.clone();
        let server_thread = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("trojan accept");
            server_clone.handle_tcp_client(stream)
        });

        let mut client = TcpStream::connect(trojan_addr).expect("client connect");
        client
            .write_all(&trojan_request(echo_addr))
            .expect("client request");
        client.write_all(b"ping").expect("client write payload");
        let mut echoed = [0u8; 4];
        client.read_exact(&mut echoed).expect("client read payload");
        assert_eq!(&echoed, b"ping");
        drop(client);

        server_thread
            .join()
            .expect("server thread")
            .expect("serve once");
        echo_thread.join().expect("echo thread");

        let records = server.drain_traffic(1);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].node_tag, "panel|trojan|1");
        assert_eq!(records[0].user_uuid, "trojan-password");
        assert_eq!(records[0].upload, 4);
        assert_eq!(records[0].download, 4);
    }

    #[test]
    fn proxies_udp_associate_and_records_user_traffic() {
        let echo = UdpSocket::bind("127.0.0.1:0").expect("echo bind");
        let echo_addr = echo.local_addr().expect("echo addr");
        let echo_thread = thread::spawn(move || {
            let mut bytes = [0u8; 1024];
            let (read, source) = echo.recv_from(&mut bytes).expect("echo read");
            assert_eq!(&bytes[..read], b"ping");
            echo.send_to(b"pong", source).expect("echo write");
        });

        let server = server();
        let listener = server.bind().expect("trojan bind");
        let trojan_addr = listener.local_addr().expect("trojan addr");
        let server_clone = server.clone();
        let server_thread = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("trojan accept");
            server_clone.handle_tcp_client(stream)
        });

        let mut client = TcpStream::connect(trojan_addr).expect("client connect");
        client
            .set_read_timeout(Some(Duration::from_secs(3)))
            .expect("client timeout");
        client
            .write_all(&trojan_udp_associate_request(echo_addr))
            .expect("client request");
        client
            .write_all(&trojan_udp_packet(echo_addr, b"ping"))
            .expect("client udp packet");
        let (source, payload) = read_trojan_udp_packet(&mut client);
        assert_eq!(source, echo_addr);
        assert_eq!(payload, b"pong");
        drop(client);

        server_thread
            .join()
            .expect("server thread")
            .expect("serve once");
        echo_thread.join().expect("echo thread");

        let records = server.drain_traffic(1);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].node_tag, "panel|trojan|1");
        assert_eq!(records[0].user_uuid, "trojan-password");
        assert_eq!(records[0].upload, 4);
        assert_eq!(records[0].download, 4);
    }

    #[test]
    fn proxies_tls_and_records_user_traffic() {
        let cert = test_cert("trojan");
        let echo = TcpListener::bind("127.0.0.1:0").expect("echo bind");
        let echo_addr = echo.local_addr().expect("echo addr");
        let echo_thread = thread::spawn(move || {
            let (mut stream, _) = echo.accept().expect("echo accept");
            let mut bytes = [0u8; 4];
            stream.read_exact(&mut bytes).expect("echo read");
            stream.write_all(&bytes).expect("echo write");
        });

        let server = server();
        let listener = server.bind().expect("trojan bind");
        let trojan_addr = listener.local_addr().expect("trojan addr");
        let acceptor =
            TlsAcceptor::from_files(&cert.cert_path, &cert.key_path, &[]).expect("tls acceptor");
        let server_clone = server.clone();
        let server_thread = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("trojan accept");
            let client = acceptor.accept(stream).expect("tls accept");
            server_clone.handle_tls_client(client)
        });

        let mut client = tls_client(trojan_addr, cert.cert_der.clone());
        client
            .write_all(&trojan_request(echo_addr))
            .expect("client request");
        client.write_all(b"ping").expect("client write payload");
        let mut echoed = [0u8; 4];
        client.read_exact(&mut echoed).expect("client read payload");
        assert_eq!(&echoed, b"ping");
        drop(client);

        server_thread
            .join()
            .expect("server thread")
            .expect("serve once");
        echo_thread.join().expect("echo thread");

        let records = server.drain_traffic(1);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].node_tag, "panel|trojan|1");
        assert_eq!(records[0].user_uuid, "trojan-password");
        assert_eq!(records[0].upload, 4);
        assert_eq!(records[0].download, 4);
    }

    #[test]
    fn proxies_tls_websocket_and_records_user_traffic() {
        let cert = test_cert("trojan-ws");
        let echo = TcpListener::bind("127.0.0.1:0").expect("echo bind");
        let echo_addr = echo.local_addr().expect("echo addr");
        let echo_thread = thread::spawn(move || {
            let (mut stream, _) = echo.accept().expect("echo accept");
            let mut bytes = [0u8; 4];
            stream.read_exact(&mut bytes).expect("echo read");
            stream.write_all(&bytes).expect("echo write");
        });

        let server = server();
        let listener = server.bind().expect("trojan bind");
        let trojan_addr = listener.local_addr().expect("trojan addr");
        let acceptor =
            TlsAcceptor::from_files(&cert.cert_path, &cert.key_path, &[]).expect("tls acceptor");
        let server_clone = server.clone();
        let server_thread = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("trojan accept");
            let client = acceptor.accept(stream).expect("tls accept");
            server_clone.handle_tls_websocket_client(client, Some("/trojan"))
        });

        let mut client = tls_client(trojan_addr, cert.cert_der.clone());
        client
            .write_all(&websocket_request("/trojan"))
            .expect("websocket request");
        let response = read_websocket_response(&mut client);
        assert!(response.contains("101 Switching Protocols"));

        client
            .write_all(&masked_frame(&trojan_request(echo_addr)))
            .expect("trojan request frame");
        client.write_all(&masked_frame(b"ping")).expect("payload");
        assert_eq!(read_binary_frame(&mut client), b"ping");
        drop(client);

        server_thread
            .join()
            .expect("server thread")
            .expect("serve once");
        echo_thread.join().expect("echo thread");

        let records = server.drain_traffic(1);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].node_tag, "panel|trojan|1");
        assert_eq!(records[0].user_uuid, "trojan-password");
        assert_eq!(records[0].upload, 4);
        assert_eq!(records[0].download, 4);
    }

    #[test]
    fn proxies_websocket_and_records_user_traffic() {
        let echo = TcpListener::bind("127.0.0.1:0").expect("echo bind");
        let echo_addr = echo.local_addr().expect("echo addr");
        let echo_thread = thread::spawn(move || {
            let (mut stream, _) = echo.accept().expect("echo accept");
            let mut bytes = [0u8; 4];
            stream.read_exact(&mut bytes).expect("echo read");
            stream.write_all(&bytes).expect("echo write");
        });

        let server = server();
        let listener = server.bind().expect("trojan bind");
        let trojan_addr = listener.local_addr().expect("trojan addr");
        let server_clone = server.clone();
        let server_thread = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("trojan accept");
            server_clone.handle_websocket_client(stream, Some("/trojan"))
        });

        let mut client = TcpStream::connect(trojan_addr).expect("client connect");
        client
            .write_all(&websocket_request("/trojan"))
            .expect("websocket request");
        let response = read_websocket_response(&mut client);
        assert!(response.contains("101 Switching Protocols"));

        client
            .write_all(&masked_frame(&trojan_request(echo_addr)))
            .expect("trojan request frame");
        client.write_all(&masked_frame(b"ping")).expect("payload");
        assert_eq!(read_binary_frame(&mut client), b"ping");
        drop(client);

        server_thread
            .join()
            .expect("server thread")
            .expect("serve once");
        echo_thread.join().expect("echo thread");

        let records = server.drain_traffic(1);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].node_tag, "panel|trojan|1");
        assert_eq!(records[0].user_uuid, "trojan-password");
        assert_eq!(records[0].upload, 4);
        assert_eq!(records[0].download, 4);
    }
}
