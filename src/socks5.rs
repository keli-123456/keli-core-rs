use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs,
    UdpSocket,
};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use crate::limits::{
    BandwidthLimiter, UserBandwidthLimiters, UserSessionGuard, UserSessionTracker,
};
use crate::stream::relay_tcp_streams_limited;
use crate::traffic::TrafficRegistry;
use crate::user::CoreUser;
use crate::{RouteDecision, RouteMatcher};

const SOCKS5_VERSION: u8 = 0x05;
const AUTH_NONE: u8 = 0x00;
const AUTH_PASSWORD: u8 = 0x02;
const AUTH_NO_MATCHING_METHOD: u8 = 0xff;
const CMD_CONNECT: u8 = 0x01;
const CMD_UDP_ASSOCIATE: u8 = 0x03;
const STATUS_SUCCESS: u8 = 0x00;
const STATUS_CONNECTION_NOT_ALLOWED: u8 = 0x02;
const STATUS_COMMAND_NOT_SUPPORTED: u8 = 0x07;
const STATUS_ADDRESS_NOT_SUPPORTED: u8 = 0x08;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

#[derive(Clone, Debug)]
pub struct Socks5ServerConfig {
    pub node_tag: String,
    pub listen: SocketAddr,
    pub users: Vec<CoreUser>,
    pub routes: Vec<crate::RouteRule>,
    pub connect_timeout: Duration,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SocksTarget {
    pub host: String,
    pub port: u16,
}

#[derive(Clone, Debug)]
pub struct Socks5Server {
    config: Socks5ServerConfig,
    users: Arc<HashMap<String, CoreUser>>,
    router: RouteMatcher,
    traffic: Arc<Mutex<TrafficRegistry>>,
    sessions: UserSessionTracker,
    bandwidth: UserBandwidthLimiters,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SocksRequest {
    command: SocksCommand,
    user_uuid: Option<String>,
    target: SocksTarget,
    client_ip: Option<IpAddr>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum SocksCommand {
    Connect,
    UdpAssociate,
}

impl Socks5Server {
    pub fn new(config: Socks5ServerConfig) -> Self {
        Self::with_traffic(config, Arc::new(Mutex::new(TrafficRegistry::default())))
    }

    pub fn with_traffic(config: Socks5ServerConfig, traffic: Arc<Mutex<TrafficRegistry>>) -> Self {
        Self::with_shared_limits(
            config,
            traffic,
            UserSessionTracker::default(),
            UserBandwidthLimiters::default(),
        )
    }

    pub fn with_shared_limits(
        config: Socks5ServerConfig,
        traffic: Arc<Mutex<TrafficRegistry>>,
        sessions: UserSessionTracker,
        bandwidth: UserBandwidthLimiters,
    ) -> Self {
        let users = config
            .users
            .iter()
            .filter(|user| !user.is_empty())
            .map(|user| (user.uuid.clone(), user.clone()))
            .collect::<HashMap<_, _>>();

        Self {
            router: RouteMatcher::new(config.routes.clone()),
            config,
            users: Arc::new(users),
            traffic,
            sessions,
            bandwidth,
        }
    }

    pub fn bind(&self) -> io::Result<TcpListener> {
        TcpListener::bind(self.config.listen)
    }

    pub fn serve_tcp_once(&self, listener: &TcpListener) -> io::Result<()> {
        let (stream, _) = listener.accept()?;
        self.handle_tcp_client(stream)
    }

    pub fn handle_tcp_client(&self, mut client: TcpStream) -> io::Result<()> {
        let client_ip = client.peer_addr().ok().map(|addr| addr.ip());
        let mut request = match self.read_request(&mut client) {
            Ok(request) => request,
            Err(error) => {
                let _ = client.shutdown(Shutdown::Both);
                return Err(error);
            }
        };
        request.client_ip = client_ip;
        let user = self.request_user(&request);
        let _session = self.acquire_user_session(user, &mut client)?;
        let bandwidth = self.bandwidth.limiter_for(user);
        if request.command == SocksCommand::UdpAssociate {
            return self.handle_udp_associate(client, request, bandwidth);
        }
        let remote =
            match self
                .router
                .decide_target(&request.target.host, request.target.port, "tcp")
            {
                RouteDecision::Direct => {
                    connect_target(&request.target, self.config.connect_timeout)?
                }
                RouteDecision::Block => {
                    write_socks5_response(&mut client, STATUS_CONNECTION_NOT_ALLOWED)?;
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
        write_socks5_response(&mut client, STATUS_SUCCESS)?;
        self.relay(client, remote, request, bandwidth)
    }

    pub fn drain_traffic(&self, minimum_bytes: u64) -> Vec<crate::traffic::TrafficDelta> {
        self.traffic
            .lock()
            .expect("traffic registry lock poisoned")
            .drain_minimum(minimum_bytes)
    }

    fn read_request<T>(&self, stream: &mut T) -> io::Result<SocksRequest>
    where
        T: Read + Write,
    {
        let mut header = [0u8; 2];
        stream.read_exact(&mut header)?;
        if header[0] != SOCKS5_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported socks version",
            ));
        }

        let methods = read_exact_vec(stream, usize::from(header[1]))?;
        let selected_method = self.select_auth_method(&methods);
        stream.write_all(&[SOCKS5_VERSION, selected_method])?;

        let user_uuid = match selected_method {
            AUTH_NONE => None,
            AUTH_PASSWORD => Some(self.read_password_auth(stream)?),
            AUTH_NO_MATCHING_METHOD => {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "no matching socks auth method",
                ));
            }
            _ => unreachable!("selected auth method is controlled internally"),
        };

        self.read_command_request(stream, user_uuid)
    }

    fn select_auth_method(&self, methods: &[u8]) -> u8 {
        let required = if self.users.is_empty() {
            AUTH_NONE
        } else {
            AUTH_PASSWORD
        };
        methods
            .iter()
            .copied()
            .find(|method| *method == required)
            .unwrap_or(AUTH_NO_MATCHING_METHOD)
    }

    fn read_password_auth<T>(&self, stream: &mut T) -> io::Result<String>
    where
        T: Read + Write,
    {
        let mut version_and_len = [0u8; 2];
        stream.read_exact(&mut version_and_len)?;
        if version_and_len[0] != 0x01 {
            stream.write_all(&[0x01, 0xff])?;
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported username/password auth version",
            ));
        }

        let username = read_string(stream, usize::from(version_and_len[1]))?;
        let mut password_len = [0u8; 1];
        stream.read_exact(&mut password_len)?;
        let password = read_string(stream, usize::from(password_len[0]))?;

        match self.users.get(&username) {
            Some(user) if user.credential() == password => {
                stream.write_all(&[0x01, 0x00])?;
                Ok(user.uuid.clone())
            }
            _ => {
                stream.write_all(&[0x01, 0xff])?;
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "invalid username or password",
                ))
            }
        }
    }

    fn read_command_request<T>(
        &self,
        stream: &mut T,
        user_uuid: Option<String>,
    ) -> io::Result<SocksRequest>
    where
        T: Read + Write,
    {
        let mut header = [0u8; 4];
        stream.read_exact(&mut header)?;
        if header[0] != SOCKS5_VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported request version",
            ));
        }
        let command = match header[1] {
            CMD_CONNECT => SocksCommand::Connect,
            CMD_UDP_ASSOCIATE => SocksCommand::UdpAssociate,
            _ => {
                write_socks5_response(stream, STATUS_COMMAND_NOT_SUPPORTED)?;
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "only socks connect and udp associate are supported",
                ));
            }
        };
        if command == SocksCommand::UdpAssociate && header[2] != 0x00 {
            write_socks5_response(stream, STATUS_COMMAND_NOT_SUPPORTED)?;
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "socks udp associate request has invalid reserved byte",
            ));
        }

        let host = match header[3] {
            ATYP_IPV4 => {
                let mut bytes = [0u8; 4];
                stream.read_exact(&mut bytes)?;
                Ipv4Addr::from(bytes).to_string()
            }
            ATYP_IPV6 => {
                let mut bytes = [0u8; 16];
                stream.read_exact(&mut bytes)?;
                Ipv6Addr::from(bytes).to_string()
            }
            ATYP_DOMAIN => {
                let mut len = [0u8; 1];
                stream.read_exact(&mut len)?;
                read_string(stream, usize::from(len[0]))?
            }
            _ => {
                write_socks5_response(stream, STATUS_ADDRESS_NOT_SUPPORTED)?;
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unsupported socks address type",
                ));
            }
        };

        let mut port = [0u8; 2];
        stream.read_exact(&mut port)?;
        Ok(SocksRequest {
            command,
            user_uuid,
            target: SocksTarget {
                host,
                port: u16::from_be_bytes(port),
            },
            client_ip: None,
        })
    }

    fn relay(
        &self,
        client: TcpStream,
        remote: TcpStream,
        request: SocksRequest,
        bandwidth: Option<Arc<BandwidthLimiter>>,
    ) -> io::Result<()> {
        let (upload, download) = relay_tcp_streams_limited(client, remote, bandwidth)?;
        if let Some(user_uuid) = request.user_uuid {
            self.traffic
                .lock()
                .expect("traffic registry lock poisoned")
                .add_with_ip(
                    self.config.node_tag.clone(),
                    user_uuid,
                    upload,
                    download,
                    request.client_ip,
                );
        }
        Ok(())
    }

    fn handle_udp_associate(
        &self,
        mut control: TcpStream,
        request: SocksRequest,
        bandwidth: Option<Arc<BandwidthLimiter>>,
    ) -> io::Result<()> {
        let bind_addr = udp_bind_addr(control.local_addr()?);
        let udp = UdpSocket::bind(bind_addr)?;
        udp.set_read_timeout(Some(Duration::from_millis(100)))?;
        control.set_read_timeout(Some(Duration::from_millis(100)))?;
        write_socks5_response_with_bind(&mut control, STATUS_SUCCESS, udp.local_addr()?)?;

        let mut upload = 0u64;
        let mut download = 0u64;
        let mut client_udp_addr = None;
        let mut buffer = vec![0u8; 65_535];
        while control_is_open(&control)? {
            match udp.recv_from(&mut buffer) {
                Ok((read, source)) => {
                    if client_udp_addr.is_none() && source.ip() == control.peer_addr()?.ip() {
                        client_udp_addr = Some(source);
                    }
                    if Some(source) == client_udp_addr {
                        let (target, payload) = parse_udp_request(&buffer[..read])?;
                        match self.router.decide_target(&target.host, target.port, "udp") {
                            RouteDecision::Direct => {
                                if let Some(limiter) = bandwidth.as_deref() {
                                    limiter.wait_for(payload.len());
                                }
                                let remote_addr = resolve_udp_target(&target)?;
                                udp.send_to(payload, remote_addr)?;
                                upload = upload.saturating_add(payload.len() as u64);
                            }
                            RouteDecision::Block => {}
                            RouteDecision::UnsupportedOutbound(tag) => {
                                return Err(io::Error::new(
                                    io::ErrorKind::Unsupported,
                                    format!("outbound route {tag} is not implemented"),
                                ));
                            }
                        }
                    } else if let Some(client_addr) = client_udp_addr {
                        let response = encode_udp_response(source, &buffer[..read]);
                        udp.send_to(&response, client_addr)?;
                        download = download.saturating_add(read as u64);
                    }
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) => {}
                Err(error) => return Err(error),
            }
        }

        if let Some(user_uuid) = request.user_uuid {
            self.traffic
                .lock()
                .expect("traffic registry lock poisoned")
                .add_with_ip(
                    self.config.node_tag.clone(),
                    user_uuid,
                    upload,
                    download,
                    request.client_ip,
                );
        }
        Ok(())
    }

    fn request_user(&self, request: &SocksRequest) -> Option<&CoreUser> {
        request
            .user_uuid
            .as_deref()
            .and_then(|uuid| self.users.get(uuid))
    }

    fn acquire_user_session(
        &self,
        user: Option<&CoreUser>,
        client: &mut TcpStream,
    ) -> io::Result<Option<UserSessionGuard>> {
        let client_ip = client.peer_addr().ok().map(|addr| addr.ip());
        match self.sessions.try_acquire_for_ip(user, client_ip) {
            Ok(guard) => Ok(guard),
            Err(error) => {
                write_socks5_response(client, STATUS_CONNECTION_NOT_ALLOWED)?;
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    error.to_string(),
                ))
            }
        }
    }
}

fn udp_bind_addr(control_addr: SocketAddr) -> SocketAddr {
    SocketAddr::new(control_addr.ip(), 0)
}

fn connect_target(target: &SocksTarget, timeout: Duration) -> io::Result<TcpStream> {
    let addrs = (target.host.as_str(), target.port).to_socket_addrs()?;
    let mut last_error = None;
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(stream) => return Ok(stream),
            Err(error) => last_error = Some(error),
        }
    }
    Err(last_error.unwrap_or_else(|| {
        io::Error::new(
            io::ErrorKind::AddrNotAvailable,
            "target did not resolve to any socket address",
        )
    }))
}

fn resolve_udp_target(target: &SocksTarget) -> io::Result<SocketAddr> {
    (target.host.as_str(), target.port)
        .to_socket_addrs()?
        .next()
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "udp target did not resolve to any socket address",
            )
        })
}

fn control_is_open(control: &TcpStream) -> io::Result<bool> {
    let mut byte = [0u8; 1];
    match control.peek(&mut byte) {
        Ok(0) => Ok(false),
        Ok(_) => Ok(true),
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ) =>
        {
            Ok(true)
        }
        Err(error) => Err(error),
    }
}

fn parse_udp_request(input: &[u8]) -> io::Result<(SocksTarget, &[u8])> {
    if input.len() < 4 || input[0] != 0 || input[1] != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid socks udp request header",
        ));
    }
    if input[2] != 0 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "fragmented socks udp packets are not supported",
        ));
    }
    let mut offset = 4;
    let host = match input[3] {
        ATYP_IPV4 => {
            if input.len() < offset + 4 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated socks udp ipv4 address",
                ));
            }
            let mut bytes = [0u8; 4];
            bytes.copy_from_slice(&input[offset..offset + 4]);
            offset += 4;
            Ipv4Addr::from(bytes).to_string()
        }
        ATYP_IPV6 => {
            if input.len() < offset + 16 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated socks udp ipv6 address",
                ));
            }
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(&input[offset..offset + 16]);
            offset += 16;
            Ipv6Addr::from(bytes).to_string()
        }
        ATYP_DOMAIN => {
            if input.len() < offset + 1 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated socks udp domain length",
                ));
            }
            let len = usize::from(input[offset]);
            offset += 1;
            if input.len() < offset + len {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated socks udp domain",
                ));
            }
            let host = String::from_utf8(input[offset..offset + len].to_vec())
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid utf-8"))?;
            offset += len;
            host
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported socks udp address type",
            ));
        }
    };
    if input.len() < offset + 2 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "truncated socks udp port",
        ));
    }
    let port = u16::from_be_bytes([input[offset], input[offset + 1]]);
    offset += 2;
    Ok((SocksTarget { host, port }, &input[offset..]))
}

fn encode_udp_response(source: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(22 + payload.len());
    output.extend_from_slice(&[0, 0, 0]);
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
    output.extend_from_slice(payload);
    output
}

fn read_exact_vec<R: Read>(reader: &mut R, len: usize) -> io::Result<Vec<u8>> {
    let mut bytes = vec![0u8; len];
    reader.read_exact(&mut bytes)?;
    Ok(bytes)
}

fn read_string<R: Read>(reader: &mut R, len: usize) -> io::Result<String> {
    let bytes = read_exact_vec(reader, len)?;
    String::from_utf8(bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid utf-8"))
}

fn write_socks5_response<W: Write>(writer: &mut W, status: u8) -> io::Result<()> {
    write_socks5_response_with_bind(
        writer,
        status,
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0),
    )
}

fn write_socks5_response_with_bind<W: Write>(
    writer: &mut W,
    status: u8,
    bind: SocketAddr,
) -> io::Result<()> {
    let mut response = vec![SOCKS5_VERSION, status, 0x00];
    match bind.ip() {
        IpAddr::V4(ip) => {
            response.push(ATYP_IPV4);
            response.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            response.push(ATYP_IPV6);
            response.extend_from_slice(&ip.octets());
        }
    }
    response.extend_from_slice(&bind.port().to_be_bytes());
    writer.write_all(&response)
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Read, Write};
    use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket};
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    use crate::socks5::{Socks5Server, Socks5ServerConfig};
    use crate::user::CoreUser;
    use crate::{RouteAction, RouteRule};

    struct MemoryStream {
        input: Cursor<Vec<u8>>,
        output: Vec<u8>,
    }

    impl MemoryStream {
        fn new(input: Vec<u8>) -> Self {
            Self {
                input: Cursor::new(input),
                output: Vec::new(),
            }
        }
    }

    impl Read for MemoryStream {
        fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
            self.input.read(buf)
        }
    }

    impl Write for MemoryStream {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.output.extend_from_slice(buf);
            Ok(buf.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
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

    fn server() -> Socks5Server {
        Socks5Server::new(Socks5ServerConfig {
            node_tag: "panel|socks|1".to_string(),
            listen: "127.0.0.1:0".parse().expect("listen addr"),
            users: vec![user()],
            routes: Vec::new(),
            connect_timeout: Duration::from_secs(3),
        })
    }

    fn limited_server() -> Socks5Server {
        let mut user = user();
        user.device_limit = 1;
        Socks5Server::new(Socks5ServerConfig {
            node_tag: "panel|socks|1".to_string(),
            listen: "127.0.0.1:0".parse().expect("listen addr"),
            users: vec![user],
            routes: Vec::new(),
            connect_timeout: Duration::from_secs(3),
        })
    }

    fn write_authenticated_ipv4_connect(client: &mut TcpStream, target: SocketAddr) {
        write_authenticated_ipv4_request(client, 0x01, target);
    }

    fn write_authenticated_ipv4_udp_associate(client: &mut TcpStream, target: SocketAddr) {
        write_authenticated_ipv4_request(client, 0x03, target);
    }

    fn write_authenticated_ipv4_request(client: &mut TcpStream, command: u8, target: SocketAddr) {
        client
            .write_all(&[
                0x05, 0x01, 0x02, 0x01, 0x06, b'u', b's', b'e', b'r', b'-', b'a', 0x06, b'u', b's',
                b'e', b'r', b'-', b'a', 0x05, command, 0x00, 0x01,
            ])
            .expect("client greeting");
        client
            .write_all(
                &target
                    .ip()
                    .to_string()
                    .parse::<std::net::Ipv4Addr>()
                    .expect("ipv4")
                    .octets(),
            )
            .expect("client target ip");
        client
            .write_all(&target.port().to_be_bytes())
            .expect("client target port");
    }

    fn udp_packet(target: SocketAddr, payload: &[u8]) -> Vec<u8> {
        let mut packet = vec![0, 0, 0, 0x01];
        packet.extend_from_slice(
            &target
                .ip()
                .to_string()
                .parse::<std::net::Ipv4Addr>()
                .expect("ipv4")
                .octets(),
        );
        packet.extend_from_slice(&target.port().to_be_bytes());
        packet.extend_from_slice(payload);
        packet
    }

    fn read_ipv4_udp_payload(packet: &[u8]) -> (SocketAddr, &[u8]) {
        assert_eq!(&packet[..4], &[0, 0, 0, 0x01]);
        let ip = std::net::Ipv4Addr::new(packet[4], packet[5], packet[6], packet[7]);
        let port = u16::from_be_bytes([packet[8], packet[9]]);
        (SocketAddr::new(ip.into(), port), &packet[10..])
    }

    fn socks_reply_addr(response: &[u8]) -> SocketAddr {
        assert_eq!(&response[0..4], &[0x05, 0x00, 0x00, 0x01]);
        let ip = std::net::Ipv4Addr::new(response[4], response[5], response[6], response[7]);
        let port = u16::from_be_bytes([response[8], response[9]]);
        SocketAddr::new(ip.into(), port)
    }

    #[test]
    fn parses_authenticated_domain_connect() {
        let server = server();
        let mut input = vec![
            0x05, 0x01, 0x02, 0x01, 0x06, b'u', b's', b'e', b'r', b'-', b'a', 0x06, b'u', b's',
            b'e', b'r', b'-', b'a', 0x05, 0x01, 0x00, 0x03, 0x0b, b'e', b'x', b'a', b'm', b'p',
            b'l', b'e', b'.', b'c', b'o', b'm',
        ];
        input.extend_from_slice(&443u16.to_be_bytes());
        let mut stream = MemoryStream::new(input);

        let request = server.read_request(&mut stream).expect("request");

        assert_eq!(request.user_uuid.as_deref(), Some("user-a"));
        assert_eq!(request.target.host, "example.com");
        assert_eq!(request.target.port, 443);
        assert_eq!(stream.output, vec![0x05, 0x02, 0x01, 0x00]);
    }

    #[test]
    fn rejects_invalid_password() {
        let server = server();
        let mut input = vec![
            0x05, 0x01, 0x02, 0x01, 0x06, b'u', b's', b'e', b'r', b'-', b'a', 0x03, b'b', b'a',
            b'd',
        ];
        let mut stream = MemoryStream::new(std::mem::take(&mut input));

        let error = server
            .read_request(&mut stream)
            .expect_err("auth should fail");

        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(stream.output, vec![0x05, 0x02, 0x01, 0xff]);
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
        let listener = server.bind().expect("socks bind");
        let socks_addr = listener.local_addr().expect("socks addr");
        let server_clone = server.clone();
        let server_thread = thread::spawn(move || server_clone.serve_tcp_once(&listener));

        let mut client = TcpStream::connect(socks_addr).expect("client connect");
        write_authenticated_ipv4_connect(&mut client, echo_addr);

        let mut response = [0u8; 14];
        client.read_exact(&mut response).expect("client response");
        assert_eq!(&response[0..2], &[0x05, 0x02]);
        assert_eq!(&response[2..4], &[0x01, 0x00]);
        assert_eq!(&response[4..6], &[0x05, 0x00]);

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
        assert_eq!(records[0].node_tag, "panel|socks|1");
        assert_eq!(records[0].user_uuid, "user-a");
        assert_eq!(records[0].upload, 4);
        assert_eq!(records[0].download, 4);
    }

    #[test]
    fn rejects_blocked_tcp_route_with_connection_not_allowed_reply() {
        let target = "127.0.0.1:48888".parse().expect("target addr");
        let server = Socks5Server::new(Socks5ServerConfig {
            node_tag: "panel|socks|1".to_string(),
            listen: "127.0.0.1:0".parse().expect("listen addr"),
            users: vec![user()],
            routes: vec![RouteRule {
                targets: vec!["port:48888".to_string()],
                action: RouteAction::Block,
            }],
            connect_timeout: Duration::from_secs(3),
        });
        let listener = server.bind().expect("socks bind");
        let socks_addr = listener.local_addr().expect("socks addr");
        let server_thread = thread::spawn(move || server.serve_tcp_once(&listener));

        let mut client = TcpStream::connect(socks_addr).expect("client connect");
        write_authenticated_ipv4_connect(&mut client, target);
        let mut response = [0u8; 14];
        client.read_exact(&mut response).expect("client response");

        let error = server_thread
            .join()
            .expect("server thread")
            .expect_err("blocked route should reject connection");
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
        assert_eq!(&response[4..6], &[0x05, 0x02]);
    }

    #[test]
    fn proxies_udp_associate_and_records_user_traffic() {
        let echo = UdpSocket::bind("127.0.0.1:0").expect("echo bind");
        let echo_addr = echo.local_addr().expect("echo addr");
        let echo_thread = thread::spawn(move || {
            let mut buffer = [0u8; 1024];
            let (read, source) = echo.recv_from(&mut buffer).expect("echo read");
            assert_eq!(&buffer[..read], b"ping");
            echo.send_to(b"pong", source).expect("echo write");
        });

        let server = server();
        let listener = server.bind().expect("socks bind");
        let socks_addr = listener.local_addr().expect("socks addr");
        let server_clone = server.clone();
        let server_thread = thread::spawn(move || server_clone.serve_tcp_once(&listener));

        let mut control = TcpStream::connect(socks_addr).expect("client connect");
        let client_udp = UdpSocket::bind("127.0.0.1:0").expect("client udp bind");
        client_udp
            .set_read_timeout(Some(Duration::from_secs(3)))
            .expect("client udp timeout");
        write_authenticated_ipv4_udp_associate(
            &mut control,
            "0.0.0.0:0".parse().expect("associate addr"),
        );

        let mut response = [0u8; 14];
        control
            .read_exact(&mut response)
            .expect("client udp associate response");
        assert_eq!(&response[0..4], &[0x05, 0x02, 0x01, 0x00]);
        let relay_addr = socks_reply_addr(&response[4..14]);

        client_udp
            .send_to(&udp_packet(echo_addr, b"ping"), relay_addr)
            .expect("send udp packet");
        let mut packet = [0u8; 1024];
        let (read, _) = client_udp
            .recv_from(&mut packet)
            .expect("read udp response");
        let (source, payload) = read_ipv4_udp_payload(&packet[..read]);
        assert_eq!(source, echo_addr);
        assert_eq!(payload, b"pong");
        drop(control);

        server_thread
            .join()
            .expect("server thread")
            .expect("serve once");
        echo_thread.join().expect("echo thread");

        let records = server.drain_traffic(1);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].node_tag, "panel|socks|1");
        assert_eq!(records[0].user_uuid, "user-a");
        assert_eq!(records[0].upload, 4);
        assert_eq!(records[0].download, 4);
    }

    #[test]
    fn allows_same_ip_to_reuse_device_limit_slot() {
        let target = TcpListener::bind("127.0.0.1:0").expect("target bind");
        let target_addr = target.local_addr().expect("target addr");
        let (release_tx, release_rx) = mpsc::channel();
        let target_thread = thread::spawn(move || {
            let (first, _) = target.accept().expect("first target accept");
            let (second, _) = target.accept().expect("second target accept");
            release_rx.recv().expect("release target");
            let _ = first.shutdown(Shutdown::Both);
            let _ = second.shutdown(Shutdown::Both);
        });

        let server = limited_server();
        let listener = server.bind().expect("socks bind");
        let socks_addr = listener.local_addr().expect("socks addr");

        let first_listener = listener.try_clone().expect("first listener");
        let first_server = server.clone();
        let first_thread = thread::spawn(move || first_server.serve_tcp_once(&first_listener));
        let mut first_client = TcpStream::connect(socks_addr).expect("first client");
        write_authenticated_ipv4_connect(&mut first_client, target_addr);
        let mut first_response = [0u8; 14];
        first_client
            .read_exact(&mut first_response)
            .expect("first response");
        assert_eq!(&first_response[4..6], &[0x05, 0x00]);

        let second_listener = listener.try_clone().expect("second listener");
        let second_server = server.clone();
        let second_thread = thread::spawn(move || second_server.serve_tcp_once(&second_listener));
        let mut second_client = TcpStream::connect(socks_addr).expect("second client");
        write_authenticated_ipv4_connect(&mut second_client, target_addr);
        let mut second_response = [0u8; 14];
        second_client
            .read_exact(&mut second_response)
            .expect("second response");

        assert_eq!(&second_response[4..6], &[0x05, 0x00]);
        drop(second_client);
        drop(first_client);
        release_tx.send(()).expect("release target");
        let _ = second_thread.join().expect("second server thread");
        first_thread
            .join()
            .expect("first server thread")
            .expect("first connection should close cleanly");
        target_thread.join().expect("target thread");
    }
}
