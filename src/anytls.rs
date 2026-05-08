use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use sha2::{Digest, Sha256};

use crate::limits::{
    BandwidthLimiter, UserBandwidthLimiters, UserSessionGuard, UserSessionTracker,
};
use crate::socks5::SocksTarget;
use crate::traffic::TrafficRegistry;
use crate::user::CoreUser;
use crate::{RouteDecision, RouteMatcher};

const CMD_WASTE: u8 = 0;
const CMD_SYN: u8 = 1;
const CMD_PSH: u8 = 2;
const CMD_FIN: u8 = 3;
const CMD_SETTINGS: u8 = 4;
const CMD_SYNACK: u8 = 7;
const CMD_HEART_REQUEST: u8 = 8;
const CMD_HEART_RESPONSE: u8 = 9;
const CMD_SERVER_SETTINGS: u8 = 10;
const FRAME_HEADER_LEN: usize = 7;
const MAX_FRAME_PAYLOAD: usize = 0xffff;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

#[derive(Clone, Debug)]
pub struct AnyTlsServerConfig {
    pub node_tag: String,
    pub listen: SocketAddr,
    pub users: Vec<CoreUser>,
    pub routes: Vec<crate::RouteRule>,
    pub connect_timeout: Duration,
}

#[derive(Clone, Debug)]
pub struct AnyTlsServer {
    config: AnyTlsServerConfig,
    users: Arc<HashMap<[u8; 32], CoreUser>>,
    router: RouteMatcher,
    traffic: Arc<Mutex<TrafficRegistry>>,
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
    user: CoreUser,
    writer: Arc<Mutex<TcpStream>>,
    remotes: HashMap<u32, TcpStream>,
    workers: Vec<JoinHandle<()>>,
    traffic: Arc<Mutex<(u64, u64)>>,
    bandwidth: Option<Arc<BandwidthLimiter>>,
}

impl AnyTlsServer {
    pub fn new(config: AnyTlsServerConfig) -> Self {
        Self::with_traffic(config, Arc::new(Mutex::new(TrafficRegistry::default())))
    }

    pub fn with_traffic(config: AnyTlsServerConfig, traffic: Arc<Mutex<TrafficRegistry>>) -> Self {
        Self::with_shared_limits(
            config,
            traffic,
            UserSessionTracker::default(),
            UserBandwidthLimiters::default(),
        )
    }

    pub fn with_shared_limits(
        config: AnyTlsServerConfig,
        traffic: Arc<Mutex<TrafficRegistry>>,
        sessions: UserSessionTracker,
        bandwidth: UserBandwidthLimiters,
    ) -> Self {
        let users = config
            .users
            .iter()
            .filter(|user| !user.is_empty())
            .map(|user| (sha256(user.credential()), user.clone()))
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

    pub fn handle_tcp_client(&self, mut client: TcpStream) -> io::Result<()> {
        let user = self.read_auth(&mut client)?;
        let _session = self.acquire_user_session(&user)?;
        let writer = Arc::new(Mutex::new(client.try_clone()?));
        let mut session = AnyTlsSession {
            bandwidth: self.bandwidth.limiter_for(Some(&user)),
            user,
            writer,
            remotes: HashMap::new(),
            workers: Vec::new(),
            traffic: Arc::new(Mutex::new((0, 0))),
        };

        let result = self.read_frames(&mut client, &mut session);
        for (_, remote) in session.remotes.drain() {
            let _ = remote.shutdown(Shutdown::Both);
        }
        for worker in session.workers {
            let _ = worker.join();
        }
        let (upload, download) = *session.traffic.lock().expect("traffic lock poisoned");
        if upload > 0 || download > 0 {
            self.traffic
                .lock()
                .expect("traffic registry lock poisoned")
                .add(
                    self.config.node_tag.clone(),
                    session.user.uuid,
                    upload,
                    download,
                );
        }
        result
    }

    pub fn drain_traffic(&self, minimum_bytes: u64) -> Vec<crate::traffic::TrafficDelta> {
        self.traffic
            .lock()
            .expect("traffic registry lock poisoned")
            .drain_minimum(minimum_bytes)
    }

    fn read_auth(&self, client: &mut TcpStream) -> io::Result<CoreUser> {
        let mut auth = [0u8; 34];
        client.read_exact(&mut auth)?;
        let mut password_hash = [0u8; 32];
        password_hash.copy_from_slice(&auth[..32]);
        let Some(user) = self.users.get(&password_hash) else {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "unknown anytls user",
            ));
        };
        let padding_len = u16::from_be_bytes([auth[32], auth[33]]) as usize;
        if padding_len > 0 {
            discard(client, padding_len)?;
        }
        Ok(user.clone())
    }

    fn read_frames(&self, client: &mut TcpStream, session: &mut AnyTlsSession) -> io::Result<()> {
        loop {
            let header = match read_frame_header(client) {
                Ok(header) => header,
                Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => return Ok(()),
                Err(error) if error.kind() == io::ErrorKind::ConnectionReset => return Ok(()),
                Err(error) => return Err(error),
            };
            let body = read_frame_body(client, header.len)?;
            match header.command {
                CMD_WASTE => {}
                CMD_SETTINGS => {
                    if body.windows(3).any(|window| window == b"v=2") {
                        write_frame(&session.writer, CMD_SERVER_SETTINGS, 0, b"v=2")?;
                    }
                }
                CMD_HEART_REQUEST => {
                    write_frame(&session.writer, CMD_HEART_RESPONSE, 0, &[])?;
                }
                CMD_SYN => {
                    write_frame(&session.writer, CMD_SYNACK, header.stream_id, &[])?;
                }
                CMD_PSH => {
                    self.handle_psh(session, header.stream_id, body)?;
                }
                CMD_FIN => {
                    if let Some(remote) = session.remotes.remove(&header.stream_id) {
                        let _ = remote.shutdown(Shutdown::Write);
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

    fn handle_psh(
        &self,
        session: &mut AnyTlsSession,
        stream_id: u32,
        body: Vec<u8>,
    ) -> io::Result<()> {
        if body.is_empty() {
            return Ok(());
        }

        if let Some(remote) = session.remotes.get_mut(&stream_id) {
            if let Some(limiter) = session.bandwidth.as_deref() {
                limiter.wait_for(body.len());
            }
            remote.write_all(&body)?;
            session.traffic.lock().expect("traffic lock poisoned").0 += body.len() as u64;
            return Ok(());
        }

        let (target, consumed) = parse_socks_addr(&body)?;
        let remote = match self.router.decide(&target.host) {
            RouteDecision::Direct => connect_target(&target, self.config.connect_timeout)?,
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
        let mut remote_read = remote.try_clone()?;
        let writer = session.writer.clone();
        let traffic = session.traffic.clone();
        session.workers.push(thread::spawn(move || {
            pump_downlink(stream_id, &mut remote_read, writer, traffic);
        }));
        session.remotes.insert(stream_id, remote);
        write_frame(&session.writer, CMD_SYNACK, stream_id, &[])?;

        if consumed < body.len() {
            let payload = &body[consumed..];
            if let Some(limiter) = session.bandwidth.as_deref() {
                limiter.wait_for(payload.len());
            }
            if let Some(remote) = session.remotes.get_mut(&stream_id) {
                remote.write_all(payload)?;
                session.traffic.lock().expect("traffic lock poisoned").0 += payload.len() as u64;
            }
        }

        Ok(())
    }

    fn acquire_user_session(&self, user: &CoreUser) -> io::Result<Option<UserSessionGuard>> {
        match self.sessions.try_acquire(Some(user)) {
            Ok(guard) => Ok(guard),
            Err(error) => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                error.to_string(),
            )),
        }
    }
}

fn pump_downlink(
    stream_id: u32,
    remote: &mut TcpStream,
    writer: Arc<Mutex<TcpStream>>,
    traffic: Arc<Mutex<(u64, u64)>>,
) {
    let mut buffer = [0u8; 16 * 1024];
    loop {
        let read = match remote.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => read,
            Err(_) => break,
        };
        traffic.lock().expect("traffic lock poisoned").1 += read as u64;
        if write_frame(&writer, CMD_PSH, stream_id, &buffer[..read]).is_err() {
            return;
        }
    }
    let _ = write_frame(&writer, CMD_FIN, stream_id, &[]);
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
    stream.write_all(&[
        command,
        (stream_id >> 24) as u8,
        (stream_id >> 16) as u8,
        (stream_id >> 8) as u8,
        stream_id as u8,
        (payload.len() >> 8) as u8,
        payload.len() as u8,
    ])?;
    stream.write_all(payload)?;
    stream.flush()
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

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::thread;
    use std::time::Duration;

    use crate::anytls::{
        parse_socks_addr, read_frame_header, sha256, AnyTlsServer, AnyTlsServerConfig, ATYP_DOMAIN,
        ATYP_IPV4, CMD_FIN, CMD_HEART_REQUEST, CMD_HEART_RESPONSE, CMD_PSH, CMD_SYNACK,
    };
    use crate::user::CoreUser;

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

    fn server() -> AnyTlsServer {
        AnyTlsServer::new(AnyTlsServerConfig {
            node_tag: "panel|anytls|1".to_string(),
            listen: "127.0.0.1:0".parse().expect("listen addr"),
            users: vec![user()],
            routes: Vec::new(),
            connect_timeout: Duration::from_secs(3),
        })
    }

    fn write_auth(client: &mut TcpStream, password: &str) {
        client
            .write_all(&sha256(password))
            .expect("auth password hash");
        client.write_all(&0u16.to_be_bytes()).expect("auth padding");
    }

    fn write_frame(client: &mut TcpStream, command: u8, stream_id: u32, payload: &[u8]) {
        client
            .write_all(&[
                command,
                (stream_id >> 24) as u8,
                (stream_id >> 16) as u8,
                (stream_id >> 8) as u8,
                stream_id as u8,
                (payload.len() >> 8) as u8,
                payload.len() as u8,
            ])
            .expect("frame header");
        client.write_all(payload).expect("frame payload");
    }

    fn read_frame(client: &mut TcpStream) -> (u8, u32, Vec<u8>) {
        let header = read_frame_header(client).expect("frame header");
        let mut body = vec![0u8; header.len];
        client.read_exact(&mut body).expect("frame body");
        (header.command, header.stream_id, body)
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
        assert_eq!(records[0].upload, 4);
        assert_eq!(records[0].download, 4);
    }
}
