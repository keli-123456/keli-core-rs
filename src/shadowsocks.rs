use std::collections::HashMap;
use std::io::{self, Read, Write};
use std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket,
};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::{Duration, Instant};

use aes_gcm::aead::{AeadInPlace, KeyInit};
use aes_gcm::{Aes128Gcm, Aes256Gcm, Nonce as AesNonce};
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaChaNonce};
use hkdf::Hkdf;
use md5::{Digest as Md5Digest, Md5};
use sha1::Sha1;

use crate::limits::{
    BandwidthLimiter, UserBandwidthLimiters, UserSessionGuard, UserSessionTracker,
};
use crate::outbound::recv_udp_response;
use crate::socks5::SocksTarget;
use crate::stream::copy_count_best_effort_limited;
use crate::traffic::TrafficRegistry;
use crate::user::CoreUser;
use crate::{
    connect_tcp_outbound, route_protocol_labels, send_udp_outbound, RouteDecision, RouteMatcher,
};

const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;
const TAG_LEN: usize = 16;
const NONCE_LEN: usize = 12;
const MAX_CHUNK_LEN: usize = 0x3fff;
const HKDF_INFO: &[u8] = b"ss-subkey";
const UDP_SESSION_TTL: Duration = Duration::from_secs(300);

#[derive(Clone, Debug)]
pub struct ShadowsocksServerConfig {
    pub node_tag: String,
    pub listen: SocketAddr,
    pub method: String,
    pub users: Vec<CoreUser>,
    pub routes: Vec<crate::RouteRule>,
    pub connect_timeout: Duration,
}

#[derive(Clone, Debug)]
pub struct ShadowsocksServer {
    config: ShadowsocksServerConfig,
    users: Arc<RwLock<Vec<CoreUser>>>,
    router: RouteMatcher,
    traffic: Arc<Mutex<TrafficRegistry>>,
    sessions: UserSessionTracker,
    bandwidth: UserBandwidthLimiters,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ShadowsocksMethod {
    Aes128Gcm,
    Aes256Gcm,
    ChaCha20IetfPoly1305,
}

enum ShadowsocksAead {
    Aes128(Aes128Gcm),
    Aes256(Aes256Gcm),
    ChaCha20(ChaCha20Poly1305),
}

struct ShadowsocksCipher {
    aead: ShadowsocksAead,
    nonce: u64,
}

struct ShadowsocksRequest {
    user: CoreUser,
    target: SocksTarget,
    initial_payload: Vec<u8>,
    client_reader: ShadowsocksReader<TcpStream>,
    client_ip: Option<IpAddr>,
}

struct ShadowsocksUdpRequest {
    user: CoreUser,
    target: SocksTarget,
    payload: Vec<u8>,
}

#[derive(Clone, Debug)]
struct UdpClientContext {
    client_addr: SocketAddr,
    user: CoreUser,
}

#[derive(Debug)]
struct UdpClientSession {
    user_uuid: String,
    last_seen: Instant,
    _guard: Option<UserSessionGuard>,
}

struct ShadowsocksReader<R> {
    reader: R,
    cipher: ShadowsocksCipher,
    buffer: Vec<u8>,
}

struct ShadowsocksWriter<W> {
    writer: W,
    cipher: ShadowsocksCipher,
}

impl ShadowsocksServer {
    pub fn new(config: ShadowsocksServerConfig) -> Self {
        Self::with_traffic(config, Arc::new(Mutex::new(TrafficRegistry::default())))
    }

    pub fn with_traffic(
        config: ShadowsocksServerConfig,
        traffic: Arc<Mutex<TrafficRegistry>>,
    ) -> Self {
        Self::with_shared_limits(
            config,
            traffic,
            UserSessionTracker::default(),
            UserBandwidthLimiters::default(),
        )
    }

    pub fn with_shared_limits(
        config: ShadowsocksServerConfig,
        traffic: Arc<Mutex<TrafficRegistry>>,
        sessions: UserSessionTracker,
        bandwidth: UserBandwidthLimiters,
    ) -> Self {
        let users = active_user_list(&config.users);
        Self {
            router: RouteMatcher::new(config.routes.clone()),
            config,
            users: Arc::new(RwLock::new(users)),
            traffic,
            sessions,
            bandwidth,
        }
    }

    pub fn bind(&self) -> io::Result<TcpListener> {
        TcpListener::bind(self.config.listen)
    }

    pub fn bind_udp(&self, listen: SocketAddr) -> io::Result<UdpSocket> {
        UdpSocket::bind(listen)
    }

    pub fn handle_tcp_client(&self, client: TcpStream) -> io::Result<()> {
        let client_ip = client.peer_addr().ok().map(|addr| addr.ip());
        let method = ShadowsocksMethod::parse(&self.config.method)?;
        let mut request = self.read_request(client, method)?;
        request.client_ip = client_ip;
        let _session = self.acquire_user_session(&request.user, client_ip)?;
        let bandwidth = self.bandwidth.limiter_for(Some(&request.user));
        let protocol_labels = route_protocol_labels("tcp", &request.initial_payload);
        let remote = match self.router.decide_target(
            &request.target.host,
            request.target.port,
            &protocol_labels,
        ) {
            RouteDecision::Direct => connect_target(&request.target, self.config.connect_timeout)?,
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
        self.relay(method, request, remote, bandwidth)
    }

    pub fn drain_traffic(&self, minimum_bytes: u64) -> Vec<crate::traffic::TrafficDelta> {
        self.traffic
            .lock()
            .expect("traffic registry lock poisoned")
            .drain_minimum(minimum_bytes)
    }

    pub fn replace_users(&self, users: Vec<CoreUser>) {
        let mut current = self.users.write().expect("shadowsocks users lock poisoned");
        *current = active_user_list(&users);
    }

    fn active_users(&self) -> Vec<CoreUser> {
        self.users
            .read()
            .expect("shadowsocks users lock poisoned")
            .clone()
    }

    pub fn serve_udp(&self, udp: UdpSocket, stop: Arc<AtomicBool>) -> io::Result<()> {
        udp.set_read_timeout(Some(Duration::from_millis(100)))?;
        let method = ShadowsocksMethod::parse(&self.config.method)?;
        let mut remotes = HashMap::<SocketAddr, UdpClientContext>::new();
        let mut client_sessions = HashMap::<SocketAddr, UdpClientSession>::new();
        let mut buffer = vec![0u8; 65_535];
        while !stop.load(Ordering::SeqCst) {
            prune_udp_sessions(&mut client_sessions, &mut remotes);
            match recv_udp_response(&udp, &mut buffer) {
                Ok((read, source)) => {
                    let packet = &buffer[..read];
                    if let Ok(request) = self.read_udp_request(packet, method) {
                        self.handle_udp_request(
                            &udp,
                            method,
                            source,
                            request,
                            &mut remotes,
                            &mut client_sessions,
                        )?;
                    } else if let Some(context) = remotes.get(&source) {
                        let response = encode_udp_packet(method, context, source, packet)?;
                        udp.send_to(&response, context.client_addr)?;
                        if let Some(session) = client_sessions.get_mut(&context.client_addr) {
                            session.last_seen = Instant::now();
                        }
                        self.record_udp_traffic(
                            &context.user.uuid,
                            0,
                            packet.len() as u64,
                            Some(context.client_addr.ip()),
                        );
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
        Ok(())
    }

    fn read_request(
        &self,
        mut client: TcpStream,
        method: ShadowsocksMethod,
    ) -> io::Result<ShadowsocksRequest> {
        let mut salt = vec![0u8; method.salt_len()];
        client.read_exact(&mut salt)?;
        let mut encrypted_len = vec![0u8; 2 + TAG_LEN];
        client.read_exact(&mut encrypted_len)?;

        for user in self.active_users() {
            let mut cipher = ShadowsocksCipher::new(method, user.credential(), &salt)?;
            let mut len_bytes = encrypted_len.clone();
            if cipher.decrypt(&mut len_bytes).is_err() || len_bytes.len() != 2 {
                continue;
            }

            let payload_len = u16::from_be_bytes([len_bytes[0], len_bytes[1]]) as usize;
            if payload_len == 0 || payload_len > MAX_CHUNK_LEN {
                continue;
            }

            let mut encrypted_payload = vec![0u8; payload_len + TAG_LEN];
            client.read_exact(&mut encrypted_payload)?;
            cipher.decrypt(&mut encrypted_payload)?;
            let (target, initial_payload) = parse_request_payload(encrypted_payload)?;
            return Ok(ShadowsocksRequest {
                user,
                target,
                initial_payload,
                client_reader: ShadowsocksReader::with_cipher(client, cipher),
                client_ip: None,
            });
        }

        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unknown shadowsocks user",
        ))
    }

    fn read_udp_request(
        &self,
        packet: &[u8],
        method: ShadowsocksMethod,
    ) -> io::Result<ShadowsocksUdpRequest> {
        if packet.len() <= method.salt_len() + TAG_LEN {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "shadowsocks udp packet too short",
            ));
        }
        let (salt, encrypted_payload) = packet.split_at(method.salt_len());
        for user in self.active_users() {
            let mut payload = encrypted_payload.to_vec();
            let mut cipher = ShadowsocksCipher::new(method, user.credential(), salt)?;
            if cipher.decrypt(&mut payload).is_err() {
                continue;
            }
            let (target, payload) = parse_request_payload(payload)?;
            return Ok(ShadowsocksUdpRequest {
                user,
                target,
                payload,
            });
        }
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "unknown shadowsocks udp user",
        ))
    }

    fn handle_udp_request(
        &self,
        udp: &UdpSocket,
        method: ShadowsocksMethod,
        client_addr: SocketAddr,
        request: ShadowsocksUdpRequest,
        remotes: &mut HashMap<SocketAddr, UdpClientContext>,
        client_sessions: &mut HashMap<SocketAddr, UdpClientSession>,
    ) -> io::Result<()> {
        let protocol_labels = route_protocol_labels("udp", &request.payload);
        let decision =
            self.router
                .decide_target(&request.target.host, request.target.port, &protocol_labels);
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
        if let Err(error) =
            self.acquire_udp_client_session(client_addr, &request.user, client_sessions)
        {
            if error.kind() == io::ErrorKind::PermissionDenied {
                return Ok(());
            }
            return Err(error);
        }
        if let Some(limiter) = self.bandwidth.limiter_for(Some(&request.user)).as_deref() {
            limiter.wait_for(request.payload.len());
        }
        if let Some(outbound) = outbound {
            match send_udp_outbound(
                outbound,
                &request.target,
                &request.payload,
                self.config.connect_timeout,
            ) {
                Ok((source, response_payload)) => {
                    let context = UdpClientContext {
                        client_addr,
                        user: request.user.clone(),
                    };
                    let response = encode_udp_packet(method, &context, source, &response_payload)?;
                    udp.send_to(&response, client_addr)?;
                    self.record_udp_traffic(
                        &request.user.uuid,
                        request.payload.len() as u64,
                        response_payload.len() as u64,
                        Some(client_addr.ip()),
                    );
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    self.record_udp_traffic(
                        &request.user.uuid,
                        request.payload.len() as u64,
                        0,
                        Some(client_addr.ip()),
                    );
                }
                Err(error) => return Err(error),
            }
            return Ok(());
        }

        let target = request.target.clone();
        let remote_addr = resolve_udp_target(&target)?;
        udp.send_to(&request.payload, remote_addr)?;
        remotes.insert(
            remote_addr,
            UdpClientContext {
                client_addr,
                user: request.user.clone(),
            },
        );
        self.record_udp_traffic(
            &request.user.uuid,
            request.payload.len() as u64,
            0,
            Some(client_addr.ip()),
        );
        Ok(())
    }

    fn acquire_udp_client_session(
        &self,
        client_addr: SocketAddr,
        user: &CoreUser,
        client_sessions: &mut HashMap<SocketAddr, UdpClientSession>,
    ) -> io::Result<()> {
        if let Some(session) = client_sessions.get_mut(&client_addr) {
            if session.user_uuid == user.uuid {
                session.last_seen = Instant::now();
                return Ok(());
            }
            client_sessions.remove(&client_addr);
        }

        let guard = self.acquire_user_session(user, Some(client_addr.ip()))?;
        client_sessions.insert(
            client_addr,
            UdpClientSession {
                user_uuid: user.uuid.clone(),
                last_seen: Instant::now(),
                _guard: guard,
            },
        );
        Ok(())
    }

    fn relay(
        &self,
        method: ShadowsocksMethod,
        request: ShadowsocksRequest,
        mut remote: TcpStream,
        bandwidth: Option<Arc<BandwidthLimiter>>,
    ) -> io::Result<()> {
        let user_uuid = request.user.uuid.clone();
        let password = request.user.credential().to_string();
        let response_stream = request.client_reader.reader.try_clone()?;
        let mut upload = 0u64;
        if !request.initial_payload.is_empty() {
            if let Some(limiter) = bandwidth.as_deref() {
                limiter.wait_for(request.initial_payload.len());
            }
            remote.write_all(&request.initial_payload)?;
            upload = request.initial_payload.len() as u64;
        }

        let mut encrypted_client = request.client_reader;
        let mut remote_write = remote.try_clone()?;
        let upload_limiter = bandwidth.clone();
        let upload_thread = thread::spawn(move || {
            let copied = copy_count_best_effort_limited(
                &mut encrypted_client,
                &mut remote_write,
                upload_limiter.as_deref(),
            );
            let _ = remote_write.shutdown(Shutdown::Write);
            copied
        });

        let mut remote_read = remote;
        let mut encrypted_writer =
            ShadowsocksWriter::new_response(response_stream, method, &password)?;
        let download =
            copy_count_best_effort_limited(&mut remote_read, &mut encrypted_writer, None);
        let _ = encrypted_writer.shutdown();
        upload =
            upload.saturating_add(upload_thread.join().map_err(|_| {
                io::Error::new(io::ErrorKind::Other, "upload relay thread panicked")
            })?);

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
        Ok(())
    }

    fn record_udp_traffic(
        &self,
        user_uuid: &str,
        upload: u64,
        download: u64,
        client_ip: Option<IpAddr>,
    ) {
        if upload > 0 || download > 0 {
            self.traffic
                .lock()
                .expect("traffic registry lock poisoned")
                .add_with_ip(
                    self.config.node_tag.clone(),
                    user_uuid.to_string(),
                    upload,
                    download,
                    client_ip,
                );
        }
    }

    fn acquire_user_session(
        &self,
        user: &CoreUser,
        client_ip: Option<IpAddr>,
    ) -> io::Result<Option<UserSessionGuard>> {
        match self.sessions.try_acquire_for_ip(Some(user), client_ip) {
            Ok(guard) => Ok(guard),
            Err(error) => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                error.to_string(),
            )),
        }
    }
}

fn prune_udp_sessions(
    client_sessions: &mut HashMap<SocketAddr, UdpClientSession>,
    remotes: &mut HashMap<SocketAddr, UdpClientContext>,
) {
    let now = Instant::now();
    let expired = client_sessions
        .iter()
        .filter_map(|(client_addr, session)| {
            (now.duration_since(session.last_seen) > UDP_SESSION_TTL).then_some(*client_addr)
        })
        .collect::<Vec<_>>();
    for client_addr in expired {
        client_sessions.remove(&client_addr);
        remotes.retain(|_, context| context.client_addr != client_addr);
    }
}

fn active_user_list(users: &[CoreUser]) -> Vec<CoreUser> {
    users
        .iter()
        .filter(|user| !user.is_empty())
        .cloned()
        .collect()
}

impl ShadowsocksMethod {
    fn parse(method: &str) -> io::Result<Self> {
        match normalize_method(method).as_str() {
            "aes-128-gcm" => Ok(Self::Aes128Gcm),
            "aes-256-gcm" => Ok(Self::Aes256Gcm),
            "chacha20-ietf-poly1305" => Ok(Self::ChaCha20IetfPoly1305),
            value => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("shadowsocks cipher {value} is not supported"),
            )),
        }
    }

    fn key_len(&self) -> usize {
        match self {
            Self::Aes128Gcm => 16,
            Self::Aes256Gcm | Self::ChaCha20IetfPoly1305 => 32,
        }
    }

    fn salt_len(&self) -> usize {
        self.key_len()
    }
}

impl ShadowsocksCipher {
    fn new(method: ShadowsocksMethod, password: &str, salt: &[u8]) -> io::Result<Self> {
        let master_key = evp_bytes_to_key(password.as_bytes(), method.key_len());
        let mut subkey = vec![0u8; method.key_len()];
        Hkdf::<Sha1>::new(Some(salt), &master_key)
            .expand(HKDF_INFO, &mut subkey)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "derive shadowsocks key"))?;

        let aead = match method {
            ShadowsocksMethod::Aes128Gcm => ShadowsocksAead::Aes128(
                Aes128Gcm::new_from_slice(&subkey)
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid key"))?,
            ),
            ShadowsocksMethod::Aes256Gcm => ShadowsocksAead::Aes256(
                Aes256Gcm::new_from_slice(&subkey)
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid key"))?,
            ),
            ShadowsocksMethod::ChaCha20IetfPoly1305 => ShadowsocksAead::ChaCha20(
                ChaCha20Poly1305::new_from_slice(&subkey)
                    .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid key"))?,
            ),
        };

        Ok(Self { aead, nonce: 0 })
    }

    fn encrypt(&mut self, bytes: &mut Vec<u8>) -> io::Result<()> {
        let nonce = nonce_bytes(self.nonce);
        match &self.aead {
            ShadowsocksAead::Aes128(cipher) => cipher
                .encrypt_in_place(AesNonce::from_slice(&nonce), b"", bytes)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "encrypt chunk"))?,
            ShadowsocksAead::Aes256(cipher) => cipher
                .encrypt_in_place(AesNonce::from_slice(&nonce), b"", bytes)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "encrypt chunk"))?,
            ShadowsocksAead::ChaCha20(cipher) => cipher
                .encrypt_in_place(ChaChaNonce::from_slice(&nonce), b"", bytes)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "encrypt chunk"))?,
        }
        self.nonce = self.nonce.wrapping_add(1);
        Ok(())
    }

    fn decrypt(&mut self, bytes: &mut Vec<u8>) -> io::Result<()> {
        let nonce = nonce_bytes(self.nonce);
        match &self.aead {
            ShadowsocksAead::Aes128(cipher) => cipher
                .decrypt_in_place(AesNonce::from_slice(&nonce), b"", bytes)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "decrypt chunk"))?,
            ShadowsocksAead::Aes256(cipher) => cipher
                .decrypt_in_place(AesNonce::from_slice(&nonce), b"", bytes)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "decrypt chunk"))?,
            ShadowsocksAead::ChaCha20(cipher) => cipher
                .decrypt_in_place(ChaChaNonce::from_slice(&nonce), b"", bytes)
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "decrypt chunk"))?,
        }
        self.nonce = self.nonce.wrapping_add(1);
        Ok(())
    }
}

impl<R: Read> ShadowsocksReader<R> {
    #[cfg(test)]
    fn new(mut reader: R, method: ShadowsocksMethod, password: &str) -> io::Result<Self> {
        let mut salt = vec![0u8; method.salt_len()];
        reader.read_exact(&mut salt)?;
        let cipher = ShadowsocksCipher::new(method, password, &salt)?;
        Ok(Self::with_cipher(reader, cipher))
    }

    fn with_cipher(reader: R, cipher: ShadowsocksCipher) -> Self {
        Self {
            reader,
            cipher,
            buffer: Vec::new(),
        }
    }

    fn read_chunk(&mut self) -> io::Result<Vec<u8>> {
        let mut encrypted_len = vec![0u8; 2 + TAG_LEN];
        self.reader.read_exact(&mut encrypted_len)?;
        self.cipher.decrypt(&mut encrypted_len)?;
        if encrypted_len.len() != 2 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid shadowsocks chunk length",
            ));
        }
        let len = u16::from_be_bytes([encrypted_len[0], encrypted_len[1]]) as usize;
        if len == 0 || len > MAX_CHUNK_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid shadowsocks chunk size",
            ));
        }
        let mut payload = vec![0u8; len + TAG_LEN];
        self.reader.read_exact(&mut payload)?;
        self.cipher.decrypt(&mut payload)?;
        Ok(payload)
    }
}

impl<R: Read> Read for ShadowsocksReader<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        if self.buffer.is_empty() {
            self.buffer = self.read_chunk()?;
        }
        let len = output.len().min(self.buffer.len());
        output[..len].copy_from_slice(&self.buffer[..len]);
        self.buffer.drain(..len);
        Ok(len)
    }
}

impl<W: Write> ShadowsocksWriter<W> {
    fn new_response(mut writer: W, method: ShadowsocksMethod, password: &str) -> io::Result<Self> {
        let mut salt = vec![0u8; method.salt_len()];
        fill_random(&mut salt)?;
        writer.write_all(&salt)?;
        let cipher = ShadowsocksCipher::new(method, password, &salt)?;
        Ok(Self { writer, cipher })
    }

    fn write_chunk(&mut self, payload: &[u8]) -> io::Result<()> {
        let mut encrypted_len = (payload.len() as u16).to_be_bytes().to_vec();
        self.cipher.encrypt(&mut encrypted_len)?;
        self.writer.write_all(&encrypted_len)?;

        let mut encrypted_payload = payload.to_vec();
        self.cipher.encrypt(&mut encrypted_payload)?;
        self.writer.write_all(&encrypted_payload)
    }

    fn shutdown(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

impl<W: Write> Write for ShadowsocksWriter<W> {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        if input.is_empty() {
            return Ok(0);
        }
        let len = input.len().min(MAX_CHUNK_LEN);
        self.write_chunk(&input[..len])?;
        Ok(len)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

pub fn is_supported_shadowsocks_cipher(method: &str) -> bool {
    ShadowsocksMethod::parse(method).is_ok()
}

fn parse_request_payload(payload: Vec<u8>) -> io::Result<(SocksTarget, Vec<u8>)> {
    let mut cursor = std::io::Cursor::new(payload);
    let host = match read_u8(&mut cursor)? {
        ATYP_IPV4 => {
            let mut bytes = [0u8; 4];
            cursor.read_exact(&mut bytes)?;
            Ipv4Addr::from(bytes).to_string()
        }
        ATYP_DOMAIN => {
            let len = read_u8(&mut cursor)?;
            read_string(&mut cursor, usize::from(len))?
        }
        ATYP_IPV6 => {
            let mut bytes = [0u8; 16];
            cursor.read_exact(&mut bytes)?;
            Ipv6Addr::from(bytes).to_string()
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported shadowsocks address type",
            ));
        }
    };

    let mut port = [0u8; 2];
    cursor.read_exact(&mut port)?;
    let position = cursor.position() as usize;
    let payload = cursor.into_inner();
    Ok((
        SocksTarget {
            host,
            port: u16::from_be_bytes(port),
        },
        payload[position..].to_vec(),
    ))
}

fn connect_target(target: &SocksTarget, timeout: Duration) -> io::Result<TcpStream> {
    crate::dns::connect_tcp(&target.host, target.port, timeout)
}

fn resolve_udp_target(target: &SocksTarget) -> io::Result<SocketAddr> {
    crate::dns::resolve_socket_addr(&target.host, target.port, Duration::from_secs(5))
}

fn encode_udp_packet(
    method: ShadowsocksMethod,
    context: &UdpClientContext,
    source: SocketAddr,
    payload: &[u8],
) -> io::Result<Vec<u8>> {
    let mut salt = vec![0u8; method.salt_len()];
    fill_random(&mut salt)?;
    let mut cipher = ShadowsocksCipher::new(method, context.user.credential(), &salt)?;
    let mut body = encode_target(source);
    body.extend_from_slice(payload);
    cipher.encrypt(&mut body)?;

    let mut output = Vec::with_capacity(salt.len() + body.len());
    output.extend_from_slice(&salt);
    output.extend_from_slice(&body);
    Ok(output)
}

fn encode_target(source: SocketAddr) -> Vec<u8> {
    let mut output = Vec::new();
    match source.ip() {
        std::net::IpAddr::V4(ip) => {
            output.push(ATYP_IPV4);
            output.extend_from_slice(&ip.octets());
        }
        std::net::IpAddr::V6(ip) => {
            output.push(ATYP_IPV6);
            output.extend_from_slice(&ip.octets());
        }
    }
    output.extend_from_slice(&source.port().to_be_bytes());
    output
}

fn evp_bytes_to_key(password: &[u8], key_len: usize) -> Vec<u8> {
    let mut key = Vec::with_capacity(key_len);
    let mut previous = Vec::new();
    while key.len() < key_len {
        let mut hasher = Md5::new();
        hasher.update(&previous);
        hasher.update(password);
        previous = hasher.finalize().to_vec();
        key.extend_from_slice(&previous);
    }
    key.truncate(key_len);
    key
}

fn normalize_method(method: &str) -> String {
    method.trim().to_ascii_lowercase().replace('_', "-")
}

fn nonce_bytes(nonce: u64) -> [u8; NONCE_LEN] {
    let mut bytes = [0u8; NONCE_LEN];
    bytes[..8].copy_from_slice(&nonce.to_le_bytes());
    bytes
}

fn fill_random(bytes: &mut [u8]) -> io::Result<()> {
    getrandom::getrandom(bytes).map_err(|error| {
        io::Error::new(
            io::ErrorKind::Other,
            format!("generate shadowsocks salt: {error}"),
        )
    })
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

#[cfg(test)]
mod tests {
    use std::collections::HashMap;
    use std::io::{self, Read, Write};
    use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    use crate::shadowsocks::{
        is_supported_shadowsocks_cipher, parse_request_payload, ShadowsocksCipher,
        ShadowsocksMethod, ShadowsocksReader, ShadowsocksServer, ShadowsocksServerConfig,
        ShadowsocksWriter, UdpClientContext, UdpClientSession, ATYP_IPV4,
    };
    use crate::user::CoreUser;

    fn user() -> CoreUser {
        CoreUser {
            id: 1,
            uuid: "ss-password".to_string(),
            password: None,
            email: None,
            speed_limit: 0,
            device_limit: 0,
        }
    }

    fn user_b() -> CoreUser {
        CoreUser {
            id: 2,
            uuid: "ss-user-b".to_string(),
            password: Some("secret-b".to_string()),
            email: None,
            speed_limit: 0,
            device_limit: 0,
        }
    }

    fn server() -> ShadowsocksServer {
        ShadowsocksServer::new(ShadowsocksServerConfig {
            node_tag: "panel|shadowsocks|1".to_string(),
            listen: "127.0.0.1:0".parse().expect("listen addr"),
            method: "aes-128-gcm".to_string(),
            users: vec![user()],
            routes: Vec::new(),
            connect_timeout: Duration::from_secs(3),
        })
    }

    fn limited_server() -> ShadowsocksServer {
        let mut limited_user = user();
        limited_user.device_limit = 1;
        ShadowsocksServer::new(ShadowsocksServerConfig {
            node_tag: "panel|shadowsocks|1".to_string(),
            listen: "127.0.0.1:0".parse().expect("listen addr"),
            method: "aes-128-gcm".to_string(),
            users: vec![limited_user],
            routes: Vec::new(),
            connect_timeout: Duration::from_secs(3),
        })
    }

    fn shadowsocks_request(target: std::net::SocketAddr, payload: &[u8]) -> Vec<u8> {
        let mut request = Vec::new();
        request.push(ATYP_IPV4);
        request.extend_from_slice(
            &target
                .ip()
                .to_string()
                .parse::<std::net::Ipv4Addr>()
                .expect("ipv4")
                .octets(),
        );
        request.extend_from_slice(&target.port().to_be_bytes());
        request.extend_from_slice(payload);
        request
    }

    fn shadowsocks_udp_packet(
        method: ShadowsocksMethod,
        password: &str,
        target: SocketAddr,
        payload: &[u8],
    ) -> Vec<u8> {
        let mut salt = vec![0x11; method.salt_len()];
        let mut cipher = ShadowsocksCipher::new(method, password, &salt).expect("udp cipher");
        let mut body = shadowsocks_request(target, payload);
        cipher.encrypt(&mut body).expect("udp encrypt");
        salt.extend_from_slice(&body);
        salt
    }

    fn read_shadowsocks_udp_packet(
        method: ShadowsocksMethod,
        password: &str,
        packet: &[u8],
    ) -> (SocketAddr, Vec<u8>) {
        let (salt, encrypted) = packet.split_at(method.salt_len());
        let mut body = encrypted.to_vec();
        let mut cipher = ShadowsocksCipher::new(method, password, salt).expect("udp cipher");
        cipher.decrypt(&mut body).expect("udp decrypt");
        let (target, payload) = parse_request_payload(body).expect("udp payload");
        let addr = format!("{}:{}", target.host, target.port)
            .parse()
            .expect("udp source addr");
        (addr, payload)
    }

    #[test]
    fn parses_supported_methods() {
        assert!(is_supported_shadowsocks_cipher("aes-128-gcm"));
        assert!(is_supported_shadowsocks_cipher("aes_256_gcm"));
        assert!(is_supported_shadowsocks_cipher("chacha20-ietf-poly1305"));
        assert!(!is_supported_shadowsocks_cipher("rc4-md5"));
    }

    #[test]
    fn parses_request_payload_with_initial_data() {
        let target = "127.0.0.1:443"
            .parse::<std::net::SocketAddr>()
            .expect("target");

        let (parsed, payload) =
            parse_request_payload(shadowsocks_request(target, b"hello")).expect("payload");

        assert_eq!(parsed.host, "127.0.0.1");
        assert_eq!(parsed.port, 443);
        assert_eq!(payload, b"hello");
    }

    #[test]
    fn replaces_users_without_rebuilding_shadowsocks_server() {
        let server = server();
        let method = ShadowsocksMethod::parse("aes-128-gcm").expect("method");
        let target = "127.0.0.1:443"
            .parse::<std::net::SocketAddr>()
            .expect("target");

        server.replace_users(vec![user_b()]);

        let old_packet = shadowsocks_udp_packet(method, "ss-password", target, b"old");
        let error = match server.read_udp_request(&old_packet, method) {
            Ok(_) => panic!("old user should fail after replacement"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);

        let new_packet = shadowsocks_udp_packet(method, "secret-b", target, b"new");
        let request = server
            .read_udp_request(&new_packet, method)
            .expect("new user should authenticate");
        assert_eq!(request.user.uuid, "ss-user-b");
        assert_eq!(request.payload, b"new");
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
        let listener = server.bind().expect("ss bind");
        let ss_addr = listener.local_addr().expect("ss addr");
        let server_clone = server.clone();
        let server_thread = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("ss accept");
            server_clone.handle_tcp_client(stream)
        });

        let mut client = TcpStream::connect(ss_addr).expect("client connect");
        let method = ShadowsocksMethod::parse("aes-128-gcm").expect("method");
        let mut writer = ShadowsocksWriter::new_response(
            client.try_clone().expect("client clone"),
            method,
            "ss-password",
        )
        .expect("client writer");
        writer
            .write_all(&shadowsocks_request(echo_addr, b"ping"))
            .expect("client request");
        writer.flush().expect("client flush");

        let mut reader = ShadowsocksReader::new(&mut client, method, "ss-password")
            .expect("client response reader");
        let mut echoed = [0u8; 4];
        reader.read_exact(&mut echoed).expect("client read payload");
        assert_eq!(&echoed, b"ping");
        drop(reader);
        drop(writer);
        drop(client);

        server_thread
            .join()
            .expect("server thread")
            .expect("serve once");
        echo_thread.join().expect("echo thread");

        let records = server.drain_traffic(1);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].node_tag, "panel|shadowsocks|1");
        assert_eq!(records[0].user_uuid, "ss-password");
        assert_eq!(records[0].upload, 4);
        assert_eq!(records[0].download, 4);
    }

    #[test]
    fn proxies_udp_and_records_user_traffic() {
        let echo = UdpSocket::bind("127.0.0.1:0").expect("echo bind");
        let echo_addr = echo.local_addr().expect("echo addr");
        let echo_thread = thread::spawn(move || {
            let mut buffer = [0u8; 1024];
            let (read, source) = echo.recv_from(&mut buffer).expect("echo read");
            assert_eq!(&buffer[..read], b"ping");
            echo.send_to(b"pong", source).expect("echo write");
        });

        let server = server();
        let udp = server
            .bind_udp("127.0.0.1:0".parse().expect("udp listen"))
            .expect("ss udp bind");
        udp.set_read_timeout(Some(Duration::from_millis(100)))
            .expect("udp timeout");
        let ss_addr = udp.local_addr().expect("ss udp addr");
        let stop = Arc::new(AtomicBool::new(false));
        let server_clone = server.clone();
        let stop_for_thread = stop.clone();
        let server_thread = thread::spawn(move || server_clone.serve_udp(udp, stop_for_thread));

        let client = UdpSocket::bind("127.0.0.1:0").expect("client bind");
        client
            .set_read_timeout(Some(Duration::from_secs(3)))
            .expect("client timeout");
        let method = ShadowsocksMethod::parse("aes-128-gcm").expect("method");
        let request = shadowsocks_udp_packet(method, "ss-password", echo_addr, b"ping");
        client.send_to(&request, ss_addr).expect("client send");

        let mut response = [0u8; 1024];
        let (read, _) = client.recv_from(&mut response).expect("client recv");
        let (source, payload) =
            read_shadowsocks_udp_packet(method, "ss-password", &response[..read]);
        assert_eq!(source, echo_addr);
        assert_eq!(payload, b"pong");

        stop.store(true, Ordering::SeqCst);
        server_thread
            .join()
            .expect("server thread")
            .expect("serve udp");
        echo_thread.join().expect("echo thread");

        let records = server.drain_traffic(1);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].node_tag, "panel|shadowsocks|1");
        assert_eq!(records[0].user_uuid, "ss-password");
        assert_eq!(records[0].upload, 4);
        assert_eq!(records[0].download, 4);
    }

    #[test]
    fn udp_device_limit_counts_same_ip_once_across_client_ports() {
        let server = limited_server();
        let relay = UdpSocket::bind("127.0.0.1:0").expect("relay bind");
        let echo = UdpSocket::bind("127.0.0.1:0").expect("echo bind");
        echo.set_read_timeout(Some(Duration::from_millis(100)))
            .expect("echo timeout");
        let echo_addr = echo.local_addr().expect("echo addr");
        let method = ShadowsocksMethod::parse("aes-128-gcm").expect("method");
        let mut remotes = HashMap::<SocketAddr, UdpClientContext>::new();
        let mut client_sessions = HashMap::<SocketAddr, UdpClientSession>::new();

        let packet = shadowsocks_udp_packet(method, "ss-password", echo_addr, b"first-client");
        let request = server
            .read_udp_request(&packet, method)
            .expect("first udp request");
        server
            .handle_udp_request(
                &relay,
                method,
                "127.0.0.1:30001".parse().expect("client one"),
                request,
                &mut remotes,
                &mut client_sessions,
            )
            .expect("first udp handle");

        let mut buffer = [0u8; 64];
        let (read, _) = echo.recv_from(&mut buffer).expect("first echo read");
        assert_eq!(&buffer[..read], b"first-client");
        assert_eq!(server.sessions.active_count("ss-password"), 1);

        let packet = shadowsocks_udp_packet(method, "ss-password", echo_addr, b"second-client");
        let request = server
            .read_udp_request(&packet, method)
            .expect("second udp request");
        server
            .handle_udp_request(
                &relay,
                method,
                "127.0.0.1:30002".parse().expect("client two"),
                request,
                &mut remotes,
                &mut client_sessions,
            )
            .expect("same-ip udp handle");

        let (read, _) = echo.recv_from(&mut buffer).expect("second echo read");
        assert_eq!(&buffer[..read], b"second-client");
        assert_eq!(server.sessions.active_count("ss-password"), 1);

        drop(client_sessions);
        assert_eq!(server.sessions.active_count("ss-password"), 0);
    }
}
