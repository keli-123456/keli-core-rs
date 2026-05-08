use std::collections::HashMap;
use std::convert::TryInto;
use std::io::{self, Cursor, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use aes::cipher::{BlockDecrypt, KeyInit as BlockKeyInit};
use aes::Aes128;
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes128Gcm, Nonce as AesGcmNonce};
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaChaNonce};
use hmac::{Hmac, Mac};
use md5::{Digest as Md5Digest, Md5};
use sha2::Sha256;
use sha3::digest::{ExtendableOutput, Update};
use sha3::Shake128;

use crate::limits::{
    BandwidthLimiter, UserBandwidthLimiters, UserSessionGuard, UserSessionTracker,
};
use crate::socks5::SocksTarget;
use crate::stream::copy_count_best_effort_limited;
use crate::tls::TlsConnection;
use crate::traffic::TrafficRegistry;
use crate::user::CoreUser;
use crate::websocket::{accept_websocket, accept_websocket_tls};
use crate::{RouteDecision, RouteMatcher};

const VERSION: u8 = 0x01;
const COMMAND_TCP: u8 = 0x01;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x02;
const ATYP_IPV6: u8 = 0x03;
const OPTION_CHUNK_STREAM: u8 = 0x01;
const OPTION_CHUNK_MASKING: u8 = 0x04;
const OPTION_GLOBAL_PADDING: u8 = 0x08;
const OPTION_AUTHENTICATED_LENGTH: u8 = 0x10;
const SECURITY_AES128_GCM: u8 = 0x03;
const SECURITY_CHACHA20_POLY1305: u8 = 0x04;
const SECURITY_NONE: u8 = 0x05;
const KDF_ROOT: &[u8] = b"VMess AEAD KDF";
const AUTH_ID_KEY: &[u8] = b"AES Auth ID Encryption";
const HEADER_LENGTH_KEY: &[u8] = b"VMess Header AEAD Key_Length";
const HEADER_LENGTH_NONCE: &[u8] = b"VMess Header AEAD Nonce_Length";
const HEADER_PAYLOAD_KEY: &[u8] = b"VMess Header AEAD Key";
const HEADER_PAYLOAD_NONCE: &[u8] = b"VMess Header AEAD Nonce";
const RESPONSE_HEADER_LENGTH_KEY: &[u8] = b"AEAD Resp Header Len Key";
const RESPONSE_HEADER_LENGTH_IV: &[u8] = b"AEAD Resp Header Len IV";
const RESPONSE_HEADER_PAYLOAD_KEY: &[u8] = b"AEAD Resp Header Key";
const RESPONSE_HEADER_PAYLOAD_IV: &[u8] = b"AEAD Resp Header IV";
const AUTHENTICATED_LENGTH_KEY: &[u8] = b"auth_len";
const CMD_KEY_SALT: &[u8] = b"c48619fe-8f02-49e0-b9e9-edf763e17e21";
const MAX_HEADER_LEN: usize = 4096;
const MAX_CHUNK_SIZE: usize = 16 * 1024;
const AUTH_ID_WINDOW_SECONDS: i64 = 120;
const AUTH_ID_REPLAY_TTL: Duration = Duration::from_secs(180);

#[derive(Clone, Debug)]
pub struct VmessServerConfig {
    pub node_tag: String,
    pub listen: SocketAddr,
    pub users: Vec<CoreUser>,
    pub routes: Vec<crate::RouteRule>,
    pub connect_timeout: Duration,
}

#[derive(Clone, Debug)]
pub struct VmessServer {
    config: VmessServerConfig,
    users: Arc<HashMap<String, CoreUser>>,
    auth_users: Arc<Vec<VmessAuthUser>>,
    replay: Arc<Mutex<HashMap<[u8; 16], Instant>>>,
    router: RouteMatcher,
    traffic: Arc<Mutex<TrafficRegistry>>,
    sessions: UserSessionTracker,
    bandwidth: UserBandwidthLimiters,
}

#[derive(Clone, Debug)]
struct VmessAuthUser {
    user_key: String,
    cmd_key: [u8; 16],
    auth_id_key: [u8; 16],
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum VmessSecurity {
    Aes128Gcm,
    ChaCha20Poly1305,
    None,
}

#[derive(Clone, Debug)]
struct VmessRequest {
    user_key: String,
    user_uuid: String,
    target: SocksTarget,
    request_body_key: [u8; 16],
    request_body_iv: [u8; 16],
    response_body_key: [u8; 16],
    response_body_iv: [u8; 16],
    response_header: u8,
    options: u8,
    security: VmessSecurity,
}

impl VmessServer {
    pub fn new(config: VmessServerConfig) -> Self {
        Self::with_traffic(config, Arc::new(Mutex::new(TrafficRegistry::default())))
    }

    pub fn with_traffic(config: VmessServerConfig, traffic: Arc<Mutex<TrafficRegistry>>) -> Self {
        Self::with_shared_limits(
            config,
            traffic,
            UserSessionTracker::default(),
            UserBandwidthLimiters::default(),
        )
    }

    pub fn with_shared_limits(
        config: VmessServerConfig,
        traffic: Arc<Mutex<TrafficRegistry>>,
        sessions: UserSessionTracker,
        bandwidth: UserBandwidthLimiters,
    ) -> Self {
        let mut users = HashMap::new();
        let mut auth_users = Vec::new();
        for user in config.users.iter().filter(|user| !user.is_empty()) {
            let Ok(uuid_bytes) = parse_uuid_bytes(&user.uuid) else {
                continue;
            };
            let user_key = format_uuid_compact(&uuid_bytes);
            let cmd_key = vmess_cmd_key(&uuid_bytes);
            let auth_id_key = kdf16(&cmd_key, &[AUTH_ID_KEY]);
            users.insert(user_key.clone(), user.clone());
            auth_users.push(VmessAuthUser {
                user_key,
                cmd_key,
                auth_id_key,
            });
        }

        Self {
            router: RouteMatcher::new(config.routes.clone()),
            config,
            users: Arc::new(users),
            auth_users: Arc::new(auth_users),
            replay: Arc::new(Mutex::new(HashMap::new())),
            traffic,
            sessions,
            bandwidth,
        }
    }

    pub fn bind(&self) -> io::Result<TcpListener> {
        TcpListener::bind(self.config.listen)
    }

    pub fn handle_tcp_client(&self, mut client: TcpStream) -> io::Result<()> {
        let request = self.read_request(&mut client)?;
        let user = self.request_user(&request);
        let _session = self.acquire_user_session(user)?;
        let bandwidth = self.bandwidth.limiter_for(user);
        let remote = self.connect_for_request(&request)?;
        write_response_header(&mut client, &request)?;
        self.relay_split(client, remote, request, bandwidth)
    }

    pub fn handle_websocket_client(&self, client: TcpStream, path: Option<&str>) -> io::Result<()> {
        let (mut reader, mut writer) = accept_websocket(client, path)?;
        let request = self.read_request(&mut reader)?;
        let user = self.request_user(&request);
        let _session = self.acquire_user_session(user)?;
        let bandwidth = self.bandwidth.limiter_for(user);
        let remote = self.connect_for_request(&request)?;
        write_response_header(&mut writer, &request)?;
        self.relay_split_io(reader, writer, remote, request, bandwidth)
    }

    pub fn handle_tls_client(&self, mut client: TlsConnection) -> io::Result<()> {
        let request = self.read_request(&mut client)?;
        let user = self.request_user(&request);
        let _session = self.acquire_user_session(user)?;
        let bandwidth = self.bandwidth.limiter_for(user);
        let remote = self.connect_for_request(&request)?;
        write_response_header(&mut client, &request)?;
        client.set_nonblocking(true)?;
        self.relay_single_io(client, remote, request, bandwidth)
    }

    pub fn handle_tls_websocket_client(
        &self,
        client: TlsConnection,
        path: Option<&str>,
    ) -> io::Result<()> {
        let mut websocket = accept_websocket_tls(client, path)?;
        let request = self.read_request(&mut websocket)?;
        let user = self.request_user(&request);
        let _session = self.acquire_user_session(user)?;
        let bandwidth = self.bandwidth.limiter_for(user);
        let remote = self.connect_for_request(&request)?;
        write_response_header(&mut websocket, &request)?;
        websocket.set_nonblocking(true)?;
        self.relay_single_io(websocket, remote, request, bandwidth)
    }

    pub fn drain_traffic(&self, minimum_bytes: u64) -> Vec<crate::traffic::TrafficDelta> {
        self.traffic
            .lock()
            .expect("traffic registry lock poisoned")
            .drain_minimum(minimum_bytes)
    }

    fn read_request<R: Read>(&self, stream: &mut R) -> io::Result<VmessRequest> {
        let mut auth_id = [0u8; 16];
        stream.read_exact(&mut auth_id)?;
        let user = self.match_auth_id(auth_id)?;
        let header = open_aead_header(stream, &user.cmd_key, &auth_id)?;
        let parsed = parse_request_header(&header)?;
        if parsed.security != VmessSecurity::None && parsed.options & OPTION_CHUNK_STREAM == 0 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "vmess aead payload requires chunk stream option",
            ));
        }
        if parsed.options & OPTION_GLOBAL_PADDING != 0 && parsed.options & OPTION_CHUNK_MASKING == 0
        {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "vmess global padding requires chunk masking",
            ));
        }
        let Some(core_user) = self.users.get(&user.user_key) else {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "unknown vmess user",
            ));
        };
        let response_body_key = first_16_sha256(&parsed.request_body_key);
        let response_body_iv = first_16_sha256(&parsed.request_body_iv);

        Ok(VmessRequest {
            user_key: user.user_key.clone(),
            user_uuid: core_user.uuid.clone(),
            target: parsed.target,
            request_body_key: parsed.request_body_key,
            request_body_iv: parsed.request_body_iv,
            response_body_key,
            response_body_iv,
            response_header: parsed.response_header,
            options: parsed.options,
            security: parsed.security,
        })
    }

    fn match_auth_id(&self, auth_id: [u8; 16]) -> io::Result<&VmessAuthUser> {
        for user in self.auth_users.iter() {
            if !decode_auth_id(&user.auth_id_key, &auth_id)? {
                continue;
            }
            self.record_auth_id(auth_id)?;
            return Ok(user);
        }
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "invalid vmess auth id",
        ))
    }

    fn record_auth_id(&self, auth_id: [u8; 16]) -> io::Result<()> {
        let now = Instant::now();
        let mut replay = self.replay.lock().expect("vmess replay lock poisoned");
        replay.retain(|_, seen_at| now.duration_since(*seen_at) <= AUTH_ID_REPLAY_TTL);
        if replay.insert(auth_id, now).is_some() {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "replayed vmess auth id",
            ));
        }
        Ok(())
    }

    fn connect_for_request(&self, request: &VmessRequest) -> io::Result<TcpStream> {
        match self.router.decide(&request.target.host) {
            RouteDecision::Direct => connect_target(&request.target, self.config.connect_timeout),
            RouteDecision::Block => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "target blocked by route",
            )),
            RouteDecision::UnsupportedOutbound(tag) => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("outbound route {tag} is not implemented"),
            )),
        }
    }

    fn relay_split(
        &self,
        client: TcpStream,
        remote: TcpStream,
        request: VmessRequest,
        bandwidth: Option<Arc<BandwidthLimiter>>,
    ) -> io::Result<()> {
        let reader = client.try_clone()?;
        self.relay_split_io(reader, client, remote, request, bandwidth)
    }

    fn relay_split_io<R, W>(
        &self,
        client_reader: R,
        client_writer: W,
        remote: TcpStream,
        request: VmessRequest,
        bandwidth: Option<Arc<BandwidthLimiter>>,
    ) -> io::Result<()>
    where
        R: Read + Send + 'static,
        W: Write,
    {
        let mut remote_write = remote.try_clone()?;
        let mut remote_read = remote;
        let mut request_body = VmessBodyReader::new(
            client_reader,
            request.request_body_key,
            request.request_body_iv,
            request.options,
            request.security,
        )?;
        let mut response_body = VmessBodyWriter::new_with_length_seed(
            client_writer,
            request.response_body_key,
            request.response_body_iv,
            request.request_body_key,
            request.request_body_iv,
            request.options,
            request.security,
        )?;
        let upload_limiter = bandwidth.clone();
        let upload_thread = thread::spawn(move || {
            let copied = copy_count_best_effort_limited(
                &mut request_body,
                &mut remote_write,
                upload_limiter.as_deref(),
            );
            let _ = remote_write.shutdown(Shutdown::Write);
            copied
        });
        let download = copy_count_best_effort_limited(
            &mut remote_read,
            &mut response_body,
            bandwidth.as_deref(),
        );
        let _ = response_body.finish();
        let upload = upload_thread
            .join()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "upload relay thread panicked"))?;
        self.traffic
            .lock()
            .expect("traffic registry lock poisoned")
            .add(
                self.config.node_tag.clone(),
                request.user_uuid,
                upload,
                download,
            );
        Ok(())
    }

    fn relay_single_io<S>(
        &self,
        mut client: S,
        mut remote: TcpStream,
        request: VmessRequest,
        bandwidth: Option<Arc<BandwidthLimiter>>,
    ) -> io::Result<()>
    where
        S: Read + Write,
    {
        remote.set_nonblocking(true)?;
        let mut request_body = VmessBodyDecoder::new(
            request.request_body_key,
            request.request_body_iv,
            request.options,
            request.security,
        );
        let mut response_body = VmessBodyEncoder::new_with_length_seed(
            request.response_body_key,
            request.response_body_iv,
            request.request_body_key,
            request.request_body_iv,
            request.options,
            request.security,
        );
        let mut upload = 0u64;
        let mut download = 0u64;
        let mut upload_done = false;
        let mut download_done = false;
        let mut client_buffer = [0u8; 16 * 1024];
        let mut remote_buffer = [0u8; 16 * 1024];

        while !upload_done || !download_done {
            let mut progressed = false;

            if !upload_done {
                match request_body.read_plain(&mut client, &mut client_buffer) {
                    Ok(0) => {
                        upload_done = true;
                        let _ = remote.shutdown(Shutdown::Write);
                        progressed = true;
                    }
                    Ok(read) => {
                        if let Some(limiter) = bandwidth.as_deref() {
                            limiter.wait_for(read);
                        }
                        write_all_wait(&mut remote, &client_buffer[..read])?;
                        upload = upload.saturating_add(read as u64);
                        progressed = true;
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(_) => {
                        upload_done = true;
                        let _ = remote.shutdown(Shutdown::Write);
                        progressed = true;
                    }
                }
            }

            if !download_done {
                match remote.read(&mut remote_buffer) {
                    Ok(0) => {
                        download_done = true;
                        let _ = response_body.finish(&mut client);
                        progressed = true;
                    }
                    Ok(read) => {
                        response_body.write_plain(&mut client, &remote_buffer[..read])?;
                        download = download.saturating_add(read as u64);
                        progressed = true;
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(_) => {
                        download_done = true;
                        let _ = response_body.finish(&mut client);
                        progressed = true;
                    }
                }
            }

            if !progressed {
                thread::sleep(Duration::from_millis(1));
            }
        }

        let _ = response_body.finish(&mut client);
        let _ = remote.shutdown(Shutdown::Both);
        self.traffic
            .lock()
            .expect("traffic registry lock poisoned")
            .add(
                self.config.node_tag.clone(),
                request.user_uuid,
                upload,
                download,
            );
        Ok(())
    }

    fn request_user(&self, request: &VmessRequest) -> Option<&CoreUser> {
        self.users.get(&request.user_key)
    }

    fn acquire_user_session(
        &self,
        user: Option<&CoreUser>,
    ) -> io::Result<Option<UserSessionGuard>> {
        match self.sessions.try_acquire(user) {
            Ok(guard) => Ok(guard),
            Err(error) => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                error.to_string(),
            )),
        }
    }
}

#[derive(Debug)]
struct ParsedVmessHeader {
    target: SocksTarget,
    request_body_key: [u8; 16],
    request_body_iv: [u8; 16],
    response_header: u8,
    options: u8,
    security: VmessSecurity,
}

struct VmessBodyReader<R> {
    reader: R,
    decoder: VmessBodyDecoder,
}

struct VmessBodyWriter<W> {
    writer: W,
    encoder: VmessBodyEncoder,
}

struct VmessBodyDecoder {
    security: VmessSecurity,
    key: [u8; 16],
    size: VmessSizeParser,
    nonce: ChunkNonce,
    options: u8,
    buffer: Vec<u8>,
    size_bytes: Vec<u8>,
    size_read: usize,
    chunk: Vec<u8>,
    chunk_read: usize,
    chunk_padding: usize,
    eof: bool,
}

struct VmessBodyEncoder {
    security: VmessSecurity,
    key: [u8; 16],
    size: VmessSizeParser,
    nonce: ChunkNonce,
    options: u8,
    finished: bool,
}

struct VmessSizeParser {
    codec: VmessSizeCodec,
}

enum VmessSizeCodec {
    Plain,
    Masked {
        shake: sha3::Shake128Reader,
    },
    Authenticated {
        auth: VmessLengthAuthenticator,
        padding: Option<sha3::Shake128Reader>,
    },
}

struct VmessLengthAuthenticator {
    security: VmessSecurity,
    key: [u8; 16],
    nonce: ChunkNonce,
}

#[derive(Clone, Copy)]
struct ChunkNonce {
    iv: [u8; 16],
    count: u16,
}

impl<R: Read> VmessBodyReader<R> {
    fn new(
        reader: R,
        key: [u8; 16],
        iv: [u8; 16],
        options: u8,
        security: VmessSecurity,
    ) -> io::Result<Self> {
        Ok(Self {
            reader,
            decoder: VmessBodyDecoder::new(key, iv, options, security),
        })
    }

    #[cfg(test)]
    fn new_with_length_seed(
        reader: R,
        key: [u8; 16],
        iv: [u8; 16],
        length_key_seed: [u8; 16],
        length_iv_seed: [u8; 16],
        options: u8,
        security: VmessSecurity,
    ) -> io::Result<Self> {
        Ok(Self {
            reader,
            decoder: VmessBodyDecoder::new_with_length_seed(
                key,
                iv,
                length_key_seed,
                length_iv_seed,
                options,
                security,
            ),
        })
    }
}

impl VmessBodyDecoder {
    fn new(key: [u8; 16], iv: [u8; 16], options: u8, security: VmessSecurity) -> Self {
        Self::new_with_length_seed(key, iv, key, iv, options, security)
    }

    fn new_with_length_seed(
        key: [u8; 16],
        iv: [u8; 16],
        length_key_seed: [u8; 16],
        length_iv_seed: [u8; 16],
        options: u8,
        security: VmessSecurity,
    ) -> Self {
        let size = VmessSizeParser::new(iv, length_key_seed, length_iv_seed, options, security);
        let size_bytes = vec![0u8; size.size_bytes()];
        Self {
            security,
            key,
            size,
            nonce: ChunkNonce { iv, count: 0 },
            options,
            buffer: Vec::new(),
            size_bytes,
            size_read: 0,
            chunk: Vec::new(),
            chunk_read: 0,
            chunk_padding: 0,
            eof: false,
        }
    }

    fn read_plain<R: Read>(&mut self, reader: &mut R, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        if self.security == VmessSecurity::None && self.options & OPTION_CHUNK_STREAM == 0 {
            return reader.read(output);
        }
        while self.buffer.is_empty() && !self.eof {
            self.read_next_chunk(reader)?;
        }
        if self.buffer.is_empty() {
            return Ok(0);
        }
        let len = output.len().min(self.buffer.len());
        output[..len].copy_from_slice(&self.buffer[..len]);
        self.buffer.drain(..len);
        Ok(len)
    }

    fn read_next_chunk<R: Read>(&mut self, reader: &mut R) -> io::Result<()> {
        if self.eof {
            return Ok(());
        }
        if self.security == VmessSecurity::None && self.options & OPTION_CHUNK_STREAM == 0 {
            return Ok(());
        }

        if self.chunk.is_empty() {
            while self.size_read < self.size_bytes.len() {
                match reader.read(&mut self.size_bytes[self.size_read..]) {
                    Ok(0) if self.size_read == 0 => {
                        self.eof = true;
                        return Ok(());
                    }
                    Ok(0) => {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "truncated vmess chunk size",
                        ));
                    }
                    Ok(read) => self.size_read += read,
                    Err(error) => return Err(error),
                }
            }

            let padding = self.padding_len()?;
            let size = self.size.decode(&self.size_bytes)? as usize;
            self.size_read = 0;
            let overhead = self.security.overhead();
            if size == overhead + padding {
                self.eof = true;
                return Ok(());
            }
            if size < overhead + padding {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "invalid vmess chunk size",
                ));
            }
            self.chunk = vec![0u8; size];
            self.chunk_read = 0;
            self.chunk_padding = padding;
        }

        while self.chunk_read < self.chunk.len() {
            match reader.read(&mut self.chunk[self.chunk_read..]) {
                Ok(0) => {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "truncated vmess chunk",
                    ));
                }
                Ok(read) => self.chunk_read += read,
                Err(error) => return Err(error),
            }
        }

        let payload_len = self.chunk.len() - self.chunk_padding;
        let payload = &self.chunk[..payload_len];
        self.buffer = match self.security {
            VmessSecurity::None => payload.to_vec(),
            VmessSecurity::Aes128Gcm => {
                let nonce = self.nonce.next();
                aes_gcm_open(&self.key, &nonce, payload, &[])?
            }
            VmessSecurity::ChaCha20Poly1305 => {
                let nonce = self.nonce.next();
                chacha20_open(&self.key, &nonce, payload, &[])?
            }
        };
        self.chunk.clear();
        self.chunk_read = 0;
        self.chunk_padding = 0;
        Ok(())
    }

    fn padding_len(&mut self) -> io::Result<usize> {
        if self.options & OPTION_GLOBAL_PADDING == 0 {
            return Ok(0);
        }
        self.size.next_padding_len()
    }
}

impl<R: Read> Read for VmessBodyReader<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        self.decoder.read_plain(&mut self.reader, output)
    }
}

impl<W: Write> VmessBodyWriter<W> {
    #[cfg(test)]
    fn new(
        writer: W,
        key: [u8; 16],
        iv: [u8; 16],
        options: u8,
        security: VmessSecurity,
    ) -> io::Result<Self> {
        Ok(Self {
            writer,
            encoder: VmessBodyEncoder::new(key, iv, options, security),
        })
    }

    fn new_with_length_seed(
        writer: W,
        key: [u8; 16],
        iv: [u8; 16],
        length_key_seed: [u8; 16],
        length_iv_seed: [u8; 16],
        options: u8,
        security: VmessSecurity,
    ) -> io::Result<Self> {
        Ok(Self {
            writer,
            encoder: VmessBodyEncoder::new_with_length_seed(
                key,
                iv,
                length_key_seed,
                length_iv_seed,
                options,
                security,
            ),
        })
    }

    fn finish(&mut self) -> io::Result<()> {
        self.encoder.finish(&mut self.writer)
    }

    #[cfg(test)]
    fn into_inner(self) -> W {
        self.writer
    }
}

impl VmessBodyEncoder {
    #[cfg(test)]
    fn new(key: [u8; 16], iv: [u8; 16], options: u8, security: VmessSecurity) -> Self {
        Self::new_with_length_seed(key, iv, key, iv, options, security)
    }

    fn new_with_length_seed(
        key: [u8; 16],
        iv: [u8; 16],
        length_key_seed: [u8; 16],
        length_iv_seed: [u8; 16],
        options: u8,
        security: VmessSecurity,
    ) -> Self {
        Self {
            security,
            key,
            size: VmessSizeParser::new(iv, length_key_seed, length_iv_seed, options, security),
            nonce: ChunkNonce { iv, count: 0 },
            options,
            finished: false,
        }
    }

    fn write_plain<W: Write>(&mut self, writer: &mut W, mut input: &[u8]) -> io::Result<usize> {
        if input.is_empty() {
            return Ok(0);
        }
        if self.security == VmessSecurity::None && self.options & OPTION_CHUNK_STREAM == 0 {
            return writer.write(input);
        }
        let original = input.len();
        while !input.is_empty() {
            let len = input.len().min(MAX_CHUNK_SIZE);
            self.write_chunk(writer, &input[..len])?;
            input = &input[len..];
        }
        Ok(original)
    }

    fn finish<W: Write>(&mut self, writer: &mut W) -> io::Result<()> {
        if self.finished {
            return Ok(());
        }
        self.finished = true;
        if self.security == VmessSecurity::None && self.options & OPTION_CHUNK_STREAM == 0 {
            return writer.flush();
        }
        self.write_chunk(writer, &[])?;
        writer.flush()
    }

    fn write_chunk<W: Write>(&mut self, writer: &mut W, input: &[u8]) -> io::Result<()> {
        let padding = self.padding_len()?;
        let payload = match self.security {
            VmessSecurity::None => input.to_vec(),
            VmessSecurity::Aes128Gcm => {
                let nonce = self.nonce.next();
                aes_gcm_seal(&self.key, &nonce, input, &[])?
            }
            VmessSecurity::ChaCha20Poly1305 => {
                let nonce = self.nonce.next();
                chacha20_seal(&self.key, &nonce, input, &[])?
            }
        };
        let total_size = payload.len() + padding;
        if total_size > u16::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "vmess chunk is too large",
            ));
        }
        let encoded = self.size.encode(total_size as u16)?;
        write_all_wait(writer, &encoded)?;
        write_all_wait(writer, &payload)?;
        if padding > 0 {
            let mut padding_bytes = vec![0u8; padding];
            getrandom::getrandom(&mut padding_bytes)
                .map_err(|error| io::Error::new(io::ErrorKind::Other, error.to_string()))?;
            write_all_wait(writer, &padding_bytes)?;
        }
        Ok(())
    }

    fn padding_len(&mut self) -> io::Result<usize> {
        if self.options & OPTION_GLOBAL_PADDING == 0 {
            return Ok(0);
        }
        self.size.next_padding_len()
    }
}

impl<W: Write> Write for VmessBodyWriter<W> {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        self.encoder.write_plain(&mut self.writer, input)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()
    }
}

impl VmessSecurity {
    fn parse(value: u8) -> io::Result<Self> {
        match value {
            SECURITY_AES128_GCM => Ok(Self::Aes128Gcm),
            SECURITY_CHACHA20_POLY1305 => Ok(Self::ChaCha20Poly1305),
            SECURITY_NONE => Ok(Self::None),
            _ => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "unsupported vmess security",
            )),
        }
    }

    fn overhead(self) -> usize {
        match self {
            Self::Aes128Gcm | Self::ChaCha20Poly1305 => 16,
            Self::None => 0,
        }
    }
}

impl VmessSizeParser {
    fn new(
        mask_seed: [u8; 16],
        length_key_seed: [u8; 16],
        length_iv_seed: [u8; 16],
        options: u8,
        security: VmessSecurity,
    ) -> Self {
        if options & OPTION_AUTHENTICATED_LENGTH != 0
            && matches!(
                security,
                VmessSecurity::Aes128Gcm | VmessSecurity::ChaCha20Poly1305
            )
        {
            return Self {
                codec: VmessSizeCodec::Authenticated {
                    auth: VmessLengthAuthenticator::new(security, length_key_seed, length_iv_seed),
                    padding: if options & OPTION_GLOBAL_PADDING != 0 {
                        Some(Self::shake(mask_seed))
                    } else {
                        None
                    },
                },
            };
        }

        if options & OPTION_CHUNK_MASKING != 0 {
            return Self {
                codec: VmessSizeCodec::Masked {
                    shake: Self::shake(mask_seed),
                },
            };
        }

        Self {
            codec: VmessSizeCodec::Plain,
        }
    }

    fn size_bytes(&self) -> usize {
        match &self.codec {
            VmessSizeCodec::Authenticated { .. } => 18,
            VmessSizeCodec::Plain | VmessSizeCodec::Masked { .. } => 2,
        }
    }

    fn decode(&mut self, bytes: &[u8]) -> io::Result<u16> {
        match &mut self.codec {
            VmessSizeCodec::Plain => Self::decode_plain_size(bytes),
            VmessSizeCodec::Masked { shake } => {
                let value = Self::decode_plain_size(bytes)?;
                Ok(value ^ Self::next_mask_from(shake))
            }
            VmessSizeCodec::Authenticated { auth, .. } => auth.open_size(bytes),
        }
    }

    fn encode(&mut self, value: u16) -> io::Result<Vec<u8>> {
        match &mut self.codec {
            VmessSizeCodec::Plain => Ok(value.to_be_bytes().to_vec()),
            VmessSizeCodec::Masked { shake } => {
                Ok((value ^ Self::next_mask_from(shake)).to_be_bytes().to_vec())
            }
            VmessSizeCodec::Authenticated { auth, .. } => auth.seal_size(value),
        }
    }

    fn next_padding_len(&mut self) -> io::Result<usize> {
        let mask = match &mut self.codec {
            VmessSizeCodec::Masked { shake } => Self::next_mask_from(shake),
            VmessSizeCodec::Authenticated { padding, .. } => {
                let Some(shake) = padding.as_mut() else {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "vmess padding requires chunk masking",
                    ));
                };
                Self::next_mask_from(shake)
            }
            VmessSizeCodec::Plain => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "vmess padding requires chunk masking",
                ));
            }
        };
        Ok((mask % 64) as usize)
    }

    fn decode_plain_size(bytes: &[u8]) -> io::Result<u16> {
        let bytes: [u8; 2] = bytes.try_into().map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid vmess chunk size length",
            )
        })?;
        Ok(u16::from_be_bytes(bytes))
    }

    fn shake(seed: [u8; 16]) -> sha3::Shake128Reader {
        let mut shake = Shake128::default();
        Update::update(&mut shake, &seed);
        shake.finalize_xof()
    }

    fn next_mask_from(reader: &mut sha3::Shake128Reader) -> u16 {
        let mut bytes = [0u8; 2];
        let _ = reader.read(&mut bytes);
        u16::from_be_bytes(bytes)
    }
}

impl VmessLengthAuthenticator {
    fn new(security: VmessSecurity, key_seed: [u8; 16], iv_seed: [u8; 16]) -> Self {
        Self {
            security,
            key: kdf16(&key_seed, &[AUTHENTICATED_LENGTH_KEY]),
            nonce: ChunkNonce {
                iv: iv_seed,
                count: 0,
            },
        }
    }

    fn open_size(&mut self, bytes: &[u8]) -> io::Result<u16> {
        if bytes.len() != 18 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid vmess authenticated length size",
            ));
        }
        let nonce = self.nonce.next();
        let plain = match self.security {
            VmessSecurity::Aes128Gcm => aes_gcm_open(&self.key, &nonce, bytes, &[])?,
            VmessSecurity::ChaCha20Poly1305 => chacha20_open(&self.key, &nonce, bytes, &[])?,
            VmessSecurity::None => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "vmess authenticated length requires aead security",
                ));
            }
        };
        let size = VmessSizeParser::decode_plain_size(&plain)?;
        size.checked_add(16).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "vmess authenticated length is too large",
            )
        })
    }

    fn seal_size(&mut self, size: u16) -> io::Result<Vec<u8>> {
        let encoded = size.checked_sub(16).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "vmess authenticated length is too small",
            )
        })?;
        let nonce = self.nonce.next();
        match self.security {
            VmessSecurity::Aes128Gcm => {
                aes_gcm_seal(&self.key, &nonce, &encoded.to_be_bytes(), &[])
            }
            VmessSecurity::ChaCha20Poly1305 => {
                chacha20_seal(&self.key, &nonce, &encoded.to_be_bytes(), &[])
            }
            VmessSecurity::None => Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "vmess authenticated length requires aead security",
            )),
        }
    }
}

impl ChunkNonce {
    fn next(&mut self) -> [u8; 12] {
        let mut bytes = self.iv;
        bytes[..2].copy_from_slice(&self.count.to_be_bytes());
        self.count = self.count.wrapping_add(1);
        bytes[..12].try_into().expect("nonce slice is 12 bytes")
    }
}

fn open_aead_header<R: Read>(
    reader: &mut R,
    cmd_key: &[u8; 16],
    auth_id: &[u8; 16],
) -> io::Result<Vec<u8>> {
    let mut encrypted_len = [0u8; 18];
    let mut nonce = [0u8; 8];
    reader.read_exact(&mut encrypted_len)?;
    reader.read_exact(&mut nonce)?;

    let len_key = kdf16(cmd_key, &[HEADER_LENGTH_KEY, auth_id, &nonce]);
    let len_nonce = first_12(&kdf(cmd_key, &[HEADER_LENGTH_NONCE, auth_id, &nonce]));
    let len_plain = aes_gcm_open(&len_key, &len_nonce, &encrypted_len, auth_id)?;
    if len_plain.len() != 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid vmess header length payload",
        ));
    }
    let payload_len = u16::from_be_bytes([len_plain[0], len_plain[1]]) as usize;
    if payload_len > MAX_HEADER_LEN {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "vmess header is too large",
        ));
    }

    let mut encrypted_payload = vec![0u8; payload_len + 16];
    reader.read_exact(&mut encrypted_payload)?;
    let payload_key = kdf16(cmd_key, &[HEADER_PAYLOAD_KEY, auth_id, &nonce]);
    let payload_nonce = first_12(&kdf(cmd_key, &[HEADER_PAYLOAD_NONCE, auth_id, &nonce]));
    aes_gcm_open(&payload_key, &payload_nonce, &encrypted_payload, auth_id)
}

fn parse_request_header(header: &[u8]) -> io::Result<ParsedVmessHeader> {
    if header.len() < 42 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "vmess request header is too short",
        ));
    }
    let checksum_offset = header.len() - 4;
    let actual = fnv1a(&header[..checksum_offset]);
    let expected = u32::from_be_bytes(
        header[checksum_offset..]
            .try_into()
            .expect("checksum is four bytes"),
    );
    if actual != expected {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "invalid vmess request checksum",
        ));
    }
    if header[0] != VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unsupported vmess version",
        ));
    }

    let request_body_iv = header[1..17].try_into().expect("iv is 16 bytes");
    let request_body_key = header[17..33].try_into().expect("key is 16 bytes");
    let response_header = header[33];
    let options = header[34];
    let padding_len = (header[35] >> 4) as usize;
    let security = VmessSecurity::parse(header[35] & 0x0f)?;
    let command = header[37];
    if command != COMMAND_TCP {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "only vmess tcp command is supported",
        ));
    }

    let mut cursor = Cursor::new(&header[38..checksum_offset]);
    let target = read_vmess_target(&mut cursor)?;
    let consumed = cursor.position() as usize;
    if consumed + padding_len != checksum_offset - 38 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid vmess request padding length",
        ));
    }

    Ok(ParsedVmessHeader {
        target,
        request_body_key,
        request_body_iv,
        response_header,
        options,
        security,
    })
}

fn read_vmess_target<R: Read>(reader: &mut R) -> io::Result<SocksTarget> {
    let mut port = [0u8; 2];
    reader.read_exact(&mut port)?;
    let port = u16::from_be_bytes(port);
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
                "unsupported vmess address type",
            ));
        }
    };
    Ok(SocksTarget { host, port })
}

fn write_response_header<W: Write>(writer: &mut W, request: &VmessRequest) -> io::Result<()> {
    let header = [request.response_header, 0x00, 0x00, 0x00];
    let len_key = kdf16(&request.response_body_key, &[RESPONSE_HEADER_LENGTH_KEY]);
    let len_nonce = first_12(&kdf(
        &request.response_body_iv,
        &[RESPONSE_HEADER_LENGTH_IV],
    ));
    let len_cipher = aes_gcm_seal(
        &len_key,
        &len_nonce,
        &(header.len() as u16).to_be_bytes(),
        &[],
    )?;
    let payload_key = kdf16(&request.response_body_key, &[RESPONSE_HEADER_PAYLOAD_KEY]);
    let payload_nonce = first_12(&kdf(
        &request.response_body_iv,
        &[RESPONSE_HEADER_PAYLOAD_IV],
    ));
    let payload_cipher = aes_gcm_seal(&payload_key, &payload_nonce, &header, &[])?;
    writer.write_all(&len_cipher)?;
    writer.write_all(&payload_cipher)
}

fn decode_auth_id(auth_id_key: &[u8; 16], auth_id: &[u8; 16]) -> io::Result<bool> {
    let cipher = Aes128::new_from_slice(auth_id_key)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid vmess auth id key"))?;
    let mut block = aes::cipher::Block::<Aes128>::clone_from_slice(auth_id);
    cipher.decrypt_block(&mut block);
    let plain = block.as_slice();
    let crc = u32::from_be_bytes(plain[12..16].try_into().expect("crc is four bytes"));
    if crc != crc32fast::hash(&plain[..12]) {
        return Ok(false);
    }
    let timestamp = i64::from_be_bytes(plain[..8].try_into().expect("timestamp is eight bytes"));
    if timestamp < 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "invalid vmess auth id timestamp",
        ));
    }
    let now = unix_timestamp();
    if (timestamp - now).abs() > AUTH_ID_WINDOW_SECONDS {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "vmess auth id timestamp is outside the accepted window",
        ));
    }
    Ok(true)
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

fn write_all_wait<W: Write>(writer: &mut W, mut input: &[u8]) -> io::Result<()> {
    while !input.is_empty() {
        match writer.write(input) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "writer returned zero",
                ));
            }
            Ok(written) => input = &input[written..],
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(1));
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn vmess_cmd_key(uuid: &[u8; 16]) -> [u8; 16] {
    let mut hasher = Md5::new();
    Md5Digest::update(&mut hasher, uuid);
    Md5Digest::update(&mut hasher, CMD_KEY_SALT);
    hasher.finalize().into()
}

fn kdf16(key: &[u8], path: &[&[u8]]) -> [u8; 16] {
    first_16(&kdf(key, path))
}

fn kdf(key: &[u8], path: &[&[u8]]) -> [u8; 32] {
    kdf_hash(key, path)
}

fn kdf_hash(data: &[u8], path: &[&[u8]]) -> [u8; 32] {
    if path.is_empty() {
        let mut mac =
            <Hmac<Sha256> as Mac>::new_from_slice(KDF_ROOT).expect("hmac accepts any key length");
        Mac::update(&mut mac, data);
        return mac.finalize().into_bytes().into();
    }
    let key = path[path.len() - 1];
    hmac_with_hash(|input| kdf_hash(input, &path[..path.len() - 1]), key, data)
}

fn hmac_with_hash<H>(hash: H, key: &[u8], message: &[u8]) -> [u8; 32]
where
    H: Fn(&[u8]) -> [u8; 32],
{
    let mut normalized_key = if key.len() > 64 {
        hash(key).to_vec()
    } else {
        key.to_vec()
    };
    normalized_key.resize(64, 0);

    let mut inner = [0x36u8; 64];
    let mut outer = [0x5cu8; 64];
    for (index, key_byte) in normalized_key.iter().enumerate() {
        inner[index] ^= key_byte;
        outer[index] ^= key_byte;
    }
    let mut inner_input = Vec::with_capacity(64 + message.len());
    inner_input.extend_from_slice(&inner);
    inner_input.extend_from_slice(message);
    let inner_hash = hash(&inner_input);

    let mut outer_input = Vec::with_capacity(64 + inner_hash.len());
    outer_input.extend_from_slice(&outer);
    outer_input.extend_from_slice(&inner_hash);
    hash(&outer_input)
}

fn aes_gcm_open(key: &[u8; 16], nonce: &[u8; 12], input: &[u8], aad: &[u8]) -> io::Result<Vec<u8>> {
    let cipher = Aes128Gcm::new_from_slice(key)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid aes-gcm key"))?;
    cipher
        .decrypt(AesGcmNonce::from_slice(nonce), Payload { msg: input, aad })
        .map_err(|_| io::Error::new(io::ErrorKind::PermissionDenied, "vmess aes-gcm open failed"))
}

fn aes_gcm_seal(key: &[u8; 16], nonce: &[u8; 12], input: &[u8], aad: &[u8]) -> io::Result<Vec<u8>> {
    let cipher = Aes128Gcm::new_from_slice(key)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid aes-gcm key"))?;
    cipher
        .encrypt(AesGcmNonce::from_slice(nonce), Payload { msg: input, aad })
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "vmess aes-gcm seal failed"))
}

fn chacha20_open(
    key: &[u8; 16],
    nonce: &[u8; 12],
    input: &[u8],
    aad: &[u8],
) -> io::Result<Vec<u8>> {
    let derived = chacha20_key(key);
    let cipher = ChaCha20Poly1305::new_from_slice(&derived)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid chacha20 key"))?;
    cipher
        .decrypt(ChaChaNonce::from_slice(nonce), Payload { msg: input, aad })
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::PermissionDenied,
                "vmess chacha20-poly1305 open failed",
            )
        })
}

fn chacha20_seal(
    key: &[u8; 16],
    nonce: &[u8; 12],
    input: &[u8],
    aad: &[u8],
) -> io::Result<Vec<u8>> {
    let derived = chacha20_key(key);
    let cipher = ChaCha20Poly1305::new_from_slice(&derived)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid chacha20 key"))?;
    cipher
        .encrypt(ChaChaNonce::from_slice(nonce), Payload { msg: input, aad })
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "vmess chacha20-poly1305 seal failed"))
}

fn chacha20_key(key: &[u8; 16]) -> [u8; 32] {
    let first: [u8; 16] = Md5::digest(key).into();
    let second: [u8; 16] = Md5::digest(first).into();
    let mut output = [0u8; 32];
    output[..16].copy_from_slice(&first);
    output[16..].copy_from_slice(&second);
    output
}

fn first_16(bytes: &[u8; 32]) -> [u8; 16] {
    bytes[..16].try_into().expect("slice is sixteen bytes")
}

fn first_12(bytes: &[u8; 32]) -> [u8; 12] {
    bytes[..12].try_into().expect("slice is twelve bytes")
}

fn first_16_sha256(bytes: &[u8; 16]) -> [u8; 16] {
    first_16(&Sha256::digest(bytes).into())
}

fn fnv1a(bytes: &[u8]) -> u32 {
    let mut hash = 0x811c9dc5u32;
    for byte in bytes {
        hash ^= u32::from(*byte);
        hash = hash.wrapping_mul(0x01000193);
    }
    hash
}

fn parse_uuid_bytes(value: &str) -> io::Result<[u8; 16]> {
    let compact = value
        .chars()
        .filter(|value| *value != '-')
        .collect::<String>();
    if compact.len() != 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "vmess user uuid must be 16 bytes",
        ));
    }
    let mut output = [0u8; 16];
    for index in 0..16 {
        output[index] =
            u8::from_str_radix(&compact[index * 2..index * 2 + 2], 16).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "vmess user uuid is invalid")
            })?;
    }
    Ok(output)
}

fn format_uuid_compact(bytes: &[u8; 16]) -> String {
    let mut output = String::with_capacity(32);
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

fn unix_timestamp() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

#[cfg(test)]
fn create_auth_id(cmd_key: &[u8; 16], timestamp: i64, random: [u8; 4]) -> [u8; 16] {
    use aes::cipher::BlockEncrypt;

    let mut plain = [0u8; 16];
    plain[..8].copy_from_slice(&timestamp.to_be_bytes());
    plain[8..12].copy_from_slice(&random);
    let crc = crc32fast::hash(&plain[..12]);
    plain[12..].copy_from_slice(&crc.to_be_bytes());
    let key = kdf16(cmd_key, &[AUTH_ID_KEY]);
    let cipher = Aes128::new_from_slice(&key).expect("aes key");
    let mut block = aes::cipher::Block::<Aes128>::clone_from_slice(&plain);
    cipher.encrypt_block(&mut block);
    block.as_slice().try_into().expect("auth id block")
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::thread;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use rustls::pki_types::{CertificateDer, ServerName};
    use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

    use super::{
        create_auth_id, fnv1a, kdf, parse_uuid_bytes, vmess_cmd_key, write_response_header,
        VmessBodyReader, VmessBodyWriter, VmessRequest, VmessSecurity, VmessServer,
        VmessServerConfig, ATYP_IPV4, COMMAND_TCP, OPTION_AUTHENTICATED_LENGTH,
        OPTION_CHUNK_MASKING, OPTION_CHUNK_STREAM, OPTION_GLOBAL_PADDING, SECURITY_AES128_GCM,
        VERSION,
    };
    use crate::socks5::SocksTarget;
    use crate::tls::TlsAcceptor;
    use crate::user::CoreUser;

    fn user() -> CoreUser {
        CoreUser {
            id: 1,
            uuid: "11111111-1111-1111-1111-111111111111".to_string(),
            password: None,
            email: None,
            speed_limit: 0,
            device_limit: 0,
        }
    }

    fn server() -> VmessServer {
        VmessServer::new(VmessServerConfig {
            node_tag: "panel|vmess|1".to_string(),
            listen: "127.0.0.1:0".parse().expect("listen addr"),
            users: vec![user()],
            routes: Vec::new(),
            connect_timeout: Duration::from_secs(3),
        })
    }

    fn vmess_request(target: std::net::SocketAddr, payload: &[u8]) -> (Vec<u8>, VmessRequest) {
        vmess_request_with_options(
            target,
            payload,
            OPTION_CHUNK_STREAM | OPTION_CHUNK_MASKING | OPTION_GLOBAL_PADDING,
        )
    }

    fn vmess_request_with_options(
        target: std::net::SocketAddr,
        payload: &[u8],
        options: u8,
    ) -> (Vec<u8>, VmessRequest) {
        let uuid = parse_uuid_bytes(&user().uuid).expect("uuid");
        let cmd_key = vmess_cmd_key(&uuid);
        let request_body_key = [0x22u8; 16];
        let request_body_iv = [0x33u8; 16];
        let response_header = 0x44;
        let security = VmessSecurity::Aes128Gcm;
        let mut header = Vec::new();
        header.push(VERSION);
        header.extend_from_slice(&request_body_iv);
        header.extend_from_slice(&request_body_key);
        header.push(response_header);
        header.push(options);
        header.push(SECURITY_AES128_GCM);
        header.push(0);
        header.push(COMMAND_TCP);
        header.extend_from_slice(&target.port().to_be_bytes());
        header.push(ATYP_IPV4);
        header.extend_from_slice(
            &target
                .ip()
                .to_string()
                .parse::<std::net::Ipv4Addr>()
                .expect("ipv4")
                .octets(),
        );
        let checksum = fnv1a(&header);
        header.extend_from_slice(&checksum.to_be_bytes());

        let auth_id = create_auth_id(&cmd_key, super::unix_timestamp(), [1, 2, 3, 4]);
        let nonce = [9u8; 8];
        let encrypted_header = seal_header(&cmd_key, &auth_id, &nonce, &header);
        let mut body = VmessBodyWriter::new(
            Vec::new(),
            request_body_key,
            request_body_iv,
            options,
            security,
        )
        .expect("body writer");
        body.write_all(payload).expect("body payload");
        body.finish().expect("body finish");

        let response_body_key = super::first_16_sha256(&request_body_key);
        let response_body_iv = super::first_16_sha256(&request_body_iv);
        let request = VmessRequest {
            user_key: "11111111111111111111111111111111".to_string(),
            user_uuid: user().uuid,
            target: SocksTarget {
                host: target.ip().to_string(),
                port: target.port(),
            },
            request_body_key,
            request_body_iv,
            response_body_key,
            response_body_iv,
            response_header,
            options,
            security,
        };

        let mut output = encrypted_header;
        output.extend_from_slice(&body.into_inner());
        (output, request)
    }

    fn seal_header(
        cmd_key: &[u8; 16],
        auth_id: &[u8; 16],
        nonce: &[u8; 8],
        header: &[u8],
    ) -> Vec<u8> {
        let len_key = super::kdf16(
            cmd_key,
            &[super::HEADER_LENGTH_KEY, auth_id, nonce.as_slice()],
        );
        let len_nonce = super::first_12(&kdf(
            cmd_key,
            &[super::HEADER_LENGTH_NONCE, auth_id, nonce.as_slice()],
        ));
        let mut output = Vec::new();
        output.extend_from_slice(auth_id);
        output.extend_from_slice(
            &super::aes_gcm_seal(
                &len_key,
                &len_nonce,
                &(header.len() as u16).to_be_bytes(),
                auth_id,
            )
            .expect("header len seal"),
        );
        output.extend_from_slice(nonce);
        let payload_key = super::kdf16(
            cmd_key,
            &[super::HEADER_PAYLOAD_KEY, auth_id, nonce.as_slice()],
        );
        let payload_nonce = super::first_12(&kdf(
            cmd_key,
            &[super::HEADER_PAYLOAD_NONCE, auth_id, nonce.as_slice()],
        ));
        output.extend_from_slice(
            &super::aes_gcm_seal(&payload_key, &payload_nonce, header, auth_id)
                .expect("header payload seal"),
        );
        output
    }

    fn decode_response_header<R: Read>(stream: &mut R, request: &VmessRequest) {
        let mut len_cipher = [0u8; 18];
        stream.read_exact(&mut len_cipher).expect("response len");
        let len_key = super::kdf16(
            &request.response_body_key,
            &[super::RESPONSE_HEADER_LENGTH_KEY],
        );
        let len_nonce = super::first_12(&kdf(
            &request.response_body_iv,
            &[super::RESPONSE_HEADER_LENGTH_IV],
        ));
        let len =
            super::aes_gcm_open(&len_key, &len_nonce, &len_cipher, &[]).expect("response len open");
        let len = u16::from_be_bytes([len[0], len[1]]) as usize;
        let mut payload_cipher = vec![0u8; len + 16];
        stream
            .read_exact(&mut payload_cipher)
            .expect("response payload");
        let payload_key = super::kdf16(
            &request.response_body_key,
            &[super::RESPONSE_HEADER_PAYLOAD_KEY],
        );
        let payload_nonce = super::first_12(&kdf(
            &request.response_body_iv,
            &[super::RESPONSE_HEADER_PAYLOAD_IV],
        ));
        let payload = super::aes_gcm_open(&payload_key, &payload_nonce, &payload_cipher, &[])
            .expect("response payload open");
        assert_eq!(payload, [request.response_header, 0, 0, 0]);
    }

    fn websocket_request(path: &str) -> Vec<u8> {
        format!(
            "GET {path} HTTP/1.1\r\nHost: example.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\n\r\n"
        )
        .into_bytes()
    }

    fn masked_frame(payload: &[u8]) -> Vec<u8> {
        let mask = [1u8, 2, 3, 4];
        let mut frame = vec![0x82];
        if payload.len() < 126 {
            frame.push(0x80 | payload.len() as u8);
        } else if payload.len() <= u16::MAX as usize {
            frame.push(0x80 | 126);
            frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        } else {
            frame.push(0x80 | 127);
            frame.extend_from_slice(&(payload.len() as u64).to_be_bytes());
        }
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
        let cert_path = dir.join(format!("keli-core-rs-vmess-{label}-{nanos}.crt"));
        let key_path = dir.join(format!("keli-core-rs-vmess-{label}-{nanos}.key"));
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

    #[test]
    fn parses_vmess_aead_request_header() {
        let echo = TcpListener::bind("127.0.0.1:0").expect("echo bind");
        let echo_addr = echo.local_addr().expect("echo addr");
        let (input, _) = vmess_request(echo_addr, b"ping");
        let server = server();
        let mut cursor = std::io::Cursor::new(input);

        let request = server.read_request(&mut cursor).expect("request");
        let mut payload = [0u8; 4];
        let mut body = VmessBodyReader::new(
            cursor,
            request.request_body_key,
            request.request_body_iv,
            request.options,
            request.security,
        )
        .expect("body reader");
        body.read_exact(&mut payload).expect("payload");

        assert_eq!(request.user_uuid, "11111111-1111-1111-1111-111111111111");
        assert_eq!(request.target.port, echo_addr.port());
        assert_eq!(&payload, b"ping");
    }

    #[test]
    fn rejects_replayed_auth_id() {
        let echo = TcpListener::bind("127.0.0.1:0").expect("echo bind");
        let echo_addr = echo.local_addr().expect("echo addr");
        let (input, _) = vmess_request(echo_addr, b"ping");
        let server = server();

        let mut first = std::io::Cursor::new(input.clone());
        server.read_request(&mut first).expect("first request");
        let mut second = std::io::Cursor::new(input);
        let error = server
            .read_request(&mut second)
            .expect_err("replay should fail");

        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
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
        let listener = server.bind().expect("vmess bind");
        let vmess_addr = listener.local_addr().expect("vmess addr");
        let server_clone = server.clone();
        let server_thread = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("vmess accept");
            server_clone.handle_tcp_client(stream)
        });

        let (request_bytes, request) = vmess_request(echo_addr, b"ping");
        let mut client = TcpStream::connect(vmess_addr).expect("client connect");
        client.write_all(&request_bytes).expect("client request");
        decode_response_header(&mut client, &request);
        let mut body = VmessBodyReader::new(
            client,
            request.response_body_key,
            request.response_body_iv,
            request.options,
            request.security,
        )
        .expect("response body");
        let mut echoed = [0u8; 4];
        body.read_exact(&mut echoed).expect("client read payload");
        assert_eq!(&echoed, b"ping");
        drop(body);

        server_thread
            .join()
            .expect("server thread")
            .expect("serve once");
        echo_thread.join().expect("echo thread");

        let records = server.drain_traffic(1);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].node_tag, "panel|vmess|1");
        assert_eq!(records[0].user_uuid, "11111111-1111-1111-1111-111111111111");
        assert_eq!(records[0].upload, 4);
        assert_eq!(records[0].download, 4);
    }

    #[test]
    fn proxies_tcp_with_authenticated_length() {
        let echo = TcpListener::bind("127.0.0.1:0").expect("echo bind");
        let echo_addr = echo.local_addr().expect("echo addr");
        let echo_thread = thread::spawn(move || {
            let (mut stream, _) = echo.accept().expect("echo accept");
            let mut bytes = [0u8; 4];
            stream.read_exact(&mut bytes).expect("echo read");
            stream.write_all(&bytes).expect("echo write");
        });

        let server = server();
        let listener = server.bind().expect("vmess bind");
        let vmess_addr = listener.local_addr().expect("vmess addr");
        let server_clone = server.clone();
        let server_thread = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("vmess accept");
            server_clone.handle_tcp_client(stream)
        });

        let (request_bytes, request) = vmess_request_with_options(
            echo_addr,
            b"ping",
            OPTION_CHUNK_STREAM
                | OPTION_CHUNK_MASKING
                | OPTION_GLOBAL_PADDING
                | OPTION_AUTHENTICATED_LENGTH,
        );
        let mut client = TcpStream::connect(vmess_addr).expect("client connect");
        client.write_all(&request_bytes).expect("client request");
        decode_response_header(&mut client, &request);
        let mut body = VmessBodyReader::new_with_length_seed(
            client,
            request.response_body_key,
            request.response_body_iv,
            request.request_body_key,
            request.request_body_iv,
            request.options,
            request.security,
        )
        .expect("response body");
        let mut echoed = [0u8; 4];
        body.read_exact(&mut echoed).expect("client read payload");
        assert_eq!(&echoed, b"ping");
        drop(body);

        server_thread
            .join()
            .expect("server thread")
            .expect("serve once");
        echo_thread.join().expect("echo thread");

        let records = server.drain_traffic(1);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].upload, 4);
        assert_eq!(records[0].download, 4);
    }

    #[test]
    fn proxies_tls_and_records_user_traffic() {
        let cert = test_cert("tcp");
        let echo = TcpListener::bind("127.0.0.1:0").expect("echo bind");
        let echo_addr = echo.local_addr().expect("echo addr");
        let echo_thread = thread::spawn(move || {
            let (mut stream, _) = echo.accept().expect("echo accept");
            let mut bytes = [0u8; 4];
            stream.read_exact(&mut bytes).expect("echo read");
            stream.write_all(&bytes).expect("echo write");
        });

        let server = server();
        let listener = server.bind().expect("vmess bind");
        let vmess_addr = listener.local_addr().expect("vmess addr");
        let acceptor =
            TlsAcceptor::from_files(&cert.cert_path, &cert.key_path, &[]).expect("tls acceptor");
        let server_clone = server.clone();
        let server_thread = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("vmess accept");
            let client = acceptor.accept(stream).expect("tls accept");
            server_clone.handle_tls_client(client)
        });

        let (request_bytes, request) = vmess_request(echo_addr, b"ping");
        let mut client = tls_client(vmess_addr, cert.cert_der.clone());
        client.write_all(&request_bytes).expect("client request");
        decode_response_header(&mut client, &request);
        let mut body = VmessBodyReader::new(
            client,
            request.response_body_key,
            request.response_body_iv,
            request.options,
            request.security,
        )
        .expect("response body");
        let mut echoed = [0u8; 4];
        body.read_exact(&mut echoed).expect("client read payload");
        assert_eq!(&echoed, b"ping");
        drop(body);

        server_thread
            .join()
            .expect("server thread")
            .expect("serve once");
        echo_thread.join().expect("echo thread");

        let records = server.drain_traffic(1);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].node_tag, "panel|vmess|1");
        assert_eq!(records[0].user_uuid, "11111111-1111-1111-1111-111111111111");
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
        let listener = server.bind().expect("vmess bind");
        let vmess_addr = listener.local_addr().expect("vmess addr");
        let server_clone = server.clone();
        let server_thread = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("vmess accept");
            server_clone.handle_websocket_client(stream, Some("/vmess"))
        });

        let (request_bytes, request) = vmess_request(echo_addr, b"ping");
        let mut client = TcpStream::connect(vmess_addr).expect("client connect");
        client
            .write_all(&websocket_request("/vmess"))
            .expect("websocket request");
        let response = read_websocket_response(&mut client);
        assert!(response.contains("101 Switching Protocols"));
        client
            .write_all(&masked_frame(&request_bytes))
            .expect("vmess frame");

        let mut response_header = read_binary_frame(&mut client);
        response_header.extend_from_slice(&read_binary_frame(&mut client));
        decode_response_header(&mut std::io::Cursor::new(response_header), &request);

        let mut body_frame = read_binary_frame(&mut client);
        body_frame.extend_from_slice(&read_binary_frame(&mut client));
        body_frame.extend_from_slice(&read_binary_frame(&mut client));
        let mut body = VmessBodyReader::new(
            std::io::Cursor::new(body_frame),
            request.response_body_key,
            request.response_body_iv,
            request.options,
            request.security,
        )
        .expect("response body");
        let mut echoed = [0u8; 4];
        body.read_exact(&mut echoed).expect("client read payload");
        assert_eq!(&echoed, b"ping");
        drop(body);
        drop(client);

        server_thread
            .join()
            .expect("server thread")
            .expect("serve once");
        echo_thread.join().expect("echo thread");

        let records = server.drain_traffic(1);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].node_tag, "panel|vmess|1");
        assert_eq!(records[0].user_uuid, "11111111-1111-1111-1111-111111111111");
        assert_eq!(records[0].upload, 4);
        assert_eq!(records[0].download, 4);
    }

    #[test]
    fn proxies_tls_websocket_and_records_user_traffic() {
        let cert = test_cert("ws");
        let echo = TcpListener::bind("127.0.0.1:0").expect("echo bind");
        let echo_addr = echo.local_addr().expect("echo addr");
        let echo_thread = thread::spawn(move || {
            let (mut stream, _) = echo.accept().expect("echo accept");
            let mut bytes = [0u8; 4];
            stream.read_exact(&mut bytes).expect("echo read");
            stream.write_all(&bytes).expect("echo write");
        });

        let server = server();
        let listener = server.bind().expect("vmess bind");
        let vmess_addr = listener.local_addr().expect("vmess addr");
        let acceptor =
            TlsAcceptor::from_files(&cert.cert_path, &cert.key_path, &[]).expect("tls acceptor");
        let server_clone = server.clone();
        let server_thread = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("vmess accept");
            let client = acceptor.accept(stream).expect("tls accept");
            server_clone.handle_tls_websocket_client(client, Some("/vmess"))
        });

        let (request_bytes, request) = vmess_request(echo_addr, b"ping");
        let mut client = tls_client(vmess_addr, cert.cert_der.clone());
        client
            .write_all(&websocket_request("/vmess"))
            .expect("websocket request");
        let response = read_websocket_response(&mut client);
        assert!(response.contains("101 Switching Protocols"));
        client
            .write_all(&masked_frame(&request_bytes))
            .expect("vmess frame");

        let mut response_header = read_binary_frame(&mut client);
        response_header.extend_from_slice(&read_binary_frame(&mut client));
        decode_response_header(&mut std::io::Cursor::new(response_header), &request);

        let mut body_frame = read_binary_frame(&mut client);
        body_frame.extend_from_slice(&read_binary_frame(&mut client));
        body_frame.extend_from_slice(&read_binary_frame(&mut client));
        let mut body = VmessBodyReader::new(
            std::io::Cursor::new(body_frame),
            request.response_body_key,
            request.response_body_iv,
            request.options,
            request.security,
        )
        .expect("response body");
        let mut echoed = [0u8; 4];
        body.read_exact(&mut echoed).expect("client read payload");
        assert_eq!(&echoed, b"ping");
        drop(body);
        drop(client);

        server_thread
            .join()
            .expect("server thread")
            .expect("serve once");
        echo_thread.join().expect("echo thread");

        let records = server.drain_traffic(1);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].node_tag, "panel|vmess|1");
        assert_eq!(records[0].user_uuid, "11111111-1111-1111-1111-111111111111");
        assert_eq!(records[0].upload, 4);
        assert_eq!(records[0].download, 4);
    }

    #[test]
    fn writes_vmess_response_header() {
        let request = VmessRequest {
            user_key: "user".to_string(),
            user_uuid: "user".to_string(),
            target: SocksTarget {
                host: "127.0.0.1".to_string(),
                port: 80,
            },
            request_body_key: [0x22; 16],
            request_body_iv: [0x33; 16],
            response_body_key: super::first_16_sha256(&[0x22; 16]),
            response_body_iv: super::first_16_sha256(&[0x33; 16]),
            response_header: 0x77,
            options: OPTION_CHUNK_STREAM,
            security: VmessSecurity::Aes128Gcm,
        };
        let mut bytes = Vec::new();

        write_response_header(&mut bytes, &request).expect("response header");
        decode_response_header(&mut std::io::Cursor::new(bytes), &request);
    }
}
