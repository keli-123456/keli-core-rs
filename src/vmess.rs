use std::collections::HashMap;
use std::convert::TryInto;
use std::io::{self, Cursor, Read, Write};
use std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket,
};
use std::sync::{Arc, Mutex, RwLock};
use std::thread;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use aes::cipher::{BlockDecrypt, BlockEncrypt, KeyInit as BlockKeyInit};
use aes::Aes128;
use aes_gcm::aead::{Aead, Payload};
use aes_gcm::{Aes128Gcm, Nonce as AesGcmNonce};
use chacha20poly1305::{ChaCha20Poly1305, Nonce as ChaChaNonce};
use hmac::{Hmac, Mac};
use md5::{Digest as Md5Digest, Md5};
use sha2::Sha256;
use sha3::digest::{ExtendableOutput, Update};
use sha3::Shake128;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, RootCertStore, SignatureScheme,
    StreamOwned,
};

use crate::config::{outbound_transport_network, OutboundConfig, OutboundTlsConfig};
use crate::grpc::connect_grpc_client;
use crate::http2::connect_http2_client;
use crate::httpupgrade::connect_httpupgrade_client;
use crate::limits::{
    sync_user_limit_delta, BandwidthLimiter, UserBandwidthLimiters, UserSessionGuard,
    UserSessionTracker,
};
use crate::outbound::recv_udp_response;
use crate::quic::connect_quic_client_stream;
use crate::socket_bind::bind_dual_stack_tcp_listener;
use crate::socks5::SocksTarget;
use crate::stream::{
    copy_count_best_effort, copy_count_best_effort_limited, join_native_blocking_relay,
    spawn_native_blocking_relay,
};
use crate::tls::TlsConnection;
use crate::traffic::{SharedTrafficRegistry, TrafficRegistry};
use crate::user::{CoreUser, CoreUserDelta, CoreUserDeltaResult, UserStore};
use crate::websocket::{accept_websocket, accept_websocket_tls, connect_websocket_client};
use crate::{
    connect_tcp_outbound, route_protocol_labels, send_udp_outbound, RouteDecision, RouteMatcher,
};

const VERSION: u8 = 0x01;
const COMMAND_TCP: u8 = 0x01;
const COMMAND_UDP: u8 = 0x02;
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
const ALTER_ID_SALT: &[u8] = b"16167dc8-16b6-4e6d-b8bb-65dd68113a81";
const ALTER_ID_RETRY_SALT: &[u8] = b"533eff8a-4113-4b10-b5ce-0f5d76b98cd2";
const MAX_HEADER_LEN: usize = 4096;
const MAX_CHUNK_SIZE: usize = 64 * 1024 - 80;
const VMESS_RELAY_BUFFER_SIZE: usize = 64 * 1024;
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
    users: UserStore,
    auth_users: Arc<RwLock<Vec<VmessAuthUser>>>,
    replay: Arc<Mutex<HashMap<[u8; 16], Instant>>>,
    router: RouteMatcher,
    traffic: SharedTrafficRegistry,
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
    command: VmessCommand,
    user_key: String,
    user_uuid: String,
    user_id: Option<u64>,
    target: SocksTarget,
    client_ip: Option<IpAddr>,
    request_body_key: [u8; 16],
    request_body_iv: [u8; 16],
    response_body_key: [u8; 16],
    response_body_iv: [u8; 16],
    response_header: u8,
    options: u8,
    security: VmessSecurity,
    header_mode: VmessHeaderMode,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum VmessCommand {
    Tcp,
    Udp,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum VmessHeaderMode {
    Aead,
    Legacy,
}

struct Aes128Cfb {
    cipher: Aes128,
    feedback: [u8; 16],
    stream: [u8; 16],
    offset: usize,
}

struct VmessUdpRelayState {
    ipv4: Option<UdpSocket>,
    ipv6: Option<UdpSocket>,
    target: Option<SocksTarget>,
    target_addr: Option<SocketAddr>,
    timeout: Duration,
}

impl VmessServer {
    pub fn new(config: VmessServerConfig) -> Self {
        Self::with_traffic(config, TrafficRegistry::shared())
    }

    pub fn with_traffic(config: VmessServerConfig, traffic: SharedTrafficRegistry) -> Self {
        Self::with_shared_limits(
            config,
            traffic,
            UserSessionTracker::default(),
            UserBandwidthLimiters::default(),
        )
    }

    pub fn with_shared_limits(
        mut config: VmessServerConfig,
        traffic: SharedTrafficRegistry,
        sessions: UserSessionTracker,
        bandwidth: UserBandwidthLimiters,
    ) -> Self {
        let users = valid_vmess_users(&config.users);
        let auth_users = vmess_auth_users(&users);
        config.users.clear();

        Self {
            router: RouteMatcher::new(config.routes.clone()),
            config,
            users: UserStore::from_keyed_users(&users, |user| {
                vmess_user_key(user).expect("valid vmess user")
            }),
            auth_users: Arc::new(RwLock::new(auth_users)),
            replay: Arc::new(Mutex::new(HashMap::new())),
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
        let mut request = self.read_request(&mut client)?;
        request.client_ip = client_ip;
        let user = self.request_user(&request);
        let _session = self.acquire_user_session(user.as_ref(), client_ip)?;
        let bandwidth = if request.command == VmessCommand::Udp {
            self.bandwidth.limiter_for(user.as_ref())
        } else {
            self.bandwidth.limiter_for_limited(user.as_ref())
        };
        if request.command == VmessCommand::Udp {
            write_response_header(&mut client, &request)?;
            return self.relay_udp_single(client, request, bandwidth);
        }
        let remote = self.connect_for_request(&request)?;
        let _connection = self
            .bandwidth
            .register_tcp_connection(Some(&request.user_uuid), &[&client, &remote])?;
        write_response_header(&mut client, &request)?;
        self.relay_split(client, remote, request, bandwidth)
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
        mut writer: W,
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
        let bandwidth = if request.command == VmessCommand::Udp {
            self.bandwidth.limiter_for(user.as_ref())
        } else {
            self.bandwidth.limiter_for_limited(user.as_ref())
        };
        if request.command == VmessCommand::Udp {
            write_response_header(&mut writer, &request)?;
            return self.relay_udp_split(reader, writer, request, bandwidth);
        }
        let remote = self.connect_for_request(&request)?;
        write_response_header(&mut writer, &request)?;
        self.relay_split_io(reader, writer, remote, request, bandwidth)
    }

    pub fn handle_tls_client(&self, mut client: TlsConnection) -> io::Result<()> {
        let client_ip = client.peer_addr().ok().map(|addr| addr.ip());
        let mut request = self.read_request(&mut client)?;
        request.client_ip = client_ip;
        let user = self.request_user(&request);
        let _session = self.acquire_user_session(user.as_ref(), client_ip)?;
        let bandwidth = if request.command == VmessCommand::Udp {
            self.bandwidth.limiter_for(user.as_ref())
        } else {
            self.bandwidth.limiter_for_limited(user.as_ref())
        };
        if request.command == VmessCommand::Udp {
            write_response_header(&mut client, &request)?;
            return self.relay_udp_single(client, request, bandwidth);
        }
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
        let client_ip = client.peer_addr().ok().map(|addr| addr.ip());
        let mut websocket = accept_websocket_tls(client, path)?;
        let mut request = self.read_request(&mut websocket)?;
        request.client_ip = client_ip;
        let user = self.request_user(&request);
        let _session = self.acquire_user_session(user.as_ref(), client_ip)?;
        let bandwidth = if request.command == VmessCommand::Udp {
            self.bandwidth.limiter_for(user.as_ref())
        } else {
            self.bandwidth.limiter_for_limited(user.as_ref())
        };
        if request.command == VmessCommand::Udp {
            write_response_header(&mut websocket, &request)?;
            return self.relay_udp_single(websocket, request, bandwidth);
        }
        let remote = self.connect_for_request(&request)?;
        write_response_header(&mut websocket, &request)?;
        websocket.set_nonblocking(true)?;
        self.relay_single_io(websocket, remote, request, bandwidth)
    }

    pub fn drain_traffic(&self, minimum_bytes: u64) -> Vec<crate::traffic::TrafficDelta> {
        self.traffic.drain_minimum(minimum_bytes)
    }

    pub fn replace_users(&self, users: Vec<CoreUser>) {
        let users = valid_vmess_users(&users);
        self.bandwidth.sync_users(&users);
        self.users.replace_keyed_users(users.clone(), |user| {
            vmess_user_key(user).expect("valid vmess user")
        });
        let mut auth_users = self
            .auth_users
            .write()
            .expect("vmess auth users lock poisoned");
        *auth_users = vmess_auth_users(&users);
    }

    pub fn apply_user_delta(&self, delta: &CoreUserDelta) -> CoreUserDeltaResult {
        let delta = CoreUserDelta {
            added: valid_vmess_users(&delta.added),
            updated: valid_vmess_users(&delta.updated),
            deleted: delta.deleted.clone(),
            full: delta.full.as_ref().map(|users| valid_vmess_users(users)),
            base_revision: delta.base_revision.clone(),
            revision: delta.revision.clone(),
        };
        sync_delta_bandwidth(&self.bandwidth, &self.sessions, &delta);
        let mut result = self.users.apply_keyed_delta(&delta, |user| {
            vmess_user_key(user).expect("valid vmess user")
        });
        let users = self.users.list();
        result.active_users = users.len();
        let mut auth_users = self
            .auth_users
            .write()
            .expect("vmess auth users lock poisoned");
        *auth_users = vmess_auth_users(&users);
        result
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
        if parsed.command == VmessCommand::Udp && parsed.options & OPTION_CHUNK_STREAM == 0 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "vmess udp command requires chunk stream option",
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
            command: parsed.command,
            user_key: user.user_key.clone(),
            user_uuid: core_user.uuid.clone(),
            user_id: Some(core_user.id),
            target: parsed.target,
            client_ip: None,
            request_body_key: parsed.request_body_key,
            request_body_iv: parsed.request_body_iv,
            response_body_key,
            response_body_iv,
            response_header: parsed.response_header,
            options: parsed.options,
            security: parsed.security,
            header_mode: VmessHeaderMode::Aead,
        })
    }

    fn match_auth_id(&self, auth_id: [u8; 16]) -> io::Result<VmessAuthUser> {
        let matched = {
            let auth_users = self
                .auth_users
                .read()
                .expect("vmess auth users lock poisoned");
            let mut matched = None;
            for user in auth_users.iter() {
                if decode_auth_id(&user.auth_id_key, &auth_id)? {
                    matched = Some(user.clone());
                    break;
                }
            }
            matched
        };
        let Some(user) = matched else {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "invalid vmess auth id",
            ));
        };
        self.record_auth_id(auth_id)?;
        Ok(user)
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
        let decision = self
            .router
            .decide_target(&request.target.host, request.target.port, "tcp");
        match &decision {
            RouteDecision::Direct => connect_target(&request.target, self.config.connect_timeout),
            RouteDecision::Outbound(outbound) => {
                connect_tcp_outbound(outbound, &request.target, self.config.connect_timeout)
            }
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
            let copied = match upload_limiter.as_deref() {
                Some(limiter) => copy_count_best_effort_limited(
                    &mut request_body,
                    &mut remote_write,
                    Some(limiter),
                ),
                None => copy_count_best_effort(&mut request_body, &mut remote_write),
            };
            let _ = remote_write.shutdown(Shutdown::Write);
            copied
        });
        let download = match bandwidth.as_deref() {
            Some(limiter) => {
                copy_count_best_effort_limited(&mut remote_read, &mut response_body, Some(limiter))
            }
            None => copy_count_best_effort(&mut remote_read, &mut response_body),
        };
        let _ = response_body.finish();
        let upload = upload_thread
            .join()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "upload relay thread panicked"))?;
        self.traffic.add_with_user_id(
            self.config.node_tag.clone(),
            request.user_uuid,
            request.user_id,
            upload,
            download,
            request.client_ip,
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
                            if !limiter.wait_for(read) {
                                upload_done = true;
                                let _ = remote.shutdown(Shutdown::Write);
                                continue;
                            }
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
        self.traffic.add_with_user_id(
            self.config.node_tag.clone(),
            request.user_uuid,
            request.user_id,
            upload,
            download,
            request.client_ip,
        );
        Ok(())
    }

    fn relay_udp_split<R, W>(
        &self,
        client_reader: R,
        client_writer: W,
        request: VmessRequest,
        bandwidth: Option<Arc<BandwidthLimiter>>,
    ) -> io::Result<()>
    where
        R: Read,
        W: Write,
    {
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
        let mut state = VmessUdpRelayState::new(self.config.connect_timeout);
        let mut upload = 0u64;
        let mut download = 0u64;
        let result = loop {
            match request_body.read_packet() {
                Ok(Some(payload)) => {
                    match self.forward_udp_payload(
                        &mut state,
                        &request.target,
                        &payload,
                        bandwidth.as_deref(),
                    ) {
                        Ok((sent, response)) => {
                            upload = upload.saturating_add(sent);
                            if let Some(response) = response {
                                response_body.write_packet(&response)?;
                                download = download.saturating_add(response.len() as u64);
                            }
                        }
                        Err(error) => break Err(error),
                    }
                }
                Ok(None) => break Ok(()),
                Err(error) => break Err(error),
            }
        };
        let _ = response_body.finish();
        self.record_traffic(
            request.user_uuid,
            request.user_id,
            upload,
            download,
            request.client_ip,
        );
        result
    }

    fn relay_udp_single<S>(
        &self,
        mut client: S,
        request: VmessRequest,
        bandwidth: Option<Arc<BandwidthLimiter>>,
    ) -> io::Result<()>
    where
        S: Read + Write,
    {
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
        let mut state = VmessUdpRelayState::new(self.config.connect_timeout);
        let mut upload = 0u64;
        let mut download = 0u64;
        let result = loop {
            match request_body.read_packet(&mut client) {
                Ok(Some(payload)) => {
                    match self.forward_udp_payload(
                        &mut state,
                        &request.target,
                        &payload,
                        bandwidth.as_deref(),
                    ) {
                        Ok((sent, response)) => {
                            upload = upload.saturating_add(sent);
                            if let Some(response) = response {
                                response_body.write_packet(&mut client, &response)?;
                                download = download.saturating_add(response.len() as u64);
                            }
                        }
                        Err(error) => break Err(error),
                    }
                }
                Ok(None) => break Ok(()),
                Err(error) => break Err(error),
            }
        };
        let _ = response_body.finish(&mut client);
        self.record_traffic(
            request.user_uuid,
            request.user_id,
            upload,
            download,
            request.client_ip,
        );
        result
    }

    fn forward_udp_payload(
        &self,
        state: &mut VmessUdpRelayState,
        target: &SocksTarget,
        payload: &[u8],
        bandwidth: Option<&BandwidthLimiter>,
    ) -> io::Result<(u64, Option<Vec<u8>>)> {
        let protocol_labels = route_protocol_labels("udp", payload);
        let decision = self
            .router
            .decide_target(&target.host, target.port, &protocol_labels);
        let outbound = match &decision {
            RouteDecision::Direct => None,
            RouteDecision::Outbound(outbound) => Some(outbound),
            RouteDecision::Block => return Ok((0, None)),
            RouteDecision::UnsupportedOutbound(tag) => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!("outbound route {tag} is not implemented"),
                ));
            }
        };

        if let Some(limiter) = bandwidth {
            if !limiter.wait_for(payload.len()) {
                return Ok((0, None));
            }
        }

        if let Some(outbound) = outbound {
            return match send_udp_outbound(outbound, target, payload, self.config.connect_timeout) {
                Ok((_, response)) => Ok((payload.len() as u64, Some(response))),
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                    ) =>
                {
                    Ok((payload.len() as u64, None))
                }
                Err(error) => Err(error),
            };
        }

        let remote_addr = state.remote_addr_for(target)?;
        let udp = state.socket_for(remote_addr)?;
        udp.send_to(payload, remote_addr)?;
        let mut response = vec![0u8; 65_535];
        match recv_udp_response(udp, &mut response) {
            Ok((read, _)) => {
                response.truncate(read);
                Ok((payload.len() as u64, Some(response)))
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                Ok((payload.len() as u64, None))
            }
            Err(error) => Err(error),
        }
    }

    fn record_traffic(
        &self,
        user_uuid: String,
        user_id: Option<u64>,
        upload: u64,
        download: u64,
        client_ip: Option<IpAddr>,
    ) {
        self.traffic.add_with_user_id(
            self.config.node_tag.clone(),
            user_uuid,
            user_id,
            upload,
            download,
            client_ip,
        );
    }

    fn request_user(&self, request: &VmessRequest) -> Option<CoreUser> {
        self.users.get(&request.user_key)
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

impl VmessUdpRelayState {
    fn new(timeout: Duration) -> Self {
        Self {
            ipv4: None,
            ipv6: None,
            target: None,
            target_addr: None,
            timeout,
        }
    }

    fn remote_addr_for(&mut self, target: &SocksTarget) -> io::Result<SocketAddr> {
        if self.target.as_ref() == Some(target) {
            if let Some(target_addr) = self.target_addr {
                return Ok(target_addr);
            }
        }
        let target_addr = resolve_udp_target(target)?;
        self.target = Some(target.clone());
        self.target_addr = Some(target_addr);
        Ok(target_addr)
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

fn valid_vmess_users(users: &[CoreUser]) -> Vec<CoreUser> {
    users
        .iter()
        .filter(|user| !user.is_empty() && vmess_user_key(user).is_some())
        .cloned()
        .collect()
}

fn sync_delta_bandwidth(
    bandwidth: &UserBandwidthLimiters,
    sessions: &UserSessionTracker,
    delta: &CoreUserDelta,
) {
    sync_user_limit_delta(bandwidth, sessions, delta);
}

fn vmess_auth_users(users: &[CoreUser]) -> Vec<VmessAuthUser> {
    users
        .iter()
        .filter_map(|user| {
            let uuid_bytes = parse_uuid_bytes(&user.uuid).ok()?;
            let user_key = format_uuid_compact(&uuid_bytes);
            let cmd_key = vmess_cmd_key(&uuid_bytes);
            let auth_id_key = kdf16(&cmd_key, &[AUTH_ID_KEY]);
            Some(VmessAuthUser {
                user_key,
                cmd_key,
                auth_id_key,
            })
        })
        .collect()
}

fn vmess_user_key(user: &CoreUser) -> Option<String> {
    parse_uuid_bytes(&user.uuid)
        .ok()
        .map(|uuid| format_uuid_compact(&uuid))
}

#[derive(Debug)]
struct ParsedVmessHeader {
    command: VmessCommand,
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

    fn read_packet(&mut self) -> io::Result<Option<Vec<u8>>> {
        self.decoder.read_packet(&mut self.reader)
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

    fn read_packet<R: Read>(&mut self, reader: &mut R) -> io::Result<Option<Vec<u8>>> {
        if self.security == VmessSecurity::None && self.options & OPTION_CHUNK_STREAM == 0 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "vmess udp packets require chunk stream framing",
            ));
        }
        if !self.buffer.is_empty() {
            return Ok(Some(std::mem::take(&mut self.buffer)));
        }
        self.read_next_chunk(reader)?;
        if self.buffer.is_empty() && self.eof {
            return Ok(None);
        }
        Ok(Some(std::mem::take(&mut self.buffer)))
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

    fn write_packet(&mut self, input: &[u8]) -> io::Result<()> {
        self.encoder.write_packet(&mut self.writer, input)
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

    fn write_packet<W: Write>(&mut self, writer: &mut W, input: &[u8]) -> io::Result<()> {
        if self.security == VmessSecurity::None && self.options & OPTION_CHUNK_STREAM == 0 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "vmess udp packets require chunk stream framing",
            ));
        }
        self.write_chunk(writer, input)
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
    let command = match header[37] {
        COMMAND_TCP => VmessCommand::Tcp,
        COMMAND_UDP => VmessCommand::Udp,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "only vmess tcp and udp commands are supported",
            ));
        }
    };

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
        command,
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
    crate::dns::connect_tcp(&target.host, target.port, timeout)
}

pub(crate) fn connect_vmess_tcp_outbound(
    outbound: &OutboundConfig,
    target: &SocksTarget,
    timeout: Duration,
) -> io::Result<TcpStream> {
    let server = vmess_outbound_server(outbound)?;
    let network = outbound_transport_network(outbound).to_ascii_lowercase();
    if network == "ws" {
        return connect_vmess_websocket_tcp_outbound(outbound, &server, target, timeout);
    }
    if network == "httpupgrade" {
        return connect_vmess_httpupgrade_tcp_outbound(outbound, &server, target, timeout);
    }
    if network == "grpc" {
        return connect_vmess_grpc_tcp_outbound(outbound, &server, target, timeout);
    }
    if matches!(network.as_str(), "h2" | "http") {
        return connect_vmess_h2_tcp_outbound(outbound, &server, target, timeout);
    }
    if network == "quic" {
        return connect_vmess_quic_tcp_outbound(outbound, &server, target, timeout);
    }
    if network != "tcp" {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("vmess outbound transport {network} is not supported yet"),
        ));
    }
    if outbound.tls.is_some() {
        return connect_vmess_tls_tcp_outbound(outbound, &server, target, timeout);
    }
    let mut stream = connect_target(&server, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    let request = write_vmess_tcp_request(&mut stream, outbound, target)?;
    local_bridge_for_vmess_tcp(stream, request)
}

fn connect_vmess_h2_tcp_outbound(
    outbound: &OutboundConfig,
    server: &SocksTarget,
    target: &SocksTarget,
    timeout: Duration,
) -> io::Result<TcpStream> {
    let host = outbound_transport_host(outbound, server);
    let mut h2 = connect_http2_client(
        server,
        timeout,
        outbound.tls.as_ref(),
        outbound_transport_path(outbound),
        &host,
        outbound_transport_method(outbound),
        outbound_transport_headers(outbound),
    )?;
    let request = write_vmess_tcp_request(&mut h2, outbound, target)?;
    h2.flush()?;
    h2.set_nonblocking(true);
    local_bridge_for_vmess(h2, request)
}

fn connect_vmess_quic_tcp_outbound(
    outbound: &OutboundConfig,
    server: &SocksTarget,
    target: &SocksTarget,
    timeout: Duration,
) -> io::Result<TcpStream> {
    let mut quic = connect_quic_client_stream(
        server,
        timeout,
        outbound.tls.as_ref(),
        outbound.transport.as_ref(),
    )?;
    let request = write_vmess_tcp_request(&mut quic, outbound, target)?;
    quic.set_nonblocking(true)?;
    local_bridge_for_vmess(quic, request)
}

fn connect_vmess_grpc_tcp_outbound(
    outbound: &OutboundConfig,
    server: &SocksTarget,
    target: &SocksTarget,
    timeout: Duration,
) -> io::Result<TcpStream> {
    let host = outbound_transport_host(outbound, server);
    let mut grpc = connect_grpc_client(
        server,
        timeout,
        outbound.tls.as_ref(),
        outbound_transport_service_name(outbound),
        &host,
    )?;
    let request = write_vmess_tcp_request(&mut grpc, outbound, target)?;
    grpc.flush()?;
    grpc.set_nonblocking(true);
    local_bridge_for_vmess(grpc, request)
}

fn connect_vmess_httpupgrade_tcp_outbound(
    outbound: &OutboundConfig,
    server: &SocksTarget,
    target: &SocksTarget,
    timeout: Duration,
) -> io::Result<TcpStream> {
    if outbound.tls.is_some() {
        let tls_stream = connect_vmess_tls_stream(outbound, server, timeout)?;
        let host = outbound_transport_host(outbound, server);
        let mut tls_stream =
            connect_httpupgrade_client(tls_stream, outbound_transport_path(outbound), &host)?;
        let request = write_vmess_tcp_request(&mut tls_stream, outbound, target)?;
        tls_stream.flush()?;
        tls_stream.sock.set_nonblocking(true)?;
        return local_bridge_for_vmess(tls_stream, request);
    }

    let remote = connect_target(server, timeout)?;
    remote.set_read_timeout(Some(timeout))?;
    remote.set_write_timeout(Some(timeout))?;
    let host = outbound_transport_host(outbound, server);
    let mut stream = connect_httpupgrade_client(remote, outbound_transport_path(outbound), &host)?;
    let request = write_vmess_tcp_request(&mut stream, outbound, target)?;
    stream.set_nonblocking(true)?;
    local_bridge_for_vmess(stream, request)
}

fn connect_vmess_websocket_tcp_outbound(
    outbound: &OutboundConfig,
    server: &SocksTarget,
    target: &SocksTarget,
    timeout: Duration,
) -> io::Result<TcpStream> {
    if outbound.tls.is_some() {
        let tls_stream = connect_vmess_tls_stream(outbound, server, timeout)?;
        let host = outbound_transport_host(outbound, server);
        let mut websocket =
            connect_websocket_client(tls_stream, outbound_transport_path(outbound), &host)?;
        let request = write_vmess_tcp_request(&mut websocket, outbound, target)?;
        websocket.flush()?;
        websocket.get_mut().sock.set_nonblocking(true)?;
        return local_bridge_for_vmess(websocket, request);
    }

    let remote = connect_target(server, timeout)?;
    remote.set_read_timeout(Some(timeout))?;
    remote.set_write_timeout(Some(timeout))?;
    let host = outbound_transport_host(outbound, server);
    let mut websocket = connect_websocket_client(remote, outbound_transport_path(outbound), &host)?;
    let request = write_vmess_tcp_request(&mut websocket, outbound, target)?;
    websocket.flush()?;
    websocket.get_mut().set_nonblocking(true)?;
    local_bridge_for_vmess(websocket, request)
}

fn connect_vmess_tls_tcp_outbound(
    outbound: &OutboundConfig,
    server: &SocksTarget,
    target: &SocksTarget,
    timeout: Duration,
) -> io::Result<TcpStream> {
    let mut tls_stream = connect_vmess_tls_stream(outbound, server, timeout)?;
    let request = write_vmess_tcp_request(&mut tls_stream, outbound, target)?;
    tls_stream.flush()?;
    tls_stream.sock.set_nonblocking(true)?;
    local_bridge_for_vmess(tls_stream, request)
}

pub(crate) fn send_vmess_udp_outbound(
    outbound: &OutboundConfig,
    target: &SocksTarget,
    payload: &[u8],
    timeout: Duration,
) -> io::Result<(SocketAddr, Vec<u8>)> {
    let server = vmess_outbound_server(outbound)?;
    let network = outbound_transport_network(outbound).to_ascii_lowercase();
    if network == "ws" {
        if outbound.tls.is_some() {
            let tls_stream = connect_vmess_tls_stream(outbound, &server, timeout)?;
            let host = outbound_transport_host(outbound, &server);
            let mut websocket =
                connect_websocket_client(tls_stream, outbound_transport_path(outbound), &host)?;
            return send_vmess_udp_over_stream(&mut websocket, outbound, target, payload, timeout);
        }
        let remote = connect_target(&server, timeout)?;
        remote.set_read_timeout(Some(timeout))?;
        remote.set_write_timeout(Some(timeout))?;
        let host = outbound_transport_host(outbound, &server);
        let mut websocket =
            connect_websocket_client(remote, outbound_transport_path(outbound), &host)?;
        return send_vmess_udp_over_stream(&mut websocket, outbound, target, payload, timeout);
    }
    if network == "httpupgrade" {
        if outbound.tls.is_some() {
            let tls_stream = connect_vmess_tls_stream(outbound, &server, timeout)?;
            let host = outbound_transport_host(outbound, &server);
            let mut stream =
                connect_httpupgrade_client(tls_stream, outbound_transport_path(outbound), &host)?;
            return send_vmess_udp_over_stream(&mut stream, outbound, target, payload, timeout);
        }
        let remote = connect_target(&server, timeout)?;
        remote.set_read_timeout(Some(timeout))?;
        remote.set_write_timeout(Some(timeout))?;
        let host = outbound_transport_host(outbound, &server);
        let mut stream =
            connect_httpupgrade_client(remote, outbound_transport_path(outbound), &host)?;
        return send_vmess_udp_over_stream(&mut stream, outbound, target, payload, timeout);
    }
    if network == "grpc" {
        let host = outbound_transport_host(outbound, &server);
        let mut grpc = connect_grpc_client(
            &server,
            timeout,
            outbound.tls.as_ref(),
            outbound_transport_service_name(outbound),
            &host,
        )?;
        return send_vmess_udp_over_stream(&mut grpc, outbound, target, payload, timeout);
    }
    if matches!(network.as_str(), "h2" | "http") {
        let host = outbound_transport_host(outbound, &server);
        let mut h2 = connect_http2_client(
            &server,
            timeout,
            outbound.tls.as_ref(),
            outbound_transport_path(outbound),
            &host,
            outbound_transport_method(outbound),
            outbound_transport_headers(outbound),
        )?;
        return send_vmess_udp_over_stream(&mut h2, outbound, target, payload, timeout);
    }
    if network == "quic" {
        let mut quic = connect_quic_client_stream(
            &server,
            timeout,
            outbound.tls.as_ref(),
            outbound.transport.as_ref(),
        )?;
        return send_vmess_udp_over_stream(&mut quic, outbound, target, payload, timeout);
    }
    if network != "tcp" {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("vmess outbound transport {network} is not supported yet"),
        ));
    }
    if outbound.tls.is_some() {
        let mut tls_stream = connect_vmess_tls_stream(outbound, &server, timeout)?;
        return send_vmess_udp_over_stream(&mut tls_stream, outbound, target, payload, timeout);
    }
    let mut stream = connect_target(&server, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    send_vmess_udp_over_stream(&mut stream, outbound, target, payload, timeout)
}

fn send_vmess_udp_over_stream<S: Read + Write>(
    stream: &mut S,
    outbound: &OutboundConfig,
    target: &SocksTarget,
    payload: &[u8],
    timeout: Duration,
) -> io::Result<(SocketAddr, Vec<u8>)> {
    let request = write_vmess_request(stream, outbound, target, VmessCommand::Udp)?;
    stream.flush()?;
    read_vmess_response_header(stream, &request)?;
    let mut request_body = VmessBodyEncoder::new_with_length_seed(
        request.request_body_key,
        request.request_body_iv,
        request.request_body_key,
        request.request_body_iv,
        request.options,
        request.security,
    );
    request_body.write_packet(stream, payload)?;
    stream.flush()?;
    let mut response_body = VmessBodyDecoder::new_with_length_seed(
        request.response_body_key,
        request.response_body_iv,
        request.request_body_key,
        request.request_body_iv,
        request.options,
        request.security,
    );
    let response = response_body.read_packet(stream)?.ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "vmess udp outbound returned no response packet",
        )
    })?;
    let _ = request_body.finish(stream);
    let source = resolve_udp_target(target)
        .or_else(|_| crate::dns::resolve_socket_addr(&target.host, target.port, timeout))?;
    Ok((source, response))
}

fn connect_vmess_tls_stream(
    outbound: &OutboundConfig,
    server: &SocksTarget,
    timeout: Duration,
) -> io::Result<StreamOwned<ClientConnection, TcpStream>> {
    let remote = connect_target(server, timeout)?;
    remote.set_read_timeout(Some(timeout))?;
    remote.set_write_timeout(Some(timeout))?;
    let tls_config = outbound
        .tls
        .as_ref()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "outbound tls is required"))?;
    let server_name = vmess_tls_server_name(tls_config, server)?;
    let connection = ClientConnection::new(vmess_tls_client_config(tls_config), server_name)
        .map_err(tls_error)?;
    let mut tls_stream = StreamOwned::new(connection, remote);
    while tls_stream.conn.is_handshaking() {
        tls_stream
            .conn
            .complete_io(&mut tls_stream.sock)
            .map_err(tls_error)?;
    }
    Ok(tls_stream)
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

fn vmess_tls_client_config(tls: &OutboundTlsConfig) -> Arc<ClientConfig> {
    let mut config = if tls.allow_insecure {
        ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
            .with_no_client_auth()
    } else {
        let roots = RootCertStore::from_iter(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth()
    };
    config.alpn_protocols = tls
        .alpn
        .iter()
        .map(|value| value.as_bytes().to_vec())
        .collect();
    Arc::new(config)
}

fn vmess_tls_server_name(
    tls: &OutboundTlsConfig,
    server: &SocksTarget,
) -> io::Result<ServerName<'static>> {
    let value = tls.server_name.trim().trim_matches(['[', ']']).to_string();
    let value = if value.is_empty() {
        server.host.trim().trim_matches(['[', ']']).to_string()
    } else {
        value
    };
    ServerName::try_from(value).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "vmess tls server_name is invalid",
        )
    })
}

fn vmess_outbound_server(outbound: &OutboundConfig) -> io::Result<SocksTarget> {
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

fn vmess_outbound_user_id(outbound: &OutboundConfig) -> io::Result<[u8; 16]> {
    let value = outbound
        .username
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "outbound username must be a vmess uuid",
            )
        })?;
    parse_uuid_bytes(value)
}

fn vmess_outbound_security(outbound: &OutboundConfig) -> io::Result<VmessSecurity> {
    let value = outbound
        .method
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .unwrap_or("auto")
        .to_ascii_lowercase();
    match value.as_str() {
        "auto" | "aes-128-gcm" | "aes128-gcm" => Ok(VmessSecurity::Aes128Gcm),
        "chacha20-poly1305" | "chacha20-ietf-poly1305" => Ok(VmessSecurity::ChaCha20Poly1305),
        "none" => Ok(VmessSecurity::None),
        _ => Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("unsupported vmess outbound security {value}"),
        )),
    }
}

fn outbound_transport_path(outbound: &OutboundConfig) -> Option<&str> {
    outbound
        .transport
        .as_ref()
        .and_then(|transport| transport.path.as_deref())
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn outbound_transport_host(outbound: &OutboundConfig, server: &SocksTarget) -> String {
    outbound
        .transport
        .as_ref()
        .and_then(|transport| transport.host.as_deref())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .or_else(|| outbound.tls.as_ref().map(|tls| tls.server_name.trim()))
        .filter(|value| !value.is_empty())
        .unwrap_or(&server.host)
        .trim_matches(['[', ']'])
        .to_string()
}

fn outbound_transport_service_name(outbound: &OutboundConfig) -> Option<&str> {
    outbound
        .transport
        .as_ref()
        .and_then(|transport| transport.service_name.as_deref())
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn outbound_transport_method(outbound: &OutboundConfig) -> Option<&str> {
    outbound
        .transport
        .as_ref()
        .and_then(|transport| transport.method.as_deref())
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

fn outbound_transport_headers(
    outbound: &OutboundConfig,
) -> Option<&std::collections::BTreeMap<String, String>> {
    outbound
        .transport
        .as_ref()
        .map(|transport| &transport.headers)
        .filter(|headers| !headers.is_empty())
}

fn write_vmess_tcp_request<W: Write>(
    writer: &mut W,
    outbound: &OutboundConfig,
    target: &SocksTarget,
) -> io::Result<VmessRequest> {
    write_vmess_request(writer, outbound, target, VmessCommand::Tcp)
}

fn write_vmess_request<W: Write>(
    writer: &mut W,
    outbound: &OutboundConfig,
    target: &SocksTarget,
    command: VmessCommand,
) -> io::Result<VmessRequest> {
    let uuid = vmess_outbound_user_id(outbound)?;
    let cmd_key = vmess_cmd_key(&uuid);
    let alter_id = outbound.alter_id.unwrap_or(0);
    let header_mode = if alter_id == 0 {
        VmessHeaderMode::Aead
    } else {
        VmessHeaderMode::Legacy
    };
    let request_body_key = random_array::<16>()?;
    let request_body_iv = random_array::<16>()?;
    let response_header = random_array::<1>()?[0];
    let options = OPTION_CHUNK_STREAM | OPTION_CHUNK_MASKING | OPTION_GLOBAL_PADDING;
    let security = vmess_outbound_security(outbound)?;
    let mut header = Vec::new();
    header.push(VERSION);
    header.extend_from_slice(&request_body_iv);
    header.extend_from_slice(&request_body_key);
    header.push(response_header);
    header.push(options);
    header.push(vmess_security_byte(security));
    header.push(0);
    header.push(match command {
        VmessCommand::Tcp => COMMAND_TCP,
        VmessCommand::Udp => COMMAND_UDP,
    });
    write_vmess_target_header(&mut header, target)?;
    let checksum = fnv1a(&header);
    header.extend_from_slice(&checksum.to_be_bytes());

    match header_mode {
        VmessHeaderMode::Aead => {
            let auth_id = create_auth_id(&cmd_key, unix_timestamp(), random_array::<4>()?);
            let nonce = random_array::<8>()?;
            writer.write_all(&seal_request_header(&cmd_key, &auth_id, &nonce, &header)?)?;
        }
        VmessHeaderMode::Legacy => {
            let alter_ids = vmess_alter_ids(&uuid, alter_id);
            let auth_uuid = alter_ids
                .get(random_index(alter_ids.len())?)
                .ok_or_else(|| {
                    io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "vmess alter_id requires at least one generated id",
                    )
                })?;
            writer.write_all(&seal_legacy_request_header(
                &cmd_key,
                auth_uuid,
                unix_timestamp(),
                &header,
            )?)?;
        }
    }

    let response_body_key = match header_mode {
        VmessHeaderMode::Aead => first_16_sha256(&request_body_key),
        VmessHeaderMode::Legacy => md5_16(&request_body_key),
    };
    let response_body_iv = match header_mode {
        VmessHeaderMode::Aead => first_16_sha256(&request_body_iv),
        VmessHeaderMode::Legacy => md5_16(&request_body_iv),
    };
    Ok(VmessRequest {
        command,
        user_key: format_uuid_compact(&uuid),
        user_uuid: outbound
            .username
            .as_deref()
            .map(str::trim)
            .unwrap_or_default()
            .to_string(),
        user_id: None,
        target: target.clone(),
        client_ip: None,
        request_body_key,
        request_body_iv,
        response_body_key,
        response_body_iv,
        response_header,
        options,
        security,
        header_mode,
    })
}

fn write_vmess_target_header(output: &mut Vec<u8>, target: &SocksTarget) -> io::Result<()> {
    output.extend_from_slice(&target.port.to_be_bytes());
    if let Ok(ip) = target.host.parse::<Ipv4Addr>() {
        output.push(ATYP_IPV4);
        output.extend_from_slice(&ip.octets());
    } else if let Ok(ip) = target.host.parse::<Ipv6Addr>() {
        output.push(ATYP_IPV6);
        output.extend_from_slice(&ip.octets());
    } else {
        let host = target.host.trim().trim_matches(['[', ']']);
        if host.is_empty() || host.len() > u8::MAX as usize {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "vmess target host is invalid",
            ));
        }
        output.push(ATYP_DOMAIN);
        output.push(host.len() as u8);
        output.extend_from_slice(host.as_bytes());
    }
    Ok(())
}

fn vmess_security_byte(security: VmessSecurity) -> u8 {
    match security {
        VmessSecurity::Aes128Gcm => SECURITY_AES128_GCM,
        VmessSecurity::ChaCha20Poly1305 => SECURITY_CHACHA20_POLY1305,
        VmessSecurity::None => SECURITY_NONE,
    }
}

fn seal_request_header(
    cmd_key: &[u8; 16],
    auth_id: &[u8; 16],
    nonce: &[u8; 8],
    header: &[u8],
) -> io::Result<Vec<u8>> {
    let len_key = kdf16(cmd_key, &[HEADER_LENGTH_KEY, auth_id, nonce.as_slice()]);
    let len_nonce = first_12(&kdf(
        cmd_key,
        &[HEADER_LENGTH_NONCE, auth_id, nonce.as_slice()],
    ));
    let payload_key = kdf16(cmd_key, &[HEADER_PAYLOAD_KEY, auth_id, nonce.as_slice()]);
    let payload_nonce = first_12(&kdf(
        cmd_key,
        &[HEADER_PAYLOAD_NONCE, auth_id, nonce.as_slice()],
    ));
    let mut output = Vec::with_capacity(42 + header.len());
    output.extend_from_slice(auth_id);
    output.extend_from_slice(&aes_gcm_seal(
        &len_key,
        &len_nonce,
        &(header.len() as u16).to_be_bytes(),
        auth_id,
    )?);
    output.extend_from_slice(nonce);
    output.extend_from_slice(&aes_gcm_seal(
        &payload_key,
        &payload_nonce,
        header,
        auth_id,
    )?);
    Ok(output)
}

fn read_vmess_response_header<R: Read>(reader: &mut R, request: &VmessRequest) -> io::Result<()> {
    if request.header_mode == VmessHeaderMode::Legacy {
        return read_legacy_vmess_response_header(reader, request);
    }

    let mut len_cipher = [0u8; 18];
    read_exact_wait(reader, &mut len_cipher)?;
    let len_key = kdf16(&request.response_body_key, &[RESPONSE_HEADER_LENGTH_KEY]);
    let len_nonce = first_12(&kdf(
        &request.response_body_iv,
        &[RESPONSE_HEADER_LENGTH_IV],
    ));
    let len = aes_gcm_open(&len_key, &len_nonce, &len_cipher, &[])?;
    if len.len() != 2 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid vmess response header length",
        ));
    }
    let len = u16::from_be_bytes([len[0], len[1]]) as usize;
    let mut payload_cipher = vec![0u8; len + 16];
    read_exact_wait(reader, &mut payload_cipher)?;
    let payload_key = kdf16(&request.response_body_key, &[RESPONSE_HEADER_PAYLOAD_KEY]);
    let payload_nonce = first_12(&kdf(
        &request.response_body_iv,
        &[RESPONSE_HEADER_PAYLOAD_IV],
    ));
    let payload = aes_gcm_open(&payload_key, &payload_nonce, &payload_cipher, &[])?;
    if payload.len() < 4 || payload[0] != request.response_header {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid vmess response header",
        ));
    }
    Ok(())
}

fn seal_legacy_request_header(
    primary_cmd_key: &[u8; 16],
    auth_uuid: &[u8; 16],
    timestamp: i64,
    header: &[u8],
) -> io::Result<Vec<u8>> {
    let mut output = Vec::with_capacity(16 + header.len());
    output.extend_from_slice(&vmess_legacy_auth_hash(auth_uuid, timestamp)?);
    let mut encrypted_header = header.to_vec();
    let iv = legacy_header_iv(timestamp);
    Aes128Cfb::new(primary_cmd_key, &iv)?.encrypt(&mut encrypted_header);
    output.extend_from_slice(&encrypted_header);
    Ok(output)
}

fn read_legacy_vmess_response_header<R: Read>(
    reader: &mut R,
    request: &VmessRequest,
) -> io::Result<()> {
    let mut cipher = Aes128Cfb::new(&request.response_body_key, &request.response_body_iv)?;
    let mut header = [0u8; 4];
    read_exact_wait(reader, &mut header)?;
    cipher.decrypt(&mut header);
    if header[0] != request.response_header {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid vmess legacy response header",
        ));
    }
    let command_len = if header[2] == 0 {
        0
    } else {
        usize::from(header[3])
    };
    if command_len > 0 {
        let mut command = vec![0u8; command_len];
        read_exact_wait(reader, &mut command)?;
        cipher.decrypt(&mut command);
    }
    Ok(())
}

fn read_exact_wait<R: Read>(reader: &mut R, mut output: &mut [u8]) -> io::Result<()> {
    while !output.is_empty() {
        match reader.read(output) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "truncated vmess response",
                ));
            }
            Ok(read) => {
                let (_, remaining) = output.split_at_mut(read);
                output = remaining;
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(1));
            }
            Err(error) => return Err(error),
        }
    }
    Ok(())
}

fn local_bridge_for_vmess<S>(remote: S, request: VmessRequest) -> io::Result<TcpStream>
where
    S: Read + Write + Send + 'static,
{
    let local_listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
    let local_addr = local_listener.local_addr()?;
    let local_client = TcpStream::connect(local_addr)?;
    let (local_plain, _) = local_listener.accept()?;

    let _ = spawn_native_blocking_relay(move || {
        let _ = relay_plain_to_vmess(local_plain, remote, request);
    })?;

    Ok(local_client)
}

fn local_bridge_for_vmess_tcp(remote: TcpStream, request: VmessRequest) -> io::Result<TcpStream> {
    let local_listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
    let local_addr = local_listener.local_addr()?;
    let local_client = TcpStream::connect(local_addr)?;
    local_client.set_nodelay(true)?;
    let (local_plain, _) = local_listener.accept()?;
    local_plain.set_nodelay(true)?;

    let plain_reader = local_plain.try_clone()?;
    let plain_writer = local_plain;
    let remote_writer = remote.try_clone()?;
    let remote_reader = remote;
    let _ = spawn_native_blocking_relay(move || {
        let _ = relay_plain_to_vmess_tcp(
            plain_reader,
            plain_writer,
            remote_reader,
            remote_writer,
            request,
        );
    })?;

    Ok(local_client)
}

fn relay_plain_to_vmess_tcp(
    mut plain_reader: TcpStream,
    mut plain_writer: TcpStream,
    mut remote_reader: TcpStream,
    mut remote_writer: TcpStream,
    request: VmessRequest,
) -> io::Result<()> {
    let upload_request = request.clone();
    let upload_task = spawn_native_blocking_relay(move || {
        let mut request_body = VmessBodyEncoder::new_with_length_seed(
            upload_request.request_body_key,
            upload_request.request_body_iv,
            upload_request.request_body_key,
            upload_request.request_body_iv,
            upload_request.options,
            upload_request.security,
        );
        let mut buffer = [0u8; VMESS_RELAY_BUFFER_SIZE];
        loop {
            match plain_reader.read(&mut buffer) {
                Ok(0) => break,
                Ok(read) => request_body.write_plain(&mut remote_writer, &buffer[..read])?,
                Err(error) => return Err(error),
            };
        }
        let _ = request_body.finish(&mut remote_writer);
        let _ = remote_writer.shutdown(Shutdown::Write);
        Ok::<(), io::Error>(())
    })?;

    let mut response_body = VmessBodyDecoder::new_with_length_seed(
        request.response_body_key,
        request.response_body_iv,
        request.request_body_key,
        request.request_body_iv,
        request.options,
        request.security,
    );
    read_vmess_response_header(&mut remote_reader, &request)?;
    let mut buffer = [0u8; VMESS_RELAY_BUFFER_SIZE];
    loop {
        match response_body.read_plain(&mut remote_reader, &mut buffer) {
            Ok(0) => break,
            Ok(read) => write_all_wait(&mut plain_writer, &buffer[..read])?,
            Err(error) => return Err(error),
        }
    }
    let _ = plain_writer.shutdown(Shutdown::Write);
    let _ = join_native_blocking_relay(upload_task, "vmess tcp bridge upload panicked")?;
    let _ = plain_writer.shutdown(Shutdown::Both);
    Ok(())
}

fn relay_plain_to_vmess<S>(
    mut plain: TcpStream,
    mut remote: S,
    request: VmessRequest,
) -> io::Result<()>
where
    S: Read + Write,
{
    plain.set_nonblocking(true)?;
    let mut request_body = VmessBodyEncoder::new_with_length_seed(
        request.request_body_key,
        request.request_body_iv,
        request.request_body_key,
        request.request_body_iv,
        request.options,
        request.security,
    );
    let mut response_body = VmessBodyDecoder::new_with_length_seed(
        request.response_body_key,
        request.response_body_iv,
        request.request_body_key,
        request.request_body_iv,
        request.options,
        request.security,
    );
    let mut upload_done = false;
    let mut download_done = false;
    let mut upload_started = false;
    let mut response_header_read = false;
    let mut upload_buffer = [0u8; VMESS_RELAY_BUFFER_SIZE];
    let mut download_buffer = [0u8; VMESS_RELAY_BUFFER_SIZE];

    while !upload_done || !download_done {
        let mut progressed = false;

        if !upload_done {
            match plain.read(&mut upload_buffer) {
                Ok(0) => {
                    upload_done = true;
                    let _ = request_body.finish(&mut remote);
                    progressed = true;
                }
                Ok(read) => {
                    request_body.write_plain(&mut remote, &upload_buffer[..read])?;
                    upload_started = true;
                    progressed = true;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(_) => {
                    upload_done = true;
                    let _ = request_body.finish(&mut remote);
                    progressed = true;
                }
            }
        }

        if !download_done {
            if !response_header_read {
                if !upload_started && !upload_done {
                    if !progressed {
                        thread::sleep(Duration::from_millis(1));
                    }
                    continue;
                }
                read_vmess_response_header(&mut remote, &request)?;
                response_header_read = true;
                progressed = true;
            }
            match response_body.read_plain(&mut remote, &mut download_buffer) {
                Ok(0) => {
                    download_done = true;
                    let _ = plain.shutdown(Shutdown::Write);
                    progressed = true;
                }
                Ok(read) => {
                    write_all_wait(&mut plain, &download_buffer[..read])?;
                    progressed = true;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(_) => {
                    download_done = true;
                    let _ = plain.shutdown(Shutdown::Write);
                    progressed = true;
                }
            }
        }

        if !progressed {
            thread::sleep(Duration::from_millis(1));
        }
    }

    let _ = request_body.finish(&mut remote);
    let _ = plain.shutdown(Shutdown::Both);
    Ok(())
}

fn random_array<const N: usize>() -> io::Result<[u8; N]> {
    let mut output = [0u8; N];
    getrandom::getrandom(&mut output)
        .map_err(|error| io::Error::new(io::ErrorKind::Other, error.to_string()))?;
    Ok(output)
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

fn tls_error(error: impl std::fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, error.to_string())
}

#[derive(Debug)]
struct NoCertificateVerification;

impl ServerCertVerifier for NoCertificateVerification {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::ED25519,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::RSA_PSS_SHA384,
            SignatureScheme::RSA_PSS_SHA512,
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
        ]
    }
}

fn create_auth_id(cmd_key: &[u8; 16], timestamp: i64, random: [u8; 4]) -> [u8; 16] {
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

fn vmess_alter_ids(primary: &[u8; 16], alter_id_count: u16) -> Vec<[u8; 16]> {
    let mut ids = Vec::with_capacity(alter_id_count as usize);
    let mut previous = *primary;
    for _ in 0..alter_id_count {
        let next = next_vmess_alter_id(&previous);
        ids.push(next);
        previous = next;
    }
    ids
}

fn next_vmess_alter_id(previous: &[u8; 16]) -> [u8; 16] {
    let mut input = Vec::with_capacity(16 + ALTER_ID_SALT.len() + ALTER_ID_RETRY_SALT.len());
    input.extend_from_slice(previous);
    input.extend_from_slice(ALTER_ID_SALT);
    loop {
        let next: [u8; 16] = Md5::digest(&input).into();
        if &next != previous {
            return next;
        }
        input.extend_from_slice(ALTER_ID_RETRY_SALT);
    }
}

fn random_index(len: usize) -> io::Result<usize> {
    if len == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "random index requires non-empty input",
        ));
    }
    let bytes = random_array::<8>()?;
    Ok((u64::from_be_bytes(bytes) as usize) % len)
}

fn vmess_legacy_auth_hash(auth_uuid: &[u8; 16], timestamp: i64) -> io::Result<[u8; 16]> {
    let mut mac = <Hmac<Md5> as Mac>::new_from_slice(auth_uuid)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid vmess legacy id"))?;
    Mac::update(&mut mac, &(timestamp as u64).to_be_bytes());
    Ok(mac.finalize().into_bytes().into())
}

fn legacy_header_iv(timestamp: i64) -> [u8; 16] {
    let bytes = (timestamp as u64).to_be_bytes();
    let mut input = [0u8; 32];
    for chunk in input.chunks_exact_mut(8) {
        chunk.copy_from_slice(&bytes);
    }
    Md5::digest(input).into()
}

fn md5_16(bytes: &[u8]) -> [u8; 16] {
    Md5::digest(bytes).into()
}

impl Aes128Cfb {
    fn new(key: &[u8; 16], iv: &[u8; 16]) -> io::Result<Self> {
        let cipher = Aes128::new_from_slice(key)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid aes-128-cfb key"))?;
        Ok(Self {
            cipher,
            feedback: *iv,
            stream: [0u8; 16],
            offset: 0,
        })
    }

    fn encrypt(&mut self, bytes: &mut [u8]) {
        self.apply(bytes, false);
    }

    fn decrypt(&mut self, bytes: &mut [u8]) {
        self.apply(bytes, true);
    }

    fn apply(&mut self, bytes: &mut [u8], decrypt: bool) {
        for byte in bytes {
            if self.offset == 0 {
                let mut block = aes::cipher::Block::<Aes128>::clone_from_slice(&self.feedback);
                self.cipher.encrypt_block(&mut block);
                self.stream.copy_from_slice(block.as_slice());
            }
            let input = *byte;
            *byte ^= self.stream[self.offset];
            self.feedback[self.offset] = if decrypt { input } else { *byte };
            self.offset = (self.offset + 1) % self.feedback.len();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
    use std::path::PathBuf;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    };
    use std::thread;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use rustls::pki_types::{CertificateDer, ServerName};
    use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

    use super::{
        connect_vmess_tcp_outbound, create_auth_id, fnv1a, kdf, parse_uuid_bytes,
        send_vmess_udp_outbound, vmess_cmd_key, vmess_user_key, write_response_header,
        VmessBodyDecoder, VmessBodyEncoder, VmessBodyReader, VmessBodyWriter, VmessCommand,
        VmessHeaderMode, VmessRequest, VmessSecurity, VmessServer, VmessServerConfig, ATYP_IPV4,
        COMMAND_TCP, COMMAND_UDP, OPTION_AUTHENTICATED_LENGTH, OPTION_CHUNK_MASKING,
        OPTION_CHUNK_STREAM, OPTION_GLOBAL_PADDING, SECURITY_AES128_GCM, VERSION,
    };
    use crate::config::{OutboundConfig, OutboundTransportConfig};
    use crate::grpc::{run_grpc_listener, GrpcStreamHandler};
    use crate::http2::{run_http2_listener, Http2StreamHandler};
    use crate::httpupgrade::accept_httpupgrade;
    use crate::socks5::SocksTarget;
    use crate::tls::TlsAcceptor;
    use crate::user::{CoreUser, CoreUserDelta};

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

    fn user_b() -> CoreUser {
        CoreUser {
            id: 2,
            uuid: "22222222-2222-2222-2222-222222222222".to_string(),
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

    fn echo_server() -> (SocketAddr, thread::JoinHandle<()>) {
        let echo = TcpListener::bind("127.0.0.1:0").expect("echo bind");
        let echo_addr = echo.local_addr().expect("echo addr");
        let echo_thread = thread::spawn(move || {
            let (mut stream, _) = echo.accept().expect("echo accept");
            let mut bytes = [0u8; 4];
            stream.read_exact(&mut bytes).expect("echo read");
            assert_eq!(&bytes, b"ping");
            stream.write_all(b"pong").expect("echo write");
        });
        (echo_addr, echo_thread)
    }

    fn vmess_outbound(
        proxy_addr: SocketAddr,
        transport: Option<OutboundTransportConfig>,
    ) -> OutboundConfig {
        OutboundConfig {
            tag: "vmess-out".to_string(),
            protocol: "vmess".to_string(),
            method: Some("aes-128-gcm".to_string()),
            alter_id: None,
            address: Some(proxy_addr.ip().to_string()),
            port: Some(proxy_addr.port()),
            username: Some("11111111-1111-1111-1111-111111111111".to_string()),
            password: None,
            tls: None,
            transport,
        }
    }

    fn assert_outbound_reaches_echo(mut stream: TcpStream, echo_thread: thread::JoinHandle<()>) {
        stream.write_all(b"ping").expect("write payload");
        let mut response = [0u8; 4];
        stream.read_exact(&mut response).expect("read response");
        assert_eq!(&response, b"pong");
        drop(stream);
        echo_thread.join().expect("echo thread");
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
        vmess_request_with_command(target, payload, options, COMMAND_TCP)
    }

    fn vmess_request_with_command(
        target: std::net::SocketAddr,
        payload: &[u8],
        options: u8,
        command: u8,
    ) -> (Vec<u8>, VmessRequest) {
        vmess_request_for_user_with_command(&user(), target, payload, options, command)
    }

    fn vmess_request_for_user_with_command(
        user: &CoreUser,
        target: std::net::SocketAddr,
        payload: &[u8],
        options: u8,
        command: u8,
    ) -> (Vec<u8>, VmessRequest) {
        vmess_request_for_user_with_auth_random(
            user,
            target,
            payload,
            options,
            command,
            [1, 2, 3, 4],
        )
    }

    fn vmess_request_for_user_with_auth_random(
        user: &CoreUser,
        target: std::net::SocketAddr,
        payload: &[u8],
        options: u8,
        command: u8,
        auth_random: [u8; 4],
    ) -> (Vec<u8>, VmessRequest) {
        let (mut output, request) = vmess_request_header_for_user_with_auth_random(
            user,
            target,
            options,
            command,
            auth_random,
        );
        let mut body = VmessBodyWriter::new(
            Vec::new(),
            request.request_body_key,
            request.request_body_iv,
            options,
            request.security,
        )
        .expect("body writer");
        body.write_all(payload).expect("body payload");
        body.finish().expect("body finish");
        output.extend_from_slice(&body.into_inner());
        (output, request)
    }

    fn vmess_request_header_for_user_with_auth_random(
        user: &CoreUser,
        target: std::net::SocketAddr,
        options: u8,
        command: u8,
        auth_random: [u8; 4],
    ) -> (Vec<u8>, VmessRequest) {
        let uuid = parse_uuid_bytes(&user.uuid).expect("uuid");
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
        header.push(command);
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

        let auth_id = create_auth_id(&cmd_key, super::unix_timestamp(), auth_random);
        let nonce = [9u8; 8];
        let encrypted_header = seal_header(&cmd_key, &auth_id, &nonce, &header);

        let response_body_key = super::first_16_sha256(&request_body_key);
        let response_body_iv = super::first_16_sha256(&request_body_iv);
        let request = VmessRequest {
            command: if command == COMMAND_UDP {
                VmessCommand::Udp
            } else {
                VmessCommand::Tcp
            },
            user_key: super::format_uuid_compact(&uuid),
            user_uuid: user.uuid.clone(),
            user_id: Some(user.id),
            target: SocksTarget {
                host: target.ip().to_string(),
                port: target.port(),
            },
            client_ip: None,
            request_body_key,
            request_body_iv,
            response_body_key,
            response_body_iv,
            response_header,
            options,
            security,
            header_mode: VmessHeaderMode::Aead,
        };

        (encrypted_header, request)
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
        assert!(try_decode_response_header(stream, request));
    }

    fn try_decode_response_header<R: Read>(stream: &mut R, request: &VmessRequest) -> bool {
        let mut len_cipher = [0u8; 18];
        if stream.read_exact(&mut len_cipher).is_err() {
            return false;
        }
        let len_key = super::kdf16(
            &request.response_body_key,
            &[super::RESPONSE_HEADER_LENGTH_KEY],
        );
        let len_nonce = super::first_12(&kdf(
            &request.response_body_iv,
            &[super::RESPONSE_HEADER_LENGTH_IV],
        ));
        let Ok(len) = super::aes_gcm_open(&len_key, &len_nonce, &len_cipher, &[]) else {
            return false;
        };
        let len = u16::from_be_bytes([len[0], len[1]]) as usize;
        let mut payload_cipher = vec![0u8; len + 16];
        if stream.read_exact(&mut payload_cipher).is_err() {
            return false;
        }
        let payload_key = super::kdf16(
            &request.response_body_key,
            &[super::RESPONSE_HEADER_PAYLOAD_KEY],
        );
        let payload_nonce = super::first_12(&kdf(
            &request.response_body_iv,
            &[super::RESPONSE_HEADER_PAYLOAD_IV],
        ));
        let Ok(payload) = super::aes_gcm_open(&payload_key, &payload_nonce, &payload_cipher, &[])
        else {
            return false;
        };
        payload == [request.response_header, 0, 0, 0]
    }

    fn vmess_tcp_probe(
        vmess_addr: SocketAddr,
        user: &CoreUser,
        echo_addr: SocketAddr,
        auth_random: [u8; 4],
    ) -> bool {
        let (request_bytes, request) = vmess_request_for_user_with_auth_random(
            user,
            echo_addr,
            b"x",
            OPTION_CHUNK_STREAM | OPTION_CHUNK_MASKING | OPTION_GLOBAL_PADDING,
            COMMAND_TCP,
            auth_random,
        );
        let mut client = match TcpStream::connect(vmess_addr) {
            Ok(client) => client,
            Err(_) => return false,
        };
        let _ = client.set_read_timeout(Some(Duration::from_secs(3)));
        let _ = client.set_write_timeout(Some(Duration::from_secs(3)));
        if client.write_all(&request_bytes).is_err() {
            return false;
        }
        if !try_decode_response_header(&mut client, &request) {
            return false;
        }
        let mut body = match VmessBodyReader::new(
            client,
            request.response_body_key,
            request.response_body_iv,
            request.options,
            request.security,
        ) {
            Ok(body) => body,
            Err(_) => return false,
        };
        let mut echoed = [0u8; 1];
        body.read_exact(&mut echoed).is_ok() && echoed == *b"x"
    }

    fn read_legacy_vmess_request_header<R: Read>(
        stream: &mut R,
        primary_uuid: &str,
        alter_id_count: u16,
    ) -> VmessRequest {
        let mut auth = [0u8; 16];
        stream.read_exact(&mut auth).expect("legacy auth");
        let uuid = parse_uuid_bytes(primary_uuid).expect("uuid");
        let alter_ids = super::vmess_alter_ids(&uuid, alter_id_count);
        let now = super::unix_timestamp();
        let timestamp = (-120..=120)
            .flat_map(|delta| now.checked_add(delta).into_iter())
            .find(|timestamp| {
                alter_ids.iter().any(|alter_id| {
                    super::vmess_legacy_auth_hash(alter_id, *timestamp).expect("auth hash") == auth
                })
            })
            .expect("legacy auth should match an alter id");

        let cmd_key = vmess_cmd_key(&uuid);
        let mut cfb =
            super::Aes128Cfb::new(&cmd_key, &super::legacy_header_iv(timestamp)).expect("cfb");
        let mut header = vec![0u8; 49];
        stream
            .read_exact(&mut header)
            .expect("legacy encrypted request header");
        cfb.decrypt(&mut header);
        let parsed = super::parse_request_header(&header).expect("legacy header");
        assert_eq!(
            parsed.security,
            VmessSecurity::Aes128Gcm,
            "legacy auth can still use AEAD body security"
        );

        VmessRequest {
            command: parsed.command,
            user_key: super::format_uuid_compact(&uuid),
            user_uuid: primary_uuid.to_string(),
            user_id: Some(1),
            target: parsed.target,
            client_ip: None,
            request_body_key: parsed.request_body_key,
            request_body_iv: parsed.request_body_iv,
            response_body_key: super::md5_16(&parsed.request_body_key),
            response_body_iv: super::md5_16(&parsed.request_body_iv),
            response_header: parsed.response_header,
            options: parsed.options,
            security: parsed.security,
            header_mode: VmessHeaderMode::Legacy,
        }
    }

    fn write_legacy_vmess_response_header<W: Write>(writer: &mut W, request: &VmessRequest) {
        let mut header = [request.response_header, 0, 0, 0];
        super::Aes128Cfb::new(&request.response_body_key, &request.response_body_iv)
            .expect("cfb")
            .encrypt(&mut header);
        writer.write_all(&header).expect("legacy response header");
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
    fn replaces_users_without_rebuilding_vmess_server() {
        let target: std::net::SocketAddr = "127.0.0.1:443".parse().expect("addr");
        let server = server();

        server.replace_users(vec![user_b()]);

        let (old_input, _) = vmess_request(target, b"ping");
        let mut old_stream = std::io::Cursor::new(old_input);
        let error = server
            .read_request(&mut old_stream)
            .expect_err("old user should fail after replacement");
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);

        let next_user = user_b();
        let (new_input, _) = vmess_request_for_user_with_command(
            &next_user,
            target,
            b"ping",
            OPTION_CHUNK_STREAM | OPTION_CHUNK_MASKING | OPTION_GLOBAL_PADDING,
            COMMAND_TCP,
        );
        let mut new_stream = std::io::Cursor::new(new_input);
        let request = server
            .read_request(&mut new_stream)
            .expect("new user should authenticate");
        assert_eq!(request.user_uuid, next_user.uuid);
        assert_eq!(request.user_key, "22222222222222222222222222222222");
    }

    #[test]
    fn apply_user_delta_updates_vmess_users() {
        let server = server();
        let mut updated = user();
        updated.speed_limit = 678;
        updated.device_limit = 8;

        let result = server.apply_user_delta(&CoreUserDelta {
            added: vec![user_b()],
            updated: vec![updated.clone()],
            ..CoreUserDelta::default()
        });

        assert_eq!(result.added, 1);
        assert_eq!(result.updated, 1);
        assert_eq!(result.active_users, 2);
        let user = server
            .users
            .get(&vmess_user_key(&updated).expect("updated key"))
            .expect("updated vmess user should remain active");
        assert_eq!(user.speed_limit, 678);
        assert_eq!(user.device_limit, 8);
        assert!(server
            .users
            .get(&vmess_user_key(&user_b()).expect("new key"))
            .is_some());
        assert_eq!(
            server
                .auth_users
                .read()
                .expect("vmess auth users lock poisoned")
                .len(),
            2
        );

        let result = server.apply_user_delta(&CoreUserDelta {
            deleted: vec![updated.uuid.clone()],
            ..CoreUserDelta::default()
        });

        assert_eq!(result.deleted, 1);
        assert_eq!(result.active_users, 1);
        assert!(server
            .users
            .get(&vmess_user_key(&updated).expect("deleted key"))
            .is_none());
        assert_eq!(
            server
                .auth_users
                .read()
                .expect("vmess auth users lock poisoned")
                .len(),
            1
        );
    }

    #[test]
    fn apply_user_delta_changes_vmess_auth_without_rebinding_listener() {
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
        let listener = server.bind().expect("vmess bind");
        let vmess_addr = listener.local_addr().expect("vmess addr");
        let server_clone = server.clone();
        let server_thread = thread::spawn(move || {
            for _ in 0..3 {
                let (stream, _) = listener.accept().expect("vmess accept");
                let _ = server_clone.handle_tcp_client(stream);
            }
        });

        let original_user = user();
        let next_user = user_b();
        assert!(
            vmess_tcp_probe(vmess_addr, &original_user, echo_addr, [1, 2, 3, 4]),
            "original vmess user should authenticate before delta"
        );

        let result = server.apply_user_delta(&CoreUserDelta {
            added: vec![next_user.clone()],
            deleted: vec![original_user.uuid.clone()],
            ..CoreUserDelta::default()
        });

        assert_eq!(result.added, 1);
        assert_eq!(result.deleted, 1);
        assert_eq!(result.active_users, 1);
        assert!(
            !vmess_tcp_probe(vmess_addr, &original_user, echo_addr, [5, 6, 7, 8]),
            "deleted vmess user should fail new authentication after delta"
        );
        assert!(
            vmess_tcp_probe(vmess_addr, &next_user, echo_addr, [9, 10, 11, 12]),
            "added vmess user should authenticate on the same listener after delta"
        );

        server_thread.join().expect("server thread");
        echo_thread.join().expect("echo thread");
    }

    #[test]
    fn deleting_vmess_user_stops_existing_tcp_relay_on_next_payload_and_reports_tail() {
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
        let listener = server.bind().expect("vmess bind");
        let vmess_addr = listener.local_addr().expect("vmess addr");
        let server_clone = server.clone();
        let server_thread = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("vmess accept");
            server_clone.handle_tcp_client(stream)
        });

        let (header, request) = vmess_request_header_for_user_with_auth_random(
            &user(),
            echo_addr,
            OPTION_CHUNK_STREAM | OPTION_CHUNK_MASKING | OPTION_GLOBAL_PADDING,
            COMMAND_TCP,
            [7, 7, 7, 7],
        );
        let mut client = TcpStream::connect(vmess_addr).expect("client connect");
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .expect("client read timeout");
        client
            .set_write_timeout(Some(Duration::from_secs(1)))
            .expect("client write timeout");
        client.write_all(&header).expect("client request header");
        let mut request_body = VmessBodyWriter::new(
            client.try_clone().expect("client clone"),
            request.request_body_key,
            request.request_body_iv,
            request.options,
            request.security,
        )
        .expect("request body writer");
        request_body.write_all(b"x").expect("first payload");
        request_body.flush().expect("first flush");

        decode_response_header(&mut client, &request);
        let mut response_body = VmessBodyReader::new(
            client.try_clone().expect("client clone"),
            request.response_body_key,
            request.response_body_iv,
            request.options,
            request.security,
        )
        .expect("response body");
        let mut echoed = [0u8; 1];
        response_body.read_exact(&mut echoed).expect("first echo");
        assert_eq!(echoed, *b"x");

        let result = server.apply_user_delta(&CoreUserDelta {
            deleted: vec![user().uuid],
            ..CoreUserDelta::default()
        });
        assert_eq!(result.deleted, 1);

        let _ = request_body.write_all(b"y");
        let _ = request_body.flush();
        assert!(
            !second_payload_rx
                .recv_timeout(Duration::from_secs(2))
                .expect("echo result"),
            "deleted user's existing VMess relay should stop forwarding new payload"
        );
        drop(request_body);
        drop(response_body);
        drop(client);
        server_thread
            .join()
            .expect("server thread")
            .expect("serve once");
        echo_thread.join().expect("echo thread");

        let records = server.drain_traffic(1);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].node_tag, "panel|vmess|1");
        assert_eq!(records[0].user_uuid, user().uuid);
        assert_eq!(records[0].user_id, Some(1));
        assert_eq!(records[0].upload, 1);
        assert_eq!(records[0].download, 1);
    }

    #[test]
    fn vmess_tcp_outbound_writes_request_and_relays_stream() {
        let (echo_addr, echo_thread) = echo_server();
        let proxy = TcpListener::bind("127.0.0.1:0").expect("proxy bind");
        let proxy_addr = proxy.local_addr().expect("proxy addr");
        let proxy_thread = thread::spawn(move || {
            let (stream, _) = proxy.accept().expect("proxy accept");
            server().handle_tcp_client(stream).expect("vmess proxy");
        });
        let target = SocksTarget {
            host: echo_addr.ip().to_string(),
            port: echo_addr.port(),
        };
        let outbound = vmess_outbound(proxy_addr, None);

        let stream = connect_vmess_tcp_outbound(&outbound, &target, Duration::from_secs(2))
            .expect("connect outbound");

        assert_outbound_reaches_echo(stream, echo_thread);
        proxy_thread.join().expect("proxy thread");
    }

    #[test]
    fn vmess_alter_id_outbound_uses_legacy_header_and_relays_stream() {
        let proxy = TcpListener::bind("127.0.0.1:0").expect("proxy bind");
        let proxy_addr = proxy.local_addr().expect("proxy addr");
        let proxy_thread = thread::spawn(move || {
            let (mut stream, _) = proxy.accept().expect("proxy accept");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("timeout");
            stream
                .set_write_timeout(Some(Duration::from_secs(2)))
                .expect("timeout");
            let request = read_legacy_vmess_request_header(
                &mut stream,
                "11111111-1111-1111-1111-111111111111",
                2,
            );
            assert_eq!(request.header_mode, VmessHeaderMode::Legacy);
            assert_eq!(request.command, VmessCommand::Tcp);
            assert_eq!(request.target.host, "127.0.0.1");
            assert_eq!(request.target.port, 443);
            write_legacy_vmess_response_header(&mut stream, &request);

            let mut body = VmessBodyReader::new_with_length_seed(
                stream.try_clone().expect("clone"),
                request.request_body_key,
                request.request_body_iv,
                request.request_body_key,
                request.request_body_iv,
                request.options,
                request.security,
            )
            .expect("request body");
            let mut payload = [0u8; 4];
            body.read_exact(&mut payload).expect("request payload");
            assert_eq!(&payload, b"ping");

            let mut response = VmessBodyWriter::new_with_length_seed(
                stream,
                request.response_body_key,
                request.response_body_iv,
                request.request_body_key,
                request.request_body_iv,
                request.options,
                request.security,
            )
            .expect("response body");
            response.write_all(b"pong").expect("response payload");
            response.finish().expect("response finish");
        });
        let target = SocksTarget {
            host: "127.0.0.1".to_string(),
            port: 443,
        };
        let mut outbound = vmess_outbound(proxy_addr, None);
        outbound.alter_id = Some(2);

        let mut stream = connect_vmess_tcp_outbound(&outbound, &target, Duration::from_secs(2))
            .expect("connect legacy outbound");
        stream.write_all(b"ping").expect("write payload");
        let mut response = [0u8; 4];
        stream.read_exact(&mut response).expect("read response");
        assert_eq!(&response, b"pong");

        proxy_thread.join().expect("proxy thread");
    }

    #[test]
    fn vmess_websocket_outbound_writes_request_and_relays_stream() {
        let (echo_addr, echo_thread) = echo_server();
        let proxy = TcpListener::bind("127.0.0.1:0").expect("proxy bind");
        let proxy_addr = proxy.local_addr().expect("proxy addr");
        let proxy_thread = thread::spawn(move || {
            let (stream, _) = proxy.accept().expect("proxy accept");
            server()
                .handle_websocket_client(stream, Some("/vmess"))
                .expect("vmess websocket proxy");
        });
        let target = SocksTarget {
            host: echo_addr.ip().to_string(),
            port: echo_addr.port(),
        };
        let outbound = vmess_outbound(
            proxy_addr,
            Some(OutboundTransportConfig {
                network: "ws".to_string(),
                path: Some("/vmess".to_string()),
                host: Some("example.test".to_string()),
                service_name: None,
                method: None,
                headers: Default::default(),
                ..OutboundTransportConfig::default()
            }),
        );

        let stream = connect_vmess_tcp_outbound(&outbound, &target, Duration::from_secs(2))
            .expect("connect outbound");

        assert_outbound_reaches_echo(stream, echo_thread);
        proxy_thread.join().expect("proxy thread");
    }

    #[test]
    fn vmess_httpupgrade_outbound_writes_request_and_relays_stream() {
        let (echo_addr, echo_thread) = echo_server();
        let proxy = TcpListener::bind("127.0.0.1:0").expect("proxy bind");
        let proxy_addr = proxy.local_addr().expect("proxy addr");
        let proxy_thread = thread::spawn(move || {
            let (stream, _) = proxy.accept().expect("proxy accept");
            let stream = accept_httpupgrade(stream, Some("/vmess"), Some("example.test"))
                .expect("httpupgrade accept");
            let reader = stream.try_clone().expect("httpupgrade clone");
            server()
                .handle_split_client(reader, stream)
                .expect("vmess httpupgrade proxy");
        });
        let target = SocksTarget {
            host: echo_addr.ip().to_string(),
            port: echo_addr.port(),
        };
        let outbound = vmess_outbound(
            proxy_addr,
            Some(OutboundTransportConfig {
                network: "httpupgrade".to_string(),
                path: Some("/vmess".to_string()),
                host: Some("example.test".to_string()),
                service_name: None,
                method: None,
                headers: Default::default(),
                ..OutboundTransportConfig::default()
            }),
        );

        let stream = connect_vmess_tcp_outbound(&outbound, &target, Duration::from_secs(2))
            .expect("connect outbound");

        assert_outbound_reaches_echo(stream, echo_thread);
        proxy_thread.join().expect("proxy thread");
    }

    #[test]
    fn vmess_h2_outbound_writes_request_and_relays_stream() {
        let (echo_addr, echo_thread) = echo_server();
        let listener = TcpListener::bind("127.0.0.1:0").expect("proxy bind");
        listener
            .set_nonblocking(true)
            .expect("proxy listener nonblocking");
        let proxy_addr = listener.local_addr().expect("proxy addr");
        let stop = Arc::new(AtomicBool::new(false));
        let server_stop = stop.clone();
        let handler_stop = stop.clone();
        let proxy_thread = thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime");
            let _guard = runtime.enter();
            let listener = tokio::net::TcpListener::from_std(listener).expect("tokio listener");
            drop(_guard);
            let handler: Http2StreamHandler = Arc::new(move |reader, writer| {
                server()
                    .handle_split_client(reader, writer)
                    .expect("vmess h2 proxy");
                handler_stop.store(true, Ordering::SeqCst);
            });
            runtime
                .block_on(run_http2_listener(
                    listener,
                    server_stop,
                    "/vmess".to_string(),
                    "PUT".to_string(),
                    None,
                    handler,
                ))
                .expect("h2 listener");
        });
        let target = SocksTarget {
            host: echo_addr.ip().to_string(),
            port: echo_addr.port(),
        };
        let outbound = vmess_outbound(
            proxy_addr,
            Some(OutboundTransportConfig {
                network: "h2".to_string(),
                path: Some("/vmess".to_string()),
                host: Some("example.test".to_string()),
                service_name: None,
                method: Some("PUT".to_string()),
                headers: Default::default(),
                ..OutboundTransportConfig::default()
            }),
        );

        let stream = connect_vmess_tcp_outbound(&outbound, &target, Duration::from_secs(2))
            .expect("connect outbound");

        assert_outbound_reaches_echo(stream, echo_thread);
        proxy_thread.join().expect("proxy thread");
    }

    #[test]
    fn vmess_grpc_outbound_writes_request_and_relays_stream() {
        let (echo_addr, echo_thread) = echo_server();
        let listener = TcpListener::bind("127.0.0.1:0").expect("proxy bind");
        listener
            .set_nonblocking(true)
            .expect("proxy listener nonblocking");
        let proxy_addr = listener.local_addr().expect("proxy addr");
        let stop = Arc::new(AtomicBool::new(false));
        let server_stop = stop.clone();
        let handler_stop = stop.clone();
        let proxy_thread = thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime");
            let _guard = runtime.enter();
            let listener = tokio::net::TcpListener::from_std(listener).expect("tokio listener");
            drop(_guard);
            let handler: GrpcStreamHandler = Arc::new(move |reader, writer| {
                server()
                    .handle_split_client(reader, writer)
                    .expect("vmess grpc proxy");
                handler_stop.store(true, Ordering::SeqCst);
            });
            runtime
                .block_on(run_grpc_listener(
                    listener,
                    server_stop,
                    "GunService".to_string(),
                    None,
                    handler,
                ))
                .expect("grpc listener");
        });
        let target = SocksTarget {
            host: echo_addr.ip().to_string(),
            port: echo_addr.port(),
        };
        let outbound = vmess_outbound(
            proxy_addr,
            Some(OutboundTransportConfig {
                network: "grpc".to_string(),
                path: None,
                host: Some("example.test".to_string()),
                service_name: Some("GunService".to_string()),
                method: None,
                headers: Default::default(),
                ..OutboundTransportConfig::default()
            }),
        );

        let stream = connect_vmess_tcp_outbound(&outbound, &target, Duration::from_secs(2))
            .expect("connect outbound");

        assert_outbound_reaches_echo(stream, echo_thread);
        proxy_thread.join().expect("proxy thread");
    }

    #[test]
    fn vmess_udp_outbound_sends_packet_and_decodes_response() {
        let echo = UdpSocket::bind("127.0.0.1:0").expect("echo bind");
        let echo_addr = echo.local_addr().expect("echo addr");
        let echo_thread = thread::spawn(move || {
            let mut bytes = [0u8; 1024];
            let (read, source) = echo.recv_from(&mut bytes).expect("echo read");
            assert_eq!(&bytes[..read], b"ping");
            echo.send_to(b"pong", source).expect("echo write");
        });

        let server = server();
        let listener = server.bind().expect("vmess bind");
        let vmess_addr = listener.local_addr().expect("vmess addr");
        let server_clone = server.clone();
        let server_thread = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("vmess accept");
            server_clone.handle_tcp_client(stream)
        });

        let outbound = vmess_outbound(vmess_addr, None);
        let target = SocksTarget {
            host: echo_addr.ip().to_string(),
            port: echo_addr.port(),
        };
        let (_, response) =
            send_vmess_udp_outbound(&outbound, &target, b"ping", Duration::from_secs(2))
                .expect("vmess udp outbound");

        assert_eq!(response, b"pong");
        server_thread
            .join()
            .expect("server thread")
            .expect("serve once");
        echo_thread.join().expect("echo thread");
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
        assert_eq!(records[0].node_tag, "panel|vmess|1");
        assert_eq!(records[0].user_uuid, "11111111-1111-1111-1111-111111111111");
        assert_eq!(records[0].user_id, Some(1));
        assert_eq!(records[0].upload, 4);
        assert_eq!(records[0].download, 4);
    }

    #[test]
    fn proxies_udp_and_records_user_traffic() {
        let _network_guard = crate::test_support::network_test_lock();
        let echo = UdpSocket::bind("127.0.0.1:0").expect("echo bind");
        let echo_addr = echo.local_addr().expect("echo addr");
        let echo_thread = thread::spawn(move || {
            let mut bytes = [0u8; 1024];
            let (read, source) = echo.recv_from(&mut bytes).expect("echo read");
            assert_eq!(&bytes[..read], b"ping");
            echo.send_to(b"pong", source).expect("echo write");
        });

        let server = server();
        let listener = server.bind().expect("vmess bind");
        let vmess_addr = listener.local_addr().expect("vmess addr");
        let server_clone = server.clone();
        let server_thread = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("vmess accept");
            server_clone.handle_tcp_client(stream)
        });

        let (request_bytes, request) = vmess_request_header_for_user_with_auth_random(
            &user(),
            echo_addr,
            OPTION_CHUNK_STREAM | OPTION_CHUNK_MASKING | OPTION_GLOBAL_PADDING,
            COMMAND_UDP,
            [1, 2, 3, 4],
        );
        let mut client = TcpStream::connect(vmess_addr).expect("client connect");
        client
            .set_read_timeout(Some(Duration::from_secs(3)))
            .expect("client timeout");
        client.write_all(&request_bytes).expect("client request");
        decode_response_header(&mut client, &request);
        let mut request_body = VmessBodyEncoder::new(
            request.request_body_key,
            request.request_body_iv,
            request.options,
            request.security,
        );
        request_body
            .write_packet(&mut client, b"ping")
            .expect("udp request write");
        client.flush().expect("udp request flush");
        let mut response_body = VmessBodyDecoder::new(
            request.response_body_key,
            request.response_body_iv,
            request.options,
            request.security,
        );
        let response = response_body
            .read_packet(&mut client)
            .expect("udp response read")
            .expect("udp response packet");
        let _ = request_body.finish(&mut client);
        assert_eq!(response, b"pong");
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

        let options = OPTION_CHUNK_STREAM
            | OPTION_CHUNK_MASKING
            | OPTION_GLOBAL_PADDING
            | OPTION_AUTHENTICATED_LENGTH;
        let (request_bytes, request) = vmess_request_header_for_user_with_auth_random(
            &user(),
            echo_addr,
            options,
            COMMAND_TCP,
            [1, 2, 3, 4],
        );
        let mut client = TcpStream::connect(vmess_addr).expect("client connect");
        client
            .set_read_timeout(Some(Duration::from_secs(3)))
            .expect("client timeout");
        client.write_all(&request_bytes).expect("client request");
        decode_response_header(&mut client, &request);
        let mut request_body = VmessBodyEncoder::new_with_length_seed(
            request.request_body_key,
            request.request_body_iv,
            request.request_body_key,
            request.request_body_iv,
            request.options,
            request.security,
        );
        request_body
            .write_plain(&mut client, b"ping")
            .expect("client request payload");
        client.flush().expect("client request flush");
        let mut response_body = VmessBodyDecoder::new_with_length_seed(
            request.response_body_key,
            request.response_body_iv,
            request.request_body_key,
            request.request_body_iv,
            request.options,
            request.security,
        );
        let mut echoed = [0u8; 4];
        response_body
            .read_plain(&mut client, &mut echoed)
            .expect("client read payload");
        assert_eq!(&echoed, b"ping");
        let _ = request_body.finish(&mut client);
        drop(client);

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
            command: VmessCommand::Tcp,
            user_key: "user".to_string(),
            user_uuid: "user".to_string(),
            user_id: Some(7),
            target: SocksTarget {
                host: "127.0.0.1".to_string(),
                port: 80,
            },
            client_ip: None,
            request_body_key: [0x22; 16],
            request_body_iv: [0x33; 16],
            response_body_key: super::first_16_sha256(&[0x22; 16]),
            response_body_iv: super::first_16_sha256(&[0x33; 16]),
            response_header: 0x77,
            options: OPTION_CHUNK_STREAM,
            security: VmessSecurity::Aes128Gcm,
            header_mode: VmessHeaderMode::Aead,
        };
        let mut bytes = Vec::new();

        write_response_header(&mut bytes, &request).expect("response header");
        decode_response_header(&mut std::io::Cursor::new(bytes), &request);
    }
}
