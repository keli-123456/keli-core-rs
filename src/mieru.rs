use std::collections::{HashMap, VecDeque};
use std::io::{self, Read, Write};
use std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket,
};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex, RwLock};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};

use crate::limits::{BandwidthLimiter, UserBandwidthLimiters, UserSessionTracker};
use crate::outbound::recv_udp_response;
use crate::socks5::SocksTarget;
use crate::stream::{
    copy_count_best_effort_limited, join_native_blocking_relay, spawn_native_blocking_relay,
    NativeRelayHandle,
};
use crate::traffic::TrafficRegistry;
use crate::user::CoreUser;
use crate::{
    connect_tcp_outbound, route_protocol_labels, send_udp_outbound, RouteDecision, RouteMatcher,
};

const NONCE_LEN: usize = 24;
const METADATA_LEN: usize = 32;
const TAG_LEN: usize = 16;
const ENCRYPTED_METADATA_LEN: usize = METADATA_LEN + TAG_LEN;
const MAX_TCP_FRAGMENT_LEN: usize = 32 * 1024;
const MAX_SESSION_PAYLOAD_LEN: usize = 1024;
const MAX_PADDING_SCAN: usize = 8192;
const KEY_WINDOW_SECS: i64 = 120;
const OPEN_SESSION_REQUEST: u8 = 2;
const OPEN_SESSION_RESPONSE: u8 = 3;
const CLOSE_SESSION_REQUEST: u8 = 4;
const CLOSE_SESSION_RESPONSE: u8 = 5;
const DATA_CLIENT_TO_SERVER: u8 = 6;
const DATA_SERVER_TO_CLIENT: u8 = 7;
const ACK_CLIENT_TO_SERVER: u8 = 8;
const ACK_SERVER_TO_CLIENT: u8 = 9;
const STATUS_OK: u8 = 0;
const SOCKS_VERSION: u8 = 5;
const SOCKS_CMD_CONNECT: u8 = 1;
const SOCKS_CMD_UDP_ASSOCIATE: u8 = 3;
const SOCKS_CONNECT_SUCCESS: [u8; 10] = [SOCKS_VERSION, 0, 0, ATYP_IPV4, 0, 0, 0, 0, 0, 0];
const ATYP_IPV4: u8 = 1;
const ATYP_DOMAIN: u8 = 3;
const ATYP_IPV6: u8 = 4;
const MIERU_UDP_MARKER_START: u8 = 0x00;
const MIERU_UDP_MARKER_END: u8 = 0xff;

type HmacSha256 = Hmac<Sha256>;

#[derive(Clone, Debug)]
pub struct MieruServerConfig {
    pub node_tag: String,
    pub listen: SocketAddr,
    pub users: Vec<CoreUser>,
    pub routes: Vec<crate::RouteRule>,
    pub connect_timeout: Duration,
}

#[derive(Clone, Debug)]
pub struct MieruServer {
    config: MieruServerConfig,
    users: Arc<RwLock<Vec<CoreUser>>>,
    router: RouteMatcher,
    traffic: Arc<Mutex<TrafficRegistry>>,
    sessions: UserSessionTracker,
    bandwidth: UserBandwidthLimiters,
}

#[derive(Clone, Debug)]
struct MieruCredential {
    user: CoreUser,
    username: String,
    password: String,
    key: [u8; 32],
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct MieruMetadata {
    protocol_type: u8,
    session_id: u32,
    sequence: u32,
    status_code: u8,
    payload_len: usize,
    prefix_len: usize,
    suffix_len: usize,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct MieruSegment {
    metadata: MieruMetadata,
    payload: Vec<u8>,
}

#[derive(Debug)]
struct MieruReader {
    stream: TcpStream,
    buffer: Vec<u8>,
    pending: VecDeque<u8>,
    initial_segment: Option<MieruSegment>,
    user: CoreUser,
    key: [u8; 32],
    nonce: [u8; NONCE_LEN],
    session_id: u32,
    closed: bool,
}

#[derive(Debug)]
struct MieruWriter {
    stream: TcpStream,
    key: [u8; 32],
    nonce: [u8; NONCE_LEN],
    session_id: u32,
    sequence: u32,
    sent_nonce: bool,
}

#[derive(Debug)]
struct MieruSessionReader {
    rx: Receiver<MieruSegment>,
    pending: VecDeque<u8>,
    closed: bool,
    stop: Arc<AtomicBool>,
}

#[derive(Clone, Debug)]
struct MieruSessionWriter {
    inner: Arc<Mutex<MieruWriter>>,
    session_id: u32,
}

trait MieruOutput: Write {
    fn shutdown_session(&mut self);
}

trait MieruInput: Read + Send {
    fn stop_handle(&self) -> Option<Arc<AtomicBool>> {
        None
    }
}

#[derive(Debug)]
enum SegmentAttempt {
    Complete {
        segment: MieruSegment,
        consumed: usize,
        next_nonce: [u8; NONCE_LEN],
    },
    NeedMore,
    Invalid,
}

#[derive(Debug, PartialEq, Eq)]
enum SocksParseResult {
    Complete {
        command: MieruSocksCommand,
        target: SocksTarget,
        consumed: usize,
    },
    NeedMore,
}

#[derive(Debug, PartialEq, Eq)]
enum MieruSocksCommand {
    TcpConnect,
    UdpAssociate,
}

#[derive(Debug, PartialEq, Eq)]
struct MieruSocksRequest {
    command: MieruSocksCommand,
    target: SocksTarget,
    consumed: usize,
}

impl MieruServer {
    pub fn new(config: MieruServerConfig) -> Self {
        Self::with_traffic(config, Arc::new(Mutex::new(TrafficRegistry::default())))
    }

    pub fn with_traffic(config: MieruServerConfig, traffic: Arc<Mutex<TrafficRegistry>>) -> Self {
        Self::with_shared_limits(
            config,
            traffic,
            UserSessionTracker::default(),
            UserBandwidthLimiters::default(),
        )
    }

    pub fn with_shared_limits(
        config: MieruServerConfig,
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

    pub fn handle_tcp_client(&self, client: TcpStream) -> io::Result<()> {
        let client_ip = client.peer_addr().ok().map(|addr| addr.ip());
        let mut reader = MieruReader::accept(client.try_clone()?, &self.active_users())?;
        let user = reader.user().clone();
        let mut writer = MieruWriter::server(client, &user, reader.session_id())?;
        let Some(initial) = reader.take_initial_segment() else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "missing mieru open session request",
            ));
        };
        if initial.metadata.protocol_type != OPEN_SESSION_REQUEST {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "first mieru segment is not an open session request",
            ));
        }

        reader.set_poll_timeout(Duration::from_millis(100))?;
        writer.set_session_id(initial.metadata.session_id);
        let writer = Arc::new(Mutex::new(writer));
        let mut sessions = HashMap::<u32, Sender<MieruSegment>>::new();
        let mut workers = Vec::new();
        let (done_tx, done_rx) = mpsc::channel();
        spawn_mieru_session(
            initial,
            user,
            client_ip,
            writer.clone(),
            MieruSessionRuntime {
                node_tag: self.config.node_tag.clone(),
                router: self.router.clone(),
                traffic: self.traffic.clone(),
                sessions: self.sessions.clone(),
                bandwidth: self.bandwidth.clone(),
                timeout: self.config.connect_timeout,
            },
            done_tx.clone(),
            &mut sessions,
            &mut workers,
        )?;

        let mut first_error = None::<(io::ErrorKind, String)>;
        loop {
            while let Ok((session_id, result)) = done_rx.try_recv() {
                sessions.remove(&session_id);
                if let Err(error) = result {
                    first_error.get_or_insert(error);
                    close_mieru_underlay(&writer);
                }
            }
            if first_error.is_some() || sessions.is_empty() {
                break;
            }

            match reader.read_segment() {
                Ok(Some(segment)) => {
                    dispatch_mieru_segment(
                        segment,
                        &reader.user,
                        client_ip,
                        writer.clone(),
                        MieruSessionRuntime {
                            node_tag: self.config.node_tag.clone(),
                            router: self.router.clone(),
                            traffic: self.traffic.clone(),
                            sessions: self.sessions.clone(),
                            bandwidth: self.bandwidth.clone(),
                            timeout: self.config.connect_timeout,
                        },
                        done_tx.clone(),
                        &mut sessions,
                        &mut workers,
                    )?;
                }
                Ok(None) => break,
                Err(error) if is_timeout_error(&error) => continue,
                Err(error) if is_connection_closed_error(&error) => break,
                Err(error) => return Err(error),
            }
        }

        drop(sessions);
        for worker in workers {
            let _ = join_native_blocking_relay(worker, "mieru session worker panicked");
        }
        while let Ok((_, result)) = done_rx.try_recv() {
            if let Err(error) = result {
                first_error.get_or_insert(error);
            }
        }
        if let Some((kind, message)) = first_error {
            return Err(io::Error::new(kind, message));
        }
        Ok(())
    }

    pub fn drain_traffic(&self, minimum_bytes: u64) -> Vec<crate::traffic::TrafficDelta> {
        self.traffic
            .lock()
            .expect("traffic registry lock poisoned")
            .drain_minimum(minimum_bytes)
    }

    pub fn replace_users(&self, users: Vec<CoreUser>) {
        let mut current = self.users.write().expect("mieru users lock poisoned");
        *current = active_user_list(&users);
    }

    fn active_users(&self) -> Vec<CoreUser> {
        self.users
            .read()
            .expect("mieru users lock poisoned")
            .clone()
    }
}

#[derive(Clone)]
struct MieruSessionRuntime {
    node_tag: String,
    router: RouteMatcher,
    traffic: Arc<Mutex<TrafficRegistry>>,
    sessions: UserSessionTracker,
    bandwidth: UserBandwidthLimiters,
    timeout: Duration,
}

fn dispatch_mieru_segment(
    segment: MieruSegment,
    user: &CoreUser,
    client_ip: Option<IpAddr>,
    writer: Arc<Mutex<MieruWriter>>,
    runtime: MieruSessionRuntime,
    done_tx: Sender<(u32, Result<(), (io::ErrorKind, String)>)>,
    sessions: &mut HashMap<u32, Sender<MieruSegment>>,
    workers: &mut Vec<NativeRelayHandle<()>>,
) -> io::Result<()> {
    match segment.metadata.protocol_type {
        OPEN_SESSION_REQUEST => spawn_mieru_session(
            segment,
            user.clone(),
            client_ip,
            writer,
            runtime,
            done_tx,
            sessions,
            workers,
        ),
        DATA_CLIENT_TO_SERVER | ACK_CLIENT_TO_SERVER => {
            let session_id = segment.metadata.session_id;
            if let Some(tx) = sessions.get(&session_id) {
                let _ = tx.send(segment);
            } else {
                write_mieru_close_response(&writer, session_id);
            }
            Ok(())
        }
        CLOSE_SESSION_REQUEST | CLOSE_SESSION_RESPONSE => {
            let session_id = segment.metadata.session_id;
            if let Some(tx) = sessions.remove(&session_id) {
                let _ = tx.send(segment);
            } else {
                write_mieru_close_response(&writer, session_id);
            }
            Ok(())
        }
        OPEN_SESSION_RESPONSE | DATA_SERVER_TO_CLIENT | ACK_SERVER_TO_CLIENT => Ok(()),
        _ => Ok(()),
    }
}

fn spawn_mieru_session(
    initial: MieruSegment,
    user: CoreUser,
    client_ip: Option<IpAddr>,
    writer: Arc<Mutex<MieruWriter>>,
    runtime: MieruSessionRuntime,
    done_tx: Sender<(u32, Result<(), (io::ErrorKind, String)>)>,
    sessions: &mut HashMap<u32, Sender<MieruSegment>>,
    workers: &mut Vec<NativeRelayHandle<()>>,
) -> io::Result<()> {
    let session_id = initial.metadata.session_id;
    if session_id == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "mieru session id 0 is reserved",
        ));
    }
    if sessions.contains_key(&session_id) {
        return Err(io::Error::new(
            io::ErrorKind::AlreadyExists,
            format!("mieru session id {session_id} is already open"),
        ));
    }

    let (tx, rx) = mpsc::channel();
    sessions.insert(session_id, tx);
    workers.push(spawn_native_blocking_relay(move || {
        let result = handle_mieru_session(initial, rx, writer.clone(), user, client_ip, runtime)
            .map_err(|error| (error.kind(), error.to_string()));
        if result.is_err() {
            close_mieru_underlay(&writer);
        }
        let _ = done_tx.send((session_id, result));
    })?);
    Ok(())
}

fn handle_mieru_session(
    initial: MieruSegment,
    rx: Receiver<MieruSegment>,
    writer: Arc<Mutex<MieruWriter>>,
    user: CoreUser,
    client_ip: Option<IpAddr>,
    runtime: MieruSessionRuntime,
) -> io::Result<()> {
    let session_id = initial.metadata.session_id;
    let mut reader = MieruSessionReader::new(initial.payload, rx);
    let mut writer = MieruSessionWriter::new(writer, session_id);
    let mut request_bytes = Vec::new();
    let request = read_socks_request_from_mieru(&mut reader, &mut request_bytes)?;
    let initial_payload = request_bytes.split_off(request.consumed);
    let _session = runtime
        .sessions
        .try_acquire_for_ip(Some(&user), client_ip)
        .map_err(|error| io::Error::new(io::ErrorKind::PermissionDenied, error.to_string()))?;
    let bandwidth = runtime.bandwidth.limiter_for(Some(&user));

    let (upload, download) = if request.command == MieruSocksCommand::UdpAssociate {
        writer.write_open_response()?;
        writer.write_all(&SOCKS_CONNECT_SUCCESS)?;
        relay_mieru_udp_associate(
            reader,
            writer,
            initial_payload,
            &runtime.router,
            runtime.timeout,
            bandwidth,
        )?
    } else {
        let protocol_labels = route_protocol_labels("tcp", &initial_payload);
        let mut remote = match runtime.router.decide_target(
            &request.target.host,
            request.target.port,
            &protocol_labels,
        ) {
            RouteDecision::Direct => connect_target(&request.target, runtime.timeout)?,
            RouteDecision::Outbound(outbound) => {
                connect_tcp_outbound(&outbound, &request.target, runtime.timeout)?
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
        writer.write_open_response()?;
        writer.write_all(&SOCKS_CONNECT_SUCCESS)?;
        let mut upload = 0u64;
        if !initial_payload.is_empty() {
            if let Some(limiter) = bandwidth.as_deref() {
                limiter.wait_for(initial_payload.len());
            }
            remote.write_all(&initial_payload)?;
            upload = initial_payload.len() as u64;
        }
        let (relayed_upload, download) = relay_mieru_streams(reader, writer, remote, bandwidth)?;
        (upload.saturating_add(relayed_upload), download)
    };

    runtime
        .traffic
        .lock()
        .expect("traffic registry lock poisoned")
        .add_with_user_id(
            runtime.node_tag,
            user.uuid,
            Some(user.id),
            upload,
            download,
            client_ip,
        );
    Ok(())
}

fn write_mieru_close_response(writer: &Arc<Mutex<MieruWriter>>, session_id: u32) {
    if let Ok(mut writer) = writer.lock() {
        let _ = writer.write_close_response_for_session(session_id);
    }
}

fn close_mieru_underlay(writer: &Arc<Mutex<MieruWriter>>) {
    if let Ok(mut writer) = writer.lock() {
        writer.close_underlay();
    }
}

fn is_timeout_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    )
}

fn is_connection_closed_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::ConnectionReset | io::ErrorKind::UnexpectedEof
    )
}

impl MieruReader {
    fn accept(mut stream: TcpStream, users: &[CoreUser]) -> io::Result<Self> {
        stream.set_read_timeout(Some(Duration::from_secs(10)))?;
        let mut buffer = Vec::new();
        loop {
            let mut temp = [0u8; 4096];
            let read = stream.read(&mut temp)?;
            if read == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "mieru connection closed before first segment",
                ));
            }
            buffer.extend_from_slice(&temp[..read]);

            let credentials = candidate_credentials(users, &buffer);
            for offset in 0..buffer
                .len()
                .saturating_sub(NONCE_LEN + ENCRYPTED_METADATA_LEN)
                + 1
            {
                let nonce = &buffer[offset..offset + NONCE_LEN];
                for credential in credentials
                    .iter()
                    .filter(|credential| nonce_matches_user_hint(nonce, &credential.username))
                {
                    let mut nonce_bytes = [0u8; NONCE_LEN];
                    nonce_bytes.copy_from_slice(nonce);
                    match try_decode_segment(&buffer, offset, true, &credential.key, nonce_bytes) {
                        SegmentAttempt::Complete {
                            segment,
                            consumed,
                            next_nonce,
                        } => {
                            let remaining = buffer.split_off(consumed);
                            let session_id = segment.metadata.session_id;
                            buffer = remaining;
                            return Ok(Self {
                                stream,
                                buffer,
                                pending: VecDeque::new(),
                                initial_segment: Some(segment),
                                user: credential.user.clone(),
                                key: credential.key,
                                nonce: next_nonce,
                                session_id,
                                closed: false,
                            });
                        }
                        SegmentAttempt::NeedMore => break,
                        SegmentAttempt::Invalid => {}
                    }
                }
            }

            if buffer.len() > MAX_PADDING_SCAN + NONCE_LEN + ENCRYPTED_METADATA_LEN {
                let drain = buffer.len() - (NONCE_LEN + ENCRYPTED_METADATA_LEN);
                buffer.drain(..drain.min(MAX_PADDING_SCAN));
            }
        }
    }

    fn user(&self) -> &CoreUser {
        &self.user
    }

    fn session_id(&self) -> u32 {
        self.session_id
    }

    fn set_poll_timeout(&self, timeout: Duration) -> io::Result<()> {
        self.stream.set_read_timeout(Some(timeout))
    }

    fn take_initial_segment(&mut self) -> Option<MieruSegment> {
        self.initial_segment.take()
    }

    fn read_segment(&mut self) -> io::Result<Option<MieruSegment>> {
        loop {
            for offset in 0..self.buffer.len().saturating_sub(ENCRYPTED_METADATA_LEN) + 1 {
                match try_decode_segment(&self.buffer, offset, false, &self.key, self.nonce) {
                    SegmentAttempt::Complete {
                        segment,
                        consumed,
                        next_nonce,
                    } => {
                        self.buffer.drain(..consumed);
                        self.nonce = next_nonce;
                        return Ok(Some(segment));
                    }
                    SegmentAttempt::NeedMore => break,
                    SegmentAttempt::Invalid => {}
                }
            }

            if self.buffer.len() > MAX_PADDING_SCAN + ENCRYPTED_METADATA_LEN {
                let drain = self.buffer.len() - ENCRYPTED_METADATA_LEN;
                self.buffer.drain(..drain.min(MAX_PADDING_SCAN));
            }

            let mut temp = [0u8; 4096];
            let read = self.stream.read(&mut temp)?;
            if read == 0 {
                return Ok(None);
            }
            self.buffer.extend_from_slice(&temp[..read]);
        }
    }
}

impl Read for MieruReader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        while self.pending.is_empty() && !self.closed {
            if let Some(segment) = self.initial_segment.take() {
                match segment.metadata.protocol_type {
                    DATA_CLIENT_TO_SERVER | DATA_SERVER_TO_CLIENT => {
                        self.pending.extend(segment.payload)
                    }
                    CLOSE_SESSION_REQUEST | CLOSE_SESSION_RESPONSE => self.closed = true,
                    _ => {}
                }
                if !self.pending.is_empty() || self.closed {
                    break;
                }
            }
            let Some(segment) = self.read_segment()? else {
                self.closed = true;
                break;
            };
            match segment.metadata.protocol_type {
                DATA_CLIENT_TO_SERVER | DATA_SERVER_TO_CLIENT => {
                    self.pending.extend(segment.payload)
                }
                CLOSE_SESSION_REQUEST | CLOSE_SESSION_RESPONSE => {
                    self.closed = true;
                    break;
                }
                ACK_CLIENT_TO_SERVER
                | ACK_SERVER_TO_CLIENT
                | OPEN_SESSION_REQUEST
                | OPEN_SESSION_RESPONSE => {}
                _ => {}
            }
        }

        let mut written = 0;
        while written < output.len() {
            let Some(byte) = self.pending.pop_front() else {
                break;
            };
            output[written] = byte;
            written += 1;
        }
        Ok(written)
    }
}

impl MieruInput for MieruReader {}

impl MieruSessionReader {
    fn new(initial_payload: Vec<u8>, rx: Receiver<MieruSegment>) -> Self {
        Self {
            rx,
            pending: initial_payload.into_iter().collect(),
            closed: false,
            stop: Arc::new(AtomicBool::new(false)),
        }
    }
}

impl Read for MieruSessionReader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        while self.pending.is_empty() && !self.closed {
            if self.stop.load(Ordering::Relaxed) {
                self.closed = true;
                break;
            }
            match self.rx.recv_timeout(Duration::from_millis(100)) {
                Ok(segment) => match segment.metadata.protocol_type {
                    DATA_CLIENT_TO_SERVER | DATA_SERVER_TO_CLIENT => {
                        self.pending.extend(segment.payload);
                    }
                    CLOSE_SESSION_REQUEST | CLOSE_SESSION_RESPONSE => {
                        self.closed = true;
                    }
                    ACK_CLIENT_TO_SERVER
                    | ACK_SERVER_TO_CLIENT
                    | OPEN_SESSION_REQUEST
                    | OPEN_SESSION_RESPONSE => {}
                    _ => {}
                },
                Err(mpsc::RecvTimeoutError::Timeout) => {}
                Err(_) => self.closed = true,
            }
        }

        let mut written = 0;
        while written < output.len() {
            let Some(byte) = self.pending.pop_front() else {
                break;
            };
            output[written] = byte;
            written += 1;
        }
        Ok(written)
    }
}

impl MieruInput for MieruSessionReader {
    fn stop_handle(&self) -> Option<Arc<AtomicBool>> {
        Some(self.stop.clone())
    }
}

impl MieruWriter {
    fn server(stream: TcpStream, user: &CoreUser, session_id: u32) -> io::Result<Self> {
        let username = mieru_username(user);
        let password = mieru_password(user);
        let mut nonce = [0u8; NONCE_LEN];
        getrandom::getrandom(&mut nonce)
            .map_err(|err| io::Error::new(io::ErrorKind::Other, err.to_string()))?;
        apply_nonce_user_hint(&mut nonce, &username);
        Ok(Self {
            stream,
            key: derive_mieru_key(&username, &password, rounded_unix_time(now_unix_secs())),
            nonce,
            session_id,
            sequence: 0,
            sent_nonce: false,
        })
    }

    fn set_session_id(&mut self, session_id: u32) {
        self.session_id = session_id;
    }

    #[cfg(test)]
    fn write_open_response(&mut self) -> io::Result<()> {
        self.write_open_response_for_session(self.session_id)
    }

    fn write_open_response_for_session(&mut self, session_id: u32) -> io::Result<()> {
        let metadata = MieruMetadata {
            protocol_type: OPEN_SESSION_RESPONSE,
            session_id,
            sequence: self.sequence,
            status_code: STATUS_OK,
            payload_len: 0,
            prefix_len: 0,
            suffix_len: 0,
        };
        self.sequence = self.sequence.saturating_add(1);
        self.write_segment(metadata, &[])
    }

    fn write_close_response(&mut self) -> io::Result<()> {
        self.write_close_response_for_session(self.session_id)
    }

    fn write_close_response_for_session(&mut self, session_id: u32) -> io::Result<()> {
        let metadata = MieruMetadata {
            protocol_type: CLOSE_SESSION_RESPONSE,
            session_id,
            sequence: self.sequence,
            status_code: STATUS_OK,
            payload_len: 0,
            prefix_len: 0,
            suffix_len: 0,
        };
        self.sequence = self.sequence.saturating_add(1);
        self.write_segment(metadata, &[])
    }

    fn write_data_segment(&mut self, payload: &[u8]) -> io::Result<()> {
        self.write_data_segment_for_session(self.session_id, payload)
    }

    fn write_data_segment_for_session(
        &mut self,
        session_id: u32,
        payload: &[u8],
    ) -> io::Result<()> {
        let metadata = MieruMetadata {
            protocol_type: DATA_SERVER_TO_CLIENT,
            session_id,
            sequence: self.sequence,
            status_code: STATUS_OK,
            payload_len: payload.len(),
            prefix_len: 0,
            suffix_len: 0,
        };
        self.sequence = self.sequence.saturating_add(1);
        self.write_segment(metadata, payload)
    }

    fn write_segment(&mut self, metadata: MieruMetadata, payload: &[u8]) -> io::Result<()> {
        let mut segment = Vec::new();
        if !self.sent_nonce {
            segment.extend_from_slice(&self.nonce);
            self.sent_nonce = true;
        }
        encode_segment_body(&mut segment, &self.key, &mut self.nonce, &metadata, payload)?;
        self.stream.write_all(&segment)
    }

    fn shutdown(&mut self) {
        let _ = self.write_close_response();
        let _ = self.stream.shutdown(Shutdown::Write);
    }

    fn close_underlay(&mut self) {
        let _ = self.stream.shutdown(Shutdown::Both);
    }
}

impl Write for MieruWriter {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        if input.is_empty() {
            return Ok(0);
        }
        for chunk in input.chunks(MAX_TCP_FRAGMENT_LEN) {
            self.write_data_segment(chunk)?;
        }
        Ok(input.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
}

impl MieruOutput for MieruWriter {
    fn shutdown_session(&mut self) {
        self.shutdown();
    }
}

impl MieruSessionWriter {
    fn new(inner: Arc<Mutex<MieruWriter>>, session_id: u32) -> Self {
        Self { inner, session_id }
    }

    fn write_open_response(&mut self) -> io::Result<()> {
        self.inner
            .lock()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "mieru writer lock poisoned"))?
            .write_open_response_for_session(self.session_id)
    }

    fn write_close_response(&mut self) -> io::Result<()> {
        self.inner
            .lock()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "mieru writer lock poisoned"))?
            .write_close_response_for_session(self.session_id)
    }
}

impl Write for MieruSessionWriter {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        if input.is_empty() {
            return Ok(0);
        }
        let mut writer = self
            .inner
            .lock()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "mieru writer lock poisoned"))?;
        for chunk in input.chunks(MAX_TCP_FRAGMENT_LEN) {
            writer.write_data_segment_for_session(self.session_id, chunk)?;
        }
        Ok(input.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner
            .lock()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "mieru writer lock poisoned"))?
            .flush()
    }
}

impl MieruOutput for MieruSessionWriter {
    fn shutdown_session(&mut self) {
        let _ = self.write_close_response();
    }
}

fn try_decode_segment(
    input: &[u8],
    offset: usize,
    has_nonce: bool,
    key: &[u8; 32],
    nonce: [u8; NONCE_LEN],
) -> SegmentAttempt {
    let metadata_offset = offset + if has_nonce { NONCE_LEN } else { 0 };
    if input.len() < metadata_offset + ENCRYPTED_METADATA_LEN {
        return SegmentAttempt::NeedMore;
    }

    let metadata_bytes = match decrypt_aead(
        key,
        &nonce,
        &input[metadata_offset..metadata_offset + ENCRYPTED_METADATA_LEN],
    ) {
        Ok(bytes) => bytes,
        Err(_) => return SegmentAttempt::Invalid,
    };
    let Some(metadata) = parse_metadata(&metadata_bytes) else {
        return SegmentAttempt::Invalid;
    };
    let mut next_nonce = nonce;
    increment_nonce(&mut next_nonce);

    let payload_offset = metadata_offset + ENCRYPTED_METADATA_LEN + metadata.prefix_len;
    let encrypted_payload_len = if metadata.payload_len == 0 {
        0
    } else {
        metadata.payload_len + TAG_LEN
    };
    let consumed = payload_offset + encrypted_payload_len + metadata.suffix_len;
    if input.len() < consumed {
        return SegmentAttempt::NeedMore;
    }
    let payload = if metadata.payload_len == 0 {
        Vec::new()
    } else {
        let payload = match decrypt_aead(
            key,
            &next_nonce,
            &input[payload_offset..payload_offset + encrypted_payload_len],
        ) {
            Ok(bytes) => bytes,
            Err(_) => return SegmentAttempt::Invalid,
        };
        if payload.len() != metadata.payload_len {
            return SegmentAttempt::Invalid;
        }
        increment_nonce(&mut next_nonce);
        payload
    };

    SegmentAttempt::Complete {
        segment: MieruSegment { metadata, payload },
        consumed,
        next_nonce,
    }
}

fn encode_segment_body(
    output: &mut Vec<u8>,
    key: &[u8; 32],
    nonce: &mut [u8; NONCE_LEN],
    metadata: &MieruMetadata,
    payload: &[u8],
) -> io::Result<()> {
    let metadata_bytes = encode_metadata(metadata)?;
    output.extend(encrypt_aead(key, nonce, &metadata_bytes)?);
    increment_nonce(nonce);
    if !payload.is_empty() {
        output.extend(encrypt_aead(key, nonce, payload)?);
        increment_nonce(nonce);
    }
    Ok(())
}

fn parse_metadata(input: &[u8]) -> Option<MieruMetadata> {
    if input.len() != METADATA_LEN {
        return None;
    }
    let protocol_type = input[0];
    if !matches!(
        protocol_type,
        OPEN_SESSION_REQUEST
            | OPEN_SESSION_RESPONSE
            | CLOSE_SESSION_REQUEST
            | CLOSE_SESSION_RESPONSE
            | DATA_CLIENT_TO_SERVER
            | DATA_SERVER_TO_CLIENT
            | ACK_CLIENT_TO_SERVER
            | ACK_SERVER_TO_CLIENT
    ) {
        return None;
    }

    let timestamp = u32::from_be_bytes([input[2], input[3], input[4], input[5]]);
    if !timestamp_is_close(timestamp) {
        return None;
    }

    let session_id = u32::from_be_bytes([input[6], input[7], input[8], input[9]]);
    let sequence = u32::from_be_bytes([input[10], input[11], input[12], input[13]]);
    match protocol_type {
        OPEN_SESSION_REQUEST
        | OPEN_SESSION_RESPONSE
        | CLOSE_SESSION_REQUEST
        | CLOSE_SESSION_RESPONSE => {
            let status_code = input[14];
            let payload_len = u16::from_be_bytes([input[15], input[16]]) as usize;
            if payload_len > MAX_SESSION_PAYLOAD_LEN {
                return None;
            }
            Some(MieruMetadata {
                protocol_type,
                session_id,
                sequence,
                status_code,
                payload_len,
                prefix_len: 0,
                suffix_len: input[17] as usize,
            })
        }
        DATA_CLIENT_TO_SERVER
        | DATA_SERVER_TO_CLIENT
        | ACK_CLIENT_TO_SERVER
        | ACK_SERVER_TO_CLIENT => {
            let payload_len = u16::from_be_bytes([input[22], input[23]]) as usize;
            if payload_len > MAX_TCP_FRAGMENT_LEN {
                return None;
            }
            Some(MieruMetadata {
                protocol_type,
                session_id,
                sequence,
                status_code: STATUS_OK,
                payload_len,
                prefix_len: input[21] as usize,
                suffix_len: input[24] as usize,
            })
        }
        _ => None,
    }
}

fn encode_metadata(metadata: &MieruMetadata) -> io::Result<[u8; METADATA_LEN]> {
    if metadata.payload_len > u16::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "mieru payload too large",
        ));
    }
    let mut output = [0u8; METADATA_LEN];
    output[0] = metadata.protocol_type;
    output[2..6].copy_from_slice(&((now_unix_secs() / 60) as u32).to_be_bytes());
    output[6..10].copy_from_slice(&metadata.session_id.to_be_bytes());
    output[10..14].copy_from_slice(&metadata.sequence.to_be_bytes());
    match metadata.protocol_type {
        OPEN_SESSION_REQUEST
        | OPEN_SESSION_RESPONSE
        | CLOSE_SESSION_REQUEST
        | CLOSE_SESSION_RESPONSE => {
            output[14] = metadata.status_code;
            output[15..17].copy_from_slice(&(metadata.payload_len as u16).to_be_bytes());
            output[17] = metadata.suffix_len as u8;
        }
        DATA_CLIENT_TO_SERVER
        | DATA_SERVER_TO_CLIENT
        | ACK_CLIENT_TO_SERVER
        | ACK_SERVER_TO_CLIENT => {
            output[18..20].copy_from_slice(&(64u16).to_be_bytes());
            output[21] = metadata.prefix_len as u8;
            output[22..24].copy_from_slice(&(metadata.payload_len as u16).to_be_bytes());
            output[24] = metadata.suffix_len as u8;
        }
        _ => {}
    }
    Ok(output)
}

fn encrypt_aead(key: &[u8; 32], nonce: &[u8; NONCE_LEN], plaintext: &[u8]) -> io::Result<Vec<u8>> {
    let cipher = <XChaCha20Poly1305 as KeyInit>::new_from_slice(key)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?;
    cipher
        .encrypt(XNonce::from_slice(nonce), plaintext)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "mieru encrypt failed"))
}

fn decrypt_aead(key: &[u8; 32], nonce: &[u8; NONCE_LEN], ciphertext: &[u8]) -> io::Result<Vec<u8>> {
    let cipher = <XChaCha20Poly1305 as KeyInit>::new_from_slice(key)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidInput, err.to_string()))?;
    cipher
        .decrypt(XNonce::from_slice(nonce), ciphertext)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "mieru decrypt failed"))
}

fn candidate_credentials(users: &[CoreUser], input: &[u8]) -> Vec<MieruCredential> {
    let now = rounded_unix_time(now_unix_secs());
    let time_slots = [now - KEY_WINDOW_SECS, now, now + KEY_WINDOW_SECS];
    users
        .iter()
        .flat_map(|user| {
            let username = mieru_username(user);
            let password = mieru_password(user);
            time_slots
                .into_iter()
                .map(move |time_slot| MieruCredential {
                    user: user.clone(),
                    username: username.clone(),
                    password: password.clone(),
                    key: derive_mieru_key(&username, &password, time_slot),
                })
        })
        .filter(|credential| {
            input.windows(NONCE_LEN).any(|nonce| {
                nonce_matches_user_hint(nonce, &credential.username)
                    && credential.password == mieru_password(&credential.user)
            })
        })
        .collect()
}

fn mieru_username(user: &CoreUser) -> String {
    user.uuid.trim().to_string()
}

fn mieru_password(user: &CoreUser) -> String {
    user.credential().trim().to_string()
}

fn derive_mieru_key(username: &str, password: &str, rounded_unix: i64) -> [u8; 32] {
    let mut password_hasher = Sha256::new();
    password_hasher.update(password.as_bytes());
    password_hasher.update([0]);
    password_hasher.update(username.as_bytes());
    let hashed_password = password_hasher.finalize();

    let mut time_hasher = Sha256::new();
    time_hasher.update((rounded_unix as u64).to_be_bytes());
    let time_salt = time_hasher.finalize();

    let mut key = [0u8; 32];
    pbkdf2_hmac_sha256(&hashed_password, &time_salt, 64, &mut key);
    key
}

fn pbkdf2_hmac_sha256(password: &[u8], salt: &[u8], iterations: u32, output: &mut [u8]) {
    let mut block_index = 1u32;
    let mut offset = 0usize;
    while offset < output.len() {
        let mut mac =
            <HmacSha256 as Mac>::new_from_slice(password).expect("hmac accepts any key length");
        mac.update(salt);
        mac.update(&block_index.to_be_bytes());
        let mut u = mac.finalize().into_bytes().to_vec();
        let mut block = u.clone();
        for _ in 1..iterations {
            let mut mac =
                <HmacSha256 as Mac>::new_from_slice(password).expect("hmac accepts any key length");
            mac.update(&u);
            u = mac.finalize().into_bytes().to_vec();
            for (left, right) in block.iter_mut().zip(&u) {
                *left ^= *right;
            }
        }

        let take = (output.len() - offset).min(block.len());
        output[offset..offset + take].copy_from_slice(&block[..take]);
        offset += take;
        block_index = block_index.saturating_add(1);
    }
}

fn nonce_matches_user_hint(nonce: &[u8], username: &str) -> bool {
    if nonce.len() != NONCE_LEN {
        return false;
    }
    let mut expected = [0u8; 4];
    expected.copy_from_slice(&nonce_user_hint(&nonce[..16], username));
    nonce[20..24] == expected
}

fn apply_nonce_user_hint(nonce: &mut [u8; NONCE_LEN], username: &str) {
    let hint = nonce_user_hint(&nonce[..16], username);
    nonce[20..24].copy_from_slice(&hint);
}

fn nonce_user_hint(nonce_prefix: &[u8], username: &str) -> [u8; 4] {
    let mut hasher = Sha256::new();
    hasher.update(username.as_bytes());
    hasher.update(nonce_prefix);
    let digest = hasher.finalize();
    [digest[0], digest[1], digest[2], digest[3]]
}

fn increment_nonce(nonce: &mut [u8; NONCE_LEN]) {
    for byte in nonce.iter_mut().rev() {
        let (next, overflow) = byte.overflowing_add(1);
        *byte = next;
        if !overflow {
            break;
        }
    }
}

fn rounded_unix_time(unix_secs: i64) -> i64 {
    ((unix_secs + KEY_WINDOW_SECS / 2) / KEY_WINDOW_SECS) * KEY_WINDOW_SECS
}

fn now_unix_secs() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs() as i64
}

fn timestamp_is_close(minutes: u32) -> bool {
    let now = (now_unix_secs() / 60) as i64;
    (now - i64::from(minutes)).abs() <= 10
}

fn active_user_list(users: &[CoreUser]) -> Vec<CoreUser> {
    users
        .iter()
        .filter(|user| !user.is_empty())
        .cloned()
        .collect()
}

fn read_socks_request_from_mieru<R: Read>(
    reader: &mut R,
    bytes: &mut Vec<u8>,
) -> io::Result<MieruSocksRequest> {
    loop {
        match parse_socks_request(bytes)? {
            SocksParseResult::Complete {
                command,
                target,
                consumed,
            } => {
                return Ok(MieruSocksRequest {
                    command,
                    target,
                    consumed,
                })
            }
            SocksParseResult::NeedMore => {
                let mut temp = [0u8; 1024];
                let read = reader.read(&mut temp)?;
                if read == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::UnexpectedEof,
                        "mieru socks request ended early",
                    ));
                }
                bytes.extend_from_slice(&temp[..read]);
            }
        }
    }
}

fn parse_socks_request(input: &[u8]) -> io::Result<SocksParseResult> {
    let Some(offset) = socks_request_offset(input)? else {
        return Ok(SocksParseResult::NeedMore);
    };
    if input.len() < offset + 4 {
        return Ok(SocksParseResult::NeedMore);
    }
    let header = &input[offset..offset + 4];
    if header[0] != SOCKS_VERSION || header[2] != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid mieru socks request header",
        ));
    }
    let command = match header[1] {
        SOCKS_CMD_CONNECT => MieruSocksCommand::TcpConnect,
        SOCKS_CMD_UDP_ASSOCIATE => MieruSocksCommand::UdpAssociate,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "mieru currently supports only socks connect and udp associate requests",
            ));
        }
    };

    let mut cursor = offset + 4;
    let host = match header[3] {
        ATYP_IPV4 => {
            if input.len() < cursor + 4 {
                return Ok(SocksParseResult::NeedMore);
            }
            let mut bytes = [0u8; 4];
            bytes.copy_from_slice(&input[cursor..cursor + 4]);
            cursor += 4;
            Ipv4Addr::from(bytes).to_string()
        }
        ATYP_IPV6 => {
            if input.len() < cursor + 16 {
                return Ok(SocksParseResult::NeedMore);
            }
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(&input[cursor..cursor + 16]);
            cursor += 16;
            Ipv6Addr::from(bytes).to_string()
        }
        ATYP_DOMAIN => {
            if input.len() < cursor + 1 {
                return Ok(SocksParseResult::NeedMore);
            }
            let len = input[cursor] as usize;
            cursor += 1;
            if input.len() < cursor + len {
                return Ok(SocksParseResult::NeedMore);
            }
            let host = String::from_utf8(input[cursor..cursor + len].to_vec()).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid mieru socks domain")
            })?;
            cursor += len;
            host
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported mieru socks address type",
            ));
        }
    };
    if input.len() < cursor + 2 {
        return Ok(SocksParseResult::NeedMore);
    }
    let port = u16::from_be_bytes([input[cursor], input[cursor + 1]]);
    cursor += 2;
    Ok(SocksParseResult::Complete {
        command,
        target: SocksTarget { host, port },
        consumed: cursor,
    })
}

fn socks_request_offset(input: &[u8]) -> io::Result<Option<usize>> {
    if input.len() < 2 {
        return Ok(None);
    }
    if input[0] != SOCKS_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "mieru payload is not a socks request",
        ));
    }
    if input.len() >= 4 && input[2] == 0 && matches!(input[3], ATYP_IPV4 | ATYP_DOMAIN | ATYP_IPV6)
    {
        return Ok(Some(0));
    }

    let greeting_len = 2 + input[1] as usize;
    if input.len() < greeting_len {
        return Ok(None);
    }
    Ok(Some(greeting_len))
}

fn connect_target(target: &SocksTarget, timeout: Duration) -> io::Result<TcpStream> {
    crate::dns::connect_tcp(&target.host, target.port, timeout)
}

fn relay_mieru_udp_associate<R, W>(
    mut reader: R,
    mut writer: W,
    mut pending: Vec<u8>,
    router: &RouteMatcher,
    timeout: Duration,
    limiter: Option<Arc<BandwidthLimiter>>,
) -> io::Result<(u64, u64)>
where
    R: Read,
    W: MieruOutput,
{
    let mut upload = 0u64;
    let mut download = 0u64;
    while let Some(packet) = read_mieru_udp_frame(&mut reader, &mut pending)? {
        let (target, payload) = parse_socks_udp_packet(&packet)?;
        if let Some(limiter) = limiter.as_deref() {
            limiter.wait_for(payload.len());
        }
        let protocol_labels = route_protocol_labels("udp", &payload);
        let response = match router.decide_target(&target.host, target.port, &protocol_labels) {
            RouteDecision::Direct => send_direct_mieru_udp(&target, &payload, timeout),
            RouteDecision::Outbound(outbound) => {
                send_udp_outbound(&outbound, &target, &payload, timeout)
            }
            RouteDecision::Block => continue,
            RouteDecision::UnsupportedOutbound(tag) => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    format!("outbound route {tag} is not implemented"),
                ));
            }
        };
        let (source, response_payload) = match response {
            Ok(response) => response,
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
                ) =>
            {
                continue;
            }
            Err(error) => return Err(error),
        };
        upload = upload.saturating_add(payload.len() as u64);
        download = download.saturating_add(response_payload.len() as u64);
        let response_target = socket_addr_to_target(source);
        let response_packet = encode_socks_udp_packet(&response_target, &response_payload)?;
        let framed = encode_mieru_udp_frame(&response_packet)?;
        writer.write_all(&framed)?;
    }
    writer.shutdown_session();
    Ok((upload, download))
}

fn read_mieru_udp_frame<R: Read>(
    reader: &mut R,
    buffer: &mut Vec<u8>,
) -> io::Result<Option<Vec<u8>>> {
    loop {
        if let Some(frame) = take_mieru_udp_frame(buffer)? {
            return Ok(Some(frame));
        }
        let mut temp = [0u8; 4096];
        let read = reader.read(&mut temp)?;
        if read == 0 {
            if buffer.is_empty() {
                return Ok(None);
            }
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "mieru udp frame ended early",
            ));
        }
        buffer.extend_from_slice(&temp[..read]);
    }
}

fn take_mieru_udp_frame(buffer: &mut Vec<u8>) -> io::Result<Option<Vec<u8>>> {
    while buffer
        .first()
        .is_some_and(|byte| *byte != MIERU_UDP_MARKER_START)
    {
        buffer.remove(0);
    }
    if buffer.len() < 4 {
        return Ok(None);
    }
    let len = u16::from_be_bytes([buffer[1], buffer[2]]) as usize;
    let total = 1 + 2 + len + 1;
    if buffer.len() < total {
        return Ok(None);
    }
    if buffer[total - 1] != MIERU_UDP_MARKER_END {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid mieru udp frame marker",
        ));
    }
    let payload = buffer[3..3 + len].to_vec();
    buffer.drain(..total);
    Ok(Some(payload))
}

fn encode_mieru_udp_frame(packet: &[u8]) -> io::Result<Vec<u8>> {
    let len = u16::try_from(packet.len()).map_err(|_| {
        io::Error::new(io::ErrorKind::InvalidInput, "mieru udp packet is too large")
    })?;
    let mut output = Vec::with_capacity(packet.len() + 4);
    output.push(MIERU_UDP_MARKER_START);
    output.extend_from_slice(&len.to_be_bytes());
    output.extend_from_slice(packet);
    output.push(MIERU_UDP_MARKER_END);
    Ok(output)
}

fn parse_socks_udp_packet(input: &[u8]) -> io::Result<(SocksTarget, Vec<u8>)> {
    if input.len() < 4 || input[0] != 0 || input[1] != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid socks udp packet header",
        ));
    }
    if input[2] != 0 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "fragmented socks udp packets are not supported",
        ));
    }
    let mut cursor = 4;
    let host = match input[3] {
        ATYP_IPV4 => {
            if input.len() < cursor + 4 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "short socks udp ipv4 address",
                ));
            }
            let mut bytes = [0u8; 4];
            bytes.copy_from_slice(&input[cursor..cursor + 4]);
            cursor += 4;
            Ipv4Addr::from(bytes).to_string()
        }
        ATYP_IPV6 => {
            if input.len() < cursor + 16 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "short socks udp ipv6 address",
                ));
            }
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(&input[cursor..cursor + 16]);
            cursor += 16;
            Ipv6Addr::from(bytes).to_string()
        }
        ATYP_DOMAIN => {
            if input.len() < cursor + 1 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "short socks udp domain length",
                ));
            }
            let len = input[cursor] as usize;
            cursor += 1;
            if input.len() < cursor + len {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "short socks udp domain",
                ));
            }
            let host = String::from_utf8(input[cursor..cursor + len].to_vec()).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid socks udp domain")
            })?;
            cursor += len;
            host
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported socks udp address type",
            ));
        }
    };
    if input.len() < cursor + 2 {
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "short socks udp port",
        ));
    }
    let port = u16::from_be_bytes([input[cursor], input[cursor + 1]]);
    cursor += 2;
    Ok((SocksTarget { host, port }, input[cursor..].to_vec()))
}

fn encode_socks_udp_packet(target: &SocksTarget, payload: &[u8]) -> io::Result<Vec<u8>> {
    let mut output = vec![0, 0, 0];
    encode_socks_target(&mut output, target)?;
    output.extend_from_slice(payload);
    Ok(output)
}

fn encode_socks_target(output: &mut Vec<u8>, target: &SocksTarget) -> io::Result<()> {
    if let Ok(ipv4) = target.host.parse::<Ipv4Addr>() {
        output.push(ATYP_IPV4);
        output.extend_from_slice(&ipv4.octets());
    } else if let Ok(ipv6) = target.host.parse::<Ipv6Addr>() {
        output.push(ATYP_IPV6);
        output.extend_from_slice(&ipv6.octets());
    } else {
        let host = target.host.as_bytes();
        let len = u8::try_from(host.len())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "socks domain is too long"))?;
        output.push(ATYP_DOMAIN);
        output.push(len);
        output.extend_from_slice(host);
    }
    output.extend_from_slice(&target.port.to_be_bytes());
    Ok(())
}

fn send_direct_mieru_udp(
    target: &SocksTarget,
    payload: &[u8],
    timeout: Duration,
) -> io::Result<(SocketAddr, Vec<u8>)> {
    let remote_addr = crate::dns::resolve_socket_addr(&target.host, target.port, timeout)?;
    let udp = UdpSocket::bind(udp_bind_addr_for_remote(remote_addr))?;
    udp.set_read_timeout(Some(timeout))?;
    udp.set_write_timeout(Some(timeout))?;
    udp.send_to(payload, remote_addr)?;
    let mut response = vec![0u8; 65_535];
    let (read, source) = recv_udp_response(&udp, &mut response)?;
    response.truncate(read);
    Ok((source, response))
}

fn udp_bind_addr_for_remote(remote: SocketAddr) -> SocketAddr {
    match remote {
        SocketAddr::V4(_) => SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0)),
        SocketAddr::V6(_) => SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
    }
}

fn socket_addr_to_target(addr: SocketAddr) -> SocksTarget {
    SocksTarget {
        host: addr.ip().to_string(),
        port: addr.port(),
    }
}

fn relay_mieru_streams<R, W>(
    mut reader: R,
    mut writer: W,
    remote: TcpStream,
    limiter: Option<Arc<BandwidthLimiter>>,
) -> io::Result<(u64, u64)>
where
    R: MieruInput + 'static,
    W: MieruOutput,
{
    let mut remote_read = remote.try_clone()?;
    let mut remote_write = remote;
    let upload_limiter = limiter.clone();
    let stop_upload = reader.stop_handle();
    let upload_task = spawn_native_blocking_relay(move || {
        let upload = copy_count_best_effort_limited(
            &mut reader,
            &mut remote_write,
            upload_limiter.as_deref(),
        );
        let _ = remote_write.shutdown(Shutdown::Write);
        upload
    })?;
    let download =
        copy_count_best_effort_limited(&mut remote_read, &mut writer, limiter.as_deref());
    if let Some(stop) = stop_upload {
        stop.store(true, Ordering::Relaxed);
    }
    writer.shutdown_session();
    let upload = join_native_blocking_relay(upload_task, "mieru upload task panicked")?;

    Ok((upload, download))
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream, UdpSocket};
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    use crate::config::{OutboundConfig, RouteAction, RouteRule};
    use crate::mieru::{
        apply_nonce_user_hint, derive_mieru_key, encode_mieru_udp_frame, encode_segment_body,
        encode_socks_udp_packet, parse_socks_request, parse_socks_udp_packet, read_mieru_udp_frame,
        rounded_unix_time, MieruMetadata, MieruReader, MieruSegment, MieruServer,
        MieruServerConfig, MieruSocksCommand, MieruWriter, SocksParseResult, DATA_CLIENT_TO_SERVER,
        DATA_SERVER_TO_CLIENT, OPEN_SESSION_REQUEST, OPEN_SESSION_RESPONSE,
        SOCKS_CMD_UDP_ASSOCIATE, SOCKS_CONNECT_SUCCESS, STATUS_OK,
    };
    use crate::user::CoreUser;

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

    #[test]
    fn key_derivation_changes_with_user_password_and_time() {
        let rounded = rounded_unix_time(1777650625);
        let key = derive_mieru_key("user-a", "pass-a", rounded);

        assert_eq!(key.len(), 32);
        assert_ne!(key, derive_mieru_key("user-b", "pass-a", rounded));
        assert_ne!(key, derive_mieru_key("user-a", "pass-b", rounded));
        assert_ne!(key, derive_mieru_key("user-a", "pass-a", rounded + 120));
    }

    #[test]
    fn parses_socks_request_with_optional_greeting() {
        let request = vec![
            0x05, 0x01, 0x00, 0x05, 0x01, 0x00, 0x03, 11, b'e', b'x', b'a', b'm', b'p', b'l', b'e',
            b'.', b'c', b'o', b'm', 0x01, 0xbb,
        ];

        let parsed = parse_socks_request(&request).expect("parse");

        assert_eq!(
            parsed,
            SocksParseResult::Complete {
                command: MieruSocksCommand::TcpConnect,
                target: crate::socks5::SocksTarget {
                    host: "example.com".to_string(),
                    port: 443
                },
                consumed: request.len()
            }
        );
    }

    #[test]
    fn decodes_first_segment_with_nonce_hint() {
        let user = user();
        let mut stream_bytes = Vec::new();
        let mut nonce = [7u8; 24];
        apply_nonce_user_hint(&mut nonce, &user.uuid);
        stream_bytes.extend_from_slice(&[0xaa, 0xbb]);
        stream_bytes.extend_from_slice(&nonce);
        let mut write_nonce = nonce;
        let key = derive_mieru_key(
            &user.uuid,
            &user.uuid,
            rounded_unix_time(super::now_unix_secs()),
        );
        let metadata = MieruMetadata {
            protocol_type: OPEN_SESSION_REQUEST,
            session_id: 42,
            sequence: 0,
            status_code: STATUS_OK,
            payload_len: 4,
            prefix_len: 0,
            suffix_len: 0,
        };
        encode_segment_body(
            &mut stream_bytes,
            &key,
            &mut write_nonce,
            &metadata,
            b"ping",
        )
        .expect("encode");

        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let sender = thread::spawn(move || {
            let mut client = TcpStream::connect(addr).expect("connect");
            client.write_all(&stream_bytes).expect("write");
        });
        let (server, _) = listener.accept().expect("accept");
        let mut reader = MieruReader::accept(server, &[user]).expect("accept mieru");

        assert_eq!(reader.session_id(), 42);
        let initial = reader.take_initial_segment().expect("initial");
        assert_eq!(initial.metadata.protocol_type, OPEN_SESSION_REQUEST);
        assert_eq!(initial.payload, b"ping");
        sender.join().expect("sender");
    }

    #[test]
    fn server_proxies_mieru_tcp_connect() {
        let echo = TcpListener::bind("127.0.0.1:0").expect("echo bind");
        let echo_addr = echo.local_addr().expect("echo addr");
        let echo_thread = thread::spawn(move || {
            let (mut stream, _) = echo.accept().expect("echo accept");
            let mut bytes = [0u8; 4];
            stream.read_exact(&mut bytes).expect("echo read");
            stream.write_all(&bytes).expect("echo write");
        });

        let server = MieruServer::new(MieruServerConfig {
            node_tag: "panel|mieru|1".to_string(),
            listen: "127.0.0.1:0".parse().unwrap(),
            users: vec![user()],
            routes: Vec::new(),
            connect_timeout: Duration::from_secs(5),
        });
        let listener = server.bind().expect("server bind");
        let listen_addr = listener.local_addr().expect("listen addr");
        let server_thread = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            server.handle_tcp_client(stream).expect("handle");
            server.drain_traffic(1)
        });

        let client = TcpStream::connect(listen_addr).expect("connect");
        let mut writer = test_client_writer(client.try_clone().expect("clone"), &user(), 9);
        let request = socks_connect_request(echo_addr);
        writer
            .write_client_segment(OPEN_SESSION_REQUEST, &request)
            .expect("open");
        let mut reader = MieruReader::accept(client, &[user()]).expect("client reader");
        let open_response = reader.take_initial_segment().expect("open");
        assert_eq!(open_response.metadata.protocol_type, OPEN_SESSION_RESPONSE);
        assert_socks_connect_success(&mut reader);

        writer
            .write_client_segment(DATA_CLIENT_TO_SERVER, b"ping")
            .expect("data");
        let mut echoed = [0u8; 4];
        reader.read_exact(&mut echoed).expect("read echo");
        assert_eq!(&echoed, b"ping");

        drop(writer);
        echo_thread.join().expect("echo thread");
        let records = server_thread.join().expect("server thread");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].user_id, Some(1));
        assert_eq!(records[0].upload, 4);
        assert_eq!(records[0].download, 4);
    }

    #[test]
    fn server_proxies_mieru_udp_associate() {
        let udp = UdpSocket::bind("127.0.0.1:0").expect("udp bind");
        let udp_addr = udp.local_addr().expect("udp addr");
        let udp_thread = thread::spawn(move || {
            let mut bytes = [0u8; 16];
            let (read, peer) = udp.recv_from(&mut bytes).expect("udp read");
            assert_eq!(&bytes[..read], b"ping");
            udp.send_to(b"pong", peer).expect("udp write");
        });

        let server = MieruServer::new(MieruServerConfig {
            node_tag: "panel|mieru|1".to_string(),
            listen: "127.0.0.1:0".parse().unwrap(),
            users: vec![user()],
            routes: Vec::new(),
            connect_timeout: Duration::from_secs(5),
        });
        let listener = server.bind().expect("server bind");
        let listen_addr = listener.local_addr().expect("listen addr");
        let server_thread = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            server.handle_tcp_client(stream).expect("handle");
            server.drain_traffic(1)
        });

        let client = TcpStream::connect(listen_addr).expect("connect");
        let mut writer = test_client_writer(client.try_clone().expect("clone"), &user(), 19);
        writer
            .write_client_segment(OPEN_SESSION_REQUEST, &socks_udp_associate_request())
            .expect("open");
        let mut reader = MieruReader::accept(client, &[user()]).expect("client reader");
        let open_response = reader.take_initial_segment().expect("open");
        assert_eq!(open_response.metadata.protocol_type, OPEN_SESSION_RESPONSE);
        assert_socks_connect_success(&mut reader);

        let udp_packet = encode_socks_udp_packet(
            &crate::socks5::SocksTarget {
                host: udp_addr.ip().to_string(),
                port: udp_addr.port(),
            },
            b"ping",
        )
        .expect("encode socks udp");
        let frame = encode_mieru_udp_frame(&udp_packet).expect("encode mieru udp");
        writer
            .write_client_segment(DATA_CLIENT_TO_SERVER, &frame)
            .expect("write udp");

        let response_frame =
            read_mieru_udp_frame(&mut reader, &mut Vec::new()).expect("read frame");
        let (response_target, response_payload) =
            parse_socks_udp_packet(&response_frame.expect("response frame")).expect("parse udp");
        assert_eq!(response_target.host, udp_addr.ip().to_string());
        assert_eq!(response_target.port, udp_addr.port());
        assert_eq!(response_payload, b"pong");

        drop(writer);
        drop(reader);
        udp_thread.join().expect("udp thread");
        let records = server_thread.join().expect("server thread");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].upload, 4);
        assert_eq!(records[0].download, 4);
    }

    #[test]
    fn server_proxies_multiplexed_mieru_tcp_sessions() {
        let echo_a = TcpListener::bind("127.0.0.1:0").expect("echo a bind");
        let echo_a_addr = echo_a.local_addr().expect("echo a addr");
        let echo_a_thread = thread::spawn(move || {
            let (mut stream, _) = echo_a.accept().expect("echo a accept");
            let mut bytes = [0u8; 3];
            stream.read_exact(&mut bytes).expect("echo a read");
            assert_eq!(&bytes, b"one");
            stream.write_all(b"eno").expect("echo a write");
        });
        let echo_b = TcpListener::bind("127.0.0.1:0").expect("echo b bind");
        let echo_b_addr = echo_b.local_addr().expect("echo b addr");
        let echo_b_thread = thread::spawn(move || {
            let (mut stream, _) = echo_b.accept().expect("echo b accept");
            let mut bytes = [0u8; 3];
            stream.read_exact(&mut bytes).expect("echo b read");
            assert_eq!(&bytes, b"two");
            stream.write_all(b"owt").expect("echo b write");
        });

        let server = MieruServer::new(MieruServerConfig {
            node_tag: "panel|mieru|1".to_string(),
            listen: "127.0.0.1:0".parse().unwrap(),
            users: vec![user()],
            routes: Vec::new(),
            connect_timeout: Duration::from_secs(5),
        });
        let listener = server.bind().expect("server bind");
        let listen_addr = listener.local_addr().expect("listen addr");
        let server_thread = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            server.handle_tcp_client(stream).expect("handle");
            server.drain_traffic(1)
        });

        let client = TcpStream::connect(listen_addr).expect("connect");
        let mut writer = test_client_writer(client.try_clone().expect("clone"), &user(), 31);
        writer
            .write_client_segment_for_session(
                31,
                OPEN_SESSION_REQUEST,
                &socks_connect_request(echo_a_addr),
            )
            .expect("open a");
        writer
            .write_client_segment_for_session(
                32,
                OPEN_SESSION_REQUEST,
                &socks_connect_request(echo_b_addr),
            )
            .expect("open b");

        let mut reader = MieruReader::accept(client, &[user()]).expect("client reader");
        let mut opened = Vec::new();
        let mut socks_ok = Vec::new();
        while opened.len() < 2 || socks_ok.len() < 2 {
            let segment = next_mieru_segment(&mut reader).expect("session setup segment");
            match segment.metadata.protocol_type {
                OPEN_SESSION_RESPONSE => opened.push(segment.metadata.session_id),
                DATA_SERVER_TO_CLIENT if segment.payload == SOCKS_CONNECT_SUCCESS => {
                    socks_ok.push(segment.metadata.session_id)
                }
                _ => {}
            }
        }
        opened.sort_unstable();
        socks_ok.sort_unstable();
        assert_eq!(opened, vec![31, 32]);
        assert_eq!(socks_ok, vec![31, 32]);

        writer
            .write_client_segment_for_session(31, DATA_CLIENT_TO_SERVER, b"one")
            .expect("data a");
        writer
            .write_client_segment_for_session(32, DATA_CLIENT_TO_SERVER, b"two")
            .expect("data b");

        let mut responses = Vec::new();
        while responses.len() < 2 {
            let segment = next_mieru_segment(&mut reader).expect("response segment");
            if segment.metadata.protocol_type == DATA_SERVER_TO_CLIENT
                && segment.payload != SOCKS_CONNECT_SUCCESS
            {
                responses.push((segment.metadata.session_id, segment.payload));
            }
        }
        responses.sort_by_key(|(session_id, _)| *session_id);
        assert_eq!(responses[0], (31, b"eno".to_vec()));
        assert_eq!(responses[1], (32, b"owt".to_vec()));

        writer.shutdown_write();
        drop(reader);
        echo_a_thread.join().expect("echo a thread");
        echo_b_thread.join().expect("echo b thread");
        let records = server_thread.join().expect("server thread");
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].upload, 6);
        assert_eq!(records[0].download, 6);
    }

    #[test]
    fn block_route_rejects_mieru_tcp_connect() {
        let server = MieruServer::new(MieruServerConfig {
            node_tag: "panel|mieru|1".to_string(),
            listen: "127.0.0.1:0".parse().unwrap(),
            users: vec![user()],
            routes: vec![RouteRule {
                targets: vec!["domain:blocked.example".to_string()],
                action: RouteAction::Block,
                outbound: None,
            }],
            connect_timeout: Duration::from_secs(5),
        });
        let listener = server.bind().expect("server bind");
        let listen_addr = listener.local_addr().expect("listen addr");
        let server_thread = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            let err = server
                .handle_tcp_client(stream)
                .expect_err("block route should reject");
            assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);
        });

        let client = TcpStream::connect(listen_addr).expect("connect");
        let mut writer = test_client_writer(client.try_clone().expect("clone"), &user(), 90);
        writer
            .write_client_segment(
                OPEN_SESSION_REQUEST,
                &socks_connect_domain_request("blocked.example", 443),
            )
            .expect("open");

        let err = MieruReader::accept(client, &[user()]).expect_err("server should close");
        assert_eq!(err.kind(), std::io::ErrorKind::UnexpectedEof);
        drop(writer);
        server_thread.join().expect("server thread");
    }

    #[test]
    fn route_rule_sends_mieru_tcp_connect_through_socks_outbound() {
        let proxy = TcpListener::bind("127.0.0.1:0").expect("proxy bind");
        let proxy_addr = proxy.local_addr().expect("proxy addr");
        let (target_tx, target_rx) = mpsc::channel();
        let proxy_thread = thread::spawn(move || {
            let (mut stream, _) = proxy.accept().expect("accept proxy");
            let mut hello = [0u8; 3];
            stream.read_exact(&mut hello).expect("hello");
            assert_eq!(hello, [0x05, 0x01, 0x00]);
            stream.write_all(&[0x05, 0x00]).expect("method");
            let target = read_socks5_connect_target(&mut stream).expect("connect target");
            target_tx.send(target).expect("send target");
            stream
                .write_all(&[0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0, 0])
                .expect("connect ok");
            let mut payload = [0u8; 4];
            stream.read_exact(&mut payload).expect("payload");
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong").expect("response");
        });

        let server = MieruServer::new(MieruServerConfig {
            node_tag: "panel|mieru|1".to_string(),
            listen: "127.0.0.1:0".parse().unwrap(),
            users: vec![user()],
            routes: vec![RouteRule {
                targets: vec!["domain:example.com".to_string()],
                action: RouteAction::Outbound("socks-out".to_string()),
                outbound: Some(OutboundConfig {
                    tag: "socks-out".to_string(),
                    protocol: "socks".to_string(),
                    method: None,
                    alter_id: None,
                    address: Some(proxy_addr.ip().to_string()),
                    port: Some(proxy_addr.port()),
                    username: None,
                    password: None,
                    tls: None,
                    transport: None,
                }),
            }],
            connect_timeout: Duration::from_secs(5),
        });
        let listener = server.bind().expect("server bind");
        let listen_addr = listener.local_addr().expect("listen addr");
        let server_thread = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            server.handle_tcp_client(stream).expect("handle");
            server.drain_traffic(1)
        });

        let client = TcpStream::connect(listen_addr).expect("connect");
        let mut writer = test_client_writer(client.try_clone().expect("clone"), &user(), 91);
        writer
            .write_client_segment(
                OPEN_SESSION_REQUEST,
                &socks_connect_domain_request("example.com", 443),
            )
            .expect("open");
        let mut reader = MieruReader::accept(client, &[user()]).expect("client reader");
        assert_eq!(
            reader
                .take_initial_segment()
                .expect("open response")
                .metadata
                .protocol_type,
            OPEN_SESSION_RESPONSE
        );
        assert_socks_connect_success(&mut reader);
        writer
            .write_client_segment(DATA_CLIENT_TO_SERVER, b"ping")
            .expect("data");
        let mut echoed = [0u8; 4];
        reader.read_exact(&mut echoed).expect("read echo");
        assert_eq!(&echoed, b"pong");

        let target = target_rx.recv().expect("target");
        assert_eq!(target.host, "example.com");
        assert_eq!(target.port, 443);
        drop(writer);
        proxy_thread.join().expect("proxy thread");
        let records = server_thread.join().expect("server thread");
        assert_eq!(records[0].upload, 4);
        assert_eq!(records[0].download, 4);
    }

    #[test]
    fn route_rule_rewrites_mieru_tcp_connect_through_freedom_outbound() {
        let echo = TcpListener::bind("127.0.0.1:0").expect("echo bind");
        let echo_addr = echo.local_addr().expect("echo addr");
        let echo_thread = thread::spawn(move || {
            let (mut stream, _) = echo.accept().expect("echo accept");
            let mut bytes = [0u8; 4];
            stream.read_exact(&mut bytes).expect("echo read");
            assert_eq!(&bytes, b"ping");
            stream.write_all(b"pong").expect("echo write");
        });

        let server = MieruServer::new(MieruServerConfig {
            node_tag: "panel|mieru|1".to_string(),
            listen: "127.0.0.1:0".parse().unwrap(),
            users: vec![user()],
            routes: vec![RouteRule {
                targets: vec!["domain:example.com".to_string()],
                action: RouteAction::Outbound("freedom-out".to_string()),
                outbound: Some(OutboundConfig {
                    tag: "freedom-out".to_string(),
                    protocol: "freedom".to_string(),
                    method: None,
                    alter_id: None,
                    address: Some(echo_addr.ip().to_string()),
                    port: Some(echo_addr.port()),
                    username: None,
                    password: None,
                    tls: None,
                    transport: None,
                }),
            }],
            connect_timeout: Duration::from_secs(5),
        });
        let listener = server.bind().expect("server bind");
        let listen_addr = listener.local_addr().expect("listen addr");
        let server_thread = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            server.handle_tcp_client(stream).expect("handle");
            server.drain_traffic(1)
        });

        let client = TcpStream::connect(listen_addr).expect("connect");
        let mut writer = test_client_writer(client.try_clone().expect("clone"), &user(), 93);
        writer
            .write_client_segment(
                OPEN_SESSION_REQUEST,
                &socks_connect_domain_request("example.com", 443),
            )
            .expect("open");
        let mut reader = MieruReader::accept(client, &[user()]).expect("client reader");
        assert_eq!(
            reader
                .take_initial_segment()
                .expect("open response")
                .metadata
                .protocol_type,
            OPEN_SESSION_RESPONSE
        );
        assert_socks_connect_success(&mut reader);
        writer
            .write_client_segment(DATA_CLIENT_TO_SERVER, b"ping")
            .expect("data");
        let mut echoed = [0u8; 4];
        reader.read_exact(&mut echoed).expect("read echo");
        assert_eq!(&echoed, b"pong");

        drop(writer);
        drop(reader);
        echo_thread.join().expect("echo thread");
        let records = server_thread.join().expect("server thread");
        assert_eq!(records[0].upload, 4);
        assert_eq!(records[0].download, 4);
    }

    #[test]
    fn route_rule_sends_mieru_udp_associate_through_socks_outbound() {
        let proxy = TcpListener::bind("127.0.0.1:0").expect("proxy bind");
        let proxy_addr = proxy.local_addr().expect("proxy addr");
        let relay = UdpSocket::bind("127.0.0.1:0").expect("relay bind");
        let relay_addr = relay.local_addr().expect("relay addr");
        let (target_tx, target_rx) = mpsc::channel();
        let proxy_thread = thread::spawn(move || {
            let (mut control, _) = proxy.accept().expect("accept proxy");
            let mut hello = [0u8; 3];
            control.read_exact(&mut hello).expect("hello");
            assert_eq!(hello, [0x05, 0x01, 0x00]);
            control.write_all(&[0x05, 0x00]).expect("method");

            let mut request = [0u8; 10];
            control.read_exact(&mut request).expect("udp associate");
            assert_eq!(&request[..4], &[0x05, 0x03, 0x00, 0x01]);
            control
                .write_all(&[
                    0x05,
                    0x00,
                    0x00,
                    0x01,
                    127,
                    0,
                    0,
                    1,
                    (relay_addr.port() >> 8) as u8,
                    relay_addr.port() as u8,
                ])
                .expect("udp relay reply");

            let mut bytes = [0u8; 512];
            let (read, peer) = relay.recv_from(&mut bytes).expect("relay udp read");
            let (target, payload) =
                parse_socks_udp_packet(&bytes[..read]).expect("parse relay packet");
            target_tx.send(target).expect("send target");
            assert_eq!(payload, b"ping");
            let response = encode_socks_udp_packet(
                &crate::socks5::SocksTarget {
                    host: "127.0.0.1".to_string(),
                    port: 5353,
                },
                b"pong",
            )
            .expect("encode relay response");
            relay.send_to(&response, peer).expect("relay udp write");
        });

        let server = MieruServer::new(MieruServerConfig {
            node_tag: "panel|mieru|1".to_string(),
            listen: "127.0.0.1:0".parse().unwrap(),
            users: vec![user()],
            routes: vec![RouteRule {
                targets: vec!["domain:example.com".to_string()],
                action: RouteAction::Outbound("socks-out".to_string()),
                outbound: Some(OutboundConfig {
                    tag: "socks-out".to_string(),
                    protocol: "socks".to_string(),
                    method: None,
                    alter_id: None,
                    address: Some(proxy_addr.ip().to_string()),
                    port: Some(proxy_addr.port()),
                    username: None,
                    password: None,
                    tls: None,
                    transport: None,
                }),
            }],
            connect_timeout: Duration::from_secs(5),
        });
        let listener = server.bind().expect("server bind");
        let listen_addr = listener.local_addr().expect("listen addr");
        let server_thread = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            server.handle_tcp_client(stream).expect("handle");
            server.drain_traffic(1)
        });

        let client = TcpStream::connect(listen_addr).expect("connect");
        let mut writer = test_client_writer(client.try_clone().expect("clone"), &user(), 92);
        writer
            .write_client_segment(OPEN_SESSION_REQUEST, &socks_udp_associate_request())
            .expect("open");
        let mut reader = MieruReader::accept(client, &[user()]).expect("client reader");
        let open_response = reader.take_initial_segment().expect("open");
        assert_eq!(open_response.metadata.protocol_type, OPEN_SESSION_RESPONSE);
        assert_socks_connect_success(&mut reader);

        let udp_packet = encode_socks_udp_packet(
            &crate::socks5::SocksTarget {
                host: "example.com".to_string(),
                port: 53,
            },
            b"ping",
        )
        .expect("encode socks udp");
        let frame = encode_mieru_udp_frame(&udp_packet).expect("encode mieru udp");
        writer
            .write_client_segment(DATA_CLIENT_TO_SERVER, &frame)
            .expect("write udp");

        let response_frame =
            read_mieru_udp_frame(&mut reader, &mut Vec::new()).expect("read frame");
        let (response_target, response_payload) =
            parse_socks_udp_packet(&response_frame.expect("response frame")).expect("parse udp");
        assert_eq!(response_target.host, "127.0.0.1");
        assert_eq!(response_target.port, 5353);
        assert_eq!(response_payload, b"pong");

        let target = target_rx.recv().expect("target");
        assert_eq!(target.host, "example.com");
        assert_eq!(target.port, 53);
        drop(writer);
        drop(reader);
        proxy_thread.join().expect("proxy thread");
        let records = server_thread.join().expect("server thread");
        assert_eq!(records[0].upload, 4);
        assert_eq!(records[0].download, 4);
    }

    #[test]
    fn wildcard_route_sends_mieru_tcp_connect_through_http_outbound() {
        let proxy = TcpListener::bind("127.0.0.1:0").expect("proxy bind");
        let proxy_addr = proxy.local_addr().expect("proxy addr");
        let (request_tx, request_rx) = mpsc::channel();
        let proxy_thread = thread::spawn(move || {
            let (mut stream, _) = proxy.accept().expect("accept proxy");
            let request = read_http_connect_request(&mut stream).expect("connect request");
            request_tx.send(request).expect("send request");
            stream
                .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                .expect("response");
            let mut payload = [0u8; 4];
            stream.read_exact(&mut payload).expect("payload");
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong").expect("response payload");
        });

        let server = MieruServer::new(MieruServerConfig {
            node_tag: "panel|mieru|1".to_string(),
            listen: "127.0.0.1:0".parse().unwrap(),
            users: vec![user()],
            routes: vec![RouteRule {
                targets: vec!["*".to_string()],
                action: RouteAction::Outbound("http-out".to_string()),
                outbound: Some(OutboundConfig {
                    tag: "http-out".to_string(),
                    protocol: "http".to_string(),
                    method: None,
                    alter_id: None,
                    address: Some(proxy_addr.ip().to_string()),
                    port: Some(proxy_addr.port()),
                    username: Some("user".to_string()),
                    password: Some("pass".to_string()),
                    tls: None,
                    transport: None,
                }),
            }],
            connect_timeout: Duration::from_secs(5),
        });
        let listener = server.bind().expect("server bind");
        let listen_addr = listener.local_addr().expect("listen addr");
        let server_thread = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            server.handle_tcp_client(stream).expect("handle");
            server.drain_traffic(1)
        });

        let client = TcpStream::connect(listen_addr).expect("connect");
        let mut writer = test_client_writer(client.try_clone().expect("clone"), &user(), 92);
        writer
            .write_client_segment(
                OPEN_SESSION_REQUEST,
                &socks_connect_domain_request("default.example", 8443),
            )
            .expect("open");
        let mut reader = MieruReader::accept(client, &[user()]).expect("client reader");
        assert_eq!(
            reader
                .take_initial_segment()
                .expect("open response")
                .metadata
                .protocol_type,
            OPEN_SESSION_RESPONSE
        );
        assert_socks_connect_success(&mut reader);
        writer
            .write_client_segment(DATA_CLIENT_TO_SERVER, b"ping")
            .expect("data");
        let mut echoed = [0u8; 4];
        reader.read_exact(&mut echoed).expect("read echo");
        assert_eq!(&echoed, b"pong");

        let request = request_rx.recv().expect("request");
        assert!(request.starts_with("CONNECT default.example:8443 HTTP/1.1\r\n"));
        assert!(request.contains("Proxy-Authorization: Basic dXNlcjpwYXNz\r\n"));
        drop(writer);
        proxy_thread.join().expect("proxy thread");
        let records = server_thread.join().expect("server thread");
        assert_eq!(records[0].upload, 4);
        assert_eq!(records[0].download, 4);
    }

    struct TestClientWriter {
        inner: MieruWriter,
    }

    impl TestClientWriter {
        fn write_client_segment_for_session(
            &mut self,
            session_id: u32,
            protocol_type: u8,
            payload: &[u8],
        ) -> std::io::Result<()> {
            let metadata = MieruMetadata {
                protocol_type,
                session_id,
                sequence: self.inner.sequence,
                status_code: STATUS_OK,
                payload_len: payload.len(),
                prefix_len: 0,
                suffix_len: 0,
            };
            self.inner.sequence += 1;
            self.inner.write_segment(metadata, payload)
        }

        fn write_client_segment(
            &mut self,
            protocol_type: u8,
            payload: &[u8],
        ) -> std::io::Result<()> {
            self.write_client_segment_for_session(self.inner.session_id, protocol_type, payload)
        }

        fn shutdown_write(&mut self) {
            let _ = self.inner.stream.shutdown(std::net::Shutdown::Write);
        }
    }

    fn test_client_writer(stream: TcpStream, user: &CoreUser, session_id: u32) -> TestClientWriter {
        let mut writer = MieruWriter::server(stream, user, session_id).expect("writer");
        writer.sent_nonce = false;
        TestClientWriter { inner: writer }
    }

    fn socks_connect_request(addr: std::net::SocketAddr) -> Vec<u8> {
        let mut request = vec![0x05, 0x01, 0x00];
        match addr.ip() {
            std::net::IpAddr::V4(ip) => {
                request.push(0x01);
                request.extend_from_slice(&ip.octets());
            }
            std::net::IpAddr::V6(ip) => {
                request.push(0x04);
                request.extend_from_slice(&ip.octets());
            }
        }
        request.extend_from_slice(&addr.port().to_be_bytes());
        request
    }

    fn socks_connect_domain_request(host: &str, port: u16) -> Vec<u8> {
        let host_bytes = host.as_bytes();
        assert!(host_bytes.len() <= u8::MAX as usize);
        let mut request = vec![0x05, 0x01, 0x00, 0x03, host_bytes.len() as u8];
        request.extend_from_slice(host_bytes);
        request.extend_from_slice(&port.to_be_bytes());
        request
    }

    fn socks_udp_associate_request() -> Vec<u8> {
        vec![0x05, SOCKS_CMD_UDP_ASSOCIATE, 0x00, 0x01, 0, 0, 0, 0, 0, 0]
    }

    fn read_socks5_connect_target(stream: &mut TcpStream) -> std::io::Result<crate::SocksTarget> {
        let mut header = [0u8; 4];
        stream.read_exact(&mut header)?;
        assert_eq!(&header[..3], &[0x05, 0x01, 0x00]);
        let host = match header[3] {
            0x01 => {
                let mut bytes = [0u8; 4];
                stream.read_exact(&mut bytes)?;
                std::net::Ipv4Addr::from(bytes).to_string()
            }
            0x03 => {
                let mut len = [0u8; 1];
                stream.read_exact(&mut len)?;
                let mut bytes = vec![0u8; usize::from(len[0])];
                stream.read_exact(&mut bytes)?;
                String::from_utf8(bytes).expect("domain utf8")
            }
            0x04 => {
                let mut bytes = [0u8; 16];
                stream.read_exact(&mut bytes)?;
                std::net::Ipv6Addr::from(bytes).to_string()
            }
            other => panic!("unsupported atyp {other}"),
        };
        let mut port = [0u8; 2];
        stream.read_exact(&mut port)?;
        Ok(crate::SocksTarget {
            host,
            port: u16::from_be_bytes(port),
        })
    }

    fn read_http_connect_request(stream: &mut TcpStream) -> std::io::Result<String> {
        let mut request = Vec::new();
        let mut byte = [0u8; 1];
        while !request.ends_with(b"\r\n\r\n") {
            stream.read_exact(&mut byte)?;
            request.push(byte[0]);
        }
        String::from_utf8(request)
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::InvalidData, "invalid utf8"))
    }

    fn assert_socks_connect_success(reader: &mut MieruReader) {
        let mut reply = [0u8; 10];
        reader.read_exact(&mut reply).expect("socks success reply");
        assert_eq!(reply, SOCKS_CONNECT_SUCCESS);
    }

    fn next_mieru_segment(reader: &mut MieruReader) -> std::io::Result<MieruSegment> {
        if let Some(segment) = reader.take_initial_segment() {
            return Ok(segment);
        }
        reader
            .read_segment()?
            .ok_or_else(|| std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "no segment"))
    }

    #[test]
    fn writer_emits_data_segments() {
        let test_user = user();
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server_thread = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            let mut reader = MieruReader::accept(stream, &[test_user]).expect("reader");
            let segment = reader.read_segment().expect("read").expect("segment");
            assert_eq!(segment.metadata.protocol_type, DATA_SERVER_TO_CLIENT);
            assert_eq!(segment.payload, b"pong");
        });
        let client = TcpStream::connect(addr).expect("connect");
        let mut writer = MieruWriter::server(client, &user(), 10).expect("writer");
        writer.write_open_response().expect("open response");
        writer.write_all(b"pong").expect("write");
        server_thread.join().expect("server thread");
    }

    #[test]
    fn reader_read_trait_accepts_server_to_client_data() {
        let test_user = user();
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server_thread = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            let mut reader = MieruReader::accept(stream, &[test_user]).expect("reader");
            let initial = reader.take_initial_segment().expect("initial");
            assert_eq!(initial.metadata.protocol_type, OPEN_SESSION_RESPONSE);
            let mut bytes = [0u8; 4];
            reader.read_exact(&mut bytes).expect("read bytes");
            assert_eq!(&bytes, b"pong");
        });
        let client = TcpStream::connect(addr).expect("connect");
        let mut writer = MieruWriter::server(client, &user(), 10).expect("writer");
        writer.write_open_response().expect("open response");
        writer.write_all(b"pong").expect("write");
        writer.shutdown();
        server_thread.join().expect("server thread");
    }

    #[test]
    fn reader_decodes_client_data_after_open_request() {
        let test_user = user();
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server_thread = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            let mut reader = MieruReader::accept(stream, &[test_user]).expect("reader");
            let initial = reader.take_initial_segment().expect("initial");
            assert_eq!(initial.metadata.protocol_type, OPEN_SESSION_REQUEST);
            let mut bytes = [0u8; 4];
            reader.read_exact(&mut bytes).expect("read data");
            assert_eq!(&bytes, b"ping");
        });
        let client = TcpStream::connect(addr).expect("connect");
        let mut writer = test_client_writer(client, &user(), 11);
        writer
            .write_client_segment(OPEN_SESSION_REQUEST, &socks_connect_request(addr))
            .expect("open");
        writer
            .write_client_segment(DATA_CLIENT_TO_SERVER, b"ping")
            .expect("data");
        server_thread.join().expect("server thread");
    }

    #[test]
    fn full_duplex_open_response_then_client_data() {
        let test_user = user();
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let addr = listener.local_addr().expect("addr");
        let server_thread = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("accept");
            let mut reader =
                MieruReader::accept(stream.try_clone().expect("clone"), &[test_user.clone()])
                    .expect("reader");
            let initial = reader.take_initial_segment().expect("initial");
            assert_eq!(initial.metadata.protocol_type, OPEN_SESSION_REQUEST);
            let mut writer =
                MieruWriter::server(stream, &test_user, reader.session_id()).expect("writer");
            writer.write_open_response().expect("open response");
            let mut bytes = [0u8; 4];
            reader.read_exact(&mut bytes).expect("read data");
            assert_eq!(&bytes, b"ping");
        });
        let client = TcpStream::connect(addr).expect("connect");
        let mut writer = test_client_writer(client.try_clone().expect("clone"), &user(), 12);
        writer
            .write_client_segment(OPEN_SESSION_REQUEST, &socks_connect_request(addr))
            .expect("open");
        let mut reader = MieruReader::accept(client, &[user()]).expect("client reader");
        let response = reader.take_initial_segment().expect("response");
        assert_eq!(response.metadata.protocol_type, OPEN_SESSION_RESPONSE);
        writer
            .write_client_segment(DATA_CLIENT_TO_SERVER, b"ping")
            .expect("data");
        server_thread.join().expect("server thread");
    }
}
