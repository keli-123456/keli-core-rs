use std::fmt;
use std::io::{self, Read, Write};
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use bytes::{Buf, Bytes};
use http::{Request, Response, StatusCode, Uri};
use quinn::crypto::rustls::QuicServerConfig;
use tokio::sync::mpsc::{channel, Receiver, Sender};
use tokio_rustls::TlsAcceptor as TokioTlsAcceptor;

use crate::abuse::ClientFailureBackoff;
use crate::limits::{
    sync_user_limit_delta, BandwidthLimiter, UserBandwidthLimiters, UserSessionTracker,
};
use crate::quic_resources::SharedQuicConnectionLimiter;
use crate::quic_tuning::{
    apply_proxy_quic_transport_defaults, apply_quic_congestion_control, proxy_quic_tuning_snapshot,
    server_endpoint_with_tuned_udp_socket,
};
use crate::socket_bind::bind_dual_stack_tcp_listener;
use crate::stream::{
    copy_count_best_effort_limited, join_native_blocking_relay, spawn_native_blocking_relay,
};
use crate::tls::server_config_from_files;
use crate::tls::{classify_tls_handshake_error, TlsHandshakeErrorClass};
use crate::traffic::{SharedTrafficRegistry, TrafficDelta, TrafficRegistry};
use crate::user::{CoreUser, CoreUserDelta, CoreUserDeltaResult, UserStore};
use crate::{connect_tcp_outbound_tokio, RouteDecision, RouteMatcher, SocksTarget};

const PADDING_FRAMES: u8 = 8;
const MAX_PADDED_PAYLOAD: usize = u16::MAX as usize;
const H2_BODY_CHANNEL_CAPACITY: usize = 64;
const NAIVE_QUIC_STOP_POLL_INTERVAL_MS: u64 = 100;
const NAIVE_QUIC_ENDPOINT_STOP_WAIT: Duration = Duration::from_secs(1);

type H3BidiStream = h3_quinn::BidiStream<Bytes>;
type H3SendStream = h3_quinn::SendStream<Bytes>;
type H3RecvStream = h3_quinn::RecvStream;
type H3ServerStream = h3::server::RequestStream<H3BidiStream, Bytes>;
type H3ServerSendStream = h3::server::RequestStream<H3SendStream, Bytes>;
type H3ServerRecvStream = h3::server::RequestStream<H3RecvStream, Bytes>;

#[derive(Clone, Debug)]
pub struct NaiveServerConfig {
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
}

#[derive(Clone)]
pub struct NaiveServer {
    config: NaiveServerConfig,
    users: UserStore,
    router: RouteMatcher,
    traffic: SharedTrafficRegistry,
    sessions: UserSessionTracker,
    bandwidth: UserBandwidthLimiters,
    tls_failures: ClientFailureBackoff,
    auth_failures: ClientFailureBackoff,
    tls_acceptor: TokioTlsAcceptor,
    quic_connections: SharedQuicConnectionLimiter,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct NaiveRequest {
    user_uuid: String,
    user_id: u64,
    target: SocksTarget,
    client_ip: Option<IpAddr>,
    padding: bool,
}

struct H2BodyReader {
    rx: Receiver<Bytes>,
    buffer: Bytes,
    offset: usize,
}

#[derive(Clone)]
struct H2BodyWriter {
    tx: Sender<Bytes>,
}

struct NaivePaddedReader<R> {
    inner: R,
    frames_done: u8,
    header: [u8; 3],
    header_pos: usize,
    data_remaining: usize,
    padding_remaining: usize,
    pending_padding: usize,
}

struct NaivePaddedWriter<W> {
    inner: W,
    frames_done: u8,
}

impl fmt::Debug for NaiveServer {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("NaiveServer")
            .field("node_tag", &self.config.node_tag)
            .field("listen", &self.config.listen)
            .field("users", &self.users.len())
            .finish_non_exhaustive()
    }
}

impl NaiveServer {
    pub fn new(config: NaiveServerConfig) -> io::Result<Self> {
        Self::with_traffic(config, TrafficRegistry::shared())
    }

    pub fn with_traffic(
        config: NaiveServerConfig,
        traffic: SharedTrafficRegistry,
    ) -> io::Result<Self> {
        Self::with_shared_limits(
            config,
            traffic,
            UserSessionTracker::default(),
            UserBandwidthLimiters::default(),
        )
    }

    pub fn with_shared_limits(
        config: NaiveServerConfig,
        traffic: SharedTrafficRegistry,
        sessions: UserSessionTracker,
        bandwidth: UserBandwidthLimiters,
    ) -> io::Result<Self> {
        Self::with_shared_limits_and_backoff(
            config,
            traffic,
            sessions,
            bandwidth,
            ClientFailureBackoff::tls_handshake(),
            ClientFailureBackoff::tcp_auth(),
        )
    }

    pub fn with_shared_limits_and_backoff(
        mut config: NaiveServerConfig,
        traffic: SharedTrafficRegistry,
        sessions: UserSessionTracker,
        bandwidth: UserBandwidthLimiters,
        tls_failures: ClientFailureBackoff,
        auth_failures: ClientFailureBackoff,
    ) -> io::Result<Self> {
        let users = UserStore::from_uuid_users(&config.users);
        let router = RouteMatcher::new(config.routes.clone());
        let tls_acceptor = naive_tls_acceptor(&config)?;
        config.users.clear();
        config.routes.clear();
        Ok(Self {
            config,
            users,
            router,
            traffic,
            sessions,
            bandwidth,
            tls_failures,
            auth_failures,
            tls_acceptor,
            quic_connections: SharedQuicConnectionLimiter::standalone(),
        })
    }

    pub fn with_quic_connection_limiter(
        mut self,
        quic_connections: SharedQuicConnectionLimiter,
    ) -> Self {
        self.quic_connections = quic_connections;
        self
    }

    pub fn bind(&self) -> io::Result<TcpListener> {
        bind_dual_stack_tcp_listener(self.config.listen)
    }

    pub fn bind_quic(&self) -> io::Result<quinn::Endpoint> {
        let server_crypto = server_config_from_files(
            &self.config.cert_file,
            &self.config.key_file,
            &naive_quic_alpn(&self.config.alpn),
            &self.config.server_name,
            self.config.reject_unknown_sni,
        )?;
        let mut server_config = quinn::ServerConfig::with_crypto(Arc::new(
            QuicServerConfig::try_from(server_crypto).map_err(io_other)?,
        ));
        let mut transport = quinn::TransportConfig::default();
        apply_proxy_quic_transport_defaults(&mut transport);
        apply_quic_congestion_control(&mut transport, "", "bbr", "naive")?;
        let resource = self.quic_connections.snapshot();
        println!(
            "INFO  core   naive shared quic limit total={} active={} listeners={} per_listener_soft={}",
            resource.total_limit,
            resource.active_connections,
            resource.listener_count,
            resource.per_listener_soft_limit
        );
        let tuning = proxy_quic_tuning_snapshot();
        println!(
            "INFO  core   naive quic tuning stream_window_mib={} conn_window_mib={} max_streams={} udp_socket_buffer_mib={} initial_rtt_ms={} idle_timeout_secs={}",
            tuning.stream_receive_window_mib,
            tuning.receive_window_mib,
            tuning.max_concurrent_streams,
            tuning.udp_socket_buffer_mib,
            tuning.initial_rtt_ms,
            tuning.max_idle_timeout_secs
        );
        server_config.transport_config(Arc::new(transport));
        server_endpoint_with_tuned_udp_socket(server_config, self.config.listen)
    }

    pub async fn run_quic(self, endpoint: quinn::Endpoint, stop: Arc<AtomicBool>) {
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
                    let Some(connection_slot) = self.quic_connections.try_acquire() else {
                        eprintln!(
                            "WARN  core   naive shared quic limit reached total={}",
                            self.quic_connections.total_limit()
                        );
                        continue;
                    };
                    let server = self.clone();
                    tokio::spawn(async move {
                        let _connection_slot = connection_slot;
                        if let Err(error) = server.handle_quic_incoming(incoming).await {
                            log_naive_quic_error("connection", &error);
                        }
                    });
                }
                _ = tokio::time::sleep(Duration::from_millis(NAIVE_QUIC_STOP_POLL_INTERVAL_MS)) => {}
            }
        }
        let _ = tokio::time::timeout(NAIVE_QUIC_ENDPOINT_STOP_WAIT, endpoint.wait_idle()).await;
    }

    pub async fn handle_tcp_client(&self, client: tokio::net::TcpStream) -> io::Result<()> {
        let peer_addr = client.peer_addr().ok();
        let peer_ip = peer_addr.map(|addr| addr.ip());
        if let Some(ip) = peer_ip {
            if self.tls_failures.is_blocked(ip) {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "naive tls handshake backoff active",
                ));
            }
        }
        let stream = match self.tls_acceptor.accept(client).await {
            Ok(stream) => {
                if let Some(ip) = peer_ip {
                    self.tls_failures.record_success(ip);
                }
                stream
            }
            Err(error) => {
                let class = classify_tls_handshake_error(&error);
                if !matches!(class, TlsHandshakeErrorClass::ClientClosed) {
                    if let Some(ip) = peer_ip {
                        self.tls_failures.record_failure(ip);
                    }
                    eprintln!(
                        "WARN  tls    handshake failed protocol=Naive tag={} class={class:?} error={error}",
                        self.config.node_tag
                    );
                }
                return Err(error);
            }
        };
        let mut connection = h2::server::handshake(stream).await.map_err(io_other)?;
        while let Some(request) = connection.accept().await {
            let (request, respond) = request.map_err(io_other)?;
            let server = self.clone();
            tokio::spawn(async move {
                let _ = server.handle_h2_request(request, respond, peer_addr).await;
            });
        }
        Ok(())
    }

    async fn handle_quic_incoming(&self, incoming: quinn::Incoming) -> io::Result<()> {
        let peer_addr = incoming.remote_address();
        let peer_ip = peer_addr.ip();
        if self.tls_failures.is_blocked(peer_ip) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "naive quic tls handshake backoff active",
            ));
        }
        let connection = match incoming.await {
            Ok(connection) => {
                self.tls_failures.record_success(peer_ip);
                connection
            }
            Err(error) => {
                self.tls_failures.record_failure(peer_ip);
                return Err(io_other(error));
            }
        };
        let mut h3_connection = h3::server::builder()
            .build::<_, Bytes>(h3_quinn::Connection::new(connection.clone()))
            .await
            .map_err(io_other)?;

        loop {
            let Some(resolver) = h3_connection.accept().await.map_err(io_other)? else {
                return Ok(());
            };
            let (request, stream) = resolver.resolve_request().await.map_err(io_other)?;
            let server = self.clone();
            tokio::spawn(async move {
                if let Err(error) = server
                    .handle_h3_request(request, stream, Some(peer_addr))
                    .await
                {
                    log_naive_quic_error("request", &error);
                }
            });
        }
    }

    pub fn drain_traffic(&self, minimum_bytes: u64) -> Vec<TrafficDelta> {
        self.traffic.drain_minimum(minimum_bytes)
    }

    pub fn replace_users(&self, users: Vec<CoreUser>) {
        self.bandwidth.sync_users(&users);
        self.users.replace_uuid_users(users);
    }

    pub fn apply_user_delta(&self, delta: &CoreUserDelta) -> CoreUserDeltaResult {
        sync_user_limit_delta(&self.bandwidth, &self.sessions, delta);
        self.users.apply_uuid_delta(delta)
    }

    async fn handle_h2_request(
        &self,
        h2_request: Request<h2::RecvStream>,
        mut respond: h2::server::SendResponse<Bytes>,
        peer_addr: Option<SocketAddr>,
    ) -> io::Result<()> {
        let wants_padding = h2_request.headers().get("padding").is_some();
        if let Some(ip) = peer_addr.map(|addr| addr.ip()) {
            if self.auth_failures.is_blocked(ip) {
                let _ = send_status(&mut respond, StatusCode::TOO_MANY_REQUESTS, wants_padding);
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "naive auth backoff active",
                ));
            }
        }
        let request = match self.parse_request(&h2_request, peer_addr.map(|addr| addr.ip())) {
            Ok(request) => {
                if let Some(ip) = peer_addr.map(|addr| addr.ip()) {
                    self.auth_failures.record_success(ip);
                }
                request
            }
            Err((status, error)) => {
                if should_record_naive_auth_failure(&error) {
                    if let Some(ip) = peer_addr.map(|addr| addr.ip()) {
                        self.auth_failures.record_failure(ip);
                    }
                }
                let _ = send_status(&mut respond, status, wants_padding);
                return Err(error);
            }
        };

        let user = self.users.get(&request.user_uuid).ok_or_else(|| {
            io::Error::new(io::ErrorKind::PermissionDenied, "naive user disappeared")
        })?;
        let _session = match self
            .sessions
            .try_acquire_for_ip(Some(&user), request.client_ip)
        {
            Ok(guard) => guard,
            Err(error) => {
                let _ = send_status(&mut respond, StatusCode::TOO_MANY_REQUESTS, request.padding);
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    error.to_string(),
                ));
            }
        };

        let decision = self
            .router
            .decide_target(&request.target.host, request.target.port, "tcp");
        let remote = match self.connect_remote(&request.target, &decision).await {
            Ok(remote) => remote,
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                let _ = send_status(&mut respond, StatusCode::FORBIDDEN, request.padding);
                return Err(error);
            }
            Err(error) if error.kind() == io::ErrorKind::Unsupported => {
                let _ = send_status(&mut respond, StatusCode::BAD_GATEWAY, request.padding);
                return Err(error);
            }
            Err(error) => {
                let _ = send_status(&mut respond, StatusCode::BAD_GATEWAY, request.padding);
                return Err(error);
            }
        };

        let mut response = Response::builder().status(StatusCode::OK);
        if request.padding {
            response = response.header("padding", generate_padding_header());
        }
        let send = respond
            .send_response(response.body(()).map_err(io_other)?, false)
            .map_err(io_other)?;
        let (reader, writer) = h2_body_channels(h2_request.into_body(), send);

        let limiter = self.bandwidth.limiter_for_limited(Some(&user));
        let server = self.clone();
        tokio::task::spawn_blocking(move || {
            let _session = _session;
            let _ = server.relay_h2_tunnel(reader, writer, remote, request, limiter);
        })
        .await
        .map_err(io_other)
    }

    async fn handle_h3_request(
        &self,
        h3_request: Request<()>,
        mut stream: H3ServerStream,
        peer_addr: Option<SocketAddr>,
    ) -> io::Result<()> {
        let wants_padding = h3_request.headers().get("padding").is_some();
        if let Some(ip) = peer_addr.map(|addr| addr.ip()) {
            if self.auth_failures.is_blocked(ip) {
                let _ =
                    send_h3_status(&mut stream, StatusCode::TOO_MANY_REQUESTS, wants_padding).await;
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "naive auth backoff active",
                ));
            }
        }
        let request = match self.parse_request(&h3_request, peer_addr.map(|addr| addr.ip())) {
            Ok(request) => {
                if let Some(ip) = peer_addr.map(|addr| addr.ip()) {
                    self.auth_failures.record_success(ip);
                }
                request
            }
            Err((status, error)) => {
                if should_record_naive_auth_failure(&error) {
                    if let Some(ip) = peer_addr.map(|addr| addr.ip()) {
                        self.auth_failures.record_failure(ip);
                    }
                }
                let _ = send_h3_status(&mut stream, status, wants_padding).await;
                return Err(error);
            }
        };

        let user = self.users.get(&request.user_uuid).ok_or_else(|| {
            io::Error::new(io::ErrorKind::PermissionDenied, "naive user disappeared")
        })?;
        let _session = match self
            .sessions
            .try_acquire_for_ip(Some(&user), request.client_ip)
        {
            Ok(guard) => guard,
            Err(error) => {
                let _ = send_h3_status(&mut stream, StatusCode::TOO_MANY_REQUESTS, request.padding)
                    .await;
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    error.to_string(),
                ));
            }
        };

        let decision = self
            .router
            .decide_target(&request.target.host, request.target.port, "tcp");
        let remote = match self.connect_remote(&request.target, &decision).await {
            Ok(remote) => remote,
            Err(error) if error.kind() == io::ErrorKind::PermissionDenied => {
                let _ = send_h3_status(&mut stream, StatusCode::FORBIDDEN, request.padding).await;
                return Err(error);
            }
            Err(error) if error.kind() == io::ErrorKind::Unsupported => {
                let _ = send_h3_status(&mut stream, StatusCode::BAD_GATEWAY, request.padding).await;
                return Err(error);
            }
            Err(error) => {
                let _ = send_h3_status(&mut stream, StatusCode::BAD_GATEWAY, request.padding).await;
                return Err(error);
            }
        };

        let mut response = Response::builder().status(StatusCode::OK);
        if request.padding {
            response = response.header("padding", generate_padding_header());
        }
        stream
            .send_response(response.body(()).map_err(io_other)?)
            .await
            .map_err(io_other)?;
        let (reader, writer) = h3_body_channels(stream);

        let limiter = self.bandwidth.limiter_for_limited(Some(&user));
        let server = self.clone();
        tokio::task::spawn_blocking(move || {
            let _session = _session;
            let _ = server.relay_h2_tunnel(reader, writer, remote, request, limiter);
        })
        .await
        .map_err(io_other)
    }

    fn parse_request<B>(
        &self,
        request: &Request<B>,
        client_ip: Option<IpAddr>,
    ) -> Result<NaiveRequest, (StatusCode, io::Error)> {
        if request.method() != http::Method::CONNECT {
            return Err((
                StatusCode::METHOD_NOT_ALLOWED,
                io::Error::new(io::ErrorKind::InvalidData, "naive requires CONNECT"),
            ));
        }
        let target = parse_connect_target(request.uri(), 443)
            .map_err(|error| (StatusCode::BAD_REQUEST, error))?;
        let auth = request
            .headers()
            .get("proxy-authorization")
            .and_then(|value| value.to_str().ok())
            .and_then(parse_basic_auth)
            .ok_or_else(|| {
                (
                    StatusCode::PROXY_AUTHENTICATION_REQUIRED,
                    io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "naive proxy authorization required",
                    ),
                )
            })?;
        let user = self.authenticate(&auth.0, &auth.1).ok_or_else(|| {
            (
                StatusCode::PROXY_AUTHENTICATION_REQUIRED,
                io::Error::new(io::ErrorKind::PermissionDenied, "invalid naive credential"),
            )
        })?;
        Ok(NaiveRequest {
            user_uuid: user.uuid,
            user_id: user.id,
            target,
            client_ip,
            padding: request.headers().get("padding").is_some(),
        })
    }

    fn authenticate(&self, username: &str, password: &str) -> Option<CoreUser> {
        if let Some(user) = self.users.get(username) {
            if user.credential() == password {
                return Some(user);
            }
        }
        if let Some(user) = self.users.get(password) {
            if user.credential() == password || user.uuid == password {
                return Some(user);
            }
        }
        None
    }

    async fn connect_remote(
        &self,
        target: &SocksTarget,
        decision: &RouteDecision,
    ) -> io::Result<TcpStream> {
        let remote = match decision {
            RouteDecision::Direct => {
                crate::dns::connect_tcp_tokio(
                    &target.host,
                    target.port,
                    self.config.connect_timeout,
                )
                .await?
            }
            RouteDecision::Outbound(outbound) => {
                connect_tcp_outbound_tokio(outbound, target, self.config.connect_timeout).await?
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
        remote.set_nodelay(true)?;
        let remote = remote.into_std()?;
        remote.set_nonblocking(false)?;
        Ok(remote)
    }

    fn relay_h2_tunnel(
        &self,
        reader: H2BodyReader,
        writer: H2BodyWriter,
        remote: TcpStream,
        request: NaiveRequest,
        limiter: Option<Arc<BandwidthLimiter>>,
    ) -> io::Result<()> {
        let _connection = self
            .bandwidth
            .register_tcp_connection(Some(&request.user_uuid), &[&remote])?;
        let mut remote_read = remote.try_clone()?;
        let mut remote_write = remote;
        let mut client_reader: Box<dyn Read + Send> = if request.padding {
            Box::new(NaivePaddedReader::new(reader))
        } else {
            Box::new(reader)
        };
        let mut client_writer: Box<dyn Write + Send> = if request.padding {
            Box::new(NaivePaddedWriter::new(writer))
        } else {
            Box::new(writer)
        };

        let upload_limiter = limiter.clone();
        let upload_task = spawn_native_blocking_relay(move || {
            let copied = copy_count_best_effort_limited(
                &mut client_reader,
                &mut remote_write,
                upload_limiter.as_deref(),
            );
            let _ = remote_write.shutdown(Shutdown::Write);
            copied
        })?;
        let download = copy_count_best_effort_limited(
            &mut remote_read,
            &mut client_writer,
            limiter.as_deref(),
        );
        let upload = join_native_blocking_relay(upload_task, "naive upload relay task panicked")?;

        self.traffic.add_with_user_id(
            self.config.node_tag.clone(),
            request.user_uuid,
            Some(request.user_id),
            upload,
            download,
            request.client_ip,
        );
        Ok(())
    }
}

impl H2BodyReader {
    fn new(rx: Receiver<Bytes>) -> Self {
        Self {
            rx,
            buffer: Bytes::new(),
            offset: 0,
        }
    }
}

impl Read for H2BodyReader {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        while self.offset >= self.buffer.len() {
            match self.rx.blocking_recv() {
                Some(data) if data.is_empty() => continue,
                Some(data) => {
                    self.buffer = data;
                    self.offset = 0;
                }
                None => return Ok(0),
            }
        }
        let available = &self.buffer[self.offset..];
        let len = output.len().min(available.len());
        output[..len].copy_from_slice(&available[..len]);
        self.offset += len;
        if self.offset >= self.buffer.len() {
            self.buffer = Bytes::new();
            self.offset = 0;
        }
        Ok(len)
    }
}

impl H2BodyWriter {
    fn new(tx: Sender<Bytes>) -> Self {
        Self { tx }
    }
}

impl Write for H2BodyWriter {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        if input.is_empty() {
            return Ok(0);
        }
        self.tx
            .blocking_send(Bytes::copy_from_slice(input))
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "h2 stream closed"))?;
        Ok(input.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl<R> NaivePaddedReader<R> {
    fn new(inner: R) -> Self {
        Self {
            inner,
            frames_done: 0,
            header: [0; 3],
            header_pos: 0,
            data_remaining: 0,
            padding_remaining: 0,
            pending_padding: 0,
        }
    }
}

impl<R: Read> Read for NaivePaddedReader<R> {
    fn read(&mut self, output: &mut [u8]) -> io::Result<usize> {
        if output.is_empty() {
            return Ok(0);
        }
        loop {
            if self.data_remaining > 0 {
                let want = output.len().min(self.data_remaining);
                let read = self.inner.read(&mut output[..want])?;
                if read == 0 {
                    return Ok(0);
                }
                self.data_remaining -= read;
                if self.data_remaining == 0 {
                    self.padding_remaining = self.pending_padding;
                    self.pending_padding = 0;
                }
                return Ok(read);
            }

            while self.padding_remaining > 0 {
                let mut scratch = [0u8; 256];
                let want = scratch.len().min(self.padding_remaining);
                let read = self.inner.read(&mut scratch[..want])?;
                if read == 0 {
                    return Ok(0);
                }
                self.padding_remaining -= read;
            }

            if self.frames_done >= PADDING_FRAMES {
                return self.inner.read(output);
            }

            while self.header_pos < self.header.len() {
                let read = self.inner.read(&mut self.header[self.header_pos..])?;
                if read == 0 {
                    return Ok(0);
                }
                self.header_pos += read;
            }
            self.header_pos = 0;
            self.frames_done = self.frames_done.saturating_add(1);
            self.data_remaining = u16::from_be_bytes([self.header[0], self.header[1]]) as usize;
            self.pending_padding = self.header[2] as usize;
            if self.data_remaining == 0 {
                self.padding_remaining = self.pending_padding;
                self.pending_padding = 0;
            }
        }
    }
}

impl<W> NaivePaddedWriter<W> {
    fn new(inner: W) -> Self {
        Self {
            inner,
            frames_done: 0,
        }
    }
}

impl<W: Write> Write for NaivePaddedWriter<W> {
    fn write(&mut self, input: &[u8]) -> io::Result<usize> {
        if input.is_empty() {
            return Ok(0);
        }
        let mut offset = 0usize;
        while offset < input.len() && self.frames_done < PADDING_FRAMES {
            let len = (input.len() - offset).min(MAX_PADDED_PAYLOAD);
            let padding_len = random_padding_len();
            let mut frame = Vec::with_capacity(3 + len + padding_len);
            frame.extend_from_slice(&(len as u16).to_be_bytes());
            frame.push(padding_len as u8);
            frame.extend_from_slice(&input[offset..offset + len]);
            append_random_padding(&mut frame, padding_len);
            self.inner.write_all(&frame)?;
            offset += len;
            self.frames_done += 1;
        }
        if offset < input.len() {
            self.inner.write_all(&input[offset..])?;
        }
        Ok(input.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

fn h2_body_channels(
    body: h2::RecvStream,
    mut send: h2::SendStream<Bytes>,
) -> (H2BodyReader, H2BodyWriter) {
    let (input_tx, input_rx) = channel(H2_BODY_CHANNEL_CAPACITY);
    let (output_tx, output_rx) = channel(H2_BODY_CHANNEL_CAPACITY);
    tokio::spawn(async move {
        let _ = read_h2_data(body, input_tx).await;
    });
    tokio::spawn(async move {
        let _ = write_h2_data(&mut send, output_rx).await;
    });
    (H2BodyReader::new(input_rx), H2BodyWriter::new(output_tx))
}

fn h3_body_channels(stream: H3ServerStream) -> (H2BodyReader, H2BodyWriter) {
    let (mut send, mut recv) = stream.split();
    let (input_tx, input_rx) = channel(H2_BODY_CHANNEL_CAPACITY);
    let (output_tx, output_rx) = channel(H2_BODY_CHANNEL_CAPACITY);
    tokio::spawn(async move {
        let _ = read_h3_data(&mut recv, input_tx).await;
    });
    tokio::spawn(async move {
        let _ = write_h3_data(&mut send, output_rx).await;
    });
    (H2BodyReader::new(input_rx), H2BodyWriter::new(output_tx))
}

async fn read_h2_data(mut stream: h2::RecvStream, tx: Sender<Bytes>) -> io::Result<()> {
    while let Some(chunk) = stream.data().await {
        let chunk = chunk.map_err(io_other)?;
        let len = chunk.len();
        if len > 0 {
            if tx.send(chunk).await.is_err() {
                return Ok(());
            }
        }
        let _ = stream.flow_control().release_capacity(len);
    }
    Ok(())
}

async fn read_h3_data(stream: &mut H3ServerRecvStream, tx: Sender<Bytes>) -> io::Result<()> {
    while let Some(mut chunk) = stream.recv_data().await.map_err(io_other)? {
        let len = chunk.remaining();
        if len > 0 {
            let payload = chunk.copy_to_bytes(len);
            if tx.send(payload).await.is_err() {
                return Ok(());
            }
        }
    }
    Ok(())
}

async fn write_h2_data(
    send: &mut h2::SendStream<Bytes>,
    mut rx: Receiver<Bytes>,
) -> io::Result<()> {
    while let Some(payload) = rx.recv().await {
        if !payload.is_empty() {
            send.send_data(payload, false).map_err(io_other)?;
        }
    }
    send.send_data(Bytes::new(), true).map_err(io_other)
}

async fn write_h3_data(stream: &mut H3ServerSendStream, mut rx: Receiver<Bytes>) -> io::Result<()> {
    while let Some(payload) = rx.recv().await {
        if !payload.is_empty() {
            stream.send_data(payload).await.map_err(io_other)?;
        }
    }
    stream.finish().await.map_err(io_other)
}

fn send_status(
    respond: &mut h2::server::SendResponse<Bytes>,
    status: StatusCode,
    padding: bool,
) -> io::Result<()> {
    let mut response = Response::builder().status(status);
    if status == StatusCode::PROXY_AUTHENTICATION_REQUIRED {
        response = response.header("proxy-authenticate", "Basic realm=\"naive\"");
    }
    if padding {
        response = response.header("padding", generate_padding_header());
    }
    respond
        .send_response(response.body(()).map_err(io_other)?, true)
        .map_err(io_other)?;
    Ok(())
}

async fn send_h3_status(
    stream: &mut H3ServerStream,
    status: StatusCode,
    padding: bool,
) -> io::Result<()> {
    let mut response = Response::builder().status(status);
    if status == StatusCode::PROXY_AUTHENTICATION_REQUIRED {
        response = response.header("proxy-authenticate", "Basic realm=\"naive\"");
    }
    if padding {
        response = response.header("padding", generate_padding_header());
    }
    stream
        .send_response(response.body(()).map_err(io_other)?)
        .await
        .map_err(io_other)?;
    stream.finish().await.map_err(io_other)
}

fn parse_basic_auth(value: &str) -> Option<(String, String)> {
    let value = value.trim();
    let mut parts = value.splitn(2, char::is_whitespace);
    let scheme = parts.next()?;
    if !scheme.eq_ignore_ascii_case("Basic") {
        return None;
    }
    let encoded = parts.next()?.trim();
    if encoded.is_empty() {
        return None;
    }
    let decoded = STANDARD.decode(encoded.trim()).ok()?;
    let decoded = String::from_utf8(decoded).ok()?;
    let (username, password) = decoded.split_once(':')?;
    Some((username.to_string(), password.to_string()))
}

fn parse_connect_target(uri: &Uri, default_port: u16) -> io::Result<SocksTarget> {
    if let Some(authority) = uri.authority() {
        return parse_authority(authority.as_str(), default_port);
    }
    let target = uri.to_string();
    if target.trim().is_empty() || target.starts_with('/') {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "missing naive authority",
        ));
    }
    parse_authority(&target, default_port)
}

fn parse_authority(value: &str, default_port: u16) -> io::Result<SocksTarget> {
    let value = value.trim();
    if value.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "empty naive authority",
        ));
    }
    if let Some(rest) = value.strip_prefix('[') {
        let Some(end) = rest.find(']') else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid naive ipv6 authority",
            ));
        };
        let host = &rest[..end];
        let port = rest[end + 1..]
            .strip_prefix(':')
            .and_then(|port| port.parse::<u16>().ok())
            .unwrap_or(default_port);
        return Ok(SocksTarget {
            host: host.to_string(),
            port,
        });
    }
    if let Some((host, port)) = value.rsplit_once(':') {
        if !host.contains(':') {
            let port = port.parse::<u16>().map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidData, "invalid naive authority port")
            })?;
            if host.trim().is_empty() {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "empty naive authority host",
                ));
            }
            return Ok(SocksTarget {
                host: host.to_string(),
                port,
            });
        }
    }
    Ok(SocksTarget {
        host: value.to_string(),
        port: default_port,
    })
}

fn naive_quic_alpn(configured: &[String]) -> Vec<String> {
    let mut alpn = configured.to_vec();
    if alpn.is_empty() {
        alpn.push("h3".to_string());
    } else if !alpn
        .iter()
        .any(|value| value.trim().eq_ignore_ascii_case("h3"))
    {
        alpn.insert(0, "h3".to_string());
    }
    alpn
}

fn naive_tls_acceptor(config: &NaiveServerConfig) -> io::Result<TokioTlsAcceptor> {
    let mut alpn = config.alpn.clone();
    if alpn.is_empty() {
        alpn.push("h2".to_string());
    } else if !alpn.iter().any(|value| value == "h2") {
        alpn.insert(0, "h2".to_string());
    }
    let config = server_config_from_files(
        &config.cert_file,
        &config.key_file,
        &alpn,
        &config.server_name,
        config.reject_unknown_sni,
    )?;
    Ok(TokioTlsAcceptor::from(Arc::new(config)))
}

fn log_naive_quic_error(context: &str, error: &io::Error) {
    match error.kind() {
        io::ErrorKind::UnexpectedEof
        | io::ErrorKind::ConnectionAborted
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::BrokenPipe => {}
        _ => eprintln!("naive h3 {context} error: {error}"),
    }
}

fn generate_padding_header() -> String {
    const CHARS: &[u8] = b"!#$()+<>?@[]^`{}";
    let len = usize::from(random_byte() % 33) + 30;
    let mut output = String::with_capacity(len);
    for _ in 0..16 {
        output.push(CHARS[usize::from(random_byte() & 0x0f)] as char);
    }
    for _ in 16..len {
        output.push('~');
    }
    output
}

fn random_padding_len() -> usize {
    random_byte() as usize
}

fn append_random_padding(output: &mut Vec<u8>, len: usize) {
    if len == 0 {
        return;
    }
    let start = output.len();
    output.resize(start + len, 0);
    let _ = getrandom::getrandom(&mut output[start..]);
}

fn should_record_naive_auth_failure(error: &io::Error) -> bool {
    if error.kind() != io::ErrorKind::PermissionDenied {
        return false;
    }
    let text = error.to_string().to_ascii_lowercase();
    text.contains("auth") || text.contains("credential")
}

fn random_byte() -> u8 {
    let mut byte = [0u8; 1];
    if getrandom::getrandom(&mut byte).is_err() {
        0
    } else {
        byte[0]
    }
}

fn io_other(error: impl fmt::Display) -> io::Error {
    io::Error::new(io::ErrorKind::Other, error.to_string())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::{self, Cursor, Read, Write};
    use std::net::{SocketAddr, TcpListener};
    use std::path::PathBuf;
    use std::sync::mpsc;
    use std::sync::Arc;
    use std::thread;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use base64::engine::general_purpose::STANDARD;
    use base64::Engine;
    use bytes::Bytes;
    use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
    use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
    use rustls::{ClientConfig, DigitallySignedStruct, SignatureScheme};
    use tokio_rustls::TlsConnector;

    use crate::abuse::{ClientFailureBackoff, ClientFailureBackoffPolicy};
    use crate::limits::{UserBandwidthLimiters, UserSessionTracker};
    use crate::naive::{
        parse_authority, parse_basic_auth, parse_connect_target, should_record_naive_auth_failure,
        H2BodyReader, H2BodyWriter, NaivePaddedReader, NaivePaddedWriter, NaiveServer,
        NaiveServerConfig, H2_BODY_CHANNEL_CAPACITY,
    };
    use crate::traffic::{TrafficDelta, TrafficRegistry};
    use crate::user::{CoreUser, CoreUserDelta};

    struct TestCert {
        cert_path: PathBuf,
        key_path: PathBuf,
    }

    #[derive(Debug)]
    struct NoCertificateVerification;

    impl Drop for TestCert {
        fn drop(&mut self) {
            let _ = fs::remove_file(&self.cert_path);
            let _ = fs::remove_file(&self.key_path);
        }
    }

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

    fn test_cert(label: &str) -> TestCert {
        let cert = rcgen::generate_simple_self_signed(vec!["localhost".to_string()])
            .expect("self signed cert");
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let dir = std::env::temp_dir();
        let cert_path = dir.join(format!("keli-core-rs-naive-{label}-{nanos}.crt"));
        let key_path = dir.join(format!("keli-core-rs-naive-{label}-{nanos}.key"));
        fs::write(&cert_path, cert.cert.pem()).expect("write cert");
        fs::write(&key_path, cert.key_pair.serialize_pem()).expect("write key");
        TestCert {
            cert_path,
            key_path,
        }
    }

    fn user(uuid: &str, id: u64, password: Option<&str>) -> CoreUser {
        CoreUser {
            id,
            uuid: uuid.to_string(),
            password: password.map(str::to_string),
            email: None,
            speed_limit: 0,
            device_limit: 0,
        }
    }

    fn spawn_echo_server() -> SocketAddr {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind echo");
        let addr = listener.local_addr().expect("echo addr");
        thread::spawn(move || {
            let (mut stream, _) = listener.accept().expect("accept echo");
            let mut payload = [0u8; 4];
            stream.read_exact(&mut payload).expect("read echo request");
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong").expect("write echo response");
        });
        addr
    }

    fn server_with_users(users: Vec<CoreUser>) -> (NaiveServer, TestCert) {
        server_with_users_and_auth_backoff(users, ClientFailureBackoff::tcp_auth())
    }

    fn server_with_users_and_auth_backoff(
        users: Vec<CoreUser>,
        auth_failures: ClientFailureBackoff,
    ) -> (NaiveServer, TestCert) {
        let cert = test_cert("server");
        let server = NaiveServer::with_shared_limits_and_backoff(
            NaiveServerConfig {
                node_tag: "panel|naive|1".to_string(),
                listen: "127.0.0.1:0".parse().unwrap(),
                users,
                routes: Vec::new(),
                cert_file: cert.cert_path.to_string_lossy().to_string(),
                key_file: cert.key_path.to_string_lossy().to_string(),
                server_name: "localhost".to_string(),
                alpn: Vec::new(),
                reject_unknown_sni: false,
                connect_timeout: Duration::from_secs(3),
            },
            TrafficRegistry::shared(),
            UserSessionTracker::default(),
            UserBandwidthLimiters::default(),
            ClientFailureBackoff::tls_handshake(),
            auth_failures,
        )
        .expect("naive server");
        (server, cert)
    }

    fn drain_traffic_with_wait(server: &NaiveServer) -> Vec<TrafficDelta> {
        for _ in 0..200 {
            let records = server.drain_traffic(1);
            if !records.is_empty() {
                return records;
            }
            thread::sleep(Duration::from_millis(10));
        }
        Vec::new()
    }

    #[test]
    fn parses_basic_auth_username_password() {
        let encoded = STANDARD.encode("user-a:secret-a");
        assert_eq!(
            parse_basic_auth(&format!("Basic {encoded}")),
            Some(("user-a".to_string(), "secret-a".to_string()))
        );
    }

    #[test]
    fn parses_basic_auth_case_insensitive_scheme_and_whitespace() {
        let encoded = STANDARD.encode("user-a:secret-a");

        assert_eq!(
            parse_basic_auth(&format!("  bAsIc \t {encoded}  ")),
            Some(("user-a".to_string(), "secret-a".to_string()))
        );
        assert_eq!(parse_basic_auth(&format!("Bearer {encoded}")), None);
    }

    #[test]
    fn parses_ipv6_authority() {
        let target = parse_authority("[2001:db8::1]:8443", 443).unwrap();
        assert_eq!(target.host, "2001:db8::1");
        assert_eq!(target.port, 8443);
    }

    #[test]
    fn parses_connect_target_from_absolute_and_authority_form_uri() {
        let absolute: http::Uri = "https://example.com:8443/path".parse().unwrap();
        let target = parse_connect_target(&absolute, 443).unwrap();
        assert_eq!(target.host, "example.com");
        assert_eq!(target.port, 8443);

        let authority_form: http::Uri = "example.net:9443".parse().unwrap();
        let target = parse_connect_target(&authority_form, 443).unwrap();
        assert_eq!(target.host, "example.net");
        assert_eq!(target.port, 9443);
    }

    #[test]
    fn h2_body_reader_reads_partial_chunks_without_dropping_bytes() {
        let (tx, rx) = tokio::sync::mpsc::channel(H2_BODY_CHANNEL_CAPACITY);
        tx.blocking_send(Bytes::from_static(&[1, 2, 3, 4]))
            .expect("send first chunk");
        tx.blocking_send(Bytes::from_static(&[5, 6]))
            .expect("send second chunk");
        drop(tx);

        let mut reader = H2BodyReader::new(rx);
        let mut first = [0u8; 2];
        let mut second = [0u8; 3];
        let mut third = [0u8; 2];

        assert_eq!(reader.read(&mut first).expect("read first"), 2);
        assert_eq!(&first, &[1, 2]);
        assert_eq!(reader.read(&mut second).expect("read second"), 2);
        assert_eq!(&second[..2], &[3, 4]);
        assert_eq!(reader.read(&mut third).expect("read third"), 2);
        assert_eq!(&third, &[5, 6]);
        assert_eq!(reader.read(&mut third).expect("eof"), 0);
    }

    #[test]
    fn h2_body_writer_sends_bounded_bytes_payloads() {
        let (tx, mut rx) = tokio::sync::mpsc::channel(H2_BODY_CHANNEL_CAPACITY);
        let mut writer = H2BodyWriter::new(tx);

        writer.write_all(b"hello").expect("write payload");
        drop(writer);

        let payload = rx.blocking_recv().expect("receive payload");
        assert_eq!(&payload[..], b"hello");
        assert!(rx.blocking_recv().is_none());
    }

    #[test]
    fn padded_transport_round_trips_first_frames() {
        let mut encoded = Vec::new();
        {
            let mut writer = NaivePaddedWriter::new(&mut encoded);
            writer.write_all(b"hello").unwrap();
            writer.write_all(b"world").unwrap();
            writer.flush().unwrap();
        }

        let mut reader = NaivePaddedReader::new(Cursor::new(encoded));
        let mut decoded = Vec::new();
        reader.read_to_end(&mut decoded).unwrap();
        assert_eq!(decoded, b"helloworld");
    }

    #[test]
    fn authenticates_uuid_password_and_applies_user_delta() {
        let (server, _cert) = server_with_users(vec![user("user-a", 1, None)]);
        assert!(server.authenticate("user-a", "user-a").is_some());
        assert!(server.authenticate("user-a", "wrong").is_none());

        let result = server.apply_user_delta(&CoreUserDelta {
            added: vec![user("user-b", 2, Some("secret-b"))],
            deleted: vec!["user-a".to_string()],
            ..CoreUserDelta::default()
        });
        assert_eq!(result.added, 1);
        assert_eq!(result.deleted, 1);
        assert!(server.authenticate("user-a", "user-a").is_none());
        assert!(server.authenticate("user-b", "secret-b").is_some());
    }

    #[test]
    fn identifies_naive_auth_failures_for_backoff() {
        assert!(should_record_naive_auth_failure(&io::Error::new(
            io::ErrorKind::PermissionDenied,
            "invalid naive credential"
        )));
        assert!(should_record_naive_auth_failure(&io::Error::new(
            io::ErrorKind::PermissionDenied,
            "naive proxy authorization required"
        )));
        assert!(!should_record_naive_auth_failure(&io::Error::new(
            io::ErrorKind::PermissionDenied,
            "target blocked by route"
        )));
        assert!(!should_record_naive_auth_failure(&io::Error::new(
            io::ErrorKind::InvalidData,
            "naive requires CONNECT"
        )));
    }

    #[test]
    fn invalid_naive_auth_records_backoff_and_blocks_next_request() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(2)
            .build()
            .expect("runtime");
        let auth_failures = ClientFailureBackoff::new(ClientFailureBackoffPolicy {
            threshold: 1,
            window: Duration::from_secs(30),
            block_duration: Duration::from_secs(30),
            max_entries: 16,
        });
        let (server, _cert) = server_with_users_and_auth_backoff(
            vec![user("naive-user", 42, Some("secret-a"))],
            auth_failures.clone(),
        );
        let listener = server.bind().expect("bind naive");
        let addr = listener.local_addr().expect("naive addr");
        listener.set_nonblocking(true).expect("nonblocking");

        runtime.block_on(async {
            let listener = tokio::net::TcpListener::from_std(listener).expect("tokio listener");
            let server_for_task = server.clone();
            let server_task = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.expect("accept naive");
                let _ = server_for_task.handle_tcp_client(stream).await;
            });

            let stream = tokio::net::TcpStream::connect(addr)
                .await
                .expect("connect naive");
            let mut tls = ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
                .with_no_client_auth();
            tls.alpn_protocols = vec![b"h2".to_vec()];
            let connector = TlsConnector::from(Arc::new(tls));
            let tls = connector
                .connect(
                    ServerName::try_from("localhost")
                        .expect("server name")
                        .to_owned(),
                    stream,
                )
                .await
                .expect("tls connect");
            let (mut client, connection) = h2::client::handshake(tls).await.expect("h2 handshake");
            let connection_task = tokio::spawn(async move {
                let _ = connection.await;
            });

            let wrong_auth = STANDARD.encode("naive-user:wrong");
            let request = http::Request::builder()
                .method(http::Method::CONNECT)
                .uri("https://example.com:443")
                .header("proxy-authorization", format!("basic {wrong_auth}"))
                .body(())
                .expect("wrong request");
            let response = client
                .send_request(request, true)
                .expect("send wrong request")
                .0
                .await
                .expect("wrong response");
            assert_eq!(
                response.status(),
                http::StatusCode::PROXY_AUTHENTICATION_REQUIRED
            );

            let good_auth = STANDARD.encode("naive-user:secret-a");
            let request = http::Request::builder()
                .method(http::Method::CONNECT)
                .uri("https://example.com:443")
                .header("proxy-authorization", format!("basic {good_auth}"))
                .body(())
                .expect("good request");
            let response = client
                .send_request(request, true)
                .expect("send blocked request")
                .0
                .await
                .expect("blocked response");
            assert_eq!(response.status(), http::StatusCode::TOO_MANY_REQUESTS);

            drop(client);
            connection_task.abort();
            let _ = tokio::time::timeout(Duration::from_secs(2), server_task).await;
        });

        let snapshot = auth_failures.snapshot();
        assert_eq!(snapshot.failure_total, 1);
        assert_eq!(snapshot.backoff_reject_total, 1);
    }

    #[test]
    fn invalid_auth_response_preserves_naive_padding_header() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(2)
            .build()
            .expect("runtime");
        let (server, _cert) = server_with_users(vec![user("naive-user", 42, Some("secret-a"))]);
        let listener = server.bind().expect("bind naive");
        let addr = listener.local_addr().expect("naive addr");
        listener.set_nonblocking(true).expect("nonblocking");

        runtime.block_on(async {
            let listener = tokio::net::TcpListener::from_std(listener).expect("tokio listener");
            let server_for_task = server.clone();
            let server_task = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.expect("accept naive");
                let _ = server_for_task.handle_tcp_client(stream).await;
            });

            let stream = tokio::net::TcpStream::connect(addr)
                .await
                .expect("connect naive");
            let mut tls = ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
                .with_no_client_auth();
            tls.alpn_protocols = vec![b"h2".to_vec()];
            let connector = TlsConnector::from(Arc::new(tls));
            let tls = connector
                .connect(
                    ServerName::try_from("localhost")
                        .expect("server name")
                        .to_owned(),
                    stream,
                )
                .await
                .expect("tls connect");
            let (mut client, connection) = h2::client::handshake(tls).await.expect("h2 handshake");
            let connection_task = tokio::spawn(async move {
                let _ = connection.await;
            });

            let auth = STANDARD.encode("naive-user:wrong");
            let request = http::Request::builder()
                .method(http::Method::CONNECT)
                .uri("https://example.com:443")
                .header("proxy-authorization", format!("basic {auth}"))
                .header("padding", super::generate_padding_header())
                .body(())
                .expect("request");
            let response = client
                .send_request(request, true)
                .expect("send request")
                .0
                .await
                .expect("response");

            assert_eq!(
                response.status(),
                http::StatusCode::PROXY_AUTHENTICATION_REQUIRED
            );
            assert!(response.headers().get("proxy-authenticate").is_some());
            assert!(response.headers().get("padding").is_some());

            drop(client);
            connection_task.abort();
            let _ = tokio::time::timeout(Duration::from_secs(2), server_task).await;
        });
    }

    #[test]
    fn proxies_h2_connect_with_padding_and_records_user_traffic() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(2)
            .build()
            .expect("runtime");
        let (server, _cert) = server_with_users(vec![user("naive-user", 42, Some("secret-a"))]);
        let listener = server.bind().expect("bind naive");
        let addr = listener.local_addr().expect("naive addr");
        listener.set_nonblocking(true).expect("nonblocking");
        let echo_addr = spawn_echo_server();

        runtime.block_on(async {
            let listener = tokio::net::TcpListener::from_std(listener).expect("tokio listener");
            let server_for_task = server.clone();
            let server_task = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.expect("accept naive");
                server_for_task
                    .handle_tcp_client(stream)
                    .await
                    .expect("handle naive client");
            });

            let stream = tokio::net::TcpStream::connect(addr)
                .await
                .expect("connect naive");
            let mut tls = ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
                .with_no_client_auth();
            tls.alpn_protocols = vec![b"h2".to_vec()];
            let connector = TlsConnector::from(Arc::new(tls));
            let tls = connector
                .connect(
                    ServerName::try_from("localhost")
                        .expect("server name")
                        .to_owned(),
                    stream,
                )
                .await
                .expect("tls connect");
            let (mut client, connection) = h2::client::handshake(tls).await.expect("h2 handshake");
            let connection_task = tokio::spawn(async move {
                let _ = connection.await;
            });

            let auth = STANDARD.encode("naive-user:secret-a");
            let request = http::Request::builder()
                .method(http::Method::CONNECT)
                .uri(format!("https://{echo_addr}"))
                .header("proxy-authorization", format!("Basic {auth}"))
                .header("padding", super::generate_padding_header())
                .body(())
                .expect("request");
            let (response, mut send) = client.send_request(request, false).expect("send request");
            let mut padded_ping = Vec::new();
            {
                let mut writer = NaivePaddedWriter::new(&mut padded_ping);
                writer.write_all(b"ping").expect("write padded ping");
            }
            send.send_data(Bytes::from(padded_ping), true)
                .expect("send ping");

            let response = response.await.expect("response");
            assert_eq!(response.status(), http::StatusCode::OK);
            assert!(response.headers().get("padding").is_some());
            let mut body = response.into_body();
            let mut padded_pong = Vec::new();
            while let Some(chunk) = body.data().await {
                let chunk = chunk.expect("body chunk");
                let len = chunk.len();
                padded_pong.extend_from_slice(&chunk);
                let _ = body.flow_control().release_capacity(len);
            }
            let mut reader = NaivePaddedReader::new(Cursor::new(padded_pong));
            let mut pong = Vec::new();
            reader.read_to_end(&mut pong).expect("decode pong");
            assert_eq!(pong, b"pong");

            drop(client);
            connection_task.abort();
            let _ = tokio::time::timeout(Duration::from_secs(2), server_task).await;
        });

        let records = drain_traffic_with_wait(&server);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].node_tag, "panel|naive|1");
        assert_eq!(records[0].user_uuid, "naive-user");
        assert_eq!(records[0].user_id, Some(42));
        assert_eq!(records[0].upload, 4);
        assert_eq!(records[0].download, 4);
    }

    #[test]
    fn deleting_naive_user_stops_existing_h2_tunnel_and_reports_tail() {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .worker_threads(2)
            .build()
            .expect("runtime");
        let (server, _cert) = server_with_users(vec![user("naive-user", 42, Some("secret-a"))]);
        let listener = server.bind().expect("bind naive");
        let addr = listener.local_addr().expect("naive addr");
        listener.set_nonblocking(true).expect("nonblocking");

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

        runtime.block_on(async {
            let listener = tokio::net::TcpListener::from_std(listener).expect("tokio listener");
            let server_for_task = server.clone();
            let server_task = tokio::spawn(async move {
                let (stream, _) = listener.accept().await.expect("accept naive");
                server_for_task
                    .handle_tcp_client(stream)
                    .await
                    .expect("handle naive client");
            });

            let stream = tokio::net::TcpStream::connect(addr)
                .await
                .expect("connect naive");
            let mut tls = ClientConfig::builder()
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(NoCertificateVerification))
                .with_no_client_auth();
            tls.alpn_protocols = vec![b"h2".to_vec()];
            let connector = TlsConnector::from(Arc::new(tls));
            let tls = connector
                .connect(
                    ServerName::try_from("localhost")
                        .expect("server name")
                        .to_owned(),
                    stream,
                )
                .await
                .expect("tls connect");
            let (mut client, connection) = h2::client::handshake(tls).await.expect("h2 handshake");
            let connection_task = tokio::spawn(async move {
                let _ = connection.await;
            });

            let auth = STANDARD.encode("naive-user:secret-a");
            let request = http::Request::builder()
                .method(http::Method::CONNECT)
                .uri(format!("https://{echo_addr}"))
                .header("proxy-authorization", format!("Basic {auth}"))
                .body(())
                .expect("request");
            let (response, mut send) = client.send_request(request, false).expect("send request");
            let response = response.await.expect("response");
            assert_eq!(response.status(), http::StatusCode::OK);
            let mut body = response.into_body();

            send.send_data(Bytes::from_static(b"x"), false)
                .expect("send first byte");
            let chunk = body
                .data()
                .await
                .expect("first response data")
                .expect("first response chunk");
            assert_eq!(chunk.as_ref(), b"x");
            let _ = body.flow_control().release_capacity(chunk.len());

            let result = server.apply_user_delta(&CoreUserDelta {
                deleted: vec!["naive-user".to_string()],
                ..CoreUserDelta::default()
            });
            assert_eq!(result.deleted, 1);
            assert!(server.authenticate("naive-user", "secret-a").is_none());

            let _ = send.send_data(Bytes::from_static(b"y"), false);
            assert!(
                !second_payload_rx
                    .recv_timeout(Duration::from_secs(2))
                    .expect("echo result"),
                "deleted user's existing Naive tunnel should stop forwarding new payload"
            );

            drop(send);
            drop(client);
            connection_task.abort();
            let _ = tokio::time::timeout(Duration::from_secs(2), server_task).await;
        });
        echo_thread.join().expect("echo thread");

        let records = drain_traffic_with_wait(&server);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].node_tag, "panel|naive|1");
        assert_eq!(records[0].user_uuid, "naive-user");
        assert_eq!(records[0].user_id, Some(42));
        assert_eq!(records[0].upload, 1);
        assert_eq!(records[0].download, 1);
    }
}
