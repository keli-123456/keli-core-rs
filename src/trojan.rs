use std::io::{self, Read, Write};
use std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket,
};
use std::sync::{
    atomic::{AtomicBool, AtomicU64, Ordering},
    mpsc, Arc, Mutex,
};
use std::thread;
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, RootCertStore, SignatureScheme,
    StreamOwned,
};
use sha2::{Digest, Sha224};

use crate::config::{outbound_transport_network, OutboundConfig, OutboundTlsConfig};
use crate::grpc::{connect_grpc_client, GrpcClientStream};
use crate::http2::{connect_http2_client, local_bridge_for_http2};
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
    relay_tcp_fast_unlimited, relay_tcp_limited, spawn_detached_blocking_relay,
    spawn_native_blocking_relay,
};
use crate::tls::{relay_tls_stream, TlsConnection};
use crate::traffic::{SharedTrafficRegistry, TrafficRegistry};
use crate::user::{CoreUser, CoreUserDelta, CoreUserDeltaResult, UserStore};
use crate::websocket::{
    accept_websocket_tls_with_client_ip, accept_websocket_with_client_ip, connect_websocket_client,
    relay_websocket_tls_stream, websocket_tls_relay_idle_timeout, WebSocketClientStream,
    WebSocketReader, WebSocketWriter,
};
use crate::{connect_tcp_outbound, send_udp_outbound, RouteDecision, RouteDispatcher};

const COMMAND_TCP: u8 = 0x01;
const COMMAND_UDP_ASSOCIATE: u8 = 0x03;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;
const TROJAN_PASSWORD_HEX_LEN: usize = 56;
const MAX_UDP_PACKET_SIZE: usize = 65_535;
const CLIENT_CLOSE_CONNECT_POLL: Duration = Duration::from_millis(10);
const TROJAN_CONNECT_THREAD_STACK: usize = 256 * 1024;

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
    router: RouteDispatcher,
    traffic: SharedTrafficRegistry,
    sessions: UserSessionTracker,
    bandwidth: UserBandwidthLimiters,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct TrojanRequest {
    command: TrojanCommand,
    password_hash: String,
    user_uuid: String,
    user_id: u64,
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
    target: Option<SocksTarget>,
    target_addr: Option<SocketAddr>,
    timeout: Duration,
}

impl TrojanServer {
    pub fn new(config: TrojanServerConfig) -> Self {
        Self::with_traffic(config, TrafficRegistry::shared())
    }

    pub fn with_traffic(config: TrojanServerConfig, traffic: SharedTrafficRegistry) -> Self {
        Self::with_shared_limits(
            config,
            traffic,
            UserSessionTracker::default(),
            UserBandwidthLimiters::default(),
        )
    }

    pub fn with_shared_limits(
        mut config: TrojanServerConfig,
        traffic: SharedTrafficRegistry,
        sessions: UserSessionTracker,
        bandwidth: UserBandwidthLimiters,
    ) -> Self {
        let users = UserStore::from_keyed_users(&config.users, |user| {
            trojan_password_hash(user.credential())
        });
        let router =
            RouteDispatcher::with_connect_timeout(config.routes.clone(), config.connect_timeout);
        config.users.clear();
        config.routes.clear();
        Self {
            router,
            config,
            users,
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
        client.set_read_timeout(Some(self.config.connect_timeout))?;
        let mut request = self.read_request(&mut client)?;
        client.set_read_timeout(None)?;
        request.client_ip = client_ip;
        let user = self.request_user(&request);
        let _session = self.acquire_user_session(user.as_ref(), client_ip)?;
        let bandwidth = if request.command == TrojanCommand::UdpAssociate {
            self.bandwidth.limiter_for(user.as_ref())
        } else {
            self.bandwidth.limiter_for_limited(user.as_ref())
        };
        if request.command == TrojanCommand::UdpAssociate {
            return self.relay_udp_stream(client, request, bandwidth);
        }
        let remote = match self
            .router
            .decide_tcp(&request.target.host, request.target.port, &[])
        {
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
        self.relay(client, remote, request, bandwidth)
    }

    pub fn handle_websocket_client(&self, client: TcpStream, path: Option<&str>) -> io::Result<()> {
        client.set_read_timeout(Some(self.config.connect_timeout))?;
        let client_ip = client.peer_addr().ok().map(|addr| addr.ip());
        let (reader, writer, forwarded_ip) = accept_websocket_with_client_ip(client, path)?;
        self.handle_websocket_split_client_with_ip(reader, writer, forwarded_ip.or(client_ip))
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
        let bandwidth = if request.command == TrojanCommand::UdpAssociate {
            self.bandwidth.limiter_for(user.as_ref())
        } else {
            self.bandwidth.limiter_for_limited(user.as_ref())
        };
        if request.command == TrojanCommand::UdpAssociate {
            return self.relay_udp_split(reader, writer, request, bandwidth);
        }
        let remote = match self
            .router
            .decide_tcp(&request.target.host, request.target.port, &[])
        {
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
        self.relay_websocket(reader, writer, remote, request, bandwidth)
    }

    fn handle_websocket_split_client_with_ip(
        &self,
        mut reader: WebSocketReader,
        writer: WebSocketWriter,
        client_ip: Option<IpAddr>,
    ) -> io::Result<()> {
        reader.set_read_timeout(Some(self.config.connect_timeout))?;
        let mut request = self.read_request(&mut reader)?;
        reader.set_read_timeout(None)?;
        request.client_ip = client_ip;
        let user = self.request_user(&request);
        let session = self.acquire_user_session(user.as_ref(), client_ip)?;
        let bandwidth = if request.command == TrojanCommand::UdpAssociate {
            self.bandwidth.limiter_for(user.as_ref())
        } else {
            self.bandwidth.limiter_for_limited(user.as_ref())
        };
        if reader.peer_closed_nonblocking()? {
            let _ = reader.shutdown();
            return Ok(());
        }
        if request.command == TrojanCommand::UdpAssociate {
            return self
                .spawn_plain_websocket_udp_relay(reader, writer, request, bandwidth, session);
        }
        let Some(remote) = self.connect_tcp_for_websocket(&reader, &request)? else {
            return Ok(());
        };
        self.spawn_plain_websocket_relay(reader, writer, remote, request, bandwidth, session)
    }

    pub fn handle_tls_client(&self, mut client: TlsConnection) -> io::Result<()> {
        let client_ip = client.peer_addr().ok().map(|addr| addr.ip());
        client.set_io_timeout(Some(self.config.connect_timeout))?;
        let mut request = self.read_request(&mut client)?;
        client.set_io_timeout(None)?;
        request.client_ip = client_ip;
        let user = self.request_user(&request);
        let session = self.acquire_user_session(user.as_ref(), client_ip)?;
        let bandwidth = if request.command == TrojanCommand::UdpAssociate {
            self.bandwidth.limiter_for(user.as_ref())
        } else {
            self.bandwidth.limiter_for_limited(user.as_ref())
        };
        if request.command == TrojanCommand::UdpAssociate {
            let _session = session;
            return self.relay_udp_stream(client, request, bandwidth);
        }
        let remote = match self
            .router
            .decide_tcp(&request.target.host, request.target.port, &[])
        {
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
        self.spawn_tls_relay(client, remote, request, bandwidth, session)
    }

    pub fn handle_tls_websocket_client(
        &self,
        client: TlsConnection,
        path: Option<&str>,
    ) -> io::Result<()> {
        client.set_io_timeout(Some(self.config.connect_timeout))?;
        let client_ip = client.peer_addr().ok().map(|addr| addr.ip());
        let (mut websocket, forwarded_ip) = accept_websocket_tls_with_client_ip(client, path)?;
        websocket.set_io_timeout(Some(self.config.connect_timeout))?;
        let mut request = self.read_request(&mut websocket)?;
        websocket.set_io_timeout(None)?;
        request.client_ip = forwarded_ip.or(client_ip);
        let user = self.request_user(&request);
        let session = self.acquire_user_session(user.as_ref(), request.client_ip)?;
        let bandwidth = if request.command == TrojanCommand::UdpAssociate {
            self.bandwidth.limiter_for(user.as_ref())
        } else {
            self.bandwidth.limiter_for_limited(user.as_ref())
        };
        if websocket.peer_closed_nonblocking()? {
            let _ = websocket.shutdown();
            return Ok(());
        }
        if request.command == TrojanCommand::UdpAssociate {
            let _session = session;
            return self.relay_udp_tls_websocket(websocket, request, bandwidth);
        }
        let Some(remote) = self.connect_tcp_for_tls_websocket(&websocket, &request)? else {
            return Ok(());
        };
        self.spawn_tls_websocket_relay(websocket, remote, request, bandwidth, session)
    }

    pub fn drain_traffic(&self, minimum_bytes: u64) -> Vec<crate::traffic::TrafficDelta> {
        self.traffic.drain_minimum(minimum_bytes)
    }

    pub fn replace_users(&self, users: Vec<CoreUser>) {
        self.bandwidth.sync_users(&users);
        self.users
            .replace_keyed_users(users, |user| trojan_password_hash(user.credential()));
    }

    pub fn apply_user_delta(&self, delta: &CoreUserDelta) -> CoreUserDeltaResult {
        sync_delta_bandwidth(&self.bandwidth, &self.sessions, delta);
        self.users
            .apply_keyed_delta(delta, |user| trojan_password_hash(user.credential()))
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
            user_id: user.id,
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
        let _connection = self
            .bandwidth
            .register_tcp_connection(Some(&request.user_uuid), &[&client, &remote])?;
        let (upload, download) = match bandwidth {
            Some(limiter) => relay_tcp_limited(client, remote, limiter)?,
            None => relay_tcp_fast_unlimited(client, remote)?,
        };
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
        let remote_shutdown = remote.try_clone()?;
        let mut remote_read = remote;
        let _connection = self
            .bandwidth
            .register_tcp_connection(Some(&request.user_uuid), &[&remote_read])?;
        let upload_limiter = bandwidth.clone();
        let upload_task = spawn_native_blocking_relay(move || {
            let result = match upload_limiter.as_deref() {
                Some(limiter) => {
                    copy_count_best_effort_limited(&mut reader, &mut remote_write, Some(limiter))
                }
                None => copy_count_best_effort(&mut reader, &mut remote_write),
            };
            let _ = remote_shutdown.shutdown(Shutdown::Both);
            result
        })?;
        let download = match bandwidth.as_deref() {
            Some(limiter) => {
                copy_count_best_effort_limited(&mut remote_read, &mut writer, Some(limiter))
            }
            None => copy_count_best_effort(&mut remote_read, &mut writer),
        };
        let upload = join_native_blocking_relay(upload_task, "upload relay task panicked")?;
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

    fn relay_plain_websocket(
        &self,
        mut reader: WebSocketReader,
        mut writer: WebSocketWriter,
        mut remote: TcpStream,
        request: TrojanRequest,
        bandwidth: Option<Arc<BandwidthLimiter>>,
    ) -> io::Result<()> {
        reader.set_nonblocking(true)?;
        remote.set_nonblocking(true)?;
        let _connection = self
            .bandwidth
            .register_tcp_connection(Some(&request.user_uuid), &[&remote])?;

        let mut upload = 0u64;
        let mut download = 0u64;
        let mut upload_done = false;
        let mut download_done = false;
        let mut client_buffer = [0u8; 16 * 1024];
        let mut remote_buffer = [0u8; 16 * 1024];
        let mut idle_rounds = 0u8;

        while !upload_done || !download_done {
            let mut progressed = false;

            if !upload_done {
                match reader.read(&mut client_buffer) {
                    Ok(0) => {
                        upload_done = true;
                        download_done = true;
                        let _ = writer.shutdown();
                        let _ = remote.shutdown(Shutdown::Both);
                        progressed = true;
                    }
                    Ok(read) => {
                        if let Some(limiter) = bandwidth.as_deref() {
                            if !limiter.wait_for(read) {
                                upload_done = true;
                                download_done = true;
                                let _ = writer.shutdown();
                                let _ = remote.shutdown(Shutdown::Both);
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
                        download_done = true;
                        let _ = writer.shutdown();
                        let _ = remote.shutdown(Shutdown::Both);
                        progressed = true;
                    }
                }
            }

            if !download_done {
                match remote.read(&mut remote_buffer) {
                    Ok(0) => {
                        download_done = true;
                        upload_done = true;
                        let _ = writer.shutdown();
                        let _ = reader.shutdown();
                        let _ = remote.shutdown(Shutdown::Both);
                        progressed = true;
                    }
                    Ok(read) => {
                        write_all_wait(&mut writer, &remote_buffer[..read])?;
                        download = download.saturating_add(read as u64);
                        progressed = true;
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(_) => {
                        download_done = true;
                        upload_done = true;
                        let _ = writer.shutdown();
                        let _ = reader.shutdown();
                        let _ = remote.shutdown(Shutdown::Both);
                        progressed = true;
                    }
                }
            }

            if !progressed {
                let timeout = websocket_tls_relay_idle_timeout(&mut idle_rounds);
                reader.wait_readable_with_remote(&remote, !upload_done, !download_done, timeout)?;
            } else {
                idle_rounds = 0;
            }
        }

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

    fn spawn_plain_websocket_relay(
        &self,
        reader: WebSocketReader,
        writer: WebSocketWriter,
        remote: TcpStream,
        request: TrojanRequest,
        bandwidth: Option<Arc<BandwidthLimiter>>,
        session: Option<UserSessionGuard>,
    ) -> io::Result<()> {
        let server = self.clone();
        spawn_detached_blocking_relay("keli-core-trojan-relay", move || {
            let _session = session;
            server.relay_plain_websocket(reader, writer, remote, request, bandwidth)
        })?;
        Ok(())
    }

    fn spawn_plain_websocket_udp_relay(
        &self,
        reader: WebSocketReader,
        writer: WebSocketWriter,
        request: TrojanRequest,
        bandwidth: Option<Arc<BandwidthLimiter>>,
        session: Option<UserSessionGuard>,
    ) -> io::Result<()> {
        let server = self.clone();
        spawn_detached_blocking_relay("keli-core-trojan-relay", move || {
            let _session = session;
            server.relay_udp_plain_websocket(reader, writer, request, bandwidth)
        })?;
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

    fn relay_tls_websocket(
        &self,
        client: crate::websocket::WebSocketTlsStream,
        remote: TcpStream,
        request: TrojanRequest,
        bandwidth: Option<Arc<BandwidthLimiter>>,
    ) -> io::Result<()> {
        let (upload, download) = relay_websocket_tls_stream(client, remote, bandwidth)?;
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

    fn spawn_tls_relay(
        &self,
        client: TlsConnection,
        remote: TcpStream,
        request: TrojanRequest,
        bandwidth: Option<Arc<BandwidthLimiter>>,
        session: Option<UserSessionGuard>,
    ) -> io::Result<()> {
        let server = self.clone();
        spawn_detached_blocking_relay("keli-core-trojan-relay", move || {
            let _session = session;
            server.relay_tls(client, remote, request, bandwidth)
        })?;
        Ok(())
    }

    fn spawn_tls_websocket_relay(
        &self,
        client: crate::websocket::WebSocketTlsStream,
        remote: TcpStream,
        request: TrojanRequest,
        bandwidth: Option<Arc<BandwidthLimiter>>,
        session: Option<UserSessionGuard>,
    ) -> io::Result<()> {
        let server = self.clone();
        spawn_detached_blocking_relay("keli-core-trojan-relay", move || {
            let _session = session;
            server.relay_tls_websocket(client, remote, request, bandwidth)
        })?;
        Ok(())
    }

    fn connect_tcp_for_websocket(
        &self,
        client: &WebSocketReader,
        request: &TrojanRequest,
    ) -> io::Result<Option<TcpStream>> {
        let router = self.router.clone();
        let target = request.target.clone();
        let timeout = self.config.connect_timeout;
        let (sender, receiver) = mpsc::channel();
        thread::Builder::new()
            .name("keli-core-trojan-connect".to_string())
            .stack_size(TROJAN_CONNECT_THREAD_STACK)
            .spawn(move || {
                let result = match router.decide_tcp(&target.host, target.port, &[]) {
                    RouteDecision::Direct => connect_target(&target, timeout),
                    RouteDecision::Outbound(outbound) => {
                        connect_tcp_outbound(&outbound, &target, timeout)
                    }
                    RouteDecision::Block => Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "target blocked by route",
                    )),
                    RouteDecision::UnsupportedOutbound(tag) => Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        format!("outbound route {tag} is not implemented"),
                    )),
                };
                let _ = sender.send(result);
            })
            .map_err(|source| {
                io::Error::new(
                    source.kind(),
                    format!("spawn trojan websocket connect worker: {source}"),
                )
            })?;

        loop {
            match receiver.try_recv() {
                Ok(result) => return result.map(Some),
                Err(mpsc::TryRecvError::Disconnected) => {
                    return Err(io::Error::other(
                        "trojan websocket connect worker stopped before sending result",
                    ));
                }
                Err(mpsc::TryRecvError::Empty) => {}
            }
            if client.peer_closed_nonblocking()? {
                let _ = client.shutdown();
                return Ok(None);
            }
            thread::sleep(CLIENT_CLOSE_CONNECT_POLL);
        }
    }

    fn connect_tcp_for_tls_websocket(
        &self,
        client: &crate::websocket::WebSocketTlsStream,
        request: &TrojanRequest,
    ) -> io::Result<Option<TcpStream>> {
        let router = self.router.clone();
        let target = request.target.clone();
        let timeout = self.config.connect_timeout;
        let (sender, receiver) = mpsc::channel();
        thread::Builder::new()
            .name("keli-core-trojan-connect".to_string())
            .stack_size(TROJAN_CONNECT_THREAD_STACK)
            .spawn(move || {
                let result = match router.decide_tcp(&target.host, target.port, &[]) {
                    RouteDecision::Direct => connect_target(&target, timeout),
                    RouteDecision::Outbound(outbound) => {
                        connect_tcp_outbound(&outbound, &target, timeout)
                    }
                    RouteDecision::Block => Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "target blocked by route",
                    )),
                    RouteDecision::UnsupportedOutbound(tag) => Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        format!("outbound route {tag} is not implemented"),
                    )),
                };
                let _ = sender.send(result);
            })
            .map_err(|error| {
                io::Error::new(
                    error.kind(),
                    format!("failed to spawn trojan outbound connector: {error}"),
                )
            })?;

        loop {
            match receiver.recv_timeout(CLIENT_CLOSE_CONNECT_POLL) {
                Ok(result) => return result.map(Some),
                Err(mpsc::RecvTimeoutError::Timeout) => {
                    if client.peer_closed_nonblocking()? {
                        let _ = client.shutdown();
                        return Ok(None);
                    }
                }
                Err(mpsc::RecvTimeoutError::Disconnected) => {
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "trojan outbound connector exited without result",
                    ));
                }
            }
        }
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
        self.record_traffic(
            request.user_uuid,
            request.user_id,
            upload,
            download,
            request.client_ip,
        );
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
        self.record_traffic(
            request.user_uuid,
            request.user_id,
            upload,
            download,
            request.client_ip,
        );
        result
    }

    fn relay_udp_plain_websocket(
        &self,
        reader: WebSocketReader,
        writer: WebSocketWriter,
        request: TrojanRequest,
        bandwidth: Option<Arc<BandwidthLimiter>>,
    ) -> io::Result<()> {
        let state = Arc::new(Mutex::new(TrojanUdpRelayState::new(
            self.config.connect_timeout,
        )));
        let writer = Arc::new(Mutex::new(writer));
        let stop = Arc::new(AtomicBool::new(false));
        let upload = Arc::new(AtomicU64::new(0));
        let download = Arc::new(AtomicU64::new(0));

        let upload_task = {
            let server = self.clone();
            let state = state.clone();
            let writer = writer.clone();
            let stop = stop.clone();
            let upload = upload.clone();
            let download = download.clone();
            spawn_native_blocking_relay(move || {
                server.relay_udp_plain_websocket_upload(
                    reader, state, writer, stop, upload, download, bandwidth,
                )
            })?
        };

        let mut idle_rounds = 0u8;
        let mut result = Ok(());
        while !stop.load(Ordering::SeqCst) {
            let mut progressed = false;
            loop {
                let packet = {
                    let state = state
                        .lock()
                        .map_err(|_| io::Error::new(io::ErrorKind::Other, "udp state poisoned"))?;
                    state.recv_available()?
                };
                let Some((source, payload)) = packet else {
                    break;
                };
                let packet = encode_trojan_udp_packet(source, &payload);
                let write_result = writer
                    .lock()
                    .map_err(|_| io::Error::new(io::ErrorKind::Other, "websocket writer poisoned"))?
                    .write_all(&packet);
                match write_result {
                    Ok(()) => {
                        download.fetch_add(payload.len() as u64, Ordering::Relaxed);
                        progressed = true;
                    }
                    Err(error) if is_stream_closed(&error) => {
                        stop.store(true, Ordering::SeqCst);
                        break;
                    }
                    Err(error) => {
                        stop.store(true, Ordering::SeqCst);
                        result = Err(error);
                        break;
                    }
                }
            }

            if result.is_err() || stop.load(Ordering::SeqCst) {
                break;
            }
            if !progressed {
                let timeout = websocket_udp_relay_idle_timeout(&mut idle_rounds);
                thread::sleep(timeout);
            } else {
                idle_rounds = 0;
            }
        }

        let _ = writer
            .lock()
            .map_err(|_| io::Error::new(io::ErrorKind::Other, "websocket writer poisoned"))
            .and_then(|writer| writer.shutdown());
        let upload_result =
            join_native_blocking_relay(upload_task, "trojan websocket UDP upload relay panicked")?;
        if result.is_ok() {
            result = upload_result;
        }
        self.record_traffic(
            request.user_uuid,
            request.user_id,
            upload.load(Ordering::Relaxed),
            download.load(Ordering::Relaxed),
            request.client_ip,
        );
        result
    }

    fn relay_udp_plain_websocket_upload(
        &self,
        mut reader: WebSocketReader,
        state: Arc<Mutex<TrojanUdpRelayState>>,
        writer: Arc<Mutex<WebSocketWriter>>,
        stop: Arc<AtomicBool>,
        upload: Arc<AtomicU64>,
        download: Arc<AtomicU64>,
        bandwidth: Option<Arc<BandwidthLimiter>>,
    ) -> io::Result<()> {
        let result = loop {
            match read_trojan_udp_packet(&mut reader) {
                Ok((target, payload)) => {
                    let response = {
                        let mut state = state.lock().map_err(|_| {
                            io::Error::new(io::ErrorKind::Other, "udp state poisoned")
                        })?;
                        self.send_udp_packet(&mut state, &target, &payload, bandwidth.as_deref())
                    };
                    match response {
                        Ok((sent, response)) => {
                            upload.fetch_add(sent, Ordering::Relaxed);
                            if let Some((source, payload)) = response {
                                let packet = encode_trojan_udp_packet(source, &payload);
                                writer
                                    .lock()
                                    .map_err(|_| {
                                        io::Error::new(
                                            io::ErrorKind::Other,
                                            "websocket writer poisoned",
                                        )
                                    })?
                                    .write_all(&packet)?;
                                download.fetch_add(payload.len() as u64, Ordering::Relaxed);
                            }
                        }
                        Err(error) => break Err(error),
                    }
                }
                Err(error) if is_stream_closed(&error) => break Ok(()),
                Err(error) => break Err(error),
            }
        };
        stop.store(true, Ordering::SeqCst);
        let _ = reader.shutdown();
        result
    }

    fn relay_udp_tls_websocket(
        &self,
        mut client: crate::websocket::WebSocketTlsStream,
        request: TrojanRequest,
        bandwidth: Option<Arc<BandwidthLimiter>>,
    ) -> io::Result<()> {
        client.set_nonblocking(true)?;
        let mut state = TrojanUdpRelayState::new(self.config.connect_timeout);
        let mut pending = Vec::new();
        let mut upload = 0u64;
        let mut download = 0u64;
        let mut idle_rounds = 0u8;
        let result = 'relay: loop {
            let mut progressed = false;
            let mut input = [0u8; 16 * 1024];

            match client.read(&mut input) {
                Ok(0) => break 'relay Ok(()),
                Ok(read) => {
                    pending.extend_from_slice(&input[..read]);
                    progressed = true;
                    while let Some((target, payload)) =
                        parse_trojan_udp_packet_from_buffer(&mut pending)?
                    {
                        match self.send_udp_packet(
                            &mut state,
                            &target,
                            &payload,
                            bandwidth.as_deref(),
                        ) {
                            Ok((sent, response)) => {
                                upload = upload.saturating_add(sent);
                                if let Some((source, payload)) = response {
                                    let packet = encode_trojan_udp_packet(source, &payload);
                                    client.write_all(&packet)?;
                                    download = download.saturating_add(payload.len() as u64);
                                }
                            }
                            Err(error) => break 'relay Err(error),
                        }
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) if is_stream_closed(&error) => break 'relay Ok(()),
                Err(error) => break 'relay Err(error),
            }

            while let Some((source, payload)) = state.recv_available()? {
                let packet = encode_trojan_udp_packet(source, &payload);
                client.write_all(&packet)?;
                download = download.saturating_add(payload.len() as u64);
                progressed = true;
            }

            if !progressed {
                let timeout = websocket_udp_relay_idle_timeout(&mut idle_rounds);
                thread::sleep(timeout);
            } else {
                idle_rounds = 0;
            }
        };
        let _ = client.set_nonblocking(false);
        self.record_traffic(
            request.user_uuid,
            request.user_id,
            upload,
            download,
            request.client_ip,
        );
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

        if let Some(limiter) = bandwidth {
            if !limiter.wait_for(payload.len()) {
                return Ok((0, 0));
            }
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

        let remote_addr = state.remote_addr_for(target)?;
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

    fn send_udp_packet(
        &self,
        state: &mut TrojanUdpRelayState,
        target: &SocksTarget,
        payload: &[u8],
        bandwidth: Option<&BandwidthLimiter>,
    ) -> io::Result<(u64, Option<(SocketAddr, Vec<u8>)>)> {
        let decision = self.router.decide_udp(&target.host, target.port, payload);
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
                Ok((source, response)) => Ok((payload.len() as u64, Some((source, response)))),
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
        let udp = state.socket_for_nonblocking(remote_addr)?;
        udp.send_to(payload, remote_addr)?;
        Ok((payload.len() as u64, None))
    }

    fn record_traffic(
        &self,
        user_uuid: String,
        user_id: u64,
        upload: u64,
        download: u64,
        client_ip: Option<IpAddr>,
    ) {
        self.traffic.add_with_user_id(
            self.config.node_tag.clone(),
            user_uuid,
            Some(user_id),
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

fn sync_delta_bandwidth(
    bandwidth: &UserBandwidthLimiters,
    sessions: &UserSessionTracker,
    delta: &CoreUserDelta,
) {
    sync_user_limit_delta(bandwidth, sessions, delta);
}

impl TrojanUdpRelayState {
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

    fn socket_for_nonblocking(&mut self, remote: SocketAddr) -> io::Result<&UdpSocket> {
        let slot = if remote.is_ipv4() {
            &mut self.ipv4
        } else {
            &mut self.ipv6
        };
        if slot.is_none() {
            let socket = UdpSocket::bind(udp_bind_addr_for_remote(remote))?;
            socket.set_nonblocking(true)?;
            *slot = Some(socket);
        }
        Ok(slot.as_ref().expect("udp socket initialized"))
    }

    fn recv_available(&self) -> io::Result<Option<(SocketAddr, Vec<u8>)>> {
        if let Some(packet) = recv_available_from_socket(self.ipv4.as_ref())? {
            return Ok(Some(packet));
        }
        recv_available_from_socket(self.ipv6.as_ref())
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
    let network = outbound_transport_network(outbound).to_ascii_lowercase();
    if network == "ws" {
        return connect_trojan_websocket_tcp_outbound(outbound, &server, password, target, timeout);
    }
    if network == "httpupgrade" {
        return connect_trojan_httpupgrade_tcp_outbound(
            outbound, &server, password, target, timeout,
        );
    }
    if network == "grpc" {
        return connect_trojan_grpc_tcp_outbound(outbound, &server, password, target, timeout);
    }
    if matches!(network.as_str(), "h2" | "http") {
        return connect_trojan_h2_tcp_outbound(outbound, &server, password, target, timeout);
    }
    if network == "quic" {
        return connect_trojan_quic_tcp_outbound(outbound, &server, password, target, timeout);
    }
    if network != "tcp" {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("trojan outbound transport {network} is not supported yet"),
        ));
    }
    if outbound.tls.is_some() {
        return connect_trojan_tls_tcp_outbound(outbound, &server, password, target, timeout);
    }
    let mut stream = connect_target(&server, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    write_trojan_tcp_request(&mut stream, password, target)?;
    Ok(stream)
}

fn connect_trojan_h2_tcp_outbound(
    outbound: &OutboundConfig,
    server: &SocksTarget,
    password: &str,
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
    write_trojan_tcp_request(&mut h2, password, target)?;
    h2.flush()?;
    local_bridge_for_http2(h2)
}

fn connect_trojan_quic_tcp_outbound(
    outbound: &OutboundConfig,
    server: &SocksTarget,
    password: &str,
    target: &SocksTarget,
    timeout: Duration,
) -> io::Result<TcpStream> {
    let mut quic = connect_quic_client_stream(
        server,
        timeout,
        outbound.tls.as_ref(),
        outbound.transport.as_ref(),
    )?;
    write_trojan_tcp_request(&mut quic, password, target)?;
    Ok(quic)
}

fn connect_trojan_grpc_tcp_outbound(
    outbound: &OutboundConfig,
    server: &SocksTarget,
    password: &str,
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
    write_trojan_tcp_request(&mut grpc, password, target)?;
    grpc.flush()?;
    grpc.set_nonblocking(true);
    local_bridge_for_grpc(grpc)
}

fn connect_trojan_httpupgrade_tcp_outbound(
    outbound: &OutboundConfig,
    server: &SocksTarget,
    password: &str,
    target: &SocksTarget,
    timeout: Duration,
) -> io::Result<TcpStream> {
    if outbound.tls.is_some() {
        let tls_stream = connect_trojan_tls_stream(outbound, server, timeout)?;
        let host = outbound_transport_host(outbound, server);
        let mut tls_stream =
            connect_httpupgrade_client(tls_stream, outbound_transport_path(outbound), &host)?;
        write_trojan_tcp_request(&mut tls_stream, password, target)?;
        tls_stream.flush()?;

        let local_listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
        let local_addr = local_listener.local_addr()?;
        let local_client = TcpStream::connect(local_addr)?;
        let (local_plain, _) = local_listener.accept()?;

        let _ = spawn_native_blocking_relay(move || {
            let _ = relay_plain_to_tls(local_plain, tls_stream);
        })?;

        return Ok(local_client);
    }

    let remote = connect_target(server, timeout)?;
    remote.set_read_timeout(Some(timeout))?;
    remote.set_write_timeout(Some(timeout))?;
    let host = outbound_transport_host(outbound, server);
    let mut stream = connect_httpupgrade_client(remote, outbound_transport_path(outbound), &host)?;
    write_trojan_tcp_request(&mut stream, password, target)?;
    Ok(stream)
}

fn connect_trojan_websocket_tcp_outbound(
    outbound: &OutboundConfig,
    server: &SocksTarget,
    password: &str,
    target: &SocksTarget,
    timeout: Duration,
) -> io::Result<TcpStream> {
    if outbound.tls.is_some() {
        let tls_stream = connect_trojan_tls_stream(outbound, server, timeout)?;
        let host = outbound_transport_host(outbound, server);
        let mut websocket =
            connect_websocket_client(tls_stream, outbound_transport_path(outbound), &host)?;
        write_trojan_tcp_request(&mut websocket, password, target)?;
        websocket.flush()?;
        websocket.get_mut().sock.set_nonblocking(true)?;
        return local_bridge_for_websocket(websocket);
    }

    let remote = connect_target(server, timeout)?;
    remote.set_read_timeout(Some(timeout))?;
    remote.set_write_timeout(Some(timeout))?;
    let host = outbound_transport_host(outbound, server);
    let mut websocket = connect_websocket_client(remote, outbound_transport_path(outbound), &host)?;
    write_trojan_tcp_request(&mut websocket, password, target)?;
    websocket.flush()?;
    websocket.get_mut().set_nonblocking(true)?;
    local_bridge_for_websocket(websocket)
}

fn connect_trojan_tls_tcp_outbound(
    outbound: &OutboundConfig,
    server: &SocksTarget,
    password: &str,
    target: &SocksTarget,
    timeout: Duration,
) -> io::Result<TcpStream> {
    let mut tls_stream = connect_trojan_tls_stream(outbound, server, timeout)?;
    write_trojan_tcp_request(&mut tls_stream, password, target)?;
    tls_stream.flush()?;

    let local_listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
    let local_addr = local_listener.local_addr()?;
    let local_client = TcpStream::connect(local_addr)?;
    let (local_plain, _) = local_listener.accept()?;

    let _ = spawn_native_blocking_relay(move || {
        let _ = relay_plain_to_tls(local_plain, tls_stream);
    })?;

    Ok(local_client)
}

fn connect_trojan_tls_stream(
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
    let server_name = trojan_tls_server_name(tls_config, server)?;
    let connection = ClientConnection::new(trojan_tls_client_config(tls_config), server_name)
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

fn trojan_tls_client_config(tls: &OutboundTlsConfig) -> Arc<ClientConfig> {
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

fn trojan_tls_server_name(
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
            "trojan tls server_name is invalid",
        )
    })
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

fn relay_plain_to_tls(
    mut plain: TcpStream,
    mut tls_stream: StreamOwned<ClientConnection, TcpStream>,
) -> io::Result<()> {
    plain.set_nonblocking(true)?;
    tls_stream.sock.set_nonblocking(true)?;

    let mut upload_done = false;
    let mut download_done = false;
    let mut upload_buffer = [0u8; 16 * 1024];
    let mut download_buffer = [0u8; 16 * 1024];

    while !upload_done || !download_done {
        let mut progressed = false;

        if !upload_done {
            match plain.read(&mut upload_buffer) {
                Ok(0) => {
                    upload_done = true;
                    tls_stream.conn.send_close_notify();
                    let _ = tls_stream.flush();
                    progressed = true;
                }
                Ok(read) => {
                    write_all_wait(&mut tls_stream, &upload_buffer[..read])?;
                    progressed = true;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(_) => {
                    upload_done = true;
                    tls_stream.conn.send_close_notify();
                    let _ = tls_stream.flush();
                    progressed = true;
                }
            }
        }

        if !download_done {
            match tls_stream.read(&mut download_buffer) {
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

    let _ = plain.shutdown(Shutdown::Both);
    let _ = tls_stream.sock.shutdown(Shutdown::Both);
    Ok(())
}

fn local_bridge_for_websocket<S>(websocket: WebSocketClientStream<S>) -> io::Result<TcpStream>
where
    S: Read + Write + Send + 'static,
{
    let local_listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
    let local_addr = local_listener.local_addr()?;
    let local_client = TcpStream::connect(local_addr)?;
    let (local_plain, _) = local_listener.accept()?;

    let _ = spawn_native_blocking_relay(move || {
        let _ = relay_plain_to_websocket(local_plain, websocket);
    })?;

    Ok(local_client)
}

fn local_bridge_for_grpc(grpc: GrpcClientStream) -> io::Result<TcpStream> {
    let local_listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
    let local_addr = local_listener.local_addr()?;
    let local_client = TcpStream::connect(local_addr)?;
    let (local_plain, _) = local_listener.accept()?;

    let _ = spawn_native_blocking_relay(move || {
        let _ = relay_plain_to_grpc(local_plain, grpc);
    })?;

    Ok(local_client)
}

fn relay_plain_to_websocket<S>(
    mut plain: TcpStream,
    mut websocket: WebSocketClientStream<S>,
) -> io::Result<()>
where
    S: Read + Write,
{
    plain.set_nonblocking(true)?;

    let mut upload_done = false;
    let mut download_done = false;
    let mut upload_buffer = [0u8; 16 * 1024];
    let mut download_buffer = [0u8; 16 * 1024];

    while !upload_done || !download_done {
        let mut progressed = false;

        if !upload_done {
            match plain.read(&mut upload_buffer) {
                Ok(0) => {
                    upload_done = true;
                    let _ = websocket.flush();
                    progressed = true;
                }
                Ok(read) => {
                    write_all_wait(&mut websocket, &upload_buffer[..read])?;
                    progressed = true;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(_) => {
                    upload_done = true;
                    let _ = websocket.flush();
                    progressed = true;
                }
            }
        }

        if !download_done {
            match websocket.read(&mut download_buffer) {
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

    let _ = plain.shutdown(Shutdown::Both);
    Ok(())
}

fn relay_plain_to_grpc(mut plain: TcpStream, mut grpc: GrpcClientStream) -> io::Result<()> {
    plain.set_nonblocking(true)?;

    let mut upload_done = false;
    let mut download_done = false;
    let mut upload_buffer = [0u8; 16 * 1024];
    let mut download_buffer = [0u8; 16 * 1024];

    while !upload_done || !download_done {
        let mut progressed = false;

        if !upload_done {
            match plain.read(&mut upload_buffer) {
                Ok(0) => {
                    upload_done = true;
                    let _ = grpc.flush();
                    progressed = true;
                }
                Ok(read) => {
                    write_all_wait(&mut grpc, &upload_buffer[..read])?;
                    progressed = true;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(_) => {
                    upload_done = true;
                    let _ = grpc.flush();
                    progressed = true;
                }
            }
        }

        if !download_done {
            match grpc.read(&mut download_buffer) {
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

    let _ = plain.shutdown(Shutdown::Both);
    Ok(())
}

fn write_all_wait<W: Write>(writer: &mut W, mut input: &[u8]) -> io::Result<()> {
    while !input.is_empty() {
        match writer.write(input) {
            Ok(0) => {
                return Err(io::Error::new(
                    io::ErrorKind::WriteZero,
                    "socket write returned zero",
                ));
            }
            Ok(written) => input = &input[written..],
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                thread::sleep(Duration::from_millis(1));
            }
            Err(error) => return Err(error),
        }
    }
    writer.flush()
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

fn parse_trojan_udp_packet_from_buffer(
    buffer: &mut Vec<u8>,
) -> io::Result<Option<(SocksTarget, Vec<u8>)>> {
    let Some((target, target_len)) = parse_trojan_target_from_bytes(buffer)? else {
        return Ok(None);
    };
    if buffer.len() < target_len + 4 {
        return Ok(None);
    }
    let len_offset = target_len;
    let payload_len = u16::from_be_bytes([buffer[len_offset], buffer[len_offset + 1]]) as usize;
    let crlf_offset = len_offset + 2;
    if &buffer[crlf_offset..crlf_offset + 2] != b"\r\n" {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid trojan udp crlf",
        ));
    }
    let payload_offset = crlf_offset + 2;
    let total_len = payload_offset + payload_len;
    if buffer.len() < total_len {
        return Ok(None);
    }
    let payload = buffer[payload_offset..total_len].to_vec();
    buffer.drain(..total_len);
    Ok(Some((target, payload)))
}

fn parse_trojan_target_from_bytes(bytes: &[u8]) -> io::Result<Option<(SocksTarget, usize)>> {
    if bytes.is_empty() {
        return Ok(None);
    }
    let mut offset = 1usize;
    let host = match bytes[0] {
        ATYP_IPV4 => {
            if bytes.len() < offset + 4 {
                return Ok(None);
            }
            let ip = Ipv4Addr::new(
                bytes[offset],
                bytes[offset + 1],
                bytes[offset + 2],
                bytes[offset + 3],
            );
            offset += 4;
            ip.to_string()
        }
        ATYP_DOMAIN => {
            if bytes.len() < offset + 1 {
                return Ok(None);
            }
            let len = usize::from(bytes[offset]);
            offset += 1;
            if bytes.len() < offset + len {
                return Ok(None);
            }
            let host = std::str::from_utf8(&bytes[offset..offset + len])
                .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid domain"))?
                .to_string();
            offset += len;
            host
        }
        ATYP_IPV6 => {
            if bytes.len() < offset + 16 {
                return Ok(None);
            }
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&bytes[offset..offset + 16]);
            offset += 16;
            Ipv6Addr::from(ip).to_string()
        }
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported trojan address type",
            ));
        }
    };

    if bytes.len() < offset + 2 {
        return Ok(None);
    }
    let port = u16::from_be_bytes([bytes[offset], bytes[offset + 1]]);
    offset += 2;
    Ok(Some((SocksTarget { host, port }, offset)))
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

fn recv_available_from_socket(
    socket: Option<&UdpSocket>,
) -> io::Result<Option<(SocketAddr, Vec<u8>)>> {
    let Some(socket) = socket else {
        return Ok(None);
    };
    let mut buffer = vec![0u8; MAX_UDP_PACKET_SIZE];
    match socket.recv_from(&mut buffer) {
        Ok((read, source)) => {
            buffer.truncate(read);
            Ok(Some((source, buffer)))
        }
        Err(error)
            if matches!(
                error.kind(),
                io::ErrorKind::WouldBlock
                    | io::ErrorKind::TimedOut
                    | io::ErrorKind::ConnectionReset
            ) =>
        {
            Ok(None)
        }
        Err(error) => Err(error),
    }
}

fn websocket_udp_relay_idle_timeout(idle_rounds: &mut u8) -> Duration {
    const BACKOFF_MS: [u64; 4] = [1, 2, 5, 10];
    let idx = usize::from((*idle_rounds).min((BACKOFF_MS.len() - 1) as u8));
    *idle_rounds = idle_rounds
        .saturating_add(1)
        .min((BACKOFF_MS.len() - 1) as u8);
    Duration::from_millis(BACKOFF_MS[idx])
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
    use std::io::{self, Cursor, Read, Write};
    use std::net::{Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket};
    use std::path::PathBuf;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        mpsc, Arc,
    };
    use std::thread;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    use rustls::pki_types::{CertificateDer, ServerName};
    use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

    use crate::config::{
        OutboundConfig, OutboundTlsConfig, OutboundTransportConfig, RouteAction, RouteRule,
    };
    use crate::grpc::{run_grpc_listener, GrpcStreamHandler};
    use crate::http2::{run_http2_listener, Http2StreamHandler};
    use crate::httpupgrade::accept_httpupgrade;
    use crate::socks5::SocksTarget;
    use crate::tls::TlsAcceptor;
    use crate::trojan::{
        connect_trojan_tcp_outbound, trojan_password_hash, TrojanServer, TrojanServerConfig,
    };
    use crate::user::{CoreUser, CoreUserDelta};
    use crate::websocket::accept_websocket;

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

    fn server_with_routes(routes: Vec<RouteRule>, connect_timeout: Duration) -> TrojanServer {
        TrojanServer::new(TrojanServerConfig {
            node_tag: "panel|trojan|1".to_string(),
            listen: "127.0.0.1:0".parse().expect("listen addr"),
            users: vec![user()],
            routes,
            connect_timeout,
        })
    }

    #[test]
    fn apply_user_delta_updates_trojan_users() {
        let server = server();
        let mut updated = user();
        updated.password = Some("rotated-trojan".to_string());
        updated.speed_limit = 456;
        updated.device_limit = 5;

        let result = server.apply_user_delta(&CoreUserDelta {
            added: vec![user_b()],
            updated: vec![updated.clone()],
            ..CoreUserDelta::default()
        });

        assert_eq!(result.added, 1);
        assert_eq!(result.updated, 1);
        assert_eq!(result.active_users, 2);
        assert!(server
            .users
            .get(&trojan_password_hash("trojan-password"))
            .is_none());
        let user = server
            .users
            .get(&trojan_password_hash("rotated-trojan"))
            .expect("updated trojan user should authenticate");
        assert_eq!(user.speed_limit, 456);
        assert_eq!(user.device_limit, 5);
        assert!(server
            .users
            .get(&trojan_password_hash("secret-b"))
            .is_some());

        let result = server.apply_user_delta(&CoreUserDelta {
            deleted: vec![updated.uuid.clone()],
            ..CoreUserDelta::default()
        });

        assert_eq!(result.deleted, 1);
        assert_eq!(result.active_users, 1);
        assert!(server
            .users
            .get(&trojan_password_hash("rotated-trojan"))
            .is_none());
        assert!(server
            .users
            .get(&trojan_password_hash("secret-b"))
            .is_some());
    }

    #[test]
    fn apply_user_delta_changes_trojan_auth_without_rebinding_listener() {
        let echo = TcpListener::bind("127.0.0.1:0").expect("echo bind");
        let echo_addr = echo.local_addr().expect("echo addr");
        let echo_thread = thread::spawn(move || {
            for _ in 0..2 {
                let (mut stream, _) = echo.accept().expect("echo accept");
                let mut buffer = [0u8; 1];
                stream.read_exact(&mut buffer).expect("echo read");
                stream.write_all(&buffer).expect("echo write");
            }
        });

        let server = server();
        let listener = server.bind().expect("trojan bind");
        listener
            .set_nonblocking(true)
            .expect("trojan listener nonblocking");
        let trojan_addr = listener.local_addr().expect("trojan addr");
        let stop = Arc::new(AtomicBool::new(false));
        let server_stop = stop.clone();
        let server_clone = server.clone();
        let server_thread = thread::spawn(move || {
            let mut workers = Vec::new();
            while !server_stop.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((stream, _)) => {
                        let server = server_clone.clone();
                        workers.push(thread::spawn(move || {
                            let _ = server.handle_tcp_client(stream);
                        }));
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("trojan accept: {error}"),
                }
            }
            for worker in workers {
                worker.join().expect("trojan worker");
            }
        });

        assert!(trojan_auth_succeeds_eventually(
            trojan_addr,
            "trojan-password",
            echo_addr
        ));

        let result = server.apply_user_delta(&CoreUserDelta {
            added: vec![user_b()],
            deleted: vec![user().uuid],
            ..CoreUserDelta::default()
        });

        assert_eq!(result.added, 1);
        assert_eq!(result.deleted, 1);
        assert_eq!(result.active_users, 1);
        assert!(!trojan_auth_succeeds(
            trojan_addr,
            "trojan-password",
            echo_addr
        ));
        assert!(trojan_auth_succeeds_eventually(
            trojan_addr,
            "secret-b",
            echo_addr
        ));

        stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(trojan_addr);
        server_thread.join().expect("trojan server thread");
        echo_thread.join().expect("echo thread");
    }

    #[test]
    fn deleting_trojan_user_stops_existing_tcp_relay_on_next_payload_and_reports_tail() {
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
        let listener = server.bind().expect("trojan bind");
        let trojan_addr = listener.local_addr().expect("trojan addr");
        let server_clone = server.clone();
        let server_thread = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("trojan accept");
            server_clone.handle_tcp_client(stream)
        });

        let mut client = TcpStream::connect(trojan_addr).expect("client connect");
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .expect("client read timeout");
        client
            .set_write_timeout(Some(Duration::from_secs(1)))
            .expect("client write timeout");
        client
            .write_all(&trojan_request(echo_addr))
            .expect("trojan request");
        client.write_all(b"x").expect("first write");
        let mut echoed = [0u8; 1];
        client.read_exact(&mut echoed).expect("first echo");
        assert_eq!(echoed, *b"x");

        let result = server.apply_user_delta(&CoreUserDelta {
            deleted: vec![user().uuid],
            ..CoreUserDelta::default()
        });
        assert_eq!(result.deleted, 1);

        assert!(
            tcp_connection_closed_eventually(&client),
            "deleted user's existing Trojan relay should close"
        );

        assert!(
            !second_payload_rx
                .recv_timeout(Duration::from_secs(2))
                .expect("echo result"),
            "deleted user's existing Trojan relay should stop forwarding new payload"
        );
        drop(client);
        server_thread
            .join()
            .expect("server thread")
            .expect("serve once");
        echo_thread.join().expect("echo thread");

        let records = drain_trojan_traffic_eventually(&server, 1);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].node_tag, "panel|trojan|1");
        assert_eq!(records[0].user_uuid, "trojan-password");
        assert_eq!(records[0].user_id, Some(1));
        assert_eq!(records[0].upload, 1);
        assert_eq!(records[0].download, 1);
    }

    fn tcp_connection_closed_eventually(stream: &TcpStream) -> bool {
        let _ = stream.set_read_timeout(Some(Duration::from_millis(20)));
        for _ in 0..250 {
            let mut probe = [0u8; 1];
            match stream.peek(&mut probe) {
                Ok(0) => return true,
                Ok(_) => return false,
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::WouldBlock
                            | io::ErrorKind::TimedOut
                            | io::ErrorKind::Interrupted
                    ) =>
                {
                    thread::sleep(Duration::from_millis(20));
                }
                Err(error)
                    if matches!(
                        error.kind(),
                        io::ErrorKind::ConnectionReset
                            | io::ErrorKind::ConnectionAborted
                            | io::ErrorKind::NotConnected
                            | io::ErrorKind::BrokenPipe
                    ) =>
                {
                    return true;
                }
                Err(_) => return true,
            }
        }
        false
    }

    fn drain_trojan_traffic_eventually(
        server: &TrojanServer,
        minimum_bytes: u64,
    ) -> Vec<crate::traffic::TrafficDelta> {
        for _ in 0..250 {
            let records = server.drain_traffic(minimum_bytes);
            if !records.is_empty() {
                return records;
            }
            thread::sleep(Duration::from_millis(20));
        }
        server.drain_traffic(minimum_bytes)
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

    fn trojan_auth_succeeds(
        server_addr: std::net::SocketAddr,
        password: &str,
        target: std::net::SocketAddr,
    ) -> bool {
        let Ok(mut stream) = TcpStream::connect(server_addr) else {
            return false;
        };
        let _ = stream.set_read_timeout(Some(Duration::from_secs(10)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(10)));
        if stream
            .write_all(&trojan_request_with_password_and_command(
                target, password, 0x01,
            ))
            .is_err()
        {
            return false;
        }
        if stream.write_all(b"x").is_err() {
            return false;
        }
        let mut response = [0u8; 1];
        stream.read_exact(&mut response).is_ok() && response == *b"x"
    }

    fn trojan_auth_succeeds_eventually(
        server_addr: std::net::SocketAddr,
        password: &str,
        target: std::net::SocketAddr,
    ) -> bool {
        for _ in 0..3 {
            if trojan_auth_succeeds(server_addr, password, target) {
                return true;
            }
            thread::sleep(Duration::from_millis(20));
        }
        false
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

    fn websocket_request_with_forwarded_for(path: &str, forwarded_for: &str) -> Vec<u8> {
        format!(
            "GET {path} HTTP/1.1\r\nHost: example.test\r\nConnection: Upgrade\r\nUpgrade: websocket\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Version: 13\r\nX-Forwarded-For: {forwarded_for}\r\n\r\n"
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
            alter_id: None,
            address: Some(proxy_addr.ip().to_string()),
            port: Some(proxy_addr.port()),
            username: None,
            password: Some("trojan-password".to_string()),
            tls: None,
            transport: None,
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
    fn trojan_tls_tcp_outbound_writes_request_and_relays_stream() {
        let cert = test_cert("trojan-out-tls");
        let proxy = TcpListener::bind("127.0.0.1:0").expect("proxy bind");
        let proxy_addr = proxy.local_addr().expect("proxy addr");
        let acceptor =
            TlsAcceptor::from_files(&cert.cert_path, &cert.key_path, &[]).expect("tls acceptor");
        let proxy_thread = thread::spawn(move || {
            let (stream, _) = proxy.accept().expect("proxy accept");
            let mut stream = acceptor.accept(stream).expect("tls accept");
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
            alter_id: None,
            address: Some(proxy_addr.ip().to_string()),
            port: Some(proxy_addr.port()),
            username: None,
            password: Some("trojan-password".to_string()),
            tls: Some(OutboundTlsConfig {
                server_name: "localhost".to_string(),
                allow_insecure: true,
                alpn: Vec::new(),
            }),
            transport: None,
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
    fn trojan_websocket_outbound_writes_request_and_relays_stream() {
        let proxy = TcpListener::bind("127.0.0.1:0").expect("proxy bind");
        let proxy_addr = proxy.local_addr().expect("proxy addr");
        let proxy_thread = thread::spawn(move || {
            let (stream, _) = proxy.accept().expect("proxy accept");
            let (mut reader, mut writer) =
                accept_websocket(stream, Some("/trojan")).expect("websocket accept");
            let server = server();
            let request = server.read_request(&mut reader).expect("trojan request");
            assert_eq!(
                request.password_hash,
                trojan_password_hash("trojan-password")
            );
            assert_eq!(request.target.host, "example.com");
            assert_eq!(request.target.port, 443);
            let mut payload = [0u8; 4];
            reader.read_exact(&mut payload).expect("payload");
            assert_eq!(&payload, b"ping");
            writer.write_all(b"pong").expect("response");
        });

        let outbound = OutboundConfig {
            tag: "trojan-out".to_string(),
            protocol: "trojan".to_string(),
            method: None,
            alter_id: None,
            address: Some(proxy_addr.ip().to_string()),
            port: Some(proxy_addr.port()),
            username: None,
            password: Some("trojan-password".to_string()),
            tls: None,
            transport: Some(OutboundTransportConfig {
                network: "ws".to_string(),
                path: Some("/trojan".to_string()),
                host: Some("example.test".to_string()),
                service_name: None,
                method: None,
                headers: Default::default(),
                ..OutboundTransportConfig::default()
            }),
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
    fn trojan_httpupgrade_outbound_writes_request_and_relays_stream() {
        let proxy = TcpListener::bind("127.0.0.1:0").expect("proxy bind");
        let proxy_addr = proxy.local_addr().expect("proxy addr");
        let proxy_thread = thread::spawn(move || {
            let (stream, _) = proxy.accept().expect("proxy accept");
            let mut stream = accept_httpupgrade(stream, Some("/trojan"), Some("example.test"))
                .expect("httpupgrade accept");
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
            alter_id: None,
            address: Some(proxy_addr.ip().to_string()),
            port: Some(proxy_addr.port()),
            username: None,
            password: Some("trojan-password".to_string()),
            tls: None,
            transport: Some(OutboundTransportConfig {
                network: "httpupgrade".to_string(),
                path: Some("/trojan".to_string()),
                host: Some("example.test".to_string()),
                service_name: None,
                method: None,
                headers: Default::default(),
                ..OutboundTransportConfig::default()
            }),
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
    fn trojan_h2_outbound_writes_request_and_relays_stream() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("proxy bind");
        listener
            .set_nonblocking(true)
            .expect("proxy listener nonblocking");
        let proxy_addr = listener.local_addr().expect("proxy addr");
        let stop = Arc::new(AtomicBool::new(false));
        let server_stop = stop.clone();
        let (handled_tx, handled_rx) = mpsc::channel();
        let proxy_thread = thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime");
            let _guard = runtime.enter();
            let listener = tokio::net::TcpListener::from_std(listener).expect("tokio listener");
            drop(_guard);
            let handler: Http2StreamHandler = Arc::new(move |mut reader, mut writer| {
                let server = server();
                let request = server.read_request(&mut reader).expect("trojan request");
                assert_eq!(
                    request.password_hash,
                    trojan_password_hash("trojan-password")
                );
                assert_eq!(request.target.host, "example.com");
                assert_eq!(request.target.port, 443);
                let mut payload = [0u8; 4];
                reader.read_exact(&mut payload).expect("payload");
                assert_eq!(&payload, b"ping");
                writer.write_all(b"pong").expect("response");
                handled_tx.send(()).expect("handler notification");
            });
            runtime
                .block_on(run_http2_listener(
                    listener,
                    server_stop,
                    "/trojan".to_string(),
                    "PUT".to_string(),
                    None,
                    handler,
                ))
                .expect("h2 listener");
        });

        let outbound = OutboundConfig {
            tag: "trojan-out".to_string(),
            protocol: "trojan".to_string(),
            method: None,
            alter_id: None,
            address: Some(proxy_addr.ip().to_string()),
            port: Some(proxy_addr.port()),
            username: None,
            password: Some("trojan-password".to_string()),
            tls: None,
            transport: Some(OutboundTransportConfig {
                network: "h2".to_string(),
                path: Some("/trojan".to_string()),
                host: Some("example.test".to_string()),
                service_name: None,
                method: Some("PUT".to_string()),
                headers: Default::default(),
                ..OutboundTransportConfig::default()
            }),
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
        handled_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("handler completed");
        stop.store(true, Ordering::SeqCst);
        proxy_thread.join().expect("proxy thread");
    }

    #[test]
    fn trojan_grpc_outbound_writes_request_and_relays_stream() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("proxy bind");
        listener
            .set_nonblocking(true)
            .expect("proxy listener nonblocking");
        let proxy_addr = listener.local_addr().expect("proxy addr");
        let stop = Arc::new(AtomicBool::new(false));
        let server_stop = stop.clone();
        let (handled_tx, handled_rx) = mpsc::channel();
        let proxy_thread = thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("runtime");
            let _guard = runtime.enter();
            let listener = tokio::net::TcpListener::from_std(listener).expect("tokio listener");
            drop(_guard);
            let handler: GrpcStreamHandler = Arc::new(move |mut reader, mut writer| {
                let server = server();
                let request = server.read_request(&mut reader).expect("trojan request");
                assert_eq!(
                    request.password_hash,
                    trojan_password_hash("trojan-password")
                );
                assert_eq!(request.target.host, "example.com");
                assert_eq!(request.target.port, 443);
                let mut payload = [0u8; 4];
                reader.read_exact(&mut payload).expect("payload");
                assert_eq!(&payload, b"ping");
                writer.write_all(b"pong").expect("response");
                handled_tx.send(()).expect("handler notification");
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

        let outbound = OutboundConfig {
            tag: "trojan-out".to_string(),
            protocol: "trojan".to_string(),
            method: None,
            alter_id: None,
            address: Some(proxy_addr.ip().to_string()),
            port: Some(proxy_addr.port()),
            username: None,
            password: Some("trojan-password".to_string()),
            tls: None,
            transport: Some(OutboundTransportConfig {
                network: "grpc".to_string(),
                path: None,
                host: Some("example.test".to_string()),
                service_name: Some("GunService".to_string()),
                method: None,
                headers: Default::default(),
                ..OutboundTransportConfig::default()
            }),
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
        handled_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("handler completed");
        stop.store(true, Ordering::SeqCst);
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

        let records = drain_trojan_traffic_eventually(&server, 1);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].node_tag, "panel|trojan|1");
        assert_eq!(records[0].user_uuid, "trojan-password");
        assert_eq!(records[0].user_id, Some(1));
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

        let records = drain_trojan_traffic_eventually(&server, 1);
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

        let records = drain_trojan_traffic_eventually(&server, 1);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].node_tag, "panel|trojan|1");
        assert_eq!(records[0].user_uuid, "trojan-password");
        assert_eq!(records[0].upload, 4);
        assert_eq!(records[0].download, 4);
    }

    #[test]
    fn tls_tcp_relay_does_not_hold_connection_worker_after_start() {
        let cert = test_cert("trojan-tls-worker");
        let echo = TcpListener::bind("127.0.0.1:0").expect("echo bind");
        let echo_addr = echo.local_addr().expect("echo addr");
        let (release_remote_tx, release_remote_rx) = mpsc::channel();
        let echo_thread = thread::spawn(move || {
            let (mut stream, _) = echo.accept().expect("echo accept");
            let mut bytes = [0u8; 4];
            stream.read_exact(&mut bytes).expect("echo read");
            stream.write_all(&bytes).expect("echo write");
            let _ = release_remote_rx.recv_timeout(Duration::from_secs(3));
        });

        let server = server();
        let listener = server.bind().expect("trojan bind");
        let trojan_addr = listener.local_addr().expect("trojan addr");
        let acceptor =
            TlsAcceptor::from_files(&cert.cert_path, &cert.key_path, &[]).expect("tls acceptor");
        let server_clone = server.clone();
        let (handled_tx, handled_rx) = mpsc::channel();
        let server_thread = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("trojan accept");
            let client = acceptor.accept(stream).expect("tls accept");
            let result = server_clone.handle_tls_client(client);
            handled_tx.send(result).expect("send handled");
        });

        let mut client = tls_client(trojan_addr, cert.cert_der.clone());
        client
            .write_all(&trojan_request(echo_addr))
            .expect("client request");
        client.write_all(b"ping").expect("payload");
        let mut echoed = [0u8; 4];
        client.read_exact(&mut echoed).expect("echoed payload");
        assert_eq!(&echoed, b"ping");

        let handled = handled_rx
            .recv_timeout(Duration::from_millis(300))
            .expect("tls relay should move off the connection worker after start");
        handled.expect("spawn background tls relay");

        drop(client);
        release_remote_tx.send(()).expect("release remote");
        server_thread.join().expect("server thread");
        echo_thread.join().expect("echo thread");
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
            .write_all(&websocket_request_with_forwarded_for(
                "/trojan",
                "198.51.100.44, 203.0.113.7",
            ))
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

        let records = drain_trojan_traffic_eventually(&server, 1);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].node_tag, "panel|trojan|1");
        assert_eq!(records[0].user_uuid, "trojan-password");
        assert_eq!(records[0].upload, 4);
        assert_eq!(records[0].download, 4);
        assert_eq!(records[0].online_ips, vec!["198.51.100.44"]);
    }

    #[test]
    fn tls_websocket_extended_frame_can_carry_request_and_first_payload() {
        let cert = test_cert("trojan-ws-extended-first-payload");
        let echo = TcpListener::bind("127.0.0.1:0").expect("echo bind");
        let echo_addr = echo.local_addr().expect("echo addr");
        let first_payload = vec![b'a'; 96];
        let expected_payload = first_payload.clone();
        let echo_thread = thread::spawn(move || {
            let (mut stream, _) = echo.accept().expect("echo accept");
            let mut bytes = vec![0u8; expected_payload.len()];
            stream.read_exact(&mut bytes).expect("echo read");
            assert_eq!(bytes, expected_payload);
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
            .write_all(&websocket_request_with_forwarded_for(
                "/trojan",
                "198.51.100.47",
            ))
            .expect("websocket request");
        let response = read_websocket_response(&mut client);
        assert!(response.contains("101 Switching Protocols"));

        let mut first_frame_payload = trojan_request(echo_addr);
        first_frame_payload.extend_from_slice(&first_payload);
        assert!(first_frame_payload.len() > 125);
        client
            .write_all(&masked_frame(&first_frame_payload))
            .expect("trojan request and payload frame");
        assert_eq!(read_binary_frame(&mut client), first_payload);
        drop(client);

        server_thread
            .join()
            .expect("server thread")
            .expect("serve once");
        echo_thread.join().expect("echo thread");

        let records = drain_trojan_traffic_eventually(&server, 1);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].upload, 96);
        assert_eq!(records[0].download, 96);
    }

    #[test]
    fn tls_websocket_udp_continues_when_previous_datagram_has_no_response() {
        let cert = test_cert("trojan-ws-udp-nonblocking");
        let blackhole = UdpSocket::bind("127.0.0.1:0").expect("blackhole bind");
        let blackhole_addr = blackhole.local_addr().expect("blackhole addr");
        let (blackhole_seen_tx, blackhole_seen_rx) = mpsc::channel();
        let blackhole_thread = thread::spawn(move || {
            let mut bytes = [0u8; 128];
            let (read, _) = blackhole.recv_from(&mut bytes).expect("blackhole read");
            assert_eq!(&bytes[..read], b"drop");
            blackhole_seen_tx.send(()).expect("blackhole seen");
            thread::sleep(Duration::from_millis(500));
        });

        let echo = UdpSocket::bind("127.0.0.1:0").expect("echo bind");
        let echo_addr = echo.local_addr().expect("echo addr");
        let echo_thread = thread::spawn(move || {
            let mut bytes = [0u8; 128];
            let (read, source) = echo.recv_from(&mut bytes).expect("echo read");
            assert_eq!(&bytes[..read], b"ping");
            echo.send_to(b"pong", source).expect("echo write");
        });

        let server = server_with_routes(Vec::new(), Duration::from_secs(2));
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
            .sock
            .set_read_timeout(Some(Duration::from_millis(300)))
            .expect("client timeout");
        client
            .write_all(&websocket_request_with_forwarded_for(
                "/trojan",
                "198.51.100.48",
            ))
            .expect("websocket request");
        let response = read_websocket_response(&mut client);
        assert!(response.contains("101 Switching Protocols"));

        client
            .write_all(&masked_frame(&trojan_udp_associate_request(blackhole_addr)))
            .expect("udp associate request");
        client
            .write_all(&masked_frame(&trojan_udp_packet(blackhole_addr, b"drop")))
            .expect("blackhole datagram");
        blackhole_seen_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("blackhole should receive first datagram");
        client
            .write_all(&masked_frame(&trojan_udp_packet(echo_addr, b"ping")))
            .expect("echo datagram");

        let response_frame = read_binary_frame(&mut client);
        let (source, payload) = read_trojan_udp_packet(&mut Cursor::new(response_frame));
        assert_eq!(source, echo_addr);
        assert_eq!(payload, b"pong");
        drop(client);

        server_thread
            .join()
            .expect("server thread")
            .expect("serve once");
        blackhole_thread.join().expect("blackhole thread");
        echo_thread.join().expect("echo thread");

        let records = server.drain_traffic(1);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].upload, 8);
        assert_eq!(records[0].download, 4);
    }

    #[test]
    fn tls_websocket_client_close_terminates_trojan_relay() {
        let cert = test_cert("trojan-ws-close");
        let echo = TcpListener::bind("127.0.0.1:0").expect("echo bind");
        let echo_addr = echo.local_addr().expect("echo addr");
        let (remote_done_tx, remote_done_rx) = mpsc::channel();
        let echo_thread = thread::spawn(move || {
            let (mut stream, _) = echo.accept().expect("echo accept");
            let mut bytes = [0u8; 4];
            stream.read_exact(&mut bytes).expect("echo read");
            stream.write_all(&bytes).expect("echo write");
            thread::sleep(Duration::from_secs(3));
            remote_done_tx.send(()).expect("send remote done");
        });

        let server = server();
        let listener = server.bind().expect("trojan bind");
        let trojan_addr = listener.local_addr().expect("trojan addr");
        let acceptor =
            TlsAcceptor::from_files(&cert.cert_path, &cert.key_path, &[]).expect("tls acceptor");
        let server_clone = server.clone();
        let (handled_tx, handled_rx) = mpsc::channel();
        let server_thread = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("trojan accept");
            let client = acceptor.accept(stream).expect("tls accept");
            let result = server_clone.handle_tls_websocket_client(client, Some("/trojan"));
            handled_tx.send(result).expect("send handled");
        });

        let mut client = tls_client(trojan_addr, cert.cert_der.clone());
        client
            .write_all(&websocket_request_with_forwarded_for(
                "/trojan",
                "198.51.100.45",
            ))
            .expect("websocket request");
        let response = read_websocket_response(&mut client);
        assert!(response.contains("101 Switching Protocols"));
        client
            .write_all(&masked_frame(&trojan_request(echo_addr)))
            .expect("trojan request frame");
        client.write_all(&masked_frame(b"ping")).expect("payload");
        assert_eq!(read_binary_frame(&mut client), b"ping");
        drop(client);

        let handled = handled_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("trojan relay exits after websocket client close");
        handled.expect("trojan relay result");
        remote_done_rx
            .recv_timeout(Duration::from_secs(4))
            .expect("remote done");
        server_thread.join().expect("server thread");
        echo_thread.join().expect("echo thread");
    }

    #[test]
    fn websocket_client_close_terminates_trojan_relay() {
        let echo = TcpListener::bind("127.0.0.1:0").expect("echo bind");
        let echo_addr = echo.local_addr().expect("echo addr");
        let (remote_done_tx, remote_done_rx) = mpsc::channel();
        let echo_thread = thread::spawn(move || {
            let (mut stream, _) = echo.accept().expect("echo accept");
            let mut bytes = [0u8; 4];
            stream.read_exact(&mut bytes).expect("echo read");
            stream.write_all(&bytes).expect("echo write");
            thread::sleep(Duration::from_secs(3));
            remote_done_tx.send(()).expect("send remote done");
        });

        let server = server();
        let listener = server.bind().expect("trojan bind");
        let trojan_addr = listener.local_addr().expect("trojan addr");
        let server_clone = server.clone();
        let (handled_tx, handled_rx) = mpsc::channel();
        let server_thread = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("trojan accept");
            let result = server_clone.handle_websocket_client(stream, Some("/trojan"));
            handled_tx.send(result).expect("send handled");
        });

        let mut client = TcpStream::connect(trojan_addr).expect("client connect");
        client
            .write_all(&websocket_request_with_forwarded_for(
                "/trojan",
                "198.51.100.49",
            ))
            .expect("websocket request");
        let response = read_websocket_response(&mut client);
        assert!(response.contains("101 Switching Protocols"));
        client
            .write_all(&masked_frame(&trojan_request(echo_addr)))
            .expect("trojan request frame");
        client.write_all(&masked_frame(b"ping")).expect("payload");
        assert_eq!(read_binary_frame(&mut client), b"ping");
        drop(client);

        let handled = handled_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("trojan relay exits after websocket client close");
        handled.expect("trojan relay result");
        remote_done_rx
            .recv_timeout(Duration::from_secs(4))
            .expect("remote done");
        server_thread.join().expect("server thread");
        echo_thread.join().expect("echo thread");
    }

    #[test]
    fn websocket_remote_eof_closes_plain_trojan_relay_like_gorilla_conn() {
        let echo = TcpListener::bind("127.0.0.1:0").expect("echo bind");
        let echo_addr = echo.local_addr().expect("echo addr");
        let echo_thread = thread::spawn(move || {
            let (mut stream, _) = echo.accept().expect("echo accept");
            let mut bytes = [0u8; 4];
            stream.read_exact(&mut bytes).expect("echo read");
            stream.write_all(&bytes).expect("echo write");
            let _ = stream.shutdown(Shutdown::Both);
        });

        let server = server();
        let listener = server.bind().expect("trojan bind");
        let trojan_addr = listener.local_addr().expect("trojan addr");
        let server_clone = server.clone();
        let (handled_tx, handled_rx) = mpsc::channel();
        let server_thread = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("trojan accept");
            let result = server_clone.handle_websocket_client(stream, Some("/trojan"));
            handled_tx.send(result).expect("send handled");
        });

        let mut client = TcpStream::connect(trojan_addr).expect("client connect");
        client
            .set_read_timeout(Some(Duration::from_millis(700)))
            .expect("client read timeout");
        client
            .write_all(&websocket_request_with_forwarded_for(
                "/trojan",
                "198.51.100.54",
            ))
            .expect("websocket request");
        let response = read_websocket_response(&mut client);
        assert!(response.contains("101 Switching Protocols"));
        client
            .write_all(&masked_frame(&trojan_request(echo_addr)))
            .expect("trojan request frame");
        client.write_all(&masked_frame(b"ping")).expect("payload");
        assert_eq!(read_binary_frame(&mut client), b"ping");

        let handled = handled_rx
            .recv_timeout(Duration::from_millis(300))
            .expect("websocket relay should move off the connection worker after start");
        handled.expect("spawn background websocket relay");
        echo_thread.join().expect("echo thread");

        let mut header = [0u8; 2];
        match client.read_exact(&mut header) {
            Ok(()) => assert_eq!(
                header[0] & 0x0f,
                0x08,
                "server should send websocket close after remote EOF"
            ),
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::UnexpectedEof
                        | io::ErrorKind::ConnectionReset
                        | io::ErrorKind::ConnectionAborted
                        | io::ErrorKind::BrokenPipe
                ) => {}
            Err(error) => panic!("server did not close websocket after remote EOF: {error}"),
        }

        let records = drain_trojan_traffic_eventually(&server, 1);
        assert_eq!(records.len(), 1);
        server_thread.join().expect("server thread");
    }

    #[test]
    fn websocket_upgrade_without_trojan_header_times_out_like_go_handshake() {
        let server = server_with_routes(Vec::new(), Duration::from_millis(120));
        let listener = server.bind().expect("trojan bind");
        let trojan_addr = listener.local_addr().expect("trojan addr");
        let server_clone = server.clone();
        let (handled_tx, handled_rx) = mpsc::channel();
        let server_thread = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("trojan accept");
            let result = server_clone.handle_websocket_client(stream, Some("/trojan"));
            handled_tx.send(result).expect("send handled");
        });

        let mut client = TcpStream::connect(trojan_addr).expect("client connect");
        client
            .write_all(&websocket_request_with_forwarded_for(
                "/trojan",
                "198.51.100.52",
            ))
            .expect("websocket request");
        let response = read_websocket_response(&mut client);
        assert!(response.contains("101 Switching Protocols"));

        let result = handled_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("websocket trojan handshake should time out");
        assert!(result.is_err(), "missing trojan header should fail");
        drop(client);
        server_thread.join().expect("server thread");
    }

    #[test]
    fn websocket_tcp_relay_does_not_hold_connection_worker_after_start() {
        let echo = TcpListener::bind("127.0.0.1:0").expect("echo bind");
        let echo_addr = echo.local_addr().expect("echo addr");
        let (release_remote_tx, release_remote_rx) = mpsc::channel();
        let echo_thread = thread::spawn(move || {
            let (mut stream, _) = echo.accept().expect("echo accept");
            let mut bytes = [0u8; 4];
            stream.read_exact(&mut bytes).expect("echo read");
            stream.write_all(&bytes).expect("echo write");
            let _ = release_remote_rx.recv_timeout(Duration::from_secs(3));
        });

        let server = server();
        let listener = server.bind().expect("trojan bind");
        let trojan_addr = listener.local_addr().expect("trojan addr");
        let server_clone = server.clone();
        let (handled_tx, handled_rx) = mpsc::channel();
        let server_thread = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("trojan accept");
            let result = server_clone.handle_websocket_client(stream, Some("/trojan"));
            handled_tx.send(result).expect("send handled");
        });

        let mut client = TcpStream::connect(trojan_addr).expect("client connect");
        client
            .write_all(&websocket_request_with_forwarded_for(
                "/trojan",
                "198.51.100.51",
            ))
            .expect("websocket request");
        let response = read_websocket_response(&mut client);
        assert!(response.contains("101 Switching Protocols"));
        client
            .write_all(&masked_frame(&trojan_request(echo_addr)))
            .expect("trojan request frame");
        client.write_all(&masked_frame(b"ping")).expect("payload");
        assert_eq!(read_binary_frame(&mut client), b"ping");

        let handled = handled_rx
            .recv_timeout(Duration::from_millis(300))
            .expect("websocket relay should move off the connection worker after start");
        handled.expect("spawn background websocket relay");

        drop(client);
        release_remote_tx.send(()).expect("release remote");
        server_thread.join().expect("server thread");
        echo_thread.join().expect("echo thread");
    }

    #[test]
    fn tls_websocket_tcp_relay_does_not_hold_connection_worker_after_start() {
        let cert = test_cert("trojan-ws-worker");
        let echo = TcpListener::bind("127.0.0.1:0").expect("echo bind");
        let echo_addr = echo.local_addr().expect("echo addr");
        let (release_remote_tx, release_remote_rx) = mpsc::channel();
        let echo_thread = thread::spawn(move || {
            let (mut stream, _) = echo.accept().expect("echo accept");
            let mut bytes = [0u8; 4];
            stream.read_exact(&mut bytes).expect("echo read");
            stream.write_all(&bytes).expect("echo write");
            let _ = release_remote_rx.recv_timeout(Duration::from_secs(3));
        });

        let server = server();
        let listener = server.bind().expect("trojan bind");
        let trojan_addr = listener.local_addr().expect("trojan addr");
        let acceptor =
            TlsAcceptor::from_files(&cert.cert_path, &cert.key_path, &[]).expect("tls acceptor");
        let server_clone = server.clone();
        let (handled_tx, handled_rx) = mpsc::channel();
        let server_thread = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("trojan accept");
            let client = acceptor.accept(stream).expect("tls accept");
            let result = server_clone.handle_tls_websocket_client(client, Some("/trojan"));
            handled_tx.send(result).expect("send handled");
        });

        let mut client = tls_client(trojan_addr, cert.cert_der.clone());
        client
            .write_all(&websocket_request_with_forwarded_for(
                "/trojan",
                "198.51.100.53",
            ))
            .expect("websocket request");
        let response = read_websocket_response(&mut client);
        assert!(response.contains("101 Switching Protocols"));
        client
            .write_all(&masked_frame(&trojan_request(echo_addr)))
            .expect("trojan request frame");
        client.write_all(&masked_frame(b"ping")).expect("payload");
        assert_eq!(read_binary_frame(&mut client), b"ping");

        let handled = handled_rx
            .recv_timeout(Duration::from_millis(300))
            .expect("tls websocket relay should move off the connection worker after start");
        handled.expect("spawn background tls websocket relay");

        drop(client);
        release_remote_tx.send(()).expect("release remote");
        server_thread.join().expect("server thread");
        echo_thread.join().expect("echo thread");
    }

    #[test]
    fn websocket_udp_continues_when_previous_datagram_has_no_response() {
        let blackhole = UdpSocket::bind("127.0.0.1:0").expect("blackhole bind");
        let blackhole_addr = blackhole.local_addr().expect("blackhole addr");
        let (blackhole_seen_tx, blackhole_seen_rx) = mpsc::channel();
        let blackhole_thread = thread::spawn(move || {
            let mut bytes = [0u8; 128];
            let (read, _) = blackhole.recv_from(&mut bytes).expect("blackhole read");
            assert_eq!(&bytes[..read], b"drop");
            blackhole_seen_tx.send(()).expect("blackhole seen");
            thread::sleep(Duration::from_millis(500));
        });

        let echo = UdpSocket::bind("127.0.0.1:0").expect("echo bind");
        let echo_addr = echo.local_addr().expect("echo addr");
        let echo_thread = thread::spawn(move || {
            let mut bytes = [0u8; 128];
            let (read, source) = echo.recv_from(&mut bytes).expect("echo read");
            assert_eq!(&bytes[..read], b"ping");
            echo.send_to(b"pong", source).expect("echo write");
        });

        let server = server_with_routes(Vec::new(), Duration::from_secs(2));
        let listener = server.bind().expect("trojan bind");
        let trojan_addr = listener.local_addr().expect("trojan addr");
        let server_clone = server.clone();
        let (handled_tx, handled_rx) = mpsc::channel();
        let server_thread = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("trojan accept");
            let result = server_clone.handle_websocket_client(stream, Some("/trojan"));
            handled_tx.send(result).expect("send handled");
        });

        let mut client = TcpStream::connect(trojan_addr).expect("client connect");
        client
            .set_read_timeout(Some(Duration::from_millis(300)))
            .expect("client timeout");
        client
            .write_all(&websocket_request_with_forwarded_for(
                "/trojan",
                "198.51.100.52",
            ))
            .expect("websocket request");
        let response = read_websocket_response(&mut client);
        assert!(response.contains("101 Switching Protocols"));

        client
            .write_all(&masked_frame(&trojan_udp_associate_request(blackhole_addr)))
            .expect("udp associate request");
        client
            .write_all(&masked_frame(&trojan_udp_packet(blackhole_addr, b"drop")))
            .expect("blackhole datagram");
        blackhole_seen_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("blackhole should receive first datagram");
        client
            .write_all(&masked_frame(&trojan_udp_packet(echo_addr, b"ping")))
            .expect("echo datagram");

        let response_frame = read_binary_frame(&mut client);
        let (source, payload) = read_trojan_udp_packet(&mut Cursor::new(response_frame));
        assert_eq!(source, echo_addr);
        assert_eq!(payload, b"pong");
        let handled = handled_rx
            .recv_timeout(Duration::from_millis(300))
            .expect("websocket UDP relay should move off the connection worker after start");
        handled.expect("spawn background websocket UDP relay");
        drop(client);

        server_thread.join().expect("server thread");
        blackhole_thread.join().expect("blackhole thread");
        echo_thread.join().expect("echo thread");

        let records = drain_trojan_traffic_eventually(&server, 1);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].upload, 8);
        assert_eq!(records[0].download, 4);
    }

    #[test]
    fn websocket_client_close_during_outbound_connect_does_not_wait_for_timeout() {
        let proxy = TcpListener::bind("127.0.0.1:0").expect("proxy bind");
        let proxy_addr = proxy.local_addr().expect("proxy addr");
        let (proxy_accepted_tx, proxy_accepted_rx) = mpsc::channel();
        let proxy_thread = thread::spawn(move || {
            let (_stream, _) = proxy.accept().expect("proxy accept");
            proxy_accepted_tx.send(()).expect("send proxy accepted");
            thread::sleep(Duration::from_secs(3));
        });

        let target = "127.0.0.1:443".parse::<SocketAddr>().expect("target addr");
        let server = server_with_routes(
            vec![RouteRule {
                targets: vec!["ip:127.0.0.1/32".to_string()],
                action: RouteAction::Outbound("tw".to_string()),
                outbound: Some(OutboundConfig {
                    tag: "tw".to_string(),
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
            Duration::from_secs(2),
        );
        let listener = server.bind().expect("trojan bind");
        let trojan_addr = listener.local_addr().expect("trojan addr");
        let (handled_tx, handled_rx) = mpsc::channel();
        let server_thread = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("trojan accept");
            let result = server.handle_websocket_client(stream, Some("/trojan"));
            handled_tx.send(result).expect("send handled");
        });

        let mut client = TcpStream::connect(trojan_addr).expect("client connect");
        client
            .write_all(&websocket_request_with_forwarded_for(
                "/trojan",
                "198.51.100.50",
            ))
            .expect("websocket request");
        let response = read_websocket_response(&mut client);
        assert!(response.contains("101 Switching Protocols"));
        client
            .write_all(&masked_frame(&trojan_request(target)))
            .expect("trojan request");
        proxy_accepted_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("proxy should receive outbound connection");

        let started = Instant::now();
        drop(client);

        let handled = handled_rx
            .recv_timeout(Duration::from_millis(700))
            .expect("server should stop waiting once websocket client closes mid-connect");
        handled.expect("client close during outbound connect is not a route error");
        assert!(started.elapsed() < Duration::from_millis(700));
        server_thread.join().expect("server thread");
        proxy_thread.join().expect("proxy thread");
    }

    #[test]
    fn tls_websocket_client_close_before_route_connect_does_not_wait_for_socks_timeout() {
        let cert = test_cert("trojan-ws-connect-close");
        let proxy = TcpListener::bind("127.0.0.1:0").expect("proxy bind");
        let proxy_addr = proxy.local_addr().expect("proxy addr");

        let target = "127.0.0.1:443".parse::<SocketAddr>().expect("target addr");
        let server = server_with_routes(
            vec![RouteRule {
                targets: vec!["ip:127.0.0.1/32".to_string()],
                action: RouteAction::Outbound("tw".to_string()),
                outbound: Some(OutboundConfig {
                    tag: "tw".to_string(),
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
            Duration::from_secs(2),
        );
        let listener = server.bind().expect("trojan bind");
        let trojan_addr = listener.local_addr().expect("trojan addr");
        let acceptor =
            TlsAcceptor::from_files(&cert.cert_path, &cert.key_path, &[]).expect("tls acceptor");
        let (handled_tx, handled_rx) = mpsc::channel();
        let server_thread = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("trojan accept");
            let client = acceptor.accept(stream).expect("tls accept");
            let result = server.handle_tls_websocket_client(client, Some("/trojan"));
            handled_tx.send(result).expect("send handled");
        });

        let mut client = tls_client(trojan_addr, cert.cert_der.clone());
        client
            .write_all(&websocket_request_with_forwarded_for(
                "/trojan",
                "198.51.100.46",
            ))
            .expect("websocket request");
        let response = read_websocket_response(&mut client);
        assert!(response.contains("101 Switching Protocols"));
        client
            .write_all(&masked_frame(&trojan_request(target)))
            .expect("trojan request");
        let started = Instant::now();
        drop(client);

        let handled = handled_rx
            .recv_timeout(Duration::from_millis(700))
            .expect("server should stop waiting once tls-websocket client closes");
        handled.expect("client close before outbound connect is not a route error");
        assert!(started.elapsed() < Duration::from_millis(700));
        server_thread.join().expect("server thread");
        drop(proxy);
    }

    #[test]
    fn tls_websocket_client_close_during_outbound_connect_does_not_wait_for_timeout() {
        let cert = test_cert("trojan-ws-connect-mid-close");
        let proxy = TcpListener::bind("127.0.0.1:0").expect("proxy bind");
        let proxy_addr = proxy.local_addr().expect("proxy addr");
        let (proxy_accepted_tx, proxy_accepted_rx) = mpsc::channel();
        let proxy_thread = thread::spawn(move || {
            let (_stream, _) = proxy.accept().expect("proxy accept");
            proxy_accepted_tx.send(()).expect("send proxy accepted");
            thread::sleep(Duration::from_secs(3));
        });

        let target = "127.0.0.1:443".parse::<SocketAddr>().expect("target addr");
        let server = server_with_routes(
            vec![RouteRule {
                targets: vec!["ip:127.0.0.1/32".to_string()],
                action: RouteAction::Outbound("tw".to_string()),
                outbound: Some(OutboundConfig {
                    tag: "tw".to_string(),
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
            Duration::from_secs(2),
        );
        let listener = server.bind().expect("trojan bind");
        let trojan_addr = listener.local_addr().expect("trojan addr");
        let acceptor =
            TlsAcceptor::from_files(&cert.cert_path, &cert.key_path, &[]).expect("tls acceptor");
        let (handled_tx, handled_rx) = mpsc::channel();
        let server_thread = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("trojan accept");
            let client = acceptor.accept(stream).expect("tls accept");
            let result = server.handle_tls_websocket_client(client, Some("/trojan"));
            handled_tx.send(result).expect("send handled");
        });

        let mut client = tls_client(trojan_addr, cert.cert_der.clone());
        client
            .write_all(&websocket_request_with_forwarded_for(
                "/trojan",
                "198.51.100.47",
            ))
            .expect("websocket request");
        let response = read_websocket_response(&mut client);
        assert!(response.contains("101 Switching Protocols"));
        client
            .write_all(&masked_frame(&trojan_request(target)))
            .expect("trojan request");
        proxy_accepted_rx
            .recv_timeout(Duration::from_secs(1))
            .expect("proxy should receive outbound connection");

        let started = Instant::now();
        drop(client);

        let handled = handled_rx
            .recv_timeout(Duration::from_millis(700))
            .expect("server should stop waiting once tls-websocket client closes mid-connect");
        handled.expect("client close during outbound connect is not a route error");
        assert!(started.elapsed() < Duration::from_millis(700));
        server_thread.join().expect("server thread");
        proxy_thread.join().expect("proxy thread");
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
            .write_all(&websocket_request_with_forwarded_for(
                "/trojan",
                "198.51.100.43, 203.0.113.7",
            ))
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

        let records = drain_trojan_traffic_eventually(&server, 1);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].node_tag, "panel|trojan|1");
        assert_eq!(records[0].user_uuid, "trojan-password");
        assert_eq!(records[0].upload, 4);
        assert_eq!(records[0].download, 4);
        assert_eq!(records[0].online_ips, vec!["198.51.100.43"]);
    }

    #[test]
    fn plain_websocket_relay_survives_tcp_fragmented_client_frame_like_gorilla() {
        let echo = TcpListener::bind("127.0.0.1:0").expect("echo bind");
        let echo_addr = echo.local_addr().expect("echo addr");
        let echo_thread = thread::spawn(move || {
            let (mut stream, _) = echo.accept().expect("echo accept");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("echo timeout");
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
            .set_read_timeout(Some(Duration::from_secs(3)))
            .expect("client timeout");
        client
            .write_all(&websocket_request_with_forwarded_for(
                "/trojan",
                "198.51.100.44",
            ))
            .expect("websocket request");
        let response = read_websocket_response(&mut client);
        assert!(response.contains("101 Switching Protocols"));

        client
            .write_all(&masked_frame(&trojan_request(echo_addr)))
            .expect("trojan request frame");

        let frame = masked_frame(b"ping");
        client.write_all(&frame[..1]).expect("first tcp chunk");
        thread::sleep(Duration::from_millis(80));
        client.write_all(&frame[1..]).expect("remaining tcp chunk");
        assert_eq!(read_binary_frame(&mut client), b"ping");
        drop(client);

        server_thread
            .join()
            .expect("server thread")
            .expect("serve once");
        echo_thread.join().expect("echo thread");
    }
}
