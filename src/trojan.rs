use std::io::{self, Read, Write};
use std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket,
};
use std::sync::Arc;
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
    BandwidthLimiter, UserBandwidthLimiters, UserSessionGuard, UserSessionTracker,
};
use crate::outbound::recv_udp_response;
use crate::quic::connect_quic_client_stream;
use crate::socks5::SocksTarget;
use crate::stream::{
    copy_count_best_effort_limited, join_native_blocking_relay, relay_tcp_streams_limited,
    spawn_native_blocking_relay,
};
use crate::tls::{relay_tls_stream, TlsConnection};
use crate::traffic::{SharedTrafficRegistry, TrafficRegistry};
use crate::user::{CoreUser, CoreUserDelta, CoreUserDeltaResult, UserStore};
use crate::websocket::{
    accept_websocket, accept_websocket_tls, connect_websocket_client, relay_websocket_tls_stream,
    WebSocketClientStream,
};
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
        config: TrojanServerConfig,
        traffic: SharedTrafficRegistry,
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
        self.traffic.drain_minimum(minimum_bytes)
    }

    pub fn replace_users(&self, users: Vec<CoreUser>) {
        self.bandwidth.sync_users(&users);
        self.users
            .replace_keyed_users(users, |user| trojan_password_hash(user.credential()));
    }

    pub fn apply_user_delta(&self, delta: &CoreUserDelta) -> CoreUserDeltaResult {
        sync_delta_bandwidth(&self.bandwidth, delta);
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
        let (upload, download) = relay_tcp_streams_limited(client, remote, bandwidth)?;
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
        let mut remote_read = remote;
        let upload_limiter = bandwidth.clone();
        let upload_task = spawn_native_blocking_relay(move || {
            copy_count_best_effort_limited(
                &mut reader,
                &mut remote_write,
                upload_limiter.as_deref(),
            )
        })?;
        let download = copy_count_best_effort_limited(&mut remote_read, &mut writer, None);
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

fn sync_delta_bandwidth(bandwidth: &UserBandwidthLimiters, delta: &CoreUserDelta) {
    if let Some(full) = delta.full.as_ref() {
        bandwidth.sync_users(full);
    } else {
        bandwidth.sync_users(&delta.added);
        bandwidth.sync_users(&delta.updated);
    }
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
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    use std::thread;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use rustls::pki_types::{CertificateDer, ServerName};
    use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

    use crate::config::{OutboundConfig, OutboundTlsConfig, OutboundTransportConfig};
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
        let handler_stop = stop.clone();
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
                handler_stop.store(true, Ordering::SeqCst);
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
        let handler_stop = stop.clone();
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
