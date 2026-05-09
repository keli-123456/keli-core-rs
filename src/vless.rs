use std::io::{self, Read, Write};
use std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket,
};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, RootCertStore, SignatureScheme,
    StreamOwned,
};

use crate::config::{outbound_transport_network, OutboundConfig, OutboundTlsConfig};
use crate::httpupgrade::connect_httpupgrade_client;
use crate::limits::{
    BandwidthLimiter, UserBandwidthLimiters, UserSessionGuard, UserSessionTracker,
};
use crate::outbound::recv_udp_response;
use crate::socks5::SocksTarget;
use crate::stream::{copy_count_best_effort_limited, relay_tcp_streams_limited};
use crate::tls::{relay_tls_stream, TlsConnection, TlsSocket};
use crate::traffic::TrafficRegistry;
use crate::user::{CoreUser, UserStore};
use crate::vision::{VisionDecoder, VisionEncoder, VisionReader, VisionWriter};
use crate::websocket::{
    accept_websocket, accept_websocket_tls, connect_websocket_client, relay_websocket_tls_stream,
    WebSocketClientStream,
};
use crate::{
    connect_tcp_outbound, route_protocol_labels, send_udp_outbound, RouteDecision, RouteMatcher,
};

const VERSION: u8 = 0x00;
const COMMAND_TCP: u8 = 0x01;
const COMMAND_UDP: u8 = 0x02;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x02;
const ATYP_IPV6: u8 = 0x03;
const FLOW_XTLS_RPRX_VISION: &str = "xtls-rprx-vision";
const MAX_UDP_PACKET_SIZE: usize = 65_535;

#[derive(Clone, Debug)]
pub struct VlessServerConfig {
    pub node_tag: String,
    pub listen: SocketAddr,
    pub users: Vec<CoreUser>,
    pub routes: Vec<crate::RouteRule>,
    pub flow: String,
    pub connect_timeout: Duration,
}

#[derive(Clone, Debug)]
pub struct VlessServer {
    config: VlessServerConfig,
    users: UserStore,
    router: RouteMatcher,
    traffic: Arc<Mutex<TrafficRegistry>>,
    sessions: UserSessionTracker,
    bandwidth: UserBandwidthLimiters,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct VlessRequest {
    command: VlessCommand,
    user_key: String,
    user_uuid: String,
    user_id: [u8; 16],
    flow: String,
    target: SocksTarget,
    client_ip: Option<IpAddr>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum VlessCommand {
    Tcp,
    Udp,
}

struct VlessUdpRelayState {
    ipv4: Option<UdpSocket>,
    ipv6: Option<UdpSocket>,
    timeout: Duration,
}

impl VlessServer {
    pub fn new(config: VlessServerConfig) -> Self {
        Self::with_traffic(config, Arc::new(Mutex::new(TrafficRegistry::default())))
    }

    pub fn with_traffic(config: VlessServerConfig, traffic: Arc<Mutex<TrafficRegistry>>) -> Self {
        Self::with_shared_limits(
            config,
            traffic,
            UserSessionTracker::default(),
            UserBandwidthLimiters::default(),
        )
    }

    pub fn with_shared_limits(
        config: VlessServerConfig,
        traffic: Arc<Mutex<TrafficRegistry>>,
        sessions: UserSessionTracker,
        bandwidth: UserBandwidthLimiters,
    ) -> Self {
        let users = UserStore::from_keyed_users(&config.users, |user| compact_uuid(&user.uuid));
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
        if request.command == VlessCommand::Udp {
            client.write_all(&[VERSION, 0x00])?;
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
        client.write_all(&[VERSION, 0x00])?;
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
        let bandwidth = self.bandwidth.limiter_for(user.as_ref());
        if request.command == VlessCommand::Udp {
            writer.write_all(&[VERSION, 0x00])?;
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
        writer.write_all(&[VERSION, 0x00])?;
        self.relay_websocket(reader, writer, remote, request, bandwidth)
    }

    pub fn handle_tls_client<S>(&self, mut client: TlsConnection<S>) -> io::Result<()>
    where
        S: TlsSocket + Send + 'static,
    {
        let client_ip = client.peer_addr().ok().map(|addr| addr.ip());
        let mut request = self.read_request(&mut client)?;
        request.client_ip = client_ip;
        let user = self.request_user(&request);
        let _session = self.acquire_user_session(user.as_ref(), client_ip)?;
        let bandwidth = self.bandwidth.limiter_for(user.as_ref());
        if request.command == VlessCommand::Udp {
            client.write_all(&[VERSION, 0x00])?;
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
        client.write_all(&[VERSION, 0x00])?;
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
        if request.command == VlessCommand::Udp {
            websocket.write_all(&[VERSION, 0x00])?;
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
        websocket.write_all(&[VERSION, 0x00])?;
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
            .replace_keyed_users(users, |user| compact_uuid(&user.uuid));
    }

    fn read_request<T>(&self, stream: &mut T) -> io::Result<VlessRequest>
    where
        T: Read,
    {
        let version = read_u8(stream)?;
        if version != VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported vless version",
            ));
        }

        let mut uuid = [0u8; 16];
        stream.read_exact(&mut uuid)?;
        let user_key = format_uuid_compact(&uuid);
        let Some(user) = self.users.get(&user_key) else {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "unknown vless user",
            ));
        };

        let flow = self.read_addon_flow(stream)?;
        self.validate_request_flow(&flow)?;

        let command = read_u8(stream)?;
        let command = match command {
            COMMAND_TCP => VlessCommand::Tcp,
            COMMAND_UDP => VlessCommand::Udp,
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::Unsupported,
                    "only vless tcp and udp commands are supported",
                ));
            }
        };
        if command == VlessCommand::Udp && !flow.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "vless udp command does not support flow",
            ));
        }

        let target = read_vless_target(stream)?;

        Ok(VlessRequest {
            command,
            user_key,
            user_uuid: user.uuid.clone(),
            user_id: uuid,
            flow,
            target,
            client_ip: None,
        })
    }

    fn read_addon_flow<T>(&self, stream: &mut T) -> io::Result<String>
    where
        T: Read,
    {
        let addon_len = read_u8(stream)?;
        if addon_len == 0 {
            return Ok(String::new());
        }
        let mut addon = vec![0u8; usize::from(addon_len)];
        stream.read_exact(&mut addon)?;
        parse_addon_flow(&addon)
    }

    fn validate_request_flow(&self, request_flow: &str) -> io::Result<()> {
        let configured_flow = self.config.flow.trim();
        match (configured_flow, request_flow.trim()) {
            ("", "") => Ok(()),
            (FLOW_XTLS_RPRX_VISION, FLOW_XTLS_RPRX_VISION) => Ok(()),
            ("", FLOW_XTLS_RPRX_VISION) => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "vless account is not allowed to use xtls-rprx-vision",
            )),
            (FLOW_XTLS_RPRX_VISION, "") => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "vless vision account requires xtls-rprx-vision flow",
            )),
            (_, flow) => Err(io::Error::new(
                io::ErrorKind::InvalidData,
                format!("unsupported vless flow {flow}"),
            )),
        }
    }

    fn relay(
        &self,
        client: TcpStream,
        remote: TcpStream,
        request: VlessRequest,
        bandwidth: Option<Arc<BandwidthLimiter>>,
    ) -> io::Result<()> {
        let (upload, download) = if request.flow == FLOW_XTLS_RPRX_VISION {
            relay_vision_tcp_streams(client, remote, request.user_id, bandwidth)?
        } else {
            relay_tcp_streams_limited(client, remote, bandwidth)?
        };
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
        request: VlessRequest,
        bandwidth: Option<Arc<BandwidthLimiter>>,
    ) -> io::Result<()>
    where
        R: Read + Send + 'static,
        W: Write,
    {
        let (upload, download) = if request.flow == FLOW_XTLS_RPRX_VISION {
            relay_vision_split_streams(reader, writer, remote, request.user_id, bandwidth)?
        } else {
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
            let upload = upload_thread.join().map_err(|_| {
                io::Error::new(io::ErrorKind::Other, "upload relay thread panicked")
            })?;
            (upload, download)
        };
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

    fn relay_tls<S>(
        &self,
        client: TlsConnection<S>,
        remote: TcpStream,
        request: VlessRequest,
        bandwidth: Option<Arc<BandwidthLimiter>>,
    ) -> io::Result<()>
    where
        S: TlsSocket + Send + 'static,
    {
        let (upload, download) = if request.flow == FLOW_XTLS_RPRX_VISION {
            relay_tls_vision_stream(client, remote, request.user_id, bandwidth)?
        } else {
            relay_tls_stream(client, remote, bandwidth)?
        };
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
        request: VlessRequest,
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
        request: VlessRequest,
        bandwidth: Option<Arc<BandwidthLimiter>>,
    ) -> io::Result<()>
    where
        S: Read + Write,
    {
        let mut state = VlessUdpRelayState::new(self.config.connect_timeout);
        let mut upload = 0u64;
        let mut download = 0u64;
        let result = loop {
            match read_vless_udp_payload(&mut stream) {
                Ok(payload) => {
                    match self.forward_udp_payload(
                        &mut state,
                        &mut stream,
                        &request.target,
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
        request: VlessRequest,
        bandwidth: Option<Arc<BandwidthLimiter>>,
    ) -> io::Result<()>
    where
        R: Read,
        W: Write,
    {
        let mut state = VlessUdpRelayState::new(self.config.connect_timeout);
        let mut upload = 0u64;
        let mut download = 0u64;
        let result = loop {
            match read_vless_udp_payload(&mut reader) {
                Ok(payload) => {
                    match self.forward_udp_payload(
                        &mut state,
                        &mut writer,
                        &request.target,
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

    fn forward_udp_payload<W>(
        &self,
        state: &mut VlessUdpRelayState,
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
                Ok((_, response)) => {
                    write_vless_udp_payload(writer, &response)?;
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
            Ok((read, _)) => {
                write_vless_udp_payload(writer, &response[..read])?;
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

    fn request_user(&self, request: &VlessRequest) -> Option<CoreUser> {
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

impl VlessUdpRelayState {
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

fn read_vless_target<R: Read>(reader: &mut R) -> io::Result<SocksTarget> {
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
                "unsupported vless address type",
            ));
        }
    };
    Ok(SocksTarget { host, port })
}

fn connect_target(target: &SocksTarget, timeout: Duration) -> io::Result<TcpStream> {
    crate::dns::connect_tcp(&target.host, target.port, timeout)
}

pub(crate) fn connect_vless_tcp_outbound(
    outbound: &OutboundConfig,
    target: &SocksTarget,
    timeout: Duration,
) -> io::Result<TcpStream> {
    let server = vless_outbound_server(outbound)?;
    let user_id = vless_outbound_user_id(outbound)?;
    let flow = outbound.method.as_deref().unwrap_or_default().trim();
    if !flow.is_empty() {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "vless outbound flow is not supported yet",
        ));
    }
    let network = outbound_transport_network(outbound).to_ascii_lowercase();
    if network == "ws" {
        return connect_vless_websocket_tcp_outbound(
            outbound, &server, &user_id, flow, target, timeout,
        );
    }
    if network == "httpupgrade" {
        return connect_vless_httpupgrade_tcp_outbound(
            outbound, &server, &user_id, flow, target, timeout,
        );
    }
    if network != "tcp" {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            format!("vless outbound transport {network} is not supported yet"),
        ));
    }
    if outbound.tls.is_some() {
        return connect_vless_tls_tcp_outbound(outbound, &server, &user_id, flow, target, timeout);
    }
    let mut stream = connect_target(&server, timeout)?;
    stream.set_read_timeout(Some(timeout))?;
    stream.set_write_timeout(Some(timeout))?;
    write_vless_tcp_request(&mut stream, &user_id, flow, target)?;
    read_vless_response_header(&mut stream)?;
    Ok(stream)
}

fn connect_vless_httpupgrade_tcp_outbound(
    outbound: &OutboundConfig,
    server: &SocksTarget,
    user_id: &[u8; 16],
    flow: &str,
    target: &SocksTarget,
    timeout: Duration,
) -> io::Result<TcpStream> {
    if outbound.tls.is_some() {
        let tls_stream = connect_vless_tls_stream(outbound, server, timeout)?;
        let host = outbound_transport_host(outbound, server);
        let mut tls_stream =
            connect_httpupgrade_client(tls_stream, outbound_transport_path(outbound), &host)?;
        write_vless_tcp_request(&mut tls_stream, user_id, flow, target)?;
        tls_stream.flush()?;
        read_vless_response_header(&mut tls_stream)?;

        let local_listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
        let local_addr = local_listener.local_addr()?;
        let local_client = TcpStream::connect(local_addr)?;
        let (local_plain, _) = local_listener.accept()?;

        thread::spawn(move || {
            let _ = relay_plain_to_tls(local_plain, tls_stream);
        });

        return Ok(local_client);
    }

    let remote = connect_target(server, timeout)?;
    remote.set_read_timeout(Some(timeout))?;
    remote.set_write_timeout(Some(timeout))?;
    let host = outbound_transport_host(outbound, server);
    let mut stream = connect_httpupgrade_client(remote, outbound_transport_path(outbound), &host)?;
    write_vless_tcp_request(&mut stream, user_id, flow, target)?;
    read_vless_response_header(&mut stream)?;
    Ok(stream)
}

fn connect_vless_websocket_tcp_outbound(
    outbound: &OutboundConfig,
    server: &SocksTarget,
    user_id: &[u8; 16],
    flow: &str,
    target: &SocksTarget,
    timeout: Duration,
) -> io::Result<TcpStream> {
    if outbound.tls.is_some() {
        let tls_stream = connect_vless_tls_stream(outbound, server, timeout)?;
        let host = outbound_transport_host(outbound, server);
        let mut websocket =
            connect_websocket_client(tls_stream, outbound_transport_path(outbound), &host)?;
        write_vless_tcp_request(&mut websocket, user_id, flow, target)?;
        websocket.flush()?;
        read_vless_response_header(&mut websocket)?;
        websocket.get_mut().sock.set_nonblocking(true)?;
        return local_bridge_for_websocket(websocket);
    }

    let remote = connect_target(server, timeout)?;
    remote.set_read_timeout(Some(timeout))?;
    remote.set_write_timeout(Some(timeout))?;
    let host = outbound_transport_host(outbound, server);
    let mut websocket = connect_websocket_client(remote, outbound_transport_path(outbound), &host)?;
    write_vless_tcp_request(&mut websocket, user_id, flow, target)?;
    websocket.flush()?;
    read_vless_response_header(&mut websocket)?;
    websocket.get_mut().set_nonblocking(true)?;
    local_bridge_for_websocket(websocket)
}

fn connect_vless_tls_tcp_outbound(
    outbound: &OutboundConfig,
    server: &SocksTarget,
    user_id: &[u8; 16],
    flow: &str,
    target: &SocksTarget,
    timeout: Duration,
) -> io::Result<TcpStream> {
    let mut tls_stream = connect_vless_tls_stream(outbound, server, timeout)?;
    write_vless_tcp_request(&mut tls_stream, user_id, flow, target)?;
    tls_stream.flush()?;
    read_vless_response_header(&mut tls_stream)?;

    let local_listener = TcpListener::bind(SocketAddr::from((Ipv4Addr::LOCALHOST, 0)))?;
    let local_addr = local_listener.local_addr()?;
    let local_client = TcpStream::connect(local_addr)?;
    let (local_plain, _) = local_listener.accept()?;

    thread::spawn(move || {
        let _ = relay_plain_to_tls(local_plain, tls_stream);
    });

    Ok(local_client)
}

fn connect_vless_tls_stream(
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
    let server_name = vless_tls_server_name(tls_config, server)?;
    let connection = ClientConnection::new(vless_tls_client_config(tls_config), server_name)
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

fn vless_tls_client_config(tls: &OutboundTlsConfig) -> Arc<ClientConfig> {
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

fn vless_tls_server_name(
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
            "vless tls server_name is invalid",
        )
    })
}

fn vless_outbound_server(outbound: &OutboundConfig) -> io::Result<SocksTarget> {
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

fn vless_outbound_user_id(outbound: &OutboundConfig) -> io::Result<[u8; 16]> {
    let value = outbound
        .username
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "outbound username must be a vless uuid",
            )
        })?;
    parse_uuid_bytes(value)
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

fn write_vless_tcp_request<W: Write>(
    writer: &mut W,
    user_id: &[u8; 16],
    flow: &str,
    target: &SocksTarget,
) -> io::Result<()> {
    writer.write_all(&[VERSION])?;
    writer.write_all(user_id)?;
    write_vless_addon(writer, flow)?;
    writer.write_all(&[COMMAND_TCP])?;
    write_vless_target(writer, target)
}

fn write_vless_addon<W: Write>(writer: &mut W, flow: &str) -> io::Result<()> {
    let flow = flow.trim();
    if flow.is_empty() {
        return writer.write_all(&[0]);
    }
    if flow.len() > (u8::MAX as usize - 2) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "vless outbound flow is too long",
        ));
    }
    writer.write_all(&[(2 + flow.len()) as u8, 0x0a, flow.len() as u8])?;
    writer.write_all(flow.as_bytes())
}

fn write_vless_target<W: Write>(writer: &mut W, target: &SocksTarget) -> io::Result<()> {
    writer.write_all(&target.port.to_be_bytes())?;
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
                "vless target host is invalid",
            ));
        }
        writer.write_all(&[ATYP_DOMAIN, host.len() as u8])?;
        writer.write_all(host.as_bytes())?;
    }
    Ok(())
}

fn read_vless_response_header<R: Read>(reader: &mut R) -> io::Result<()> {
    let version = read_u8(reader)?;
    if version != VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "invalid vless outbound response version",
        ));
    }
    let addon_len = read_u8(reader)?;
    if addon_len > 0 {
        let mut addon = vec![0u8; usize::from(addon_len)];
        reader.read_exact(&mut addon)?;
    }
    Ok(())
}

fn resolve_udp_target(target: &SocksTarget) -> io::Result<SocketAddr> {
    crate::dns::resolve_socket_addr(&target.host, target.port, Duration::from_secs(5))
}

fn read_vless_udp_payload<R: Read>(reader: &mut R) -> io::Result<Vec<u8>> {
    let mut len = [0u8; 2];
    reader.read_exact(&mut len)?;
    let len = u16::from_be_bytes(len) as usize;
    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload)?;
    Ok(payload)
}

fn write_vless_udp_payload<W: Write>(writer: &mut W, payload: &[u8]) -> io::Result<()> {
    if payload.len() > u16::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "vless udp payload is too large",
        ));
    }
    writer.write_all(&(payload.len() as u16).to_be_bytes())?;
    writer.write_all(payload)
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
                    write_all_wait_tls_bridge(&mut tls_stream, &upload_buffer[..read])?;
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
                    write_all_wait_tls_bridge(&mut plain, &download_buffer[..read])?;
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

    thread::spawn(move || {
        let _ = relay_plain_to_websocket(local_plain, websocket);
    });

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
                    write_all_wait_tls_bridge(&mut websocket, &upload_buffer[..read])?;
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
                    write_all_wait_tls_bridge(&mut plain, &download_buffer[..read])?;
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

fn write_all_wait_tls_bridge<W: Write>(writer: &mut W, mut input: &[u8]) -> io::Result<()> {
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

fn relay_vision_tcp_streams(
    client: TcpStream,
    remote: TcpStream,
    user_id: [u8; 16],
    limiter: Option<Arc<BandwidthLimiter>>,
) -> io::Result<(u64, u64)> {
    let client_reader = client.try_clone()?;
    let client_writer = client;
    relay_vision_split_streams(client_reader, client_writer, remote, user_id, limiter)
}

fn relay_vision_split_streams<R, W>(
    reader: R,
    writer: W,
    remote: TcpStream,
    user_id: [u8; 16],
    limiter: Option<Arc<BandwidthLimiter>>,
) -> io::Result<(u64, u64)>
where
    R: Read + Send + 'static,
    W: Write,
{
    let mut remote_write = remote.try_clone()?;
    let mut remote_read = remote;
    let upload_limiter = limiter.clone();
    let upload_thread = thread::spawn(move || {
        let mut vision_reader = VisionReader::new(reader, user_id);
        let bytes = copy_count_best_effort_limited(
            &mut vision_reader,
            &mut remote_write,
            upload_limiter.as_deref(),
        );
        let _ = remote_write.shutdown(Shutdown::Write);
        bytes
    });

    let mut vision_writer = VisionWriter::new(writer, user_id);
    let download = copy_count_best_effort_limited(&mut remote_read, &mut vision_writer, None);
    let upload = upload_thread
        .join()
        .map_err(|_| io::Error::new(io::ErrorKind::Other, "upload relay thread panicked"))?;

    Ok((upload, download))
}

fn relay_tls_vision_stream<S>(
    mut client: TlsConnection<S>,
    mut remote: TcpStream,
    user_id: [u8; 16],
    limiter: Option<Arc<BandwidthLimiter>>,
) -> io::Result<(u64, u64)>
where
    S: TlsSocket,
{
    client.set_nonblocking(true)?;
    remote.set_nonblocking(true)?;

    let mut upload = 0u64;
    let mut download = 0u64;
    let mut upload_done = false;
    let mut download_done = false;
    let mut client_buffer = [0u8; 16 * 1024];
    let mut remote_buffer = [0u8; 16 * 1024];
    let mut vision_decoder = VisionDecoder::new(user_id);
    let mut vision_encoder = VisionEncoder::new(user_id);

    while !upload_done || !download_done {
        let mut progressed = false;

        if !upload_done {
            let decoded = vision_decoder.read_decoded(&mut client_buffer)?;
            if decoded > 0 {
                if let Some(limiter) = limiter.as_deref() {
                    limiter.wait_for(decoded);
                }
                write_all_wait(&mut remote, &client_buffer[..decoded])?;
                upload = upload.saturating_add(decoded as u64);
                progressed = true;
            } else {
                match client.read(&mut client_buffer) {
                    Ok(0) => {
                        upload_done = true;
                        vision_decoder.finish();
                        let _ = remote.shutdown(Shutdown::Write);
                        progressed = true;
                    }
                    Ok(read) => {
                        vision_decoder.push(&client_buffer[..read]);
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
        }

        if !download_done {
            match remote.read(&mut remote_buffer) {
                Ok(0) => {
                    download_done = true;
                    let _ = client.close_notify_wait();
                    progressed = true;
                }
                Ok(read) => {
                    let encoded = vision_encoder.encode(&remote_buffer[..read]);
                    client.write_plain_all_wait(&encoded)?;
                    download = download.saturating_add(read as u64);
                    progressed = true;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(_) => {
                    download_done = true;
                    let _ = client.close_notify_wait();
                    progressed = true;
                }
            }
        }

        if !progressed {
            thread::sleep(Duration::from_millis(1));
        }
    }

    let _ = client.shutdown(Shutdown::Both);
    let _ = remote.shutdown(Shutdown::Both);
    Ok((upload, download))
}

fn write_all_wait(writer: &mut TcpStream, mut input: &[u8]) -> io::Result<()> {
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
    Ok(())
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

fn parse_addon_flow(addon: &[u8]) -> io::Result<String> {
    let mut index = 0usize;
    let mut flow = String::new();
    while index < addon.len() {
        let key = read_varint(addon, &mut index)?;
        let field = key >> 3;
        let wire_type = key & 0x07;
        match (field, wire_type) {
            (1, 2) => {
                let len = read_varint(addon, &mut index)? as usize;
                if index + len > addon.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "vless addon flow is truncated",
                    ));
                }
                flow = String::from_utf8(addon[index..index + len].to_vec()).map_err(|_| {
                    io::Error::new(
                        io::ErrorKind::InvalidData,
                        "vless addon flow is invalid utf-8",
                    )
                })?;
                index += len;
            }
            (_, 0) => {
                let _ = read_varint(addon, &mut index)?;
            }
            (_, 2) => {
                let len = read_varint(addon, &mut index)? as usize;
                if index + len > addon.len() {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "vless addon field is truncated",
                    ));
                }
                index += len;
            }
            (_, wire_type) => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("unsupported vless addon wire type {wire_type}"),
                ));
            }
        }
    }
    Ok(flow)
}

fn read_varint(input: &[u8], index: &mut usize) -> io::Result<u64> {
    let mut value = 0u64;
    let mut shift = 0u32;
    while *index < input.len() {
        let byte = input[*index];
        *index += 1;
        value |= u64::from(byte & 0x7f) << shift;
        if byte & 0x80 == 0 {
            return Ok(value);
        }
        shift += 7;
        if shift >= 64 {
            break;
        }
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidData,
        "vless addon varint is truncated",
    ))
}

fn parse_uuid_bytes(value: &str) -> io::Result<[u8; 16]> {
    let value = compact_uuid(value);
    if value.len() != 32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "vless uuid must contain 32 hex characters",
        ));
    }
    let mut bytes = [0u8; 16];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        let hex = std::str::from_utf8(chunk)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid vless uuid"))?;
        bytes[index] = u8::from_str_radix(hex, 16)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "invalid vless uuid"))?;
    }
    Ok(bytes)
}

fn compact_uuid(value: &str) -> String {
    value
        .chars()
        .filter(|value| *value != '-')
        .flat_map(|value| value.to_lowercase())
        .collect()
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

#[cfg(test)]
mod tests {
    use std::fs;
    use std::io::{Cursor, Read, Write};
    use std::net::{TcpListener, TcpStream, UdpSocket};
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::thread;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

    use rustls::pki_types::{CertificateDer, ServerName};
    use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

    use crate::config::{OutboundConfig, OutboundTlsConfig, OutboundTransportConfig};
    use crate::httpupgrade::accept_httpupgrade;
    use crate::socks5::SocksTarget;
    use crate::tls::TlsAcceptor;
    use crate::user::CoreUser;
    use crate::vision::{VisionReader, VisionWriter};
    use crate::vless::{connect_vless_tcp_outbound, VlessServer, VlessServerConfig};
    use crate::websocket::{accept_websocket, accept_websocket_tls};

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

    fn server() -> VlessServer {
        server_with_flow("")
    }

    fn server_with_flow(flow: &str) -> VlessServer {
        VlessServer::new(VlessServerConfig {
            node_tag: "panel|vless|1".to_string(),
            listen: "127.0.0.1:0".parse().expect("listen addr"),
            users: vec![user()],
            routes: Vec::new(),
            flow: flow.to_string(),
            connect_timeout: Duration::from_secs(3),
        })
    }

    fn vless_request(target: std::net::SocketAddr) -> Vec<u8> {
        vless_request_with_flow(target, "")
    }

    fn vless_udp_request(target: std::net::SocketAddr) -> Vec<u8> {
        vless_request_with_flow_and_command(target, "", 0x02)
    }

    fn vless_request_with_flow(target: std::net::SocketAddr, flow: &str) -> Vec<u8> {
        vless_request_with_flow_and_command(target, flow, 0x01)
    }

    fn vless_request_with_flow_and_command(
        target: std::net::SocketAddr,
        flow: &str,
        command: u8,
    ) -> Vec<u8> {
        vless_request_for_user_with_flow_and_command([0x11; 16], target, flow, command)
    }

    fn vless_request_for_user_with_flow_and_command(
        user_id: [u8; 16],
        target: std::net::SocketAddr,
        flow: &str,
        command: u8,
    ) -> Vec<u8> {
        let mut input = vec![0x00];
        input.extend_from_slice(&user_id);
        if flow.is_empty() {
            input.push(0x00);
        } else {
            let flow = flow.as_bytes();
            let addon_len = 2 + flow.len();
            input.push(addon_len as u8);
            input.push(0x0a);
            input.push(flow.len() as u8);
            input.extend_from_slice(flow);
        }
        input.push(command);
        input.extend_from_slice(&target.port().to_be_bytes());
        input.push(0x01);
        input.extend_from_slice(
            &target
                .ip()
                .to_string()
                .parse::<std::net::Ipv4Addr>()
                .expect("ipv4")
                .octets(),
        );
        input
    }

    fn vless_udp_payload(payload: &[u8]) -> Vec<u8> {
        let mut frame = Vec::with_capacity(2 + payload.len());
        frame.extend_from_slice(&(payload.len() as u16).to_be_bytes());
        frame.extend_from_slice(payload);
        frame
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
    fn parses_vless_tcp_request() {
        let server = server();
        let mut input = vec![0x00];
        input.extend_from_slice(&[0x11; 16]);
        input.push(0x00);
        input.push(0x01);
        input.extend_from_slice(&443u16.to_be_bytes());
        input.push(0x02);
        input.push(11);
        input.extend_from_slice(b"example.com");
        let mut stream = MemoryStream::new(input);

        let request = server.read_request(&mut stream).expect("request");

        assert_eq!(request.user_uuid, "11111111-1111-1111-1111-111111111111");
        assert_eq!(request.target.host, "example.com");
        assert_eq!(request.target.port, 443);
    }

    #[test]
    fn parses_vless_addon_flow() {
        let flow = super::parse_addon_flow(&[
            0x0a, 0x10, b'x', b't', b'l', b's', b'-', b'r', b'p', b'r', b'x', b'-', b'v', b'i',
            b's', b'i', b'o', b'n',
        ])
        .expect("addon flow");

        assert_eq!(flow, "xtls-rprx-vision");
    }

    #[test]
    fn accepts_matching_vless_vision_flow() {
        let server = server_with_flow("xtls-rprx-vision");
        let target: std::net::SocketAddr = "127.0.0.1:443".parse().expect("addr");
        let mut stream = MemoryStream::new(vless_request_with_flow(target, "xtls-rprx-vision"));

        let request = server.read_request(&mut stream).expect("request");

        assert_eq!(request.flow, "xtls-rprx-vision");
        assert_eq!(request.user_id, [0x11; 16]);
    }

    #[test]
    fn rejects_missing_vless_vision_flow() {
        let server = server_with_flow("xtls-rprx-vision");
        let target: std::net::SocketAddr = "127.0.0.1:443".parse().expect("addr");
        let mut stream = MemoryStream::new(vless_request(target));

        let error = server
            .read_request(&mut stream)
            .expect_err("missing flow should fail");

        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn rejects_vless_udp_with_vision_flow() {
        let server = server_with_flow("xtls-rprx-vision");
        let target: std::net::SocketAddr = "127.0.0.1:443".parse().expect("addr");
        let mut stream = MemoryStream::new(vless_request_with_flow_and_command(
            target,
            "xtls-rprx-vision",
            0x02,
        ));

        let error = server
            .read_request(&mut stream)
            .expect_err("vless udp with flow should fail");

        assert_eq!(error.kind(), std::io::ErrorKind::Unsupported);
    }

    #[test]
    fn rejects_unknown_vless_user() {
        let server = server();
        let mut input = vec![0x00];
        input.extend_from_slice(&[0x22; 16]);
        let mut stream = MemoryStream::new(input);

        let error = server
            .read_request(&mut stream)
            .expect_err("unknown user should fail");

        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);
    }

    #[test]
    fn replaces_users_without_rebuilding_vless_server() {
        let server = server();
        let target: std::net::SocketAddr = "127.0.0.1:443".parse().expect("addr");

        server.replace_users(vec![user_b()]);

        let mut old_stream = MemoryStream::new(vless_request(target));
        let error = server
            .read_request(&mut old_stream)
            .expect_err("old user should fail after replacement");
        assert_eq!(error.kind(), std::io::ErrorKind::PermissionDenied);

        let mut new_stream = MemoryStream::new(vless_request_for_user_with_flow_and_command(
            [0x22; 16], target, "", 0x01,
        ));
        let request = server
            .read_request(&mut new_stream)
            .expect("new user should authenticate");
        assert_eq!(request.user_uuid, "22222222-2222-2222-2222-222222222222");
    }

    #[test]
    fn vless_tcp_outbound_writes_request_and_consumes_response_header() {
        let proxy = TcpListener::bind("127.0.0.1:0").expect("proxy bind");
        let proxy_addr = proxy.local_addr().expect("proxy addr");
        let proxy_thread = thread::spawn(move || {
            let (mut stream, _) = proxy.accept().expect("proxy accept");
            let request = server().read_request(&mut stream).expect("vless request");
            assert_eq!(request.user_uuid, "11111111-1111-1111-1111-111111111111");
            assert_eq!(request.target.host, "example.com");
            assert_eq!(request.target.port, 443);

            stream
                .write_all(&[super::VERSION, 0x00])
                .expect("response header");
            let mut payload = [0u8; 4];
            stream.read_exact(&mut payload).expect("payload");
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong").expect("response");
        });
        let outbound = OutboundConfig {
            tag: "vless-out".to_string(),
            protocol: "vless".to_string(),
            method: None,
            address: Some(proxy_addr.ip().to_string()),
            port: Some(proxy_addr.port()),
            username: Some("11111111-1111-1111-1111-111111111111".to_string()),
            password: None,
            tls: None,
            transport: None,
        };
        let target = SocksTarget {
            host: "example.com".to_string(),
            port: 443,
        };

        let mut stream = connect_vless_tcp_outbound(&outbound, &target, Duration::from_secs(2))
            .expect("connect outbound");
        stream.write_all(b"ping").expect("write payload");
        let mut response = [0u8; 4];
        stream.read_exact(&mut response).expect("read response");

        assert_eq!(&response, b"pong");
        proxy_thread.join().expect("proxy thread");
    }

    #[test]
    fn vless_tls_tcp_outbound_writes_request_and_relays_stream() {
        let cert = test_cert("vless-outbound");
        let proxy = TcpListener::bind("127.0.0.1:0").expect("proxy bind");
        let proxy_addr = proxy.local_addr().expect("proxy addr");
        let acceptor =
            TlsAcceptor::from_files(&cert.cert_path, &cert.key_path, &[]).expect("tls acceptor");
        let proxy_thread = thread::spawn(move || {
            let (stream, _) = proxy.accept().expect("proxy accept");
            let mut stream = acceptor.accept(stream).expect("tls accept");
            let request = server().read_request(&mut stream).expect("vless request");
            assert_eq!(request.user_uuid, "11111111-1111-1111-1111-111111111111");
            assert_eq!(request.target.host, "example.com");
            assert_eq!(request.target.port, 443);

            stream
                .write_all(&[super::VERSION, 0x00])
                .expect("response header");
            let mut payload = [0u8; 4];
            stream.read_exact(&mut payload).expect("payload");
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong").expect("response");
        });
        let outbound = OutboundConfig {
            tag: "vless-out".to_string(),
            protocol: "vless".to_string(),
            method: None,
            address: Some(proxy_addr.ip().to_string()),
            port: Some(proxy_addr.port()),
            username: Some("11111111-1111-1111-1111-111111111111".to_string()),
            password: None,
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

        let mut stream = connect_vless_tcp_outbound(&outbound, &target, Duration::from_secs(2))
            .expect("connect outbound");
        stream.write_all(b"ping").expect("write payload");
        let mut response = [0u8; 4];
        stream.read_exact(&mut response).expect("read response");

        assert_eq!(&response, b"pong");
        proxy_thread.join().expect("proxy thread");
    }

    #[test]
    fn vless_websocket_outbound_writes_request_and_relays_stream() {
        let proxy = TcpListener::bind("127.0.0.1:0").expect("proxy bind");
        let proxy_addr = proxy.local_addr().expect("proxy addr");
        let proxy_thread = thread::spawn(move || {
            let (stream, _) = proxy.accept().expect("proxy accept");
            let (mut reader, mut writer) =
                accept_websocket(stream, Some("/vless")).expect("websocket accept");
            let request = server().read_request(&mut reader).expect("vless request");
            assert_eq!(request.user_uuid, "11111111-1111-1111-1111-111111111111");
            assert_eq!(request.target.host, "example.com");
            assert_eq!(request.target.port, 443);

            writer
                .write_all(&[super::VERSION, 0x00])
                .expect("response header");
            let mut payload = [0u8; 4];
            reader.read_exact(&mut payload).expect("payload");
            assert_eq!(&payload, b"ping");
            writer.write_all(b"pong").expect("response");
        });
        let outbound = OutboundConfig {
            tag: "vless-out".to_string(),
            protocol: "vless".to_string(),
            method: None,
            address: Some(proxy_addr.ip().to_string()),
            port: Some(proxy_addr.port()),
            username: Some("11111111-1111-1111-1111-111111111111".to_string()),
            password: None,
            tls: None,
            transport: Some(OutboundTransportConfig {
                network: "ws".to_string(),
                path: Some("/vless".to_string()),
                host: Some("example.test".to_string()),
                service_name: None,
            }),
        };
        let target = SocksTarget {
            host: "example.com".to_string(),
            port: 443,
        };

        let mut stream = connect_vless_tcp_outbound(&outbound, &target, Duration::from_secs(2))
            .expect("connect outbound");
        stream.write_all(b"ping").expect("write payload");
        let mut response = [0u8; 4];
        stream.read_exact(&mut response).expect("read response");

        assert_eq!(&response, b"pong");
        proxy_thread.join().expect("proxy thread");
    }

    #[test]
    fn vless_tls_websocket_outbound_writes_request_and_relays_stream() {
        let cert = test_cert("vless-ws-outbound");
        let proxy = TcpListener::bind("127.0.0.1:0").expect("proxy bind");
        let proxy_addr = proxy.local_addr().expect("proxy addr");
        let acceptor =
            TlsAcceptor::from_files(&cert.cert_path, &cert.key_path, &[]).expect("tls acceptor");
        let proxy_thread = thread::spawn(move || {
            let (stream, _) = proxy.accept().expect("proxy accept");
            let stream = acceptor.accept(stream).expect("tls accept");
            let mut websocket =
                accept_websocket_tls(stream, Some("/vless")).expect("websocket accept");
            let request = server()
                .read_request(&mut websocket)
                .expect("vless request");
            assert_eq!(request.user_uuid, "11111111-1111-1111-1111-111111111111");
            assert_eq!(request.target.host, "example.com");
            assert_eq!(request.target.port, 443);

            websocket
                .write_all(&[super::VERSION, 0x00])
                .expect("response header");
            let mut payload = [0u8; 4];
            websocket.read_exact(&mut payload).expect("payload");
            assert_eq!(&payload, b"ping");
            websocket.write_all(b"pong").expect("response");
        });
        let outbound = OutboundConfig {
            tag: "vless-out".to_string(),
            protocol: "vless".to_string(),
            method: None,
            address: Some(proxy_addr.ip().to_string()),
            port: Some(proxy_addr.port()),
            username: Some("11111111-1111-1111-1111-111111111111".to_string()),
            password: None,
            tls: Some(OutboundTlsConfig {
                server_name: "localhost".to_string(),
                allow_insecure: true,
                alpn: Vec::new(),
            }),
            transport: Some(OutboundTransportConfig {
                network: "ws".to_string(),
                path: Some("/vless".to_string()),
                host: Some("localhost".to_string()),
                service_name: None,
            }),
        };
        let target = SocksTarget {
            host: "example.com".to_string(),
            port: 443,
        };

        let mut stream = connect_vless_tcp_outbound(&outbound, &target, Duration::from_secs(2))
            .expect("connect outbound");
        stream.write_all(b"ping").expect("write payload");
        let mut response = [0u8; 4];
        stream.read_exact(&mut response).expect("read response");

        assert_eq!(&response, b"pong");
        proxy_thread.join().expect("proxy thread");
    }

    #[test]
    fn vless_httpupgrade_outbound_writes_request_and_relays_stream() {
        let proxy = TcpListener::bind("127.0.0.1:0").expect("proxy bind");
        let proxy_addr = proxy.local_addr().expect("proxy addr");
        let proxy_thread = thread::spawn(move || {
            let (stream, _) = proxy.accept().expect("proxy accept");
            let mut stream = accept_httpupgrade(stream, Some("/vless"), Some("example.test"))
                .expect("httpupgrade accept");
            let request = server().read_request(&mut stream).expect("vless request");
            assert_eq!(request.user_uuid, "11111111-1111-1111-1111-111111111111");
            assert_eq!(request.target.host, "example.com");
            assert_eq!(request.target.port, 443);

            stream
                .write_all(&[super::VERSION, 0x00])
                .expect("response header");
            let mut payload = [0u8; 4];
            stream.read_exact(&mut payload).expect("payload");
            assert_eq!(&payload, b"ping");
            stream.write_all(b"pong").expect("response");
        });
        let outbound = OutboundConfig {
            tag: "vless-out".to_string(),
            protocol: "vless".to_string(),
            method: None,
            address: Some(proxy_addr.ip().to_string()),
            port: Some(proxy_addr.port()),
            username: Some("11111111-1111-1111-1111-111111111111".to_string()),
            password: None,
            tls: None,
            transport: Some(OutboundTransportConfig {
                network: "httpupgrade".to_string(),
                path: Some("/vless".to_string()),
                host: Some("example.test".to_string()),
                service_name: None,
            }),
        };
        let target = SocksTarget {
            host: "example.com".to_string(),
            port: 443,
        };

        let mut stream = connect_vless_tcp_outbound(&outbound, &target, Duration::from_secs(2))
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
        let listener = server.bind().expect("vless bind");
        let vless_addr = listener.local_addr().expect("vless addr");
        let server_clone = server.clone();
        let server_thread = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("vless accept");
            server_clone.handle_tcp_client(stream)
        });

        let mut client = TcpStream::connect(vless_addr).expect("client connect");
        client
            .write_all(&vless_request(echo_addr))
            .expect("client request");
        let mut response = [0u8; 2];
        client.read_exact(&mut response).expect("client response");
        assert_eq!(response, [0x00, 0x00]);

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
        assert_eq!(records[0].node_tag, "panel|vless|1");
        assert_eq!(records[0].user_uuid, "11111111-1111-1111-1111-111111111111");
        assert_eq!(records[0].upload, 4);
        assert_eq!(records[0].download, 4);
    }

    #[test]
    fn proxies_udp_and_records_user_traffic() {
        let echo = UdpSocket::bind("127.0.0.1:0").expect("echo bind");
        let echo_addr = echo.local_addr().expect("echo addr");
        let echo_thread = thread::spawn(move || {
            let mut bytes = [0u8; 1024];
            let (read, source) = echo.recv_from(&mut bytes).expect("echo read");
            assert_eq!(&bytes[..read], b"ping");
            echo.send_to(b"pong", source).expect("echo write");
        });

        let server = server();
        let listener = server.bind().expect("vless bind");
        let vless_addr = listener.local_addr().expect("vless addr");
        let server_clone = server.clone();
        let server_thread = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("vless accept");
            server_clone.handle_tcp_client(stream)
        });

        let mut client = TcpStream::connect(vless_addr).expect("client connect");
        client
            .set_read_timeout(Some(Duration::from_secs(3)))
            .expect("client timeout");
        client
            .write_all(&vless_udp_request(echo_addr))
            .expect("client request");
        let mut response = [0u8; 2];
        client.read_exact(&mut response).expect("client response");
        assert_eq!(response, [0x00, 0x00]);

        client
            .write_all(&vless_udp_payload(b"ping"))
            .expect("client udp packet");
        let response = super::read_vless_udp_payload(&mut client).expect("udp response");
        assert_eq!(response, b"pong");
        drop(client);

        server_thread
            .join()
            .expect("server thread")
            .expect("serve once");
        echo_thread.join().expect("echo thread");

        let records = server.drain_traffic(1);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].node_tag, "panel|vless|1");
        assert_eq!(records[0].user_uuid, "11111111-1111-1111-1111-111111111111");
        assert_eq!(records[0].upload, 4);
        assert_eq!(records[0].download, 4);
    }

    #[test]
    fn proxies_tls_and_records_user_traffic() {
        let cert = test_cert("vless");
        let echo = TcpListener::bind("127.0.0.1:0").expect("echo bind");
        let echo_addr = echo.local_addr().expect("echo addr");
        let echo_thread = thread::spawn(move || {
            let (mut stream, _) = echo.accept().expect("echo accept");
            let mut bytes = [0u8; 4];
            stream.read_exact(&mut bytes).expect("echo read");
            stream.write_all(&bytes).expect("echo write");
        });

        let server = server();
        let listener = server.bind().expect("vless bind");
        let vless_addr = listener.local_addr().expect("vless addr");
        let acceptor =
            TlsAcceptor::from_files(&cert.cert_path, &cert.key_path, &[]).expect("tls acceptor");
        let server_clone = server.clone();
        let server_thread = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("vless accept");
            let client = acceptor.accept(stream).expect("tls accept");
            server_clone.handle_tls_client(client)
        });

        let mut client = tls_client(vless_addr, cert.cert_der.clone());
        client
            .write_all(&vless_request(echo_addr))
            .expect("client request");
        let mut response = [0u8; 2];
        client.read_exact(&mut response).expect("client response");
        assert_eq!(response, [0x00, 0x00]);

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
        assert_eq!(records[0].node_tag, "panel|vless|1");
        assert_eq!(records[0].user_uuid, "11111111-1111-1111-1111-111111111111");
        assert_eq!(records[0].upload, 4);
        assert_eq!(records[0].download, 4);
    }

    #[test]
    fn proxies_tls_vision_and_records_user_traffic() {
        let cert = test_cert("vless-vision");
        let echo = TcpListener::bind("127.0.0.1:0").expect("echo bind");
        let echo_addr = echo.local_addr().expect("echo addr");
        let echo_thread = thread::spawn(move || {
            let (mut stream, _) = echo.accept().expect("echo accept");
            let mut bytes = [0u8; 4];
            stream.read_exact(&mut bytes).expect("echo read");
            stream.write_all(&bytes).expect("echo write");
        });

        let server = server_with_flow("xtls-rprx-vision");
        let listener = server.bind().expect("vless bind");
        let vless_addr = listener.local_addr().expect("vless addr");
        let acceptor =
            TlsAcceptor::from_files(&cert.cert_path, &cert.key_path, &[]).expect("tls acceptor");
        let server_clone = server.clone();
        let server_thread = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("vless accept");
            let client = acceptor.accept(stream).expect("tls accept");
            server_clone.handle_tls_client(client)
        });

        let mut client = tls_client(vless_addr, cert.cert_der.clone());
        client
            .write_all(&vless_request_with_flow(echo_addr, "xtls-rprx-vision"))
            .expect("client request");
        let mut response = [0u8; 2];
        client.read_exact(&mut response).expect("client response");
        assert_eq!(response, [0x00, 0x00]);

        let mut encoded = Vec::new();
        VisionWriter::new(&mut encoded, [0x11; 16])
            .write_all(b"ping")
            .expect("vision payload");
        client.write_all(&encoded).expect("client write payload");

        let mut echoed = [0u8; 4];
        VisionReader::new(&mut client, [0x11; 16])
            .read_exact(&mut echoed)
            .expect("client read payload");
        assert_eq!(&echoed, b"ping");
        drop(client);

        server_thread
            .join()
            .expect("server thread")
            .expect("serve once");
        echo_thread.join().expect("echo thread");

        let records = server.drain_traffic(1);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].node_tag, "panel|vless|1");
        assert_eq!(records[0].user_uuid, "11111111-1111-1111-1111-111111111111");
        assert_eq!(records[0].upload, 4);
        assert_eq!(records[0].download, 4);
    }

    #[test]
    fn proxies_tls_websocket_and_records_user_traffic() {
        let cert = test_cert("vless-ws");
        let echo = TcpListener::bind("127.0.0.1:0").expect("echo bind");
        let echo_addr = echo.local_addr().expect("echo addr");
        let echo_thread = thread::spawn(move || {
            let (mut stream, _) = echo.accept().expect("echo accept");
            let mut bytes = [0u8; 4];
            stream.read_exact(&mut bytes).expect("echo read");
            stream.write_all(&bytes).expect("echo write");
        });

        let server = server();
        let listener = server.bind().expect("vless bind");
        let vless_addr = listener.local_addr().expect("vless addr");
        let acceptor =
            TlsAcceptor::from_files(&cert.cert_path, &cert.key_path, &[]).expect("tls acceptor");
        let server_clone = server.clone();
        let server_thread = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("vless accept");
            let client = acceptor.accept(stream).expect("tls accept");
            server_clone.handle_tls_websocket_client(client, Some("/vless"))
        });

        let mut client = tls_client(vless_addr, cert.cert_der.clone());
        client
            .write_all(&websocket_request("/vless"))
            .expect("websocket request");
        let response = read_websocket_response(&mut client);
        assert!(response.contains("101 Switching Protocols"));

        client
            .write_all(&masked_frame(&vless_request(echo_addr)))
            .expect("vless request frame");
        assert_eq!(read_binary_frame(&mut client), [0x00, 0x00]);

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
        assert_eq!(records[0].node_tag, "panel|vless|1");
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
        let listener = server.bind().expect("vless bind");
        let vless_addr = listener.local_addr().expect("vless addr");
        let server_clone = server.clone();
        let server_thread = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("vless accept");
            server_clone.handle_websocket_client(stream, Some("/vless"))
        });

        let mut client = TcpStream::connect(vless_addr).expect("client connect");
        client
            .write_all(&websocket_request("/vless"))
            .expect("websocket request");
        let response = read_websocket_response(&mut client);
        assert!(response.contains("101 Switching Protocols"));

        client
            .write_all(&masked_frame(&vless_request(echo_addr)))
            .expect("vless request frame");
        assert_eq!(read_binary_frame(&mut client), [0x00, 0x00]);

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
        assert_eq!(records[0].node_tag, "panel|vless|1");
        assert_eq!(records[0].user_uuid, "11111111-1111-1111-1111-111111111111");
        assert_eq!(records[0].upload, 4);
        assert_eq!(records[0].download, 4);
    }
}
