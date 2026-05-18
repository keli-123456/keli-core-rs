use std::env;
use std::io::{self, Read, Write};
use std::net::{
    IpAddr, Ipv4Addr, Ipv6Addr, Shutdown, SocketAddr, TcpListener, TcpStream, UdpSocket,
};
#[cfg(test)]
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, RootCertStore, SignatureScheme,
    StreamOwned,
};
use socket2::SockRef;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

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
    relay_tcp_fast_unlimited_close_on_eof, relay_tcp_limited, spawn_native_blocking_relay,
};
use crate::tls::{relay_tls_stream, RawTcpStreamAccess, TlsConnection, TlsSocket};
use crate::traffic::{SharedTrafficRegistry, TrafficRegistry};
use crate::user::{CoreUser, CoreUserDelta, CoreUserDeltaResult, UserStore};
use crate::vision::{VisionDecoder, VisionEncoder, VisionReader, VisionWriter};
use crate::websocket::{
    accept_websocket, accept_websocket_tls, connect_websocket_client, relay_websocket_tls_stream,
    WebSocketClientStream,
};
use crate::{
    connect_tcp_outbound, connect_tcp_outbound_tokio, route_protocol_labels, send_udp_outbound,
    send_udp_outbound_tokio, RouteDecision, RouteMatcher,
};

const VERSION: u8 = 0x00;
const COMMAND_TCP: u8 = 0x01;
const COMMAND_UDP: u8 = 0x02;
const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x02;
const ATYP_IPV6: u8 = 0x03;
const FLOW_XTLS_RPRX_VISION: &str = "xtls-rprx-vision";
const MAX_UDP_PACKET_SIZE: usize = 65_535;
const ASYNC_TRAFFIC_FLUSH_BYTES: u64 = 4 * 1024 * 1024;
const VLESS_TRACE_ENV: &str = "KELI_CORE_VLESS_TRACE";
const VLESS_VISION_DRAIN_MS_ENV: &str = "KELI_CORE_VLESS_VISION_DRAIN_MS";
const VLESS_VISION_DRAIN_SECS_ENV: &str = "KELI_CORE_VLESS_VISION_DRAIN_SECS";
const VLESS_ASYNC_RELAY_IO_TIMEOUT_SECS_ENV: &str = "KELI_CORE_VLESS_RELAY_IO_TIMEOUT_SECS";
const DEFAULT_VLESS_ASYNC_RELAY_IO_TIMEOUT_SECS: u64 = 15;

#[cfg(test)]
static VLESS_VISION_RAW_RELAY_SWITCHES: AtomicUsize = AtomicUsize::new(0);

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
    traffic: SharedTrafficRegistry,
    sessions: UserSessionTracker,
    bandwidth: UserBandwidthLimiters,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct VlessRequest {
    command: VlessCommand,
    user_key: String,
    user_uuid: String,
    user_numeric_id: u64,
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
    target: Option<SocksTarget>,
    target_addr: Option<SocketAddr>,
    timeout: Duration,
}

struct AsyncVlessUdpRelayState {
    ipv4: Option<tokio::net::UdpSocket>,
    ipv6: Option<tokio::net::UdpSocket>,
    target: Option<SocksTarget>,
    target_addr: Option<SocketAddr>,
    timeout: Duration,
}

impl VlessServer {
    pub fn new(config: VlessServerConfig) -> Self {
        Self::with_traffic(config, TrafficRegistry::shared())
    }

    pub fn with_traffic(config: VlessServerConfig, traffic: SharedTrafficRegistry) -> Self {
        Self::with_shared_limits(
            config,
            traffic,
            UserSessionTracker::default(),
            UserBandwidthLimiters::default(),
        )
    }

    pub fn with_shared_limits(
        mut config: VlessServerConfig,
        traffic: SharedTrafficRegistry,
        sessions: UserSessionTracker,
        bandwidth: UserBandwidthLimiters,
    ) -> Self {
        let users = UserStore::from_keyed_users(&config.users, |user| compact_uuid(&user.uuid));
        let router = RouteMatcher::new(config.routes.clone());
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

    pub fn handle_tcp_client(&self, client: TcpStream) -> io::Result<()> {
        let result = self.handle_tcp_client_inner(client);
        if let Err(error) = &result {
            record_vless_connection_error("tcp", error);
        }
        result
    }

    fn handle_tcp_client_inner(&self, mut client: TcpStream) -> io::Result<()> {
        let _ = client.set_read_timeout(Some(self.config.connect_timeout));
        let _ = client.set_write_timeout(Some(self.config.connect_timeout));
        let client_ip = client.peer_addr().ok().map(|addr| addr.ip());
        let mut request = match self.read_request(&mut client) {
            Ok(request) => request,
            Err(error) => {
                let _ = client.shutdown(Shutdown::Both);
                return Err(error);
            }
        };
        let _ = client.set_read_timeout(None);
        let _ = client.set_write_timeout(None);
        request.client_ip = client_ip;
        let user = self.request_user(&request);
        let _session = self.acquire_user_session(user.as_ref(), client_ip)?;
        if request.command == VlessCommand::Udp {
            let bandwidth = self.bandwidth.limiter_for(user.as_ref());
            client.write_all(&[VERSION, 0x00])?;
            return self.relay_udp_stream(client, request, bandwidth);
        }
        let bandwidth = self.bandwidth.limiter_for_limited(user.as_ref());
        let remote =
            match self
                .router
                .decide_target(&request.target.host, request.target.port, "tcp")
            {
                RouteDecision::Direct => {
                    match connect_target(&request.target, self.config.connect_timeout) {
                        Ok(remote) => remote,
                        Err(error) => {
                            let _ = client.shutdown(Shutdown::Both);
                            return Err(error);
                        }
                    }
                }
                RouteDecision::Outbound(outbound) => {
                    match connect_tcp_outbound(
                        &outbound,
                        &request.target,
                        self.config.connect_timeout,
                    ) {
                        Ok(remote) => remote,
                        Err(error) => {
                            let _ = client.shutdown(Shutdown::Both);
                            return Err(error);
                        }
                    }
                }
                RouteDecision::Block => {
                    let _ = client.shutdown(Shutdown::Both);
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "target blocked by route",
                    ));
                }
                RouteDecision::UnsupportedOutbound(tag) => {
                    let _ = client.shutdown(Shutdown::Both);
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        format!("outbound route {tag} is not implemented"),
                    ));
                }
            };
        if let Err(error) = client.write_all(&[VERSION, 0x00]) {
            let _ = client.shutdown(Shutdown::Both);
            return Err(error);
        }
        self.relay(client, remote, request, bandwidth)
    }

    pub async fn handle_tcp_client_async(&self, client: tokio::net::TcpStream) -> io::Result<()> {
        let result = self.handle_tcp_client_async_inner(client).await;
        if let Err(error) = &result {
            record_vless_connection_error("tcp", error);
        }
        result
    }

    async fn handle_tcp_client_async_inner(
        &self,
        mut client: tokio::net::TcpStream,
    ) -> io::Result<()> {
        let client_shutdown = clone_tokio_tcp_stream_for_shutdown(&client).ok();
        let client_ip = client.peer_addr().ok().map(|addr| addr.ip());
        let mut request = match self.read_request_async(&mut client).await {
            Ok(request) => request,
            Err(error) => {
                if let Some(socket) = &client_shutdown {
                    let _ = socket.shutdown(Shutdown::Both);
                }
                return Err(error);
            }
        };
        request.client_ip = client_ip;
        let user = self.request_user(&request);
        let _session = self.acquire_user_session(user.as_ref(), client_ip)?;
        if request.command == VlessCommand::Udp {
            let bandwidth = self.bandwidth.limiter_for(user.as_ref());
            client.write_all(&[VERSION, 0x00]).await?;
            return self
                .relay_udp_stream_async(client, request, bandwidth)
                .await;
        }
        let bandwidth = self.bandwidth.limiter_for_limited(user.as_ref());
        if request.flow == FLOW_XTLS_RPRX_VISION {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "vless vision requires the tls handler",
            ));
        }
        let remote =
            match self
                .router
                .decide_target(&request.target.host, request.target.port, "tcp")
            {
                RouteDecision::Direct => {
                    match connect_target_async(&request.target, self.config.connect_timeout).await {
                        Ok(remote) => remote,
                        Err(error) => {
                            if let Some(socket) = &client_shutdown {
                                let _ = socket.shutdown(Shutdown::Both);
                            }
                            return Err(error);
                        }
                    }
                }
                RouteDecision::Outbound(outbound) => {
                    match connect_tcp_outbound_tokio(
                        &outbound,
                        &request.target,
                        self.config.connect_timeout,
                    )
                    .await
                    {
                        Ok(remote) => remote,
                        Err(error) => {
                            if let Some(socket) = &client_shutdown {
                                let _ = socket.shutdown(Shutdown::Both);
                            }
                            return Err(error);
                        }
                    }
                }
                RouteDecision::Block => {
                    if let Some(socket) = &client_shutdown {
                        let _ = socket.shutdown(Shutdown::Both);
                    }
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "target blocked by route",
                    ));
                }
                RouteDecision::UnsupportedOutbound(tag) => {
                    if let Some(socket) = &client_shutdown {
                        let _ = socket.shutdown(Shutdown::Both);
                    }
                    return Err(io::Error::new(
                        io::ErrorKind::Unsupported,
                        format!("outbound route {tag} is not implemented"),
                    ));
                }
            };
        if let Err(error) = client.write_all(&[VERSION, 0x00]).await {
            if let Some(socket) = &client_shutdown {
                let _ = socket.shutdown(Shutdown::Both);
            }
            return Err(error);
        }
        self.relay_async(client, remote, request, bandwidth).await
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
        let bandwidth = if request.command == VlessCommand::Udp {
            self.bandwidth.limiter_for(user.as_ref())
        } else {
            self.bandwidth.limiter_for_limited(user.as_ref())
        };
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
        S: TlsSocket + RawTcpStreamAccess + Send + 'static,
    {
        let _ = client.set_io_timeout(Some(self.config.connect_timeout));
        let client_ip = client.peer_addr().ok().map(|addr| addr.ip());
        let mut request = self.read_request(&mut client)?;
        let _ = client.set_io_timeout(None);
        request.client_ip = client_ip;
        let user = self.request_user(&request);
        let _session = self.acquire_user_session(user.as_ref(), client_ip)?;
        let bandwidth = if request.command == VlessCommand::Udp {
            self.bandwidth.limiter_for(user.as_ref())
        } else {
            self.bandwidth.limiter_for_limited(user.as_ref())
        };
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
        trace_vless(|| {
            format!(
                "tls request target={}:{} flow={} user={}",
                request.target.host, request.target.port, request.flow, request.user_key
            )
        });
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
        let bandwidth = if request.command == VlessCommand::Udp {
            self.bandwidth.limiter_for(user.as_ref())
        } else {
            self.bandwidth.limiter_for_limited(user.as_ref())
        };
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
        self.traffic.drain_minimum(minimum_bytes)
    }

    pub fn replace_users(&self, users: Vec<CoreUser>) {
        self.bandwidth.sync_users(&users);
        self.users
            .replace_keyed_users(users, |user| compact_uuid(&user.uuid));
    }

    pub fn apply_user_delta(&self, delta: &CoreUserDelta) -> CoreUserDeltaResult {
        sync_delta_bandwidth(&self.bandwidth, &self.sessions, delta);
        self.users
            .apply_keyed_delta(delta, |user| compact_uuid(&user.uuid))
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
            user_numeric_id: user.id,
            user_id: uuid,
            flow,
            target,
            client_ip: None,
        })
    }

    async fn read_request_async<R>(&self, stream: &mut R) -> io::Result<VlessRequest>
    where
        R: AsyncRead + Unpin,
    {
        let version = read_u8_async(stream).await?;
        if version != VERSION {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "unsupported vless version",
            ));
        }

        let mut uuid = [0u8; 16];
        stream.read_exact(&mut uuid).await?;
        let user_key = format_uuid_compact(&uuid);
        let Some(user) = self.users.get(&user_key) else {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "unknown vless user",
            ));
        };

        let flow = self.read_addon_flow_async(stream).await?;
        self.validate_request_flow(&flow)?;

        let command = read_u8_async(stream).await?;
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

        let target = read_vless_target_async(stream).await?;

        Ok(VlessRequest {
            command,
            user_key,
            user_uuid: user.uuid.clone(),
            user_numeric_id: user.id,
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

    async fn read_addon_flow_async<R>(&self, stream: &mut R) -> io::Result<String>
    where
        R: AsyncRead + Unpin,
    {
        let addon_len = read_u8_async(stream).await?;
        if addon_len == 0 {
            return Ok(String::new());
        }
        let mut addon = vec![0u8; usize::from(addon_len)];
        stream.read_exact(&mut addon).await?;
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
        let _connection = self
            .bandwidth
            .register_tcp_connection(Some(&request.user_uuid), &[&client, &remote])?;
        let (upload, download) = if request.flow == FLOW_XTLS_RPRX_VISION {
            relay_vision_tcp_streams(client, remote, request.user_id, bandwidth)?
        } else if let Some(limiter) = bandwidth {
            relay_tcp_limited(client, remote, limiter)?
        } else {
            relay_tcp_fast_unlimited_close_on_eof(client, remote)?
        };
        self.traffic.add_with_user_id(
            self.config.node_tag.clone(),
            request.user_uuid,
            Some(request.user_numeric_id),
            upload,
            download,
            request.client_ip,
        );
        Ok(())
    }

    async fn relay_async(
        &self,
        client: tokio::net::TcpStream,
        remote: tokio::net::TcpStream,
        request: VlessRequest,
        bandwidth: Option<Arc<BandwidthLimiter>>,
    ) -> io::Result<()> {
        let _connection = self
            .bandwidth
            .register_tokio_tcp_connection(Some(&request.user_uuid), &[&client, &remote])?;
        let upload_traffic = self.traffic.clone();
        let upload_node_tag = self.config.node_tag.clone();
        let upload_user_uuid = request.user_uuid.clone();
        let upload_user_id = request.user_numeric_id;
        let download_traffic = self.traffic.clone();
        let download_node_tag = self.config.node_tag.clone();
        let download_user_uuid = request.user_uuid;
        let download_user_id = request.user_numeric_id;
        let upload_flush = traffic_flush_callback(
            upload_traffic,
            upload_node_tag,
            upload_user_uuid,
            Some(upload_user_id),
            true,
            request.client_ip,
        );
        let download_flush = traffic_flush_callback(
            download_traffic,
            download_node_tag,
            download_user_uuid,
            Some(download_user_id),
            false,
            None,
        );
        relay_tcp_streams_async(client, remote, bandwidth, upload_flush, download_flush).await?;
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
            let _connection = self
                .bandwidth
                .register_tcp_connection(Some(&request.user_uuid), &[&remote_read])?;
            let upload_limiter = bandwidth.clone();
            let upload_task =
                spawn_native_blocking_relay(move || match upload_limiter.as_deref() {
                    Some(limiter) => copy_count_best_effort_limited(
                        &mut reader,
                        &mut remote_write,
                        Some(limiter),
                    ),
                    None => copy_count_best_effort(&mut reader, &mut remote_write),
                })?;
            let download = match bandwidth.as_deref() {
                Some(limiter) => {
                    copy_count_best_effort_limited(&mut remote_read, &mut writer, Some(limiter))
                }
                None => copy_count_best_effort(&mut remote_read, &mut writer),
            };
            let upload = join_native_blocking_relay(upload_task, "upload relay task panicked")?;
            (upload, download)
        };
        self.traffic.add_with_user_id(
            self.config.node_tag.clone(),
            request.user_uuid,
            Some(request.user_numeric_id),
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
        S: TlsSocket + RawTcpStreamAccess,
    {
        let (upload, download) = if request.flow == FLOW_XTLS_RPRX_VISION {
            relay_tls_vision_stream(client, remote, request.user_id, bandwidth)?
        } else {
            relay_tls_stream(client, remote, bandwidth)?
        };
        self.traffic.add_with_user_id(
            self.config.node_tag.clone(),
            request.user_uuid,
            Some(request.user_numeric_id),
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
        self.traffic.add_with_user_id(
            self.config.node_tag.clone(),
            request.user_uuid,
            Some(request.user_numeric_id),
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
        self.record_traffic(
            request.user_uuid,
            request.user_numeric_id,
            upload,
            download,
            request.client_ip,
        );
        result
    }

    async fn relay_udp_stream_async(
        &self,
        mut stream: tokio::net::TcpStream,
        request: VlessRequest,
        bandwidth: Option<Arc<BandwidthLimiter>>,
    ) -> io::Result<()> {
        let mut state = AsyncVlessUdpRelayState::new(self.config.connect_timeout);
        let mut upload = 0u64;
        let mut download = 0u64;
        let result = loop {
            match read_vless_udp_payload_async(&mut stream).await {
                Ok(payload) => {
                    match self
                        .forward_udp_payload_async(
                            &mut state,
                            &mut stream,
                            &request.target,
                            &payload,
                            bandwidth.as_deref(),
                        )
                        .await
                    {
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
            request.user_numeric_id,
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
        self.record_traffic(
            request.user_uuid,
            request.user_numeric_id,
            upload,
            download,
            request.client_ip,
        );
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
            if !limiter.wait_for(payload.len()) {
                return Ok((0, 0));
            }
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

        let remote_addr = state.remote_addr_for(target)?;
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

    async fn forward_udp_payload_async<W>(
        &self,
        state: &mut AsyncVlessUdpRelayState,
        writer: &mut W,
        target: &SocksTarget,
        payload: &[u8],
        bandwidth: Option<&BandwidthLimiter>,
    ) -> io::Result<(u64, u64)>
    where
        W: AsyncWrite + Unpin,
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
            if !limiter.wait_for_async(payload.len()).await {
                return Ok((0, 0));
            }
        }

        if let Some(outbound) = outbound {
            return match send_udp_outbound_tokio(
                outbound,
                target,
                payload,
                self.config.connect_timeout,
            )
            .await
            {
                Ok((_, response)) => {
                    write_vless_udp_payload_async(writer, &response).await?;
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

        let remote_addr = state.remote_addr_for(target).await?;
        let timeout = state.timeout;
        let udp = state.socket_for(remote_addr).await?;
        udp.send_to(payload, remote_addr).await?;
        let mut response = vec![0u8; MAX_UDP_PACKET_SIZE];
        let download = match recv_udp_response_async(udp, &mut response, timeout).await {
            Ok((read, _)) => {
                write_vless_udp_payload_async(writer, &response[..read]).await?;
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

fn sync_delta_bandwidth(
    bandwidth: &UserBandwidthLimiters,
    sessions: &UserSessionTracker,
    delta: &CoreUserDelta,
) {
    sync_user_limit_delta(bandwidth, sessions, delta);
}

fn record_vless_connection_error(scope: &'static str, error: &io::Error) {
    crate::metrics::record_connection_error("vless", scope, classify_vless_connection_error(error));
}

fn classify_vless_connection_error(error: &io::Error) -> &'static str {
    let text = error.to_string();
    if error.kind() == io::ErrorKind::PermissionDenied {
        if text.contains("target blocked by route") {
            return "route_blocked";
        }
        if text.contains("private ip blocked") {
            return "dns_private_blocked";
        }
        if text.contains("unknown vless user")
            || text.contains("not allowed")
            || text.contains("requires xtls-rprx-vision")
            || text.contains("device limit")
            || text.contains("session limit")
        {
            return "auth_failed";
        }
        return "permission_denied";
    }
    if error.kind() == io::ErrorKind::TimedOut || text.contains("timed out") {
        return "upstream_timeout";
    }
    if matches!(
        error.kind(),
        io::ErrorKind::ConnectionRefused | io::ErrorKind::AddrNotAvailable
    ) {
        return "upstream_connect_failed";
    }
    if matches!(
        error.kind(),
        io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::UnexpectedEof
    ) {
        return "client_closed";
    }
    if error.kind() == io::ErrorKind::Unsupported {
        return "unsupported";
    }
    if error.kind() == io::ErrorKind::InvalidData {
        return "invalid_request";
    }
    "error"
}

impl VlessUdpRelayState {
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

impl AsyncVlessUdpRelayState {
    fn new(timeout: Duration) -> Self {
        Self {
            ipv4: None,
            ipv6: None,
            target: None,
            target_addr: None,
            timeout,
        }
    }

    async fn remote_addr_for(&mut self, target: &SocksTarget) -> io::Result<SocketAddr> {
        if self.target.as_ref() == Some(target) {
            if let Some(target_addr) = self.target_addr {
                return Ok(target_addr);
            }
        }
        let target_addr = resolve_udp_target_async(target).await?;
        self.target = Some(target.clone());
        self.target_addr = Some(target_addr);
        Ok(target_addr)
    }

    async fn socket_for(&mut self, remote: SocketAddr) -> io::Result<&tokio::net::UdpSocket> {
        let slot = if remote.is_ipv4() {
            &mut self.ipv4
        } else {
            &mut self.ipv6
        };
        if slot.is_none() {
            let socket = tokio::net::UdpSocket::bind(udp_bind_addr_for_remote(remote)).await?;
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

async fn read_vless_target_async<R>(reader: &mut R) -> io::Result<SocksTarget>
where
    R: AsyncRead + Unpin,
{
    let mut port = [0u8; 2];
    reader.read_exact(&mut port).await?;
    let port = u16::from_be_bytes(port);
    let host = match read_u8_async(reader).await? {
        ATYP_IPV4 => {
            let mut bytes = [0u8; 4];
            reader.read_exact(&mut bytes).await?;
            Ipv4Addr::from(bytes).to_string()
        }
        ATYP_DOMAIN => {
            let len = read_u8_async(reader).await?;
            read_string_async(reader, usize::from(len)).await?
        }
        ATYP_IPV6 => {
            let mut bytes = [0u8; 16];
            reader.read_exact(&mut bytes).await?;
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

async fn connect_target_async(
    target: &SocksTarget,
    timeout: Duration,
) -> io::Result<tokio::net::TcpStream> {
    crate::dns::connect_tcp_tokio(&target.host, target.port, timeout).await
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
        if flow != FLOW_XTLS_RPRX_VISION {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                format!("vless outbound flow {flow} is not supported"),
            ));
        }
        if outbound.tls.is_none() {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "vless outbound flow is supported only with tls",
            ));
        }
    }
    let network = outbound_transport_network(outbound).to_ascii_lowercase();
    if !flow.is_empty() && network != "tcp" {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "vless outbound flow is supported only on tcp transport",
        ));
    }
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
    if network == "grpc" {
        return connect_vless_grpc_tcp_outbound(outbound, &server, &user_id, flow, target, timeout);
    }
    if matches!(network.as_str(), "h2" | "http") {
        return connect_vless_h2_tcp_outbound(outbound, &server, &user_id, flow, target, timeout);
    }
    if network == "quic" {
        return connect_vless_quic_tcp_outbound(outbound, &server, &user_id, flow, target, timeout);
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

fn connect_vless_h2_tcp_outbound(
    outbound: &OutboundConfig,
    server: &SocksTarget,
    user_id: &[u8; 16],
    flow: &str,
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
    write_vless_tcp_request(&mut h2, user_id, flow, target)?;
    h2.flush()?;
    read_vless_response_header(&mut h2)?;
    local_bridge_for_http2(h2)
}

fn connect_vless_quic_tcp_outbound(
    outbound: &OutboundConfig,
    server: &SocksTarget,
    user_id: &[u8; 16],
    flow: &str,
    target: &SocksTarget,
    timeout: Duration,
) -> io::Result<TcpStream> {
    let mut quic = connect_quic_client_stream(
        server,
        timeout,
        outbound.tls.as_ref(),
        outbound.transport.as_ref(),
    )?;
    write_vless_tcp_request(&mut quic, user_id, flow, target)?;
    read_vless_response_header(&mut quic)?;
    Ok(quic)
}

fn connect_vless_grpc_tcp_outbound(
    outbound: &OutboundConfig,
    server: &SocksTarget,
    user_id: &[u8; 16],
    flow: &str,
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
    write_vless_tcp_request(&mut grpc, user_id, flow, target)?;
    grpc.flush()?;
    read_vless_response_header(&mut grpc)?;
    grpc.set_nonblocking(true);
    local_bridge_for_grpc(grpc)
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
    let use_vision = flow == FLOW_XTLS_RPRX_VISION;
    let user_id = *user_id;

    let _ = spawn_native_blocking_relay(move || {
        if use_vision {
            let _ = tls_stream.sock.set_nonblocking(true);
            let _ = relay_plain_to_vless_vision(local_plain, tls_stream, user_id);
        } else {
            let _ = relay_plain_to_tls(local_plain, tls_stream);
        };
    })?;

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

async fn resolve_udp_target_async(target: &SocksTarget) -> io::Result<SocketAddr> {
    crate::dns::resolve_socket_addr_tokio(&target.host, target.port, Duration::from_secs(5)).await
}

fn read_vless_udp_payload<R: Read>(reader: &mut R) -> io::Result<Vec<u8>> {
    let mut len = [0u8; 2];
    reader.read_exact(&mut len)?;
    let len = u16::from_be_bytes(len) as usize;
    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload)?;
    Ok(payload)
}

async fn read_vless_udp_payload_async<R>(reader: &mut R) -> io::Result<Vec<u8>>
where
    R: AsyncRead + Unpin,
{
    let mut len = [0u8; 2];
    reader.read_exact(&mut len).await?;
    let len = u16::from_be_bytes(len) as usize;
    let mut payload = vec![0u8; len];
    reader.read_exact(&mut payload).await?;
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

async fn write_vless_udp_payload_async<W>(writer: &mut W, payload: &[u8]) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    if payload.len() > u16::MAX as usize {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "vless udp payload is too large",
        ));
    }
    writer
        .write_all(&(payload.len() as u16).to_be_bytes())
        .await?;
    writer.write_all(payload).await
}

async fn recv_udp_response_async(
    udp: &tokio::net::UdpSocket,
    response: &mut [u8],
    timeout: Duration,
) -> io::Result<(usize, SocketAddr)> {
    let mut resets = 0usize;
    loop {
        match tokio::time::timeout(timeout, udp.recv_from(response)).await {
            Ok(Ok(result)) => return Ok(result),
            Ok(Err(error)) if error.kind() == io::ErrorKind::ConnectionReset => {
                resets += 1;
                if resets <= 256 {
                    continue;
                }
                return Err(error);
            }
            Ok(Err(error)) => return Err(error),
            Err(_) => {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "udp response timed out",
                ));
            }
        }
    }
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

fn relay_plain_to_vless_vision<S>(
    mut plain: TcpStream,
    mut remote: S,
    user_id: [u8; 16],
) -> io::Result<()>
where
    S: Read + Write,
{
    plain.set_nonblocking(true)?;

    let mut upload_done = false;
    let mut download_done = false;
    let mut upload_buffer = [0u8; 16 * 1024];
    let mut download_buffer = [0u8; 16 * 1024];
    let mut decode_buffer = [0u8; 16 * 1024];
    let mut vision_encoder = VisionEncoder::new(user_id);
    let mut vision_decoder = VisionDecoder::new(user_id);

    while !upload_done || !download_done {
        let mut progressed = false;

        if !upload_done {
            match plain.read(&mut upload_buffer) {
                Ok(0) => {
                    upload_done = true;
                    let _ = remote.flush();
                    progressed = true;
                }
                Ok(read) => {
                    let encoded = vision_encoder.encode(&upload_buffer[..read]);
                    write_all_wait_tls_bridge(&mut remote, &encoded)?;
                    progressed = true;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(_) => {
                    upload_done = true;
                    let _ = remote.flush();
                    progressed = true;
                }
            }
        }

        if !download_done {
            let decoded = vision_decoder.read_decoded(&mut download_buffer)?;
            if decoded > 0 {
                write_all_wait_tls_bridge(&mut plain, &download_buffer[..decoded])?;
                progressed = true;
            } else {
                match remote.read(&mut decode_buffer) {
                    Ok(0) => {
                        vision_decoder.finish();
                        let decoded = vision_decoder.read_decoded(&mut download_buffer)?;
                        if decoded > 0 {
                            write_all_wait_tls_bridge(&mut plain, &download_buffer[..decoded])?;
                        }
                        download_done = true;
                        let _ = plain.shutdown(Shutdown::Write);
                        progressed = true;
                    }
                    Ok(read) => {
                        vision_decoder.push(&decode_buffer[..read]);
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
        }

        if !progressed {
            thread::sleep(Duration::from_millis(1));
        }
    }

    let _ = plain.shutdown(Shutdown::Both);
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
                    write_all_wait_tls_bridge(&mut grpc, &upload_buffer[..read])?;
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

fn traffic_flush_callback(
    traffic: SharedTrafficRegistry,
    node_tag: String,
    user_uuid: String,
    user_id: Option<u64>,
    upload: bool,
    mut client_ip: Option<IpAddr>,
) -> impl FnMut(u64) {
    let mut pending = 0u64;
    let mut flushed_once = false;
    move |bytes| {
        pending = pending.saturating_add(bytes);
        if pending == 0 {
            return;
        }
        if flushed_once && bytes != 0 && pending < ASYNC_TRAFFIC_FLUSH_BYTES {
            return;
        }
        if upload {
            traffic.add_with_user_id(
                node_tag.clone(),
                user_uuid.clone(),
                user_id,
                pending,
                0,
                client_ip.take(),
            );
        } else {
            traffic.add_with_user_id(
                node_tag.clone(),
                user_uuid.clone(),
                user_id,
                0,
                pending,
                None,
            );
        }
        pending = 0;
        flushed_once = true;
    }
}

async fn relay_tcp_streams_async(
    client: tokio::net::TcpStream,
    remote: tokio::net::TcpStream,
    limiter: Option<Arc<BandwidthLimiter>>,
    mut on_upload: impl FnMut(u64) + Send + 'static,
    mut on_download: impl FnMut(u64) + Send + 'static,
) -> io::Result<(u64, u64)> {
    let upload_client_shutdown = clone_tokio_tcp_stream_for_shutdown(&client)?;
    let upload_remote_shutdown = clone_tokio_tcp_stream_for_shutdown(&remote)?;
    let download_client_shutdown = clone_tokio_tcp_stream_for_shutdown(&client)?;
    let download_remote_shutdown = clone_tokio_tcp_stream_for_shutdown(&remote)?;
    let (mut client_read, mut client_write) = client.into_split();
    let (mut remote_read, mut remote_write) = remote.into_split();
    let upload_limiter = limiter.clone();
    let upload = tokio::spawn(async move {
        let mut total = 0u64;
        let mut buffer = [0u8; 16 * 1024];
        loop {
            let read_result = if let Some(limiter) = upload_limiter.as_deref() {
                tokio::select! {
                    read = client_read.read(&mut buffer) => read,
                    _ = wait_limiter_revoke(limiter) => {
                        on_upload(0);
                        let _ = remote_write.shutdown().await;
                        close_tcp_pair(&upload_client_shutdown, &upload_remote_shutdown);
                        return Ok::<u64, io::Error>(total);
                    }
                }
            } else {
                client_read.read(&mut buffer).await
            };
            let read = match read_result {
                Ok(read) => read,
                Err(error) => {
                    on_upload(0);
                    let _ = remote_write.shutdown().await;
                    close_tcp_pair(&upload_client_shutdown, &upload_remote_shutdown);
                    return Err(error);
                }
            };
            if read == 0 {
                on_upload(0);
                let _ = remote_write.shutdown().await;
                close_tcp_pair(&upload_client_shutdown, &upload_remote_shutdown);
                return Ok::<u64, io::Error>(total);
            }
            if let Some(limiter) = upload_limiter.as_deref() {
                if !limiter.wait_for_async(read).await {
                    on_upload(0);
                    let _ = remote_write.shutdown().await;
                    close_tcp_pair(&upload_client_shutdown, &upload_remote_shutdown);
                    return Ok::<u64, io::Error>(total);
                }
            }
            if let Err(error) =
                async_write_all_with_timeout(&mut remote_write, &buffer[..read]).await
            {
                on_upload(0);
                let _ = remote_write.shutdown().await;
                close_tcp_pair(&upload_client_shutdown, &upload_remote_shutdown);
                return Err(error);
            }
            on_upload(read as u64);
            total = total.saturating_add(read as u64);
        }
    });
    let download = tokio::spawn(async move {
        let mut total = 0u64;
        let mut buffer = [0u8; 16 * 1024];
        loop {
            let read_result = if let Some(limiter) = limiter.as_deref() {
                tokio::select! {
                    read = remote_read.read(&mut buffer) => read,
                    _ = wait_limiter_revoke(limiter) => {
                        on_download(0);
                        let _ = client_write.shutdown().await;
                        close_tcp_pair(&download_client_shutdown, &download_remote_shutdown);
                        return Ok::<u64, io::Error>(total);
                    }
                }
            } else {
                remote_read.read(&mut buffer).await
            };
            let read = match read_result {
                Ok(read) => read,
                Err(error) => {
                    on_download(0);
                    let _ = client_write.shutdown().await;
                    close_tcp_pair(&download_client_shutdown, &download_remote_shutdown);
                    return Err(error);
                }
            };
            if read == 0 {
                on_download(0);
                let _ = client_write.shutdown().await;
                close_tcp_pair(&download_client_shutdown, &download_remote_shutdown);
                return Ok::<u64, io::Error>(total);
            }
            if let Some(limiter) = limiter.as_deref() {
                if !limiter.wait_for_async(read).await {
                    on_download(0);
                    let _ = client_write.shutdown().await;
                    close_tcp_pair(&download_client_shutdown, &download_remote_shutdown);
                    return Ok::<u64, io::Error>(total);
                }
            }
            if let Err(error) =
                async_write_all_with_timeout(&mut client_write, &buffer[..read]).await
            {
                on_download(0);
                let _ = client_write.shutdown().await;
                close_tcp_pair(&download_client_shutdown, &download_remote_shutdown);
                return Err(error);
            }
            on_download(read as u64);
            total = total.saturating_add(read as u64);
        }
    });
    let (upload, download) = tokio::try_join!(upload, download).map_err(|error| {
        io::Error::new(io::ErrorKind::Other, format!("relay task failed: {error}"))
    })?;
    Ok((upload?, download?))
}

fn clone_tokio_tcp_stream_for_shutdown(socket: &tokio::net::TcpStream) -> io::Result<TcpStream> {
    Ok(TcpStream::from(SockRef::from(socket).try_clone()?))
}

fn close_tcp_pair(left: &TcpStream, right: &TcpStream) {
    let _ = left.shutdown(Shutdown::Both);
    let _ = right.shutdown(Shutdown::Both);
}

async fn async_write_all_with_timeout<W>(writer: &mut W, buffer: &[u8]) -> io::Result<()>
where
    W: AsyncWrite + Unpin,
{
    match tokio::time::timeout(vless_async_relay_io_timeout(), writer.write_all(buffer)).await {
        Ok(result) => result,
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "vless relay write timed out",
        )),
    }
}

fn vless_async_relay_io_timeout() -> Duration {
    let seconds = env::var(VLESS_ASYNC_RELAY_IO_TIMEOUT_SECS_ENV)
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|seconds| *seconds > 0)
        .unwrap_or(DEFAULT_VLESS_ASYNC_RELAY_IO_TIMEOUT_SECS);
    Duration::from_secs(seconds)
}

async fn wait_limiter_revoke(limiter: &BandwidthLimiter) {
    limiter.wait_revoked().await;
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
    let upload_task = spawn_native_blocking_relay(move || {
        let mut vision_reader = VisionReader::new(reader, user_id);
        let bytes = match upload_limiter.as_deref() {
            Some(limiter) => {
                copy_count_best_effort_limited(&mut vision_reader, &mut remote_write, Some(limiter))
            }
            None => copy_count_best_effort(&mut vision_reader, &mut remote_write),
        };
        let _ = remote_write.shutdown(Shutdown::Write);
        bytes
    })?;

    let mut vision_writer = VisionWriter::new(writer, user_id);
    let download = match limiter.as_deref() {
        Some(limiter) => {
            copy_count_best_effort_limited(&mut remote_read, &mut vision_writer, Some(limiter))
        }
        None => copy_count_best_effort(&mut remote_read, &mut vision_writer),
    };
    let upload = join_native_blocking_relay(upload_task, "vision upload relay task panicked")?;

    Ok((upload, download))
}

fn relay_tls_vision_stream<S>(
    mut client: TlsConnection<S>,
    mut remote: TcpStream,
    user_id: [u8; 16],
    limiter: Option<Arc<BandwidthLimiter>>,
) -> io::Result<(u64, u64)>
where
    S: TlsSocket + RawTcpStreamAccess,
{
    let drain_after_client_eof = vless_vision_drain_after_client_eof();
    client.set_nonblocking(true)?;
    remote.set_nonblocking(true)?;

    let mut upload = 0u64;
    let mut download = 0u64;
    let mut upload_done = false;
    let mut download_done = false;
    let mut client_eof_at = None::<Instant>;
    let mut client_buffer = [0u8; 16 * 1024];
    let mut remote_buffer = [0u8; 16 * 1024];
    let mut vision_decoder = VisionDecoder::new(user_id);
    let mut vision_encoder = VisionEncoder::new(user_id);
    let mut uplink_direct = false;
    let mut downlink_direct = false;
    let mut idle_rounds = 0u8;
    let trace = vless_trace_enabled();

    if trace {
        eprintln!("keli-core-rs vless trace: vision relay start");
    }

    while !upload_done || !download_done {
        if limiter
            .as_deref()
            .map(BandwidthLimiter::is_revoked)
            .unwrap_or(false)
        {
            let _ = client.shutdown(Shutdown::Both);
            let _ = remote.shutdown(Shutdown::Both);
            break;
        }
        let mut progressed = false;

        if !upload_done {
            if uplink_direct {
                match client.raw_read(&mut client_buffer) {
                    Ok(0) => {
                        upload_done = true;
                        client_eof_at = Some(Instant::now());
                        let _ = remote.shutdown(Shutdown::Write);
                        progressed = true;
                    }
                    Ok(read) => {
                        if trace {
                            eprintln!(
                                "keli-core-rs vless trace: vision upload raw={} first={:02x?}",
                                read,
                                &client_buffer[..read.min(8)]
                            );
                        }
                        if let Some(limiter) = limiter.as_deref() {
                            if !limiter.wait_for(read) {
                                upload_done = true;
                                download_done = true;
                                let _ = client.shutdown(Shutdown::Both);
                                let _ = remote.shutdown(Shutdown::Both);
                                continue;
                            }
                        }
                        write_all_wait_or_cancel(&mut remote, &client_buffer[..read], || {
                            vless_vision_client_peer_closed(&client)
                        })?;
                        upload = upload.saturating_add(read as u64);
                        progressed = true;
                    }
                    Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                    Err(_) => {
                        upload_done = true;
                        client_eof_at = Some(Instant::now());
                        let _ = remote.shutdown(Shutdown::Write);
                        progressed = true;
                    }
                }
            } else {
                let decoded = vision_decoder.read_decoded(&mut client_buffer)?;
                if decoded > 0 {
                    if trace {
                        eprintln!(
                            "keli-core-rs vless trace: vision upload decoded={} first={:02x?}",
                            decoded,
                            &client_buffer[..decoded.min(8)]
                        );
                    }
                    if let Some(limiter) = limiter.as_deref() {
                        if !limiter.wait_for(decoded) {
                            upload_done = true;
                            download_done = true;
                            let _ = client.shutdown(Shutdown::Both);
                            let _ = remote.shutdown(Shutdown::Both);
                            continue;
                        }
                    }
                    write_all_wait_or_cancel(&mut remote, &client_buffer[..decoded], || {
                        vless_vision_client_peer_closed(&client)
                    })?;
                    upload = upload.saturating_add(decoded as u64);
                    progressed = true;
                    if vision_decoder.is_direct_copy() {
                        uplink_direct = true;
                        if trace {
                            eprintln!("keli-core-rs vless trace: vision upload switched direct");
                        }
                    }
                } else {
                    if vision_decoder.is_direct_copy() {
                        uplink_direct = true;
                        if trace {
                            eprintln!("keli-core-rs vless trace: vision upload switched direct");
                        }
                        continue;
                    }
                    match client.read(&mut client_buffer) {
                        Ok(0) => {
                            upload_done = true;
                            client_eof_at = Some(Instant::now());
                            vision_decoder.finish();
                            let _ = remote.shutdown(Shutdown::Write);
                            progressed = true;
                        }
                        Ok(read) => {
                            vision_decoder.push(&client_buffer[..read]);
                            progressed = true;
                            if vision_decoder.is_direct_copy() {
                                uplink_direct = true;
                                if trace {
                                    eprintln!(
                                        "keli-core-rs vless trace: vision upload switched direct"
                                    );
                                }
                            }
                        }
                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                        Err(_) => {
                            upload_done = true;
                            client_eof_at = Some(Instant::now());
                            let _ = remote.shutdown(Shutdown::Write);
                            progressed = true;
                        }
                    }
                }
            }
        }

        if !download_done {
            match remote.read(&mut remote_buffer) {
                Ok(0) => {
                    download_done = true;
                    upload_done = true;
                    let _ = client.shutdown(Shutdown::Both);
                    let _ = remote.shutdown(Shutdown::Both);
                    progressed = true;
                }
                Ok(read) => {
                    if trace {
                        eprintln!(
                            "keli-core-rs vless trace: vision download read={} first={:02x?}",
                            read,
                            &remote_buffer[..read.min(8)]
                        );
                    }
                    if let Some(limiter) = limiter.as_deref() {
                        if !limiter.wait_for(read) {
                            download_done = true;
                            upload_done = true;
                            let _ = client.shutdown(Shutdown::Both);
                            let _ = remote.shutdown(Shutdown::Both);
                            continue;
                        }
                    }
                    if downlink_direct {
                        client.raw_write_all_wait(&remote_buffer[..read])?;
                    } else {
                        let frame = vision_encoder.encode(&remote_buffer[..read]);
                        client.write_plain_all_wait(&frame)?;
                        if vision_encoder.is_direct_copy() {
                            downlink_direct = true;
                            if trace {
                                eprintln!(
                                    "keli-core-rs vless trace: vision download switched direct"
                                );
                            }
                        }
                    }
                    download = download.saturating_add(read as u64);
                    progressed = true;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(_) => {
                    download_done = true;
                    upload_done = true;
                    let _ = client.shutdown(Shutdown::Both);
                    let _ = remote.shutdown(Shutdown::Both);
                    progressed = true;
                }
            }
        }

        if client_eof_at
            .map(|instant| instant.elapsed() >= drain_after_client_eof)
            .unwrap_or(false)
        {
            let _ = client.shutdown(Shutdown::Both);
            let _ = remote.shutdown(Shutdown::Both);
            break;
        }

        if uplink_direct
            && downlink_direct
            && vision_decoder.is_drained()
            && client.raw_tcp_stream_ready()
        {
            #[cfg(test)]
            VLESS_VISION_RAW_RELAY_SWITCHES.fetch_add(1, Ordering::Relaxed);
            if trace {
                eprintln!("keli-core-rs vless trace: vision switched to raw tcp relay");
            }
            client.set_nonblocking(false)?;
            remote.set_nonblocking(false)?;
            let raw_client = client.into_socket().into_raw_tcp_stream();
            let (raw_upload, raw_download) = match limiter.clone() {
                Some(limiter) => relay_tcp_limited(raw_client, remote, limiter)?,
                None => relay_tcp_fast_unlimited_close_on_eof(raw_client, remote)?,
            };
            upload = upload.saturating_add(raw_upload);
            download = download.saturating_add(raw_download);
            if trace {
                eprintln!(
                    "keli-core-rs vless trace: vision raw tcp relay finish upload={} download={}",
                    upload, download
                );
            }
            return Ok((upload, download));
        }

        if !progressed {
            if !upload_done && vless_vision_client_peer_closed(&client) {
                upload_done = true;
                client_eof_at = Some(Instant::now());
                let _ = remote.shutdown(Shutdown::Write);
                if drain_after_client_eof.is_zero() {
                    let _ = client.shutdown(Shutdown::Both);
                    let _ = remote.shutdown(Shutdown::Both);
                    break;
                }
                continue;
            }
            relay_vision_wait_readable(
                &client,
                &remote,
                !upload_done,
                !download_done,
                &mut idle_rounds,
            );
        } else {
            idle_rounds = 0;
        }
    }

    let _ = client.shutdown(Shutdown::Both);
    let _ = remote.shutdown(Shutdown::Both);
    if trace {
        eprintln!(
            "keli-core-rs vless trace: vision relay finish upload={} download={}",
            upload, download
        );
    }
    Ok((upload, download))
}

fn vless_vision_client_peer_closed<S>(client: &TlsConnection<S>) -> bool
where
    S: TlsSocket,
{
    match client.peer_closed() {
        Ok(closed) => closed,
        Err(error) if is_stream_closed(&error) => true,
        Err(_) => false,
    }
}

fn vless_trace_enabled() -> bool {
    env::var_os(VLESS_TRACE_ENV).is_some()
}

fn trace_vless(message: impl FnOnce() -> String) {
    if vless_trace_enabled() {
        eprintln!("keli-core-rs vless trace: {}", message());
    }
}

fn relay_vision_wait_readable<S>(
    _client: &TlsConnection<S>,
    _remote: &TcpStream,
    wait_client: bool,
    wait_remote: bool,
    idle_rounds: &mut u8,
) where
    S: TlsSocket,
{
    if wait_client || wait_remote {
        relay_idle_sleep(idle_rounds);
    }
}

fn relay_idle_sleep(idle_rounds: &mut u8) {
    let timeout_ms = relay_sleep_idle_timeout_ms(idle_rounds);
    thread::sleep(Duration::from_millis(timeout_ms as u64));
}

fn relay_sleep_idle_timeout_ms(idle_rounds: &mut u8) -> i32 {
    const BACKOFF_MS: [i32; 5] = [1, 2, 4, 8, 16];
    let idx = usize::from((*idle_rounds).min((BACKOFF_MS.len() - 1) as u8));
    *idle_rounds = idle_rounds
        .saturating_add(1)
        .min((BACKOFF_MS.len() - 1) as u8);
    BACKOFF_MS[idx]
}

fn vless_vision_drain_after_client_eof() -> Duration {
    const DEFAULT_DRAIN_MS: u64 = 250;
    const MAX_DRAIN_MS: u64 = 30_000;
    const MAX_DRAIN_SECS: u64 = 30;
    if let Some(milliseconds) = env::var(VLESS_VISION_DRAIN_MS_ENV)
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
    {
        return Duration::from_millis(milliseconds.min(MAX_DRAIN_MS));
    }
    env::var(VLESS_VISION_DRAIN_SECS_ENV)
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .map(|value| value.min(MAX_DRAIN_SECS))
        .map(Duration::from_secs)
        .unwrap_or_else(|| Duration::from_millis(DEFAULT_DRAIN_MS))
}

fn write_all_wait_or_cancel(
    writer: &mut TcpStream,
    mut input: &[u8],
    mut should_cancel: impl FnMut() -> bool,
) -> io::Result<()> {
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
                if should_cancel() {
                    return Err(io::Error::new(
                        io::ErrorKind::ConnectionAborted,
                        "peer closed while waiting for socket write",
                    ));
                }
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

async fn read_u8_async<R>(reader: &mut R) -> io::Result<u8>
where
    R: AsyncRead + Unpin,
{
    let mut byte = [0u8; 1];
    reader.read_exact(&mut byte).await?;
    Ok(byte[0])
}

fn read_string<R: Read>(reader: &mut R, len: usize) -> io::Result<String> {
    let mut bytes = vec![0u8; len];
    reader.read_exact(&mut bytes)?;
    String::from_utf8(bytes)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "invalid utf-8"))
}

async fn read_string_async<R>(reader: &mut R, len: usize) -> io::Result<String>
where
    R: AsyncRead + Unpin,
{
    let mut bytes = vec![0u8; len];
    reader.read_exact(&mut bytes).await?;
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
    use std::io::{self, Cursor, Read, Write};
    use std::net::{Shutdown, TcpListener, TcpStream, UdpSocket};
    use std::path::PathBuf;
    use std::sync::mpsc;
    use std::sync::{
        atomic::{AtomicBool, Ordering},
        Arc,
    };
    use std::thread;
    use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
    use crate::user::{CoreUser, CoreUserDelta};
    use crate::vision::{VisionEncoder, VisionReader, VisionWriter};
    use crate::vless::{compact_uuid, connect_vless_tcp_outbound, VlessServer, VlessServerConfig};
    use crate::websocket::{accept_websocket, accept_websocket_tls};
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

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
            std::io::Read::read(&mut self.input, buf)
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

    #[test]
    fn classifies_vless_connection_errors_with_low_cardinality_reasons() {
        assert_eq!(
            super::classify_vless_connection_error(&io::Error::new(
                io::ErrorKind::PermissionDenied,
                "unknown vless user",
            )),
            "auth_failed"
        );
        assert_eq!(
            super::classify_vless_connection_error(&io::Error::new(
                io::ErrorKind::TimedOut,
                "tcp connect timed out",
            )),
            "upstream_timeout"
        );
        assert_eq!(
            super::classify_vless_connection_error(&io::Error::new(
                io::ErrorKind::PermissionDenied,
                "private ip blocked by dns guard",
            )),
            "dns_private_blocked"
        );
        assert_eq!(
            super::classify_vless_connection_error(&io::Error::new(
                io::ErrorKind::ConnectionReset,
                "Connection reset by peer",
            )),
            "client_closed"
        );
    }

    fn server() -> VlessServer {
        server_with_flow("")
    }

    fn server_with_user(user: CoreUser) -> VlessServer {
        VlessServer::new(VlessServerConfig {
            node_tag: "panel|vless|1".to_string(),
            listen: "127.0.0.1:0".parse().expect("listen addr"),
            users: vec![user],
            routes: Vec::new(),
            flow: String::new(),
            connect_timeout: Duration::from_secs(3),
        })
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

    #[test]
    fn server_clone_does_not_duplicate_full_user_list() {
        let server = VlessServer::new(VlessServerConfig {
            node_tag: "panel|vless|1".to_string(),
            listen: "127.0.0.1:0".parse().expect("listen addr"),
            users: vec![user()],
            routes: vec![RouteRule {
                action: RouteAction::Block,
                targets: vec!["domain:blocked.example".to_string()],
                outbound: None,
            }],
            flow: String::new(),
            connect_timeout: Duration::from_secs(3),
        });

        assert_eq!(server.users.len(), 1);
        assert!(server.config.users.is_empty());
        assert!(server.config.routes.is_empty());
        assert!(server.clone().config.users.is_empty());
        assert!(server.clone().config.routes.is_empty());
        assert!(matches!(
            server.router.decide("blocked.example"),
            crate::RouteDecision::Block
        ));
    }

    #[test]
    fn apply_user_delta_updates_vless_users() {
        let server = server();
        let mut updated = user();
        updated.speed_limit = 321;
        updated.device_limit = 4;

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
            .get(&compact_uuid(&updated.uuid))
            .expect("updated vless user should remain active");
        assert_eq!(user.speed_limit, 321);
        assert_eq!(user.device_limit, 4);
        assert!(server.users.get(&compact_uuid(&user_b().uuid)).is_some());

        let result = server.apply_user_delta(&CoreUserDelta {
            deleted: vec![updated.uuid.clone()],
            ..CoreUserDelta::default()
        });

        assert_eq!(result.deleted, 1);
        assert_eq!(result.active_users, 1);
        assert!(server.users.get(&compact_uuid(&updated.uuid)).is_none());
        assert!(server.users.get(&compact_uuid(&user_b().uuid)).is_some());
    }

    #[test]
    fn apply_user_delta_changes_vless_auth_without_rebinding_listener() {
        let echo = TcpListener::bind("127.0.0.1:0").expect("echo bind");
        let echo_addr = echo.local_addr().expect("echo addr");
        let echo_thread = thread::spawn(move || {
            for _ in 0..2 {
                let (mut stream, _) = echo.accept().expect("echo accept");
                let mut buffer = [0u8; 1];
                let _ = stream.read(&mut buffer);
            }
        });

        let server = server();
        let listener = server.bind().expect("vless bind");
        listener
            .set_nonblocking(true)
            .expect("vless listener nonblocking");
        let vless_addr = listener.local_addr().expect("vless addr");
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
                    Err(error) => panic!("vless accept: {error}"),
                }
            }
            for worker in workers {
                worker.join().expect("vless worker");
            }
        });

        assert!(vless_auth_succeeds(vless_addr, [0x11; 16], echo_addr));

        let result = server.apply_user_delta(&CoreUserDelta {
            added: vec![user_b()],
            deleted: vec![user().uuid],
            ..CoreUserDelta::default()
        });

        assert_eq!(result.added, 1);
        assert_eq!(result.deleted, 1);
        assert_eq!(result.active_users, 1);
        assert!(!vless_auth_succeeds(vless_addr, [0x11; 16], echo_addr));
        assert!(vless_auth_succeeds(vless_addr, [0x22; 16], echo_addr));

        stop.store(true, Ordering::SeqCst);
        let _ = TcpStream::connect(vless_addr);
        server_thread.join().expect("vless server thread");
        echo_thread.join().expect("echo thread");
    }

    #[test]
    fn deleting_vless_user_stops_existing_tcp_relay_on_next_payload_and_reports_tail() {
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
        let listener = server.bind().expect("vless bind");
        let vless_addr = listener.local_addr().expect("vless addr");
        let server_clone = server.clone();
        let server_thread = thread::spawn(move || {
            let (stream, _) = listener.accept().expect("vless accept");
            server_clone.handle_tcp_client(stream)
        });

        let mut client = TcpStream::connect(vless_addr).expect("client connect");
        client
            .set_read_timeout(Some(Duration::from_secs(1)))
            .expect("client read timeout");
        client
            .set_write_timeout(Some(Duration::from_secs(1)))
            .expect("client write timeout");
        client
            .write_all(&vless_request(echo_addr))
            .expect("vless request");
        let mut header = [0u8; 2];
        client.read_exact(&mut header).expect("vless response");
        assert_eq!(header, [super::VERSION, 0x00]);
        client.write_all(b"x").expect("first write");
        let mut echoed = [0u8; 1];
        client.read_exact(&mut echoed).expect("first echo");
        assert_eq!(echoed, *b"x");

        let result = server.apply_user_delta(&CoreUserDelta {
            deleted: vec![user().uuid],
            ..CoreUserDelta::default()
        });
        assert_eq!(result.deleted, 1);

        let _ = client.write_all(b"y");
        assert!(
            !second_payload_rx
                .recv_timeout(Duration::from_secs(2))
                .expect("echo result"),
            "deleted user's existing VLESS relay should stop forwarding new payload"
        );
        drop(client);
        server_thread
            .join()
            .expect("server thread")
            .expect("serve once");
        echo_thread.join().expect("echo thread");

        let records = server.drain_traffic(1);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].node_tag, "panel|vless|1");
        assert_eq!(records[0].user_uuid, user().uuid);
        assert_eq!(records[0].user_id, Some(1));
        assert_eq!(records[0].upload, 1);
        assert_eq!(records[0].download, 1);
    }

    fn vless_request(target: std::net::SocketAddr) -> Vec<u8> {
        vless_request_with_flow(target, "")
    }

    fn vless_udp_request(target: std::net::SocketAddr) -> Vec<u8> {
        vless_request_with_flow_and_command(target, "", 0x02)
    }

    fn vless_auth_succeeds(
        server_addr: std::net::SocketAddr,
        user_id: [u8; 16],
        target: std::net::SocketAddr,
    ) -> bool {
        let Ok(mut stream) = TcpStream::connect(server_addr) else {
            return false;
        };
        let _ = stream.set_read_timeout(Some(Duration::from_secs(3)));
        let _ = stream.set_write_timeout(Some(Duration::from_secs(3)));
        if stream
            .write_all(&vless_request_for_user_with_flow_and_command(
                user_id, target, "", 0x01,
            ))
            .is_err()
        {
            return false;
        }
        let mut header = [0u8; 2];
        stream.read_exact(&mut header).is_ok() && header == [super::VERSION, 0x00]
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

    fn tls_client_hello_like_record() -> Vec<u8> {
        vec![0x16, 0x03, 0x03, 0x00, 0x02, 0x01, 0x00]
    }

    fn tls_application_data_record(payload: &[u8]) -> Vec<u8> {
        let mut record = Vec::with_capacity(5 + payload.len());
        record.extend_from_slice(&[
            0x17,
            0x03,
            0x03,
            (payload.len() >> 8) as u8,
            payload.len() as u8,
        ]);
        record.extend_from_slice(payload);
        record
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
    fn replace_users_updates_active_vless_bandwidth_limiter() {
        let server = server();
        let mut limited = user();
        limited.speed_limit = 8;
        let limiter = server
            .bandwidth
            .limiter_for(Some(&limited))
            .expect("limited user");

        limited.speed_limit = 16;
        server.replace_users(vec![limited]);

        assert_eq!(limiter.bytes_per_second(), 2 * 1024 * 1024);
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
            alter_id: None,
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
            alter_id: None,
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
    fn vless_vision_tls_outbound_encodes_and_decodes_flow_stream() {
        let cert = test_cert("vless-vision-outbound");
        let proxy = TcpListener::bind("127.0.0.1:0").expect("proxy bind");
        let proxy_addr = proxy.local_addr().expect("proxy addr");
        let acceptor =
            TlsAcceptor::from_files(&cert.cert_path, &cert.key_path, &[]).expect("tls acceptor");
        let proxy_thread = thread::spawn(move || {
            let (stream, _) = proxy.accept().expect("proxy accept");
            let mut stream = acceptor.accept(stream).expect("tls accept");
            let request = server_with_flow(super::FLOW_XTLS_RPRX_VISION)
                .read_request(&mut stream)
                .expect("vless request");
            assert_eq!(request.user_uuid, "11111111-1111-1111-1111-111111111111");
            assert_eq!(request.flow, super::FLOW_XTLS_RPRX_VISION);
            assert_eq!(request.target.host, "example.com");
            assert_eq!(request.target.port, 443);

            stream
                .write_all(&[super::VERSION, 0x00])
                .expect("response header");
            let mut reader = VisionReader::new(&mut stream, [0x11; 16]);
            let mut payload = [0u8; 4];
            reader.read_exact(&mut payload).expect("vision payload");
            assert_eq!(&payload, b"ping");
            let mut writer = VisionWriter::new(&mut stream, [0x11; 16]);
            writer.write_all(b"pong").expect("vision response");
            writer.flush().expect("vision response flush");
        });
        let outbound = OutboundConfig {
            tag: "vless-out".to_string(),
            protocol: "vless".to_string(),
            method: Some(super::FLOW_XTLS_RPRX_VISION.to_string()),
            alter_id: None,
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
            alter_id: None,
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
                method: None,
                headers: Default::default(),
                ..OutboundTransportConfig::default()
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
            alter_id: None,
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
                method: None,
                headers: Default::default(),
                ..OutboundTransportConfig::default()
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
            alter_id: None,
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
                method: None,
                headers: Default::default(),
                ..OutboundTransportConfig::default()
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
    fn vless_h2_outbound_writes_request_and_relays_stream() {
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
                handled_tx.send(()).expect("handler notification");
            });
            runtime
                .block_on(run_http2_listener(
                    listener,
                    server_stop,
                    "/vless".to_string(),
                    "PUT".to_string(),
                    None,
                    handler,
                ))
                .expect("h2 listener");
        });
        let outbound = OutboundConfig {
            tag: "vless-out".to_string(),
            protocol: "vless".to_string(),
            method: None,
            alter_id: None,
            address: Some(proxy_addr.ip().to_string()),
            port: Some(proxy_addr.port()),
            username: Some("11111111-1111-1111-1111-111111111111".to_string()),
            password: None,
            tls: None,
            transport: Some(OutboundTransportConfig {
                network: "h2".to_string(),
                path: Some("/vless".to_string()),
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

        let mut stream = connect_vless_tcp_outbound(&outbound, &target, Duration::from_secs(2))
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
    fn vless_grpc_outbound_writes_request_and_relays_stream() {
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
            tag: "vless-out".to_string(),
            protocol: "vless".to_string(),
            method: None,
            alter_id: None,
            address: Some(proxy_addr.ip().to_string()),
            port: Some(proxy_addr.port()),
            username: Some("11111111-1111-1111-1111-111111111111".to_string()),
            password: None,
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

        let mut stream = connect_vless_tcp_outbound(&outbound, &target, Duration::from_secs(2))
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
            for _ in 0..2 {
                let mut bytes = [0u8; 4];
                stream.read_exact(&mut bytes).expect("echo read");
                stream.write_all(&bytes).expect("echo write");
            }
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
        client.write_all(b"pong").expect("client write payload");
        let mut echoed = [0u8; 4];
        client.read_exact(&mut echoed).expect("client read payload");
        assert_eq!(&echoed, b"pong");
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
        assert_eq!(records[0].user_id, Some(1));
        assert_eq!(records[0].upload, 8);
        assert_eq!(records[0].download, 8);
    }

    #[tokio::test]
    async fn proxies_async_tcp_and_records_user_traffic() {
        let echo = TcpListener::bind("127.0.0.1:0").expect("echo bind");
        let echo_addr = echo.local_addr().expect("echo addr");
        let echo_thread = thread::spawn(move || {
            let (mut stream, _) = echo.accept().expect("echo accept");
            for _ in 0..2 {
                let mut bytes = [0u8; 4];
                stream.read_exact(&mut bytes).expect("echo read");
                stream.write_all(&bytes).expect("echo write");
            }
        });

        let server = server();
        let listener = server.bind().expect("vless bind");
        listener
            .set_nonblocking(true)
            .expect("nonblocking listener");
        let vless_addr = listener.local_addr().expect("vless addr");
        let listener = tokio::net::TcpListener::from_std(listener).expect("tokio listener");
        let server_clone = server.clone();
        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("vless accept");
            server_clone.handle_tcp_client_async(stream).await
        });

        let mut client = tokio::net::TcpStream::connect(vless_addr)
            .await
            .expect("client connect");
        client
            .write_all(&vless_request(echo_addr))
            .await
            .expect("client request");
        let mut response = [0u8; 2];
        client
            .read_exact(&mut response)
            .await
            .expect("client response");
        assert_eq!(response, [0x00, 0x00]);

        client.write_all(b"ping").await.expect("client payload");
        let mut echoed = [0u8; 4];
        client.read_exact(&mut echoed).await.expect("client echo");
        assert_eq!(&echoed, b"ping");

        tokio::time::sleep(Duration::from_millis(20)).await;
        let partial = server.drain_traffic(1);
        assert_eq!(partial.len(), 1);
        assert_eq!(partial[0].upload, 4);
        assert_eq!(partial[0].download, 4);

        client.write_all(b"pong").await.expect("client payload");
        let mut echoed = [0u8; 4];
        client.read_exact(&mut echoed).await.expect("client echo");
        assert_eq!(&echoed, b"pong");
        drop(client);

        server_task.await.expect("server task").expect("serve once");
        echo_thread.join().expect("echo thread");

        let records = server.drain_traffic(1);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].node_tag, "panel|vless|1");
        assert_eq!(records[0].user_uuid, "11111111-1111-1111-1111-111111111111");
        assert_eq!(records[0].upload, 4);
        assert_eq!(records[0].download, 4);
    }

    #[tokio::test]
    async fn async_vless_tcp_unlimited_user_uses_fast_path_and_delete_closes_connection() {
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
        let listener = server.bind().expect("vless bind");
        listener
            .set_nonblocking(true)
            .expect("nonblocking listener");
        let vless_addr = listener.local_addr().expect("vless addr");
        let listener = tokio::net::TcpListener::from_std(listener).expect("tokio listener");
        let server_clone = server.clone();
        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("vless accept");
            server_clone.handle_tcp_client_async(stream).await
        });

        let mut client = tokio::net::TcpStream::connect(vless_addr)
            .await
            .expect("client connect");
        client
            .write_all(&vless_request(echo_addr))
            .await
            .expect("vless request");
        let mut header = [0u8; 2];
        client
            .read_exact(&mut header)
            .await
            .expect("vless response");
        assert_eq!(header, [super::VERSION, 0x00]);
        client.write_all(b"x").await.expect("first write");
        let mut echoed = [0u8; 1];
        client.read_exact(&mut echoed).await.expect("first echo");
        assert_eq!(echoed, *b"x");

        assert!(
            !server.bandwidth.has_limiter_for(&user().uuid),
            "unlimited VLESS TCP should not create limiter hot-path state"
        );
        assert_eq!(server.bandwidth.active_connection_count(&user().uuid), 1);

        let result = server.apply_user_delta(&CoreUserDelta {
            deleted: vec![user().uuid],
            ..CoreUserDelta::default()
        });
        assert_eq!(result.deleted, 1);

        let _ = client.write_all(b"y").await;
        assert!(
            !second_payload_rx
                .recv_timeout(Duration::from_secs(2))
                .expect("echo result"),
            "deleted unlimited user's existing async VLESS relay should stop forwarding"
        );
        drop(client);
        let result = server_task.await.expect("server task");
        if let Err(error) = result {
            assert!(
                super::is_stream_closed(&error),
                "unexpected relay error: {error}"
            );
        }
        echo_thread.join().expect("echo thread");

        let records = server.drain_traffic(1);
        assert_eq!(records.len(), 1);
        assert_eq!(records[0].user_uuid, user().uuid);
        assert_eq!(records[0].user_id, Some(1));
        assert_eq!(records[0].upload, 1);
        assert_eq!(records[0].download, 1);
    }

    #[tokio::test]
    async fn limited_vless_tcp_uses_limiter_and_limiter_revoke_stops_relay() {
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

        let mut limited = user();
        limited.speed_limit = 8192;
        let server = server_with_user(limited.clone());
        let listener = server.bind().expect("vless bind");
        listener
            .set_nonblocking(true)
            .expect("nonblocking listener");
        let vless_addr = listener.local_addr().expect("vless addr");
        let listener = tokio::net::TcpListener::from_std(listener).expect("tokio listener");
        let server_clone = server.clone();
        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("vless accept");
            server_clone.handle_tcp_client_async(stream).await
        });

        let mut client = tokio::net::TcpStream::connect(vless_addr)
            .await
            .expect("client connect");
        client
            .write_all(&vless_request(echo_addr))
            .await
            .expect("vless request");
        let mut header = [0u8; 2];
        client
            .read_exact(&mut header)
            .await
            .expect("vless response");
        assert_eq!(header, [super::VERSION, 0x00]);
        client.write_all(b"x").await.expect("first write");
        let mut echoed = [0u8; 1];
        client.read_exact(&mut echoed).await.expect("first echo");
        assert_eq!(echoed, *b"x");

        assert!(server.bandwidth.has_limiter_for(&limited.uuid));
        let limiter = server
            .bandwidth
            .limiter_for_limited(Some(&limited))
            .expect("limited user limiter");
        limiter.revoke();

        let _ = client.write_all(b"y").await;
        assert!(
            !second_payload_rx
                .recv_timeout(Duration::from_secs(2))
                .expect("echo result"),
            "revoked limited VLESS relay should stop forwarding"
        );
        drop(client);
        server_task.await.expect("server task").expect("serve once");
        echo_thread.join().expect("echo thread");
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

    #[tokio::test]
    async fn proxies_async_udp_and_records_user_traffic() {
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
        listener
            .set_nonblocking(true)
            .expect("nonblocking listener");
        let vless_addr = listener.local_addr().expect("vless addr");
        let listener = tokio::net::TcpListener::from_std(listener).expect("tokio listener");
        let server_clone = server.clone();
        let server_task = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.expect("vless accept");
            server_clone.handle_tcp_client_async(stream).await
        });

        let mut client = tokio::net::TcpStream::connect(vless_addr)
            .await
            .expect("client connect");
        client
            .write_all(&vless_udp_request(echo_addr))
            .await
            .expect("client request");
        let mut response = [0u8; 2];
        client
            .read_exact(&mut response)
            .await
            .expect("client response");
        assert_eq!(response, [0x00, 0x00]);

        client
            .write_all(&vless_udp_payload(b"ping"))
            .await
            .expect("client udp packet");
        let mut len = [0u8; 2];
        client.read_exact(&mut len).await.expect("udp response len");
        let mut payload = vec![0u8; u16::from_be_bytes(len) as usize];
        client.read_exact(&mut payload).await.expect("udp response");
        assert_eq!(payload, b"pong");
        drop(client);

        server_task.await.expect("server task").expect("serve once");
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

        let mut vision_reader = VisionReader::new(&mut client, [0x11; 16]);
        let mut echoed = [0u8; 4];
        vision_reader
            .read_exact(&mut echoed)
            .expect("client read payload");
        assert_eq!(&echoed, b"ping");
        drop(vision_reader);
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
    fn tls_vision_switches_to_raw_tcp_fast_path_after_direct_copy() {
        super::VLESS_VISION_RAW_RELAY_SWITCHES.store(0, Ordering::SeqCst);
        let cert = test_cert("vless-vision-raw-fast-path");
        let echo = TcpListener::bind("127.0.0.1:0").expect("echo bind");
        let echo_addr = echo.local_addr().expect("echo addr");
        let client_hello = tls_client_hello_like_record();
        let app_data = tls_application_data_record(b"GET / HTTP/1.1\r\n\r\n");
        let expected_len = client_hello.len() + app_data.len();
        let client_hello_len = client_hello.len();
        let app_data_len = app_data.len();
        let echo_thread = thread::spawn(move || {
            let (mut stream, _) = echo.accept().expect("echo accept");
            let mut first = vec![0u8; client_hello_len];
            stream.read_exact(&mut first).expect("echo first read");
            stream.write_all(&first).expect("echo first write");
            let mut second = vec![0u8; app_data_len];
            stream.read_exact(&mut second).expect("echo second read");
            stream.write_all(&second).expect("echo second write");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("echo timeout");
            let mut byte = [0u8; 1];
            let _ = stream.read(&mut byte);
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

        let mut encoder = VisionEncoder::new([0x11; 16]);
        let first_encoded = encoder.encode(&client_hello);
        let second_encoded = encoder.encode(&app_data);
        client
            .write_all(&first_encoded)
            .expect("client write client hello");
        thread::sleep(Duration::from_millis(50));
        client
            .write_all(&second_encoded)
            .expect("client write app data");

        let mut vision_reader = VisionReader::new(&mut client, [0x11; 16]);
        let mut echoed = vec![0u8; expected_len];
        vision_reader
            .read_exact(&mut echoed)
            .expect("client read payload");
        drop(vision_reader);
        drop(client);

        server_thread
            .join()
            .expect("server thread")
            .expect("serve once");
        echo_thread.join().expect("echo thread");
        assert!(
            super::VLESS_VISION_RAW_RELAY_SWITCHES.load(Ordering::SeqCst) > 0,
            "VLESS Vision relay should switch to the raw TCP fast path after direct copy"
        );
    }

    #[test]
    fn tls_vision_relay_exits_when_client_disconnects_while_remote_is_idle() {
        let cert = test_cert("vless-vision-client-close");
        let inbound = TcpListener::bind("127.0.0.1:0").expect("inbound bind");
        let inbound_addr = inbound.local_addr().expect("inbound addr");
        let remote = TcpListener::bind("127.0.0.1:0").expect("remote bind");
        let remote_addr = remote.local_addr().expect("remote addr");
        let acceptor =
            TlsAcceptor::from_files(&cert.cert_path, &cert.key_path, &[]).expect("tls acceptor");

        let (relay_tx, relay_rx) = mpsc::channel();
        let relay_thread = thread::spawn(move || {
            let (stream, _) = inbound.accept().expect("accept inbound");
            let client = acceptor.accept(stream).expect("tls accept");
            let remote_stream = TcpStream::connect(remote_addr).expect("connect remote");
            let result = super::relay_tls_vision_stream(client, remote_stream, [0x11; 16], None);
            relay_tx.send(result).expect("send relay result");
        });

        let remote_thread = thread::spawn(move || {
            let (mut stream, _) = remote.accept().expect("accept remote");
            stream
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("remote timeout");
            let mut byte = [0u8; 1];
            matches!(stream.read(&mut byte), Ok(0) | Err(_))
        });

        let mut client = tls_client(inbound_addr, cert.cert_der.clone());
        client.write_all(b"bye").expect("client app data");
        drop(client);

        relay_rx
            .recv_timeout(Duration::from_secs(2))
            .expect("relay must exit after client disconnect")
            .expect("relay result");
        assert!(
            remote_thread.join().expect("remote thread"),
            "remote side should be closed when VLESS Vision client disconnects"
        );
        relay_thread.join().expect("relay thread");
    }

    #[test]
    fn tls_vision_relay_exits_when_client_half_closes_while_remote_is_idle() {
        let cert = test_cert("vless-vision-client-half-close");
        let inbound = TcpListener::bind("127.0.0.1:0").expect("inbound bind");
        let inbound_addr = inbound.local_addr().expect("inbound addr");
        let remote = TcpListener::bind("127.0.0.1:0").expect("remote bind");
        let remote_addr = remote.local_addr().expect("remote addr");
        let acceptor =
            TlsAcceptor::from_files(&cert.cert_path, &cert.key_path, &[]).expect("tls acceptor");

        let (relay_tx, relay_rx) = mpsc::channel();
        let relay_thread = thread::spawn(move || {
            let (stream, _) = inbound.accept().expect("accept inbound");
            let client = acceptor.accept(stream).expect("tls accept");
            let remote_stream = TcpStream::connect(remote_addr).expect("connect remote");
            let result = super::relay_tls_vision_stream(client, remote_stream, [0x11; 16], None);
            relay_tx.send(result).expect("send relay result");
        });

        let remote_thread = thread::spawn(move || {
            let (mut stream, _) = remote.accept().expect("accept remote");
            stream
                .set_read_timeout(Some(Duration::from_secs(5)))
                .expect("remote timeout");
            let mut byte = [0u8; 1];
            matches!(stream.read(&mut byte), Ok(0) | Err(_))
        });

        let mut client = tls_client(inbound_addr, cert.cert_der.clone());
        while client.conn.is_handshaking() {
            client
                .conn
                .complete_io(&mut client.sock)
                .expect("client tls handshake");
        }
        client
            .sock
            .shutdown(Shutdown::Write)
            .expect("client half close");

        relay_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("relay must exit after client half close")
            .expect("relay result");
        assert!(
            remote_thread.join().expect("remote thread"),
            "remote side should be closed when VLESS Vision client half-closes"
        );
        relay_thread.join().expect("relay thread");
    }

    #[test]
    fn proxies_tls_vision_plain_payload_without_padding_prefix() {
        let cert = test_cert("vless-vision-plain");
        let echo = TcpListener::bind("127.0.0.1:0").expect("echo bind");
        let echo_addr = echo.local_addr().expect("echo addr");
        let payload = b"plain-http-like-payload".to_vec();
        let expected = payload.clone();
        let echo_thread = thread::spawn(move || {
            let (mut stream, _) = echo.accept().expect("echo accept");
            let mut bytes = vec![0u8; expected.len()];
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

        client.write_all(&payload).expect("plain payload");
        let mut vision_reader = VisionReader::new(&mut client, [0x11; 16]);
        let mut echoed = vec![0u8; payload.len()];
        vision_reader
            .read_exact(&mut echoed)
            .expect("plain echoed payload");
        assert_eq!(echoed, payload);
        drop(vision_reader);
        drop(client);

        server_thread
            .join()
            .expect("server thread")
            .expect("serve once");
        echo_thread.join().expect("echo thread");
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
