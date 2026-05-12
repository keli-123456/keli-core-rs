pub mod anytls;
pub mod bench;
pub mod config;
pub mod config_io;
pub mod control;
pub mod control_server;
pub mod dns;
pub mod grpc;
pub mod http2;
pub mod http_proxy;
pub mod httpupgrade;
pub mod hysteria2;
pub mod limits;
pub mod mieru;
pub mod mkcp;
pub mod outbound;
pub mod protocol;
pub mod quic;
mod quic_packet;
pub mod reality;
pub mod routing;
pub mod runtime;
mod salamander;
pub mod service;
pub mod shadowsocks;
pub mod socks5;
pub mod stream;
pub mod tls;
pub mod traffic;
pub mod trojan;
pub mod tuic;
pub mod user;
pub mod vision;
pub mod vless;
pub mod vmess;
pub mod websocket;

pub use anytls::{AnyTlsServer, AnyTlsServerConfig};
pub use config::{
    CoreConfig, InboundConfig, OutboundConfig, RealityConfig, RouteAction, RouteRule,
    SniffingConfig, StatsConfig, TlsConfig, TransportConfig, ValidationError,
};
pub use config_io::load_core_config_json;
pub use control::{CoreCommand, CoreController, CoreResponse};
pub use control_server::{start_control_server, ControlServerError, ControlServerHandle};
pub use http_proxy::{HttpProxyServer, HttpProxyServerConfig};
pub use hysteria2::{Hysteria2Server, Hysteria2ServerConfig};
pub use limits::{
    BandwidthLimiter, DeviceLimitExceeded, UserBandwidthLimiters, UserSessionGuard,
    UserSessionTracker,
};
pub use mieru::{MieruServer, MieruServerConfig};
pub use outbound::{
    connect_tcp_outbound, connect_tcp_outbound_tokio, outbound_udp_target, send_udp_outbound,
    send_udp_outbound_tokio,
};
pub use protocol::{Protocol, ProtocolPlacement};
pub use routing::{route_protocol_labels, RouteDecision, RouteMatcher};
pub use runtime::{CorePlan, CoreStatus, ReloadDecision, RuntimeState};
pub use service::{CoreService, CoreServiceError, ListenerStatus};
pub use shadowsocks::{
    is_supported_shadowsocks_cipher, ShadowsocksServer, ShadowsocksServerConfig,
};
pub use socks5::{Socks5Server, Socks5ServerConfig, SocksTarget};
pub use tls::{relay_tls_stream, TlsAcceptor, TlsConnection};
pub use traffic::{SharedTrafficRegistry, TrafficDelta, TrafficKey, TrafficRegistry};
pub use trojan::{trojan_password_hash, TrojanServer, TrojanServerConfig};
pub use tuic::{TuicServer, TuicServerConfig};
pub use user::{CoreUser, CoreUserDelta, CoreUserDeltaResult, UserStore};
pub use vless::{VlessServer, VlessServerConfig};
pub use vmess::{VmessServer, VmessServerConfig};

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
