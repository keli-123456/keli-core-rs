pub mod config;
pub mod config_io;
pub mod control;
pub mod http_proxy;
pub mod protocol;
pub mod routing;
pub mod runtime;
pub mod service;
pub mod socks5;
pub mod stream;
pub mod traffic;
pub mod user;

pub use config::{
    CoreConfig, InboundConfig, OutboundConfig, RouteAction, RouteRule, SniffingConfig, StatsConfig,
    TlsConfig, TransportConfig, ValidationError,
};
pub use config_io::load_core_config_json;
pub use control::{CoreCommand, CoreController, CoreResponse};
pub use http_proxy::{HttpProxyServer, HttpProxyServerConfig};
pub use protocol::{Protocol, ProtocolPlacement};
pub use routing::{RouteDecision, RouteMatcher};
pub use runtime::{CorePlan, CoreStatus, ReloadDecision, RuntimeState};
pub use service::{CoreService, CoreServiceError, ListenerStatus};
pub use socks5::{Socks5Server, Socks5ServerConfig, SocksTarget};
pub use traffic::{TrafficDelta, TrafficKey, TrafficRegistry};
pub use user::CoreUser;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
