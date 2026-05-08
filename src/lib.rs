pub mod config;
pub mod control;
pub mod protocol;
pub mod runtime;
pub mod service;
pub mod socks5;
pub mod traffic;
pub mod user;

pub use config::{
    CoreConfig, InboundConfig, OutboundConfig, RouteAction, RouteRule, SniffingConfig, StatsConfig,
    TlsConfig, TransportConfig, ValidationError,
};
pub use control::{CoreCommand, CoreController, CoreResponse};
pub use protocol::{Protocol, ProtocolPlacement};
pub use runtime::{CorePlan, CoreStatus, ReloadDecision, RuntimeState};
pub use service::{CoreService, CoreServiceError, ListenerStatus};
pub use socks5::{Socks5Server, Socks5ServerConfig, SocksTarget};
pub use traffic::{TrafficDelta, TrafficKey, TrafficRegistry};
pub use user::CoreUser;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
