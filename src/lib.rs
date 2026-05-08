pub mod config;
pub mod control;
pub mod protocol;
pub mod runtime;
pub mod traffic;
pub mod user;

pub use config::{
    CoreConfig, InboundConfig, OutboundConfig, RouteAction, RouteRule, SniffingConfig,
    StatsConfig, TlsConfig, TransportConfig, ValidationError,
};
pub use control::{CoreCommand, CoreController, CoreResponse};
pub use protocol::{Protocol, ProtocolPlacement};
pub use runtime::{CorePlan, CoreStatus, ReloadDecision, RuntimeState};
pub use traffic::{TrafficDelta, TrafficKey, TrafficRegistry};
pub use user::CoreUser;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
