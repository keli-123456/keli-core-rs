pub mod abuse;
pub mod anytls;
pub mod bench;
pub mod config;
pub mod config_io;
pub mod control;
pub mod control_server;
pub mod dispatcher;
pub mod dns;
pub mod grpc;
pub mod http2;
pub mod http_proxy;
pub mod httpupgrade;
pub mod hysteria2;
pub mod limits;
pub mod metrics;
pub mod mieru;
pub mod mkcp;
pub mod naive;
pub mod outbound;
pub mod protocol;
pub mod quic;
mod quic_packet;
pub mod quic_resources;
pub mod quic_tuning;
pub mod reality;
pub mod routing;
pub mod runtime;
mod salamander;
pub mod service;
pub mod shadowsocks;
mod socket_bind;
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

#[cfg(test)]
pub(crate) mod test_support {
    use std::sync::{Mutex, MutexGuard, OnceLock};

    static NETWORK_TEST_LOCK: OnceLock<Mutex<()>> = OnceLock::new();

    pub(crate) fn network_test_lock() -> MutexGuard<'static, ()> {
        NETWORK_TEST_LOCK
            .get_or_init(|| Mutex::new(()))
            .lock()
            .expect("network test lock poisoned")
    }
}

pub use abuse::{ClientFailureBackoff, ClientFailureBackoffPolicy, ClientFailureBackoffSnapshot};
pub use anytls::{AnyTlsServer, AnyTlsServerConfig};
pub use config::{
    CoreConfig, InboundConfig, OutboundConfig, PolicyConfig, RealityConfig, RouteAction, RouteRule,
    SniffingConfig, StatsConfig, TlsConfig, TransportConfig, ValidationError,
};
pub use config_io::load_core_config_json;
pub use control::{CoreCommand, CoreController, CoreResponse};
pub use control_server::{
    start_control_server, start_control_server_with_token, ControlServerError, ControlServerHandle,
};
pub use dispatcher::RouteDispatcher;
pub use dns::DnsMetricsSnapshot;
pub use http_proxy::{HttpProxyServer, HttpProxyServerConfig};
pub use hysteria2::{Hysteria2Server, Hysteria2ServerConfig};
pub use limits::{
    BandwidthLimiter, DeviceLimitExceeded, UserBandwidthLimiters, UserSessionGuard,
    UserSessionTracker,
};
pub use metrics::{CoreDurationMetrics, CoreMetricsSnapshot};
pub use mieru::{MieruServer, MieruServerConfig};
pub use naive::{NaiveServer, NaiveServerConfig};
pub use outbound::{
    connect_tcp_outbound, connect_tcp_outbound_tokio, outbound_udp_target, send_udp_outbound,
    send_udp_outbound_tokio,
};
pub use protocol::Protocol;
pub use quic_resources::{QuicResourceSnapshot, SharedQuicConnectionLimiter};
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

/// Applies Linux/glibc process defaults that keep relay memory behavior close to
/// Go under many short-lived OS-threaded connection workers.
pub fn apply_process_memory_defaults() {
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    unsafe {
        let _ = libc::mallopt(libc::M_ARENA_MAX, 2);
        let _ = libc::mallopt(libc::M_TRIM_THRESHOLD, 128 * 1024);
    }
}

/// Returns free heap pages to the OS after large connection batches are closed.
pub fn trim_process_memory() {
    #[cfg(all(target_os = "linux", target_env = "gnu"))]
    unsafe {
        let _ = libc::malloc_trim(0);
    }
}

#[cfg(test)]
mod process_memory_tests {
    #[test]
    fn process_memory_defaults_are_safe_to_apply() {
        crate::apply_process_memory_defaults();
    }

    #[test]
    fn process_memory_trim_is_safe_to_apply() {
        crate::trim_process_memory();
    }
}
