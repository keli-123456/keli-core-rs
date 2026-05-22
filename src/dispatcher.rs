use std::io;
use std::net::{SocketAddr, TcpStream};
use std::time::Duration;

use crate::config::{PolicyConfig, RouteRule, SniffingConfig};
use crate::outbound::{
    connect_tcp_outbound, connect_tcp_outbound_tokio, send_udp_outbound, send_udp_outbound_tokio,
};
use crate::routing::{route_protocol_labels, RouteDecision, RouteMatcher};
use crate::socks5::SocksTarget;

#[derive(Clone, Debug)]
pub struct RouteDispatcher {
    router: RouteMatcher,
    sniffing: SniffingConfig,
    policy: PolicyConfig,
}

impl RouteDispatcher {
    pub fn new(routes: Vec<RouteRule>) -> Self {
        Self::with_policy_and_sniffing(routes, PolicyConfig::default(), SniffingConfig::default())
    }

    pub fn with_sniffing(routes: Vec<RouteRule>, sniffing: SniffingConfig) -> Self {
        Self::with_policy_and_sniffing(routes, PolicyConfig::default(), sniffing)
    }

    pub fn with_connect_timeout(routes: Vec<RouteRule>, connect_timeout: Duration) -> Self {
        let mut policy = PolicyConfig::default();
        policy.connect_timeout_secs = connect_timeout.as_secs().clamp(1, 60);
        Self::with_policy_and_sniffing(routes, policy, SniffingConfig::default())
    }

    pub fn with_policy_and_sniffing(
        routes: Vec<RouteRule>,
        policy: PolicyConfig,
        sniffing: SniffingConfig,
    ) -> Self {
        Self {
            router: RouteMatcher::new(routes),
            policy,
            sniffing,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.router.is_empty()
    }

    pub fn decide(&self, host: &str) -> RouteDecision {
        self.router.decide(host)
    }

    pub fn policy(&self) -> &PolicyConfig {
        &self.policy
    }

    pub fn connect_timeout(&self) -> Duration {
        Duration::from_secs(self.policy.connect_timeout_secs.clamp(1, 60))
    }

    pub fn sniffing_cache_timeout(&self) -> Duration {
        Duration::from_millis(self.policy.sniffing_cache_millis.max(1))
    }

    pub fn decide_tcp(&self, host: &str, port: u16, initial_payload: &[u8]) -> RouteDecision {
        self.decide_by_payload("tcp", host, port, initial_payload)
    }

    pub fn decide_udp(&self, host: &str, port: u16, payload: &[u8]) -> RouteDecision {
        self.decide_by_payload("udp", host, port, payload)
    }

    pub fn decide_with_labels(
        &self,
        host: &str,
        port: u16,
        protocol_labels: &str,
    ) -> RouteDecision {
        self.router.decide_target(host, port, protocol_labels)
    }

    pub fn decide_target(&self, host: &str, port: u16, protocol_labels: &str) -> RouteDecision {
        self.decide_with_labels(host, port, protocol_labels)
    }

    pub fn connect_tcp(
        &self,
        target: &SocksTarget,
        initial_payload: &[u8],
    ) -> io::Result<TcpStream> {
        self.connect_tcp_with_decision(
            target,
            &self.decide_tcp(&target.host, target.port, initial_payload),
        )
    }

    pub fn connect_tcp_with_labels(
        &self,
        target: &SocksTarget,
        protocol_labels: &str,
    ) -> io::Result<TcpStream> {
        self.connect_tcp_with_decision(
            target,
            &self.decide_with_labels(&target.host, target.port, protocol_labels),
        )
    }

    pub async fn connect_tcp_tokio(
        &self,
        target: &SocksTarget,
        initial_payload: &[u8],
    ) -> io::Result<tokio::net::TcpStream> {
        self.connect_tcp_with_decision_tokio(
            target,
            &self.decide_tcp(&target.host, target.port, initial_payload),
        )
        .await
    }

    pub async fn connect_tcp_with_labels_tokio(
        &self,
        target: &SocksTarget,
        protocol_labels: &str,
    ) -> io::Result<tokio::net::TcpStream> {
        self.connect_tcp_with_decision_tokio(
            target,
            &self.decide_with_labels(&target.host, target.port, protocol_labels),
        )
        .await
    }

    pub fn send_udp(
        &self,
        target: &SocksTarget,
        payload: &[u8],
    ) -> io::Result<Option<(SocketAddr, Vec<u8>)>> {
        match self.decide_udp(&target.host, target.port, payload) {
            RouteDecision::Direct => Ok(None),
            RouteDecision::Outbound(outbound) => {
                send_udp_outbound(&outbound, target, payload, self.connect_timeout()).map(Some)
            }
            RouteDecision::Block => Ok(Some((blocked_udp_addr(), Vec::new()))),
            RouteDecision::UnsupportedOutbound(tag) => Err(unsupported_outbound(tag)),
        }
    }

    pub async fn send_udp_tokio(
        &self,
        target: &SocksTarget,
        payload: &[u8],
    ) -> io::Result<Option<(SocketAddr, Vec<u8>)>> {
        match self.decide_udp(&target.host, target.port, payload) {
            RouteDecision::Direct => Ok(None),
            RouteDecision::Outbound(outbound) => {
                send_udp_outbound_tokio(&outbound, target, payload, self.connect_timeout())
                    .await
                    .map(Some)
            }
            RouteDecision::Block => Ok(Some((blocked_udp_addr(), Vec::new()))),
            RouteDecision::UnsupportedOutbound(tag) => Err(unsupported_outbound(tag)),
        }
    }

    fn decide_by_payload(
        &self,
        network: &str,
        host: &str,
        port: u16,
        payload: &[u8],
    ) -> RouteDecision {
        let labels = self.protocol_labels(network, payload);
        self.router.decide_target(host, port, &labels)
    }

    fn protocol_labels(&self, network: &str, payload: &[u8]) -> String {
        let network = network.trim();
        if !self.sniffing.enabled || payload.is_empty() {
            return network.to_string();
        }
        let allowed = self
            .sniffing
            .dest_override
            .iter()
            .map(|value| value.trim().to_ascii_lowercase())
            .collect::<Vec<_>>();
        route_protocol_labels(network, payload)
            .split(',')
            .filter(|label| {
                let label = label.trim();
                label == network || allowed.iter().any(|allowed| allowed == label)
            })
            .collect::<Vec<_>>()
            .join(",")
    }

    fn connect_tcp_with_decision(
        &self,
        target: &SocksTarget,
        decision: &RouteDecision,
    ) -> io::Result<TcpStream> {
        match decision {
            RouteDecision::Direct => {
                crate::dns::connect_tcp(&target.host, target.port, self.connect_timeout())
            }
            RouteDecision::Outbound(outbound) => {
                connect_tcp_outbound(outbound, target, self.connect_timeout())
            }
            RouteDecision::Block => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "target blocked by route",
            )),
            RouteDecision::UnsupportedOutbound(tag) => Err(unsupported_outbound(tag.clone())),
        }
    }

    async fn connect_tcp_with_decision_tokio(
        &self,
        target: &SocksTarget,
        decision: &RouteDecision,
    ) -> io::Result<tokio::net::TcpStream> {
        match decision {
            RouteDecision::Direct => {
                crate::dns::connect_tcp_tokio(&target.host, target.port, self.connect_timeout())
                    .await
            }
            RouteDecision::Outbound(outbound) => {
                connect_tcp_outbound_tokio(outbound, target, self.connect_timeout()).await
            }
            RouteDecision::Block => Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "target blocked by route",
            )),
            RouteDecision::UnsupportedOutbound(tag) => Err(unsupported_outbound(tag.clone())),
        }
    }
}

fn unsupported_outbound(tag: String) -> io::Error {
    io::Error::new(
        io::ErrorKind::Unsupported,
        format!("outbound route {tag} is not implemented"),
    )
}

fn blocked_udp_addr() -> SocketAddr {
    "0.0.0.0:0".parse().expect("static socket addr")
}
