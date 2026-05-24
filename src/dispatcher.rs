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

    pub fn sniffed_tcp_target(&self, target: &SocksTarget, initial_payload: &[u8]) -> SocksTarget {
        if !self.sniffing.enabled || initial_payload.is_empty() {
            return target.clone();
        }
        if self.sniffing_allows("http") {
            if let Some(sniffed) = sniff_http_host(initial_payload, target.port) {
                return sniffed;
            }
        }
        if self.sniffing_allows("tls") {
            if let Some(host) = sniff_tls_sni(initial_payload) {
                return SocksTarget {
                    host,
                    port: target.port,
                };
            }
        }
        target.clone()
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

    fn sniffing_allows(&self, protocol: &str) -> bool {
        self.sniffing
            .dest_override
            .iter()
            .any(|value| value.trim().eq_ignore_ascii_case(protocol))
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

fn sniff_http_host(payload: &[u8], default_port: u16) -> Option<SocksTarget> {
    let header_end = payload
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .map(|index| index + 4)?;
    let header = std::str::from_utf8(&payload[..header_end]).ok()?;
    let mut lines = header.split("\r\n");
    let request_line = lines.next()?.trim();
    if !looks_like_http_request_line(request_line) {
        return None;
    }
    lines.find_map(|line| {
        let (name, value) = line.split_once(':')?;
        if !name.trim().eq_ignore_ascii_case("host") {
            return None;
        }
        parse_host_header_target(value.trim(), default_port)
    })
}

fn looks_like_http_request_line(line: &str) -> bool {
    line.starts_with("GET ")
        || line.starts_with("POST ")
        || line.starts_with("HEAD ")
        || line.starts_with("PUT ")
        || line.starts_with("DELETE ")
        || line.starts_with("PATCH ")
        || line.starts_with("OPTIONS ")
        || line.starts_with("CONNECT ")
}

fn parse_host_header_target(value: &str, default_port: u16) -> Option<SocksTarget> {
    let value = value.trim().trim_matches('"');
    if value.is_empty() {
        return None;
    }
    if let Some(rest) = value.strip_prefix('[') {
        let (host, tail) = rest.split_once(']')?;
        let port = tail
            .strip_prefix(':')
            .and_then(|port| port.parse::<u16>().ok())
            .unwrap_or(default_port);
        return sanitized_target(host, port);
    }
    let colon_count = value.as_bytes().iter().filter(|byte| **byte == b':').count();
    if colon_count == 1 {
        let (host, port) = value.rsplit_once(':')?;
        let port = port.parse::<u16>().ok().unwrap_or(default_port);
        return sanitized_target(host, port);
    }
    sanitized_target(value, default_port)
}

fn sniff_tls_sni(payload: &[u8]) -> Option<String> {
    if payload.len() < 5 || payload[0] != 0x16 {
        return None;
    }
    let record_len = read_u16(payload, 3)? as usize;
    if payload.len() < 5 + record_len {
        return None;
    }
    let body = &payload[5..5 + record_len];
    if body.len() < 4 || body[0] != 0x01 {
        return None;
    }
    let handshake_len = read_u24(body, 1)? as usize;
    if body.len() < 4 + handshake_len {
        return None;
    }
    let hello = &body[4..4 + handshake_len];
    let mut cursor = ByteCursor::new(hello);
    cursor.skip(2)?;
    cursor.skip(32)?;
    let session_id_len = cursor.read_u8()? as usize;
    cursor.skip(session_id_len)?;
    let cipher_len = cursor.read_u16()? as usize;
    cursor.skip(cipher_len)?;
    let compression_len = cursor.read_u8()? as usize;
    cursor.skip(compression_len)?;
    let extensions_len = cursor.read_u16()? as usize;
    let extensions = cursor.read_slice(extensions_len)?;
    let mut extensions = ByteCursor::new(extensions);
    while extensions.remaining() > 0 {
        let ext_type = extensions.read_u16()?;
        let ext_len = extensions.read_u16()? as usize;
        let ext = extensions.read_slice(ext_len)?;
        if ext_type == 0 {
            return parse_sni_extension(ext);
        }
    }
    None
}

fn parse_sni_extension(input: &[u8]) -> Option<String> {
    let mut cursor = ByteCursor::new(input);
    let list_len = cursor.read_u16()? as usize;
    let list = cursor.read_slice(list_len)?;
    let mut list = ByteCursor::new(list);
    while list.remaining() > 0 {
        let name_type = list.read_u8()?;
        let len = list.read_u16()? as usize;
        let value = list.read_slice(len)?;
        if name_type == 0 {
            let host = std::str::from_utf8(value).ok()?;
            return sanitized_host(host).map(str::to_string);
        }
    }
    None
}

fn sanitized_target(host: &str, port: u16) -> Option<SocksTarget> {
    sanitized_host(host).map(|host| SocksTarget {
        host: host.to_string(),
        port,
    })
}

fn sanitized_host(host: &str) -> Option<&str> {
    let host = host.trim().trim_end_matches('.');
    if host.is_empty()
        || host.len() > 253
        || host
            .bytes()
            .any(|byte| byte.is_ascii_control() || byte.is_ascii_whitespace() || byte == b'/')
    {
        return None;
    }
    Some(host)
}

fn read_u16(input: &[u8], offset: usize) -> Option<u16> {
    Some(u16::from_be_bytes([
        *input.get(offset)?,
        *input.get(offset + 1)?,
    ]))
}

fn read_u24(input: &[u8], offset: usize) -> Option<u32> {
    Some(
        ((*input.get(offset)? as u32) << 16)
            | ((*input.get(offset + 1)? as u32) << 8)
            | (*input.get(offset + 2)? as u32),
    )
}

struct ByteCursor<'a> {
    input: &'a [u8],
    offset: usize,
}

impl<'a> ByteCursor<'a> {
    fn new(input: &'a [u8]) -> Self {
        Self { input, offset: 0 }
    }

    fn remaining(&self) -> usize {
        self.input.len().saturating_sub(self.offset)
    }

    fn skip(&mut self, len: usize) -> Option<()> {
        self.read_slice(len).map(|_| ())
    }

    fn read_u8(&mut self) -> Option<u8> {
        let value = *self.input.get(self.offset)?;
        self.offset += 1;
        Some(value)
    }

    fn read_u16(&mut self) -> Option<u16> {
        let value = read_u16(self.input, self.offset)?;
        self.offset += 2;
        Some(value)
    }

    fn read_slice(&mut self, len: usize) -> Option<&'a [u8]> {
        let end = self.offset.checked_add(len)?;
        let slice = self.input.get(self.offset..end)?;
        self.offset = end;
        Some(slice)
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
