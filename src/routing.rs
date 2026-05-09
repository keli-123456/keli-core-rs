use std::env;
use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, ToSocketAddrs};
use std::path::PathBuf;

use crate::config::{OutboundConfig, RouteAction, RouteRule};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RouteDecision {
    Direct,
    Block,
    Outbound(OutboundConfig),
    UnsupportedOutbound(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RoutedTarget {
    pub host: String,
    pub port: u16,
}

#[derive(Clone, Debug, Default)]
pub struct RouteMatcher {
    routes: Vec<RouteRule>,
}

impl RouteMatcher {
    pub fn new(routes: Vec<RouteRule>) -> Self {
        Self { routes }
    }

    pub fn decide(&self, host: &str) -> RouteDecision {
        self.decide_target(host, 0, "")
    }

    pub fn decide_target(&self, host: &str, port: u16, protocol_labels: &str) -> RouteDecision {
        for route in &self.routes {
            if route_targets_match(&route.targets, host, port, protocol_labels) {
                return match &route.action {
                    RouteAction::Direct => RouteDecision::Direct,
                    RouteAction::Block => RouteDecision::Block,
                    RouteAction::Outbound(tag) => route
                        .outbound
                        .clone()
                        .map(RouteDecision::Outbound)
                        .unwrap_or_else(|| RouteDecision::UnsupportedOutbound(tag.clone())),
                };
            }
        }
        RouteDecision::Direct
    }
}

pub fn route_targets_match(
    targets: &[String],
    host: &str,
    port: u16,
    protocol_labels: &str,
) -> bool {
    let host = host.trim().trim_matches(['[', ']']).to_ascii_lowercase();
    let host_ip = host.parse::<IpAddr>().ok();
    let mut resolved_ips = None;
    targets.iter().any(|target| {
        matches_target(
            &host,
            host_ip,
            &mut resolved_ips,
            port,
            protocol_labels,
            target,
        )
    })
}

pub fn route_protocol_labels(network: &str, payload: &[u8]) -> String {
    let mut labels = Vec::new();
    push_protocol_label(&mut labels, network);
    if looks_like_http(payload) {
        push_protocol_label(&mut labels, "http");
    }
    if looks_like_tls(payload) {
        push_protocol_label(&mut labels, "tls");
    }
    if looks_like_quic(payload) {
        push_protocol_label(&mut labels, "quic");
    }
    if looks_like_bittorrent(payload) {
        push_protocol_label(&mut labels, "bittorrent");
    }
    labels.join(",")
}

impl RouteDecision {
    pub fn apply_to_target(&self, host: &str, port: u16) -> RoutedTarget {
        match self {
            RouteDecision::Outbound(outbound)
                if outbound.protocol.trim().eq_ignore_ascii_case("freedom") =>
            {
                RoutedTarget {
                    host: outbound
                        .address
                        .as_deref()
                        .map(str::trim)
                        .filter(|value| !value.is_empty())
                        .unwrap_or(host)
                        .to_string(),
                    port: outbound.port.unwrap_or(port),
                }
            }
            _ => RoutedTarget {
                host: host.to_string(),
                port,
            },
        }
    }
}

fn matches_target(
    host: &str,
    host_ip: Option<IpAddr>,
    resolved_ips: &mut Option<Vec<IpAddr>>,
    port: u16,
    protocol_labels: &str,
    target: &str,
) -> bool {
    let target = target.trim().to_ascii_lowercase();
    if target.is_empty() {
        return false;
    }
    if let Some(rule) = target.strip_prefix("ip:") {
        if let Some(rule) = rule.strip_prefix("geoip:") {
            return any_target_ip_matches(host, host_ip, resolved_ips, port, |ip| {
                matches_geoip_rule(ip, rule)
            });
        }
        return any_target_ip_matches(host, host_ip, resolved_ips, port, |ip| {
            matches_ip_rule(ip, rule)
        });
    }
    if let Some(rule) = target.strip_prefix("geoip:") {
        return any_target_ip_matches(host, host_ip, resolved_ips, port, |ip| {
            matches_geoip_rule(ip, rule)
        });
    }
    if let Some(rule) = target.strip_prefix("geosite:") {
        return matches_geosite_rule(host, rule);
    }
    if let Some(rule) = target.strip_prefix("regexp:") {
        return regex::Regex::new(rule).is_ok_and(|regex| regex.is_match(host));
    }
    if let Some(rule) = target.strip_prefix("protocol:") {
        return matches_protocol_rule(protocol_labels, rule);
    }
    if let Some(rule) = target.strip_prefix("port:") {
        return port != 0 && matches_port_rule(port, rule);
    }
    if let Some(rule) = target.strip_prefix("network:") {
        return protocol_labels_match(protocol_labels, rule);
    }
    if let Some(rule) = target.strip_prefix("domain:") {
        return matches_domain_suffix(host, rule);
    }
    if let Some(rule) = target.strip_prefix("full:") {
        return host == rule.trim().trim_matches(['[', ']']);
    }
    if let Some(rule) = target.strip_prefix("keyword:") {
        let rule = rule.trim();
        return !rule.is_empty() && host.contains(rule);
    }
    if target == "*" {
        return true;
    }
    if let Some(suffix) = target.strip_prefix("*.") {
        return matches_domain_suffix(host, suffix);
    }
    if let Some(suffix) = target.strip_prefix('.') {
        return matches_domain_suffix(host, suffix);
    }
    host == target
}

fn matches_domain_suffix(host: &str, suffix: &str) -> bool {
    let suffix = suffix
        .trim()
        .trim_start_matches('.')
        .trim_matches(['[', ']']);
    !suffix.is_empty() && (host == suffix || host.ends_with(&format!(".{suffix}")))
}

fn any_target_ip_matches<F>(
    host: &str,
    host_ip: Option<IpAddr>,
    resolved_ips: &mut Option<Vec<IpAddr>>,
    port: u16,
    mut predicate: F,
) -> bool
where
    F: FnMut(IpAddr) -> bool,
{
    if let Some(ip) = host_ip {
        return predicate(ip);
    }
    if port == 0 {
        return false;
    }
    let ips = resolved_ips.get_or_insert_with(|| resolve_route_ips(host, port));
    ips.iter().copied().any(predicate)
}

fn resolve_route_ips(host: &str, port: u16) -> Vec<IpAddr> {
    (host, port)
        .to_socket_addrs()
        .map(|addrs| addrs.map(|addr| addr.ip()).collect())
        .unwrap_or_default()
}

fn matches_ip_rule(ip: IpAddr, rule: &str) -> bool {
    let rule = rule.trim().trim_matches(['[', ']']);
    if let Ok(exact) = rule.parse::<IpAddr>() {
        return ip == exact;
    }
    let Some((base, prefix)) = rule.split_once('/') else {
        return false;
    };
    let Ok(prefix) = prefix.trim().parse::<u8>() else {
        return false;
    };
    match (ip, base.trim().parse::<IpAddr>()) {
        (IpAddr::V4(ip), Ok(IpAddr::V4(base))) if prefix <= 32 => {
            let mask = ipv4_mask(prefix);
            ipv4_to_u32(ip) & mask == ipv4_to_u32(base) & mask
        }
        (IpAddr::V6(ip), Ok(IpAddr::V6(base))) if prefix <= 128 => {
            let mask = ipv6_mask(prefix);
            ipv6_to_u128(ip) & mask == ipv6_to_u128(base) & mask
        }
        _ => false,
    }
}

fn matches_geoip_rule(ip: IpAddr, rule: &str) -> bool {
    let rule = rule.trim().to_ascii_lowercase();
    if rule.is_empty() {
        return false;
    }
    if matches!(rule.as_str(), "private" | "local" | "lan") {
        return is_private_ip(ip);
    }
    load_geoip_rules(&rule)
        .iter()
        .any(|cidr| matches_ip_rule(ip, cidr))
}

fn matches_geosite_rule(host: &str, rule: &str) -> bool {
    let rule = rule.trim().to_ascii_lowercase();
    if rule.is_empty() {
        return false;
    }
    if builtin_geosite_domains(&rule)
        .iter()
        .any(|domain| matches_domain_suffix(host, domain))
    {
        return true;
    }
    load_geosite_rules(&rule)
        .iter()
        .any(|domain| matches_geosite_domain(host, domain))
}

fn matches_geosite_domain(host: &str, rule: &str) -> bool {
    let rule = rule.trim().to_ascii_lowercase();
    if rule.is_empty() || rule.starts_with('#') {
        return false;
    }
    if let Some(rule) = rule.strip_prefix("regexp:") {
        return regex::Regex::new(rule).is_ok_and(|regex| regex.is_match(host));
    }
    if let Some(rule) = rule.strip_prefix("domain:") {
        return matches_domain_suffix(host, rule);
    }
    if let Some(rule) = rule.strip_prefix("full:") {
        return host == rule.trim().trim_matches(['[', ']']);
    }
    if let Some(rule) = rule.strip_prefix("keyword:") {
        let rule = rule.trim();
        return !rule.is_empty() && host.contains(rule);
    }
    matches_domain_suffix(host, &rule)
}

fn matches_protocol_rule(protocol_labels: &str, rule: &str) -> bool {
    protocol_labels_match(protocol_labels, rule)
}

fn protocol_labels_match(protocol_labels: &str, rule: &str) -> bool {
    rule.split(',').map(str::trim).any(|expected| {
        !expected.is_empty()
            && protocol_labels
                .split(',')
                .map(str::trim)
                .any(|label| label.eq_ignore_ascii_case(expected))
    })
}

fn push_protocol_label(labels: &mut Vec<String>, label: &str) {
    let label = label.trim().to_ascii_lowercase();
    if !label.is_empty() && !labels.iter().any(|existing| existing == &label) {
        labels.push(label);
    }
}

fn looks_like_http(payload: &[u8]) -> bool {
    const METHODS: [&[u8]; 9] = [
        b"GET ",
        b"POST ",
        b"PUT ",
        b"PATCH ",
        b"DELETE ",
        b"HEAD ",
        b"OPTIONS ",
        b"CONNECT ",
        b"TRACE ",
    ];
    METHODS.iter().any(|method| {
        payload.len() >= method.len() && payload[..method.len()].eq_ignore_ascii_case(method)
    })
}

fn looks_like_tls(payload: &[u8]) -> bool {
    payload.len() >= 5
        && payload[0] == 0x16
        && payload[1] == 0x03
        && payload[2] <= 0x04
        && u16::from_be_bytes([payload[3], payload[4]]) > 0
}

fn looks_like_quic(payload: &[u8]) -> bool {
    payload.len() >= 6 && payload[0] & 0x80 != 0 && payload[1..5] != [0, 0, 0, 0]
}

fn looks_like_bittorrent(payload: &[u8]) -> bool {
    if payload.len() >= 20 && payload[0] == 19 && &payload[1..20] == b"BitTorrent protocol" {
        return true;
    }
    payload.len() >= 16
        && payload[..8] == [0, 0, 4, 23, 39, 16, 25, 128]
        && payload[8..12] == [0, 0, 0, 0]
}

fn is_private_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(ip) => {
            ip.is_private()
                || ip.is_loopback()
                || ip.is_link_local()
                || ip.is_broadcast()
                || ip.is_documentation()
                || ip.octets()[0] == 0
        }
        IpAddr::V6(ip) => {
            ip.is_loopback()
                || ip.is_unspecified()
                || ((ip.segments()[0] & 0xfe00) == 0xfc00)
                || ((ip.segments()[0] & 0xffc0) == 0xfe80)
        }
    }
}

fn builtin_geosite_domains(rule: &str) -> &'static [&'static str] {
    match rule {
        "private" | "local" => &["localhost", "local", "lan", "home.arpa"],
        "openai" => &[
            "openai.com",
            "chatgpt.com",
            "oaistatic.com",
            "oaiusercontent.com",
            "openaiapi-site.azureedge.net",
        ],
        "google" => &[
            "google.com",
            "gstatic.com",
            "googleapis.com",
            "googleusercontent.com",
            "youtube.com",
            "ytimg.com",
        ],
        "telegram" => &["telegram.org", "telegram.me", "t.me", "tdesktop.com"],
        "netflix" => &["netflix.com", "nflxvideo.net", "nflximg.net", "nflxso.net"],
        _ => &[],
    }
}

fn load_geoip_rules(rule: &str) -> Vec<String> {
    load_rule_lines("KELI_CORE_GEOIP_DIR", rule)
}

fn load_geosite_rules(rule: &str) -> Vec<String> {
    load_rule_lines("KELI_CORE_GEOSITE_DIR", rule)
}

fn load_rule_lines(env_key: &str, rule: &str) -> Vec<String> {
    let Ok(base) = env::var(env_key) else {
        return Vec::new();
    };
    let Some(path) = rule_file_path(&base, rule) else {
        return Vec::new();
    };
    fs::read_to_string(path)
        .ok()
        .map(|content| {
            content
                .lines()
                .map(str::trim)
                .filter(|line| !line.is_empty() && !line.starts_with('#'))
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default()
}

fn rule_file_path(base: &str, rule: &str) -> Option<PathBuf> {
    if rule
        .chars()
        .any(|ch| !(ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.')))
    {
        return None;
    }
    Some(PathBuf::from(base).join(format!("{rule}.txt")))
}

fn matches_port_rule(port: u16, rule: &str) -> bool {
    rule.split(',').any(|item| {
        let item = item.trim();
        if item.is_empty() {
            return false;
        }
        if let Some((start, end)) = item.split_once('-') {
            let Ok(start) = start.trim().parse::<u16>() else {
                return false;
            };
            let Ok(end) = end.trim().parse::<u16>() else {
                return false;
            };
            return start <= port && port <= end;
        }
        item.parse::<u16>().is_ok_and(|value| value == port)
    })
}

fn ipv4_to_u32(ip: Ipv4Addr) -> u32 {
    u32::from_be_bytes(ip.octets())
}

fn ipv6_to_u128(ip: Ipv6Addr) -> u128 {
    u128::from_be_bytes(ip.octets())
}

fn ipv4_mask(prefix: u8) -> u32 {
    if prefix == 0 {
        0
    } else {
        u32::MAX << (32 - prefix)
    }
}

fn ipv6_mask(prefix: u8) -> u128 {
    if prefix == 0 {
        0
    } else {
        u128::MAX << (128 - prefix)
    }
}

#[cfg(test)]
mod tests {
    use crate::config::{OutboundConfig, RouteAction, RouteRule};
    use crate::routing::{route_protocol_labels, RouteDecision, RouteMatcher};

    use super::matches_geosite_domain;

    #[test]
    fn matches_exact_and_suffix_block_rules() {
        let matcher = RouteMatcher::new(vec![
            RouteRule {
                targets: vec!["blocked.example.com".to_string()],
                action: RouteAction::Block,
                outbound: None,
            },
            RouteRule {
                targets: vec!["*.ads.example.com".to_string()],
                action: RouteAction::Block,
                outbound: None,
            },
        ]);

        assert_eq!(matcher.decide("blocked.example.com"), RouteDecision::Block);
        assert_eq!(matcher.decide("a.ads.example.com"), RouteDecision::Block);
        assert_eq!(matcher.decide("allowed.example.com"), RouteDecision::Direct);
    }

    #[test]
    fn matches_xray_style_domain_rules() {
        let matcher = RouteMatcher::new(vec![RouteRule {
            targets: vec![
                "domain:example.com".to_string(),
                "full:exact.example.net".to_string(),
                "keyword:tracker".to_string(),
            ],
            action: RouteAction::Block,
            outbound: None,
        }]);

        assert_eq!(matcher.decide("api.example.com"), RouteDecision::Block);
        assert_eq!(matcher.decide("exact.example.net"), RouteDecision::Block);
        assert_eq!(matcher.decide("cdn-tracker.example"), RouteDecision::Block);
        assert_eq!(
            matcher.decide("almost-exact.example.net"),
            RouteDecision::Direct
        );
    }

    #[test]
    fn matches_ip_cidr_and_port_rules() {
        let matcher = RouteMatcher::new(vec![
            RouteRule {
                targets: vec!["ip:10.0.0.0/8".to_string(), "ip:2001:db8::/32".to_string()],
                action: RouteAction::Block,
                outbound: None,
            },
            RouteRule {
                targets: vec!["port:6881-6889,6969".to_string()],
                action: RouteAction::Block,
                outbound: None,
            },
        ]);

        assert_eq!(
            matcher.decide_target("10.1.2.3", 443, "tcp"),
            RouteDecision::Block
        );
        assert_eq!(
            matcher.decide_target("[2001:db8::1]", 443, "tcp"),
            RouteDecision::Block
        );
        assert_eq!(
            matcher.decide_target("example.com", 6883, "tcp"),
            RouteDecision::Block
        );
        assert_eq!(
            matcher.decide_target("example.com", 443, "tcp"),
            RouteDecision::Direct
        );
    }

    #[test]
    fn matches_geo_regexp_and_protocol_rules() {
        let matcher = RouteMatcher::new(vec![
            RouteRule {
                targets: vec!["geosite:openai".to_string(), "regexp:^api\\.".to_string()],
                action: RouteAction::Block,
                outbound: None,
            },
            RouteRule {
                targets: vec!["protocol:udp".to_string()],
                action: RouteAction::Block,
                outbound: None,
            },
            RouteRule {
                targets: vec!["geoip:private".to_string()],
                action: RouteAction::Block,
                outbound: None,
            },
        ]);

        assert_eq!(
            matcher.decide_target("192.168.1.10", 443, "tcp"),
            RouteDecision::Block
        );
        assert_eq!(
            matcher.decide_target("localhost", 443, "tcp"),
            RouteDecision::Block
        );
        assert_eq!(
            matcher.decide_target("chatgpt.com", 443, "tcp"),
            RouteDecision::Block
        );
        assert_eq!(
            matcher.decide_target("api.example.com", 443, "tcp"),
            RouteDecision::Block
        );
        assert_eq!(
            matcher.decide_target("example.com", 443, "udp"),
            RouteDecision::Block
        );
        assert_eq!(
            matcher.decide_target("example.com", 443, "udp,quic"),
            RouteDecision::Block
        );
        assert_eq!(
            matcher.decide_target("example.com", 443, "tcp,http"),
            RouteDecision::Direct
        );
    }

    #[test]
    fn geosite_file_rules_accept_domain_prefix() {
        assert!(matches_geosite_domain(
            "api.example.com",
            "domain:example.com"
        ));
        assert!(matches_geosite_domain("example.com", "domain:example.com"));
        assert!(!matches_geosite_domain(
            "badexample.com",
            "domain:example.com"
        ));
    }

    #[test]
    fn derives_protocol_labels_from_udp_payloads() {
        assert_eq!(
            route_protocol_labels("udp", b"GET / HTTP/1.1\r\n"),
            "udp,http"
        );
        assert_eq!(
            route_protocol_labels("udp", &[0x16, 0x03, 0x01, 0x00, 0x2a]),
            "udp,tls"
        );
        assert_eq!(
            route_protocol_labels("udp", &[0xc3, 0x00, 0x00, 0x00, 0x01, 0x08]),
            "udp,quic"
        );
        assert_eq!(
            route_protocol_labels(
                "udp",
                &[0, 0, 4, 23, 39, 16, 25, 128, 0, 0, 0, 0, 0, 0, 0, 1]
            ),
            "udp,bittorrent"
        );
    }

    #[test]
    fn freedom_outbound_routes_are_direct_decisions() {
        let matcher = RouteMatcher::new(vec![RouteRule {
            targets: vec!["domain:example.com".to_string()],
            action: RouteAction::Outbound("warp".to_string()),
            outbound: Some(OutboundConfig {
                tag: "warp".to_string(),
                protocol: "freedom".to_string(),
                method: None,
                address: None,
                port: None,
                username: None,
                password: None,
            }),
        }]);

        assert_eq!(
            matcher.decide("api.example.com"),
            RouteDecision::Outbound(OutboundConfig {
                tag: "warp".to_string(),
                protocol: "freedom".to_string(),
                method: None,
                address: None,
                port: None,
                username: None,
                password: None,
            })
        );
    }

    #[test]
    fn outbound_decision_rewrites_address_and_port() {
        let decision = RouteDecision::Outbound(OutboundConfig {
            tag: "redirect".to_string(),
            protocol: "freedom".to_string(),
            method: None,
            address: Some("127.0.0.1".to_string()),
            port: Some(8443),
            username: None,
            password: None,
        });

        let target = decision.apply_to_target("example.com", 443);

        assert_eq!(target.host, "127.0.0.1");
        assert_eq!(target.port, 8443);
    }
}
