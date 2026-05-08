use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::config::{RouteAction, RouteRule};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RouteDecision {
    Direct,
    Block,
    UnsupportedOutbound(String),
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

    pub fn decide_target(&self, host: &str, port: u16, network: &str) -> RouteDecision {
        let host = host.trim().trim_matches(['[', ']']).to_ascii_lowercase();
        let host_ip = host.parse::<IpAddr>().ok();
        for route in &self.routes {
            if route
                .targets
                .iter()
                .any(|target| matches_target(&host, host_ip, port, network, target))
            {
                return match &route.action {
                    RouteAction::Direct => RouteDecision::Direct,
                    RouteAction::Block => RouteDecision::Block,
                    RouteAction::Outbound(tag) => RouteDecision::UnsupportedOutbound(tag.clone()),
                };
            }
        }
        RouteDecision::Direct
    }
}

fn matches_target(
    host: &str,
    host_ip: Option<IpAddr>,
    port: u16,
    network: &str,
    target: &str,
) -> bool {
    let target = target.trim().to_ascii_lowercase();
    if target.is_empty() {
        return false;
    }
    if let Some(rule) = target.strip_prefix("ip:") {
        return host_ip.is_some_and(|ip| matches_ip_rule(ip, rule));
    }
    if let Some(rule) = target.strip_prefix("port:") {
        return port != 0 && matches_port_rule(port, rule);
    }
    if let Some(rule) = target.strip_prefix("network:") {
        return !network.trim().is_empty() && network.trim().eq_ignore_ascii_case(rule.trim());
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
    use crate::config::{RouteAction, RouteRule};
    use crate::routing::{RouteDecision, RouteMatcher};

    #[test]
    fn matches_exact_and_suffix_block_rules() {
        let matcher = RouteMatcher::new(vec![
            RouteRule {
                targets: vec!["blocked.example.com".to_string()],
                action: RouteAction::Block,
            },
            RouteRule {
                targets: vec!["*.ads.example.com".to_string()],
                action: RouteAction::Block,
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
            },
            RouteRule {
                targets: vec!["port:6881-6889,6969".to_string()],
                action: RouteAction::Block,
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
}
