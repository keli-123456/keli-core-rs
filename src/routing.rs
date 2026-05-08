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
        let host = host.trim().trim_matches(['[', ']']).to_ascii_lowercase();
        for route in &self.routes {
            if route
                .targets
                .iter()
                .any(|target| matches_target(&host, target))
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

fn matches_target(host: &str, target: &str) -> bool {
    let target = target.trim().to_ascii_lowercase();
    if target.is_empty() {
        return false;
    }
    if target == "*" {
        return true;
    }
    if let Some(suffix) = target.strip_prefix("*.") {
        return host == suffix || host.ends_with(&format!(".{suffix}"));
    }
    if let Some(suffix) = target.strip_prefix('.') {
        return host == suffix || host.ends_with(&format!(".{suffix}"));
    }
    host == target
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
}
