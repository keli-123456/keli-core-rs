use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    #[serde(rename = "shadowsocks")]
    Shadowsocks,
    Vmess,
    Vless,
    Trojan,
    #[serde(rename = "hysteria2")]
    Hysteria2,
    Tuic,
    #[serde(rename = "anytls")]
    AnyTls,
    Socks,
    Http,
    Naive,
    Mieru,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProtocolPlacement {
    CorePlanned,
    ExternalSidecar,
}

impl Protocol {
    pub fn placement(&self) -> ProtocolPlacement {
        match self {
            Protocol::Naive | Protocol::Mieru => ProtocolPlacement::ExternalSidecar,
            Protocol::Shadowsocks
            | Protocol::Vmess
            | Protocol::Vless
            | Protocol::Trojan
            | Protocol::Hysteria2
            | Protocol::Tuic
            | Protocol::AnyTls
            | Protocol::Socks
            | Protocol::Http => ProtocolPlacement::CorePlanned,
        }
    }

    pub fn can_enter_core_plan(&self) -> bool {
        self.placement() == ProtocolPlacement::CorePlanned
    }
}

#[cfg(test)]
mod tests {
    use super::{Protocol, ProtocolPlacement};

    #[test]
    fn separates_external_sidecar_protocols() {
        assert_eq!(
            Protocol::Naive.placement(),
            ProtocolPlacement::ExternalSidecar
        );
        assert_eq!(
            Protocol::Mieru.placement(),
            ProtocolPlacement::ExternalSidecar
        );
        assert!(Protocol::Vless.can_enter_core_plan());
    }
}
