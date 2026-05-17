use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    #[serde(rename = "shadowsocks")]
    Shadowsocks,
    Vmess,
    Vless,
    Trojan,
    #[serde(rename = "hysteria2", alias = "hysteria")]
    Hysteria2,
    Tuic,
    #[serde(rename = "anytls")]
    AnyTls,
    Socks,
    Http,
    Naive,
    Mieru,
}

#[cfg(test)]
mod tests {
    use super::Protocol;

    #[test]
    fn deserializes_native_protocols() {
        assert!(matches!(
            serde_json::from_str::<Protocol>("\"naive\"").expect("naive"),
            Protocol::Naive
        ));
        assert!(matches!(
            serde_json::from_str::<Protocol>("\"mieru\"").expect("mieru"),
            Protocol::Mieru
        ));
        assert!(matches!(
            serde_json::from_str::<Protocol>("\"vless\"").expect("vless"),
            Protocol::Vless
        ));
    }
}
