use std::collections::HashSet;
use std::fmt;

use serde::{Deserialize, Serialize};

use crate::protocol::Protocol;
use crate::user::CoreUser;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreConfig {
    pub instance_id: String,
    pub log_level: String,
    pub inbounds: Vec<InboundConfig>,
    pub outbounds: Vec<OutboundConfig>,
    pub routes: Vec<RouteRule>,
    pub stats: StatsConfig,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct InboundConfig {
    pub tag: String,
    pub protocol: Protocol,
    pub listen: String,
    pub port: u16,
    pub users: Vec<CoreUser>,
    pub transport: TransportConfig,
    pub tls: Option<TlsConfig>,
    pub sniffing: SniffingConfig,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutboundConfig {
    pub tag: String,
    pub protocol: String,
    pub address: Option<String>,
    pub port: Option<u16>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RouteRule {
    pub targets: Vec<String>,
    pub action: RouteAction,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RouteAction {
    Direct,
    Block,
    Outbound(String),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportConfig {
    pub network: String,
    pub path: Option<String>,
    pub host: Option<String>,
    pub service_name: Option<String>,
    pub proxy_protocol: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TlsConfig {
    pub server_name: String,
    pub cert_file: Option<String>,
    pub key_file: Option<String>,
    pub alpn: Vec<String>,
    pub reject_unknown_sni: bool,
    pub reality: Option<RealityConfig>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RealityConfig {
    pub dest: String,
    pub server_port: Option<u16>,
    pub private_key: String,
    pub short_id: String,
    pub xver: u32,
    pub mldsa65_seed: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SniffingConfig {
    pub enabled: bool,
    pub dest_override: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct StatsConfig {
    pub enabled: bool,
    pub per_user: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidationError {
    message: String,
}

impl ValidationError {
    pub fn new(message: impl Into<String>) -> Self {
        Self {
            message: message.into(),
        }
    }
}

impl fmt::Display for ValidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for ValidationError {}

impl CoreConfig {
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.instance_id.trim().is_empty() {
            return Err(ValidationError::new("instance_id is required"));
        }
        if self.inbounds.is_empty() {
            return Err(ValidationError::new("at least one inbound is required"));
        }

        let mut tags = HashSet::new();
        for inbound in &self.inbounds {
            inbound.validate()?;
            if !tags.insert(inbound.tag.as_str()) {
                return Err(ValidationError::new(format!(
                    "duplicate inbound tag: {}",
                    inbound.tag
                )));
            }
        }

        Ok(())
    }
}

impl InboundConfig {
    pub fn validate(&self) -> Result<(), ValidationError> {
        if self.tag.trim().is_empty() {
            return Err(ValidationError::new("inbound tag is required"));
        }
        if self.listen.trim().is_empty() {
            return Err(ValidationError::new(format!(
                "{} listen address is required",
                self.tag
            )));
        }
        if self.port == 0 {
            return Err(ValidationError::new(format!(
                "{} port is required",
                self.tag
            )));
        }
        if !self.protocol.can_enter_core_plan() {
            return Err(ValidationError::new(format!(
                "{} is an external sidecar protocol and must not be faked inside keli-core-rs",
                self.tag
            )));
        }
        if self.users.iter().any(CoreUser::is_empty) {
            return Err(ValidationError::new(format!(
                "{} contains an empty user uuid",
                self.tag
            )));
        }
        if self.protocol == Protocol::Vless {
            let network = self.transport.network.trim();
            if network != "tcp" || self.tls.is_some() {
                return Err(ValidationError::new(format!(
                    "{} vless currently supports only plain tcp without tls/reality",
                    self.tag
                )));
            }
        }

        Ok(())
    }
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            network: "tcp".to_string(),
            path: None,
            host: None,
            service_name: None,
            proxy_protocol: false,
        }
    }
}

impl Default for SniffingConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            dest_override: vec!["http".to_string(), "tls".to_string()],
        }
    }
}

impl Default for StatsConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            per_user: true,
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::protocol::Protocol;
    use crate::user::CoreUser;

    use super::{
        CoreConfig, InboundConfig, OutboundConfig, SniffingConfig, StatsConfig, TlsConfig,
        TransportConfig,
    };

    fn user() -> CoreUser {
        CoreUser {
            id: 1,
            uuid: "user-a".to_string(),
            password: None,
            email: None,
            speed_limit: 0,
            device_limit: 0,
        }
    }

    #[test]
    fn validates_basic_core_plan() {
        let config = CoreConfig {
            instance_id: "node-a".to_string(),
            log_level: "info".to_string(),
            inbounds: vec![InboundConfig {
                tag: "panel|vless|1".to_string(),
                protocol: Protocol::Vless,
                listen: "0.0.0.0".to_string(),
                port: 443,
                users: vec![user()],
                transport: TransportConfig::default(),
                tls: None,
                sniffing: SniffingConfig::default(),
            }],
            outbounds: vec![OutboundConfig {
                tag: "direct".to_string(),
                protocol: "freedom".to_string(),
                address: None,
                port: None,
            }],
            routes: Vec::new(),
            stats: StatsConfig::default(),
        };

        assert!(config.validate().is_ok());
    }

    #[test]
    fn rejects_sidecar_protocols_in_core_plan() {
        let inbound = InboundConfig {
            tag: "panel|naive|1".to_string(),
            protocol: Protocol::Naive,
            listen: "0.0.0.0".to_string(),
            port: 443,
            users: vec![user()],
            transport: TransportConfig::default(),
            tls: None,
            sniffing: SniffingConfig::default(),
        };

        assert!(inbound.validate().is_err());
    }

    #[test]
    fn rejects_vless_tls_until_data_path_supports_it() {
        let inbound = InboundConfig {
            tag: "panel|vless|1".to_string(),
            protocol: Protocol::Vless,
            listen: "0.0.0.0".to_string(),
            port: 443,
            users: vec![user()],
            transport: TransportConfig::default(),
            tls: Some(TlsConfig {
                server_name: "example.com".to_string(),
                cert_file: None,
                key_file: None,
                alpn: Vec::new(),
                reject_unknown_sni: false,
                reality: None,
            }),
            sniffing: SniffingConfig::default(),
        };

        let error = inbound
            .validate()
            .expect_err("vless tls should not be accepted yet");

        assert!(error.to_string().contains("plain tcp"));
    }
}
