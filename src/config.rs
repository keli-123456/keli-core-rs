use std::collections::HashSet;
use std::fmt;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::config::RouteAction::{Block, Direct, Outbound};
use crate::protocol::Protocol;
use crate::reality::{decode_reality_private_key, decode_short_id};
use crate::shadowsocks::is_supported_shadowsocks_cipher;
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
    #[serde(default)]
    pub cipher: Option<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub flow: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub padding_scheme: Vec<String>,
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
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub up_mbps: u32,
    #[serde(default, skip_serializing_if = "is_zero_u32")]
    pub down_mbps: u32,
    #[serde(default, skip_serializing_if = "is_false")]
    pub ignore_client_bandwidth: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub obfs: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub obfs_password: Option<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub congestion_control: String,
    #[serde(default, skip_serializing_if = "is_false")]
    pub zero_rtt_handshake: bool,
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
        self.validate_outbounds()?;
        self.validate_routes()?;

        Ok(())
    }

    fn validate_outbounds(&self) -> Result<(), ValidationError> {
        for outbound in &self.outbounds {
            if outbound.tag.trim().is_empty() {
                return Err(ValidationError::new("outbound tag is required"));
            }
            if outbound.protocol.trim() != "freedom" {
                return Err(ValidationError::new(format!(
                    "outbound {} protocol {} is not implemented in keli-core-rs yet",
                    outbound.tag, outbound.protocol
                )));
            }
            if outbound.tag != "direct" {
                return Err(ValidationError::new(format!(
                    "outbound {} is not implemented in keli-core-rs yet",
                    outbound.tag
                )));
            }
            if outbound.address.is_some() || outbound.port.is_some() {
                return Err(ValidationError::new(format!(
                    "outbound {} address/port routing is not implemented in keli-core-rs yet",
                    outbound.tag
                )));
            }
        }
        Ok(())
    }

    fn validate_routes(&self) -> Result<(), ValidationError> {
        for route in &self.routes {
            validate_route_targets(route)?;
            match &route.action {
                Direct | Block => {}
                Outbound(tag) => {
                    return Err(ValidationError::new(format!(
                        "route outbound {tag} is not implemented in keli-core-rs yet"
                    )));
                }
            }
        }
        Ok(())
    }
}

fn validate_route_targets(route: &RouteRule) -> Result<(), ValidationError> {
    for target in &route.targets {
        let target = target.trim();
        if target.is_empty() {
            return Err(ValidationError::new("route target must not be empty"));
        }
        let normalized = target.to_ascii_lowercase();
        if let Some(rule) = normalized.strip_prefix("ip:") {
            if !is_supported_ip_route_rule(rule) {
                return Err(ValidationError::new(format!(
                    "route target {target} is not supported in keli-core-rs yet"
                )));
            }
            continue;
        }
        if let Some(rule) = normalized.strip_prefix("port:") {
            if !is_supported_port_route_rule(rule) {
                return Err(ValidationError::new(format!(
                    "route target {target} is not supported in keli-core-rs yet"
                )));
            }
            continue;
        }
        if let Some(rule) = normalized.strip_prefix("network:") {
            if !matches!(rule.trim(), "tcp" | "udp") {
                return Err(ValidationError::new(format!(
                    "route target {target} is not supported in keli-core-rs yet"
                )));
            }
            continue;
        }
        if let Some(rule) = normalized.strip_prefix("domain:") {
            if rule.trim().trim_start_matches('.').is_empty() {
                return Err(ValidationError::new(format!(
                    "route target {target} is not supported in keli-core-rs yet"
                )));
            }
            continue;
        }
        if let Some(rule) = normalized.strip_prefix("full:") {
            if rule.trim().trim_matches(['[', ']']).is_empty() {
                return Err(ValidationError::new(format!(
                    "route target {target} is not supported in keli-core-rs yet"
                )));
            }
            continue;
        }
        if let Some(rule) = normalized.strip_prefix("keyword:") {
            if rule.trim().is_empty() {
                return Err(ValidationError::new(format!(
                    "route target {target} is not supported in keli-core-rs yet"
                )));
            }
            continue;
        }
        if normalized.starts_with("geoip:")
            || normalized.starts_with("geosite:")
            || normalized.starts_with("regexp:")
            || normalized.starts_with("protocol:")
        {
            return Err(ValidationError::new(format!(
                "route target {target} is not supported in keli-core-rs yet"
            )));
        }
    }
    Ok(())
}

fn is_supported_ip_route_rule(rule: &str) -> bool {
    let rule = rule.trim().trim_matches(['[', ']']);
    if rule.parse::<IpAddr>().is_ok() {
        return true;
    }
    let Some((ip, prefix)) = rule.split_once('/') else {
        return false;
    };
    let Ok(ip) = ip.trim().parse::<IpAddr>() else {
        return false;
    };
    let Ok(prefix) = prefix.trim().parse::<u8>() else {
        return false;
    };
    match ip {
        IpAddr::V4(_) => prefix <= 32,
        IpAddr::V6(_) => prefix <= 128,
    }
}

fn is_supported_port_route_rule(rule: &str) -> bool {
    rule.split(',').all(|item| {
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
            return start <= end;
        }
        item.parse::<u16>().is_ok()
    })
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
        self.validate_protocol_scoped_fields()?;
        self.validate_flow()?;
        if matches!(self.protocol, Protocol::Socks | Protocol::Http) {
            let network = self.transport.network.trim();
            if network != "tcp" {
                return Err(ValidationError::new(format!(
                    "{} {} currently supports only tcp transport",
                    self.tag,
                    protocol_label(&self.protocol)
                )));
            }
            if self.tls.is_some() {
                return Err(ValidationError::new(format!(
                    "{} {} currently supports only plain tcp",
                    self.tag,
                    protocol_label(&self.protocol)
                )));
            }
        }
        if self.protocol == Protocol::Vless {
            let network = self.transport.network.trim();
            if !matches!(network, "tcp" | "ws" | "httpupgrade" | "grpc") {
                return Err(ValidationError::new(format!(
                    "{} vless currently supports only tcp/ws/httpupgrade/grpc transport",
                    self.tag
                )));
            }
            validate_tls_config("vless", &self.tag, network, self.tls.as_ref())?;
        }
        if self.protocol == Protocol::Vmess {
            let network = self.transport.network.trim();
            if !matches!(network, "tcp" | "ws" | "httpupgrade" | "grpc") {
                return Err(ValidationError::new(format!(
                    "{} vmess currently supports only tcp/ws/httpupgrade/grpc transport",
                    self.tag
                )));
            }
            validate_tls_config("vmess", &self.tag, network, self.tls.as_ref())?;
            if self.users.is_empty() {
                return Err(ValidationError::new(format!(
                    "{} vmess requires at least one user",
                    self.tag
                )));
            }
        }
        if self.protocol == Protocol::Trojan {
            let network = self.transport.network.trim();
            if !matches!(network, "tcp" | "ws" | "httpupgrade" | "grpc") {
                return Err(ValidationError::new(format!(
                    "{} trojan currently supports only tcp/ws/httpupgrade/grpc transport",
                    self.tag
                )));
            }
            validate_tls_config("trojan", &self.tag, network, self.tls.as_ref())?;
        }
        if self.protocol == Protocol::Shadowsocks {
            let network = self.transport.network.trim().to_ascii_lowercase();
            if !matches!(network.as_str(), "tcp" | "tcp,udp") || self.tls.is_some() {
                return Err(ValidationError::new(format!(
                    "{} shadowsocks currently supports only plain tcp or tcp,udp",
                    self.tag
                )));
            }
            if self.users.is_empty() {
                return Err(ValidationError::new(format!(
                    "{} shadowsocks requires at least one user",
                    self.tag
                )));
            }
            if self.cipher.as_deref().unwrap_or("").trim().is_empty() {
                return Err(ValidationError::new(format!(
                    "{} shadowsocks cipher is required",
                    self.tag
                )));
            }
            if !is_supported_shadowsocks_cipher(self.cipher.as_deref().unwrap_or("")) {
                return Err(ValidationError::new(format!(
                    "{} shadowsocks cipher {} is not supported",
                    self.tag,
                    self.cipher.as_deref().unwrap_or("")
                )));
            }
        }
        if self.protocol == Protocol::AnyTls {
            let network = self.transport.network.trim();
            if network != "tcp" || self.tls.is_some() {
                return Err(ValidationError::new(format!(
                    "{} anytls currently supports only plain tcp framing",
                    self.tag
                )));
            }
            if self.users.is_empty() {
                return Err(ValidationError::new(format!(
                    "{} anytls requires at least one user",
                    self.tag
                )));
            }
        }
        if self.protocol == Protocol::Tuic {
            let network = self.transport.network.trim();
            if network != "tuic" {
                return Err(ValidationError::new(format!(
                    "{} tuic currently requires tuic transport",
                    self.tag
                )));
            }
            validate_quic_tls_config("tuic", &self.tag, self.tls.as_ref())?;
            if self.users.is_empty() {
                return Err(ValidationError::new(format!(
                    "{} tuic requires at least one user",
                    self.tag
                )));
            }
            validate_tuic_transport_options(&self.tag, &self.transport)?;
        }
        if self.protocol == Protocol::Hysteria2 {
            let network = self.transport.network.trim();
            if !matches!(network, "hysteria" | "hysteria2") {
                return Err(ValidationError::new(format!(
                    "{} hysteria2 currently requires hysteria transport",
                    self.tag
                )));
            }
            validate_quic_tls_config("hysteria2", &self.tag, self.tls.as_ref())?;
            if self.users.is_empty() {
                return Err(ValidationError::new(format!(
                    "{} hysteria2 requires at least one user",
                    self.tag
                )));
            }
            if self.transport.ignore_client_bandwidth
                && (self.transport.up_mbps > 0 || self.transport.down_mbps > 0)
            {
                return Err(ValidationError::new(format!(
                    "{} hysteria2 ignore_client_bandwidth conflicts with up_mbps/down_mbps",
                    self.tag
                )));
            }
            validate_hysteria2_obfs(&self.tag, &self.transport)?;
        }

        Ok(())
    }

    fn validate_protocol_scoped_fields(&self) -> Result<(), ValidationError> {
        let protocol = protocol_label(&self.protocol);
        if self.protocol != Protocol::Shadowsocks
            && self
                .cipher
                .as_deref()
                .is_some_and(|cipher| !cipher.trim().is_empty())
        {
            return Err(ValidationError::new(format!(
                "{} {protocol} does not support cipher",
                self.tag
            )));
        }
        if self.protocol != Protocol::AnyTls && !self.padding_scheme.is_empty() {
            return Err(ValidationError::new(format!(
                "{} {protocol} does not support padding_scheme",
                self.tag
            )));
        }

        validate_protocol_transport_fields(self)?;
        Ok(())
    }

    fn validate_flow(&self) -> Result<(), ValidationError> {
        let flow = self.flow.trim();
        if flow.is_empty() {
            return Ok(());
        }
        if self.protocol != Protocol::Vless {
            return Err(ValidationError::new(format!(
                "{} flow {flow} is supported only for vless",
                self.tag
            )));
        }
        if flow != "xtls-rprx-vision" {
            return Err(ValidationError::new(format!(
                "{} vless flow {flow} is not supported",
                self.tag
            )));
        }
        let network = self.transport.network.trim();
        if network != "tcp" {
            return Err(ValidationError::new(format!(
                "{} vless vision currently requires tcp transport",
                self.tag
            )));
        }
        if self.tls.is_none() {
            return Err(ValidationError::new(format!(
                "{} vless vision requires tls",
                self.tag
            )));
        }
        Ok(())
    }
}

fn validate_protocol_transport_fields(inbound: &InboundConfig) -> Result<(), ValidationError> {
    let protocol = protocol_label(&inbound.protocol);
    let transport = &inbound.transport;
    let network = transport.network.trim();

    if transport.proxy_protocol {
        return Err(ValidationError::new(format!(
            "{} {protocol} proxy_protocol is not implemented in keli-core-rs yet",
            inbound.tag
        )));
    }

    let has_bandwidth_options =
        transport.up_mbps > 0 || transport.down_mbps > 0 || transport.ignore_client_bandwidth;
    let has_obfs_options = transport
        .obfs
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty())
        || transport
            .obfs_password
            .as_deref()
            .is_some_and(|value| !value.trim().is_empty());
    if inbound.protocol != Protocol::Hysteria2 && (has_bandwidth_options || has_obfs_options) {
        return Err(ValidationError::new(format!(
            "{} {protocol} does not support hysteria2 bandwidth/obfs transport options",
            inbound.tag
        )));
    }

    let has_tuic_options =
        !transport.congestion_control.trim().is_empty() || transport.zero_rtt_handshake;
    if inbound.protocol != Protocol::Tuic && has_tuic_options {
        return Err(ValidationError::new(format!(
            "{} {protocol} does not support tuic transport options",
            inbound.tag
        )));
    }

    let supports_http_transport_fields = matches!(
        inbound.protocol,
        Protocol::Vless | Protocol::Vmess | Protocol::Trojan
    ) && matches!(network, "ws" | "httpupgrade");
    let supports_grpc_service_name = matches!(
        inbound.protocol,
        Protocol::Vless | Protocol::Vmess | Protocol::Trojan
    ) && network == "grpc";
    if transport
        .path
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty())
        && !supports_http_transport_fields
    {
        return Err(ValidationError::new(format!(
            "{} {protocol} transport path is supported only for ws/httpupgrade",
            inbound.tag
        )));
    }
    if transport
        .host
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty())
        && !supports_http_transport_fields
    {
        return Err(ValidationError::new(format!(
            "{} {protocol} transport host is supported only for ws/httpupgrade",
            inbound.tag
        )));
    }
    if transport
        .service_name
        .as_deref()
        .is_some_and(|value| !value.trim().is_empty())
        && !supports_grpc_service_name
    {
        return Err(ValidationError::new(format!(
            "{} {protocol} transport service_name is supported only for grpc",
            inbound.tag
        )));
    }

    Ok(())
}

fn protocol_label(protocol: &Protocol) -> &'static str {
    match protocol {
        Protocol::Shadowsocks => "shadowsocks",
        Protocol::Vmess => "vmess",
        Protocol::Vless => "vless",
        Protocol::Trojan => "trojan",
        Protocol::Hysteria2 => "hysteria2",
        Protocol::Tuic => "tuic",
        Protocol::AnyTls => "anytls",
        Protocol::Socks => "socks",
        Protocol::Http => "http",
        Protocol::Naive => "naive",
        Protocol::Mieru => "mieru",
    }
}

fn validate_tls_config(
    protocol: &str,
    tag: &str,
    network: &str,
    tls: Option<&TlsConfig>,
) -> Result<(), ValidationError> {
    let Some(tls) = tls else {
        return Ok(());
    };
    if !matches!(network, "tcp" | "ws" | "httpupgrade" | "grpc") {
        return Err(ValidationError::new(format!(
            "{tag} {protocol} tls currently supports only tcp/ws/httpupgrade/grpc transport"
        )));
    }
    if tls.reality.is_some() {
        validate_reality_tls_config(protocol, tag, network, tls)?;
        return Ok(());
    }
    if tls.cert_file.as_deref().unwrap_or("").trim().is_empty()
        || tls.key_file.as_deref().unwrap_or("").trim().is_empty()
    {
        return Err(ValidationError::new(format!(
            "{tag} {protocol} tls requires cert_file and key_file"
        )));
    }
    if tls.reject_unknown_sni && tls.server_name.trim().is_empty() {
        return Err(ValidationError::new(format!(
            "{tag} {protocol} reject_unknown_sni requires server_name"
        )));
    }
    Ok(())
}

fn validate_reality_tls_config(
    protocol: &str,
    tag: &str,
    network: &str,
    tls: &TlsConfig,
) -> Result<(), ValidationError> {
    let reality = tls.reality.as_ref().expect("reality config exists");
    if protocol != "vless" {
        return Err(ValidationError::new(format!(
            "{tag} {protocol} reality currently supports only vless"
        )));
    }
    if network != "tcp" {
        return Err(ValidationError::new(format!(
            "{tag} vless reality currently requires tcp transport"
        )));
    }
    if tls.server_name.trim().is_empty() {
        return Err(ValidationError::new(format!(
            "{tag} vless reality requires server_name"
        )));
    }
    if reality.dest.trim().is_empty() {
        return Err(ValidationError::new(format!(
            "{tag} vless reality requires dest"
        )));
    }
    if !dest_has_explicit_port(&reality.dest) && reality.server_port.unwrap_or_default() == 0 {
        return Err(ValidationError::new(format!(
            "{tag} vless reality requires server_port when dest has no port"
        )));
    }
    decode_reality_private_key(&reality.private_key).map_err(|error| {
        ValidationError::new(format!(
            "{tag} vless reality private_key is invalid: {error}"
        ))
    })?;
    decode_short_id(&reality.short_id).map_err(|error| {
        ValidationError::new(format!("{tag} vless reality short_id is invalid: {error}"))
    })?;
    if reality.xver > 2 {
        return Err(ValidationError::new(format!(
            "{tag} vless reality xver must be 0, 1 or 2"
        )));
    }
    if reality
        .mldsa65_seed
        .as_deref()
        .is_some_and(|seed| !seed.trim().is_empty())
    {
        return Err(ValidationError::new(format!(
            "{tag} vless reality mldsa65_seed is not implemented in keli-core-rs yet"
        )));
    }
    Ok(())
}

fn dest_has_explicit_port(dest: &str) -> bool {
    let dest = dest.trim();
    if let Some(rest) = dest.strip_prefix('[') {
        return rest
            .split_once("]:")
            .and_then(|(_, port)| port.parse::<u16>().ok())
            .is_some();
    }
    if dest.matches(':').count() > 1 {
        return false;
    }
    dest.rsplit_once(':')
        .and_then(|(_, port)| port.parse::<u16>().ok())
        .is_some()
}

fn validate_quic_tls_config(
    protocol: &str,
    tag: &str,
    tls: Option<&TlsConfig>,
) -> Result<(), ValidationError> {
    let Some(tls) = tls else {
        return Err(ValidationError::new(format!(
            "{tag} {protocol} requires tls certificate files"
        )));
    };
    if tls.reality.is_some() {
        return Err(ValidationError::new(format!(
            "{tag} {protocol} reality is not implemented in keli-core-rs yet"
        )));
    }
    if tls.cert_file.as_deref().unwrap_or("").trim().is_empty()
        || tls.key_file.as_deref().unwrap_or("").trim().is_empty()
    {
        return Err(ValidationError::new(format!(
            "{tag} {protocol} requires cert_file and key_file"
        )));
    }
    if tls.reject_unknown_sni && tls.server_name.trim().is_empty() {
        return Err(ValidationError::new(format!(
            "{tag} {protocol} reject_unknown_sni requires server_name"
        )));
    }
    Ok(())
}

impl Default for TransportConfig {
    fn default() -> Self {
        Self {
            network: "tcp".to_string(),
            path: None,
            host: None,
            service_name: None,
            proxy_protocol: false,
            up_mbps: 0,
            down_mbps: 0,
            ignore_client_bandwidth: false,
            obfs: None,
            obfs_password: None,
            congestion_control: String::new(),
            zero_rtt_handshake: false,
        }
    }
}

fn validate_tuic_transport_options(
    tag: &str,
    transport: &TransportConfig,
) -> Result<(), ValidationError> {
    let congestion = transport.congestion_control.trim();
    if !congestion.is_empty() && !is_supported_tuic_congestion_control(congestion) {
        return Err(ValidationError::new(format!(
            "{tag} tuic congestion_control {congestion} is not supported"
        )));
    }
    if transport.zero_rtt_handshake {
        return Err(ValidationError::new(format!(
            "{tag} tuic zero_rtt_handshake is not supported yet"
        )));
    }
    Ok(())
}

fn is_supported_tuic_congestion_control(value: &str) -> bool {
    matches!(
        value
            .trim()
            .to_ascii_lowercase()
            .replace(['-', ' '], "_")
            .as_str(),
        "" | "cubic" | "bbr" | "new_reno" | "newreno" | "reno"
    )
}

fn validate_hysteria2_obfs(tag: &str, transport: &TransportConfig) -> Result<(), ValidationError> {
    let obfs = transport.obfs.as_deref().unwrap_or("").trim();
    let password = transport.obfs_password.as_deref().unwrap_or("").trim();
    if obfs.is_empty() && password.is_empty() {
        return Ok(());
    }
    if !obfs.eq_ignore_ascii_case("salamander") {
        return Err(ValidationError::new(format!(
            "{tag} hysteria2 only supports salamander obfs"
        )));
    }
    if password.len() < 4 {
        return Err(ValidationError::new(format!(
            "{tag} hysteria2 salamander obfs password must be at least 4 bytes"
        )));
    }
    Ok(())
}

fn is_zero_u32(value: &u32) -> bool {
    *value == 0
}

fn is_false(value: &bool) -> bool {
    !*value
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
        CoreConfig, InboundConfig, OutboundConfig, RealityConfig, SniffingConfig, StatsConfig,
        TlsConfig, TransportConfig,
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
                cipher: None,
                flow: String::new(),
                padding_scheme: Vec::new(),
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
    fn rejects_custom_outbounds_until_data_path_exists() {
        let mut config = CoreConfig {
            instance_id: "node-a".to_string(),
            log_level: "info".to_string(),
            inbounds: vec![InboundConfig {
                tag: "panel|vless|1".to_string(),
                protocol: Protocol::Vless,
                listen: "0.0.0.0".to_string(),
                port: 443,
                users: vec![user()],
                cipher: None,
                flow: String::new(),
                padding_scheme: Vec::new(),
                transport: TransportConfig::default(),
                tls: None,
                sniffing: SniffingConfig::default(),
            }],
            outbounds: vec![
                OutboundConfig {
                    tag: "direct".to_string(),
                    protocol: "freedom".to_string(),
                    address: None,
                    port: None,
                },
                OutboundConfig {
                    tag: "warp".to_string(),
                    protocol: "freedom".to_string(),
                    address: None,
                    port: None,
                },
            ],
            routes: Vec::new(),
            stats: StatsConfig::default(),
        };

        let error = config
            .validate()
            .expect_err("custom outbound should be rejected before runtime");
        assert!(error.to_string().contains("outbound warp"));

        config.outbounds.pop();
        config.routes = vec![crate::config::RouteRule {
            targets: vec!["*.example.test".to_string()],
            action: crate::config::RouteAction::Outbound("warp".to_string()),
        }];

        let error = config
            .validate()
            .expect_err("custom outbound routes should be rejected before runtime");
        assert!(error.to_string().contains("route outbound warp"));
    }

    #[test]
    fn validates_supported_route_targets_and_rejects_unsupported_sources() {
        let mut config = CoreConfig {
            instance_id: "node-a".to_string(),
            log_level: "info".to_string(),
            inbounds: vec![InboundConfig {
                tag: "panel|http|1".to_string(),
                protocol: Protocol::Http,
                listen: "0.0.0.0".to_string(),
                port: 8080,
                users: vec![user()],
                cipher: None,
                flow: String::new(),
                padding_scheme: Vec::new(),
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
            routes: vec![crate::config::RouteRule {
                targets: vec![
                    "domain:example.com".to_string(),
                    "full:exact.example.com".to_string(),
                    "keyword:tracker".to_string(),
                    "ip:10.0.0.0/8".to_string(),
                    "port:6881-6889,6969".to_string(),
                    "network:udp".to_string(),
                ],
                action: crate::config::RouteAction::Block,
            }],
            stats: StatsConfig::default(),
        };

        config.validate().expect("supported route targets");

        config.routes[0].targets = vec!["geosite:private".to_string()];
        let error = config
            .validate()
            .expect_err("geosite route target should fail");
        assert!(error.to_string().contains("geosite:private"));

        config.routes[0].targets = vec!["ip:geoip:private".to_string()];
        let error = config
            .validate()
            .expect_err("geoip route target should fail");
        assert!(error.to_string().contains("ip:geoip:private"));

        config.routes[0].targets = vec!["keyword:".to_string()];
        let error = config
            .validate()
            .expect_err("empty keyword route target should fail");
        assert!(error.to_string().contains("keyword:"));
    }

    #[test]
    fn validates_stream_transports_for_vless_vmess_and_trojan() {
        for (protocol, network) in [
            (Protocol::Vless, "ws"),
            (Protocol::Vmess, "ws"),
            (Protocol::Trojan, "ws"),
            (Protocol::Vless, "httpupgrade"),
            (Protocol::Vmess, "httpupgrade"),
            (Protocol::Trojan, "httpupgrade"),
        ] {
            let inbound = InboundConfig {
                tag: format!("panel|{network}|1"),
                protocol,
                listen: "0.0.0.0".to_string(),
                port: 443,
                users: vec![user()],
                cipher: None,
                flow: String::new(),
                padding_scheme: Vec::new(),
                transport: TransportConfig {
                    network: network.to_string(),
                    path: Some("/edge".to_string()),
                    host: Some("example.com".to_string()),
                    ..TransportConfig::default()
                },
                tls: None,
                sniffing: SniffingConfig::default(),
            };

            inbound.validate().expect("http transport inbound");
        }

        for protocol in [Protocol::Vless, Protocol::Vmess, Protocol::Trojan] {
            let inbound = InboundConfig {
                tag: "panel|grpc|1".to_string(),
                protocol,
                listen: "0.0.0.0".to_string(),
                port: 443,
                users: vec![user()],
                cipher: None,
                flow: String::new(),
                padding_scheme: Vec::new(),
                transport: TransportConfig {
                    network: "grpc".to_string(),
                    service_name: Some("GunService".to_string()),
                    ..TransportConfig::default()
                },
                tls: None,
                sniffing: SniffingConfig::default(),
            };

            inbound.validate().expect("grpc transport inbound");
        }
    }

    #[test]
    fn rejects_transport_fields_that_runtime_would_ignore() {
        let mut inbound = InboundConfig {
            tag: "panel|vless|1".to_string(),
            protocol: Protocol::Vless,
            listen: "0.0.0.0".to_string(),
            port: 443,
            users: vec![user()],
            cipher: Some("aes-128-gcm".to_string()),
            flow: String::new(),
            padding_scheme: Vec::new(),
            transport: TransportConfig::default(),
            tls: None,
            sniffing: SniffingConfig::default(),
        };

        let error = inbound
            .validate()
            .expect_err("non-shadowsocks cipher should be rejected");
        assert!(error.to_string().contains("does not support cipher"));

        inbound.cipher = None;
        inbound.padding_scheme = vec!["stop=8".to_string()];
        let error = inbound
            .validate()
            .expect_err("non-anytls padding should be rejected");
        assert!(error.to_string().contains("padding_scheme"));

        inbound.padding_scheme.clear();
        inbound.transport.proxy_protocol = true;
        let error = inbound
            .validate()
            .expect_err("proxy protocol should be rejected until implemented");
        assert!(error.to_string().contains("proxy_protocol"));

        inbound.transport.proxy_protocol = false;
        inbound.transport.up_mbps = 100;
        let error = inbound
            .validate()
            .expect_err("non-hysteria2 bandwidth should be rejected");
        assert!(error.to_string().contains("bandwidth/obfs"));

        inbound.transport.up_mbps = 0;
        inbound.transport.congestion_control = "bbr".to_string();
        let error = inbound
            .validate()
            .expect_err("non-tuic congestion should be rejected");
        assert!(error.to_string().contains("tuic transport options"));
    }

    #[test]
    fn rejects_transport_field_on_wrong_network() {
        let mut inbound = InboundConfig {
            tag: "panel|vless|1".to_string(),
            protocol: Protocol::Vless,
            listen: "0.0.0.0".to_string(),
            port: 443,
            users: vec![user()],
            cipher: None,
            flow: String::new(),
            padding_scheme: Vec::new(),
            transport: TransportConfig {
                network: "tcp".to_string(),
                path: Some("/edge".to_string()),
                ..TransportConfig::default()
            },
            tls: None,
            sniffing: SniffingConfig::default(),
        };

        let error = inbound.validate().expect_err("tcp path should be rejected");
        assert!(error.to_string().contains("transport path"));

        inbound.transport.network = "ws".to_string();
        inbound.transport.path = None;
        inbound.transport.service_name = Some("GunService".to_string());
        let error = inbound
            .validate()
            .expect_err("ws service_name should be rejected");
        assert!(error.to_string().contains("service_name"));

        inbound.transport.network = "grpc".to_string();
        inbound.transport.service_name = None;
        inbound.transport.host = Some("example.com".to_string());
        let error = inbound
            .validate()
            .expect_err("grpc host should be rejected");
        assert!(error.to_string().contains("transport host"));
    }

    #[test]
    fn rejects_plain_proxy_tls_and_non_tcp_transport() {
        let mut inbound = InboundConfig {
            tag: "panel|socks|1".to_string(),
            protocol: Protocol::Socks,
            listen: "0.0.0.0".to_string(),
            port: 1080,
            users: vec![user()],
            cipher: None,
            flow: String::new(),
            padding_scheme: Vec::new(),
            transport: TransportConfig {
                network: "ws".to_string(),
                ..TransportConfig::default()
            },
            tls: None,
            sniffing: SniffingConfig::default(),
        };

        let error = inbound.validate().expect_err("socks ws should be rejected");
        assert!(error.to_string().contains("only tcp transport"));

        inbound.transport.network = "tcp".to_string();
        inbound.tls = Some(TlsConfig {
            server_name: "example.com".to_string(),
            cert_file: Some("/tmp/cert.pem".to_string()),
            key_file: Some("/tmp/key.pem".to_string()),
            alpn: Vec::new(),
            reject_unknown_sni: false,
            reality: None,
        });
        let error = inbound
            .validate()
            .expect_err("socks tls should be rejected");
        assert!(error.to_string().contains("plain tcp"));
    }

    #[test]
    fn rejects_sidecar_protocols_in_core_plan() {
        let inbound = InboundConfig {
            tag: "panel|naive|1".to_string(),
            protocol: Protocol::Naive,
            listen: "0.0.0.0".to_string(),
            port: 443,
            users: vec![user()],
            cipher: None,
            flow: String::new(),
            padding_scheme: Vec::new(),
            transport: TransportConfig::default(),
            tls: None,
            sniffing: SniffingConfig::default(),
        };

        assert!(inbound.validate().is_err());
    }

    #[test]
    fn rejects_vless_tls_without_certificate_files() {
        let inbound = InboundConfig {
            tag: "panel|vless|1".to_string(),
            protocol: Protocol::Vless,
            listen: "0.0.0.0".to_string(),
            port: 443,
            users: vec![user()],
            cipher: None,
            flow: String::new(),
            padding_scheme: Vec::new(),
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
            .expect_err("vless tls without certificate files should fail");

        assert!(error.to_string().contains("cert_file and key_file"));
    }

    #[test]
    fn rejects_trojan_tls_without_certificate_files() {
        let inbound = InboundConfig {
            tag: "panel|trojan|1".to_string(),
            protocol: Protocol::Trojan,
            listen: "0.0.0.0".to_string(),
            port: 443,
            users: vec![user()],
            cipher: None,
            flow: String::new(),
            padding_scheme: Vec::new(),
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
            .expect_err("trojan tls without certificate files should fail");

        assert!(error.to_string().contains("cert_file and key_file"));
    }

    #[test]
    fn validates_vless_vision_flow_only_for_tcp_tls() {
        let mut inbound = InboundConfig {
            tag: "panel|vless|1".to_string(),
            protocol: Protocol::Vless,
            listen: "0.0.0.0".to_string(),
            port: 443,
            users: vec![user()],
            cipher: None,
            flow: "xtls-rprx-vision".to_string(),
            padding_scheme: Vec::new(),
            transport: TransportConfig::default(),
            tls: Some(TlsConfig {
                server_name: "example.com".to_string(),
                cert_file: Some("/tmp/cert.pem".to_string()),
                key_file: Some("/tmp/key.pem".to_string()),
                alpn: Vec::new(),
                reject_unknown_sni: false,
                reality: None,
            }),
            sniffing: SniffingConfig::default(),
        };

        inbound.validate().expect("vless vision tcp tls");

        inbound.transport.network = "ws".to_string();
        let error = inbound.validate().expect_err("vless vision ws should fail");
        assert!(error.to_string().contains("requires tcp transport"));
    }

    #[test]
    fn validates_vless_reality_without_certificate_files() {
        let inbound = InboundConfig {
            tag: "panel|vless|reality|1".to_string(),
            protocol: Protocol::Vless,
            listen: "0.0.0.0".to_string(),
            port: 443,
            users: vec![user()],
            cipher: None,
            flow: "xtls-rprx-vision".to_string(),
            padding_scheme: Vec::new(),
            transport: TransportConfig::default(),
            tls: Some(TlsConfig {
                server_name: "www.example.com".to_string(),
                cert_file: None,
                key_file: None,
                alpn: Vec::new(),
                reject_unknown_sni: false,
                reality: Some(RealityConfig {
                    dest: "www.example.com:443".to_string(),
                    server_port: None,
                    private_key: "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc".to_string(),
                    short_id: "6ba85179e30d4fc2".to_string(),
                    xver: 0,
                    mldsa65_seed: None,
                }),
            }),
            sniffing: SniffingConfig::default(),
        };

        inbound.validate().expect("vless reality config");
    }

    #[test]
    fn validates_vless_reality_ipv6_dest_with_separate_port() {
        let inbound = InboundConfig {
            tag: "panel|vless|reality|1".to_string(),
            protocol: Protocol::Vless,
            listen: "0.0.0.0".to_string(),
            port: 443,
            users: vec![user()],
            cipher: None,
            flow: "xtls-rprx-vision".to_string(),
            padding_scheme: Vec::new(),
            transport: TransportConfig::default(),
            tls: Some(TlsConfig {
                server_name: "www.example.com".to_string(),
                cert_file: None,
                key_file: None,
                alpn: Vec::new(),
                reject_unknown_sni: false,
                reality: Some(RealityConfig {
                    dest: "2607:f358:1a:e::d4d9:5831".to_string(),
                    server_port: Some(443),
                    private_key: "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc".to_string(),
                    short_id: "6ba85179e30d4fc2".to_string(),
                    xver: 0,
                    mldsa65_seed: None,
                }),
            }),
            sniffing: SniffingConfig::default(),
        };

        inbound.validate().expect("vless reality ipv6 dest");
    }

    #[test]
    fn rejects_vless_reality_on_non_tcp_transport() {
        let inbound = InboundConfig {
            tag: "panel|vless|reality|1".to_string(),
            protocol: Protocol::Vless,
            listen: "0.0.0.0".to_string(),
            port: 443,
            users: vec![user()],
            cipher: None,
            flow: String::new(),
            padding_scheme: Vec::new(),
            transport: TransportConfig {
                network: "ws".to_string(),
                ..TransportConfig::default()
            },
            tls: Some(TlsConfig {
                server_name: "www.example.com".to_string(),
                cert_file: None,
                key_file: None,
                alpn: Vec::new(),
                reject_unknown_sni: false,
                reality: Some(RealityConfig {
                    dest: "www.example.com:443".to_string(),
                    server_port: None,
                    private_key: "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc".to_string(),
                    short_id: "6ba85179e30d4fc2".to_string(),
                    xver: 0,
                    mldsa65_seed: None,
                }),
            }),
            sniffing: SniffingConfig::default(),
        };

        let error = inbound
            .validate()
            .expect_err("vless reality ws should fail");

        assert!(error.to_string().contains("requires tcp transport"));
    }

    #[test]
    fn rejects_invalid_vless_reality_keys() {
        let inbound = InboundConfig {
            tag: "panel|vless|reality|1".to_string(),
            protocol: Protocol::Vless,
            listen: "0.0.0.0".to_string(),
            port: 443,
            users: vec![user()],
            cipher: None,
            flow: String::new(),
            padding_scheme: Vec::new(),
            transport: TransportConfig::default(),
            tls: Some(TlsConfig {
                server_name: "www.example.com".to_string(),
                cert_file: None,
                key_file: None,
                alpn: Vec::new(),
                reject_unknown_sni: false,
                reality: Some(RealityConfig {
                    dest: "www.example.com:443".to_string(),
                    server_port: None,
                    private_key: "not-a-key".to_string(),
                    short_id: "6ba85179e30d4fc2".to_string(),
                    xver: 0,
                    mldsa65_seed: None,
                }),
            }),
            sniffing: SniffingConfig::default(),
        };

        let error = inbound
            .validate()
            .expect_err("vless reality key should fail");

        assert!(error.to_string().contains("private_key is invalid"));
    }

    #[test]
    fn rejects_unimplemented_vless_reality_mldsa_seed() {
        let inbound = InboundConfig {
            tag: "panel|vless|reality|1".to_string(),
            protocol: Protocol::Vless,
            listen: "0.0.0.0".to_string(),
            port: 443,
            users: vec![user()],
            cipher: None,
            flow: String::new(),
            padding_scheme: Vec::new(),
            transport: TransportConfig::default(),
            tls: Some(TlsConfig {
                server_name: "www.example.com".to_string(),
                cert_file: None,
                key_file: None,
                alpn: Vec::new(),
                reject_unknown_sni: false,
                reality: Some(RealityConfig {
                    dest: "www.example.com:443".to_string(),
                    server_port: None,
                    private_key: "BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc".to_string(),
                    short_id: "6ba85179e30d4fc2".to_string(),
                    xver: 0,
                    mldsa65_seed: Some("seed".to_string()),
                }),
            }),
            sniffing: SniffingConfig::default(),
        };

        let error = inbound
            .validate()
            .expect_err("vless reality mldsa seed should fail");

        assert!(error
            .to_string()
            .contains("mldsa65_seed is not implemented"));
    }

    #[test]
    fn rejects_shadowsocks_without_cipher() {
        let inbound = InboundConfig {
            tag: "panel|shadowsocks|1".to_string(),
            protocol: Protocol::Shadowsocks,
            listen: "0.0.0.0".to_string(),
            port: 8388,
            users: vec![user()],
            cipher: None,
            flow: String::new(),
            padding_scheme: Vec::new(),
            transport: TransportConfig::default(),
            tls: None,
            sniffing: SniffingConfig::default(),
        };

        let error = inbound
            .validate()
            .expect_err("shadowsocks cipher should be required");

        assert!(error.to_string().contains("cipher is required"));
    }

    #[test]
    fn validates_shadowsocks_tcp_udp_transport() {
        let inbound = InboundConfig {
            tag: "panel|shadowsocks|1".to_string(),
            protocol: Protocol::Shadowsocks,
            listen: "0.0.0.0".to_string(),
            port: 8388,
            users: vec![user()],
            cipher: Some("aes-128-gcm".to_string()),
            flow: String::new(),
            padding_scheme: Vec::new(),
            transport: TransportConfig {
                network: "tcp,udp".to_string(),
                ..TransportConfig::default()
            },
            tls: None,
            sniffing: SniffingConfig::default(),
        };

        inbound.validate().expect("shadowsocks tcp,udp");
    }

    #[test]
    fn validates_tuic_supported_congestion_controls() {
        for congestion in ["cubic", "bbr", "new-reno"] {
            let inbound = InboundConfig {
                tag: "panel|tuic|1".to_string(),
                protocol: Protocol::Tuic,
                listen: "0.0.0.0".to_string(),
                port: 443,
                users: vec![user()],
                cipher: None,
                flow: String::new(),
                padding_scheme: Vec::new(),
                transport: TransportConfig {
                    network: "tuic".to_string(),
                    congestion_control: congestion.to_string(),
                    ..TransportConfig::default()
                },
                tls: Some(TlsConfig {
                    server_name: "tuic.example.test".to_string(),
                    cert_file: Some("/tmp/tuic.crt".to_string()),
                    key_file: Some("/tmp/tuic.key".to_string()),
                    alpn: vec!["h3".to_string()],
                    reject_unknown_sni: false,
                    reality: None,
                }),
                sniffing: SniffingConfig::default(),
            };

            inbound.validate().expect("tuic congestion should validate");
        }
    }

    #[test]
    fn rejects_tuic_unsupported_congestion_control() {
        let inbound = InboundConfig {
            tag: "panel|tuic|1".to_string(),
            protocol: Protocol::Tuic,
            listen: "0.0.0.0".to_string(),
            port: 443,
            users: vec![user()],
            cipher: None,
            flow: String::new(),
            padding_scheme: Vec::new(),
            transport: TransportConfig {
                network: "tuic".to_string(),
                congestion_control: "brutal".to_string(),
                ..TransportConfig::default()
            },
            tls: Some(TlsConfig {
                server_name: "tuic.example.test".to_string(),
                cert_file: Some("/tmp/tuic.crt".to_string()),
                key_file: Some("/tmp/tuic.key".to_string()),
                alpn: vec!["h3".to_string()],
                reject_unknown_sni: false,
                reality: None,
            }),
            sniffing: SniffingConfig::default(),
        };

        let error = inbound
            .validate()
            .expect_err("unsupported tuic congestion should fail");

        assert!(error.to_string().contains("congestion_control brutal"));
    }

    #[test]
    fn rejects_tuic_zero_rtt_until_runtime_supports_it() {
        let inbound = InboundConfig {
            tag: "panel|tuic|1".to_string(),
            protocol: Protocol::Tuic,
            listen: "0.0.0.0".to_string(),
            port: 443,
            users: vec![user()],
            cipher: None,
            flow: String::new(),
            padding_scheme: Vec::new(),
            transport: TransportConfig {
                network: "tuic".to_string(),
                zero_rtt_handshake: true,
                ..TransportConfig::default()
            },
            tls: Some(TlsConfig {
                server_name: "tuic.example.test".to_string(),
                cert_file: Some("/tmp/tuic.crt".to_string()),
                key_file: Some("/tmp/tuic.key".to_string()),
                alpn: vec!["h3".to_string()],
                reject_unknown_sni: false,
                reality: None,
            }),
            sniffing: SniffingConfig::default(),
        };

        let error = inbound
            .validate()
            .expect_err("tuic zero-rtt should fail until implemented");

        assert!(error.to_string().contains("zero_rtt_handshake"));
    }

    #[test]
    fn rejects_anytls_without_users() {
        let inbound = InboundConfig {
            tag: "panel|anytls|1".to_string(),
            protocol: Protocol::AnyTls,
            listen: "0.0.0.0".to_string(),
            port: 8443,
            users: Vec::new(),
            cipher: None,
            flow: String::new(),
            padding_scheme: Vec::new(),
            transport: TransportConfig::default(),
            tls: None,
            sniffing: SniffingConfig::default(),
        };

        let error = inbound
            .validate()
            .expect_err("anytls users should be required");

        assert!(error.to_string().contains("requires at least one user"));
    }
}
