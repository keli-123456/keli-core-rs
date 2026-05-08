use serde::{Deserialize, Serialize};

use crate::config::{CoreConfig, ValidationError};
use crate::traffic::{TrafficDelta, TrafficRegistry};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CoreStatus {
    Stopped,
    Running,
    Reloading,
    Failed(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CorePlan {
    pub fingerprint: String,
    pub config: CoreConfig,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReloadDecision {
    Noop,
    Reloaded,
}

#[derive(Clone, Debug)]
pub struct RuntimeState {
    active_fingerprint: Option<String>,
    status: CoreStatus,
    traffic: TrafficRegistry,
}

impl RuntimeState {
    pub fn new() -> Self {
        Self {
            active_fingerprint: None,
            status: CoreStatus::Stopped,
            traffic: TrafficRegistry::default(),
        }
    }

    pub fn status(&self) -> &CoreStatus {
        &self.status
    }

    pub fn plan(config: CoreConfig) -> Result<CorePlan, ValidationError> {
        config.validate()?;
        Ok(CorePlan {
            fingerprint: fingerprint_config(&config),
            config,
        })
    }

    pub fn apply_plan(&mut self, plan: CorePlan) -> ReloadDecision {
        if self.active_fingerprint.as_deref() == Some(plan.fingerprint.as_str()) {
            self.status = CoreStatus::Running;
            return ReloadDecision::Noop;
        }

        self.status = CoreStatus::Reloading;
        self.active_fingerprint = Some(plan.fingerprint);
        self.status = CoreStatus::Running;
        ReloadDecision::Reloaded
    }

    pub fn needs_reload(&self, plan: &CorePlan) -> bool {
        self.active_fingerprint.as_deref() != Some(plan.fingerprint.as_str())
    }

    pub fn fail(&mut self, message: impl Into<String>) {
        self.status = CoreStatus::Failed(message.into());
    }

    pub fn stop(&mut self) {
        self.active_fingerprint = None;
        self.status = CoreStatus::Stopped;
    }

    pub fn record_traffic(
        &mut self,
        node_tag: impl Into<String>,
        user_uuid: impl Into<String>,
        upload: u64,
        download: u64,
    ) {
        self.traffic.add(node_tag, user_uuid, upload, download);
    }

    pub fn drain_traffic(&mut self, minimum_bytes: u64) -> Vec<TrafficDelta> {
        self.traffic.drain_minimum(minimum_bytes)
    }
}

impl Default for RuntimeState {
    fn default() -> Self {
        Self::new()
    }
}

fn fingerprint_config(config: &CoreConfig) -> String {
    let body = serde_json::to_vec(config).unwrap_or_default();
    format!("{:016x}", fnv1a64(&body))
}

fn fnv1a64(bytes: &[u8]) -> u64 {
    let mut hash = 0xcbf29ce484222325u64;
    for byte in bytes {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100000001b3);
    }
    hash
}

#[cfg(test)]
mod tests {
    use crate::config::{
        CoreConfig, DnsConfig, InboundConfig, OutboundConfig, SniffingConfig, StatsConfig,
        TransportConfig,
    };
    use crate::protocol::Protocol;
    use crate::runtime::{ReloadDecision, RuntimeState};
    use crate::user::CoreUser;

    fn config() -> CoreConfig {
        CoreConfig {
            instance_id: "node-a".to_string(),
            log_level: "info".to_string(),
            dns: DnsConfig::default(),
            inbounds: vec![InboundConfig {
                tag: "panel|socks|1".to_string(),
                protocol: Protocol::Socks,
                listen: "127.0.0.1".to_string(),
                port: 1080,
                users: vec![CoreUser {
                    id: 1,
                    uuid: "user-a".to_string(),
                    password: None,
                    email: None,
                    speed_limit: 0,
                    device_limit: 0,
                }],
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
                username: None,
                password: None,
            }],
            routes: Vec::new(),
            stats: StatsConfig::default(),
        }
    }

    #[test]
    fn applies_reload_only_when_fingerprint_changes() {
        let plan = RuntimeState::plan(config()).expect("plan");
        let same_plan = RuntimeState::plan(config()).expect("same plan");
        let mut state = RuntimeState::new();

        assert_eq!(state.apply_plan(plan), ReloadDecision::Reloaded);
        assert_eq!(state.apply_plan(same_plan), ReloadDecision::Noop);
    }
}
