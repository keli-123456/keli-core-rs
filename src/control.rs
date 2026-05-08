use serde::{Deserialize, Serialize};

use crate::config::CoreConfig;
use crate::runtime::{CoreStatus, ReloadDecision, RuntimeState};
use crate::service::{CoreService, ListenerStatus};
use crate::traffic::TrafficDelta;

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CoreCommand {
    ApplyConfig { config: CoreConfig },
    DrainTraffic { minimum_bytes: u64 },
    Status,
    Stop,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CoreResponse {
    Applied {
        decision: String,
        status: CoreStatus,
        listeners: Vec<ListenerStatus>,
    },
    Traffic {
        records: Vec<TrafficDelta>,
    },
    Status {
        status: CoreStatus,
        listeners: Vec<ListenerStatus>,
    },
    Stopped,
    Error {
        message: String,
    },
}

#[derive(Debug, Default)]
pub struct CoreController {
    runtime: RuntimeState,
    service: Option<CoreService>,
}

impl CoreController {
    pub fn new() -> Self {
        Self {
            runtime: RuntimeState::new(),
            service: None,
        }
    }

    pub fn handle(&mut self, command: CoreCommand) -> CoreResponse {
        match command {
            CoreCommand::ApplyConfig { config } => self.apply_config(config),
            CoreCommand::DrainTraffic { minimum_bytes } => CoreResponse::Traffic {
                records: self.drain_traffic(minimum_bytes),
            },
            CoreCommand::Status => CoreResponse::Status {
                status: self.runtime.status().clone(),
                listeners: self.listeners(),
            },
            CoreCommand::Stop => {
                if let Some(service) = &mut self.service {
                    service.stop();
                }
                self.service = None;
                self.runtime.stop();
                CoreResponse::Stopped
            }
        }
    }

    fn apply_config(&mut self, config: CoreConfig) -> CoreResponse {
        let plan = match RuntimeState::plan(config.clone()) {
            Ok(plan) => plan,
            Err(error) => {
                self.runtime.fail(error.to_string());
                return CoreResponse::Error {
                    message: error.to_string(),
                };
            }
        };

        if !self.runtime.needs_reload(&plan) {
            let decision = self.runtime.apply_plan(plan);
            return CoreResponse::Applied {
                decision: decision_name(decision).to_string(),
                status: self.runtime.status().clone(),
                listeners: self.listeners(),
            };
        }

        if let Some(service) = &mut self.service {
            if service.can_update_users(&config) {
                service.update_users(config);
                let decision = self.runtime.apply_update(plan);
                return CoreResponse::Applied {
                    decision: decision_name(decision).to_string(),
                    status: self.runtime.status().clone(),
                    listeners: self.listeners(),
                };
            }
        }

        if let Some(service) = &mut self.service {
            service.stop();
        }
        self.service = None;

        let service = match CoreService::start(config) {
            Ok(service) => service,
            Err(error) => {
                self.runtime.fail(error.to_string());
                return CoreResponse::Error {
                    message: error.to_string(),
                };
            }
        };

        self.service = Some(service);
        let decision = self.runtime.apply_plan(plan);
        CoreResponse::Applied {
            decision: decision_name(decision).to_string(),
            status: self.runtime.status().clone(),
            listeners: self.listeners(),
        }
    }

    fn drain_traffic(&mut self, minimum_bytes: u64) -> Vec<TrafficDelta> {
        match &self.service {
            Some(service) => service.drain_traffic(minimum_bytes),
            None => self.runtime.drain_traffic(minimum_bytes),
        }
    }

    fn listeners(&self) -> Vec<ListenerStatus> {
        self.service
            .as_ref()
            .map(CoreService::listeners)
            .unwrap_or_default()
    }
}

fn decision_name(decision: ReloadDecision) -> &'static str {
    match decision {
        ReloadDecision::Noop => "noop",
        ReloadDecision::Reloaded => "reloaded",
        ReloadDecision::Updated => "updated",
    }
}

#[cfg(test)]
mod tests {
    use std::net::TcpListener;

    use crate::config::{
        CoreConfig, DnsConfig, InboundConfig, OutboundConfig, SniffingConfig, StatsConfig,
        TransportConfig,
    };
    use crate::control::{CoreCommand, CoreController, CoreResponse};
    use crate::protocol::Protocol;
    use crate::runtime::CoreStatus;
    use crate::user::CoreUser;

    fn free_port() -> u16 {
        TcpListener::bind("127.0.0.1:0")
            .expect("bind free port")
            .local_addr()
            .expect("free port addr")
            .port()
    }

    fn config(protocol: Protocol) -> CoreConfig {
        CoreConfig {
            instance_id: "node-a".to_string(),
            log_level: "info".to_string(),
            dns: DnsConfig::default(),
            inbounds: vec![InboundConfig {
                tag: "panel|proxy|1".to_string(),
                protocol,
                listen: "127.0.0.1".to_string(),
                port: free_port(),
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
    fn apply_config_starts_real_service_and_noops_same_fingerprint() {
        let config = config(Protocol::Socks);
        let mut controller = CoreController::new();

        let first = controller.handle(CoreCommand::ApplyConfig {
            config: config.clone(),
        });
        let second = controller.handle(CoreCommand::ApplyConfig { config });

        match first {
            CoreResponse::Applied {
                decision,
                status,
                listeners,
            } => {
                assert_eq!(decision, "reloaded");
                assert_eq!(status, CoreStatus::Running);
                assert_eq!(listeners.len(), 1);
            }
            response => panic!("unexpected response: {response:?}"),
        }
        match second {
            CoreResponse::Applied {
                decision,
                status,
                listeners,
            } => {
                assert_eq!(decision, "noop");
                assert_eq!(status, CoreStatus::Running);
                assert_eq!(listeners.len(), 1);
            }
            response => panic!("unexpected response: {response:?}"),
        }
        assert!(matches!(
            controller.handle(CoreCommand::Stop),
            CoreResponse::Stopped
        ));
    }

    #[test]
    fn apply_config_hot_updates_users_without_rebinding_listener() {
        let config = config(Protocol::Socks);
        let mut updated = config.clone();
        updated.inbounds[0].users[0].uuid = "user-b".to_string();
        updated.inbounds[0].users[0].password = Some("secret-b".to_string());
        let mut controller = CoreController::new();

        let first = controller.handle(CoreCommand::ApplyConfig {
            config: config.clone(),
        });
        let first_addr = match first {
            CoreResponse::Applied {
                decision,
                listeners,
                ..
            } => {
                assert_eq!(decision, "reloaded");
                listeners[0].local_addr
            }
            response => panic!("unexpected response: {response:?}"),
        };
        let second = controller.handle(CoreCommand::ApplyConfig { config: updated });

        match second {
            CoreResponse::Applied {
                decision,
                status,
                listeners,
            } => {
                assert_eq!(decision, "updated");
                assert_eq!(status, CoreStatus::Running);
                assert_eq!(listeners[0].local_addr, first_addr);
            }
            response => panic!("unexpected response: {response:?}"),
        }
        assert!(matches!(
            controller.handle(CoreCommand::Stop),
            CoreResponse::Stopped
        ));
    }

    #[test]
    fn apply_config_reports_sidecar_protocol_errors() {
        let mut controller = CoreController::new();

        let response = controller.handle(CoreCommand::ApplyConfig {
            config: config(Protocol::Naive),
        });

        match response {
            CoreResponse::Error { message } => assert!(message.contains("external sidecar")),
            response => panic!("unexpected response: {response:?}"),
        }
    }
}
