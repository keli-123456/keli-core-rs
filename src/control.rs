use serde::{Deserialize, Serialize};

use crate::config::CoreConfig;
use crate::runtime::{CoreStatus, ReloadDecision, RuntimeState};
use crate::service::{CoreService, ListenerStatus};
use crate::traffic::TrafficDelta;
use crate::user::{CoreUserDelta, CoreUserDeltaResult};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CoreCommand {
    ApplyConfig {
        config: CoreConfig,
    },
    ApplyUserDelta {
        node_tag: String,
        delta: CoreUserDelta,
    },
    DrainTraffic {
        minimum_bytes: u64,
    },
    RequeueTraffic {
        records: Vec<TrafficDelta>,
    },
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
    UserDeltaApplied {
        node_tag: String,
        result: CoreUserDeltaResult,
        status: CoreStatus,
        listeners: Vec<ListenerStatus>,
    },
    Traffic {
        records: Vec<TrafficDelta>,
    },
    TrafficRequeued {
        count: usize,
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
            CoreCommand::ApplyUserDelta { node_tag, delta } => {
                self.apply_user_delta(node_tag, delta)
            }
            CoreCommand::DrainTraffic { minimum_bytes } => CoreResponse::Traffic {
                records: self.drain_traffic(minimum_bytes),
            },
            CoreCommand::RequeueTraffic { records } => {
                let count = records.len();
                self.requeue_traffic(records);
                CoreResponse::TrafficRequeued { count }
            }
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

    fn apply_user_delta(&mut self, node_tag: String, delta: CoreUserDelta) -> CoreResponse {
        let Some(service) = &mut self.service else {
            return CoreResponse::Error {
                message: "cannot apply user delta before config is applied".to_string(),
            };
        };
        let result = match service.apply_user_delta(&node_tag, &delta) {
            Ok(result) => result,
            Err(message) => {
                return CoreResponse::Error { message };
            }
        };
        self.runtime.apply_runtime_update();
        CoreResponse::UserDeltaApplied {
            node_tag,
            result,
            status: self.runtime.status().clone(),
            listeners: self.listeners(),
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

    fn requeue_traffic(&mut self, records: Vec<TrafficDelta>) {
        match &mut self.service {
            Some(service) => service.requeue_traffic(records),
            None => self.runtime.requeue_traffic(records),
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
    use std::io::{Read, Write};
    use std::net::{SocketAddr, TcpListener, TcpStream};

    use crate::config::{
        CoreConfig, DnsConfig, InboundConfig, OutboundConfig, SniffingConfig, StatsConfig,
        TransportConfig,
    };
    use crate::control::{CoreCommand, CoreController, CoreResponse};
    use crate::protocol::Protocol;
    use crate::runtime::CoreStatus;
    use crate::traffic::TrafficDelta;
    use crate::user::{CoreUser, CoreUserDelta};

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
                method: None,
                alter_id: None,
                address: None,
                port: None,
                username: None,
                password: None,
                tls: None,
                transport: None,
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
    fn apply_user_delta_updates_users_without_rebinding_listener() {
        let config = config(Protocol::Socks);
        let node_tag = config.inbounds[0].tag.clone();
        let mut controller = CoreController::new();

        let first = controller.handle(CoreCommand::ApplyConfig {
            config: config.clone(),
        });
        let first_addr = match first {
            CoreResponse::Applied { listeners, .. } => listeners[0].local_addr,
            response => panic!("unexpected response: {response:?}"),
        };
        assert_eq!(socks_auth_status(first_addr, "user-a", "user-a"), 0x00);

        let second = controller.handle(CoreCommand::ApplyUserDelta {
            node_tag: node_tag.clone(),
            delta: CoreUserDelta {
                added: vec![user_with_password("user-b", Some("secret-b"), 4096)],
                deleted: vec!["user-a".to_string()],
                ..CoreUserDelta::default()
            },
        });

        match second {
            CoreResponse::UserDeltaApplied {
                node_tag: applied_tag,
                result,
                status,
                listeners,
            } => {
                assert_eq!(applied_tag, node_tag);
                assert_eq!(result.added, 1);
                assert_eq!(result.deleted, 1);
                assert_eq!(result.active_users, 1);
                assert_eq!(status, CoreStatus::Running);
                assert_eq!(listeners[0].local_addr, first_addr);
            }
            response => panic!("unexpected response: {response:?}"),
        }
        assert_eq!(socks_auth_status(first_addr, "user-a", "user-a"), 0xff);
        assert_eq!(socks_auth_status(first_addr, "user-b", "secret-b"), 0x00);
        assert!(matches!(
            controller.handle(CoreCommand::Stop),
            CoreResponse::Stopped
        ));
    }

    #[test]
    fn apply_user_delta_reports_unknown_node_tag() {
        let mut controller = CoreController::new();
        let apply = controller.handle(CoreCommand::ApplyConfig {
            config: config(Protocol::Socks),
        });
        assert!(matches!(apply, CoreResponse::Applied { .. }));

        match controller.handle(CoreCommand::ApplyUserDelta {
            node_tag: "missing".to_string(),
            delta: CoreUserDelta::default(),
        }) {
            CoreResponse::Error { message } => assert!(message.contains("unknown inbound")),
            response => panic!("unexpected response: {response:?}"),
        }
        assert!(matches!(
            controller.handle(CoreCommand::Stop),
            CoreResponse::Stopped
        ));
    }

    #[test]
    fn apply_user_delta_empty_delta_keeps_listener() {
        let config = config(Protocol::Socks);
        let node_tag = config.inbounds[0].tag.clone();
        let mut controller = CoreController::new();

        let first = controller.handle(CoreCommand::ApplyConfig { config });
        let first_addr = match first {
            CoreResponse::Applied { listeners, .. } => listeners[0].local_addr,
            response => panic!("unexpected response: {response:?}"),
        };

        match controller.handle(CoreCommand::ApplyUserDelta {
            node_tag,
            delta: CoreUserDelta::default(),
        }) {
            CoreResponse::UserDeltaApplied {
                result, listeners, ..
            } => {
                assert_eq!(result.added, 0);
                assert_eq!(result.updated, 0);
                assert_eq!(result.deleted, 0);
                assert_eq!(result.active_users, 1);
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

    fn user_with_password(uuid: &str, password: Option<&str>, speed_limit: u64) -> CoreUser {
        CoreUser {
            id: 2,
            uuid: uuid.to_string(),
            password: password.map(str::to_string),
            email: None,
            speed_limit,
            device_limit: 0,
        }
    }

    fn socks_auth_status(addr: SocketAddr, username: &str, password: &str) -> u8 {
        let mut stream = TcpStream::connect(addr).expect("connect socks listener");
        stream
            .write_all(&[0x05, 0x01, 0x02])
            .expect("write socks methods");
        let mut method = [0u8; 2];
        stream.read_exact(&mut method).expect("read socks method");
        assert_eq!(method, [0x05, 0x02]);
        let mut auth = vec![0x01, username.len() as u8];
        auth.extend_from_slice(username.as_bytes());
        auth.push(password.len() as u8);
        auth.extend_from_slice(password.as_bytes());
        stream.write_all(&auth).expect("write auth");
        let mut status = [0u8; 2];
        stream.read_exact(&mut status).expect("read auth status");
        assert_eq!(status[0], 0x01);
        status[1]
    }

    #[test]
    fn requeues_drained_traffic_records() {
        let mut controller = CoreController::new();
        let record = TrafficDelta {
            node_tag: "node-a".to_string(),
            user_uuid: "user-a".to_string(),
            user_id: Some(7),
            upload: 10,
            download: 20,
            online_ips: vec!["198.51.100.7".to_string()],
        };

        assert!(matches!(
            controller.handle(CoreCommand::RequeueTraffic {
                records: vec![record]
            }),
            CoreResponse::TrafficRequeued { count: 1 }
        ));

        match controller.handle(CoreCommand::DrainTraffic { minimum_bytes: 1 }) {
            CoreResponse::Traffic { records } => {
                assert_eq!(records.len(), 1);
                assert_eq!(records[0].user_id, Some(7));
                assert_eq!(records[0].upload, 10);
                assert_eq!(records[0].online_ips, vec!["198.51.100.7"]);
            }
            response => panic!("unexpected response: {response:?}"),
        }
    }
}
