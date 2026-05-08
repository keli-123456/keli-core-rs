use serde::{Deserialize, Serialize};

use crate::config::CoreConfig;
use crate::runtime::{CoreStatus, ReloadDecision, RuntimeState};
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
    },
    Traffic {
        records: Vec<TrafficDelta>,
    },
    Status {
        status: CoreStatus,
    },
    Stopped,
    Error {
        message: String,
    },
}

#[derive(Clone, Debug, Default)]
pub struct CoreController {
    runtime: RuntimeState,
}

impl CoreController {
    pub fn new() -> Self {
        Self {
            runtime: RuntimeState::new(),
        }
    }

    pub fn handle(&mut self, command: CoreCommand) -> CoreResponse {
        match command {
            CoreCommand::ApplyConfig { config } => match RuntimeState::plan(config) {
                Ok(plan) => {
                    let decision = self.runtime.apply_plan(plan);
                    CoreResponse::Applied {
                        decision: decision_name(decision).to_string(),
                        status: self.runtime.status().clone(),
                    }
                }
                Err(error) => CoreResponse::Error {
                    message: error.to_string(),
                },
            },
            CoreCommand::DrainTraffic { minimum_bytes } => CoreResponse::Traffic {
                records: self.runtime.drain_traffic(minimum_bytes),
            },
            CoreCommand::Status => CoreResponse::Status {
                status: self.runtime.status().clone(),
            },
            CoreCommand::Stop => {
                self.runtime.stop();
                CoreResponse::Stopped
            }
        }
    }
}

fn decision_name(decision: ReloadDecision) -> &'static str {
    match decision {
        ReloadDecision::Noop => "noop",
        ReloadDecision::Reloaded => "reloaded",
    }
}
