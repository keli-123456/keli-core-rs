use std::process::ExitCode;
use std::thread;
use std::time::Duration;

use keli_core_rs::{
    load_core_config_json, CoreCommand, CoreController, CoreResponse, RuntimeState, VERSION,
};

fn main() -> ExitCode {
    match run() {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::FAILURE
        }
    }
}

fn run() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("--version") | Some("version") => {
            println!("keli-core-rs {}", VERSION);
        }
        Some("health") => {
            println!("ok");
        }
        Some("check-config") => {
            let path = args
                .next()
                .ok_or_else(|| "check-config requires a json config path".to_string())?;
            let config = load_core_config_json(path).map_err(|error| error.to_string())?;
            let plan = RuntimeState::plan(config).map_err(|error| error.to_string())?;
            println!(
                "{}",
                serde_json::json!({
                    "ok": true,
                    "fingerprint": plan.fingerprint,
                })
            );
        }
        Some("run-config") => {
            let path = args
                .next()
                .ok_or_else(|| "run-config requires a json config path".to_string())?;
            let config = load_core_config_json(path).map_err(|error| error.to_string())?;
            let mut controller = CoreController::new();
            let response = controller.handle(CoreCommand::ApplyConfig { config });
            println!(
                "{}",
                serde_json::to_string(&response).map_err(|error| error.to_string())?
            );
            if matches!(response, CoreResponse::Error { .. }) {
                return Err("failed to start core service".to_string());
            }
            loop {
                thread::park_timeout(Duration::from_secs(3600));
            }
        }
        _ => {
            println!("keli-core-rs {} experimental core skeleton", VERSION);
            println!("commands: version, health, check-config <path>, run-config <path>");
        }
    }
    Ok(())
}
