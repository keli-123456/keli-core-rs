use std::process::ExitCode;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use keli_core_rs::{
    load_core_config_json, start_control_server, CoreCommand, CoreController, CoreResponse,
    RuntimeState, VERSION,
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
            let control_addr = parse_run_config_options(args)?;
            let config = load_core_config_json(path).map_err(|error| error.to_string())?;
            let controller = Arc::new(Mutex::new(CoreController::new()));
            let response = controller
                .lock()
                .map_err(|_| "controller lock poisoned".to_string())?
                .handle(CoreCommand::ApplyConfig { config });
            println!(
                "{}",
                serde_json::to_string(&response).map_err(|error| error.to_string())?
            );
            if matches!(response, CoreResponse::Error { .. }) {
                return Err("failed to start core service".to_string());
            }
            let mut control = match control_addr {
                Some(addr) => Some(
                    start_control_server(&addr, controller).map_err(|error| error.to_string())?,
                ),
                None => None,
            };
            loop {
                if control.as_ref().is_some_and(|handle| handle.is_stopped()) {
                    break;
                }
                thread::park_timeout(Duration::from_secs(1));
            }
            if let Some(handle) = &mut control {
                handle.stop();
            }
        }
        _ => {
            println!("keli-core-rs {} experimental core skeleton", VERSION);
            println!(
                "commands: version, health, check-config <path>, run-config <path> [--control <addr>]"
            );
        }
    }
    Ok(())
}

fn parse_run_config_options(
    mut args: impl Iterator<Item = String>,
) -> Result<Option<String>, String> {
    let mut control_addr = None;
    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--control" => {
                let value = args
                    .next()
                    .ok_or_else(|| "--control requires a listen address".to_string())?;
                if value.trim().is_empty() {
                    return Err("--control requires a listen address".to_string());
                }
                control_addr = Some(value);
            }
            value => return Err(format!("unknown run-config option {value}")),
        }
    }
    Ok(control_addr)
}
