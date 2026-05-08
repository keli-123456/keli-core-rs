use keli_core_rs::VERSION;

fn main() {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("--version") | Some("version") => {
            println!("keli-core-rs {}", VERSION);
        }
        Some("health") => {
            println!("ok");
        }
        _ => {
            println!("keli-core-rs {} experimental core skeleton", VERSION);
            println!("commands: version, health");
        }
    }
}
