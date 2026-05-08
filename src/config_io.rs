use std::fs;
use std::io;
use std::path::Path;

use crate::config::CoreConfig;

pub fn load_core_config_json(path: impl AsRef<Path>) -> io::Result<CoreConfig> {
    let body = fs::read_to_string(path)?;
    serde_json::from_str(&body).map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error))
}

#[cfg(test)]
mod tests {
    use std::fs;

    use crate::config_io::load_core_config_json;
    use crate::protocol::Protocol;

    #[test]
    fn loads_core_config_from_json_file() {
        let path =
            std::env::temp_dir().join(format!("keli-core-rs-config-{}.json", std::process::id()));
        fs::write(
            &path,
            r#"{
                "instance_id": "node-a",
                "log_level": "info",
                "inbounds": [{
                    "tag": "panel|socks|1",
                    "protocol": "socks",
                    "listen": "127.0.0.1",
                    "port": 1080,
                    "users": [{
                        "id": 1,
                        "uuid": "user-a",
                        "password": null,
                        "email": null,
                        "speed_limit": 0,
                        "device_limit": 0
                    }],
                    "transport": {
                        "network": "tcp",
                        "path": null,
                        "host": null,
                        "service_name": null,
                        "proxy_protocol": false
                    },
                    "tls": null,
                    "sniffing": {
                        "enabled": true,
                        "dest_override": ["http", "tls"]
                    }
                }],
                "outbounds": [{
                    "tag": "direct",
                    "protocol": "freedom",
                    "address": null,
                    "port": null
                }],
                "routes": [],
                "stats": {
                    "enabled": true,
                    "per_user": true
                }
            }"#,
        )
        .expect("write config");

        let config = load_core_config_json(&path).expect("load config");
        let _ = fs::remove_file(&path);

        assert_eq!(config.instance_id, "node-a");
        assert_eq!(config.inbounds[0].protocol, Protocol::Socks);
    }
}
