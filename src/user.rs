use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreUser {
    pub id: u64,
    pub uuid: String,
    pub password: Option<String>,
    pub email: Option<String>,
    pub speed_limit: u64,
    pub device_limit: u32,
}

impl CoreUser {
    pub fn credential(&self) -> &str {
        self.password.as_deref().unwrap_or(&self.uuid)
    }

    pub fn traffic_key(&self, node_tag: &str) -> String {
        format!("{}|{}", node_tag, self.uuid)
    }

    pub fn is_empty(&self) -> bool {
        self.uuid.trim().is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::CoreUser;

    #[test]
    fn keeps_go_compatible_traffic_key() {
        let user = CoreUser {
            id: 7,
            uuid: "user-a".to_string(),
            password: None,
            email: None,
            speed_limit: 0,
            device_limit: 0,
        };

        assert_eq!(user.traffic_key("panel|vless|1"), "panel|vless|1|user-a");
        assert_eq!(user.credential(), "user-a");
    }
}
