use std::collections::HashMap;
use std::sync::{Arc, RwLock};

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

#[derive(Clone, Debug, Default)]
pub struct UserStore {
    users: Arc<RwLock<HashMap<String, CoreUser>>>,
}

impl UserStore {
    pub fn from_uuid_users(users: &[CoreUser]) -> Self {
        Self::from_keyed_users(users, |user| user.uuid.clone())
    }

    pub fn from_keyed_users<F>(users: &[CoreUser], key: F) -> Self
    where
        F: Fn(&CoreUser) -> String,
    {
        Self {
            users: Arc::new(RwLock::new(keyed_user_map(users, key))),
        }
    }

    pub fn replace_uuid_users(&self, users: Vec<CoreUser>) {
        self.replace_keyed_users(users, |user| user.uuid.clone());
    }

    pub fn replace_keyed_users<F>(&self, users: Vec<CoreUser>, key: F)
    where
        F: Fn(&CoreUser) -> String,
    {
        let next = keyed_user_map(&users, key);
        let mut current = self.users.write().expect("user store lock poisoned");
        *current = next;
    }

    pub fn is_empty(&self) -> bool {
        self.users
            .read()
            .expect("user store lock poisoned")
            .is_empty()
    }

    pub fn get(&self, uuid: &str) -> Option<CoreUser> {
        self.users
            .read()
            .expect("user store lock poisoned")
            .get(uuid)
            .cloned()
    }
}

fn keyed_user_map<F>(users: &[CoreUser], key: F) -> HashMap<String, CoreUser>
where
    F: Fn(&CoreUser) -> String,
{
    let mut map = HashMap::with_capacity(users.len());
    for user in users {
        if !user.is_empty() {
            map.insert(key(user), user.clone());
        }
    }
    map
}

#[cfg(test)]
mod tests {
    use super::{CoreUser, UserStore};

    fn user(uuid: &str) -> CoreUser {
        CoreUser {
            id: 7,
            uuid: uuid.to_string(),
            password: None,
            email: None,
            speed_limit: 0,
            device_limit: 0,
        }
    }

    #[test]
    fn keeps_go_compatible_traffic_key() {
        let user = user("user-a");

        assert_eq!(user.traffic_key("panel|vless|1"), "panel|vless|1|user-a");
        assert_eq!(user.credential(), "user-a");
    }

    #[test]
    fn user_store_replaces_uuid_users() {
        let store = UserStore::from_uuid_users(&[user("user-a")]);

        assert!(store.get("user-a").is_some());
        assert!(store.get("user-b").is_none());

        store.replace_uuid_users(vec![user("user-b")]);

        assert!(store.get("user-a").is_none());
        assert!(store.get("user-b").is_some());
    }

    #[test]
    fn user_store_replaces_large_user_sets() {
        let store = UserStore::default();
        let users = (0..10_000)
            .map(|index| user(&format!("user-{index:05}")))
            .collect::<Vec<_>>();

        store.replace_uuid_users(users);

        assert!(store.get("user-00000").is_some());
        assert!(store.get("user-05000").is_some());
        assert!(store.get("user-09999").is_some());
        assert!(store.get("user-10000").is_none());
    }
}
