use std::collections::HashMap;
use std::hash::Hash;
use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;
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

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreUserDelta {
    #[serde(default)]
    pub added: Vec<CoreUser>,
    #[serde(default)]
    pub updated: Vec<CoreUser>,
    #[serde(default)]
    pub deleted: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub full: Option<Vec<CoreUser>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base_revision: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revision: Option<String>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreUserDeltaResult {
    pub added: usize,
    pub updated: usize,
    pub deleted: usize,
    pub missing_updated: usize,
    pub missing_deleted: usize,
    pub active_users: usize,
    pub full_applied: bool,
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

#[derive(Clone)]
pub struct UserStore {
    users: Arc<ArcSwap<UserStoreState>>,
    writes: Arc<Mutex<()>>,
}

#[derive(Clone, Debug, Default)]
struct UserStoreState {
    users: HashMap<String, Arc<CoreUser>>,
}

impl UserStore {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn from_uuid_users(users: &[CoreUser]) -> Self {
        Self::from_keyed_users(users, |user| user.uuid.clone())
    }

    pub fn from_keyed_users<F>(users: &[CoreUser], key: F) -> Self
    where
        F: Fn(&CoreUser) -> String,
    {
        Self {
            users: Arc::new(ArcSwap::from_pointee(keyed_user_state(users, key))),
            writes: Arc::new(Mutex::new(())),
        }
    }

    pub fn replace_uuid_users(&self, users: Vec<CoreUser>) {
        self.replace_keyed_users(users, |user| user.uuid.clone());
    }

    pub fn replace_keyed_users<F>(&self, users: Vec<CoreUser>, key: F)
    where
        F: Fn(&CoreUser) -> String,
    {
        let next = keyed_user_state(&users, key);
        let _guard = self.writes.lock().expect("user store write lock poisoned");
        self.users.store(Arc::new(next));
    }

    pub fn is_empty(&self) -> bool {
        self.users.load().users.is_empty()
    }

    pub fn len(&self) -> usize {
        self.users.load().users.len()
    }

    pub fn list(&self) -> Vec<CoreUser> {
        let snapshot = self.users.load_full();
        let mut users = snapshot
            .users
            .values()
            .map(|user| user.as_ref().clone())
            .collect::<Vec<_>>();
        users.sort_by(|left, right| left.uuid.cmp(&right.uuid));
        users
    }

    pub fn get(&self, uuid: &str) -> Option<CoreUser> {
        self.get_arc(uuid).map(|user| user.as_ref().clone())
    }

    pub fn get_arc(&self, uuid: &str) -> Option<Arc<CoreUser>> {
        self.users.load().users.get(uuid).cloned()
    }

    pub fn apply_uuid_delta(&self, delta: &CoreUserDelta) -> CoreUserDeltaResult {
        self.apply_keyed_delta(delta, |user| user.uuid.clone())
    }

    pub fn apply_keyed_delta<F>(&self, delta: &CoreUserDelta, key: F) -> CoreUserDeltaResult
    where
        F: Fn(&CoreUser) -> String,
    {
        if let Some(full) = delta.full.as_ref() {
            let _guard = self.writes.lock().expect("user store write lock poisoned");
            let next = keyed_user_state(full, key);
            let active_users = next.users.len();
            self.users.store(Arc::new(next));
            return CoreUserDeltaResult {
                active_users,
                full_applied: true,
                ..CoreUserDeltaResult::default()
            };
        }

        let mut result = CoreUserDeltaResult::default();
        let _guard = self.writes.lock().expect("user store write lock poisoned");
        let mut current = self.users.load_full().as_ref().clone();
        for user in &delta.added {
            if user.is_empty() {
                continue;
            }
            let key = key(user);
            if remove_arc_user_by_uuid(&mut current.users, &user.uuid).is_some() {
                result.updated += 1;
            } else {
                result.added += 1;
            }
            current.users.insert(key, Arc::new(user.clone()));
        }
        for user in &delta.updated {
            if user.is_empty() {
                continue;
            }
            let key = key(user);
            if remove_arc_user_by_uuid(&mut current.users, &user.uuid).is_some() {
                current.users.insert(key, Arc::new(user.clone()));
                result.updated += 1;
            } else {
                result.missing_updated += 1;
            }
        }
        for uuid in &delta.deleted {
            if remove_arc_user_by_uuid(&mut current.users, uuid).is_some() {
                result.deleted += 1;
            } else {
                result.missing_deleted += 1;
            }
        }
        result.active_users = current.users.len();
        self.users.store(Arc::new(current));
        result
    }
}

impl Default for UserStore {
    fn default() -> Self {
        Self {
            users: Arc::new(ArcSwap::from_pointee(UserStoreState::default())),
            writes: Arc::new(Mutex::new(())),
        }
    }
}

impl std::fmt::Debug for UserStore {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("UserStore")
            .field("len", &self.len())
            .finish_non_exhaustive()
    }
}

pub fn apply_user_delta_to_vec(
    users: &mut Vec<CoreUser>,
    delta: &CoreUserDelta,
) -> CoreUserDeltaResult {
    if let Some(full) = delta.full.as_ref() {
        *users = active_user_vec(full);
        return CoreUserDeltaResult {
            active_users: users.len(),
            full_applied: true,
            ..CoreUserDeltaResult::default()
        };
    }

    let mut result = CoreUserDeltaResult::default();
    let mut by_uuid = users
        .drain(..)
        .filter(|user| !user.is_empty())
        .map(|user| (user.uuid.clone(), user))
        .collect::<HashMap<_, _>>();
    for user in &delta.added {
        if user.is_empty() {
            continue;
        }
        if by_uuid.insert(user.uuid.clone(), user.clone()).is_some() {
            result.updated += 1;
        } else {
            result.added += 1;
        }
    }
    for user in &delta.updated {
        if user.is_empty() {
            continue;
        }
        if by_uuid.contains_key(&user.uuid) {
            by_uuid.insert(user.uuid.clone(), user.clone());
            result.updated += 1;
        } else {
            result.missing_updated += 1;
        }
    }
    for uuid in &delta.deleted {
        if by_uuid.remove(uuid).is_some() {
            result.deleted += 1;
        } else {
            result.missing_deleted += 1;
        }
    }
    *users = by_uuid.into_values().collect();
    users.sort_by(|left, right| left.uuid.cmp(&right.uuid));
    result.active_users = users.len();
    result
}

pub fn apply_user_delta_to_keyed_map<K, F>(
    users: &mut HashMap<K, CoreUser>,
    delta: &CoreUserDelta,
    key: F,
) -> CoreUserDeltaResult
where
    K: Clone + Eq + Hash,
    F: Fn(&CoreUser) -> Option<K>,
{
    if let Some(full) = delta.full.as_ref() {
        users.clear();
        for user in full {
            if !user.is_empty() {
                if let Some(key) = key(user) {
                    users.insert(key, user.clone());
                }
            }
        }
        return CoreUserDeltaResult {
            active_users: users.len(),
            full_applied: true,
            ..CoreUserDeltaResult::default()
        };
    }

    let mut result = CoreUserDeltaResult::default();
    let mut uuid_keys = users
        .iter()
        .map(|(key, user)| (user.uuid.clone(), key.clone()))
        .collect::<HashMap<_, _>>();
    for user in &delta.added {
        if user.is_empty() {
            continue;
        }
        let Some(key) = key(user) else {
            continue;
        };
        if let Some(old_key) = uuid_keys.insert(user.uuid.clone(), key.clone()) {
            users.remove(&old_key);
            result.updated += 1;
        } else {
            result.added += 1;
        }
        users.insert(key, user.clone());
    }
    for user in &delta.updated {
        if user.is_empty() {
            continue;
        }
        let Some(key) = key(user) else {
            result.missing_updated += 1;
            continue;
        };
        if let Some(old_key) = uuid_keys.insert(user.uuid.clone(), key.clone()) {
            users.remove(&old_key);
            users.insert(key, user.clone());
            result.updated += 1;
        } else {
            uuid_keys.remove(&user.uuid);
            result.missing_updated += 1;
        }
    }
    for uuid in &delta.deleted {
        if let Some(key) = uuid_keys.remove(uuid) {
            if users.remove(&key).is_some() {
                result.deleted += 1;
            } else {
                result.missing_deleted += 1;
            }
        } else {
            result.missing_deleted += 1;
        }
    }
    result.active_users = users.len();
    result
}

pub fn apply_user_delta_to_keyed_arc_map<K, F>(
    users: &mut HashMap<K, Arc<CoreUser>>,
    delta: &CoreUserDelta,
    key: F,
) -> CoreUserDeltaResult
where
    K: Clone + Eq + Hash,
    F: Fn(&CoreUser) -> Option<K>,
{
    if let Some(full) = delta.full.as_ref() {
        users.clear();
        for user in full {
            if !user.is_empty() {
                if let Some(key) = key(user) {
                    users.insert(key, Arc::new(user.clone()));
                }
            }
        }
        return CoreUserDeltaResult {
            active_users: users.len(),
            full_applied: true,
            ..CoreUserDeltaResult::default()
        };
    }

    let mut result = CoreUserDeltaResult::default();
    let mut uuid_keys = users
        .iter()
        .map(|(key, user)| (user.uuid.clone(), key.clone()))
        .collect::<HashMap<_, _>>();
    for user in &delta.added {
        if user.is_empty() {
            continue;
        }
        let Some(key) = key(user) else {
            continue;
        };
        if let Some(old_key) = uuid_keys.insert(user.uuid.clone(), key.clone()) {
            users.remove(&old_key);
            result.updated += 1;
        } else {
            result.added += 1;
        }
        users.insert(key, Arc::new(user.clone()));
    }
    for user in &delta.updated {
        if user.is_empty() {
            continue;
        }
        let Some(key) = key(user) else {
            result.missing_updated += 1;
            continue;
        };
        if let Some(old_key) = uuid_keys.insert(user.uuid.clone(), key.clone()) {
            users.remove(&old_key);
            users.insert(key, Arc::new(user.clone()));
            result.updated += 1;
        } else {
            uuid_keys.remove(&user.uuid);
            result.missing_updated += 1;
        }
    }
    for uuid in &delta.deleted {
        if let Some(key) = uuid_keys.remove(uuid) {
            if users.remove(&key).is_some() {
                result.deleted += 1;
            } else {
                result.missing_deleted += 1;
            }
        } else {
            result.missing_deleted += 1;
        }
    }
    result.active_users = users.len();
    result
}

fn active_user_vec(users: &[CoreUser]) -> Vec<CoreUser> {
    let mut users = users
        .iter()
        .filter(|user| !user.is_empty())
        .cloned()
        .collect::<Vec<_>>();
    users.sort_by(|left, right| left.uuid.cmp(&right.uuid));
    users
}

fn keyed_user_state<F>(users: &[CoreUser], key: F) -> UserStoreState
where
    F: Fn(&CoreUser) -> String,
{
    let mut state = UserStoreState {
        users: HashMap::with_capacity(users.len()),
    };
    for user in users {
        if !user.is_empty() {
            let key = key(user);
            state.users.insert(key, Arc::new(user.clone()));
        }
    }
    state
}

fn remove_arc_user_by_uuid(
    users: &mut HashMap<String, Arc<CoreUser>>,
    uuid: &str,
) -> Option<Arc<CoreUser>> {
    let key = users
        .iter()
        .find_map(|(key, user)| (user.uuid == uuid).then(|| key.clone()))?;
    users.remove(&key)
}

#[cfg(test)]
mod tests {
    use std::collections::HashMap;

    use super::{
        apply_user_delta_to_keyed_arc_map, apply_user_delta_to_keyed_map, apply_user_delta_to_vec,
        CoreUser, CoreUserDelta, UserStore,
    };
    use std::sync::Arc;

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
    fn apply_user_delta_to_keyed_arc_map_preserves_unchanged_user_arcs() {
        let user_a = Arc::new(user("user-a"));
        let mut users = HashMap::from([("user-a".to_string(), Arc::clone(&user_a))]);

        let result = apply_user_delta_to_keyed_arc_map(
            &mut users,
            &CoreUserDelta {
                added: vec![user("user-b")],
                ..CoreUserDelta::default()
            },
            |user| Some(user.uuid.clone()),
        );

        assert_eq!(result.added, 1);
        assert_eq!(result.active_users, 2);
        assert!(Arc::ptr_eq(
            &user_a,
            users.get("user-a").expect("existing user should remain")
        ));
    }

    #[test]
    fn apply_user_delta_to_keyed_arc_map_replaces_only_updated_user_arc() {
        let user_a = Arc::new(user("user-a"));
        let user_b = Arc::new(user("user-b"));
        let mut users = HashMap::from([
            ("user-a".to_string(), Arc::clone(&user_a)),
            ("user-b".to_string(), Arc::clone(&user_b)),
        ]);
        let mut updated_a = user("user-a");
        updated_a.password = Some("rotated".to_string());

        let result = apply_user_delta_to_keyed_arc_map(
            &mut users,
            &CoreUserDelta {
                updated: vec![updated_a],
                ..CoreUserDelta::default()
            },
            |user| Some(user.credential().to_string()),
        );

        assert_eq!(result.updated, 1);
        assert_eq!(result.active_users, 2);
        assert!(users.get("user-a").is_none());
        assert!(!Arc::ptr_eq(
            &user_a,
            users.get("rotated").expect("updated user should move keys")
        ));
        assert!(Arc::ptr_eq(
            &user_b,
            users.get("user-b").expect("unchanged user should remain")
        ));
    }

    fn limited_user(uuid: &str, speed_limit: u64) -> CoreUser {
        CoreUser {
            speed_limit,
            ..user(uuid)
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

    #[test]
    fn user_store_applies_uuid_delta() {
        let store = UserStore::from_uuid_users(&[user("user-a"), user("user-b")]);
        let old_user_b = store.get_arc("user-b").expect("old user b snapshot");
        let result = store.apply_uuid_delta(&CoreUserDelta {
            added: vec![user("user-c")],
            updated: vec![limited_user("user-b", 1024)],
            deleted: vec!["user-a".to_string()],
            ..CoreUserDelta::default()
        });

        assert_eq!(result.added, 1);
        assert_eq!(result.updated, 1);
        assert_eq!(result.deleted, 1);
        assert_eq!(result.active_users, 2);
        assert!(store.get("user-a").is_none());
        assert_eq!(store.get("user-b").expect("user b").speed_limit, 1024);
        assert!(store.get("user-c").is_some());
        assert_eq!(
            old_user_b.speed_limit, 0,
            "existing readers keep a stable pre-delta snapshot"
        );
    }

    #[test]
    fn user_store_rekeys_updated_credentials() {
        let mut initial = user("user-a");
        initial.password = Some("old".to_string());
        let store = UserStore::from_keyed_users(&[initial], |user| user.credential().to_string());
        let mut updated = user("user-a");
        updated.password = Some("new".to_string());

        let result = store.apply_keyed_delta(
            &CoreUserDelta {
                updated: vec![updated],
                ..CoreUserDelta::default()
            },
            |user| user.credential().to_string(),
        );

        assert_eq!(result.updated, 1);
        assert!(store.get("old").is_none());
        assert!(store.get("new").is_some());
    }

    #[test]
    fn user_store_counts_duplicate_added_as_update() {
        let store = UserStore::from_uuid_users(&[]);

        let result = store.apply_uuid_delta(&CoreUserDelta {
            added: vec![user("user-a"), limited_user("user-a", 2048)],
            ..CoreUserDelta::default()
        });

        assert_eq!(result.added, 1);
        assert_eq!(result.updated, 1);
        assert_eq!(result.active_users, 1);
        assert_eq!(store.get("user-a").expect("user a").speed_limit, 2048);
    }

    #[test]
    fn user_store_reports_missing_update_and_delete() {
        let store = UserStore::from_uuid_users(&[user("user-a")]);

        let result = store.apply_uuid_delta(&CoreUserDelta {
            updated: vec![user("missing-update")],
            deleted: vec!["missing-delete".to_string()],
            ..CoreUserDelta::default()
        });

        assert_eq!(result.missing_updated, 1);
        assert_eq!(result.missing_deleted, 1);
        assert_eq!(result.active_users, 1);
        assert!(store.get("user-a").is_some());
    }

    #[test]
    fn vec_delta_full_snapshot_replaces_users() {
        let mut users = vec![user("user-a"), user("user-b")];

        let result = apply_user_delta_to_vec(
            &mut users,
            &CoreUserDelta {
                full: Some(vec![user("user-c")]),
                ..CoreUserDelta::default()
            },
        );

        assert!(result.full_applied);
        assert_eq!(result.active_users, 1);
        assert_eq!(users, vec![user("user-c")]);
    }

    #[test]
    fn keyed_map_delta_updates_by_uuid_and_key() {
        let mut old = user("user-a");
        old.password = Some("old".to_string());
        let mut users = HashMap::from([(old.credential().to_string(), old)]);
        let mut updated = user("user-a");
        updated.password = Some("new".to_string());

        let result = apply_user_delta_to_keyed_map(
            &mut users,
            &CoreUserDelta {
                updated: vec![updated],
                ..CoreUserDelta::default()
            },
            |user| Some(user.credential().to_string()),
        );

        assert_eq!(result.updated, 1);
        assert!(!users.contains_key("old"));
        assert!(users.contains_key("new"));
    }
}
