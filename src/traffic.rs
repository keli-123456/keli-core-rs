use std::collections::hash_map::{DefaultHasher, Entry};
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
use std::net::IpAddr;
use std::sync::{Arc, Mutex};

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TrafficKey {
    pub node_tag: String,
    pub user_uuid: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrafficDelta {
    pub node_tag: String,
    pub user_uuid: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub user_id: Option<u64>,
    pub upload: u64,
    pub download: u64,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub online_ips: Vec<String>,
}

const TRAFFIC_REGISTRY_SHARDS: usize = 64;

pub type SharedTrafficRegistry = Arc<TrafficRegistry>;

#[derive(Debug)]
pub struct TrafficRegistry {
    shards: Vec<Mutex<HashMap<TrafficKey, TrafficDelta>>>,
}

impl Default for TrafficRegistry {
    fn default() -> Self {
        Self {
            shards: (0..TRAFFIC_REGISTRY_SHARDS)
                .map(|_| Mutex::new(HashMap::new()))
                .collect(),
        }
    }
}

impl TrafficRegistry {
    pub fn shared() -> SharedTrafficRegistry {
        Arc::new(Self::default())
    }

    pub fn add(
        &self,
        node_tag: impl Into<String>,
        user_uuid: impl Into<String>,
        upload: u64,
        download: u64,
    ) {
        self.add_with_ip(node_tag, user_uuid, upload, download, None);
    }

    pub fn add_with_ip(
        &self,
        node_tag: impl Into<String>,
        user_uuid: impl Into<String>,
        upload: u64,
        download: u64,
        client_ip: Option<IpAddr>,
    ) {
        self.add_with_user_id(node_tag, user_uuid, None, upload, download, client_ip);
    }

    pub fn add_with_user_id(
        &self,
        node_tag: impl Into<String>,
        user_uuid: impl Into<String>,
        user_id: Option<u64>,
        upload: u64,
        download: u64,
        client_ip: Option<IpAddr>,
    ) {
        let key = TrafficKey {
            node_tag: node_tag.into(),
            user_uuid: user_uuid.into(),
        };
        let mut shard = self
            .shard_for(&key)
            .lock()
            .expect("traffic shard lock poisoned");
        let entry = match shard.entry(key) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                let key = entry.key();
                let delta = TrafficDelta {
                    node_tag: key.node_tag.clone(),
                    user_uuid: key.user_uuid.clone(),
                    user_id,
                    upload: 0,
                    download: 0,
                    online_ips: Vec::new(),
                };
                entry.insert(delta)
            }
        };
        if entry.user_id.is_none() {
            entry.user_id = user_id;
        }
        entry.upload = entry.upload.saturating_add(upload);
        entry.download = entry.download.saturating_add(download);
        if let Some(client_ip) = client_ip {
            let client_ip = client_ip.to_string();
            if !entry.online_ips.iter().any(|value| value == &client_ip) {
                entry.online_ips.push(client_ip);
                entry.online_ips.sort();
            }
        }
    }

    pub fn add_delta(&self, delta: TrafficDelta) {
        let key = TrafficKey {
            node_tag: delta.node_tag,
            user_uuid: delta.user_uuid,
        };
        let mut shard = self
            .shard_for(&key)
            .lock()
            .expect("traffic shard lock poisoned");
        let entry = match shard.entry(key) {
            Entry::Occupied(entry) => entry.into_mut(),
            Entry::Vacant(entry) => {
                let node_tag = entry.key().node_tag.clone();
                let user_uuid = entry.key().user_uuid.clone();
                entry.insert(TrafficDelta {
                    node_tag,
                    user_uuid,
                    user_id: delta.user_id,
                    upload: 0,
                    download: 0,
                    online_ips: Vec::new(),
                })
            }
        };
        if entry.user_id.is_none() {
            entry.user_id = delta.user_id;
        }
        entry.upload = entry.upload.saturating_add(delta.upload);
        entry.download = entry.download.saturating_add(delta.download);
        for ip in delta.online_ips {
            if !entry.online_ips.iter().any(|value| value == &ip) {
                entry.online_ips.push(ip);
            }
        }
        entry.online_ips.sort();
    }

    pub fn add_deltas(&self, records: impl IntoIterator<Item = TrafficDelta>) {
        for record in records {
            self.add_delta(record);
        }
    }

    pub fn drain_all(&self) -> Vec<TrafficDelta> {
        let mut records = Vec::new();
        for shard in &self.shards {
            records.extend(
                shard
                    .lock()
                    .expect("traffic shard lock poisoned")
                    .drain()
                    .map(|(_, value)| value),
            );
        }
        records.sort_by(|left, right| {
            left.node_tag
                .cmp(&right.node_tag)
                .then_with(|| left.user_uuid.cmp(&right.user_uuid))
        });
        records
    }

    pub fn drain_minimum(&self, minimum_bytes: u64) -> Vec<TrafficDelta> {
        let mut records = Vec::new();
        for shard in &self.shards {
            let mut shard = shard.lock().expect("traffic shard lock poisoned");
            let keys = shard
                .iter()
                .filter_map(|(key, value)| {
                    let total = value.upload.saturating_add(value.download);
                    (total >= minimum_bytes).then(|| key.clone())
                })
                .collect::<Vec<_>>();

            for key in keys {
                if let Some(value) = shard.remove(&key) {
                    records.push(value);
                }
            }
        }
        records.sort_by(|left, right| {
            left.node_tag
                .cmp(&right.node_tag)
                .then_with(|| left.user_uuid.cmp(&right.user_uuid))
        });
        records
    }

    pub fn len(&self) -> usize {
        self.shards
            .iter()
            .map(|shard| shard.lock().expect("traffic shard lock poisoned").len())
            .sum()
    }

    pub fn is_empty(&self) -> bool {
        self.shards.iter().all(|shard| {
            shard
                .lock()
                .expect("traffic shard lock poisoned")
                .is_empty()
        })
    }

    fn shard_for(&self, key: &TrafficKey) -> &Mutex<HashMap<TrafficKey, TrafficDelta>> {
        let mut hasher = DefaultHasher::new();
        key.hash(&mut hasher);
        &self.shards[(hasher.finish() as usize) % self.shards.len()]
    }
}

#[cfg(test)]
mod tests {
    use std::thread;

    use super::TrafficRegistry;

    #[test]
    fn accumulates_and_drains_traffic() {
        let registry = TrafficRegistry::default();

        registry.add("node-a", "user-a", 10, 20);
        registry.add("node-a", "user-a", 1, 2);
        registry.add("node-a", "user-b", 1, 1);

        let records = registry.drain_minimum(10);

        assert_eq!(records.len(), 1);
        assert_eq!(records[0].upload, 11);
        assert_eq!(records[0].download, 22);
        assert_eq!(registry.len(), 1);
    }

    #[test]
    fn records_online_ips_without_duplicates() {
        let registry = TrafficRegistry::default();

        registry.add_with_ip(
            "node-a",
            "user-a",
            1,
            1,
            Some("198.51.100.7".parse().unwrap()),
        );
        registry.add_with_ip(
            "node-a",
            "user-a",
            1,
            1,
            Some("198.51.100.7".parse().unwrap()),
        );

        let records = registry.drain_minimum(1);

        assert_eq!(records[0].online_ips, vec!["198.51.100.7"]);
    }

    #[test]
    fn preserves_user_id_for_deleted_user_reporting() {
        let registry = TrafficRegistry::default();

        registry.add_with_user_id("node-a", "user-a", Some(42), 10, 20, None);
        registry.add_with_user_id("node-a", "user-a", None, 1, 2, None);

        let records = registry.drain_all();

        assert_eq!(records[0].user_uuid, "user-a");
        assert_eq!(records[0].user_id, Some(42));
        assert_eq!(records[0].upload, 11);
        assert_eq!(records[0].download, 22);
    }

    #[test]
    fn requeues_drained_traffic_deltas() {
        let registry = TrafficRegistry::default();

        registry.add_with_user_id(
            "node-a",
            "user-a",
            Some(42),
            10,
            20,
            Some("198.51.100.7".parse().unwrap()),
        );
        let records = registry.drain_all();
        assert!(registry.is_empty());

        registry.add_deltas(records);
        registry.add_with_user_id(
            "node-a",
            "user-a",
            None,
            1,
            2,
            Some("198.51.100.8".parse().unwrap()),
        );
        let records = registry.drain_all();

        assert_eq!(records[0].user_id, Some(42));
        assert_eq!(records[0].upload, 11);
        assert_eq!(records[0].download, 22);
        assert_eq!(records[0].online_ips, vec!["198.51.100.7", "198.51.100.8"]);
    }

    #[test]
    fn shared_registry_accepts_concurrent_writers() {
        let registry = TrafficRegistry::shared();
        let mut workers = Vec::new();

        for worker in 0..16 {
            let registry = registry.clone();
            workers.push(thread::spawn(move || {
                for _ in 0..100 {
                    registry.add_with_user_id(
                        "node-a",
                        format!("user-{worker}"),
                        Some(worker),
                        1,
                        2,
                        None,
                    );
                }
            }));
        }

        for worker in workers {
            worker.join().expect("traffic worker should not panic");
        }

        let records = registry.drain_all();
        assert_eq!(records.len(), 16);
        assert_eq!(
            records.iter().map(|record| record.upload).sum::<u64>(),
            1600
        );
        assert_eq!(
            records.iter().map(|record| record.download).sum::<u64>(),
            3200
        );
    }
}
