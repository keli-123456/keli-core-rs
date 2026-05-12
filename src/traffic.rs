use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::net::IpAddr;

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

#[derive(Clone, Debug, Default)]
pub struct TrafficRegistry {
    counters: HashMap<TrafficKey, TrafficDelta>,
}

impl TrafficRegistry {
    pub fn add(
        &mut self,
        node_tag: impl Into<String>,
        user_uuid: impl Into<String>,
        upload: u64,
        download: u64,
    ) {
        self.add_with_ip(node_tag, user_uuid, upload, download, None);
    }

    pub fn add_with_ip(
        &mut self,
        node_tag: impl Into<String>,
        user_uuid: impl Into<String>,
        upload: u64,
        download: u64,
        client_ip: Option<IpAddr>,
    ) {
        self.add_with_user_id(node_tag, user_uuid, None, upload, download, client_ip);
    }

    pub fn add_with_user_id(
        &mut self,
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
        let entry = match self.counters.entry(key) {
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

    pub fn drain_all(&mut self) -> Vec<TrafficDelta> {
        let mut records = self
            .counters
            .drain()
            .map(|(_, value)| value)
            .collect::<Vec<_>>();
        records.sort_by(|left, right| {
            left.node_tag
                .cmp(&right.node_tag)
                .then_with(|| left.user_uuid.cmp(&right.user_uuid))
        });
        records
    }

    pub fn drain_minimum(&mut self, minimum_bytes: u64) -> Vec<TrafficDelta> {
        let keys = self
            .counters
            .iter()
            .filter_map(|(key, value)| {
                let total = value.upload.saturating_add(value.download);
                (total >= minimum_bytes).then(|| key.clone())
            })
            .collect::<Vec<_>>();

        let mut records = Vec::with_capacity(keys.len());
        for key in keys {
            if let Some(value) = self.counters.remove(&key) {
                records.push(value);
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
        self.counters.len()
    }

    pub fn is_empty(&self) -> bool {
        self.counters.is_empty()
    }
}

#[cfg(test)]
mod tests {
    use super::TrafficRegistry;

    #[test]
    fn accumulates_and_drains_traffic() {
        let mut registry = TrafficRegistry::default();

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
        let mut registry = TrafficRegistry::default();

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
        let mut registry = TrafficRegistry::default();

        registry.add_with_user_id("node-a", "user-a", Some(42), 10, 20, None);
        registry.add_with_user_id("node-a", "user-a", None, 1, 2, None);

        let records = registry.drain_all();

        assert_eq!(records[0].user_uuid, "user-a");
        assert_eq!(records[0].user_id, Some(42));
        assert_eq!(records[0].upload, 11);
        assert_eq!(records[0].download, 22);
    }
}
