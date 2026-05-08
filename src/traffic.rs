use std::collections::HashMap;

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
    pub upload: u64,
    pub download: u64,
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
        let node_tag = node_tag.into();
        let user_uuid = user_uuid.into();
        let key = TrafficKey {
            node_tag: node_tag.clone(),
            user_uuid: user_uuid.clone(),
        };
        let entry = self.counters.entry(key).or_insert_with(|| TrafficDelta {
            node_tag,
            user_uuid,
            upload: 0,
            download: 0,
        });
        entry.upload = entry.upload.saturating_add(upload);
        entry.download = entry.download.saturating_add(download);
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
}
