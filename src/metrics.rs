use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::quic_resources::QuicResourceSnapshot;

const USER_DELTA_DURATION_BUCKETS_MS: [u64; 10] = [1, 5, 10, 25, 50, 100, 250, 500, 1000, 5000];

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreMetricsSnapshot {
    pub keli_core_user_delta_apply_total: u64,
    pub keli_core_user_delta_apply_error_total: u64,
    pub keli_core_user_delta_incremental_total: u64,
    pub keli_core_user_delta_full_snapshot_total: u64,
    pub keli_core_user_delta_revision_mismatch_total: u64,
    pub keli_core_user_delta_current_revision_missing_total: u64,
    pub keli_core_user_delta_apply_duration_ms: CoreDurationMetrics,
    pub keli_core_user_delta_active_users: BTreeMap<String, usize>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keli_core_quic_resource: Option<QuicResourceSnapshot>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CoreDurationMetrics {
    pub count: u64,
    pub total_ms: u64,
    pub last_ms: u64,
    pub max_ms: u64,
    pub buckets: BTreeMap<String, u64>,
}

#[derive(Debug, Default)]
pub struct CoreMetrics {
    snapshot: CoreMetricsSnapshot,
}

impl CoreMetrics {
    pub fn snapshot(&self) -> CoreMetricsSnapshot {
        self.snapshot.clone()
    }

    pub fn snapshot_with_quic_resource(
        &self,
        quic_resource: Option<QuicResourceSnapshot>,
    ) -> CoreMetricsSnapshot {
        let mut snapshot = self.snapshot();
        snapshot.keli_core_quic_resource = quic_resource;
        snapshot
    }

    pub fn record_user_delta_success(
        &mut self,
        node_tag: &str,
        full_snapshot: bool,
        duration_ms: u64,
        active_users: usize,
    ) {
        self.record_user_delta_attempt(full_snapshot, duration_ms);
        self.snapshot
            .keli_core_user_delta_active_users
            .insert(node_tag.to_string(), active_users);
    }

    pub fn record_user_delta_error(
        &mut self,
        full_snapshot: bool,
        duration_ms: u64,
        message: &str,
    ) {
        self.record_user_delta_attempt(full_snapshot, duration_ms);
        self.snapshot.keli_core_user_delta_apply_error_total = self
            .snapshot
            .keli_core_user_delta_apply_error_total
            .saturating_add(1);
        if is_revision_mismatch(message) {
            self.snapshot.keli_core_user_delta_revision_mismatch_total = self
                .snapshot
                .keli_core_user_delta_revision_mismatch_total
                .saturating_add(1);
        }
        if is_current_revision_missing(message) {
            self.snapshot
                .keli_core_user_delta_current_revision_missing_total = self
                .snapshot
                .keli_core_user_delta_current_revision_missing_total
                .saturating_add(1);
        }
    }

    fn record_user_delta_attempt(&mut self, full_snapshot: bool, duration_ms: u64) {
        self.snapshot.keli_core_user_delta_apply_total = self
            .snapshot
            .keli_core_user_delta_apply_total
            .saturating_add(1);
        if full_snapshot {
            self.snapshot.keli_core_user_delta_full_snapshot_total = self
                .snapshot
                .keli_core_user_delta_full_snapshot_total
                .saturating_add(1);
        } else {
            self.snapshot.keli_core_user_delta_incremental_total = self
                .snapshot
                .keli_core_user_delta_incremental_total
                .saturating_add(1);
        }
        self.snapshot
            .keli_core_user_delta_apply_duration_ms
            .record(duration_ms);
    }
}

impl CoreDurationMetrics {
    fn record(&mut self, duration_ms: u64) {
        self.count = self.count.saturating_add(1);
        self.total_ms = self.total_ms.saturating_add(duration_ms);
        self.last_ms = duration_ms;
        self.max_ms = self.max_ms.max(duration_ms);
        for bucket in USER_DELTA_DURATION_BUCKETS_MS {
            if duration_ms <= bucket {
                let key = format!("le_{bucket}");
                *self.buckets.entry(key).or_default() += 1;
            }
        }
        *self.buckets.entry("le_inf".to_string()).or_default() += 1;
    }
}

fn is_revision_mismatch(message: &str) -> bool {
    message.contains("revision mismatch")
}

fn is_current_revision_missing(message: &str) -> bool {
    message.contains("current <missing>") || message.contains("full snapshot required")
}

#[cfg(test)]
mod tests {
    use crate::metrics::CoreMetrics;
    use crate::quic_resources::QuicResourceSnapshot;

    #[test]
    fn records_user_delta_success_without_user_labels() {
        let mut metrics = CoreMetrics::default();

        metrics.record_user_delta_success("panel|proxy|1", false, 12, 260_000);

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.keli_core_user_delta_apply_total, 1);
        assert_eq!(snapshot.keli_core_user_delta_incremental_total, 1);
        assert_eq!(snapshot.keli_core_user_delta_full_snapshot_total, 0);
        assert_eq!(
            snapshot.keli_core_user_delta_active_users["panel|proxy|1"],
            260_000
        );
        assert_eq!(snapshot.keli_core_user_delta_apply_duration_ms.count, 1);
        assert_eq!(
            snapshot.keli_core_user_delta_apply_duration_ms.buckets["le_25"],
            1
        );
        assert!(!snapshot
            .keli_core_user_delta_active_users
            .contains_key("user-a"));
    }

    #[test]
    fn records_revision_and_missing_current_errors() {
        let mut metrics = CoreMetrics::default();

        metrics.record_user_delta_error(
            false,
            2,
            "revision mismatch for inbound panel|proxy|1: current <missing>, base 1; full snapshot required",
        );

        let snapshot = metrics.snapshot();
        assert_eq!(snapshot.keli_core_user_delta_apply_total, 1);
        assert_eq!(snapshot.keli_core_user_delta_apply_error_total, 1);
        assert_eq!(snapshot.keli_core_user_delta_revision_mismatch_total, 1);
        assert_eq!(
            snapshot.keli_core_user_delta_current_revision_missing_total,
            1
        );
    }

    #[test]
    fn snapshots_include_quic_resource_without_user_labels() {
        let metrics = CoreMetrics::default();

        let snapshot = metrics.snapshot_with_quic_resource(Some(QuicResourceSnapshot {
            total_limit: 4096,
            active_connections: 12,
            available_connections: 4084,
            listener_count: 2,
            per_listener_soft_limit: 2048,
            cpu_count: 4,
            memory_limit_mib: Some(4096),
            fd_limit: Some(1_048_576),
        }));

        let quic = snapshot
            .keli_core_quic_resource
            .expect("quic resource metrics");
        assert_eq!(quic.total_limit, 4096);
        assert_eq!(quic.active_connections, 12);
        assert_eq!(quic.listener_count, 2);
    }
}
