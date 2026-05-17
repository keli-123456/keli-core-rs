use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock};

use serde::{Deserialize, Serialize};

use crate::abuse::ClientFailureBackoffSnapshot;
use crate::dns::{dns_metrics_snapshot, DnsMetricsSnapshot};
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
    pub keli_core_tls_handshake_failure_total: u64,
    pub keli_core_tls_handshake_backoff_reject_total: u64,
    pub keli_core_tls_handshake_backoff_active_ips: usize,
    pub keli_core_tls_handshake_backoff_blocked_ips: usize,
    pub keli_core_tcp_auth_failure_total: u64,
    pub keli_core_tcp_auth_backoff_reject_total: u64,
    pub keli_core_tcp_auth_backoff_active_ips: usize,
    pub keli_core_tcp_auth_backoff_blocked_ips: usize,
    #[serde(default)]
    pub keli_core_connection_error_total: BTreeMap<String, u64>,
    pub keli_core_dns: DnsMetricsSnapshot,
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
        self.snapshot_with_runtime_metrics(quic_resource, None, None)
    }

    pub fn snapshot_with_runtime_metrics(
        &self,
        quic_resource: Option<QuicResourceSnapshot>,
        tls_handshake: Option<ClientFailureBackoffSnapshot>,
        tcp_auth: Option<ClientFailureBackoffSnapshot>,
    ) -> CoreMetricsSnapshot {
        let mut snapshot = self.snapshot();
        snapshot.keli_core_dns = dns_metrics_snapshot();
        snapshot.keli_core_quic_resource = quic_resource;
        if let Some(tls_handshake) = tls_handshake {
            snapshot.keli_core_tls_handshake_failure_total = tls_handshake.failure_total;
            snapshot.keli_core_tls_handshake_backoff_reject_total =
                tls_handshake.backoff_reject_total;
            snapshot.keli_core_tls_handshake_backoff_active_ips = tls_handshake.active_ips;
            snapshot.keli_core_tls_handshake_backoff_blocked_ips = tls_handshake.blocked_ips;
        }
        if let Some(tcp_auth) = tcp_auth {
            snapshot.keli_core_tcp_auth_failure_total = tcp_auth.failure_total;
            snapshot.keli_core_tcp_auth_backoff_reject_total = tcp_auth.backoff_reject_total;
            snapshot.keli_core_tcp_auth_backoff_active_ips = tcp_auth.active_ips;
            snapshot.keli_core_tcp_auth_backoff_blocked_ips = tcp_auth.blocked_ips;
        }
        snapshot.keli_core_connection_error_total = connection_error_metrics_snapshot();
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

pub fn record_connection_error(protocol: &'static str, scope: &'static str, reason: &'static str) {
    let key = connection_error_key(protocol, scope, reason);
    let mut metrics = connection_error_metrics()
        .lock()
        .expect("connection error metrics poisoned");
    let counter = metrics.entry(key).or_default();
    *counter = counter.saturating_add(1);
}

fn connection_error_metrics_snapshot() -> BTreeMap<String, u64> {
    connection_error_metrics()
        .lock()
        .expect("connection error metrics poisoned")
        .clone()
}

fn connection_error_metrics() -> &'static Mutex<BTreeMap<String, u64>> {
    static METRICS: OnceLock<Mutex<BTreeMap<String, u64>>> = OnceLock::new();
    METRICS.get_or_init(|| Mutex::new(BTreeMap::new()))
}

fn connection_error_key(protocol: &str, scope: &str, reason: &str) -> String {
    format!(
        "{}.{}.{}",
        sanitize_connection_error_part(protocol),
        sanitize_connection_error_part(scope),
        sanitize_connection_error_part(reason)
    )
}

fn sanitize_connection_error_part(value: &str) -> String {
    value
        .chars()
        .map(|ch| match ch {
            'a'..='z' | '0'..='9' | '_' | '-' => ch,
            'A'..='Z' => ch.to_ascii_lowercase(),
            _ => '_',
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::abuse::ClientFailureBackoffSnapshot;
    use crate::metrics::{record_connection_error, CoreMetrics};
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

    #[test]
    fn snapshots_include_abuse_backoff_metrics_without_ip_labels() {
        let metrics = CoreMetrics::default();

        let snapshot = metrics.snapshot_with_runtime_metrics(
            None,
            Some(ClientFailureBackoffSnapshot {
                failure_total: 7,
                backoff_reject_total: 2,
                active_ips: 3,
                blocked_ips: 1,
            }),
            Some(ClientFailureBackoffSnapshot {
                failure_total: 11,
                backoff_reject_total: 4,
                active_ips: 5,
                blocked_ips: 2,
            }),
        );

        assert_eq!(snapshot.keli_core_tls_handshake_failure_total, 7);
        assert_eq!(snapshot.keli_core_tls_handshake_backoff_reject_total, 2);
        assert_eq!(snapshot.keli_core_tls_handshake_backoff_active_ips, 3);
        assert_eq!(snapshot.keli_core_tls_handshake_backoff_blocked_ips, 1);
        assert_eq!(snapshot.keli_core_tcp_auth_failure_total, 11);
        assert_eq!(snapshot.keli_core_tcp_auth_backoff_reject_total, 4);
        assert_eq!(snapshot.keli_core_tcp_auth_backoff_active_ips, 5);
        assert_eq!(snapshot.keli_core_tcp_auth_backoff_blocked_ips, 2);
    }

    #[test]
    fn snapshots_include_dns_metrics_without_host_labels() {
        let metrics = CoreMetrics::default();
        let dns = crate::dns::dns_metrics_snapshot();

        let snapshot = metrics.snapshot_with_runtime_metrics(None, None, None);

        assert_eq!(snapshot.keli_core_dns, dns);
    }

    #[test]
    fn snapshots_include_connection_error_metrics_without_dynamic_labels() {
        let metrics = CoreMetrics::default();

        record_connection_error("VLESS", "tcp relay", "upstream timeout");

        let snapshot = metrics.snapshot_with_runtime_metrics(None, None, None);
        assert_eq!(
            snapshot.keli_core_connection_error_total["vless.tcp_relay.upstream_timeout"],
            1
        );
        assert!(!snapshot
            .keli_core_connection_error_total
            .contains_key("user-a"));
    }
}
