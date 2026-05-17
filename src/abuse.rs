use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

const TLS_FAILURE_THRESHOLD: u32 = 6;
const TLS_FAILURE_WINDOW: Duration = Duration::from_secs(30);
const TLS_FAILURE_BLOCK_DURATION: Duration = Duration::from_secs(10);
const TLS_FAILURE_MAX_ENTRIES: usize = 4096;

#[derive(Clone, Debug)]
pub struct ClientFailureBackoff {
    entries: Arc<Mutex<HashMap<IpAddr, ClientFailureEntry>>>,
    policy: ClientFailureBackoffPolicy,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ClientFailureBackoffPolicy {
    pub threshold: u32,
    pub window: Duration,
    pub block_duration: Duration,
    pub max_entries: usize,
}

#[derive(Clone, Debug)]
struct ClientFailureEntry {
    failures: u32,
    window_started: Instant,
    blocked_until: Option<Instant>,
}

impl ClientFailureBackoff {
    pub fn new(policy: ClientFailureBackoffPolicy) -> Self {
        Self {
            entries: Arc::new(Mutex::new(HashMap::new())),
            policy,
        }
    }

    pub fn tls_handshake() -> Self {
        Self::new(ClientFailureBackoffPolicy::tls_handshake())
    }

    pub fn is_blocked(&self, ip: IpAddr) -> bool {
        self.is_blocked_at(ip, Instant::now())
    }

    pub fn record_failure(&self, ip: IpAddr) {
        self.record_failure_at(ip, Instant::now());
    }

    pub fn record_success(&self, ip: IpAddr) {
        let mut entries = self
            .entries
            .lock()
            .expect("client failure backoff state poisoned");
        entries.remove(&ip);
    }

    pub fn len(&self) -> usize {
        self.entries
            .lock()
            .expect("client failure backoff state poisoned")
            .len()
    }

    pub(crate) fn is_blocked_at(&self, ip: IpAddr, now: Instant) -> bool {
        let mut entries = self
            .entries
            .lock()
            .expect("client failure backoff state poisoned");
        let Some(entry) = entries.get_mut(&ip) else {
            return false;
        };
        let Some(blocked_until) = entry.blocked_until else {
            return false;
        };
        if now < blocked_until {
            return true;
        }
        entry.failures = 0;
        entry.window_started = now;
        entry.blocked_until = None;
        false
    }

    pub(crate) fn record_failure_at(&self, ip: IpAddr, now: Instant) {
        let mut entries = self
            .entries
            .lock()
            .expect("client failure backoff state poisoned");
        if entries.len() >= self.policy.max_entries {
            entries.retain(|_, entry| !entry.is_expired(now, self.policy.window));
        }
        let entry = entries.entry(ip).or_insert(ClientFailureEntry {
            failures: 0,
            window_started: now,
            blocked_until: None,
        });
        let in_window = now
            .checked_duration_since(entry.window_started)
            .map(|elapsed| elapsed <= self.policy.window)
            .unwrap_or(false);
        if !in_window {
            entry.failures = 0;
            entry.window_started = now;
            entry.blocked_until = None;
        }
        entry.failures = entry.failures.saturating_add(1);
        if entry.failures >= self.policy.threshold {
            entry.blocked_until = Some(now + self.policy.block_duration);
        }
    }
}

impl ClientFailureBackoffPolicy {
    pub fn tls_handshake() -> Self {
        Self {
            threshold: TLS_FAILURE_THRESHOLD,
            window: TLS_FAILURE_WINDOW,
            block_duration: TLS_FAILURE_BLOCK_DURATION,
            max_entries: TLS_FAILURE_MAX_ENTRIES,
        }
    }
}

impl ClientFailureEntry {
    fn is_expired(&self, now: Instant, window: Duration) -> bool {
        if let Some(blocked_until) = self.blocked_until {
            return now >= blocked_until
                && now
                    .checked_duration_since(blocked_until)
                    .map(|elapsed| elapsed > window)
                    .unwrap_or(false);
        }
        now.checked_duration_since(self.window_started)
            .map(|elapsed| elapsed > window * 2)
            .unwrap_or(false)
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::{Duration, Instant};

    use super::{ClientFailureBackoff, ClientFailureBackoffPolicy};

    fn policy() -> ClientFailureBackoffPolicy {
        ClientFailureBackoffPolicy {
            threshold: 3,
            window: Duration::from_secs(10),
            block_duration: Duration::from_secs(5),
            max_entries: 2,
        }
    }

    #[test]
    fn repeated_failures_temporarily_block_ip() {
        let backoff = ClientFailureBackoff::new(policy());
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 10));
        let now = Instant::now();

        backoff.record_failure_at(ip, now);
        backoff.record_failure_at(ip, now + Duration::from_secs(1));
        assert!(!backoff.is_blocked_at(ip, now + Duration::from_secs(2)));

        backoff.record_failure_at(ip, now + Duration::from_secs(2));
        assert!(backoff.is_blocked_at(ip, now + Duration::from_secs(3)));
        assert!(!backoff.is_blocked_at(ip, now + Duration::from_secs(8)));
    }

    #[test]
    fn success_clears_previous_failures() {
        let backoff = ClientFailureBackoff::new(policy());
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 11));
        let now = Instant::now();

        backoff.record_failure_at(ip, now);
        backoff.record_failure_at(ip, now + Duration::from_secs(1));
        backoff.record_success(ip);
        backoff.record_failure_at(ip, now + Duration::from_secs(2));

        assert!(!backoff.is_blocked_at(ip, now + Duration::from_secs(3)));
    }

    #[test]
    fn failure_window_resets_after_idle_period() {
        let backoff = ClientFailureBackoff::new(policy());
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 12));
        let now = Instant::now();

        backoff.record_failure_at(ip, now);
        backoff.record_failure_at(ip, now + Duration::from_secs(1));
        backoff.record_failure_at(ip, now + Duration::from_secs(20));

        assert!(!backoff.is_blocked_at(ip, now + Duration::from_secs(21)));
    }

    #[test]
    fn cleanup_removes_expired_entries_when_map_is_full() {
        let backoff = ClientFailureBackoff::new(policy());
        let now = Instant::now();
        let old = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 13));
        let active = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 14));
        let next = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 15));

        backoff.record_failure_at(old, now);
        backoff.record_failure_at(active, now + Duration::from_secs(25));
        backoff.record_failure_at(next, now + Duration::from_secs(26));

        assert!(backoff.len() <= 2);
        assert!(!backoff.is_blocked_at(active, now + Duration::from_secs(27)));
        assert!(!backoff.is_blocked_at(next, now + Duration::from_secs(27)));
    }
}
