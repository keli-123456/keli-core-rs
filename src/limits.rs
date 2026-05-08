use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use crate::user::CoreUser;

#[derive(Clone, Debug, Default)]
pub struct UserSessionTracker {
    active: Arc<Mutex<HashMap<String, usize>>>,
}

#[derive(Clone, Debug, Default)]
pub struct UserBandwidthLimiters {
    limiters: Arc<Mutex<HashMap<String, Arc<BandwidthLimiter>>>>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceLimitExceeded {
    user_uuid: String,
    limit: u32,
}

#[derive(Debug)]
pub struct UserSessionGuard {
    user_uuid: String,
    active: Arc<Mutex<HashMap<String, usize>>>,
}

#[derive(Debug)]
pub struct BandwidthLimiter {
    bytes_per_second: u64,
    state: Mutex<BandwidthState>,
}

#[derive(Debug)]
struct BandwidthState {
    tokens: f64,
    last_refill: Instant,
}

impl UserSessionTracker {
    pub fn try_acquire(
        &self,
        user: Option<&CoreUser>,
    ) -> Result<Option<UserSessionGuard>, DeviceLimitExceeded> {
        let Some(user) = user else {
            return Ok(None);
        };
        if user.device_limit == 0 {
            return Ok(None);
        }

        let limit = user.device_limit as usize;
        let mut active = self.active.lock().expect("user session lock poisoned");
        let current = active.get(&user.uuid).copied().unwrap_or(0);
        if current >= limit {
            return Err(DeviceLimitExceeded {
                user_uuid: user.uuid.clone(),
                limit: user.device_limit,
            });
        }

        active.insert(user.uuid.clone(), current + 1);
        Ok(Some(UserSessionGuard {
            user_uuid: user.uuid.clone(),
            active: Arc::clone(&self.active),
        }))
    }

    pub fn active_count(&self, user_uuid: &str) -> usize {
        self.active
            .lock()
            .expect("user session lock poisoned")
            .get(user_uuid)
            .copied()
            .unwrap_or(0)
    }
}

impl UserBandwidthLimiters {
    pub fn limiter_for(&self, user: Option<&CoreUser>) -> Option<Arc<BandwidthLimiter>> {
        let user = user?;
        let bytes_per_second = speed_limit_mbps_to_bytes_per_second(user.speed_limit)?;
        let mut limiters = self
            .limiters
            .lock()
            .expect("user bandwidth limiter lock poisoned");

        if let Some(limiter) = limiters.get(&user.uuid) {
            if limiter.bytes_per_second() == bytes_per_second {
                return Some(Arc::clone(limiter));
            }
        }

        let limiter = Arc::new(BandwidthLimiter::new(bytes_per_second));
        limiters.insert(user.uuid.clone(), Arc::clone(&limiter));
        Some(limiter)
    }
}

impl BandwidthLimiter {
    pub fn new(bytes_per_second: u64) -> Self {
        Self {
            bytes_per_second: bytes_per_second.max(1),
            state: Mutex::new(BandwidthState {
                tokens: 0.0,
                last_refill: Instant::now(),
            }),
        }
    }

    pub fn bytes_per_second(&self) -> u64 {
        self.bytes_per_second
    }

    pub fn wait_for(&self, bytes: usize) {
        if bytes == 0 {
            return;
        }

        let requested = bytes as f64;
        let rate = self.bytes_per_second as f64;
        loop {
            let sleep_for = {
                let mut state = self.state.lock().expect("bandwidth limiter lock poisoned");
                let now = Instant::now();
                let elapsed = now.duration_since(state.last_refill).as_secs_f64();
                let capacity = rate.max(requested);
                state.tokens = (state.tokens + elapsed * rate).min(capacity);
                state.last_refill = now;

                if state.tokens >= requested {
                    state.tokens -= requested;
                    None
                } else {
                    let missing = requested - state.tokens;
                    state.tokens = 0.0;
                    Some(Duration::from_secs_f64(missing / rate))
                }
            };

            let Some(duration) = sleep_for else {
                return;
            };
            thread::sleep(duration);
        }
    }
}

impl DeviceLimitExceeded {
    pub fn user_uuid(&self) -> &str {
        &self.user_uuid
    }

    pub fn limit(&self) -> u32 {
        self.limit
    }
}

impl fmt::Display for DeviceLimitExceeded {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "device limit reached for user {} ({})",
            self.user_uuid, self.limit
        )
    }
}

impl std::error::Error for DeviceLimitExceeded {}

impl Drop for UserSessionGuard {
    fn drop(&mut self) {
        let Ok(mut active) = self.active.lock() else {
            return;
        };
        match active.get_mut(&self.user_uuid) {
            Some(count) if *count > 1 => *count -= 1,
            Some(_) => {
                active.remove(&self.user_uuid);
            }
            None => {}
        }
    }
}

fn speed_limit_mbps_to_bytes_per_second(mbps: u64) -> Option<u64> {
    if mbps == 0 {
        return None;
    }
    Some(mbps.saturating_mul(1024 * 1024).saturating_div(8).max(1))
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use crate::limits::{
        speed_limit_mbps_to_bytes_per_second, UserBandwidthLimiters, UserSessionTracker,
    };
    use crate::user::CoreUser;

    fn user(device_limit: u32) -> CoreUser {
        CoreUser {
            id: 1,
            uuid: "user-a".to_string(),
            password: None,
            email: None,
            speed_limit: 0,
            device_limit,
        }
    }

    #[test]
    fn unlimited_users_do_not_create_tracked_sessions() {
        let tracker = UserSessionTracker::default();
        let guard = tracker
            .try_acquire(Some(&user(0)))
            .expect("unlimited acquire");

        assert!(guard.is_none());
        assert_eq!(tracker.active_count("user-a"), 0);
    }

    #[test]
    fn enforces_limit_and_releases_on_drop() {
        let tracker = UserSessionTracker::default();
        let user = user(1);
        let guard = tracker
            .try_acquire(Some(&user))
            .expect("first acquire")
            .expect("tracked guard");

        let error = tracker
            .try_acquire(Some(&user))
            .expect_err("second acquire should be limited");
        assert_eq!(error.user_uuid(), "user-a");
        assert_eq!(error.limit(), 1);
        assert_eq!(tracker.active_count("user-a"), 1);

        drop(guard);

        assert_eq!(tracker.active_count("user-a"), 0);
        assert!(tracker
            .try_acquire(Some(&user))
            .expect("reacquire")
            .is_some());
    }

    #[test]
    fn converts_mbps_to_bytes_per_second() {
        assert_eq!(speed_limit_mbps_to_bytes_per_second(0), None);
        assert_eq!(speed_limit_mbps_to_bytes_per_second(8), Some(1024 * 1024));
    }

    #[test]
    fn bandwidth_limiter_is_reused_until_speed_changes() {
        let limiters = UserBandwidthLimiters::default();
        let mut user = user(0);
        user.speed_limit = 8;

        let first = limiters.limiter_for(Some(&user)).expect("first limiter");
        let second = limiters.limiter_for(Some(&user)).expect("second limiter");
        assert!(Arc::ptr_eq(&first, &second));

        user.speed_limit = 16;
        let third = limiters.limiter_for(Some(&user)).expect("third limiter");
        assert!(!Arc::ptr_eq(&first, &third));
        assert_eq!(third.bytes_per_second(), 2 * 1024 * 1024);
    }
}
