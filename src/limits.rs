use std::collections::HashMap;
use std::fmt;
use std::sync::{Arc, Mutex};

use crate::user::CoreUser;

#[derive(Clone, Debug, Default)]
pub struct UserSessionTracker {
    active: Arc<Mutex<HashMap<String, usize>>>,
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

#[cfg(test)]
mod tests {
    use crate::limits::UserSessionTracker;
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
}
