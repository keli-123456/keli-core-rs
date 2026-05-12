use std::collections::hash_map::DefaultHasher;
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::hash::{Hash, Hasher};
use std::io;
use std::net::{IpAddr, Shutdown, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::thread;
use std::time::{Duration, Instant};

use crate::user::{CoreUser, CoreUserDelta};

const USER_LIMIT_SHARDS: usize = 64;

type UserSessionShards = Arc<Vec<Mutex<HashMap<String, UserSessionState>>>>;
type BandwidthLimiterShards = Arc<Vec<Mutex<HashMap<String, Arc<BandwidthLimiter>>>>>;
type UserConnectionShards = Arc<Vec<Mutex<HashMap<String, Vec<Weak<UserConnectionHandle>>>>>>;

#[derive(Clone, Debug)]
pub struct UserSessionTracker {
    active: UserSessionShards,
}

#[derive(Clone, Debug)]
pub struct UserBandwidthLimiters {
    limiters: BandwidthLimiterShards,
    connections: UserConnectionShards,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceLimitExceeded {
    user_uuid: String,
    limit: u32,
}

#[derive(Debug)]
pub struct UserSessionGuard {
    user_uuid: String,
    key: UserSessionKey,
    active: UserSessionShards,
}

#[derive(Debug)]
pub struct UserConnectionGuard {
    user_uuid: String,
    handle: Arc<UserConnectionHandle>,
    active: UserConnectionShards,
}

#[derive(Debug)]
pub struct BandwidthLimiter {
    bytes_per_second: AtomicU64,
    revoked: AtomicBool,
    state: Mutex<BandwidthState>,
}

#[derive(Debug)]
struct BandwidthState {
    tokens: f64,
    last_refill: Instant,
}

#[derive(Debug)]
struct UserConnectionHandle {
    sockets: Vec<TcpStream>,
}

#[derive(Clone, Debug, Default)]
struct UserSessionState {
    ips: HashMap<IpAddr, usize>,
    anonymous: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum UserSessionKey {
    Ip(IpAddr),
    Anonymous,
}

impl Default for UserSessionTracker {
    fn default() -> Self {
        Self {
            active: sharded_hash_maps(),
        }
    }
}

impl Default for UserBandwidthLimiters {
    fn default() -> Self {
        Self {
            limiters: sharded_hash_maps(),
            connections: sharded_hash_maps(),
        }
    }
}

impl UserSessionTracker {
    pub fn try_acquire(
        &self,
        user: Option<&CoreUser>,
    ) -> Result<Option<UserSessionGuard>, DeviceLimitExceeded> {
        self.try_acquire_for_ip(user, None)
    }

    pub fn try_acquire_for_ip(
        &self,
        user: Option<&CoreUser>,
        client_ip: Option<IpAddr>,
    ) -> Result<Option<UserSessionGuard>, DeviceLimitExceeded> {
        let Some(user) = user else {
            return Ok(None);
        };
        if user.device_limit == 0 {
            return Ok(None);
        }

        let limit = user.device_limit as usize;
        let mut active = user_session_shard(&self.active, &user.uuid)
            .lock()
            .expect("user session lock poisoned");
        let state = active.entry(user.uuid.clone()).or_default();
        let key = if let Some(ip) = client_ip {
            if let Some(count) = state.ips.get_mut(&ip) {
                *count += 1;
                return Ok(Some(UserSessionGuard {
                    user_uuid: user.uuid.clone(),
                    key: UserSessionKey::Ip(ip),
                    active: Arc::clone(&self.active),
                }));
            }
            if state.device_count() >= limit {
                return Err(DeviceLimitExceeded {
                    user_uuid: user.uuid.clone(),
                    limit: user.device_limit,
                });
            }
            state.ips.insert(ip, 1);
            UserSessionKey::Ip(ip)
        } else {
            if state.device_count() >= limit {
                return Err(DeviceLimitExceeded {
                    user_uuid: user.uuid.clone(),
                    limit: user.device_limit,
                });
            }
            state.anonymous += 1;
            UserSessionKey::Anonymous
        };
        Ok(Some(UserSessionGuard {
            user_uuid: user.uuid.clone(),
            key,
            active: Arc::clone(&self.active),
        }))
    }

    pub fn active_count(&self, user_uuid: &str) -> usize {
        user_session_shard(&self.active, user_uuid)
            .lock()
            .expect("user session lock poisoned")
            .get(user_uuid)
            .map(UserSessionState::device_count)
            .unwrap_or(0)
    }

    pub fn revoke_users(&self, user_uuids: &[String]) {
        for user_uuid in user_uuids {
            user_session_shard(&self.active, user_uuid)
                .lock()
                .expect("user session lock poisoned")
                .remove(user_uuid);
        }
    }

    pub fn sync_users(&self, users: &[CoreUser]) {
        let active_uuids = users
            .iter()
            .map(|user| user.uuid.as_str())
            .collect::<HashSet<_>>();
        for shard in self.active.iter() {
            shard
                .lock()
                .expect("user session lock poisoned")
                .retain(|uuid, _| active_uuids.contains(uuid.as_str()));
        }
    }
}

impl UserSessionState {
    fn device_count(&self) -> usize {
        self.ips.len() + self.anonymous
    }

    fn release(&mut self, key: UserSessionKey) {
        match key {
            UserSessionKey::Ip(ip) => match self.ips.get_mut(&ip) {
                Some(count) if *count > 1 => *count -= 1,
                Some(_) => {
                    self.ips.remove(&ip);
                }
                None => {}
            },
            UserSessionKey::Anonymous => {
                self.anonymous = self.anonymous.saturating_sub(1);
            }
        }
    }
}

impl UserBandwidthLimiters {
    pub fn register_tcp_connection(
        &self,
        user_uuid: Option<&str>,
        sockets: &[&TcpStream],
    ) -> io::Result<Option<UserConnectionGuard>> {
        let Some(user_uuid) = user_uuid.map(str::trim).filter(|uuid| !uuid.is_empty()) else {
            return Ok(None);
        };
        if sockets.is_empty() {
            return Ok(None);
        }

        let sockets = sockets
            .iter()
            .map(|socket| socket.try_clone())
            .collect::<io::Result<Vec<_>>>()?;
        let handle = Arc::new(UserConnectionHandle { sockets });
        let mut active = user_connection_shard(&self.connections, user_uuid)
            .lock()
            .expect("user connection lock poisoned");
        let handles = active.entry(user_uuid.to_string()).or_default();
        handles.retain(|handle| handle.upgrade().is_some());
        handles.push(Arc::downgrade(&handle));

        Ok(Some(UserConnectionGuard {
            user_uuid: user_uuid.to_string(),
            handle,
            active: Arc::clone(&self.connections),
        }))
    }

    pub fn limiter_for(&self, user: Option<&CoreUser>) -> Option<Arc<BandwidthLimiter>> {
        let user = user?;
        let bytes_per_second = speed_limit_mbps_to_bytes_per_second(user.speed_limit);
        let mut limiters = bandwidth_limiter_shard(&self.limiters, &user.uuid)
            .lock()
            .expect("user bandwidth limiter lock poisoned");

        if let Some(limiter) = limiters.get(&user.uuid) {
            match bytes_per_second {
                Some(bytes_per_second) => limiter.set_bytes_per_second(bytes_per_second),
                None => limiter.set_unlimited(),
            }
            return Some(Arc::clone(limiter));
        }

        let limiter = Arc::new(match bytes_per_second {
            Some(bytes_per_second) => BandwidthLimiter::new(bytes_per_second),
            None => BandwidthLimiter::unlimited(),
        });
        limiters.insert(user.uuid.clone(), Arc::clone(&limiter));
        Some(limiter)
    }

    pub fn sync_users(&self, users: &[CoreUser]) {
        for user in users {
            let bytes_per_second = speed_limit_mbps_to_bytes_per_second(user.speed_limit);
            let limiters = bandwidth_limiter_shard(&self.limiters, &user.uuid)
                .lock()
                .expect("user bandwidth limiter lock poisoned");
            let Some(limiter) = limiters.get(&user.uuid) else {
                continue;
            };
            match bytes_per_second {
                Some(bytes_per_second) => limiter.set_bytes_per_second(bytes_per_second),
                None => limiter.set_unlimited(),
            }
        }
    }

    pub fn sync_full_users(&self, users: &[CoreUser]) {
        let active_uuids = users
            .iter()
            .map(|user| user.uuid.as_str())
            .collect::<HashSet<_>>();
        for shard in self.limiters.iter() {
            let limiters = shard.lock().expect("user bandwidth limiter lock poisoned");
            for (uuid, limiter) in limiters.iter() {
                if !active_uuids.contains(uuid.as_str()) {
                    limiter.revoke();
                }
            }
        }
        self.close_connections_except(&active_uuids);
        self.sync_users(users);
    }

    pub fn revoke_users(&self, user_uuids: &[String]) {
        self.close_user_connections(user_uuids);
        for user_uuid in user_uuids {
            let limiters = bandwidth_limiter_shard(&self.limiters, user_uuid)
                .lock()
                .expect("user bandwidth limiter lock poisoned");
            if let Some(limiter) = limiters.get(user_uuid) {
                limiter.revoke();
            }
        }
    }

    pub fn active_connection_count(&self, user_uuid: &str) -> usize {
        let mut active = user_connection_shard(&self.connections, user_uuid)
            .lock()
            .expect("user connection lock poisoned");
        let Some(handles) = active.get_mut(user_uuid) else {
            return 0;
        };
        handles.retain(|handle| handle.upgrade().is_some());
        let count = handles.len();
        if count == 0 {
            active.remove(user_uuid);
        }
        count
    }

    fn close_user_connections(&self, user_uuids: &[String]) {
        for user_uuid in user_uuids {
            let handles = self.connection_handles(user_uuid);
            for handle in handles {
                handle.close();
            }
        }
    }

    fn close_connections_except(&self, active_uuids: &HashSet<&str>) {
        let removed = self
            .connections
            .iter()
            .flat_map(|shard| {
                let active = shard.lock().expect("user connection lock poisoned");
                active
                    .keys()
                    .filter(|uuid| !active_uuids.contains(uuid.as_str()))
                    .cloned()
                    .collect::<Vec<_>>()
            })
            .collect::<Vec<_>>();
        self.close_user_connections(&removed);
    }

    fn connection_handles(&self, user_uuid: &str) -> Vec<Arc<UserConnectionHandle>> {
        let mut active = user_connection_shard(&self.connections, user_uuid)
            .lock()
            .expect("user connection lock poisoned");
        let Some(handles) = active.get_mut(user_uuid) else {
            return Vec::new();
        };
        let upgraded = handles.iter().filter_map(Weak::upgrade).collect::<Vec<_>>();
        handles.retain(|handle| handle.upgrade().is_some());
        if handles.is_empty() {
            active.remove(user_uuid);
        }
        upgraded
    }
}

pub fn sync_user_limit_delta(
    bandwidth: &UserBandwidthLimiters,
    sessions: &UserSessionTracker,
    delta: &CoreUserDelta,
) {
    if let Some(full) = delta.full.as_ref() {
        bandwidth.sync_full_users(full);
        sessions.sync_users(full);
    } else {
        bandwidth.revoke_users(&delta.deleted);
        sessions.revoke_users(&delta.deleted);
        bandwidth.sync_users(&delta.added);
        bandwidth.sync_users(&delta.updated);
    }
}

impl BandwidthLimiter {
    pub fn new(bytes_per_second: u64) -> Self {
        Self {
            bytes_per_second: AtomicU64::new(bytes_per_second.max(1)),
            revoked: AtomicBool::new(false),
            state: Mutex::new(BandwidthState {
                tokens: 0.0,
                last_refill: Instant::now(),
            }),
        }
    }

    pub fn unlimited() -> Self {
        Self {
            bytes_per_second: AtomicU64::new(0),
            revoked: AtomicBool::new(false),
            state: Mutex::new(BandwidthState {
                tokens: 0.0,
                last_refill: Instant::now(),
            }),
        }
    }

    pub fn bytes_per_second(&self) -> u64 {
        self.bytes_per_second.load(Ordering::Relaxed)
    }

    fn set_bytes_per_second(&self, bytes_per_second: u64) {
        self.revoked.store(false, Ordering::Relaxed);
        self.bytes_per_second
            .store(bytes_per_second.max(1), Ordering::Relaxed);
    }

    fn set_unlimited(&self) {
        self.revoked.store(false, Ordering::Relaxed);
        self.bytes_per_second.store(0, Ordering::Relaxed);
    }

    pub fn revoke(&self) {
        self.revoked.store(true, Ordering::Relaxed);
    }

    pub fn is_revoked(&self) -> bool {
        self.revoked.load(Ordering::Relaxed)
    }

    pub fn wait_for(&self, bytes: usize) -> bool {
        if bytes == 0 {
            return !self.is_revoked();
        }

        loop {
            if self.is_revoked() {
                return false;
            }
            let Some(duration) = self.reserve_wait_duration(bytes) else {
                return !self.is_revoked();
            };
            thread::sleep(duration);
        }
    }

    pub async fn wait_for_async(&self, bytes: usize) -> bool {
        if bytes == 0 {
            return !self.is_revoked();
        }

        loop {
            if self.is_revoked() {
                return false;
            }
            let Some(duration) = self.reserve_wait_duration(bytes) else {
                return !self.is_revoked();
            };
            tokio::time::sleep(duration).await;
        }
    }

    fn reserve_wait_duration(&self, bytes: usize) -> Option<Duration> {
        let requested = bytes as f64;
        let bytes_per_second = self.bytes_per_second();
        if bytes_per_second == 0 {
            return None;
        }
        let rate = bytes_per_second as f64;
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

impl UserConnectionHandle {
    fn close(&self) {
        for socket in &self.sockets {
            let _ = socket.shutdown(Shutdown::Both);
        }
    }
}

impl Drop for UserSessionGuard {
    fn drop(&mut self) {
        let Ok(mut active) = user_session_shard(&self.active, &self.user_uuid).lock() else {
            return;
        };
        if let Some(state) = active.get_mut(&self.user_uuid) {
            state.release(self.key);
            if state.device_count() == 0 {
                active.remove(&self.user_uuid);
            }
        }
    }
}

impl Drop for UserConnectionGuard {
    fn drop(&mut self) {
        let Ok(mut active) = user_connection_shard(&self.active, &self.user_uuid).lock() else {
            return;
        };
        if let Some(handles) = active.get_mut(&self.user_uuid) {
            handles.retain(|weak| {
                weak.upgrade()
                    .map(|handle| !Arc::ptr_eq(&handle, &self.handle))
                    .unwrap_or(false)
            });
            if handles.is_empty() {
                active.remove(&self.user_uuid);
            }
        }
    }
}

fn speed_limit_mbps_to_bytes_per_second(mbps: u64) -> Option<u64> {
    if mbps == 0 {
        return None;
    }
    Some(mbps.saturating_mul(1024 * 1024).saturating_div(8).max(1))
}

fn sharded_hash_maps<T>() -> Arc<Vec<Mutex<HashMap<String, T>>>> {
    Arc::new(
        (0..USER_LIMIT_SHARDS)
            .map(|_| Mutex::new(HashMap::new()))
            .collect(),
    )
}

fn user_session_shard<'a>(
    shards: &'a UserSessionShards,
    user_uuid: &str,
) -> &'a Mutex<HashMap<String, UserSessionState>> {
    &shards[user_limit_shard_index(user_uuid)]
}

fn bandwidth_limiter_shard<'a>(
    shards: &'a BandwidthLimiterShards,
    user_uuid: &str,
) -> &'a Mutex<HashMap<String, Arc<BandwidthLimiter>>> {
    &shards[user_limit_shard_index(user_uuid)]
}

fn user_connection_shard<'a>(
    shards: &'a UserConnectionShards,
    user_uuid: &str,
) -> &'a Mutex<HashMap<String, Vec<Weak<UserConnectionHandle>>>> {
    &shards[user_limit_shard_index(user_uuid)]
}

fn user_limit_shard_index(user_uuid: &str) -> usize {
    let mut hasher = DefaultHasher::new();
    user_uuid.hash(&mut hasher);
    (hasher.finish() as usize) % USER_LIMIT_SHARDS
}

#[cfg(test)]
mod tests {
    use std::io::Read;
    use std::net::{TcpListener, TcpStream};
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

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
    fn counts_same_ip_as_one_device() {
        let tracker = UserSessionTracker::default();
        let user = user(1);
        let ip = "198.51.100.7".parse().expect("client ip");
        let first = tracker
            .try_acquire_for_ip(Some(&user), Some(ip))
            .expect("first acquire")
            .expect("first guard");
        let second = tracker
            .try_acquire_for_ip(Some(&user), Some(ip))
            .expect("same ip acquire")
            .expect("second guard");

        assert_eq!(tracker.active_count("user-a"), 1);
        let error = tracker
            .try_acquire_for_ip(Some(&user), Some("198.51.100.8".parse().unwrap()))
            .expect_err("different ip should be limited");
        assert_eq!(error.user_uuid(), "user-a");

        drop(first);
        assert_eq!(tracker.active_count("user-a"), 1);
        drop(second);
        assert_eq!(tracker.active_count("user-a"), 0);
    }

    #[test]
    fn converts_mbps_to_bytes_per_second() {
        assert_eq!(speed_limit_mbps_to_bytes_per_second(0), None);
        assert_eq!(speed_limit_mbps_to_bytes_per_second(8), Some(1024 * 1024));
    }

    #[test]
    fn bandwidth_limiter_updates_existing_arc_when_speed_changes() {
        let limiters = UserBandwidthLimiters::default();
        let mut user = user(0);
        user.speed_limit = 8;

        let first = limiters.limiter_for(Some(&user)).expect("first limiter");
        let second = limiters.limiter_for(Some(&user)).expect("second limiter");
        assert!(Arc::ptr_eq(&first, &second));

        user.speed_limit = 16;
        let third = limiters.limiter_for(Some(&user)).expect("third limiter");
        assert!(Arc::ptr_eq(&first, &third));
        assert_eq!(third.bytes_per_second(), 2 * 1024 * 1024);
    }

    #[test]
    fn bandwidth_limiter_can_disable_existing_arc() {
        let limiters = UserBandwidthLimiters::default();
        let mut user = user(0);
        user.speed_limit = 8;
        let limiter = limiters.limiter_for(Some(&user)).expect("limited");

        user.speed_limit = 0;

        let unlimited = limiters.limiter_for(Some(&user)).expect("unlimited");
        assert!(Arc::ptr_eq(&limiter, &unlimited));
        assert_eq!(limiter.bytes_per_second(), 0);
    }

    #[test]
    fn unlimited_users_still_get_revocable_limiters() {
        let limiters = UserBandwidthLimiters::default();
        let user = user(0);

        let limiter = limiters
            .limiter_for(Some(&user))
            .expect("unlimited limiter");

        assert_eq!(limiter.bytes_per_second(), 0);
        assert!(!limiter.is_revoked());
        assert!(limiter.wait_for(16));
    }

    #[test]
    fn revoked_limiter_stops_existing_connection_and_can_be_reenabled() {
        let limiters = UserBandwidthLimiters::default();
        let user = user(0);
        let limiter = limiters.limiter_for(Some(&user)).expect("active limiter");

        limiters.revoke_users(std::slice::from_ref(&user.uuid));

        assert!(limiter.is_revoked());
        assert!(!limiter.wait_for(16));

        let revived = limiters.limiter_for(Some(&user)).expect("revived limiter");
        assert!(Arc::ptr_eq(&limiter, &revived));
        assert!(!revived.is_revoked());
        assert!(revived.wait_for(16));
    }

    #[test]
    fn revoke_user_closes_registered_tcp_connections() {
        let limiters = UserBandwidthLimiters::default();
        let user = user(0);
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        let client = TcpStream::connect(listener.local_addr().expect("addr")).expect("client");
        let (server, _) = listener.accept().expect("server");
        client
            .set_read_timeout(Some(Duration::from_millis(500)))
            .expect("client timeout");

        let guard = limiters
            .register_tcp_connection(Some(&user.uuid), &[&client, &server])
            .expect("register")
            .expect("guard");
        assert_eq!(limiters.active_connection_count(&user.uuid), 1);

        limiters.revoke_users(std::slice::from_ref(&user.uuid));

        let mut buffer = [0u8; 1];
        let closed = matches!(client.peek(&mut buffer), Ok(0) | Err(_))
            || matches!(
                client.try_clone().unwrap().read(&mut buffer),
                Ok(0) | Err(_)
            );
        assert!(closed, "registered connection should close on revoke");
        drop(guard);
        assert_eq!(limiters.active_connection_count(&user.uuid), 0);
    }

    #[test]
    fn sync_users_updates_active_bandwidth_limiter() {
        let limiters = UserBandwidthLimiters::default();
        let mut user = user(0);
        user.speed_limit = 8;
        let limiter = limiters.limiter_for(Some(&user)).expect("limited");

        user.speed_limit = 32;
        limiters.sync_users(&[user.clone()]);

        assert_eq!(limiter.bytes_per_second(), 4 * 1024 * 1024);

        user.speed_limit = 0;
        limiters.sync_users(&[user]);

        assert_eq!(limiter.bytes_per_second(), 0);
    }

    #[test]
    fn deleted_user_clears_active_device_sessions() {
        let tracker = UserSessionTracker::default();
        let user = user(1);
        let guard = tracker
            .try_acquire(Some(&user))
            .expect("session acquire")
            .expect("tracked session");

        tracker.revoke_users(std::slice::from_ref(&user.uuid));

        assert_eq!(tracker.active_count(&user.uuid), 0);
        drop(guard);
        assert_eq!(tracker.active_count(&user.uuid), 0);
    }

    #[test]
    fn full_user_snapshot_prunes_removed_sessions() {
        let tracker = UserSessionTracker::default();
        let user_a = user(1);
        let mut user_b = user(1);
        user_b.uuid = "user-b".to_string();
        let guard_a = tracker
            .try_acquire(Some(&user_a))
            .expect("session a")
            .expect("guard a");
        let guard_b = tracker
            .try_acquire(Some(&user_b))
            .expect("session b")
            .expect("guard b");

        tracker.sync_users(std::slice::from_ref(&user_b));

        assert_eq!(tracker.active_count(&user_a.uuid), 0);
        assert_eq!(tracker.active_count(&user_b.uuid), 1);
        drop(guard_a);
        drop(guard_b);
        assert_eq!(tracker.active_count(&user_b.uuid), 0);
    }

    #[test]
    fn full_user_snapshot_revokes_removed_bandwidth_limiters() {
        let limiters = UserBandwidthLimiters::default();
        let user_a = user(0);
        let mut user_b = user(0);
        user_b.uuid = "user-b".to_string();
        let limiter_a = limiters.limiter_for(Some(&user_a)).expect("limiter a");
        let limiter_b = limiters.limiter_for(Some(&user_b)).expect("limiter b");

        limiters.sync_full_users(std::slice::from_ref(&user_b));

        assert!(limiter_a.is_revoked());
        assert!(!limiter_b.is_revoked());
    }

    #[test]
    fn session_tracker_accepts_concurrent_users() {
        let tracker = UserSessionTracker::default();
        let mut workers = Vec::new();

        for index in 0..16 {
            let tracker = tracker.clone();
            workers.push(thread::spawn(move || {
                let mut user = user(1);
                user.uuid = format!("user-{index}");
                tracker
                    .try_acquire_for_ip(Some(&user), Some("198.51.100.7".parse().unwrap()))
                    .expect("concurrent acquire")
                    .expect("tracked guard")
            }));
        }

        let guards = workers
            .into_iter()
            .map(|worker| worker.join().expect("session worker should not panic"))
            .collect::<Vec<_>>();
        for index in 0..16 {
            assert_eq!(tracker.active_count(&format!("user-{index}")), 1);
        }

        drop(guards);
        for index in 0..16 {
            assert_eq!(tracker.active_count(&format!("user-{index}")), 0);
        }
    }

    #[test]
    fn bandwidth_limiters_share_same_user_limiter_across_threads() {
        let limiters = UserBandwidthLimiters::default();
        let mut workers = Vec::new();

        for _ in 0..16 {
            let limiters = limiters.clone();
            workers.push(thread::spawn(move || {
                let mut user = user(0);
                user.speed_limit = 8;
                limiters.limiter_for(Some(&user)).expect("limiter")
            }));
        }

        let limiters = workers
            .into_iter()
            .map(|worker| worker.join().expect("limiter worker should not panic"))
            .collect::<Vec<_>>();
        for limiter in &limiters[1..] {
            assert!(Arc::ptr_eq(&limiters[0], limiter));
        }
    }
}
