use std::collections::hash_map::DefaultHasher;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fmt;
use std::hash::{Hash, Hasher};
use std::io;
use std::net::{IpAddr, Shutdown, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, Weak};
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use socket2::SockRef;
use tokio::sync::Notify;

use crate::user::{CoreUser, CoreUserDelta};

const USER_LIMIT_SHARDS: usize = 64;
const REPORTED_ALIVE_BRIDGE_TTL: Duration = Duration::from_secs(120);

type UserSessionShards = Arc<Vec<Mutex<HashMap<String, UserSessionState>>>>;
type BandwidthLimiterShards = Arc<Vec<Mutex<HashMap<String, Arc<BandwidthLimiter>>>>>;
type UserConnectionShards = Arc<Vec<Mutex<HashMap<String, Vec<Weak<UserConnectionHandle>>>>>>;

#[derive(Clone, Debug)]
pub struct UserSessionTracker {
    active: UserSessionShards,
    devices: Arc<Mutex<DeviceLimitRuntimeState>>,
}

#[derive(Clone, Debug)]
pub struct UserBandwidthLimiters {
    limiters: BandwidthLimiterShards,
    connections: ActiveConnectionRegistry,
}

#[derive(Clone, Debug)]
pub struct ActiveConnectionRegistry {
    active: UserConnectionShards,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DeviceLimitExceeded {
    user_uuid: String,
    limit: u32,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DeviceLimitPolicy {
    pub udp_rebind_tolerant: bool,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceLimitSnapshot {
    pub node_tag: String,
    #[serde(default)]
    pub alive: BTreeMap<u64, usize>,
    #[serde(default)]
    pub alive_ips: BTreeMap<u64, Vec<IpAddr>>,
    #[serde(default)]
    pub mode: i32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceLimitOnlineRecord {
    pub node_tag: String,
    pub user_id: u64,
    pub ip: IpAddr,
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
    revoked_notify: Notify,
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

#[derive(Debug, Default)]
struct DeviceLimitRuntimeState {
    snapshots: HashMap<String, DeviceLimitNodeState>,
    pending: HashMap<String, HashMap<IpAddr, u64>>,
    reported: HashMap<String, HashMap<u64, HashMap<IpAddr, Instant>>>,
}

#[derive(Debug)]
struct DeviceLimitNodeState {
    alive: HashMap<u64, usize>,
    alive_ips: HashMap<u64, HashSet<IpAddr>>,
    mode: i32,
    last_alive_pull: Instant,
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
            devices: Arc::new(Mutex::new(DeviceLimitRuntimeState::default())),
        }
    }
}

impl Default for UserBandwidthLimiters {
    fn default() -> Self {
        Self {
            limiters: sharded_hash_maps(),
            connections: ActiveConnectionRegistry::default(),
        }
    }
}

impl Default for ActiveConnectionRegistry {
    fn default() -> Self {
        Self {
            active: sharded_hash_maps(),
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
        self.try_acquire_for_node_ip("", user, client_ip)
    }

    pub fn try_acquire_for_node_ip(
        &self,
        node_tag: &str,
        user: Option<&CoreUser>,
        client_ip: Option<IpAddr>,
    ) -> Result<Option<UserSessionGuard>, DeviceLimitExceeded> {
        self.try_acquire_for_node_ip_with_policy(
            node_tag,
            user,
            client_ip,
            DeviceLimitPolicy::default(),
        )
    }

    pub fn try_acquire_for_node_ip_with_policy(
        &self,
        node_tag: &str,
        user: Option<&CoreUser>,
        client_ip: Option<IpAddr>,
        policy: DeviceLimitPolicy,
    ) -> Result<Option<UserSessionGuard>, DeviceLimitExceeded> {
        let Some(user) = user else {
            return Ok(None);
        };
        if user.device_limit == 0 {
            return Ok(None);
        }
        if let Some(client_ip) = client_ip {
            self.check_device_limit_ip(node_tag, user, client_ip, policy)?;
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

    pub fn apply_device_limit_snapshot(&self, snapshot: DeviceLimitSnapshot) {
        let mut devices = self.devices.lock().expect("device limit lock poisoned");
        let now = Instant::now();
        devices.prune_reported(now);
        devices.snapshots.insert(
            snapshot.node_tag,
            DeviceLimitNodeState {
                alive: snapshot.alive.into_iter().collect(),
                alive_ips: snapshot
                    .alive_ips
                    .into_iter()
                    .map(|(user_id, ips)| (user_id, ips.into_iter().collect()))
                    .collect(),
                mode: snapshot.mode,
                last_alive_pull: now,
            },
        );
    }

    pub fn commit_device_limit_report(&self, records: &[DeviceLimitOnlineRecord]) {
        let mut devices = self.devices.lock().expect("device limit lock poisoned");
        let now = Instant::now();
        devices.prune_reported(now);
        for record in records {
            if record.node_tag.trim().is_empty() || record.user_id == 0 {
                continue;
            }
            devices
                .reported
                .entry(record.node_tag.clone())
                .or_default()
                .entry(record.user_id)
                .or_default()
                .insert(record.ip, now);
            let prefix = format!("{}|", record.node_tag);
            let mut empty_keys = Vec::new();
            for (key, pending) in &mut devices.pending {
                if !key.starts_with(&prefix) {
                    continue;
                }
                if pending.get(&record.ip) == Some(&record.user_id) {
                    pending.remove(&record.ip);
                }
                if pending.is_empty() {
                    empty_keys.push(key.clone());
                }
            }
            for key in empty_keys {
                devices.pending.remove(&key);
            }
        }
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
        if !user_uuids.is_empty() {
            let mut devices = self.devices.lock().expect("device limit lock poisoned");
            devices.pending.retain(|key, _| {
                !user_uuids
                    .iter()
                    .any(|user_uuid| key == user_uuid || key.ends_with(&format!("|{user_uuid}")))
            });
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
        let mut devices = self.devices.lock().expect("device limit lock poisoned");
        devices.pending.retain(|key, _| {
            key.rsplit_once('|')
                .map(|(_, uuid)| active_uuids.contains(uuid))
                .unwrap_or_else(|| active_uuids.contains(key.as_str()))
        });
    }

    fn check_device_limit_ip(
        &self,
        node_tag: &str,
        user: &CoreUser,
        ip: IpAddr,
        policy: DeviceLimitPolicy,
    ) -> Result<(), DeviceLimitExceeded> {
        let mut devices = self.devices.lock().expect("device limit lock poisoned");
        devices.prune_reported(Instant::now());
        let key = device_limit_user_key(node_tag, &user.uuid);
        if devices
            .pending
            .get(&key)
            .and_then(|pending| pending.get(&ip))
            == Some(&user.id)
        {
            return Ok(());
        }
        let known = devices.is_known_alive_ip(node_tag, user.id, ip);
        if !known {
            let known_device_count = devices.known_device_count(node_tag, user.id);
            let mut pending_new = devices.pending_new_ip_count(&key, node_tag, user.id);
            if user.device_limit as usize <= known_device_count.saturating_add(pending_new)
                && policy.udp_rebind_tolerant
                && known_device_count > 0
            {
                if devices.drop_one_pending_unknown_ip(&key, node_tag, user.id) && pending_new > 0 {
                    pending_new -= 1;
                }
            }
            if user.device_limit as usize <= known_device_count.saturating_add(pending_new) {
                if !(policy.udp_rebind_tolerant
                    && known_device_count > 0
                    && user.device_limit as usize == known_device_count.saturating_add(pending_new))
                {
                    return Err(DeviceLimitExceeded {
                        user_uuid: user.uuid.clone(),
                        limit: user.device_limit,
                    });
                }
            }
        }
        devices.pending.entry(key).or_default().insert(ip, user.id);
        Ok(())
    }
}

impl DeviceLimitRuntimeState {
    fn prune_reported(&mut self, now: Instant) {
        for users in self.reported.values_mut() {
            for ips in users.values_mut() {
                ips.retain(|_, reported_at| {
                    now.saturating_duration_since(*reported_at) <= REPORTED_ALIVE_BRIDGE_TTL
                });
            }
            users.retain(|_, ips| !ips.is_empty());
        }
        self.reported.retain(|_, users| !users.is_empty());
    }

    fn is_known_alive_ip(&self, node_tag: &str, user_id: u64, ip: IpAddr) -> bool {
        self.reported
            .get(node_tag)
            .and_then(|users| users.get(&user_id))
            .map(|ips| ips.contains_key(&ip))
            .unwrap_or(false)
            || self
                .snapshots
                .get(node_tag)
                .filter(|snapshot| snapshot.mode == 1)
                .and_then(|snapshot| snapshot.alive_ips.get(&user_id))
                .map(|ips| ips.contains(&ip))
                .unwrap_or(false)
    }

    fn known_device_count(&self, node_tag: &str, user_id: u64) -> usize {
        self.snapshot_alive_count(node_tag, user_id)
            .saturating_add(self.recent_reported_local_count(node_tag, user_id))
    }

    fn snapshot_alive_count(&self, node_tag: &str, user_id: u64) -> usize {
        self.snapshots
            .get(node_tag)
            .and_then(|snapshot| snapshot.alive.get(&user_id))
            .copied()
            .unwrap_or(0)
    }

    fn recent_reported_local_count(&self, node_tag: &str, user_id: u64) -> usize {
        let last_alive_pull = self
            .snapshots
            .get(node_tag)
            .map(|snapshot| snapshot.last_alive_pull);
        self.reported
            .get(node_tag)
            .and_then(|users| users.get(&user_id))
            .map(|ips| {
                ips.values()
                    .filter(|reported_at| {
                        last_alive_pull
                            .map(|last_alive_pull| **reported_at > last_alive_pull)
                            .unwrap_or(true)
                    })
                    .count()
            })
            .unwrap_or(0)
    }

    fn pending_new_ip_count(&self, key: &str, node_tag: &str, user_id: u64) -> usize {
        self.pending
            .get(key)
            .map(|pending| {
                pending
                    .iter()
                    .filter(|(ip, pending_user_id)| {
                        **pending_user_id == user_id
                            && !self.is_known_alive_ip(node_tag, user_id, **ip)
                    })
                    .count()
            })
            .unwrap_or(0)
    }

    fn drop_one_pending_unknown_ip(&mut self, key: &str, node_tag: &str, user_id: u64) -> bool {
        let Some(pending) = self.pending.get(key) else {
            return false;
        };
        let drop_ip = pending.iter().find_map(|(ip, pending_user_id)| {
            (*pending_user_id == user_id && !self.is_known_alive_ip(node_tag, user_id, *ip))
                .then_some(*ip)
        });
        let Some(drop_ip) = drop_ip else {
            return false;
        };
        if let Some(pending) = self.pending.get_mut(key) {
            pending.remove(&drop_ip);
        }
        true
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

fn device_limit_user_key(node_tag: &str, user_uuid: &str) -> String {
    if node_tag.trim().is_empty() {
        user_uuid.to_string()
    } else {
        format!("{node_tag}|{user_uuid}")
    }
}

impl UserBandwidthLimiters {
    pub fn register_tcp_connection(
        &self,
        user_uuid: Option<&str>,
        sockets: &[&TcpStream],
    ) -> io::Result<Option<UserConnectionGuard>> {
        self.connections.register_tcp_connection(user_uuid, sockets)
    }

    pub fn register_tokio_tcp_connection(
        &self,
        user_uuid: Option<&str>,
        sockets: &[&tokio::net::TcpStream],
    ) -> io::Result<Option<UserConnectionGuard>> {
        self.connections
            .register_tokio_tcp_connection(user_uuid, sockets)
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

    pub fn limiter_for_limited(&self, user: Option<&CoreUser>) -> Option<Arc<BandwidthLimiter>> {
        let user = user?;
        let Some(bytes_per_second) = speed_limit_mbps_to_bytes_per_second(user.speed_limit) else {
            let limiters = bandwidth_limiter_shard(&self.limiters, &user.uuid)
                .lock()
                .expect("user bandwidth limiter lock poisoned");
            if let Some(limiter) = limiters.get(&user.uuid) {
                limiter.set_unlimited();
            }
            return None;
        };

        let mut limiters = bandwidth_limiter_shard(&self.limiters, &user.uuid)
            .lock()
            .expect("user bandwidth limiter lock poisoned");

        if let Some(limiter) = limiters.get(&user.uuid) {
            limiter.set_bytes_per_second(bytes_per_second);
            return Some(Arc::clone(limiter));
        }

        let limiter = Arc::new(BandwidthLimiter::new(bytes_per_second));
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

    pub fn close_all_connections(&self) {
        self.connections.close_all();
    }

    pub fn active_connection_count(&self, user_uuid: &str) -> usize {
        self.connections.active_count(user_uuid)
    }

    pub fn has_limiter_for(&self, user_uuid: &str) -> bool {
        bandwidth_limiter_shard(&self.limiters, user_uuid)
            .lock()
            .expect("user bandwidth limiter lock poisoned")
            .contains_key(user_uuid)
    }

    fn close_user_connections(&self, user_uuids: &[String]) {
        self.connections.close_users(user_uuids);
    }

    fn close_connections_except(&self, active_uuids: &HashSet<&str>) {
        self.connections.close_except(active_uuids);
    }
}

impl ActiveConnectionRegistry {
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
        self.register_owned_tcp_connections(Some(user_uuid), sockets)
    }

    pub fn register_tokio_tcp_connection(
        &self,
        user_uuid: Option<&str>,
        sockets: &[&tokio::net::TcpStream],
    ) -> io::Result<Option<UserConnectionGuard>> {
        let Some(user_uuid) = user_uuid.map(str::trim).filter(|uuid| !uuid.is_empty()) else {
            return Ok(None);
        };
        if sockets.is_empty() {
            return Ok(None);
        }

        let sockets = sockets
            .iter()
            .map(|socket| {
                let cloned = SockRef::from(*socket).try_clone()?;
                Ok(TcpStream::from(cloned))
            })
            .collect::<io::Result<Vec<_>>>()?;
        self.register_owned_tcp_connections(Some(user_uuid), sockets)
    }

    fn register_owned_tcp_connections(
        &self,
        user_uuid: Option<&str>,
        sockets: Vec<TcpStream>,
    ) -> io::Result<Option<UserConnectionGuard>> {
        let Some(user_uuid) = user_uuid.map(str::trim).filter(|uuid| !uuid.is_empty()) else {
            return Ok(None);
        };
        if sockets.is_empty() {
            return Ok(None);
        }

        let handle = Arc::new(UserConnectionHandle { sockets });
        let mut active = user_connection_shard(&self.active, user_uuid)
            .lock()
            .expect("user connection lock poisoned");
        let handles = active.entry(user_uuid.to_string()).or_default();
        handles.retain(|handle| handle.upgrade().is_some());
        handles.push(Arc::downgrade(&handle));

        Ok(Some(UserConnectionGuard {
            user_uuid: user_uuid.to_string(),
            handle,
            active: Arc::clone(&self.active),
        }))
    }

    pub fn close_all(&self) {
        let mut handles = Vec::new();
        for shard in self.active.iter() {
            let active = shard.lock().expect("user connection lock poisoned");
            handles.extend(
                active
                    .values()
                    .flat_map(|handles| handles.iter().filter_map(Weak::upgrade)),
            );
        }
        for handle in handles {
            handle.close();
        }
    }

    pub fn active_count(&self, user_uuid: &str) -> usize {
        let mut active = user_connection_shard(&self.active, user_uuid)
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

    pub fn close_users(&self, user_uuids: &[String]) {
        for user_uuid in user_uuids {
            let handles = self.connection_handles(user_uuid);
            for handle in handles {
                handle.close();
            }
        }
    }

    pub fn close_except(&self, active_uuids: &HashSet<&str>) {
        let removed = self
            .active
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
        self.close_users(&removed);
    }

    fn connection_handles(&self, user_uuid: &str) -> Vec<Arc<UserConnectionHandle>> {
        let mut active = user_connection_shard(&self.active, user_uuid)
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
        let updated = delta
            .updated
            .iter()
            .map(|user| user.uuid.clone())
            .collect::<Vec<_>>();
        if !updated.is_empty() {
            bandwidth.close_user_connections(&updated);
            sessions.revoke_users(&updated);
        }
    }
}

impl BandwidthLimiter {
    pub fn new(bytes_per_second: u64) -> Self {
        Self {
            bytes_per_second: AtomicU64::new(bytes_per_second.max(1)),
            revoked: AtomicBool::new(false),
            revoked_notify: Notify::new(),
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
            revoked_notify: Notify::new(),
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
        if !self.revoked.swap(true, Ordering::AcqRel) {
            self.revoked_notify.notify_waiters();
        }
    }

    pub fn is_revoked(&self) -> bool {
        self.revoked.load(Ordering::Acquire)
    }

    pub async fn wait_revoked(&self) {
        loop {
            let notified = self.revoked_notify.notified();
            if self.is_revoked() {
                return;
            }
            notified.await;
        }
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
            let _ = SockRef::from(socket).set_linger(Some(Duration::ZERO));
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
    use std::collections::BTreeMap;
    use std::io::Read;
    use std::net::{IpAddr, TcpListener, TcpStream};
    use std::sync::Arc;
    use std::thread;
    use std::time::Duration;

    use crate::limits::{
        speed_limit_mbps_to_bytes_per_second, ActiveConnectionRegistry, DeviceLimitOnlineRecord,
        DeviceLimitPolicy, DeviceLimitSnapshot, UserBandwidthLimiters, UserSessionTracker,
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

    fn snapshot(
        node_tag: &str,
        alive: impl IntoIterator<Item = (u64, usize)>,
        alive_ips: impl IntoIterator<Item = (u64, Vec<&'static str>)>,
        mode: i32,
    ) -> DeviceLimitSnapshot {
        DeviceLimitSnapshot {
            node_tag: node_tag.to_string(),
            alive: alive.into_iter().collect(),
            alive_ips: alive_ips
                .into_iter()
                .map(|(uid, ips)| {
                    (
                        uid,
                        ips.into_iter()
                            .map(|ip| ip.parse::<IpAddr>().expect("test ip"))
                            .collect(),
                    )
                })
                .collect::<BTreeMap<_, _>>(),
            mode,
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
    fn rejects_burst_of_local_new_ips_before_alive_sync() {
        let tracker = UserSessionTracker::default();
        let user = user(2);
        let node_tag = "panel|vless|1";

        let first = tracker
            .try_acquire_for_node_ip(node_tag, Some(&user), Some("198.51.100.1".parse().unwrap()))
            .expect("first acquire")
            .expect("first guard");
        let second = tracker
            .try_acquire_for_node_ip(node_tag, Some(&user), Some("198.51.100.2".parse().unwrap()))
            .expect("second acquire")
            .expect("second guard");

        let error = tracker
            .try_acquire_for_node_ip(node_tag, Some(&user), Some("198.51.100.3".parse().unwrap()))
            .expect_err("third ip should be limited before alive sync");
        assert_eq!(error.user_uuid(), "user-a");

        drop(first);
        drop(second);
    }

    #[test]
    fn allows_same_global_ip_in_alive_ip_mode() {
        let tracker = UserSessionTracker::default();
        let user = user(1);
        let node_tag = "panel|vless|1";
        tracker.apply_device_limit_snapshot(snapshot(
            node_tag,
            [(1, 1usize)],
            [(1, vec!["198.51.100.7"])],
            1,
        ));

        let same = tracker
            .try_acquire_for_node_ip(node_tag, Some(&user), Some("198.51.100.7".parse().unwrap()))
            .expect("same global ip should be accepted");
        assert!(same.is_some());

        let error = tracker
            .try_acquire_for_node_ip(node_tag, Some(&user), Some("198.51.100.8".parse().unwrap()))
            .expect_err("different global ip should be limited");
        assert_eq!(error.limit(), 1);
    }

    #[test]
    fn committed_online_report_bridges_until_next_alive_pull() {
        let tracker = UserSessionTracker::default();
        let user = user(1);
        let node_tag = "panel|vless|1";
        let first_ip = "198.51.100.9".parse().unwrap();

        let first = tracker
            .try_acquire_for_node_ip(node_tag, Some(&user), Some(first_ip))
            .expect("first acquire")
            .expect("first guard");
        tracker.commit_device_limit_report(&[DeviceLimitOnlineRecord {
            node_tag: node_tag.to_string(),
            user_id: 1,
            ip: first_ip,
        }]);
        drop(first);

        assert!(tracker
            .try_acquire_for_node_ip(node_tag, Some(&user), Some(first_ip))
            .expect("same reported ip should be accepted")
            .is_some());
        let error = tracker
            .try_acquire_for_node_ip(
                node_tag,
                Some(&user),
                Some("198.51.100.10".parse().unwrap()),
            )
            .expect_err("new ip should be limited while report bridge is fresh");
        assert_eq!(error.user_uuid(), "user-a");
    }

    #[test]
    fn committed_online_report_keeps_same_ip_for_different_users() {
        let tracker = UserSessionTracker::default();
        let user_a = user(1);
        let mut user_b = user(1);
        user_b.id = 2;
        user_b.uuid = "user-b".to_string();
        let node_tag = "panel|vless|1";
        let ip = "198.51.100.7".parse().unwrap();
        tracker.commit_device_limit_report(&[
            DeviceLimitOnlineRecord {
                node_tag: node_tag.to_string(),
                user_id: 1,
                ip,
            },
            DeviceLimitOnlineRecord {
                node_tag: node_tag.to_string(),
                user_id: 2,
                ip,
            },
        ]);

        assert!(tracker
            .try_acquire_for_node_ip(
                node_tag,
                Some(&user_a),
                Some("198.51.100.8".parse().unwrap())
            )
            .is_err());
        assert!(tracker
            .try_acquire_for_node_ip(node_tag, Some(&user_a), Some(ip))
            .is_ok());
        assert!(tracker
            .try_acquire_for_node_ip(node_tag, Some(&user_b), Some(ip))
            .is_ok());
    }

    #[test]
    fn udp_rebind_policy_allows_one_transient_unknown_ip_when_alive_at_limit() {
        let tracker = UserSessionTracker::default();
        let user = user(1);
        let node_tag = "panel|hysteria2|1";
        tracker.apply_device_limit_snapshot(snapshot(node_tag, [(1, 1usize)], [], 0));

        let first = tracker
            .try_acquire_for_node_ip_with_policy(
                node_tag,
                Some(&user),
                Some("198.51.100.20".parse().unwrap()),
                DeviceLimitPolicy {
                    udp_rebind_tolerant: true,
                },
            )
            .expect("first transient rebind should be accepted");
        assert!(first.is_some());

        let second = tracker
            .try_acquire_for_node_ip_with_policy(
                node_tag,
                Some(&user),
                Some("198.51.100.21".parse().unwrap()),
                DeviceLimitPolicy {
                    udp_rebind_tolerant: true,
                },
            )
            .expect("second transient rebind should replace the pending ip");
        assert!(second.is_some());

        let error = tracker
            .try_acquire_for_node_ip(
                node_tag,
                Some(&user),
                Some("198.51.100.22".parse().unwrap()),
            )
            .expect_err("strict protocol should still reject beyond the limit");
        assert_eq!(error.limit(), 1);
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
    fn limiter_for_limited_skips_new_unlimited_users() {
        let limiters = UserBandwidthLimiters::default();
        let user = user(0);

        assert!(limiters.limiter_for_limited(Some(&user)).is_none());
        assert!(!limiters.has_limiter_for(&user.uuid));
    }

    #[test]
    fn limiter_for_limited_creates_limiter_for_limited_users() {
        let limiters = UserBandwidthLimiters::default();
        let mut user = user(0);
        user.speed_limit = 8;

        let limiter = limiters
            .limiter_for_limited(Some(&user))
            .expect("limited user should have limiter");

        assert_eq!(limiter.bytes_per_second(), 1024 * 1024);
        assert!(limiters.has_limiter_for(&user.uuid));
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
    fn close_all_connections_closes_registered_tcp_connections() {
        let limiters = UserBandwidthLimiters::default();
        let user_a = user(0);
        let mut user_b = user(0);
        user_b.uuid = "user-b".to_string();
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        let client_a = TcpStream::connect(listener.local_addr().expect("addr")).expect("client a");
        let (server_a, _) = listener.accept().expect("server a");
        let client_b = TcpStream::connect(listener.local_addr().expect("addr")).expect("client b");
        let (server_b, _) = listener.accept().expect("server b");
        client_a
            .set_read_timeout(Some(Duration::from_millis(500)))
            .expect("client a timeout");
        client_b
            .set_read_timeout(Some(Duration::from_millis(500)))
            .expect("client b timeout");

        let guard_a = limiters
            .register_tcp_connection(Some(&user_a.uuid), &[&client_a, &server_a])
            .expect("register a")
            .expect("guard a");
        let guard_b = limiters
            .register_tcp_connection(Some(&user_b.uuid), &[&client_b, &server_b])
            .expect("register b")
            .expect("guard b");
        assert_eq!(limiters.active_connection_count(&user_a.uuid), 1);
        assert_eq!(limiters.active_connection_count(&user_b.uuid), 1);

        limiters.close_all_connections();

        let mut buffer = [0u8; 1];
        let a_closed = matches!(client_a.peek(&mut buffer), Ok(0) | Err(_))
            || matches!(
                client_a.try_clone().unwrap().read(&mut buffer),
                Ok(0) | Err(_)
            );
        let b_closed = matches!(client_b.peek(&mut buffer), Ok(0) | Err(_))
            || matches!(
                client_b.try_clone().unwrap().read(&mut buffer),
                Ok(0) | Err(_)
            );
        assert!(a_closed, "first registered connection should close");
        assert!(b_closed, "second registered connection should close");

        drop(guard_a);
        drop(guard_b);
        assert_eq!(limiters.active_connection_count(&user_a.uuid), 0);
        assert_eq!(limiters.active_connection_count(&user_b.uuid), 0);
    }

    #[test]
    fn active_connection_registry_closes_only_deleted_user() {
        let registry = ActiveConnectionRegistry::default();
        let user_a = user(0);
        let mut user_b = user(0);
        user_b.uuid = "user-b".to_string();
        let listener = TcpListener::bind("127.0.0.1:0").expect("listener");
        let client_a = TcpStream::connect(listener.local_addr().expect("addr")).expect("client a");
        let (server_a, _) = listener.accept().expect("server a");
        let client_b = TcpStream::connect(listener.local_addr().expect("addr")).expect("client b");
        let (server_b, _) = listener.accept().expect("server b");
        client_a
            .set_read_timeout(Some(Duration::from_millis(500)))
            .expect("client a timeout");
        client_b
            .set_read_timeout(Some(Duration::from_millis(500)))
            .expect("client b timeout");

        let guard_a = registry
            .register_tcp_connection(Some(&user_a.uuid), &[&client_a, &server_a])
            .expect("register a")
            .expect("guard a");
        let guard_b = registry
            .register_tcp_connection(Some(&user_b.uuid), &[&client_b, &server_b])
            .expect("register b")
            .expect("guard b");
        registry.close_users(std::slice::from_ref(&user_a.uuid));

        let mut buffer = [0u8; 1];
        let a_closed = matches!(client_a.peek(&mut buffer), Ok(0) | Err(_))
            || matches!(
                client_a.try_clone().unwrap().read(&mut buffer),
                Ok(0) | Err(_)
            );
        assert!(a_closed, "deleted user's connection should close");
        assert_eq!(registry.active_count(&user_b.uuid), 1);

        drop(guard_a);
        drop(guard_b);
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
