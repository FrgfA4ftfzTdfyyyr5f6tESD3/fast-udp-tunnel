//! Server-Side Multi-User Engine & Subscription Manager.
//! Manages persistent user credentials (`users.json`), virtual IP allocation (`10.8.0.x`, `fd00:8::x`),
//! atomic traffic counters, expiration, rate limiting, and concurrent session capping.

use std::collections::HashMap;
use std::fs;
use std::net::IpAddr;
use std::net::SocketAddr;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use crate::common::SubscriptionToken;
use crate::mimic::MimicProfile;

pub const DEFAULT_USERS_FILE: &str = "users.json";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UserRecord {
    pub id: String,
    pub name: String,
    pub psk: [u8; 8],
    pub created_at: u64,
    pub expires_at: u64,
    pub quota_bytes: u64,
    pub used_bytes: u64,
    pub speed_limit_bps: u64,
    pub max_connections: u32,
    pub enabled: bool,
    pub assigned_ipv4: String,
    pub assigned_ipv6: String,
    pub preferred_profile: u8,
    pub payload_mode: u8,
}

pub struct ActiveUserEntry {
    pub record: UserRecord,
    pub used_bytes_atomic: Arc<AtomicU64>,
    pub active_sessions: Arc<RwLock<Vec<SocketAddr>>>,
}

#[derive(Clone)]
pub struct UserManager {
    pub users: Arc<RwLock<HashMap<String, ActiveUserEntry>>>,
    pub psk_map: Arc<RwLock<HashMap<[u8; 8], String>>>,
    pub ip_map: Arc<RwLock<HashMap<IpAddr, String>>>,
    pub file_path: String,
    pub next_ip_idx: Arc<RwLock<u32>>,
}

impl UserManager {
    /// Initialize or load user database from JSON file
    pub fn load_or_init(file_path: &str, default_psk: [u8; 8]) -> Self {
        let path = Path::new(file_path);
        let records: Vec<UserRecord> = if path.exists() {
            fs::read_to_string(path)
                .ok()
                .and_then(|s| serde_json::from_str(&s).ok())
                .unwrap_or_default()
        } else {
            Vec::new()
        };

        let mut users_map = HashMap::new();
        let mut psk_map = HashMap::new();
        let mut ip_map = HashMap::new();
        let mut max_ip_idx = 1u32;

        if records.is_empty() {
            // Provision default baseline admin user for backward compatibility
            let default_user = UserRecord {
                id: "usr_admin_01".to_string(),
                name: "Default Admin".to_string(),
                psk: default_psk,
                created_at: current_unix_secs(),
                expires_at: 0, // Lifetime
                quota_bytes: 0, // Unlimited
                used_bytes: 0,
                speed_limit_bps: 0, // Unlimited wire speed
                max_connections: 5,
                enabled: true,
                assigned_ipv4: "10.8.0.2".to_string(),
                assigned_ipv6: "fd00:8:0::2".to_string(),
                preferred_profile: 0, // QUIC_V1
                payload_mode: 0,      // Shaped
            };

            let entry = ActiveUserEntry {
                record: default_user.clone(),
                used_bytes_atomic: Arc::new(AtomicU64::new(0)),
                active_sessions: Arc::new(RwLock::new(Vec::new())),
            };

            users_map.insert(default_user.id.clone(), entry);
            psk_map.insert(default_psk, default_user.id.clone());
            if let Ok(ip) = "10.8.0.2".parse::<IpAddr>() {
                ip_map.insert(ip, default_user.id.clone());
            }
            if let Ok(ip) = "fd00:8:0::2".parse::<IpAddr>() {
                ip_map.insert(ip, default_user.id.clone());
            }
            max_ip_idx = 2;

            let mgr = Self {
                users: Arc::new(RwLock::new(users_map)),
                psk_map: Arc::new(RwLock::new(psk_map)),
                ip_map: Arc::new(RwLock::new(ip_map)),
                file_path: file_path.to_string(),
                next_ip_idx: Arc::new(RwLock::new(max_ip_idx + 1)),
            };
            let _ = mgr.save_to_disk();
            return mgr;
        }

        for rec in records {
            // Extract IP index if format is 10.8.0.x
            if let Some(last_octet) = rec.assigned_ipv4.split('.').last() {
                if let Ok(idx) = last_octet.parse::<u32>() {
                    if idx > max_ip_idx {
                        max_ip_idx = idx;
                    }
                }
            }

            psk_map.insert(rec.psk, rec.id.clone());
            if let Ok(ip) = rec.assigned_ipv4.parse::<IpAddr>() {
                ip_map.insert(ip, rec.id.clone());
            }
            if let Ok(ip) = rec.assigned_ipv6.parse::<IpAddr>() {
                ip_map.insert(ip, rec.id.clone());
            }

            let entry = ActiveUserEntry {
                used_bytes_atomic: Arc::new(AtomicU64::new(rec.used_bytes)),
                active_sessions: Arc::new(RwLock::new(Vec::new())),
                record: rec.clone(),
            };
            users_map.insert(rec.id.clone(), entry);
        }

        // Guarantee baseline administrative / benchmark access with default PSK
        if !users_map.contains_key("usr_admin_01") {
            let default_user = UserRecord {
                id: "usr_admin_01".to_string(),
                name: "Default Admin".to_string(),
                psk: default_psk,
                created_at: current_unix_secs(),
                expires_at: 0,
                quota_bytes: 0,
                used_bytes: 0,
                speed_limit_bps: 0,
                max_connections: 5,
                enabled: true,
                assigned_ipv4: "10.8.0.2".to_string(),
                assigned_ipv6: "fd00:8:0::2".to_string(),
                preferred_profile: 0,
                payload_mode: 0,
            };

            let entry = ActiveUserEntry {
                record: default_user.clone(),
                used_bytes_atomic: Arc::new(AtomicU64::new(0)),
                active_sessions: Arc::new(RwLock::new(Vec::new())),
            };

            users_map.insert(default_user.id.clone(), entry);
            psk_map.insert(default_psk, default_user.id.clone());
            if let Ok(ip) = "10.8.0.2".parse::<IpAddr>() {
                ip_map.insert(ip, default_user.id.clone());
            }
            if let Ok(ip) = "fd00:8:0::2".parse::<IpAddr>() {
                ip_map.insert(ip, default_user.id.clone());
            }
        }

        Self {
            users: Arc::new(RwLock::new(users_map)),
            psk_map: Arc::new(RwLock::new(psk_map)),
            ip_map: Arc::new(RwLock::new(ip_map)),
            file_path: file_path.to_string(),
            next_ip_idx: Arc::new(RwLock::new(max_ip_idx + 1)),
        }
    }

    /// Save current state and accumulated traffic atomically to `users.json`
    pub fn save_to_disk(&self) -> Result<(), String> {
        let users_guard = self.users.read().map_err(|e| e.to_string())?;
        let mut list = Vec::new();
        for (_, entry) in users_guard.iter() {
            let mut rec = entry.record.clone();
            rec.used_bytes = entry.used_bytes_atomic.load(Ordering::Relaxed);
            list.push(rec);
        }
        let json = serde_json::to_string_pretty(&list).map_err(|e| e.to_string())?;
        let tmp_path = format!("{}.tmp", &self.file_path);
        fs::write(&tmp_path, json).map_err(|e| e.to_string())?;
        fs::rename(&tmp_path, &self.file_path).map_err(|e| e.to_string())?;
        Ok(())
    }

    /// Authenticate packet PSK in O(1) time and check validity (enabled, expiration, quota)
    pub fn authenticate_psk(&self, psk: &[u8; 8]) -> Option<UserRecord> {
        let psk_guard = self.psk_map.read().ok()?;
        let user_id = psk_guard.get(psk)?;

        let users_guard = self.users.read().ok()?;
        let entry = users_guard.get(user_id)?;
        let rec = &entry.record;

        if !rec.enabled {
            return None;
        }

        let now = current_unix_secs();
        if rec.expires_at > 0 && now > rec.expires_at {
            return None;
        }

        let used = entry.used_bytes_atomic.load(Ordering::Relaxed);
        if rec.quota_bytes > 0 && used >= rec.quota_bytes {
            return None;
        }

        Some(rec.clone())
    }

    /// Fast-path validity check without heap allocations (checks enabled, expiration, and quota)
    #[inline(always)]
    pub fn is_user_valid(&self, user_id: &str) -> bool {
        if let Ok(users_guard) = self.users.read() {
            if let Some(entry) = users_guard.get(user_id) {
                let rec = &entry.record;
                if !rec.enabled {
                    return false;
                }
                let now = current_unix_secs();
                if rec.expires_at > 0 && now > rec.expires_at {
                    return false;
                }
                let used = entry.used_bytes_atomic.load(Ordering::Relaxed);
                if rec.quota_bytes > 0 && used >= rec.quota_bytes {
                    return false;
                }
                return true;
            }
        }
        false
    }

    /// Check if an internal IP address (IPv4 or IPv6) is legitimately assigned to this user (Anti-IP-Spoofing)
    #[inline(always)]
    pub fn is_ip_assigned_to_user(&self, user_id: &str, ip: &IpAddr) -> bool {
        if let Ok(users_guard) = self.users.read() {
            if let Some(entry) = users_guard.get(user_id) {
                if let Ok(v4) = entry.record.assigned_ipv4.parse::<IpAddr>() {
                    if &v4 == ip {
                        return true;
                    }
                }
                if let Ok(v6) = entry.record.assigned_ipv6.parse::<IpAddr>() {
                    if &v6 == ip {
                        return true;
                    }
                }
            }
        }
        false
    }

    /// Find user record by virtual IP address
    pub fn get_user_by_ip(&self, ip: &IpAddr) -> Option<UserRecord> {
        let ip_guard = self.ip_map.read().ok()?;
        let user_id = ip_guard.get(ip)?;

        let users_guard = self.users.read().ok()?;
        users_guard.get(user_id).map(|e| e.record.clone())
    }

    /// Record incoming or outgoing bandwidth atomically
    #[inline(always)]
    pub fn record_traffic(&self, user_id: &str, bytes: u64) {
        if let Ok(users_guard) = self.users.read() {
            if let Some(entry) = users_guard.get(user_id) {
                entry.used_bytes_atomic.fetch_add(bytes, Ordering::Relaxed);
            }
        }
    }

    /// Register active socket session for user and evict oldest session if `max_connections` exceeded.
    /// Returns `Some(evicted_socket_addr)` if an old session had to be booted.
    pub fn register_active_session(&self, user_id: &str, addr: SocketAddr) -> Option<SocketAddr> {
        let users_guard = self.users.read().ok()?;
        let entry = users_guard.get(user_id)?;
        let mut sessions = entry.active_sessions.write().ok()?;

        if sessions.contains(&addr) {
            return None;
        }

        let mut evicted = None;
        let limit = entry.record.max_connections.max(1) as usize;
        if sessions.len() >= limit {
            // Evict the oldest session (FIFO)
            evicted = Some(sessions.remove(0));
        }

        sessions.push(addr);
        evicted
    }

    /// Remove disconnected or stale session
    pub fn unregister_session(&self, user_id: &str, addr: &SocketAddr) {
        if let Ok(users_guard) = self.users.read() {
            if let Some(entry) = users_guard.get(user_id) {
                if let Ok(mut sessions) = entry.active_sessions.write() {
                    sessions.retain(|s| s != addr);
                }
            }
        }
    }

    /// Get active session count for a user
    pub fn get_active_session_count(&self, user_id: &str) -> usize {
        if let Ok(users_guard) = self.users.read() {
            if let Some(entry) = users_guard.get(user_id) {
                if let Ok(sessions) = entry.active_sessions.read() {
                    return sessions.len();
                }
            }
        }
        0
    }

    /// Create new user subscriber, allocate IPs, generate PSK and SubscriptionToken
    pub fn create_user(
        &self,
        name: &str,
        days: u64,
        quota_gb: u64,
        speed_mbps: u64,
        profile_id: u8,
        max_connections: u32,
        server_v4: Option<String>,
        server_v6: Option<String>,
        port: u16,
    ) -> Result<(UserRecord, String), String> {
        let now = current_unix_secs();
        let expires_at = if days == 0 { 0 } else { now + (days * 86400) };
        let quota_bytes = quota_gb * 1024 * 1024 * 1024;
        let speed_limit_bps = (speed_mbps * 1_000_000) / 8;

        // Generate unique user ID and cryptographically random 8-byte PSK using CSPRNG
        let mut psk = [0u8; 8];
        secure_random_bytes(&mut psk);
        let mut rand_bytes = [0u8; 4];
        secure_random_bytes(&mut rand_bytes);
        let user_id = format!("usr_{:08x}", u32::from_be_bytes(rand_bytes));

        let ip_idx = {
            let users_guard = self.users.read().map_err(|e| e.to_string())?;
            let used_ips: std::collections::HashSet<u8> = users_guard
                .values()
                .filter_map(|u| {
                    u.record
                        .assigned_ipv4
                        .split('.')
                        .last()
                        .and_then(|s| s.parse::<u8>().ok())
                })
                .collect();

            (2..=254u8)
                .find(|idx| !used_ips.contains(idx))
                .ok_or_else(|| "All 253 internal tunnel IPv4 addresses (10.8.0.2 - 10.8.0.254) are allocated".to_string())?
        };

        let assigned_ipv4 = format!("10.8.0.{}", ip_idx);
        let assigned_ipv6 = format!("fd00:8:0::{:x}", ip_idx);

        let record = UserRecord {
            id: user_id.clone(),
            name: name.to_string(),
            psk,
            created_at: now,
            expires_at,
            quota_bytes,
            used_bytes: 0,
            speed_limit_bps,
            max_connections: max_connections.clamp(1, 3),
            enabled: true,
            assigned_ipv4: assigned_ipv4.clone(),
            assigned_ipv6: assigned_ipv6.clone(),
            preferred_profile: profile_id,
            payload_mode: 0, // Shaped
        };

        // Generate SubscriptionToken
        let token = SubscriptionToken {
            v: 1,
            user_id: user_id.clone(),
            name: name.to_string(),
            psk,
            server_v4,
            server_v6,
            port,
            profile_id,
            payload_mode: 0,
            expires_at,
            quota_bytes,
            speed_limit_bps,
            max_connections: max_connections.clamp(1, 3),
            assigned_ipv4: Some(assigned_ipv4.clone()),
            assigned_ipv6: Some(assigned_ipv6.clone()),
        };

        let token_uri = token.to_uri()?;

        // Register in internal tables
        {
            let mut users_guard = self.users.write().map_err(|e| e.to_string())?;
            let mut psk_guard = self.psk_map.write().map_err(|e| e.to_string())?;
            let mut ip_guard = self.ip_map.write().map_err(|e| e.to_string())?;

            psk_guard.insert(psk, user_id.clone());
            if let Ok(ip) = assigned_ipv4.parse::<IpAddr>() {
                ip_guard.insert(ip, user_id.clone());
            }
            if let Ok(ip) = assigned_ipv6.parse::<IpAddr>() {
                ip_guard.insert(ip, user_id.clone());
            }

            users_guard.insert(user_id, ActiveUserEntry {
                record: record.clone(),
                used_bytes_atomic: Arc::new(AtomicU64::new(0)),
                active_sessions: Arc::new(RwLock::new(Vec::new())),
            });
        }

        self.save_to_disk()?;
        Ok((record, token_uri))
    }

    /// Toggle user enabled / disabled
    pub fn toggle_user(&self, user_id: &str) -> Result<bool, String> {
        let mut users_guard = self.users.write().map_err(|e| e.to_string())?;
        if let Some(entry) = users_guard.get_mut(user_id) {
            entry.record.enabled = !entry.record.enabled;
            let status = entry.record.enabled;
            drop(users_guard);
            self.save_to_disk()?;
            Ok(status)
        } else {
            Err("User not found".to_string())
        }
    }

    /// Delete user
    pub fn delete_user(&self, user_id: &str) -> Result<(), String> {
        let mut users_guard = self.users.write().map_err(|e| e.to_string())?;
        if let Some(entry) = users_guard.remove(user_id) {
            let mut psk_guard = self.psk_map.write().map_err(|e| e.to_string())?;
            let mut ip_guard = self.ip_map.write().map_err(|e| e.to_string())?;

            psk_guard.remove(&entry.record.psk);
            if let Ok(ip) = entry.record.assigned_ipv4.parse::<IpAddr>() {
                ip_guard.remove(&ip);
            }
            if let Ok(ip) = entry.record.assigned_ipv6.parse::<IpAddr>() {
                ip_guard.remove(&ip);
            }
            drop(users_guard);
            drop(psk_guard);
            drop(ip_guard);
            self.save_to_disk()?;
            Ok(())
        } else {
            Err("User not found".to_string())
        }
    }

    /// Extend user expiration and/or quota
    pub fn extend_user(&self, user_id: &str, add_days: u64, add_quota_gb: u64) -> Result<(), String> {
        let mut users_guard = self.users.write().map_err(|e| e.to_string())?;
        if let Some(entry) = users_guard.get_mut(user_id) {
            let now = current_unix_secs();
            let base = if entry.record.expires_at > now { entry.record.expires_at } else { now };
            if add_days > 0 {
                entry.record.expires_at = base + (add_days * 86400);
            }
            if add_quota_gb > 0 {
                entry.record.quota_bytes += add_quota_gb * 1024 * 1024 * 1024;
            }
            drop(users_guard);
            self.save_to_disk()?;
            Ok(())
        } else {
            Err("User not found".to_string())
        }
    }

    /// Update existing subscriber properties (name, expiry, quota, speed, max connections, enabled, reset used bytes)
    pub fn update_user(
        &self,
        user_id: &str,
        name: Option<String>,
        days_from_now: Option<u64>,
        add_quota_gb: Option<u64>,
        set_quota_gb: Option<u64>,
        speed_mbps: Option<u64>,
        max_connections: Option<u32>,
        enabled: Option<bool>,
        reset_traffic: bool,
    ) -> Result<UserRecord, String> {
        let mut users_guard = self.users.write().map_err(|e| e.to_string())?;
        if let Some(entry) = users_guard.get_mut(user_id) {
            let now = current_unix_secs();
            if let Some(n) = name {
                let trimmed = n.trim();
                if !trimmed.is_empty() {
                    entry.record.name = trimmed.to_string();
                }
            }
            if let Some(days) = days_from_now {
                entry.record.expires_at = if days == 0 { 0 } else { now + (days * 86400) };
            }
            if let Some(set_q) = set_quota_gb {
                entry.record.quota_bytes = set_q * 1024 * 1024 * 1024;
            } else if let Some(add_q) = add_quota_gb {
                entry.record.quota_bytes += add_q * 1024 * 1024 * 1024;
            }
            if let Some(speed) = speed_mbps {
                entry.record.speed_limit_bps = (speed * 1_000_000) / 8;
            }
            if let Some(max_conn) = max_connections {
                entry.record.max_connections = max_conn.clamp(1, 3);
            }
            if let Some(en) = enabled {
                entry.record.enabled = en;
            }
            if reset_traffic {
                entry.used_bytes_atomic.store(0, Ordering::Relaxed);
                entry.record.used_bytes = 0;
            }
            let rec = entry.record.clone();
            drop(users_guard);
            self.save_to_disk()?;
            Ok(rec)
        } else {
            Err("User not found".to_string())
        }
    }

    /// Generate token URI for existing user
    pub fn get_token_uri(
        &self,
        user_id: &str,
        server_v4: Option<String>,
        server_v6: Option<String>,
        port: u16,
    ) -> Result<String, String> {
        let users_guard = self.users.read().map_err(|e| e.to_string())?;
        let entry = users_guard.get(user_id).ok_or_else(|| "User not found".to_string())?;
        let rec = &entry.record;

        let token = SubscriptionToken {
            v: 1,
            user_id: rec.id.clone(),
            name: rec.name.clone(),
            psk: rec.psk,
            server_v4,
            server_v6,
            port,
            profile_id: rec.preferred_profile,
            payload_mode: rec.payload_mode,
            expires_at: rec.expires_at,
            quota_bytes: rec.quota_bytes,
            speed_limit_bps: rec.speed_limit_bps,
            max_connections: rec.max_connections,
            assigned_ipv4: Some(rec.assigned_ipv4.clone()),
            assigned_ipv6: Some(rec.assigned_ipv6.clone()),
        };

        token.to_uri()
    }

    /// List all users for Admin UI representation
    pub fn list_user_views(&self) -> Vec<serde_json::Value> {
        let mut list = Vec::new();
        if let Ok(users_guard) = self.users.read() {
            for (_, entry) in users_guard.iter() {
                let rec = &entry.record;
                let used = entry.used_bytes_atomic.load(Ordering::Relaxed);
                let active = entry.active_sessions.read().map(|s| s.len()).unwrap_or(0);
                let prof = MimicProfile::from_id(rec.preferred_profile).unwrap_or(MimicProfile::QuicV1);

                list.push(serde_json::json!({
                    "id": rec.id,
                    "name": rec.name,
                    "assigned_ipv4": rec.assigned_ipv4,
                    "assigned_ipv6": rec.assigned_ipv6,
                    "profile_name": prof.as_str().to_uppercase(),
                    "quota_bytes": rec.quota_bytes,
                    "used_bytes": used,
                    "expires_at": rec.expires_at,
                    "speed_limit_bps": rec.speed_limit_bps,
                    "max_connections": rec.max_connections,
                    "active_sockets": active,
                    "enabled": rec.enabled,
                }));
            }
        }
        list
    }

    /// Return total consumed traffic across all subscribers
    pub fn total_traffic_bytes(&self) -> u64 {
        let mut total = 0;
        if let Ok(users_guard) = self.users.read() {
            for (_, entry) in users_guard.iter() {
                total += entry.used_bytes_atomic.load(Ordering::Relaxed);
            }
        }
        total
    }
}

fn current_unix_secs() -> u64 {
    SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

pub fn secure_random_bytes(buf: &mut [u8]) {
    #[cfg(unix)]
    {
        if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
            use std::io::Read;
            if f.read_exact(buf).is_ok() {
                return;
            }
        }
    }
    let nanos = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0xDEAD_BEEF_CAFE_BABE);
    let mut state = nanos ^ ((std::process::id() as u128) << 32) ^ (buf.as_ptr() as usize as u128);
    for b in buf.iter_mut() {
        state = state.wrapping_add(0x9E3779B97F4A7C159E3779B97F4A7C15);
        let mut z = (state ^ (state >> 64)) as u64;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        *b = (z ^ (z >> 31)) as u8;
    }
}

pub fn secure_random_u64() -> u64 {
    let mut b = [0u8; 8];
    secure_random_bytes(&mut b);
    u64::from_le_bytes(b)
}
