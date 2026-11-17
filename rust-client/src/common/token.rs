//! Encrypted Subscription Token Format (fudp://<base64>)
//! Encapsulates multi-user credentials, remote server IPs (v4 & v6), port, mimic profile,
//! payload protection mode, quota, expiration, and speed limits.

use serde::{Deserialize, Serialize};
use std::fmt;

use crate::common::constants::{LEGACY_TOKEN_URI_PREFIX, TOKEN_URI_PREFIX};
use crate::core::crypto::PayloadMode;
use crate::mimic::MimicProfile;

const MORPH_MASTER_SEED: [u8; 16] = [
    0x4D, 0x4F, 0x52, 0x50, // "MORP"
    0x48, 0x5F, 0x53, 0x55, // "H_SU"
    0x42, 0x5F, 0x54, 0x4F, // "B_TO"
    0x4B, 0x45, 0x4E, 0x31, // "KEN1"
];

const LEGACY_MASTER_SEED: [u8; 16] = [
    0x46, 0x55, 0x44, 0x50, // "FUDP"
    0x5F, 0x53, 0x55, 0x42, // "_SUB"
    0x5F, 0x54, 0x4F, 0x4B, // "_TOK"
    0x45, 0x4E, 0x5F, 0x31, // "EN_1"
];

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct SubscriptionToken {
    /// Token schema version (currently 1)
    pub v: u8,
    /// Unique user identifier
    pub user_id: String,
    /// User display label / friendly name
    pub name: String,
    /// 8-byte PSK for authentication & cryptographic encapsulation
    pub psk: [u8; 8],
    /// Remote Server IPv4 address (e.g. "203.0.113.10")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_v4: Option<String>,
    /// Remote Server IPv6 address (e.g. "2001:db8::1" or "[2001:db8::1]")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_v6: Option<String>,
    /// Remote primary tunnel port
    pub port: u16,
    /// Camouflage profile ID (0-15)
    pub profile_id: u8,
    /// Payload mode (0=Shaped, 1=Stream, 2=Plaintext)
    pub payload_mode: u8,
    /// Expiration unix timestamp in seconds (0 = unlimited)
    pub expires_at: u64,
    /// Total quota limit in bytes (0 = unlimited)
    pub quota_bytes: u64,
    /// Bandwidth rate limit in bytes per second (0 = unlimited)
    pub speed_limit_bps: u64,
    /// Maximum concurrent connections allowed
    pub max_connections: u32,
    /// Assigned virtual IPv4 (e.g. "10.8.0.2")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assigned_ipv4: Option<String>,
    /// Assigned virtual IPv6 (e.g. "fd00:8::2")
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub assigned_ipv6: Option<String>,
}

impl SubscriptionToken {
    /// Return the corresponding MimicProfile
    pub fn mimic_profile(&self) -> MimicProfile {
        MimicProfile::from_id(self.profile_id).unwrap_or(MimicProfile::QuicV1)
    }

    /// Return the corresponding PayloadMode
    pub fn payload_protection_mode(&self) -> PayloadMode {
        match self.payload_mode {
            1 => PayloadMode::StreamCipher,
            2 => PayloadMode::Plaintext,
            _ => PayloadMode::ShapedDpi,
        }
    }

    /// Check if this token has expired
    pub fn is_expired(&self, current_unix_secs: u64) -> bool {
        self.expires_at > 0 && current_unix_secs > self.expires_at
    }

    /// Check if quota has been exceeded
    pub fn is_quota_exceeded(&self, used_bytes: u64) -> bool {
        self.quota_bytes > 0 && used_bytes >= self.quota_bytes
    }

    /// Format remaining time in a human-readable string
    pub fn remaining_time_str(&self, current_unix_secs: u64) -> String {
        if self.expires_at == 0 {
            "Unlimited (Lifetime)".to_string()
        } else if current_unix_secs >= self.expires_at {
            "Expired".to_string()
        } else {
            let diff = self.expires_at - current_unix_secs;
            let days = diff / 86400;
            let hours = (diff % 86400) / 3600;
            if days > 0 {
                format!("{}d {}h remaining", days, hours)
            } else {
                let mins = (diff % 3600) / 60;
                format!("{}h {}m remaining", hours, mins)
            }
        }
    }

    /// Format quota in a human-readable string
    pub fn quota_str(&self) -> String {
        if self.quota_bytes == 0 {
            "Unlimited".to_string()
        } else {
            format_bytes_human(self.quota_bytes)
        }
    }

    /// Format speed limit in human-readable string
    pub fn speed_str(&self) -> String {
        if self.speed_limit_bps == 0 {
            "Unlimited".to_string()
        } else {
            let mbps = (self.speed_limit_bps * 8) as f64 / 1_000_000.0;
            format!("{:.1} Mbps", mbps)
        }
    }

    /// Serialize and encrypt this token into `fudp://<base64>` URI
    pub fn to_uri(&self) -> Result<String, String> {
        let json_bytes = serde_json::to_vec(self).map_err(|e| format!("Serialization error: {}", e))?;
        let encrypted_blob = encrypt_token_payload(&json_bytes);
        let b64 = base64_encode(&encrypted_blob);
        Ok(format!("{}{}", TOKEN_URI_PREFIX, b64))
    }

    /// Decrypt and parse a `morph://<base64>` (or legacy `fudp://`) URI into a SubscriptionToken
    pub fn from_uri(uri: &str) -> Result<Self, String> {
        let trimmed = uri.trim();
        let b64_payload = if let Some(stripped) = trimmed.strip_prefix(TOKEN_URI_PREFIX) {
            stripped
        } else if let Some(stripped) = trimmed.strip_prefix("MORPH://") {
            stripped
        } else if let Some(stripped) = trimmed.strip_prefix(LEGACY_TOKEN_URI_PREFIX) {
            stripped
        } else if let Some(stripped) = trimmed.strip_prefix("FUDP://") {
            stripped
        } else {
            // Also accept bare base64
            trimmed
        };

        let decoded_bytes = base64_decode(b64_payload)
            .ok_or_else(|| "Invalid Base64 encoding in token payload".to_string())?;

        let decrypted_json = decrypt_token_payload(&decoded_bytes)?;
        let token: SubscriptionToken = serde_json::from_slice(&decrypted_json)
            .map_err(|e| format!("Invalid token structure: {}", e))?;

        if token.port == 0 {
            return Err("Invalid token: port cannot be 0".to_string());
        }

        Ok(token)
    }
}

impl fmt::Display for SubscriptionToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "User: {} ({}) | Server: v4={:?}, v6={:?}:{} | Camouflage: [{}] | Mode: [{}] | Quota: {} | Speed: {}",
            self.name,
            self.user_id,
            self.server_v4,
            self.server_v6,
            self.port,
            self.mimic_profile().as_str().to_uppercase(),
            self.payload_protection_mode().as_str(),
            self.quota_str(),
            self.speed_str()
        )
    }
}

// ---------------------------------------------------------------------------
// Encryption & Integrity Layer for Tokens
// ---------------------------------------------------------------------------

fn crc32_checksum(data: &[u8]) -> u32 {
    let mut crc = 0xFFFFFFFFu32;
    for &b in data {
        crc ^= b as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB88320 & mask);
        }
    }
    !crc
}

fn derive_token_keystream(seed: &[u8; 16], salt: &[u8; 4], length: usize) -> Vec<u8> {
    let mut state = 0x9E3779B97F4A7C15u64;
    for &b in seed {
        state = state.wrapping_add((b as u64).rotate_left(11)).wrapping_mul(0x517cc1b727220a95);
    }
    for &b in salt {
        state = state.wrapping_add((b as u64).rotate_left(17)).wrapping_mul(0x94d049bb133111eb);
    }

    let mut stream = Vec::with_capacity(length);
    while stream.len() < length {
        state = state.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
        let word = (z ^ (z >> 31)).to_le_bytes();
        let remaining = length - stream.len();
        let take = remaining.min(8);
        stream.extend_from_slice(&word[..take]);
    }
    stream
}

fn encrypt_token_payload(plaintext: &[u8]) -> Vec<u8> {
    let checksum = crc32_checksum(plaintext);
    // 4 bytes pseudo-random salt based on monotonic system time
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u32)
        .unwrap_or(0xCAFEBABE);
    let salt = nanos.to_be_bytes();

    let keystream = derive_token_keystream(&MORPH_MASTER_SEED, &salt, plaintext.len());
    let mut ciphertext = Vec::with_capacity(plaintext.len());
    for i in 0..plaintext.len() {
        ciphertext.push(plaintext[i] ^ keystream[i]);
    }

    // Binary layout: [4 bytes salt] [4 bytes CRC32 checksum] [N bytes ciphertext]
    let mut out = Vec::with_capacity(8 + ciphertext.len());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&checksum.to_be_bytes());
    out.extend_from_slice(&ciphertext);
    out
}

fn decrypt_token_payload(blob: &[u8]) -> Result<Vec<u8>, String> {
    if blob.len() < 8 {
        return Err("Encrypted token payload too short (truncated)".to_string());
    }

    let mut salt = [0u8; 4];
    salt.copy_from_slice(&blob[0..4]);

    let expected_crc = u32::from_be_bytes([blob[4], blob[5], blob[6], blob[7]]);
    let ciphertext = &blob[8..];

    // Attempt 1: Morph Master Seed
    let keystream = derive_token_keystream(&MORPH_MASTER_SEED, &salt, ciphertext.len());
    let mut plaintext = Vec::with_capacity(ciphertext.len());
    for i in 0..ciphertext.len() {
        plaintext.push(ciphertext[i] ^ keystream[i]);
    }
    if crc32_checksum(&plaintext) == expected_crc {
        return Ok(plaintext);
    }

    // Attempt 2: Fallback to Legacy Seed
    let legacy_keystream = derive_token_keystream(&LEGACY_MASTER_SEED, &salt, ciphertext.len());
    let mut legacy_plaintext = Vec::with_capacity(ciphertext.len());
    for i in 0..ciphertext.len() {
        legacy_plaintext.push(ciphertext[i] ^ legacy_keystream[i]);
    }
    if crc32_checksum(&legacy_plaintext) == expected_crc {
        return Ok(legacy_plaintext);
    }

    Err("Token verification failed: CRC32 integrity check mismatch or wrong key".to_string())
}

// ---------------------------------------------------------------------------
// Zero-Dependency URL-Safe & Standard Base64
// ---------------------------------------------------------------------------

const BASE64_ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

pub fn base64_encode(data: &[u8]) -> String {
    let mut out = String::with_capacity((data.len() + 2) / 3 * 4);
    let chunks = data.chunks_exact(3);
    let remainder = chunks.remainder();

    for chunk in chunks {
        let b0 = chunk[0] as usize;
        let b1 = chunk[1] as usize;
        let b2 = chunk[2] as usize;

        out.push(BASE64_ALPHABET[(b0 >> 2) & 0x3F] as char);
        out.push(BASE64_ALPHABET[((b0 << 4) | (b1 >> 4)) & 0x3F] as char);
        out.push(BASE64_ALPHABET[((b1 << 2) | (b2 >> 6)) & 0x3F] as char);
        out.push(BASE64_ALPHABET[b2 & 0x3F] as char);
    }

    match remainder.len() {
        1 => {
            let b0 = remainder[0] as usize;
            out.push(BASE64_ALPHABET[(b0 >> 2) & 0x3F] as char);
            out.push(BASE64_ALPHABET[(b0 << 4) & 0x3F] as char);
            out.push('=');
            out.push('=');
        }
        2 => {
            let b0 = remainder[0] as usize;
            let b1 = remainder[1] as usize;
            out.push(BASE64_ALPHABET[(b0 >> 2) & 0x3F] as char);
            out.push(BASE64_ALPHABET[((b0 << 4) | (b1 >> 4)) & 0x3F] as char);
            out.push(BASE64_ALPHABET[(b1 << 2) & 0x3F] as char);
            out.push('=');
        }
        _ => {}
    }

    out
}

pub fn base64_decode(input: &str) -> Option<Vec<u8>> {
    let clean = input.trim();
    let mut bytes = Vec::new();

    let decode_char = |c: u8| -> Option<u8> {
        match c {
            b'A'..=b'Z' => Some(c - b'A'),
            b'a'..=b'z' => Some(c - b'a' + 26),
            b'0'..=b'9' => Some(c - b'0' + 52),
            b'+' | b'-' => Some(62),
            b'/' | b'_' => Some(63),
            b'=' => None,
            _ => None,
        }
    };

    let input_bytes: Vec<u8> = clean.bytes().filter(|&b| b != b'=' && !b.is_ascii_whitespace()).collect();
    let chunks = input_bytes.chunks_exact(4);
    let remainder = chunks.remainder();

    for chunk in chunks {
        let c0 = decode_char(chunk[0])?;
        let c1 = decode_char(chunk[1])?;
        let c2 = decode_char(chunk[2])?;
        let c3 = decode_char(chunk[3])?;

        bytes.push((c0 << 2) | (c1 >> 4));
        bytes.push((c1 << 4) | (c2 >> 2));
        bytes.push((c2 << 6) | c3);
    }

    match remainder.len() {
        2 => {
            let c0 = decode_char(remainder[0])?;
            let c1 = decode_char(remainder[1])?;
            bytes.push((c0 << 2) | (c1 >> 4));
        }
        3 => {
            let c0 = decode_char(remainder[0])?;
            let c1 = decode_char(remainder[1])?;
            let c2 = decode_char(remainder[2])?;
            bytes.push((c0 << 2) | (c1 >> 4));
            bytes.push((c1 << 4) | (c2 >> 2));
        }
        _ => {}
    }

    Some(bytes)
}

fn format_bytes_human(bytes: u64) -> String {
    const KB: u64 = 1024;
    const MB: u64 = KB * 1024;
    const GB: u64 = MB * 1024;
    const TB: u64 = GB * 1024;

    if bytes >= TB {
        format!("{:.2} TB", bytes as f64 / TB as f64)
    } else if bytes >= GB {
        format!("{:.2} GB", bytes as f64 / GB as f64)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes as f64 / MB as f64)
    } else if bytes >= KB {
        format!("{:.2} KB", bytes as f64 / KB as f64)
    } else {
        format!("{} B", bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_token_roundtrip() {
        let token = SubscriptionToken {
            v: 1,
            user_id: "usr_demo_01".to_string(),
            name: "Edge Node Test".to_string(),
            psk: [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88],
            server_v4: Some("203.0.113.10".to_string()),
            server_v6: Some("[2001:db8::1]".to_string()),
            port: 443,
            profile_id: 0,
            payload_mode: 0,
            expires_at: 1800000000,
            quota_bytes: 50 * 1024 * 1024 * 1024,
            speed_limit_bps: 12_500_000, // 100 Mbps
            max_connections: 1,
            assigned_ipv4: Some("10.8.0.2".to_string()),
            assigned_ipv6: Some("fd00:8::2".to_string()),
        };

        let uri = token.to_uri().expect("Failed to encode token");
        assert!(uri.starts_with("morph://"));

        let decoded = SubscriptionToken::from_uri(&uri).expect("Failed to decode token");
        assert_eq!(token, decoded);
    }
}
