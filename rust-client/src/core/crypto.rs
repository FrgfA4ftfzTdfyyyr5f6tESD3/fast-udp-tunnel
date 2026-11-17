//! Cryptographic routines, key derivation, and multi-mode payload shaping.

use crate::mimic::MimicProfile;
pub use crate::common::DEFAULT_PSK;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PayloadMode {
    /// Mode 1: Zero encryption overhead - native IP packets (Maximum speed for HTTPS/TLS)
    Plaintext,
    /// Mode 2: Ultra-fast 64-bit word stream cipher (High-entropy encrypted ciphertext)
    StreamCipher,
    /// Mode 3: Protocol-conforming payload shaping (Evades Shannon Entropy & DPI tests)
    ShapedDpi,
}

impl PayloadMode {
    pub fn as_str(&self) -> &'static str {
        match self {
            PayloadMode::Plaintext => "plaintext",
            PayloadMode::StreamCipher => "stream",
            PayloadMode::ShapedDpi => "shaped",
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            PayloadMode::Plaintext => "Plaintext IP Passthrough (Maximum Throughput)",
            PayloadMode::StreamCipher => "Fast Stream Cipher (High-Entropy Ciphertext)",
            PayloadMode::ShapedDpi => "Protocol-Conforming Shaping (Anti-DPI & Entropy Matching)",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        let clean = s.trim().to_ascii_lowercase().replace('_', "").replace('-', "");
        match clean.as_str() {
            "1" | "shaped" | "dpi" | "shannon" | "shapeddpi" => Some(PayloadMode::ShapedDpi),
            "2" | "stream" | "cipher" | "encrypt" | "streamcipher" => Some(PayloadMode::StreamCipher),
            "3" | "plain" | "plaintext" | "none" => Some(PayloadMode::Plaintext),
            _ => None,
        }
    }

    pub fn to_flags(&self) -> u16 {
        match self {
            PayloadMode::ShapedDpi => crate::mimic::MODE_SHAPED,
            PayloadMode::StreamCipher => crate::mimic::MODE_STREAM,
            PayloadMode::Plaintext => crate::mimic::MODE_PLAIN,
        }
    }

    #[inline(always)]
    pub fn from_flags(flags: u16) -> Self {
        match flags & 0x00F0 {
            crate::mimic::MODE_STREAM => PayloadMode::StreamCipher,
            crate::mimic::MODE_PLAIN => PayloadMode::Plaintext,
            _ => PayloadMode::ShapedDpi,
        }
    }

    pub fn to_id(&self) -> u8 {
        match self {
            PayloadMode::ShapedDpi => 0,
            PayloadMode::StreamCipher => 1,
            PayloadMode::Plaintext => 2,
        }
    }

    pub fn from_id(id: u8) -> Option<Self> {
        match id {
            0 => Some(PayloadMode::ShapedDpi),
            1 => Some(PayloadMode::StreamCipher),
            2 => Some(PayloadMode::Plaintext),
            _ => None,
        }
    }
}

/// Deterministic, high-dispersion key derivation function from an arbitrary passphrase.
pub fn derive_psk(passphrase: &str) -> [u8; 8] {
    if passphrase.trim().is_empty() {
        return DEFAULT_PSK;
    }

    let mut hash: u64 = 0xcbf29ce484222325;
    for &b in passphrase.as_bytes() {
        hash ^= b as u64;
        hash = hash.wrapping_mul(0x100000001b3);
    }

    let mut h2 = hash ^ 0x9e3779b97f4a7c15;
    for &b in passphrase.as_bytes().iter().rev() {
        h2 = (h2 ^ (b as u64)).rotate_left(13).wrapping_mul(0x517cc1b727220a95);
    }

    (hash ^ h2).to_be_bytes()
}

/// Ultra-Fast 64-bit Word Keystream Generator (In-Place Encrypt/Decrypt).
/// Strictly normalized to 16-bit sequence number (seq: u16) for 100% symmetric synchronization.
#[inline(always)]
pub fn crypt_payload(payload: &mut [u8], psk: &[u8; 8], seq: u16) {
    if payload.is_empty() {
        return;
    }

    let psk_u64 = u64::from_be_bytes(*psk);
    let mut state = psk_u64.wrapping_add((seq as u64).wrapping_mul(0x9e3779b97f4a7c15));

    let len = payload.len();
    let mut offset = 0;

    // Process 8-byte (64-bit) chunks
    while offset + 8 <= len {
        state = state.wrapping_add(0x9e3779b97f4a7c15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
        let key_word = z ^ (z >> 31);

        let chunk = &mut payload[offset..offset + 8];
        let word = u64::from_le_bytes(chunk.try_into().unwrap());
        chunk.copy_from_slice(&(word ^ key_word).to_le_bytes());
        offset += 8;
    }

    // Process remaining trailing bytes (< 8 bytes)
    if offset < len {
        state = state.wrapping_add(0x9e3779b97f4a7c15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58476d1ce4e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d049bb133111eb);
        let key_bytes = (z ^ (z >> 31)).to_le_bytes();
        let mut i = 0;
        while offset + i < len {
            payload[offset + i] ^= key_bytes[i];
            i += 1;
        }
    }
}

/// Domain-separated cipher sequence derivation for micro-segmented fragments.
#[allow(dead_code)]
#[inline(always)]
pub fn fragment_cipher_seq(seq: u16, is_frag2: bool) -> u16 {
    if is_frag2 {
        seq ^ 0xA55A
    } else {
        seq
    }
}

/// Protocol-Conforming Payload Shaping:
/// Applies realistic protocol framing (Opus voice header, STUN TLV DATA attribute,
/// DNS QCLASS IN, RDPEUDP marker, game opcodes, or native ciphertext for AEAD protocols)
/// before encrypting the remainder of the payload.
pub fn apply_payload_shaping(
    payload: &[u8],
    out: &mut [u8],
    psk: &[u8; 8],
    seq: u16,
    mode: PayloadMode,
    profile: MimicProfile,
) -> usize {
    let len = payload.len();
    match mode {
        PayloadMode::Plaintext => {
            out[..len].copy_from_slice(payload);
            len
        }
        PayloadMode::StreamCipher => {
            out[..len].copy_from_slice(payload);
            crypt_payload(&mut out[..len], psk, seq);
            len
        }
        PayloadMode::ShapedDpi => {
            match profile {
                MimicProfile::WebRtc | MimicProfile::Turn | MimicProfile::Discord => {
                    // Prepend Opus 20ms mono audio frame TOC header (RFC 6716 / RFC 7587)
                    out[0] = 0x78; // Opus Config 15 (20ms)
                    out[1] = 0x0B;
                    out[2..2 + len].copy_from_slice(payload);
                    crypt_payload(&mut out[2..2 + len], psk, seq);
                    2 + len
                }
                MimicProfile::Zoom => {
                    // Prepend Zoom SFU audio encapsulation header
                    out[0] = 0x0F; // Zoom Audio Media Encapsulation
                    out[1] = 0x00;
                    out[2..2 + len].copy_from_slice(payload);
                    crypt_payload(&mut out[2..2 + len], psk, seq);
                    2 + len
                }
                MimicProfile::Dns => {
                    // Prepend RFC 1035 DNS QCLASS IN (0x0001) framing
                    out[0] = 0x00;
                    out[1] = 0x01;
                    out[2..2 + len].copy_from_slice(payload);
                    crypt_payload(&mut out[2..2 + len], psk, seq);
                    2 + len
                }
                MimicProfile::Rdp => {
                    // Prepend MS-RDPEUDP payload segment header (TPKT v3)
                    out[0] = 0x03;
                    out[1] = 0x00;
                    out[2..2 + len].copy_from_slice(payload);
                    crypt_payload(&mut out[2..2 + len], psk, seq);
                    2 + len
                }
                MimicProfile::Stun => {
                    // Prepend RFC 5389/5766 STUN DATA Attribute TLV (Type 0x0013 + 16-bit Length)
                    let attr_len = (len as u16).to_be_bytes();
                    out[0] = 0x00;
                    out[1] = 0x13;
                    out[2] = attr_len[0];
                    out[3] = attr_len[1];
                    out[4..4 + len].copy_from_slice(payload);
                    crypt_payload(&mut out[4..4 + len], psk, seq);
                    4 + len
                }
                MimicProfile::RakNet | MimicProfile::Steam | MimicProfile::Sdr | MimicProfile::Riot => {
                    // Prepend game command packet opcode (Low entropy start)
                    out[0] = 0x04; // Game Stream Channel
                    out[1..1 + len].copy_from_slice(payload);
                    crypt_payload(&mut out[1..1 + len], psk, seq);
                    1 + len
                }
                // QUIC v1, QUIC v2, DTLS 1.2, IPsec ESP, uTP MSE natively carry high-entropy ciphertext
                MimicProfile::QuicV1
                | MimicProfile::QuicV2
                | MimicProfile::Dtls
                | MimicProfile::Esp
                | MimicProfile::Utp => {
                    out[..len].copy_from_slice(payload);
                    crypt_payload(&mut out[..len], psk, seq);
                    len
                }
            }
        }
    }
}

/// Strip protocol-conforming framing and decrypt incoming payload.
pub fn strip_payload_shaping(
    data: &mut [u8],
    psk: &[u8; 8],
    seq: u16,
    mode: PayloadMode,
    profile: MimicProfile,
) -> Option<usize> {
    let len = data.len();
    if len == 0 {
        return None;
    }

    match mode {
        PayloadMode::Plaintext => Some(len),
        PayloadMode::StreamCipher => {
            crypt_payload(data, psk, seq);
            Some(len)
        }
        PayloadMode::ShapedDpi => {
            match profile {
                MimicProfile::WebRtc
                | MimicProfile::Turn
                | MimicProfile::Discord
                | MimicProfile::Zoom
                | MimicProfile::Dns
                | MimicProfile::Rdp => {
                    if len < 3 {
                        return None;
                    }
                    crypt_payload(&mut data[2..], psk, seq);
                    data.copy_within(2..len, 0);
                    Some(len - 2)
                }
                MimicProfile::Stun => {
                    if len < 5 {
                        return None;
                    }
                    crypt_payload(&mut data[4..], psk, seq);
                    data.copy_within(4..len, 0);
                    Some(len - 4)
                }
                MimicProfile::RakNet | MimicProfile::Steam | MimicProfile::Sdr | MimicProfile::Riot => {
                    if len < 2 {
                        return None;
                    }
                    crypt_payload(&mut data[1..], psk, seq);
                    data.copy_within(1..len, 0);
                    Some(len - 1)
                }
                MimicProfile::QuicV1
                | MimicProfile::QuicV2
                | MimicProfile::Dtls
                | MimicProfile::Esp
                | MimicProfile::Utp => {
                    crypt_payload(data, psk, seq);
                    Some(len)
                }
            }
        }
    }
}
