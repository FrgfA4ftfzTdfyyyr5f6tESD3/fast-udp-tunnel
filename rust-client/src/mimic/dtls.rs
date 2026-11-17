//! DTLS 1.2 Record Layer Mimicry (RFC 6347 & nDPI `tls.c` `is_dtls`).
//! Byte 0: 0x17 (Application Data)
//! Bytes 1..3: 0xFE, 0xFD (DTLS 1.2 Protocol Version)
//! Bytes 3..5: Epoch 0x00, 0x01
//! Bytes 5..11: 48-bit Sequence (0x00, 0x00, 0x00, 0x00, seq_hi, seq_lo)
//! Bytes 11..13: 16-bit Fragment Length (buf.len() - 13, strictly verified by nDPI)
//! Bytes 13..15: Flags (flags: u16)
//! Bytes 15..20: 5 bytes of PSK authentication token

use super::MIMICRY_HEADER_LEN;

pub const MAGIC_CONTENT_TYPE: u8 = 0x17;
pub const MAGIC_VERSION_MAJOR: u8 = 0xFE;
pub const MAGIC_VERSION_MINOR: u8 = 0xFD;

#[inline(always)]
pub fn wrap_dtls_header(buf: &mut [u8], flags: u16, seq: u16, psk: &[u8; 8]) {
    buf[0] = MAGIC_CONTENT_TYPE;
    buf[1] = MAGIC_VERSION_MAJOR;
    buf[2] = MAGIC_VERSION_MINOR;
    let epoch: u16 = 0x0001;
    buf[3..5].copy_from_slice(&epoch.to_be_bytes());
    buf[5..9].copy_from_slice(&[0x00, 0x00, 0x00, 0x00]);
    buf[9..11].copy_from_slice(&seq.to_be_bytes());

    let fragment_len: u16 = (buf.len().saturating_sub(13)) as u16;
    buf[11..13].copy_from_slice(&fragment_len.to_be_bytes());
    buf[13..15].copy_from_slice(&flags.to_be_bytes());

    for i in 0..5 {
        let mask = ((seq >> ((i % 2) * 8)) as u8) ^ (0x33u8.wrapping_mul(i as u8 + 1));
        buf[15 + i] = (psk[i] ^ psk[i + 3]) ^ mask;
    }
}

#[inline(always)]
pub fn unwrap_dtls_header(packet: &[u8], psk: &[u8; 8]) -> Option<(u16, u16)> {
    if packet.len() < MIMICRY_HEADER_LEN
        || packet[0] != MAGIC_CONTENT_TYPE
        || packet[1] != MAGIC_VERSION_MAJOR
        || packet[2] != MAGIC_VERSION_MINOR
    {
        return None;
    }

    let seq = u16::from_be_bytes([packet[9], packet[10]]);
    let flags = u16::from_be_bytes([packet[13], packet[14]]);

    for i in 0..5 {
        let mask = ((seq >> ((i % 2) * 8)) as u8) ^ (0x33u8.wrapping_mul(i as u8 + 1));
        if (packet[15 + i] ^ mask) != (psk[i] ^ psk[i + 3]) {
            return None;
        }
    }

    Some((flags, seq))
}
