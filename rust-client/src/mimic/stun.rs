//! STUN / ICE Media Protocol Mimicry (RFC 5389 & nDPI `stun.c` `is_stun`).
//! Bytes 0..2: 0x00 0x01 (Binding Request)
//! Bytes 2..4: Message Length = buf.len() - 20 (strictly verified by nDPI: `msg_len + 20 == payload_length`)
//! Bytes 4..8: 0x21 0x12 0xA4 0x42 (STUN Magic Cookie)
//! Bytes 8..20: 12-byte Transaction ID (RFC 5389 compliant):
//!   Bytes 8..10: seq: u16 masked with cookie
//!   Bytes 10..12: flags: u16 masked with cookie
//!   Bytes 12..20: 8 bytes of PSK token masked with seq & cookie

use super::MIMICRY_HEADER_LEN;

pub const MAGIC_STUN_TYPE: [u8; 2] = [0x00, 0x01];
pub const MAGIC_STUN_COOKIE: [u8; 4] = [0x21, 0x12, 0xA4, 0x42];

#[inline(always)]
pub fn wrap_stun_header(buf: &mut [u8], flags: u16, seq: u16, psk: &[u8; 8]) {
    buf[0..2].copy_from_slice(&MAGIC_STUN_TYPE);
    let msg_len: u16 = (buf.len().saturating_sub(20)) as u16;
    buf[2..4].copy_from_slice(&msg_len.to_be_bytes());
    buf[4..8].copy_from_slice(&MAGIC_STUN_COOKIE);

    let masked_seq = seq ^ 0x2112;
    buf[8..10].copy_from_slice(&masked_seq.to_be_bytes());

    let masked_flags = flags ^ 0xA442;
    buf[10..12].copy_from_slice(&masked_flags.to_be_bytes());

    for i in 0..8 {
        let mask = MAGIC_STUN_COOKIE[i % 4] ^ ((seq >> ((i % 2) * 8)) as u8) ^ (0x37u8.wrapping_mul(i as u8 + 1));
        buf[12 + i] = psk[i] ^ mask;
    }
}

#[inline(always)]
pub fn unwrap_stun_header(packet: &[u8], psk: &[u8; 8]) -> Option<(u16, u16)> {
    if packet.len() < MIMICRY_HEADER_LEN
        || packet[0] != MAGIC_STUN_TYPE[0]
        || packet[1] != MAGIC_STUN_TYPE[1]
        || &packet[4..8] != &MAGIC_STUN_COOKIE
    {
        return None;
    }

    let seq = u16::from_be_bytes([packet[8], packet[9]]) ^ 0x2112;
    let flags = u16::from_be_bytes([packet[10], packet[11]]) ^ 0xA442;

    for i in 0..8 {
        let mask = MAGIC_STUN_COOKIE[i % 4] ^ ((seq >> ((i % 2) * 8)) as u8) ^ (0x37u8.wrapping_mul(i as u8 + 1));
        if packet[12 + i] ^ mask != psk[i] {
            return None;
        }
    }

    Some((flags, seq))
}
