//! TURN ChannelData Mimicry (RFC 5766 Section 11 & nDPI).
//! Bytes 0..2: 0x40 0x01 (Channel Number in 0x4000..0x7FFF range)
//! Bytes 2..4: Length = buf.len() - 4 (RFC 5766 Section 11 standard)
//! Bytes 4..6: Sequence Number (seq: u16)
//! Bytes 6..8: Flags (flags: u16)
//! Bytes 8..16: 8 bytes of PSK token masked with seq
//! Bytes 16..20: 4 bytes salt / padding

use super::MIMICRY_HEADER_LEN;

pub const MAGIC_CHANNEL_NUM: [u8; 2] = [0x40, 0x01];

#[inline(always)]
pub fn wrap_turn_header(buf: &mut [u8], flags: u16, seq: u16, psk: &[u8; 8]) {
    buf[0..2].copy_from_slice(&MAGIC_CHANNEL_NUM);
    let len_field: u16 = (buf.len().saturating_sub(4)) as u16;
    buf[2..4].copy_from_slice(&len_field.to_be_bytes());
    buf[4..6].copy_from_slice(&seq.to_be_bytes());
    buf[6..8].copy_from_slice(&flags.to_be_bytes());

    for i in 0..8 {
        let mask = MAGIC_CHANNEL_NUM[i % 2] ^ ((seq >> ((i % 2) * 8)) as u8) ^ (0x24u8.wrapping_mul(i as u8 + 1));
        buf[8 + i] = psk[i] ^ mask;
    }

    let salt: u32 = (seq as u32).wrapping_mul(31) ^ 0x40010000;
    buf[16..20].copy_from_slice(&salt.to_be_bytes());
}

#[inline(always)]
pub fn unwrap_turn_header(packet: &[u8], psk: &[u8; 8]) -> Option<(u16, u16)> {
    if packet.len() < MIMICRY_HEADER_LEN || packet[0] != MAGIC_CHANNEL_NUM[0] || packet[1] != MAGIC_CHANNEL_NUM[1] {
        return None;
    }

    let seq = u16::from_be_bytes([packet[4], packet[5]]);
    let flags = u16::from_be_bytes([packet[6], packet[7]]);

    for i in 0..8 {
        let mask = MAGIC_CHANNEL_NUM[i % 2] ^ ((seq >> ((i % 2) * 8)) as u8) ^ (0x24u8.wrapping_mul(i as u8 + 1));
        if packet[8 + i] ^ mask != psk[i] {
            return None;
        }
    }

    Some((flags, seq))
}
