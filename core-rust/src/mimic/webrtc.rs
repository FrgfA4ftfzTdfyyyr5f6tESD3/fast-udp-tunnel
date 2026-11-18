//! WebRTC / SRTP (RTP v2) Mimicry (RFC 3550 & nDPI `rtp.c`).
//! Byte 0: 0x80 (V=2, P=0, X=0, CC=0)
//! Byte 1: 0x60 (M=0, PT=96 Dynamic RTP)
//! Bytes 2..4: Sequence Number (`seq: u16`)
//! Bytes 4..8: 32-bit Timestamp (`seq * 160`)
//! Bytes 8..12: 32-bit SSRC (`0x11223344`)
//! Bytes 12..14: Flags (`flags: u16`)
//! Bytes 14..20: 6 bytes of PSK authentication token

use super::MIMICRY_HEADER_LEN;

pub const MAGIC_V2: u8 = 0x80;
pub const MAGIC_PT96: u8 = 0x60;
pub const MAGIC_SSRC: [u8; 4] = [0x11, 0x22, 0x33, 0x44];

#[inline(always)]
pub fn wrap_webrtc_header(buf: &mut [u8], flags: u16, seq: u16, psk: &[u8; 8]) {
    buf[0] = MAGIC_V2;
    buf[1] = MAGIC_PT96;
    buf[2..4].copy_from_slice(&seq.to_be_bytes());
    let ts: u32 = (seq as u32).wrapping_mul(160) ^ 0xa5a50000;
    buf[4..8].copy_from_slice(&ts.to_be_bytes());
    buf[8..12].copy_from_slice(&MAGIC_SSRC);
    buf[12..14].copy_from_slice(&flags.to_be_bytes());

    for i in 0..6 {
        let mask = ((seq >> ((i % 2) * 8)) as u8) ^ MAGIC_SSRC[i % 4];
        buf[14 + i] = (psk[i] ^ psk[6 + (i % 2)]) ^ mask;
    }
}

#[inline(always)]
pub fn unwrap_webrtc_header(packet: &[u8], psk: &[u8; 8]) -> Option<(u16, u16)> {
    if packet.len() < MIMICRY_HEADER_LEN || packet[0] != MAGIC_V2 || packet[1] != MAGIC_PT96 {
        return None;
    }

    if &packet[8..12] != &MAGIC_SSRC {
        return None;
    }

    let seq = u16::from_be_bytes([packet[2], packet[3]]);
    let flags = u16::from_be_bytes([packet[12], packet[13]]);

    for i in 0..6 {
        let mask = ((seq >> ((i % 2) * 8)) as u8) ^ MAGIC_SSRC[i % 4];
        if (packet[14 + i] ^ mask) != (psk[i] ^ psk[6 + (i % 2)]) {
            return None;
        }
    }

    Some((flags, seq))
}
