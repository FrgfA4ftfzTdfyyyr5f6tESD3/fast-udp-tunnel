//! QUIC v2 Initial Header Mimicry (RFC 9369 & nDPI `quic.c` V_2 0x6b3343cf).
//! Byte 0: 0xD3 (Long Header: Form=1, Fixed=1, Type=0x01 (Initial in v2), PktNumLen=3)
//! Bytes 1..5: 4-byte QUIC v2 Version (0x6b3343cf)
//! Byte 5: 1-byte Destination Connection ID Length (0x08)
//! Bytes 6..14: 8-byte DCID derived with RFC 9369 v2 Salt
//! Bytes 14..16: Packet Number / Sequence (`seq: u16`)
//! Bytes 16..18: Flags (`flags: u16`)
//! Bytes 18..20: 2 bytes of PSK authentication token

use super::MIMICRY_HEADER_LEN;

pub const MAGIC_INITIAL: u8 = 0xD3;
pub const QUIC_V2_VERSION: [u8; 4] = [0x6B, 0x33, 0x43, 0xCF];
pub const QUIC_V2_SALT_PREFIX: [u8; 8] = [0x0D, 0xED, 0xE3, 0xDE, 0xF7, 0x00, 0xA6, 0xDB];

#[inline(always)]
fn get_dcid_v2(psk: &[u8; 8]) -> [u8; 8] {
    let mut dcid = [0u8; 8];
    for i in 0..8 {
        dcid[i] = psk[i] ^ QUIC_V2_SALT_PREFIX[i];
    }
    dcid
}

#[inline(always)]
pub fn wrap_quic_v2_header(buf: &mut [u8], flags: u16, seq: u16, psk: &[u8; 8]) {
    buf[0] = MAGIC_INITIAL;
    buf[1..5].copy_from_slice(&QUIC_V2_VERSION);
    buf[5] = 0x08; // DCID Length = 8 bytes
    let dcid = get_dcid_v2(psk);
    buf[6..14].copy_from_slice(&dcid);
    buf[14..16].copy_from_slice(&seq.to_be_bytes());
    buf[16..18].copy_from_slice(&flags.to_be_bytes());

    let mask = (seq ^ 0x6B33).to_be_bytes();
    buf[18] = psk[0] ^ mask[0];
    buf[19] = psk[1] ^ mask[1];
}

#[inline(always)]
pub fn unwrap_quic_v2_header(packet: &[u8], psk: &[u8; 8]) -> Option<(u16, u16)> {
    if packet.len() < MIMICRY_HEADER_LEN || packet[0] != MAGIC_INITIAL {
        return None;
    }

    if &packet[1..5] != &QUIC_V2_VERSION || packet[5] != 0x08 {
        return None;
    }

    let dcid = get_dcid_v2(psk);
    if &packet[6..14] != &dcid {
        return None;
    }

    let seq = u16::from_be_bytes([packet[14], packet[15]]);
    let flags = u16::from_be_bytes([packet[16], packet[17]]);

    let mask = (seq ^ 0x6B33).to_be_bytes();
    if packet[18] ^ mask[0] != psk[0] || packet[19] ^ mask[1] != psk[1] {
        return None;
    }

    Some((flags, seq))
}
