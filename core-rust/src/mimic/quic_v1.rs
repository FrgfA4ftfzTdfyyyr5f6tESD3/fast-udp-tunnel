//! QUIC v1 / HTTP/3 Short Header Mimicry (RFC 9000 & nDPI `quic.c`).
//! Byte 0: 0x43 (1-RTT Short Header, Fixed=1, Spin=0, KeyPhase=0, PktNumLen=2)
//! Bytes 1..9: 8-byte Destination Connection ID (DCID, validated by nDPI `may_be_sh`)
//! Bytes 9..11: Packet Number / Sequence (`seq: u16`)
//! Bytes 11..13: Flags (`flags: u16`)
//! Bytes 13..20: 7 bytes of PSK authentication token

use super::MIMICRY_HEADER_LEN;

pub const MAGIC_BYTE: u8 = 0x43;

#[inline(always)]
fn get_dcid(psk: &[u8; 8]) -> [u8; 8] {
    let mut dcid = [0u8; 8];
    for i in 0..8 {
        dcid[i] = psk[i] ^ 0x47;
    }
    dcid
}

#[inline(always)]
pub fn wrap_quic_v1_header(buf: &mut [u8], flags: u16, seq: u16, psk: &[u8; 8]) {
    buf[0] = MAGIC_BYTE;
    let dcid = get_dcid(psk);
    buf[1..9].copy_from_slice(&dcid);
    buf[9..11].copy_from_slice(&seq.to_be_bytes());
    buf[11..13].copy_from_slice(&flags.to_be_bytes());

    for i in 0..7 {
        let mask = ((seq >> ((i % 2) * 8)) as u8) ^ (0x5A ^ (i as u8 * 7));
        buf[13 + i] = psk[i] ^ mask;
    }
}

#[inline(always)]
pub fn unwrap_quic_v1_header(packet: &[u8], psk: &[u8; 8]) -> Option<(u16, u16)> {
    if packet.len() < MIMICRY_HEADER_LEN || packet[0] != MAGIC_BYTE {
        return None;
    }

    let dcid = get_dcid(psk);
    if &packet[1..9] != &dcid {
        return None;
    }

    let seq = u16::from_be_bytes([packet[9], packet[10]]);
    let flags = u16::from_be_bytes([packet[11], packet[12]]);

    for i in 0..7 {
        let mask = ((seq >> ((i % 2) * 8)) as u8) ^ (0x5A ^ (i as u8 * 7));
        if packet[13 + i] ^ mask != psk[i] {
            return None;
        }
    }

    Some((flags, seq))
}
