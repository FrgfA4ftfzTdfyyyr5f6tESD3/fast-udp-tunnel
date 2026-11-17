//! Riot Games / Valorant UDP Protocol Mimicry (nDPI `riotgames.c`).
//! Mimics Riot Games real-time game traffic (Channel 0x0001, RG identifier, dynamic session).
//! Bytes 0..4: [0x00, 0x01, 0x52, 0x47] (Riot Protocol Channel 1, "RG" marker)
//! Bytes 4..8: Session / Match ID derived from PSK
//! Bytes 8..10: Sequence Number (`seq: u16`)
//! Bytes 10..12: Flags (`flags: u16`)
//! Bytes 12..20: 8 bytes of PSK authentication token

use super::MIMICRY_HEADER_LEN;

pub const MAGIC_RIOT_PREFIX: [u8; 4] = [0x00, 0x01, 0x52, 0x47];

#[inline(always)]
fn get_session_id(psk: &[u8; 8]) -> [u8; 4] {
    [
        psk[0] ^ 0xAA,
        psk[1] ^ 0xBB,
        psk[2] ^ 0xCC,
        psk[3] ^ 0xDD,
    ]
}

#[inline(always)]
pub fn wrap_riot_header(buf: &mut [u8], flags: u16, seq: u16, psk: &[u8; 8]) {
    buf[0..4].copy_from_slice(&MAGIC_RIOT_PREFIX);
    let session = get_session_id(psk);
    buf[4..8].copy_from_slice(&session);
    buf[8..10].copy_from_slice(&seq.to_be_bytes());
    buf[10..12].copy_from_slice(&flags.to_be_bytes());

    for i in 0..8 {
        let mask = ((seq >> ((i % 2) * 8)) as u8) ^ (0x3C ^ (i as u8 * 5));
        buf[12 + i] = psk[i] ^ mask;
    }
}

#[inline(always)]
pub fn unwrap_riot_header(packet: &[u8], psk: &[u8; 8]) -> Option<(u16, u16)> {
    if packet.len() < MIMICRY_HEADER_LEN || &packet[0..4] != &MAGIC_RIOT_PREFIX {
        return None;
    }

    let session = get_session_id(psk);
    if &packet[4..8] != &session {
        return None;
    }

    let seq = u16::from_be_bytes([packet[8], packet[9]]);
    let flags = u16::from_be_bytes([packet[10], packet[11]]);

    for i in 0..8 {
        let mask = ((seq >> ((i % 2) * 8)) as u8) ^ (0x3C ^ (i as u8 * 5));
        if packet[12 + i] ^ mask != psk[i] {
            return None;
        }
    }

    Some((flags, seq))
}
