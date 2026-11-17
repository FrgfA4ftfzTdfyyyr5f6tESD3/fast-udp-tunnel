//! Valve Source Engine / Steam UDP Protocol Mimicry (CS:GO, Dota 2, TF2 & nDPI `source_engine.c`).
//! Bytes 0..4: 0xFF 0xFF 0xFF 0xFF (Unfragmented A2S datagram header)
//! Byte 4: 0x55 ('U' - A2S_PLAYER query opcode, strictly classified by nDPI)
//! Bytes 5..7: Sequence Number (seq: u16)
//! Bytes 7..9: Flags (flags: u16)
//! Bytes 9..17: 8 bytes of PSK authentication token
//! Bytes 17..20: 3 bytes padding / salt

use super::MIMICRY_HEADER_LEN;

pub const MAGIC_A2S_HEADER: [u8; 4] = [0xFF, 0xFF, 0xFF, 0xFF];
pub const MAGIC_A2S_OPCODE: u8 = 0x55; // 'U'

#[inline(always)]
pub fn wrap_steam_header(buf: &mut [u8], flags: u16, seq: u16, psk: &[u8; 8]) {
    buf[0..4].copy_from_slice(&MAGIC_A2S_HEADER);
    buf[4] = MAGIC_A2S_OPCODE;
    buf[5..7].copy_from_slice(&seq.to_be_bytes());
    buf[7..9].copy_from_slice(&flags.to_be_bytes());

    for i in 0..8 {
        let mask = MAGIC_A2S_OPCODE ^ ((seq >> ((i % 2) * 8)) as u8) ^ (0x1Fu8.wrapping_mul(i as u8 + 1));
        buf[9 + i] = psk[i] ^ mask;
    }

    buf[17] = 0xAA;
    buf[18] = 0xBB;
    buf[19] = 0xCC;
}

#[inline(always)]
pub fn unwrap_steam_header(packet: &[u8], psk: &[u8; 8]) -> Option<(u16, u16)> {
    if packet.len() < MIMICRY_HEADER_LEN || &packet[0..4] != &MAGIC_A2S_HEADER || packet[4] != MAGIC_A2S_OPCODE {
        return None;
    }

    let seq = u16::from_be_bytes([packet[5], packet[6]]);
    let flags = u16::from_be_bytes([packet[7], packet[8]]);

    for i in 0..8 {
        let mask = MAGIC_A2S_OPCODE ^ ((seq >> ((i % 2) * 8)) as u8) ^ (0x1Fu8.wrapping_mul(i as u8 + 1));
        if packet[9 + i] ^ mask != psk[i] {
            return None;
        }
    }

    Some((flags, seq))
}
