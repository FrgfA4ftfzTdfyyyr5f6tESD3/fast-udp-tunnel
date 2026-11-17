//! Steam Datagram Relay (SDR) Mimicry (nDPI `steam_datagram_relay.c`).
//! Uses Valve's proprietary SDR routing/ping framing (`sdping` token at offset 2).
//! Byte 0..2: [0x08, 0x00] (SDR Routing Opcode / Connection frame)
//! Bytes 2..8: "sdping" (6-byte ASCII tag triggering nDPI Valve SDR dissector)
//! Bytes 8..12: Valve AppID / SDR Route Token
//! Bytes 12..14: Sequence Number (`seq: u16`)
//! Bytes 14..16: Flags (`flags: u16`)
//! Bytes 16..20: 4 bytes of PSK authentication token

use super::MIMICRY_HEADER_LEN;

pub const MAGIC_SDR_PREFIX: [u8; 2] = [0x08, 0x00];
pub const MAGIC_SDR_TAG: &[u8; 6] = b"sdping";
pub const VALVE_CS2_APPID: [u8; 4] = [0x00, 0x00, 0x02, 0xDA]; // Valve AppID 730 (CS2)

#[inline(always)]
pub fn wrap_sdr_header(buf: &mut [u8], flags: u16, seq: u16, psk: &[u8; 8]) {
    buf[0..2].copy_from_slice(&MAGIC_SDR_PREFIX);
    buf[2..8].copy_from_slice(MAGIC_SDR_TAG);
    buf[8..12].copy_from_slice(&VALVE_CS2_APPID);
    buf[12..14].copy_from_slice(&seq.to_be_bytes());
    buf[14..16].copy_from_slice(&flags.to_be_bytes());

    for i in 0..4 {
        let mask = ((seq >> ((i % 2) * 8)) as u8) ^ (0x73 ^ (i as u8 * 9));
        buf[16 + i] = (psk[i] ^ psk[i + 4]) ^ mask;
    }
}

#[inline(always)]
pub fn unwrap_sdr_header(packet: &[u8], psk: &[u8; 8]) -> Option<(u16, u16)> {
    if packet.len() < MIMICRY_HEADER_LEN {
        return None;
    }

    if &packet[0..2] != &MAGIC_SDR_PREFIX || &packet[2..8] != MAGIC_SDR_TAG {
        return None;
    }

    let seq = u16::from_be_bytes([packet[12], packet[13]]);
    let flags = u16::from_be_bytes([packet[14], packet[15]]);

    for i in 0..4 {
        let mask = ((seq >> ((i % 2) * 8)) as u8) ^ (0x73 ^ (i as u8 * 9));
        if (packet[16 + i] ^ mask) != (psk[i] ^ psk[i + 4]) {
            return None;
        }
    }

    Some((flags, seq))
}
