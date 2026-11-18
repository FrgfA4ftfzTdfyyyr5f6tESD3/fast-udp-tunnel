//! Discord Voice / Media Protocol Mimicry (nDPI `discord.c`).
//! Mimics Discord RTP voice and media transport (PT=120 Discord Opus Audio with SSRC).
//! Bytes 0..2: [0x80, 0x78] (RTP v2, Discord Audio PT 120)
//! Bytes 2..4: Sequence Number (`seq: u16`)
//! Bytes 4..8: Discord Voice SSRC [0xD1, 0x5C, 0x08, 0xD0]
//! Bytes 8..10: Flags (`flags: u16`)
//! Bytes 10..14: 4-byte Audio Timestamp
//! Bytes 14..20: 6 bytes of PSK authentication token

use super::MIMICRY_HEADER_LEN;

pub const MAGIC_DISCORD_RTP: [u8; 2] = [0x80, 0x78];
pub const MAGIC_DISCORD_SSRC: [u8; 4] = [0xD1, 0x5C, 0x08, 0xD0];

#[inline(always)]
pub fn wrap_discord_header(buf: &mut [u8], flags: u16, seq: u16, psk: &[u8; 8]) {
    buf[0..2].copy_from_slice(&MAGIC_DISCORD_RTP);
    buf[2..4].copy_from_slice(&seq.to_be_bytes());
    buf[4..8].copy_from_slice(&MAGIC_DISCORD_SSRC);
    buf[8..10].copy_from_slice(&flags.to_be_bytes());

    let ts = (0x44495343u32).wrapping_add(seq as u32).to_be_bytes();
    buf[10..14].copy_from_slice(&ts);

    for i in 0..6 {
        let mask = ((seq >> ((i % 2) * 8)) as u8) ^ (0x2B ^ (i as u8 * 17));
        buf[14 + i] = (psk[i] ^ psk[6 + (i % 2)]) ^ mask;
    }
}

#[inline(always)]
pub fn unwrap_discord_header(packet: &[u8], psk: &[u8; 8]) -> Option<(u16, u16)> {
    if packet.len() < MIMICRY_HEADER_LEN || &packet[0..2] != &MAGIC_DISCORD_RTP || &packet[4..8] != &MAGIC_DISCORD_SSRC {
        return None;
    }

    let seq = u16::from_be_bytes([packet[2], packet[3]]);
    let flags = u16::from_be_bytes([packet[8], packet[9]]);

    for i in 0..6 {
        let mask = ((seq >> ((i % 2) * 8)) as u8) ^ (0x2B ^ (i as u8 * 17));
        if (packet[14 + i] ^ mask) != (psk[i] ^ psk[6 + (i % 2)]) {
            return None;
        }
    }

    Some((flags, seq))
}
