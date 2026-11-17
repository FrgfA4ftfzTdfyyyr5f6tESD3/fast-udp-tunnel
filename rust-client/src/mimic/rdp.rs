//! Microsoft RDP over UDP (MS-RDPEUDP) Mimicry (nDPI `rdp.c`).
//! Mimics RDPEUDP transport (RFC / Microsoft Remote Desktop Protocol UDP).
//! Bytes 0..4: [0xFF, 0xFF, 0xFF, 0xFF] (RDPEUDP SYN Frame header)
//! Bytes 4..6: [0x00, 0x00] (Source Session ID, distinguishing from Steam 0x55)
//! Bytes 6..8: [0x00, 0x01] (RDPUDP_FLAG_SYN = 0x0001 matching nDPI check)
//! Bytes 8..10: Sequence Number (`seq: u16`)
//! Bytes 10..12: Flags (`flags: u16`)
//! Bytes 12..14: Upstream MTU = 1380 (0x0564 <= 1600 matching nDPI check)
//! Bytes 14..16: Downstream MTU = 1380 (0x0564 <= 1600 matching nDPI check)
//! Bytes 16..20: 4 bytes of PSK authentication token

use super::MIMICRY_HEADER_LEN;

pub const MAGIC_RDP_PREFIX: [u8; 4] = [0xFF, 0xFF, 0xFF, 0xFF];
pub const MAGIC_RDP_SYN_FLAGS: [u8; 2] = [0x00, 0x01];
pub const RDPEUDP_MTU: [u8; 2] = [0x05, 0x64]; // 1380 MTU

#[inline(always)]
pub fn wrap_rdp_header(buf: &mut [u8], flags: u16, seq: u16, psk: &[u8; 8]) {
    buf[0..4].copy_from_slice(&MAGIC_RDP_PREFIX);
    buf[4..6].copy_from_slice(&[0x00, 0x00]); // Source session (distinct from Steam 'U' 0x55)
    buf[6..8].copy_from_slice(&MAGIC_RDP_SYN_FLAGS);
    buf[8..10].copy_from_slice(&seq.to_be_bytes());
    buf[10..12].copy_from_slice(&flags.to_be_bytes());
    buf[12..14].copy_from_slice(&RDPEUDP_MTU);
    buf[14..16].copy_from_slice(&RDPEUDP_MTU);

    for i in 0..4 {
        let mask = ((seq >> ((i % 2) * 8)) as u8) ^ (0x9D ^ (i as u8 * 13));
        buf[16 + i] = (psk[i] ^ psk[i + 4]) ^ mask;
    }
}

#[inline(always)]
pub fn unwrap_rdp_header(packet: &[u8], psk: &[u8; 8]) -> Option<(u16, u16)> {
    if packet.len() < MIMICRY_HEADER_LEN {
        return None;
    }

    if &packet[0..4] != &MAGIC_RDP_PREFIX || packet[4] != 0x00 || &packet[6..8] != &MAGIC_RDP_SYN_FLAGS {
        return None;
    }

    let seq = u16::from_be_bytes([packet[8], packet[9]]);
    let flags = u16::from_be_bytes([packet[10], packet[11]]);

    for i in 0..4 {
        let mask = ((seq >> ((i % 2) * 8)) as u8) ^ (0x9D ^ (i as u8 * 13));
        if (packet[16 + i] ^ mask) != (psk[i] ^ psk[i + 4]) {
            return None;
        }
    }

    Some((flags, seq))
}
