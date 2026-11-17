//! Zoom Media Stream Mimicry (nDPI `zoom.c`).
//! Mimics Zoom SFU client media stream (SFU Type 1 handshake & media transport).
//! Bytes 0..3: [0x01, 0x00, 0x03] (Matching nDPI Zoom client marker `tomatch[]`)
//! Byte 3: 0x00 (SFU Direction: Client -> Zoom)
//! Bytes 4..6: Sequence Number (`seq: u16`)
//! Bytes 6..8: Flags (`flags: u16`)
//! Bytes 8..12: 4-byte Zoom Session Timestamp
//! Bytes 12..20: 8 bytes of PSK authentication token

use super::MIMICRY_HEADER_LEN;

pub const MAGIC_ZOOM_PREFIX: [u8; 3] = [0x01, 0x00, 0x03];

#[inline(always)]
pub fn wrap_zoom_header(buf: &mut [u8], flags: u16, seq: u16, psk: &[u8; 8]) {
    buf[0..3].copy_from_slice(&MAGIC_ZOOM_PREFIX);
    buf[3] = 0x00; // Client -> Server direction
    buf[4..6].copy_from_slice(&seq.to_be_bytes());
    buf[6..8].copy_from_slice(&flags.to_be_bytes());

    let ts = (0x19840401u32).wrapping_add(seq as u32).to_be_bytes();
    buf[8..12].copy_from_slice(&ts);

    for i in 0..8 {
        let mask = ((seq >> ((i % 2) * 8)) as u8) ^ (0x4E ^ (i as u8 * 11));
        buf[12 + i] = psk[i] ^ mask;
    }
}

#[inline(always)]
pub fn unwrap_zoom_header(packet: &[u8], psk: &[u8; 8]) -> Option<(u16, u16)> {
    if packet.len() < MIMICRY_HEADER_LEN || &packet[0..3] != &MAGIC_ZOOM_PREFIX || packet[3] != 0x00 {
        return None;
    }

    let seq = u16::from_be_bytes([packet[4], packet[5]]);
    let flags = u16::from_be_bytes([packet[6], packet[7]]);

    for i in 0..8 {
        let mask = ((seq >> ((i % 2) * 8)) as u8) ^ (0x4E ^ (i as u8 * 11));
        if packet[12 + i] ^ mask != psk[i] {
            return None;
        }
    }

    Some((flags, seq))
}
