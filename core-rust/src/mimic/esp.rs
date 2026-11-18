//! IPsec NAT-Traversal ESP Header Mimicry (RFC 3948 & nDPI `ipsec.c`).
//! Bytes 0..4: 32-bit Security Parameter Index (SPI != 0x00000000)
//! Bytes 4..8: 32-bit Sequence Number
//! Bytes 8..10: Flags (flags: u16)
//! Bytes 10..18: 8 bytes of PSK authentication token
//! Bytes 18..20: 2 bytes padding

use super::MIMICRY_HEADER_LEN;

pub const MAGIC_SPI: [u8; 4] = [0x19, 0x84, 0x07, 0x10];

#[inline(always)]
pub fn wrap_esp_header(buf: &mut [u8], flags: u16, seq: u16, psk: &[u8; 8]) {
    buf[0..4].copy_from_slice(&MAGIC_SPI);
    let seq_32: u32 = seq as u32;
    buf[4..8].copy_from_slice(&seq_32.to_be_bytes());
    buf[8..10].copy_from_slice(&flags.to_be_bytes());

    for i in 0..8 {
        let mask = MAGIC_SPI[i % 4] ^ ((seq >> ((i % 2) * 8)) as u8) ^ (0x4Bu8.wrapping_mul(i as u8 + 1));
        buf[10 + i] = psk[i] ^ mask;
    }

    buf[18] = 0x00;
    buf[19] = 0x00;
}

#[inline(always)]
pub fn unwrap_esp_header(packet: &[u8], psk: &[u8; 8]) -> Option<(u16, u16)> {
    if packet.len() < MIMICRY_HEADER_LEN || &packet[0..4] != &MAGIC_SPI {
        return None;
    }

    let seq = u16::from_be_bytes([packet[6], packet[7]]);
    let flags = u16::from_be_bytes([packet[8], packet[9]]);

    for i in 0..8 {
        let mask = MAGIC_SPI[i % 4] ^ ((seq >> ((i % 2) * 8)) as u8) ^ (0x4Bu8.wrapping_mul(i as u8 + 1));
        if packet[10 + i] ^ mask != psk[i] {
            return None;
        }
    }

    Some((flags, seq))
}
