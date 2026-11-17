//! DNS Query/Response Header Mimicry (RFC 1035 & nDPI `dns.c` `is_valid_dns`).
//! Bytes 0..2: 16-bit Transaction ID
//! Bytes 2..4: 0x01 0x00 (Standard Query, Opcode 0, RD=1, strictly verified by nDPI)
//! Bytes 4..6: 0x00 0x01 (Questions Count = 1)
//! Bytes 6..8: 0x00 0x00 (Answer RRs = 0)
//! Bytes 8..10: Flags (flags: u16)
//! Bytes 10..18: 8 bytes of PSK authentication token
//! Bytes 18..20: 0x00 0x01 (QTYPE A)

use super::MIMICRY_HEADER_LEN;

pub const MAGIC_DNS_FLAGS: [u8; 4] = [0x01, 0x00, 0x00, 0x01];

#[inline(always)]
pub fn wrap_dns_header(buf: &mut [u8], flags: u16, seq: u16, psk: &[u8; 8]) {
    let tx_id = seq ^ 0xcafe;
    buf[0..2].copy_from_slice(&tx_id.to_be_bytes());
    buf[2..6].copy_from_slice(&MAGIC_DNS_FLAGS);
    buf[6..8].copy_from_slice(&[0x00, 0x00]);
    buf[8..10].copy_from_slice(&flags.to_be_bytes());

    for i in 0..8 {
        let mask = ((tx_id >> ((i % 2) * 8)) as u8) ^ ((seq >> ((i % 2) * 8)) as u8) ^ (0x13u8.wrapping_mul(i as u8 + 1));
        buf[10 + i] = psk[i] ^ mask;
    }

    buf[18] = 0x00;
    buf[19] = 0x01; // QTYPE A
}

#[inline(always)]
pub fn unwrap_dns_header(packet: &[u8], psk: &[u8; 8]) -> Option<(u16, u16)> {
    if packet.len() < MIMICRY_HEADER_LEN || &packet[2..6] != &MAGIC_DNS_FLAGS {
        return None;
    }

    let tx_id = u16::from_be_bytes([packet[0], packet[1]]);
    let seq = tx_id ^ 0xcafe;
    let flags = u16::from_be_bytes([packet[8], packet[9]]);

    for i in 0..8 {
        let mask = ((tx_id >> ((i % 2) * 8)) as u8) ^ ((seq >> ((i % 2) * 8)) as u8) ^ (0x13u8.wrapping_mul(i as u8 + 1));
        if packet[10 + i] ^ mask != psk[i] {
            return None;
        }
    }

    Some((flags, seq))
}
