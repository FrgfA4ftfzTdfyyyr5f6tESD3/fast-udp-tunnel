//! RakNet Game Stream Protocol Mimicry (Minecraft / Mobile Gaming & nDPI `raknet.c`).
//! Byte 0: 0x84 (Connected Frame Data)
//! Bytes 1..4: 24-bit Little-Endian Sequence Number (RakNet standard)
//! Byte 4: 0x40 (Reliable frame, lower 4 bits zero, strictly verified by nDPI)
//! Bytes 5..7: 16-bit Message Size in bits ((buf.len() - 7) * 8, verified by nDPI)
//! Bytes 7..9: Flags (flags: u16)
//! Bytes 9..11: Salt
//! Bytes 11..19: 8 bytes of PSK authentication token
//! Byte 19: 0x00

use super::MIMICRY_HEADER_LEN;

pub const MAGIC_RAKNET_FRAME: u8 = 0x84;

#[inline(always)]
pub fn wrap_raknet_header(buf: &mut [u8], flags: u16, seq: u16, psk: &[u8; 8]) {
    buf[0] = MAGIC_RAKNET_FRAME;
    // 24-bit Little-Endian Sequence Number
    buf[1] = seq as u8;
    buf[2] = (seq >> 8) as u8;
    buf[3] = 0x00;

    // Byte 4: msg_flags (reliable, lower 4 bits == 0 required by nDPI)
    buf[4] = 0x40;

    // Bytes 5..7: Message size in bits (big-endian)
    let msg_bits: u16 = (buf.len().saturating_sub(7) * 8) as u16;
    buf[5..7].copy_from_slice(&msg_bits.to_be_bytes());

    buf[7..9].copy_from_slice(&flags.to_be_bytes());

    let salt: u16 = seq.wrapping_mul(73) ^ 0x1337;
    buf[9..11].copy_from_slice(&salt.to_be_bytes());

    for i in 0..8 {
        let mask = ((salt >> ((i % 2) * 8)) as u8) ^ ((seq >> ((i % 2) * 8)) as u8);
        buf[11 + i] = psk[i] ^ mask;
    }
    buf[19] = 0x00;
}

#[inline(always)]
pub fn unwrap_raknet_header(packet: &[u8], psk: &[u8; 8]) -> Option<(u16, u16)> {
    if packet.len() < MIMICRY_HEADER_LEN || packet[0] != MAGIC_RAKNET_FRAME || (packet[4] & 0x0F) != 0 {
        return None;
    }

    let seq = (packet[1] as u16) | ((packet[2] as u16) << 8);
    let flags = u16::from_be_bytes([packet[7], packet[8]]);
    let salt = u16::from_be_bytes([packet[9], packet[10]]);

    for i in 0..8 {
        let mask = ((salt >> ((i % 2) * 8)) as u8) ^ ((seq >> ((i % 2) * 8)) as u8);
        if packet[11 + i] ^ mask != psk[i] {
            return None;
        }
    }

    Some((flags, seq))
}
