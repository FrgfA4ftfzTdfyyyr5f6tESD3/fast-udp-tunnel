//! uTP (BitTorrent Micro Transport Protocol) Mimicry (RFC 6817 & nDPI `bittorrent.c` `is_utpv1_pkt`).
//! Byte 0: 0x01 (ST_DATA = 0, Version = 1)
//! Byte 1: 0x00 (Extension = 0)
//! Bytes 2..4: 16-bit Connection ID (derived from PSK, non-zero required by nDPI)
//! Bytes 4..8: 32-bit Microsecond Timestamp (ts_usec != 0)
//! Bytes 8..12: 32-bit Delay Difference / Auth Token (tdiff_usec)
//! Bytes 12..16: 32-bit Advertised Window Size (window_size = 1MB)
//! Bytes 16..18: 16-bit Sequence Number (seq: u16)
//! Bytes 18..20: 16-bit ACK Number / Masked Flags

use super::MIMICRY_HEADER_LEN;

pub const MAGIC_TYPE_DATA: u8 = 0x01;
pub const MAGIC_EXT_NONE: u8 = 0x00;

#[inline(always)]
fn get_conn_id(psk: &[u8; 8]) -> [u8; 2] {
    let mut id = [psk[0] ^ 0x7F, psk[1] ^ 0x10];
    if id == [0, 0] {
        id = [0x7F, 0x10];
    }
    id
}

#[inline(always)]
pub fn wrap_utp_header(buf: &mut [u8], flags: u16, seq: u16, psk: &[u8; 8]) {
    buf[0] = MAGIC_TYPE_DATA;
    buf[1] = MAGIC_EXT_NONE;
    let conn_id = get_conn_id(psk);
    buf[2..4].copy_from_slice(&conn_id);

    let ts_usec: u32 = (seq as u32).wrapping_mul(1000) | 0x00123456;
    buf[4..8].copy_from_slice(&ts_usec.to_be_bytes());

    let auth_token: u32 = u32::from_be_bytes([
        psk[2] ^ psk[6],
        psk[3] ^ psk[7],
        psk[4] ^ psk[6],
        psk[5] ^ psk[7],
    ]) ^ ts_usec;
    buf[8..12].copy_from_slice(&auth_token.to_be_bytes());

    let window_size: u32 = 0x00100000; // 1 MB window
    buf[12..16].copy_from_slice(&window_size.to_be_bytes());

    buf[16..18].copy_from_slice(&seq.to_be_bytes());

    let psk_word = u16::from_be_bytes([psk[6], psk[7]]);
    let ack_masked = flags ^ psk_word ^ seq;
    buf[18..20].copy_from_slice(&ack_masked.to_be_bytes());
}

#[inline(always)]
pub fn unwrap_utp_header(packet: &[u8], psk: &[u8; 8]) -> Option<(u16, u16)> {
    if packet.len() < MIMICRY_HEADER_LEN
        || packet[0] != MAGIC_TYPE_DATA
        || packet[1] != MAGIC_EXT_NONE
    {
        return None;
    }

    let conn_id = get_conn_id(psk);
    if &packet[2..4] != &conn_id {
        return None;
    }

    let ts_usec = u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]);
    let expected_auth = u32::from_be_bytes([
        psk[2] ^ psk[6],
        psk[3] ^ psk[7],
        psk[4] ^ psk[6],
        psk[5] ^ psk[7],
    ]) ^ ts_usec;
    if &packet[8..12] != &expected_auth.to_be_bytes() {
        return None;
    }

    let seq = u16::from_be_bytes([packet[16], packet[17]]);
    let psk_word = u16::from_be_bytes([psk[6], psk[7]]);
    let ack_masked = u16::from_be_bytes([packet[18], packet[19]]);
    let flags = ack_masked ^ psk_word ^ seq;

    Some((flags, seq))
}
