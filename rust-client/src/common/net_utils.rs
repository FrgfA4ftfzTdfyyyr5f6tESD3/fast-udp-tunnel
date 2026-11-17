//! Central Unified Network & System Utilities.
//! Provides shared, safe kernel manipulation, IP parsing, checksum calculation, and probing.

use std::fs;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::path::Path;

/// Safely write a value to `/proc/sys/...` with graceful handling for read-only / container environments.
pub fn write_proc_sys(subpath: &str, value: &str) -> bool {
    let full_path = format!("/proc/sys/{}", subpath.trim_start_matches('/'));
    if !Path::new(&full_path).exists() {
        return false;
    }
    fs::write(&full_path, value.as_bytes()).is_ok()
}

/// Safely read a string from `/proc/sys/...`.
pub fn read_proc_sys(subpath: &str) -> Option<String> {
    let full_path = format!("/proc/sys/{}", subpath.trim_start_matches('/'));
    if !Path::new(&full_path).exists() {
        return None;
    }
    fs::read_to_string(&full_path).ok()
}

/// Calculate standard RFC 1071 16-bit one's complement Internet Checksum.
pub fn compute_checksum(data: &[u8]) -> u16 {
    let mut sum = 0u32;
    let mut i = 0;
    while i + 1 < data.len() {
        let word = u16::from_be_bytes([data[i], data[i + 1]]);
        sum += word as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while (sum >> 16) != 0 {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    !sum as u16
}

/// Build an encapsulated 28-byte ICMP Echo Request probe packet for latency & quality measurement.
pub fn build_icmp_probe_packet(seq: u16, src_ipv4: [u8; 4]) -> [u8; 28] {
    let mut pkt = [0u8; 28];
    pkt[0] = 0x45; // IPv4, Header Len = 20 bytes
    pkt[1] = 0x00;
    pkt[2] = 0x00;
    pkt[3] = 0x1c; // Total Length = 28 bytes
    pkt[4] = 0x00;
    pkt[5] = 0x00;
    pkt[6] = 0x40; // Don't fragment
    pkt[7] = 0x00;
    pkt[8] = 64;   // TTL = 64
    pkt[9] = 1;    // Protocol = ICMP (1)
    pkt[10] = 0x00;
    pkt[11] = 0x00;
    // Source: dynamically configured client assigned IPv4
    pkt[12..16].copy_from_slice(&src_ipv4);
    // Dest: 10.8.0.1
    pkt[16] = 10;
    pkt[17] = 8;
    pkt[18] = 0;
    pkt[19] = 1;

    let ip_cksum = compute_checksum(&pkt[0..20]);
    pkt[10] = (ip_cksum >> 8) as u8;
    pkt[11] = (ip_cksum & 0xff) as u8;

    // ICMP Echo Request (Type = 8, Code = 0)
    pkt[20] = 8;
    pkt[21] = 0;
    pkt[22] = 0;
    pkt[23] = 0;
    pkt[24] = 0x13;
    pkt[25] = 0x37; // Identifier
    pkt[26] = (seq >> 8) as u8;
    pkt[27] = (seq & 0xff) as u8;

    let icmp_cksum = compute_checksum(&pkt[20..28]);
    pkt[22] = (icmp_cksum >> 8) as u8;
    pkt[23] = (icmp_cksum & 0xff) as u8;

    pkt
}

/// Zero-allocation, high-performance extraction of inner IP destination address.
/// Supports both IPv4 and IPv6 packets without heap allocations.
#[inline(always)]
pub fn parse_ip_destination(packet: &[u8]) -> Option<IpAddr> {
    if packet.is_empty() {
        return None;
    }
    match packet[0] >> 4 {
        4 if packet.len() >= 20 => {
            let dst_bytes: [u8; 4] = [packet[16], packet[17], packet[18], packet[19]];
            Some(IpAddr::V4(Ipv4Addr::from(dst_bytes)))
        }
        6 if packet.len() >= 40 => {
            let mut dst_bytes = [0u8; 16];
            dst_bytes.copy_from_slice(&packet[24..40]);
            Some(IpAddr::V6(Ipv6Addr::from(dst_bytes)))
        }
        _ => None,
    }
}

/// Zero-allocation, high-performance extraction of inner IP source address.
#[inline(always)]
pub fn parse_ip_source(packet: &[u8]) -> Option<IpAddr> {
    if packet.is_empty() {
        return None;
    }
    match packet[0] >> 4 {
        4 if packet.len() >= 20 => {
            let src_bytes: [u8; 4] = [packet[12], packet[13], packet[14], packet[15]];
            Some(IpAddr::V4(Ipv4Addr::from(src_bytes)))
        }
        6 if packet.len() >= 40 => {
            let mut src_bytes = [0u8; 16];
            src_bytes.copy_from_slice(&packet[8..24]);
            Some(IpAddr::V6(Ipv6Addr::from(src_bytes)))
        }
        _ => None,
    }
}
