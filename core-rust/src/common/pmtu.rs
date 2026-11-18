//! Connect-Time Dynamic Path MTU Discovery & Negotiation Engine (RFC 1981 / RFC 1191 / RFC 8899).
//! Eliminates hardcoded MTU, detects actual wire capacity (Fiber 1500 vs Cellular 1400),
//! and negotiates zero-fragmentation MTU between Client and Server.

use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

use crate::common::constants::{MIMICRY_HEADER_LEN, FLAG_FRAME_MASK, FLAG_KEEPALIVE, FLAG_KEEPALIVE_ACK};
use crate::core::crypto::PayloadMode;
use crate::mimic::MimicProfile;

/// Handshake Magic prefix for MTU negotiation frame ('M', 'T')
pub const MTU_HANDSHAKE_MAGIC: [u8; 2] = [0x4D, 0x54];

/// Protocol boundaries
pub const MIN_TUNNEL_MTU: u32 = 1280;
pub const MAX_TUNNEL_MTU: u32 = 1500;
pub const DEFAULT_TUNNEL_MTU: u32 = 1500;

/// Enable Don't Fragment flag (DF=1) cross-platform to activate Path MTU Discovery.
#[cfg(target_os = "windows")]
pub fn set_socket_dont_fragment(socket: &UdpSocket, is_ipv6: bool) {
    use std::os::windows::io::AsRawSocket;
    let raw = socket.as_raw_socket() as usize;
    let enabled: i32 = 1;
    unsafe {
        #[link(name = "ws2_32")]
        extern "system" {
            fn setsockopt(s: usize, level: i32, optname: i32, optval: *const u8, optlen: i32) -> i32;
        }
        if is_ipv6 {
            // Level 41 (IPPROTO_IPV6), Opt 14 (IPV6_DONTFRAG)
            let _ = setsockopt(
                raw,
                41,
                14,
                &enabled as *const _ as *const u8,
                std::mem::size_of::<i32>() as i32,
            );
        } else {
            // Level 0 (IPPROTO_IP), Opt 14 (IP_DONTFRAGMENT)
            let _ = setsockopt(
                raw,
                0,
                14,
                &enabled as *const _ as *const u8,
                std::mem::size_of::<i32>() as i32,
            );
        }
    }
}

#[cfg(target_os = "linux")]
pub fn set_socket_dont_fragment(socket: &UdpSocket, is_ipv6: bool) {
    use std::os::unix::io::AsRawFd;
    let raw = socket.as_raw_fd();
    unsafe {
        if is_ipv6 {
            // IPPROTO_IPV6 = 41, IPV6_MTU_DISCOVER = 23, IPV6_PMTUDISC_DO = 2
            let pmtu_disc: libc::c_int = 2;
            let _ = libc::setsockopt(
                raw,
                libc::IPPROTO_IPV6,
                23,
                &pmtu_disc as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
            let enabled: libc::c_int = 1;
            let _ = libc::setsockopt(
                raw,
                libc::IPPROTO_IPV6,
                62, // IPV6_DONTFRAG
                &enabled as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        } else {
            // IPPROTO_IP = 0, IP_MTU_DISCOVER = 10, IP_PMTUDISC_DO = 2
            let pmtu_disc: libc::c_int = 2;
            let _ = libc::setsockopt(
                raw,
                libc::IPPROTO_IP,
                10,
                &pmtu_disc as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            );
        }
    }
}

#[cfg(not(any(target_os = "windows", target_os = "linux")))]
pub fn set_socket_dont_fragment(_socket: &UdpSocket, _is_ipv6: bool) {}

/// Calculate total exact header overhead for the active transport, mimicry profile, and payload mode.
/// Dynamically measures the exact framing length using the active crypto shaping engine.
/// IPv6: 40 bytes outer IPv6 + 8 bytes UDP + 20 bytes Mimicry + Shaping Prefix (0-2 bytes) = 68-70 bytes.
/// IPv4: 20 bytes outer IPv4 + 8 bytes UDP + 20 bytes Mimicry + Shaping Prefix (0-2 bytes) = 48-50 bytes.
pub fn calculate_transport_overhead(is_ipv6: bool, profile: MimicProfile, mode: PayloadMode) -> u32 {
    let outer_ip_hdr = if is_ipv6 { 40 } else { 20 };
    let outer_udp_hdr = 8;
    let mimicry_hdr = MIMICRY_HEADER_LEN as u32;

    // Dynamically measure exact shaping/masking overhead from crypto engine
    let mut dummy_out = [0u8; 16];
    let dummy_psk = [0u8; 8];
    let shaping_prefix = crate::core::crypto::apply_payload_shaping(
        &[],
        &mut dummy_out,
        &dummy_psk,
        0,
        mode,
        profile,
    ) as u32;

    outer_ip_hdr + outer_udp_hdr + mimicry_hdr + shaping_prefix
}

/// Calculate optimal zero-fragmentation TUNNEL_MTU.
/// With Tunnel-Level Micro-Segmentation, inner MTU is guaranteed at full standard 1500 bytes.
pub fn calculate_tunnel_mtu(_wire_pmtu: u32, _is_ipv6: bool, _profile: MimicProfile, _mode: PayloadMode) -> u32 {
    crate::common::TUNNEL_MTU
}

/// Query OS routing table / destination cache for cached Path MTU.
pub fn query_os_destination_cache(target_ip: &str, is_v6: bool) -> Option<u32> {
    #[cfg(target_os = "windows")]
    {
        let family = if is_v6 { "ipv6" } else { "ipv4" };
        let output = std::process::Command::new("netsh")
            .args(["interface", family, "show", "destinationcache"])
            .output()
            .ok()?;
        let text = String::from_utf8_lossy(&output.stdout);
        let clean_target = target_ip.trim_matches(|c| c == '[' || c == ']');
        for line in text.lines() {
            if line.contains(clean_target) {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    if let Ok(val) = parts[0].parse::<u32>() {
                        if (1280..=1500).contains(&val) {
                            return Some(val);
                        }
                    }
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    {
        let mut cmd = std::process::Command::new("ip");
        if is_v6 {
            cmd.arg("-6");
        }
        let output = cmd
            .args(["route", "get", target_ip])
            .output()
            .ok()?;
        let text = String::from_utf8_lossy(&output.stdout);
        if let Some(pos) = text.find("mtu ") {
            let after = &text[pos + 4..];
            if let Some(mtu_str) = after.split_whitespace().next() {
                if let Ok(val) = mtu_str.parse::<u32>() {
                    if (1280..=1500).contains(&val) {
                        return Some(val);
                    }
                }
            }
        }
    }

    let _ = target_ip;
    let _ = is_v6;
    None
}

/// One-Shot Connect-Time Path MTU Discovery.
/// Enforces DF=1, actively probes 1500B wire packet first, inspects kernel ICMP PTB feedback,
/// probes secondary APN ceiling, and returns discovered Wire PMTU and method.
pub fn discover_path_mtu(
    socket: &UdpSocket,
    server_addr: SocketAddr,
    profile: MimicProfile,
    mode: PayloadMode,
    psk: &[u8; 8],
) -> (u32, &'static str) {
    let is_v6 = server_addr.is_ipv6();
    let host_str = server_addr.ip().to_string();
    let ka_flags = FLAG_KEEPALIVE | mode.to_flags();

    // 0. Enforce DF=1 on probe socket cross-platform
    set_socket_dont_fragment(socket, is_v6);

    let outer_ip_hdr = if is_v6 { 40 } else { 20 };
    let outer_udp_hdr = 8;

    // 1. Active Probe Phase 1: 1500-byte wire datagram (Fiber / Ethernet full MTU) with DF=1
    let probe_1500_payload = 1500 - outer_ip_hdr - outer_udp_hdr;
    let mut probe_buf = vec![0u8; probe_1500_payload];
    for i in MIMICRY_HEADER_LEN..probe_1500_payload {
        probe_buf[i] = ((i * 37) & 0xFF) as u8;
    }
    profile.wrap_header(&mut probe_buf[..probe_1500_payload], ka_flags, 0xF150, psk);

    let _ = socket.set_read_timeout(Some(Duration::from_millis(250)));
    let send_1500_res = socket.send(&probe_buf);

    let mut rx_buf = [0u8; 512];
    let probe_1500_succeeded = match send_1500_res {
        Ok(_) => match socket.recv(&mut rx_buf) {
            Ok(n) if n >= MIMICRY_HEADER_LEN => {
                if let Some((flags, seq)) = profile.unwrap_header(&rx_buf[..n], psk) {
                    (flags & FLAG_FRAME_MASK) == FLAG_KEEPALIVE_ACK && seq == 0xF150
                } else {
                    false
                }
            }
            _ => false,
        },
        Err(_) => false, // WSAEMSGSIZE or local interface limit
    };

    if probe_1500_succeeded {
        let _ = socket.set_read_timeout(Some(Duration::from_millis(500)));
        return (1500, "Active 1500B Wire Probe (Full Wire Speed)");
    }

    // 2. The 1500B probe failed or was dropped.
    // Check if intermediate router sent ICMP Packet Too Big / Fragmentation Needed and kernel updated cache.
    std::thread::sleep(Duration::from_millis(60));
    if let Some(cached_pmtu) = query_os_destination_cache(&host_str, is_v6) {
        if cached_pmtu < 1500 {
            let _ = socket.set_read_timeout(Some(Duration::from_millis(500)));
            return (cached_pmtu, "Router ICMP Packet Too Big Feedback");
        }
    }

    // 3. Active Probe Phase 2: Probe at detected cache ceiling or 1400-byte wire datagram
    let target_probe_size = query_os_destination_cache(&host_str, is_v6)
        .filter(|&m| (1280..1500).contains(&m))
        .unwrap_or(1400);

    let probe_second_payload = (target_probe_size as usize).saturating_sub(outer_ip_hdr + outer_udp_hdr);
    let mut probe_second = vec![0u8; probe_second_payload];
    for i in MIMICRY_HEADER_LEN..probe_second_payload as usize {
        probe_second[i] = ((i * 53) & 0xFF) as u8;
    }
    profile.wrap_header(&mut probe_second[..probe_second_payload], ka_flags, 0xF140, psk);

    let _ = socket.set_read_timeout(Some(Duration::from_millis(250)));
    let send_second_res = socket.send(&probe_second);

    let probe_second_succeeded = match send_second_res {
        Ok(_) => match socket.recv(&mut rx_buf) {
            Ok(n) if n >= MIMICRY_HEADER_LEN => {
                if let Some((flags, seq)) = profile.unwrap_header(&rx_buf[..n], psk) {
                    (flags & FLAG_FRAME_MASK) == FLAG_KEEPALIVE_ACK && seq == 0xF140
                } else {
                    false
                }
            }
            _ => false,
        },
        Err(_) => false,
    };

    let _ = socket.set_read_timeout(Some(Duration::from_millis(500)));

    if probe_second_succeeded {
        return (target_probe_size, "Active Mobile Wire Probe (Cellular APN)");
    }

    // 4. Check cache again after probe
    if let Some(cached_pmtu) = query_os_destination_cache(&host_str, is_v6) {
        if cached_pmtu < 1500 {
            return (cached_pmtu, "Kernel Destination Cache (Post-Probe)");
        }
    }

    // 5. Safe baseline fallback (Anti-Black Hole)
    if is_v6 {
        (1400, "Safe Cellular IPv6 Baseline")
    } else {
        (1400, "Safe Cellular IPv4 Baseline")
    }
}
