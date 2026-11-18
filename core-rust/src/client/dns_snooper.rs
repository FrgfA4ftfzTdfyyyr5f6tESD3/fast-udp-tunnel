//! Ultra-Fast In-Memory DNS Engine, Zero-RTT Cache, Dynamic DNS Snooping Router,
//! and ICMP Packet-Too-Big (PTB) Feedback Generator for QUIC / HTTP/3.

use std::collections::{HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::sync::RwLock;
use std::time::{Duration, Instant};

#[derive(Clone)]
pub struct CachedDnsEntry {
    pub response_payload: Vec<u8>,
    pub expires_at: Instant,
    pub resolved_ips: Vec<IpAddr>,
}

pub struct DnsSnooper {
    wintun_if_index: u32,
    protected_server_ip: IpAddr,
    cache: RwLock<HashMap<(String, u16), CachedDnsEntry>>,
    routed_ips: RwLock<HashSet<IpAddr>>,
}

impl DnsSnooper {
    pub fn new(wintun_if_index: u32, protected_server_ip: IpAddr) -> Self {
        Self {
            wintun_if_index,
            protected_server_ip,
            cache: RwLock::new(HashMap::with_capacity(1024)),
            routed_ips: RwLock::new(HashSet::with_capacity(2048)),
        }
    }

    /// Check if domain is domestic Iranian (.ir)
    pub fn is_iranian_domain(domain: &str) -> bool {
        let d = domain.trim().trim_end_matches('.').to_ascii_lowercase();
        d.ends_with(".ir")
    }

    /// Check if an IPv4 address belongs to major Iranian domestic ASNs / CIDRs
    pub fn is_iranian_ip(ip: &IpAddr) -> bool {
        match ip {
            IpAddr::V4(v4) => {
                let o = v4.octets();
                // Major Iranian Domestic ISP Prefixes
                matches!(
                    (o[0], o[1]),
                    (2, 144..=147)
                        | (5, 56..=63)
                        | (31, 2..=3)
                        | (31, 24..=31)
                        | (37, 98..=99)
                        | (37, 110..=111)
                        | (37, 156..=159)
                        | (37, 254..=255)
                        | (78, 38..=39)
                        | (79, 127)
                        | (80, 191)
                        | (85, 185)
                        | (89, 144..=147)
                        | (91, 98..=99)
                        | (91, 108..=109)
                        | (94, 182..=183)
                        | (151, 232..=235)
                        | (178, 131)
                        | (185, 88..=89)
                        | (185, 143)
                        | (188, 136..=139)
                )
            }
            IpAddr::V6(_) => false,
        }
    }

    /// Parse DNS Query QNAME and QTYPE from raw DNS UDP payload
    pub fn parse_dns_query(dns_data: &[u8]) -> Option<(String, u16)> {
        if dns_data.len() < 12 {
            return None;
        }
        let qdcount = u16::from_be_bytes([dns_data[4], dns_data[5]]);
        if qdcount == 0 {
            return None;
        }

        let mut pos = 12;
        let mut domain_parts = Vec::new();
        while pos < dns_data.len() {
            let len = dns_data[pos] as usize;
            if len == 0 {
                pos += 1;
                break;
            }
            if pos + 1 + len > dns_data.len() {
                return None;
            }
            if let Ok(label) = std::str::from_utf8(&dns_data[pos + 1..pos + 1 + len]) {
                domain_parts.push(label.to_ascii_lowercase());
            }
            pos += 1 + len;
        }

        if pos + 4 > dns_data.len() {
            return None;
        }
        let qtype = u16::from_be_bytes([dns_data[pos], dns_data[pos + 1]]);
        let domain = domain_parts.join(".");
        Some((domain, qtype))
    }

    /// Lookup cache for instantaneous zero-latency reply (< 0.1 ms)
    pub fn lookup_cache(&self, domain: &str, qtype: u16, query_id: u16) -> Option<Vec<u8>> {
        let now = Instant::now();
        let cache = self.cache.read().ok()?;
        let entry = cache.get(&(domain.to_ascii_lowercase(), qtype))?;
        if now < entry.expires_at {
            let mut payload = entry.response_payload.clone();
            if payload.len() >= 2 {
                payload[0..2].copy_from_slice(&query_id.to_be_bytes());
            }
            Some(payload)
        } else {
            None
        }
    }

    /// Parse DNS Response, extract resolved A / AAAA addresses, record into cache,
    /// and dynamically inject host routes into Wintun forwarding table.
    pub fn process_dns_response(&self, dns_data: &[u8]) {
        if dns_data.len() < 12 {
            return;
        }
        let qr = (dns_data[2] & 0x80) != 0;
        if !qr {
            return; // Not a response
        }
        let qdcount = u16::from_be_bytes([dns_data[4], dns_data[5]]) as usize;
        let ancount = u16::from_be_bytes([dns_data[6], dns_data[7]]) as usize;
        if ancount == 0 {
            return;
        }

        // Parse Question
        let mut pos = 12;
        let mut domain_parts = Vec::new();
        let mut qtype_found: u16 = 1;
        for _ in 0..qdcount {
            while pos < dns_data.len() {
                let len = dns_data[pos] as usize;
                if len == 0 {
                    pos += 1;
                    break;
                }
                if (len & 0xC0) == 0xC0 {
                    pos += 2;
                    break;
                }
                if pos + 1 + len > dns_data.len() {
                    return;
                }
                if let Ok(label) = std::str::from_utf8(&dns_data[pos + 1..pos + 1 + len]) {
                    domain_parts.push(label.to_ascii_lowercase());
                }
                pos += 1 + len;
            }
            if pos + 2 <= dns_data.len() {
                qtype_found = u16::from_be_bytes([dns_data[pos], dns_data[pos + 1]]);
            }
            pos += 4; // QTYPE + QCLASS
        }
        let domain = domain_parts.join(".");

        let mut resolved_ips = Vec::new();
        let mut min_ttl: u32 = 300;

        // Parse Answers
        for _ in 0..ancount {
            if pos >= dns_data.len() {
                break;
            }
            // Skip NAME (may be compressed pointer)
            if (dns_data[pos] & 0xC0) == 0xC0 {
                pos += 2;
            } else {
                while pos < dns_data.len() && dns_data[pos] != 0 {
                    pos += 1 + dns_data[pos] as usize;
                }
                pos += 1;
            }

            if pos + 10 > dns_data.len() {
                break;
            }
            let rtype = u16::from_be_bytes([dns_data[pos], dns_data[pos + 1]]);
            let ttl = u32::from_be_bytes([
                dns_data[pos + 4],
                dns_data[pos + 5],
                dns_data[pos + 6],
                dns_data[pos + 7],
            ]);
            let rdlength = u16::from_be_bytes([dns_data[pos + 8], dns_data[pos + 9]]) as usize;
            pos += 10;

            if pos + rdlength > dns_data.len() {
                break;
            }

            if ttl > 0 && ttl < min_ttl {
                min_ttl = ttl;
            }

            if rtype == 1 && rdlength == 4 {
                // Type A (IPv4)
                let ip = Ipv4Addr::new(
                    dns_data[pos],
                    dns_data[pos + 1],
                    dns_data[pos + 2],
                    dns_data[pos + 3],
                );
                resolved_ips.push(IpAddr::V4(ip));
            } else if rtype == 28 && rdlength == 16 {
                // Type AAAA (IPv6)
                let mut v6_octets = [0u8; 16];
                v6_octets.copy_from_slice(&dns_data[pos..pos + 16]);
                resolved_ips.push(IpAddr::V6(Ipv6Addr::from(v6_octets)));
            }

            pos += rdlength;
        }

        min_ttl = min_ttl.clamp(60, 3600);

        // DNS Snooper: Dynamically route resolved IPs to Wintun
        if !Self::is_iranian_domain(&domain) {
            for ip in &resolved_ips {
                if ip.is_loopback() || ip.is_unspecified() || ip.is_multicast() || *ip == self.protected_server_ip {
                    continue;
                }
                if Self::is_iranian_ip(ip) {
                    continue;
                }

                // Check if already dynamically routed
                let mut routed = match self.routed_ips.write() {
                    Ok(r) => r,
                    Err(_) => continue,
                };

                if routed.insert(*ip) {
                    Self::inject_host_route(self.wintun_if_index, *ip);
                }
            }
        }

        // Cache the response
        if !domain.is_empty() {
            if let Ok(mut cache) = self.cache.write() {
                cache.insert(
                    (domain, qtype_found),
                    CachedDnsEntry {
                        response_payload: dns_data.to_vec(),
                        expires_at: Instant::now() + Duration::from_secs(min_ttl as u64),
                        resolved_ips,
                    },
                );
            }
        }
    }

    /// Fast host route injection directly into Windows kernel FIB (< 0.05ms)
    fn inject_host_route(if_index: u32, ip: IpAddr) {
        use windows_sys::Win32::Foundation::{ERROR_OBJECT_ALREADY_EXISTS, NO_ERROR};
        use windows_sys::Win32::NetworkManagement::IpHelper::{
            CreateIpForwardEntry2, InitializeIpForwardEntry, MIB_IPFORWARD_ROW2,
        };
        use windows_sys::Win32::Networking::WinSock::{AF_INET, AF_INET6, SOCKADDR_INET};

        let mut row: MIB_IPFORWARD_ROW2 = unsafe { std::mem::zeroed() };
        unsafe { InitializeIpForwardEntry(&mut row) };
        row.InterfaceIndex = if_index;
        row.Metric = 1;

        let mut sa: SOCKADDR_INET = unsafe { std::mem::zeroed() };
        let mut nh: SOCKADDR_INET = unsafe { std::mem::zeroed() };

        match ip {
            IpAddr::V4(v4) => {
                row.DestinationPrefix.PrefixLength = 32;
                sa.Ipv4.sin_family = AF_INET;
                sa.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(v4.octets());
                row.DestinationPrefix.Prefix = sa;

                nh.Ipv4.sin_family = AF_INET;
                nh.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes([10, 8, 0, 1]);
                row.NextHop = nh;
            }
            IpAddr::V6(v6) => {
                row.DestinationPrefix.PrefixLength = 128;
                sa.Ipv6.sin6_family = AF_INET6;
                sa.Ipv6.sin6_addr.u.Byte = v6.octets();
                row.DestinationPrefix.Prefix = sa;

                nh.Ipv6.sin6_family = AF_INET6;
                let mut gw = [0u8; 16];
                gw[0] = 0xFD; gw[1] = 0x00; gw[2] = 0x08; gw[15] = 0x01;
                nh.Ipv6.sin6_addr.u.Byte = gw;
                row.NextHop = nh;
            }
        }

        let code = unsafe { CreateIpForwardEntry2(&row) };
        if code != NO_ERROR && code != ERROR_OBJECT_ALREADY_EXISTS {
            // Transparent fallback to route.exe
            match ip {
                IpAddr::V4(v4) => {
                    let _ = std::process::Command::new("route")
                        .args(["add", &v4.to_string(), "mask", "255.255.255.255", "10.8.0.1", "metric", "1", "if", &if_index.to_string()])
                        .output();
                }
                IpAddr::V6(v6) => {
                    let _ = std::process::Command::new("netsh")
                        .args(["interface", "ipv6", "add", "route", &format!("{}/128", v6), &format!("interface={}", if_index), "nexthop=fd00:8::1", "metric=1", "store=active"])
                        .output();
                }
            }
        }
    }

    /// Restore and purge all dynamic routes on exit
    pub fn clean_all_dynamic_routes(&self) {
        if let Ok(routed) = self.routed_ips.read() {
            for ip in routed.iter() {
                match ip {
                    IpAddr::V4(v4) => {
                        let _ = std::process::Command::new("route")
                            .args(["delete", &v4.to_string()])
                            .output();
                    }
                    IpAddr::V6(v6) => {
                        let _ = std::process::Command::new("netsh")
                            .args(["interface", "ipv6", "delete", "route", &format!("{}/128", v6), &format!("interface={}", self.wintun_if_index)])
                            .output();
                    }
                }
            }
        }
    }
}

/// Check if packet is an outbound DNS query to port 53
#[inline(always)]
pub fn is_dns_query(packet: &[u8]) -> bool {
    if packet.is_empty() {
        return false;
    }
    let ver = packet[0] >> 4;
    if ver == 4 {
        if packet.len() < 28 || packet[9] != 17 {
            return false;
        }
        let dst_port = u16::from_be_bytes([packet[22], packet[23]]);
        dst_port == 53
    } else if ver == 6 {
        if packet.len() < 48 || packet[6] != 17 {
            return false;
        }
        let dst_port = u16::from_be_bytes([packet[42], packet[43]]);
        dst_port == 53
    } else {
        false
    }
}

/// Check if packet is an inbound DNS response from port 53
#[inline(always)]
pub fn is_dns_response(packet: &[u8]) -> bool {
    if packet.is_empty() {
        return false;
    }
    let ver = packet[0] >> 4;
    if ver == 4 {
        if packet.len() < 28 || packet[9] != 17 {
            return false;
        }
        let src_port = u16::from_be_bytes([packet[20], packet[21]]);
        src_port == 53
    } else if ver == 6 {
        if packet.len() < 48 || packet[6] != 17 {
            return false;
        }
        let src_port = u16::from_be_bytes([packet[40], packet[41]]);
        src_port == 53
    } else {
        false
    }
}

/// Extract DNS payload from UDP packet
#[inline(always)]
pub fn extract_dns_payload(packet: &[u8]) -> Option<&[u8]> {
    let ver = packet[0] >> 4;
    if ver == 4 && packet.len() >= 28 {
        Some(&packet[28..])
    } else if ver == 6 && packet.len() >= 48 {
        Some(&packet[48..])
    } else {
        None
    }
}

/// Synthesize a raw IP/UDP DNS response packet from cached DNS payload
pub fn synthesize_dns_ip_packet(query_packet: &[u8], dns_payload: &[u8]) -> Option<Vec<u8>> {
    let ver = query_packet[0] >> 4;
    if ver == 4 {
        if query_packet.len() < 28 {
            return None;
        }
        let orig_src_ip = &query_packet[12..16];
        let orig_dst_ip = &query_packet[16..20];
        let orig_src_port = &query_packet[20..22];

        let udp_len = 8 + dns_payload.len();
        let total_len = 20 + udp_len;
        let mut pkt = vec![0u8; total_len];

        // IPv4 Header
        pkt[0] = 0x45;
        pkt[1] = 0x00;
        pkt[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        pkt[4..6].copy_from_slice(&0x3456u16.to_be_bytes());
        pkt[6..8].copy_from_slice(&0x4000u16.to_be_bytes());
        pkt[8] = 64;
        pkt[9] = 17; // UDP
        pkt[12..16].copy_from_slice(orig_dst_ip); // Src = 10.8.0.1
        pkt[16..20].copy_from_slice(orig_src_ip); // Dst = client
        let ip_cksum = internet_checksum(&pkt[..20]);
        pkt[10..12].copy_from_slice(&ip_cksum.to_be_bytes());

        // UDP Header
        pkt[20..22].copy_from_slice(&53u16.to_be_bytes()); // Src Port = 53
        pkt[22..24].copy_from_slice(orig_src_port);         // Dst Port = client port
        pkt[24..26].copy_from_slice(&(udp_len as u16).to_be_bytes());
        pkt[26..28].copy_from_slice(&[0, 0]); // UDP checksum optional in IPv4

        // DNS Payload
        pkt[28..28 + dns_payload.len()].copy_from_slice(dns_payload);

        Some(pkt)
    } else if ver == 6 {
        if query_packet.len() < 48 {
            return None;
        }
        let orig_src_ip = &query_packet[8..24];
        let orig_dst_ip = &query_packet[24..40];
        let orig_src_port = &query_packet[40..42];

        let udp_len = 8 + dns_payload.len();
        let total_len = 40 + udp_len;
        let mut pkt = vec![0u8; total_len];

        // IPv6 Header
        pkt[0] = 0x60;
        pkt[4..6].copy_from_slice(&(udp_len as u16).to_be_bytes());
        pkt[6] = 17; // UDP
        pkt[7] = 64;
        pkt[8..24].copy_from_slice(orig_dst_ip); // Src = fd00:8:0::1
        pkt[24..40].copy_from_slice(orig_src_ip); // Dst = client

        // UDP Header
        pkt[40..42].copy_from_slice(&53u16.to_be_bytes()); // Src Port = 53
        pkt[42..44].copy_from_slice(orig_src_port);         // Dst Port = client port
        pkt[44..46].copy_from_slice(&(udp_len as u16).to_be_bytes());
        pkt[46..48].copy_from_slice(&[0, 0]); // UDP checksum placeholder

        // DNS Payload
        pkt[48..48 + dns_payload.len()].copy_from_slice(dns_payload);

        // Calculate IPv6 UDP Checksum over pseudo-header
        let mut pseudo = Vec::with_capacity(40 + udp_len);
        pseudo.extend_from_slice(&pkt[8..24]);  // Src
        pseudo.extend_from_slice(&pkt[24..40]); // Dst
        pseudo.extend_from_slice(&(udp_len as u32).to_be_bytes());
        pseudo.extend_from_slice(&[0, 0, 0, 17]); // Next Header 17
        pseudo.extend_from_slice(&pkt[40..]);

        let udp_cksum = internet_checksum(&pseudo);
        let final_cksum = if udp_cksum == 0 { 0xFFFF } else { udp_cksum };
        pkt[46..48].copy_from_slice(&final_cksum.to_be_bytes());

        Some(pkt)
    } else {
        None
    }
}

/// Calculate standard 1's complement Internet Checksum
pub fn internet_checksum(data: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    let mut i = 0;
    while i + 1 < data.len() {
        let word = u16::from_be_bytes([data[i], data[i + 1]]);
        sum += word as u32;
        i += 2;
    }
    if i < data.len() {
        sum += (data[i] as u32) << 8;
    }
    while (sum >> 16) > 0 {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// Generate an instant ICMPv4/ICMPv6 "Packet Too Big" response packet
/// back to Windows so Chrome / Edge instantly scales down QUIC datagrams
/// instead of dropping packets and stalling for 3 seconds.
pub fn generate_icmp_packet_too_big(original_packet: &[u8], next_hop_mtu: u16) -> Option<Vec<u8>> {
    if original_packet.is_empty() {
        return None;
    }
    let ver = original_packet[0] >> 4;
    if ver == 4 {
        if original_packet.len() < 20 {
            return None;
        }
        let orig_src = &original_packet[12..16];

        // IPv4 Header (20 bytes) + ICMP Header (8 bytes) + Original IPv4 Header (20 bytes) + 8 bytes payload
        let payload_len = 20 + 8.min(original_packet.len().saturating_sub(20));
        let total_len = 20 + 8 + payload_len;
        let mut pkt = vec![0u8; total_len];

        // IPv4 Header
        pkt[0] = 0x45; // Version 4, IHL 5
        pkt[1] = 0x00; // DSCP / ECN
        pkt[2..4].copy_from_slice(&(total_len as u16).to_be_bytes());
        pkt[4..6].copy_from_slice(&0x1234u16.to_be_bytes()); // ID
        pkt[6..8].copy_from_slice(&0x4000u16.to_be_bytes()); // Flags (DF)
        pkt[8] = 64; // TTL
        pkt[9] = 1;  // Protocol: ICMP (1)
        pkt[12..16].copy_from_slice(&[10, 8, 0, 1]); // Source IP: Tunnel Gateway
        pkt[16..20].copy_from_slice(orig_src);       // Dest IP: Original Sender

        let ip_cksum = internet_checksum(&pkt[..20]);
        pkt[10..12].copy_from_slice(&ip_cksum.to_be_bytes());

        // ICMPv4 Header: Type 3 (Destination Unreachable), Code 4 (Fragmentation Needed and DF set)
        pkt[20] = 3; // Type
        pkt[21] = 4; // Code
        pkt[22..24].copy_from_slice(&[0, 0]); // Checksum placeholder
        pkt[24..26].copy_from_slice(&[0, 0]); // Unused
        pkt[26..28].copy_from_slice(&next_hop_mtu.to_be_bytes()); // Next-Hop MTU!

        // Copy Original IP header + 8 bytes of original datagram
        pkt[28..28 + payload_len].copy_from_slice(&original_packet[..payload_len]);

        let icmp_cksum = internet_checksum(&pkt[20..]);
        pkt[22..24].copy_from_slice(&icmp_cksum.to_be_bytes());

        Some(pkt)
    } else if ver == 6 {
        if original_packet.len() < 40 {
            return None;
        }
        let orig_src = &original_packet[8..24];

        // IPv6 Header (40 bytes) + ICMPv6 Header (8 bytes) + Original payload (up to 1232 bytes)
        let payload_len = original_packet.len().min(1232);
        let icmp_len = 8 + payload_len;
        let total_len = 40 + icmp_len;
        let mut pkt = vec![0u8; total_len];

        // IPv6 Header
        pkt[0] = 0x60; // Version 6
        pkt[4..6].copy_from_slice(&(icmp_len as u16).to_be_bytes()); // Payload Length
        pkt[6] = 58; // Next Header: ICMPv6
        pkt[7] = 64; // Hop Limit
        // Source: fd00:8:0::1
        pkt[8] = 0xFD; pkt[9] = 0x00; pkt[10] = 0x08; pkt[23] = 0x01;
        // Dest: Original Sender
        pkt[24..40].copy_from_slice(orig_src);

        // ICMPv6 Header: Type 2 (Packet Too Big), Code 0
        pkt[40] = 2; // Type
        pkt[41] = 0; // Code
        pkt[42..44].copy_from_slice(&[0, 0]); // Checksum placeholder
        pkt[44..48].copy_from_slice(&(next_hop_mtu as u32).to_be_bytes()); // Next-Hop MTU!

        // Copy original packet
        pkt[48..48 + payload_len].copy_from_slice(&original_packet[..payload_len]);

        // ICMPv6 Pseudo-Header Checksum
        let mut pseudo = Vec::with_capacity(40 + icmp_len);
        pseudo.extend_from_slice(&pkt[8..24]);  // Src
        pseudo.extend_from_slice(&pkt[24..40]); // Dst
        pseudo.extend_from_slice(&(icmp_len as u32).to_be_bytes());
        pseudo.extend_from_slice(&[0, 0, 0, 58]); // Next Header 58
        pseudo.extend_from_slice(&pkt[40..]);

        let icmp6_cksum = internet_checksum(&pseudo);
        pkt[42..44].copy_from_slice(&icmp6_cksum.to_be_bytes());

        Some(pkt)
    } else {
        None
    }
}
