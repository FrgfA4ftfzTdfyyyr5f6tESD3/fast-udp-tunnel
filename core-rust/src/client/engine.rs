//! Client full-duplex forwarding engine with multi-profile mimicry, payload shaping,
//! and anti-NAT keepalive.

use std::error::Error;
use std::io::{self, Write};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use crate::common::{
    KEEPALIVE_JITTER_MAX_MS, KEEPALIVE_JITTER_MIN_MS, KEEPALIVE_PADDING_MAX_BYTES,
    KEEPALIVE_PADDING_MIN_BYTES,
};
use crate::core::crypto::{apply_payload_shaping, strip_payload_shaping, PayloadMode};
use crate::core::metrics::{format_size, MetricTracker};
use crate::core::build_icmp_probe_packet;
use crate::mimic::{
    FLAG_DATA, FLAG_FRAG_1, FLAG_FRAG_2, FLAG_FRAME_MASK, FLAG_KEEPALIVE, FLAG_KEEPALIVE_ACK, MIMICRY_HEADER_LEN, MimicProfile,
};
use crate::client::routing::{clean_stale_routes_and_nrpt, TunnelRoutes};
use crate::client::socket::create_connected_socket;
use crate::client::wintun::{allocate_packet_resilient, initialize_wintun};

pub fn run_engine(
    server_endpoint: &str,
    profile: MimicProfile,
    mode: PayloadMode,
    psk: [u8; 8],
    assigned_v4: Option<&str>,
    assigned_v6: Option<&str>,
) -> Result<(), Box<dyn Error>> {
    let telem = crate::core::metrics::TunnelTelemetry::global();
    if telem.shutdown_requested.load(Ordering::Acquire) {
        return Ok(());
    }

    println!("[CLIENT] Running proactive self-healing cleanup of stale routes and NRPT policies...");
    clean_stale_routes_and_nrpt();

    if telem.shutdown_requested.load(Ordering::Acquire) {
        return Ok(());
    }

    let server_addr: SocketAddr = server_endpoint.parse()?;
    let server_host = server_addr.ip().to_string();

    let (phys_v4, phys_v6) = TunnelRoutes::detect_physical_gateways();

    // 1. Create Connected UDP Socket locked in Windows Kernel
    let socket = create_connected_socket(server_addr)?;
    let _ = socket.set_read_timeout(Some(Duration::from_millis(100)));
    println!(
        "[CLIENT] Connected UDP socket LOCKED in Windows Kernel to {} (Local: {})",
        server_addr,
        socket.local_addr()?
    );

    // 1b. Connect-Time Dynamic PMTU Discovery & Zero-Fragmentation Adaptation
    println!("[CLIENT] Running Connect-Time Path MTU Discovery (RFC 1981 / RFC 1191)...");
    let (wire_pmtu, discovery_method) = crate::common::discover_path_mtu(&socket, server_addr, profile, mode, &psk);
    if telem.shutdown_requested.load(Ordering::Acquire) {
        return Ok(());
    }
    let negotiated_mtu = crate::common::calculate_tunnel_mtu(wire_pmtu, server_addr.is_ipv6(), profile, mode);
    let overhead = crate::common::calculate_transport_overhead(server_addr.is_ipv6(), profile, mode);

    println!("------------------------------------------------------------------");
    println!("  DYNAMIC PMTU DISCOVERY & ZERO-FRAGMENTATION ADAPTATION");
    println!("  -> Wire Path MTU (Discovered) : {} bytes [{}]", wire_pmtu, discovery_method);
    println!("  -> Protocol & Framing Overhead: {} bytes ({} + UDP + Mimicry + Shaping)", overhead, if server_addr.is_ipv6() { "IPv6" } else { "IPv4" });
    println!("  -> Negotiated Inner Tunnel MTU: {} bytes (Zero Fragmentation Guaranteed)", negotiated_mtu);
    println!("------------------------------------------------------------------");

    // 2. Load Wintun Driver & Establish Ring Buffer Session
    if !crate::client::is_elevated() {
        eprintln!("\n==================================================================");
        eprintln!("  [ERROR] ADMINISTRATOR PRIVILEGES REQUIRED");
        eprintln!("==================================================================");
        eprintln!("  Morph Core requires Windows Administrator privileges to initialize");
        eprintln!("  the Wintun virtual network adapter and manage routing tables.");
        eprintln!();
        eprintln!("  Please right-click the application or your command prompt");
        eprintln!("  and select 'Run as administrator'.");
        eprintln!("==================================================================\n");
        return Err("Administrator privileges required to create Wintun adapter".into());
    }

    println!("[CLIENT] Loading Wintun driver and opening adapter...");
    let wintun = unsafe { wintun::load()? };
    let (adapter, session, if_index) = initialize_wintun(&wintun, negotiated_mtu, assigned_v4, assigned_v6)?;
    if telem.shutdown_requested.load(Ordering::Acquire) {
        return Ok(());
    }

    println!("[CLIENT] Wintun Adapter 'FastUDPTunnel' active on IF #{}", if_index);
    println!(
        "[CLIENT] Wintun Ring Buffer Session established! (Inner MTU: {} | Discovered Wire PMTU: {})",
        negotiated_mtu, wire_pmtu
    );

    let routes = TunnelRoutes::new(if_index, server_host, phys_v6, phys_v4);
    routes.apply();

    telem.set_status(crate::core::metrics::TunnelStatus::Connected);
    telem.pmtu.store(negotiated_mtu as u16, Ordering::Relaxed);

    println!("[CLIENT] Policy-Based Selective Split Tunneling Active: Clean Remote IPv6 & Global Services");
    println!("[CLIENT] Default internet (0.0.0.0/0 & ::/0) preserved on physical gateway (Zero Bottleneck)");
    println!("[CLIENT] In-Tunnel Kernel DNS Active: fd00:8:0::1 & 10.8.0.1 (Zero Proxy, RFC 6724 Elevated)");
    println!("[CLIENT] Camouflage Protocol: {} [Port: {}]", profile.display_name(), server_addr.port());
    println!("[CLIENT] Payload Protection: {}", mode.display_name());
    println!("[CLIENT] Anti-Hijack PSK Token: [{:02X}{:02X}...{:02X}{:02X}]", psk[0], psk[1], psk[6], psk[7]);

    let running = Arc::new(AtomicBool::new(true));
    let metrics = Arc::new(MetricTracker::new());
    let seq_counter = Arc::new(AtomicU32::new(1));
    let last_tx_epoch = Arc::new(AtomicU64::new(0));
    let tunnel_start = Instant::now();

    // Parse assigned source IPv4 for encapsulated in-band probe packets
    let src_v4_bytes: [u8; 4] = assigned_v4
        .and_then(|s| s.parse::<std::net::Ipv4Addr>().ok())
        .map(|ip| ip.octets())
        .unwrap_or([10, 8, 0, 2]);

    // Send initial handshake Keepalive packet carrying negotiated dynamic MTU & payload mode
    let mut init_wire = [0u8; MIMICRY_HEADER_LEN + 4];
    let init_seq = (seq_counter.fetch_add(1, Ordering::Relaxed) & 0xFFFF) as u16;
    let init_flags = FLAG_KEEPALIVE | mode.to_flags();
    init_wire[MIMICRY_HEADER_LEN..MIMICRY_HEADER_LEN + 2].copy_from_slice(&crate::common::MTU_HANDSHAKE_MAGIC);
    init_wire[MIMICRY_HEADER_LEN + 2..MIMICRY_HEADER_LEN + 4].copy_from_slice(&(negotiated_mtu as u16).to_be_bytes());
    profile.wrap_header(&mut init_wire, init_flags, init_seq, &psk);
    let _ = socket.send(&init_wire);

#[inline(always)]
fn is_routable_unicast(packet: &[u8]) -> bool {
    if packet.is_empty() {
        return false;
    }
    let ver = packet[0] >> 4;
    if ver == 4 {
        if packet.len() < 20 {
            return false;
        }
        let d = &packet[16..20];
        // Drop limited broadcast (255.255.255.255)
        if d == [255, 255, 255, 255] {
            return false;
        }
        // Drop subnet broadcast (10.8.0.255)
        if d[0] == 10 && d[1] == 8 && d[2] == 0 && d[3] == 255 {
            return false;
        }
        // Drop IPv4 multicast (224.0.0.0/4 -> 224..=239)
        if d[0] >= 224 && d[0] <= 239 {
            return false;
        }
        // Drop 0.0.0.0
        if d == [0, 0, 0, 0] {
            return false;
        }
        true
    } else if ver == 6 {
        if packet.len() < 40 {
            return false;
        }
        // Drop IPv6 multicast (ff00::/8)
        if packet[24] == 0xFF {
            return false;
        }
        // Drop unspecified (::)
        if packet[24..40].iter().all(|&b| b == 0) {
            return false;
        }
        true
    } else {
        false
    }
}

    // Thread 1: Wintun (Kernel IP Packets) -> Payload Shaping -> Mimicry Header -> Connected UDP Socket
    let dns_snooper = Arc::new(crate::client::dns_snooper::DnsSnooper::new(if_index, server_addr.ip()));
    let dns_snooper_w2u = Arc::clone(&dns_snooper);
    let dns_snooper_u2w = Arc::clone(&dns_snooper);

    let session_w2u = Arc::clone(&session);
    let socket_w2u = socket.try_clone()?;
    let running_w2u = Arc::clone(&running);
    let metrics_w2u = Arc::clone(&metrics);
    let seq_w2u = Arc::clone(&seq_counter);
    let last_tx_w2u = Arc::clone(&last_tx_epoch);
    let tunnel_start_w2u = tunnel_start;

    let _mtu_w2u = negotiated_mtu as usize;
    let handle_w2u = thread::Builder::new()
        .name("wintun_to_udp".into())
        .spawn(move || {
            let mut wire_buf = [0u8; 2048];

            macro_rules! transmit_ip {
                ($pkt:expr) => {
                    let pkt_slice = $pkt;
                    if crate::common::should_fragment(pkt_slice.len()) {
                        let seq = (seq_w2u.fetch_add(1, Ordering::Relaxed) & 0xFFFF) as u16;
                        let (frag1, frag2) = crate::common::split_packet(pkt_slice);

                        // Frag 1
                        let payload_out1 = &mut wire_buf[MIMICRY_HEADER_LEN..];
                        let shaped_len1 = apply_payload_shaping(frag1, payload_out1, &psk, seq, mode, profile);
                        let wire_len1 = MIMICRY_HEADER_LEN + shaped_len1;
                        let flags1 = FLAG_FRAG_1 | mode.to_flags();
                        profile.wrap_header(&mut wire_buf[..wire_len1], flags1, seq, &psk);
                        let _ = socket_w2u.send(&wire_buf[..wire_len1]);

                        // Frag 2
                        let payload_out2 = &mut wire_buf[MIMICRY_HEADER_LEN..];
                        let shaped_len2 = apply_payload_shaping(frag2, payload_out2, &psk, seq, mode, profile);
                        let wire_len2 = MIMICRY_HEADER_LEN + shaped_len2;
                        let flags2 = FLAG_FRAG_2 | mode.to_flags();
                        profile.wrap_header(&mut wire_buf[..wire_len2], flags2, seq, &psk);
                        let _ = socket_w2u.send(&wire_buf[..wire_len2]);

                        metrics_w2u.total_tx_bytes.fetch_add((wire_len1 + wire_len2) as u64, Ordering::Relaxed);
                        last_tx_w2u.store(tunnel_start_w2u.elapsed().as_millis() as u64, Ordering::Relaxed);
                    } else {
                        let seq = (seq_w2u.fetch_add(1, Ordering::Relaxed) & 0xFFFF) as u16;
                        let payload_out = &mut wire_buf[MIMICRY_HEADER_LEN..];
                        let shaped_len = apply_payload_shaping(pkt_slice, payload_out, &psk, seq, mode, profile);
                        let total_wire_len = MIMICRY_HEADER_LEN + shaped_len;

                        let full_flags = FLAG_DATA | mode.to_flags();
                        profile.wrap_header(&mut wire_buf[..total_wire_len], full_flags, seq, &psk);

                        if socket_w2u.send(&wire_buf[..total_wire_len]).is_ok() {
                            metrics_w2u.total_tx_bytes.fetch_add(total_wire_len as u64, Ordering::Relaxed);
                            last_tx_w2u.store(tunnel_start_w2u.elapsed().as_millis() as u64, Ordering::Relaxed);
                        }
                    }
                };
            }

            while running_w2u.load(Ordering::Relaxed) && !crate::core::metrics::TunnelTelemetry::global().shutdown_requested.load(Ordering::Relaxed) {
                match session_w2u.receive_blocking() {
                    Ok(packet) => {
                        let bytes = packet.bytes();
                        let len = bytes.len();

                        if len > 0 && is_routable_unicast(bytes) {
                            // Zero-RTT In-Memory DNS Cache Intercept (< 0.1 ms)
                            let mut handled_by_cache = false;
                            if crate::client::dns_snooper::is_dns_query(bytes) {
                                if let Some(dns_payload) = crate::client::dns_snooper::extract_dns_payload(bytes) {
                                    if let Some((domain, qtype)) = crate::client::dns_snooper::DnsSnooper::parse_dns_query(dns_payload) {
                                        let query_id = u16::from_be_bytes([dns_payload[0], dns_payload[1]]);
                                        if let Some(cached_resp) = dns_snooper_w2u.lookup_cache(&domain, qtype, query_id) {
                                            if let Some(resp_ip_pkt) = crate::client::dns_snooper::synthesize_dns_ip_packet(bytes, &cached_resp) {
                                                if let Ok(mut send_packet) = allocate_packet_resilient(&session_w2u, resp_ip_pkt.len() as u16) {
                                                    send_packet.bytes_mut().copy_from_slice(&resp_ip_pkt);
                                                    session_w2u.send_packet(send_packet);
                                                    handled_by_cache = true;
                                                }
                                            }
                                        }
                                    }
                                }
                            }

                            if !handled_by_cache {
                                transmit_ip!(bytes);
                            }
                        }

                        // Batch drain backlogged packets without context-switch sleeping
                        while let Ok(Some(pkt)) = session_w2u.try_receive() {
                            let b = pkt.bytes();
                            let l = b.len();

                            if l > 0 && is_routable_unicast(b) {
                                let mut handled_by_cache = false;
                                if crate::client::dns_snooper::is_dns_query(b) {
                                    if let Some(dns_payload) = crate::client::dns_snooper::extract_dns_payload(b) {
                                        if let Some((domain, qtype)) = crate::client::dns_snooper::DnsSnooper::parse_dns_query(dns_payload) {
                                            let query_id = u16::from_be_bytes([dns_payload[0], dns_payload[1]]);
                                            if let Some(cached_resp) = dns_snooper_w2u.lookup_cache(&domain, qtype, query_id) {
                                                if let Some(resp_ip_pkt) = crate::client::dns_snooper::synthesize_dns_ip_packet(b, &cached_resp) {
                                                    if let Ok(mut send_packet) = allocate_packet_resilient(&session_w2u, resp_ip_pkt.len() as u16) {
                                                        send_packet.bytes_mut().copy_from_slice(&resp_ip_pkt);
                                                        session_w2u.send_packet(send_packet);
                                                        handled_by_cache = true;
                                                    }
                                                }
                                            }
                                        }
                                    }
                                }

                                if !handled_by_cache {
                                    transmit_ip!(b);
                                }
                            }
                        }
                    }
                    Err(_) => {
                        if !running_w2u.load(Ordering::Relaxed) {
                            break;
                        }
                    }
                }
            }
        })?;

    // Thread 2: Connected UDP Socket -> Decapsulation, Un-shaping & Wintun Delivery
    let session_u2w = Arc::clone(&session);
    let socket_u2w = socket.try_clone()?;
    let running_u2w = Arc::clone(&running);
    let metrics_u2w = Arc::clone(&metrics);

    let handle_u2w = thread::Builder::new()
        .name("udp_to_wintun".into())
        .spawn(move || {
            let mut buf = [0u8; 65536];
            let mut reasm = crate::common::ReassemblyBuffer::new();
            let mut reasm_out = [0u8; 2048];

            while running_u2w.load(Ordering::Relaxed) && !crate::core::metrics::TunnelTelemetry::global().shutdown_requested.load(Ordering::Relaxed) {
                match socket_u2w.recv(&mut buf) {
                    Ok(n) if n >= MIMICRY_HEADER_LEN => {
                        metrics_u2w.total_rx_bytes.fetch_add(n as u64, Ordering::Relaxed);

                        // Validate Mimicry Header & PSK Auth Token
                        if let Some((flags, seq)) = profile.unwrap_header(&buf[..n], &psk) {
                            let frame_type = flags & FLAG_FRAME_MASK;
                            if frame_type == FLAG_KEEPALIVE_ACK {
                                continue;
                            }
                            let incoming_mode = PayloadMode::from_flags(flags);
                            let payload_data = &mut buf[MIMICRY_HEADER_LEN..n];

                            if frame_type == FLAG_DATA {
                                if let Some(raw_len) = strip_payload_shaping(payload_data, &psk, seq, incoming_mode, profile) {
                                    let ip_pkt = &payload_data[..raw_len];
                                    if ip_pkt.is_empty() {
                                        continue;
                                    }

                                    // Demux in-band ICMP probe reply
                                    if metrics_u2w.handle_possible_probe_reply(ip_pkt) {
                                        continue;
                                    }

                                    // DNS Snooper: Inspect DNS responses, dynamically inject routes for resolved IPs, and cache
                                    if crate::client::dns_snooper::is_dns_response(ip_pkt) {
                                        if let Some(dns_payload) = crate::client::dns_snooper::extract_dns_payload(ip_pkt) {
                                            dns_snooper_u2w.process_dns_response(dns_payload);
                                        }
                                    }

                                    // Deliver clean IP packet to Windows Wintun
                                    if let Ok(mut send_packet) = allocate_packet_resilient(&session_u2w, raw_len as u16) {
                                        send_packet.bytes_mut().copy_from_slice(ip_pkt);
                                        session_u2w.send_packet(send_packet);
                                    }
                                }
                            } else if frame_type == FLAG_FRAG_1 || frame_type == FLAG_FRAG_2 {
                                if let Some(raw_len) = strip_payload_shaping(payload_data, &psk, seq, incoming_mode, profile) {
                                    let is_frag1 = frame_type == FLAG_FRAG_1;
                                    if let Some(reassembled_len) = reasm.process(is_frag1, seq, &payload_data[..raw_len], &mut reasm_out) {
                                        let ip_pkt = &reasm_out[..reassembled_len];
                                        if ip_pkt.is_empty() {
                                            continue;
                                        }

                                        // Demux in-band ICMP probe reply
                                        if metrics_u2w.handle_possible_probe_reply(ip_pkt) {
                                            continue;
                                        }

                                        // DNS Snooper: Inspect DNS responses
                                        if crate::client::dns_snooper::is_dns_response(ip_pkt) {
                                            if let Some(dns_payload) = crate::client::dns_snooper::extract_dns_payload(ip_pkt) {
                                                dns_snooper_u2w.process_dns_response(dns_payload);
                                            }
                                        }

                                        // Deliver reassembled IP packet to Windows Wintun
                                        if let Ok(mut send_packet) = allocate_packet_resilient(&session_u2w, reassembled_len as u16) {
                                            send_packet.bytes_mut().copy_from_slice(ip_pkt);
                                            session_u2w.send_packet(send_packet);
                                        }
                                    }
                                }
                            }
                        }
                    }
                    Ok(_) => {}
                    Err(ref e) if e.kind() == io::ErrorKind::TimedOut || e.kind() == io::ErrorKind::WouldBlock => {
                        if !running_u2w.load(Ordering::Relaxed) || crate::core::metrics::TunnelTelemetry::global().shutdown_requested.load(Ordering::Relaxed) {
                            break;
                        }
                    }
                    Err(_) => {
                        if !running_u2w.load(Ordering::Relaxed) || crate::core::metrics::TunnelTelemetry::global().shutdown_requested.load(Ordering::Relaxed) {
                            break;
                        }
                    }
                }
            }
        })?;

    // Thread 3: In-Band Loss Prober, Anti-NAT Keepalive & Real-Time Live HUD
    let session_prober = Arc::clone(&session);
    let socket_prober = socket.try_clone()?;
    let running_prober = Arc::clone(&running);
    let metrics_prober = Arc::clone(&metrics);
    let seq_prober = Arc::clone(&seq_counter);
    let last_tx_prober = Arc::clone(&last_tx_epoch);
    let tunnel_start_prober = tunnel_start;

    let handle_prober = thread::Builder::new()
        .name("metric_monitor".into())
        .spawn(move || {
            let mut icmp_seq: u16 = 0;
            let mut prev_tx: u64 = 0;
            let mut prev_rx: u64 = 0;
            let mut prev_time = Instant::now();

            // Lightweight pseudo-random generator state for Jitter & Variable Padding
            let mut rng_state: u64 = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0xFEED_FACE_CAFE_BABE) ^ (psk[0] as u64 | ((psk[1] as u64) << 8));

            let rand_u64 = |min: u64, max: u64, state: &mut u64| -> u64 {
                *state ^= *state << 13;
                *state ^= *state >> 7;
                *state ^= *state << 17;
                min + (*state % (max - min + 1))
            };

            // WireGuard-style PersistentKeepalive with anti-DPI random jitter: 20s - 25s (20000ms - 25000ms)
            let mut next_ka_interval_ms = rand_u64(KEEPALIVE_JITTER_MIN_MS, KEEPALIVE_JITTER_MAX_MS, &mut rng_state);

            println!("\n------------------------------------------------------------------");
            println!("  LIVE TRAFFIC & QUALITY DASHBOARD [{}]", profile.as_str().to_uppercase());
            println!("  Anti-DPI Keepalive: WireGuard-Style 20-25s Jitter (Idle-Only) Active");
            println!("------------------------------------------------------------------");

            while running_prober.load(Ordering::Relaxed) && !crate::core::metrics::TunnelTelemetry::global().shutdown_requested.load(Ordering::Relaxed) {
                for _ in 0..20 {
                    if !running_prober.load(Ordering::Relaxed) || crate::core::metrics::TunnelTelemetry::global().shutdown_requested.load(Ordering::Relaxed) {
                        break;
                    }
                    thread::sleep(Duration::from_millis(50));
                }
                if !running_prober.load(Ordering::Relaxed) || crate::core::metrics::TunnelTelemetry::global().shutdown_requested.load(Ordering::Relaxed) {
                    running_prober.store(false, Ordering::Relaxed);
                    let _ = session_prober.shutdown();
                    break;
                }

                let current_elapsed_ms = tunnel_start_prober.elapsed().as_millis() as u64;
                let last_user_tx_ms = last_tx_prober.load(Ordering::Relaxed);
                let idle_ms = current_elapsed_ms.saturating_sub(last_user_tx_ms);

                // Anti-NAT Idle-Only Keepalive:
                // Only triggers if the user has been completely idle (no data sent) for 20-25s!
                if idle_ms >= next_ka_interval_ms {
                    let padding_len = rand_u64(KEEPALIVE_PADDING_MIN_BYTES as u64, KEEPALIVE_PADDING_MAX_BYTES as u64, &mut rng_state) as usize;
                    let total_ka_len = MIMICRY_HEADER_LEN + padding_len;
                    let mut ka_pkt = [0u8; MIMICRY_HEADER_LEN + KEEPALIVE_PADDING_MAX_BYTES];

                    // Fill padding with dynamic pseudo-random entropy (Anti-DPI profile matching)
                    for i in 0..padding_len {
                        ka_pkt[MIMICRY_HEADER_LEN + i] = (rand_u64(0, 255, &mut rng_state) & 0xFF) as u8;
                    }

                    let seq = (seq_prober.fetch_add(1, Ordering::Relaxed) & 0xFFFF) as u16;
                    let ka_flags = FLAG_KEEPALIVE | mode.to_flags();
                    profile.wrap_header(&mut ka_pkt[..total_ka_len], ka_flags, seq, &psk);
                    let _ = socket_prober.send(&ka_pkt[..total_ka_len]);

                    // Reset idle mark and pick a fresh jitter interval (20-25s)
                    last_tx_prober.store(current_elapsed_ms, Ordering::Relaxed);
                    next_ka_interval_ms = rand_u64(KEEPALIVE_JITTER_MIN_MS, KEEPALIVE_JITTER_MAX_MS, &mut rng_state);
                }

                // In-band latency probe (1s when actively used, 5s when line is silent to preserve stealth)
                let should_probe = if idle_ms < 5000 {
                    true
                } else {
                    (current_elapsed_ms / 1000) % 5 == 0
                };

                if should_probe {
                    icmp_seq = icmp_seq.wrapping_add(1);
                    let icmp_inner = build_icmp_probe_packet(icmp_seq, src_v4_bytes);
                    let mut probe_wire = [0u8; MIMICRY_HEADER_LEN + 64];
                    let seq = (seq_prober.fetch_add(1, Ordering::Relaxed) & 0xFFFF) as u16;

                    let shaped_len = apply_payload_shaping(&icmp_inner, &mut probe_wire[MIMICRY_HEADER_LEN..], &psk, seq, mode, profile);
                    let total_len = MIMICRY_HEADER_LEN + shaped_len;

                    let full_flags = FLAG_DATA | mode.to_flags();
                    profile.wrap_header(&mut probe_wire[..total_len], full_flags, seq, &psk);

                    if socket_prober.send(&probe_wire[..total_len]).is_ok() {
                        metrics_prober.record_probe_sent(icmp_seq);
                    }
                }

                let now = Instant::now();
                let dt = now.duration_since(prev_time).as_secs_f64();
                prev_time = now;

                let tx_now = metrics_prober.total_tx_bytes.load(Ordering::Relaxed);
                let rx_now = metrics_prober.total_rx_bytes.load(Ordering::Relaxed);

                let tx_speed = if dt > 0.0 { (tx_now.saturating_sub(prev_tx)) as f64 / dt } else { 0.0 };
                let rx_speed = if dt > 0.0 { (rx_now.saturating_sub(prev_rx)) as f64 / dt } else { 0.0 };
                prev_tx = tx_now;
                prev_rx = rx_now;

                let ping = metrics_prober.current_ping_ms.load(Ordering::Relaxed);

                // Update global telemetry for Tauri GUI
                let telem = crate::core::metrics::TunnelTelemetry::global();
                telem.tx_rate_bps.store(tx_speed as u64, Ordering::Relaxed);
                telem.rx_rate_bps.store(rx_speed as u64, Ordering::Relaxed);
                telem.total_tx_bytes.store(tx_now, Ordering::Relaxed);
                telem.total_rx_bytes.store(rx_now, Ordering::Relaxed);
                telem.ping_ms.store(ping, Ordering::Relaxed);

                print!(
                    "\r[METRICS] ⬆ Up: {:>8}/s ({:>8}) | ⬇ Down: {:>8}/s ({:>8}) | 📶 Ping: {:>3} ms   ",
                    format_size(tx_speed),
                    format_size(tx_now as f64),
                    format_size(rx_speed),
                    format_size(rx_now as f64),
                    ping,
                );
                let _ = io::stdout().flush();
            }
        })?;

    let _ = handle_w2u.join();
    let _ = handle_u2w.join();
    let _ = handle_prober.join();

    routes.restore();
    dns_snooper.clean_all_dynamic_routes();
    drop(session);
    drop(adapter);

    let telem = crate::core::metrics::TunnelTelemetry::global();
    telem.set_status(crate::core::metrics::TunnelStatus::Disconnected);
    telem.tx_rate_bps.store(0, Ordering::Relaxed);
    telem.rx_rate_bps.store(0, Ordering::Relaxed);
    telem.ping_ms.store(0, Ordering::Relaxed);

    println!("[CLIENT] All resources cleaned up. Clean exit.");
    Ok(())
}
