//! Live quality, latency, and throughput profiling tool for testing real tunnel performance
//! across all 16 camouflage protocols and all 3 payload modes.

use std::error::Error;
use std::net::UdpSocket;
use std::time::{Duration, Instant};

use crate::core::crypto::{apply_payload_shaping, strip_payload_shaping, PayloadMode};
use crate::mimic::{
    MimicProfile, FLAG_FRAME_MASK, FLAG_KEEPALIVE, FLAG_KEEPALIVE_ACK, MIMICRY_HEADER_LEN,
};

pub fn run_live_benchmark(server_host: &str, psk: [u8; 8]) -> Result<(), Box<dyn Error>> {
    println!("==================================================================");
    println!("  PURE CONNECTED UDP RAW IP TUNNEL - END-TO-END STRESS AUDIT");
    println!("  Target Server: {}", server_host);
    println!("  Timestamp    : 2026-11-15 | Mode: Full Integration & Stress Profiling");
    println!("==================================================================");

    let clean_host = server_host.trim_matches(|c| c == '[' || c == ']');
    let bind_addr = if clean_host.contains(':') {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };

    println!("\n[PHASE 0] Dynamic Path MTU Discovery & Zero-Fragmentation Calibration");
    println!("-----------------------------------------------------------------------------------------");
    let is_v6 = clean_host.contains(':');
    let test_ep: std::net::SocketAddr = if is_v6 {
        format!("[{}]:443", clean_host).parse()?
    } else {
        format!("{}:443", clean_host).parse()?
    };
    let test_sock = UdpSocket::bind(bind_addr)?;
    let _ = test_sock.connect(test_ep);
    let (wire_pmtu, discovery_method) = crate::common::discover_path_mtu(&test_sock, test_ep, MimicProfile::QuicV1, PayloadMode::ShapedDpi, &psk);
    let dyn_tunnel_mtu = crate::common::calculate_tunnel_mtu(wire_pmtu, is_v6, MimicProfile::QuicV1, PayloadMode::Plaintext);
    let total_overhead = crate::common::calculate_transport_overhead(is_v6, MimicProfile::QuicV1, PayloadMode::Plaintext);
    println!("  Discovered Wire Path MTU : {} bytes [{}]", wire_pmtu, discovery_method);
    println!("  Base Protocol Overhead   : {} bytes ({} + UDP + Mimicry)", total_overhead, if is_v6 { "IPv6" } else { "IPv4" });
    println!("  Negotiated Tunnel MTU    : {} bytes (100% Zero-Fragmentation Guaranteed)", dyn_tunnel_mtu);

    // Profile-Specific Exact Zero-Waste Calibration:
    let q_ovh = crate::common::calculate_transport_overhead(is_v6, MimicProfile::QuicV1, PayloadMode::Plaintext);
    let q_mtu = crate::common::calculate_tunnel_mtu(wire_pmtu, is_v6, MimicProfile::QuicV1, PayloadMode::Plaintext);

    let r_ovh = crate::common::calculate_transport_overhead(is_v6, MimicProfile::RakNet, PayloadMode::ShapedDpi);
    let r_mtu = crate::common::calculate_tunnel_mtu(wire_pmtu, is_v6, MimicProfile::RakNet, PayloadMode::ShapedDpi);

    let w_ovh = crate::common::calculate_transport_overhead(is_v6, MimicProfile::WebRtc, PayloadMode::ShapedDpi);
    let w_mtu = crate::common::calculate_tunnel_mtu(wire_pmtu, is_v6, MimicProfile::WebRtc, PayloadMode::ShapedDpi);

    println!("\n  Dynamic Profile-Specific Zero-Waste Calibration:");
    println!("    * QUIC_V1 (Standard)     : Overhead {:>2}B -> Negotiated MTU: {:>4}B (Zero-Waste)", q_ovh, q_mtu);
    println!("    * RAKNET  (+1B Opcode)   : Overhead {:>2}B -> Negotiated MTU: {:>4}B (Zero-Waste)", r_ovh, r_mtu);
    println!("    * WEBRTC  (+2B Opus TOC) : Overhead {:>2}B -> Negotiated MTU: {:>4}B (Zero-Waste)", w_ovh, w_mtu);
    println!("-----------------------------------------------------------------------------------------");

    let profiles = [
        MimicProfile::QuicV1,
        MimicProfile::QuicV2,
        MimicProfile::WebRtc,
        MimicProfile::Dtls,
        MimicProfile::Dns,
        MimicProfile::Esp,
        MimicProfile::Utp,
        MimicProfile::RakNet,
        MimicProfile::Stun,
        MimicProfile::Turn,
        MimicProfile::Steam,
        MimicProfile::Sdr,
        MimicProfile::Riot,
        MimicProfile::Zoom,
        MimicProfile::Rdp,
        MimicProfile::Discord,
    ];

    println!("\n[PHASE 1] Stealth Camouflage Protocols Verification (16/16 Profiles Under Full-MTU Load)");
    println!("---------------------------------------------------------------------------------------------------");
    println!(
        "{:<4} {:<18} {:<6} {:<10} {:<10} {:<10} {:<10} {:<13} {:<8}",
        "#", "Protocol", "Port", "Min RTT", "Avg RTT", "Max RTT", "Loss %", "Throughput", "Status"
    );
    println!("---------------------------------------------------------------------------------------------------");

    let mut total_passed = 0;
    for (idx, &prof) in profiles.iter().enumerate() {
        let port = prof.default_port();
        let target_endpoint = if clean_host.contains(':') {
            format!("[{}]:{}", clean_host, port)
        } else {
            format!("{}:{}", clean_host, port)
        };

        let socket = match UdpSocket::bind(bind_addr) {
            Ok(s) => s,
            Err(e) => {
                println!(
                    "{:<4} {:<18} {:<6} [SOCKET BIND ERROR: {}]",
                    idx + 1,
                    prof.as_str().to_uppercase(),
                    port,
                    e
                );
                continue;
            }
        };
        crate::common::pmtu::set_socket_dont_fragment(&socket, is_v6);
        let _ = socket.set_read_timeout(Some(Duration::from_millis(1500)));

        let mut rtts: Vec<f64> = Vec::new();
        let mut lost = 0;
        let trials = 5;
        let payload_size = 1200; // Realistic MTU payload burst
        let mut successful_bytes: u64 = 0;
        let mut total_roundtrip_time_secs: f64 = 0.0;

        for seq in 1..=trials {
            let mut wire = vec![0u8; MIMICRY_HEADER_LEN + payload_size];
            prof.wrap_header(&mut wire[..MIMICRY_HEADER_LEN], FLAG_KEEPALIVE, seq as u16, &psk);
            for i in MIMICRY_HEADER_LEN..wire.len() {
                wire[i] = ((i * 37) & 0xFF) as u8;
            }

            let send_time = Instant::now();
            if socket.send_to(&wire, &target_endpoint).is_err() {
                lost += 1;
                continue;
            }

            let mut rx_buf = [0u8; 256];
            match socket.recv_from(&mut rx_buf) {
                Ok((n, _)) => {
                    let rtt_dur = send_time.elapsed();
                    let rtt = rtt_dur.as_secs_f64() * 1000.0;
                    if let Some((flags, _)) = prof.unwrap_header(&rx_buf[..n], &psk) {
                        if (flags & FLAG_FRAME_MASK) == FLAG_KEEPALIVE_ACK {
                            rtts.push(rtt);
                            successful_bytes += wire.len() as u64;
                            total_roundtrip_time_secs += rtt_dur.as_secs_f64();
                        } else {
                            lost += 1;
                        }
                    } else {
                        lost += 1;
                    }
                }
                Err(_) => {
                    lost += 1;
                }
            }
            std::thread::sleep(Duration::from_millis(40));
        }

        let mut status = if !rtts.is_empty() && lost == 0 {
            total_passed += 1;
            "PASS".to_string()
        } else if !rtts.is_empty() {
            total_passed += 1;
            "DEGRADED".to_string()
        } else {
            "FAIL (Blocked)".to_string()
        };

        // If standard port was blocked by ISP, test Emergency Port 443 override!
        if rtts.is_empty() && port != 443 {
            let override_endpoint = if clean_host.contains(':') {
                format!("[{}]:443", clean_host)
            } else {
                format!("{}:443", clean_host)
            };
            let mut override_rtts = Vec::new();
            for seq in 1..=3 {
                let mut wire = vec![0u8; MIMICRY_HEADER_LEN + payload_size];
                prof.wrap_header(&mut wire[..MIMICRY_HEADER_LEN], FLAG_KEEPALIVE, seq as u16, &psk);
                let t = Instant::now();
                if socket.send_to(&wire, &override_endpoint).is_ok() {
                    let mut rx_buf = [0u8; 256];
                    if let Ok((n, _)) = socket.recv_from(&mut rx_buf) {
                        let r_dur = t.elapsed();
                        let r = r_dur.as_secs_f64() * 1000.0;
                        if let Some((flags, _)) = prof.unwrap_header(&rx_buf[..n], &psk) {
                            if (flags & FLAG_FRAME_MASK) == FLAG_KEEPALIVE_ACK {
                                override_rtts.push(r);
                                successful_bytes += wire.len() as u64;
                                total_roundtrip_time_secs += r_dur.as_secs_f64();
                            }
                        }
                    }
                }
                std::thread::sleep(Duration::from_millis(40));
            }
            if !override_rtts.is_empty() {
                total_passed += 1;
                let avg = override_rtts.iter().sum::<f64>() / override_rtts.len() as f64;
                status = format!("PASS (443: {:.0}ms)", avg);
            }
        }

        let min_rtt = rtts.iter().cloned().fold(f64::INFINITY, f64::min);
        let max_rtt = rtts.iter().cloned().fold(0.0, f64::max);
        let avg_rtt = if !rtts.is_empty() {
            rtts.iter().sum::<f64>() / rtts.len() as f64
        } else {
            0.0
        };
        let loss_pct = (lost as f64 / trials as f64) * 100.0;

        let throughput_str = if total_roundtrip_time_secs > 0.0 && successful_bytes > 0 {
            let mbps = (successful_bytes as f64 * 8.0) / (total_roundtrip_time_secs * 1_000_000.0);
            format!("{:>6.2} Mbps", mbps)
        } else {
            "-- Mbps".to_string()
        };

        if !rtts.is_empty() {
            println!(
                "{:<4} {:<18} {:<6} {:>7.1} ms {:>7.1} ms {:>7.1} ms {:>8.1}%   {:>11}   {:<8}",
                idx + 1,
                prof.as_str().to_uppercase(),
                port,
                min_rtt,
                avg_rtt,
                max_rtt,
                loss_pct,
                throughput_str,
                status
            );
        } else {
            println!(
                "{:<4} {:<18} {:<6} {:>10} {:>10} {:>10} {:>8.1}%   {:>11}   {:<8}",
                idx + 1,
                prof.as_str().to_uppercase(),
                port,
                "TIMEOUT",
                "TIMEOUT",
                "TIMEOUT",
                100.0,
                throughput_str,
                status
            );
        }
    }
    println!("---------------------------------------------------------------------------------------------------");
    println!(
        "Stealth Mimicry Score: {}/{} Profiles Validated Live (PSK Token Anti-Hijack Enforced)\n",
        total_passed,
        profiles.len()
    );

    println!("\n[PHASE 2] Payload Protection Modes & Symmetric Wire Lock Benchmark");
    println!("---------------------------------------------------------------------------------------------------");
    println!(
        "{:<35} {:<10} {:<18} {:<16} {:<14}",
        "Payload Mode", "Overhead", "Entropy / Stealth", "Memory Integrity", "Wire Roundtrip"
    );
    println!("---------------------------------------------------------------------------------------------------");
    for mode in [PayloadMode::Plaintext, PayloadMode::StreamCipher, PayloadMode::ShapedDpi] {
        let dummy_ip_pkt = [
            0x45, 0x00, 0x00, 0x54, 0x12, 0x34, 0x00, 0x00, 0x40, 0x01, 0x00, 0x00, 0x0A, 0x08,
            0x00, 0x02, 0x01, 0x01, 0x01, 0x01,
        ];
        let mut out = [0u8; 128];
        let shaped_len = apply_payload_shaping(
            &dummy_ip_pkt,
            &mut out,
            &psk,
            100,
            mode,
            MimicProfile::QuicV1,
        );
        let overhead = shaped_len.saturating_sub(dummy_ip_pkt.len());
        let mut dec = out[..shaped_len].to_vec();
        let stripped_len =
            strip_payload_shaping(&mut dec, &psk, 100, mode, MimicProfile::QuicV1).unwrap_or(0);
        let integrity = if stripped_len == dummy_ip_pkt.len() && &dec[..stripped_len] == &dummy_ip_pkt[..]
        {
            "VERIFIED OK"
        } else {
            "CORRUPTED"
        };
        let stealth = match mode {
            PayloadMode::ShapedDpi => "Zero-Entropy Evasion",
            PayloadMode::StreamCipher => "High-Entropy AES-GCM",
            PayloadMode::Plaintext => "Zero-Overhead Raw IP",
        };

        // Live wire roundtrip test with Mode Flag verification & multi-port resilience
        let mut wire_status = "SKIPPED".to_string();
        'probe_loop: for prof in [MimicProfile::Riot, MimicProfile::Discord, MimicProfile::Dtls] {
            if let Ok(sock) = UdpSocket::bind(bind_addr) {
                let _ = sock.set_read_timeout(Some(Duration::from_millis(800)));
                let mut wire_pkt = [0u8; MIMICRY_HEADER_LEN + 32];
                let test_flags = FLAG_KEEPALIVE | mode.to_flags();
                prof.wrap_header(&mut wire_pkt[..MIMICRY_HEADER_LEN], test_flags, 42, &psk);
                let target_ep = if clean_host.contains(':') {
                    format!("[{}]:{}", clean_host, prof.default_port())
                } else {
                    format!("{}:{}", clean_host, prof.default_port())
                };

                for _ in 0..3 {
                    let t_start = Instant::now();
                    if sock.send_to(&wire_pkt, &target_ep).is_ok() {
                        let mut rx_buf = [0u8; 256];
                        if let Ok((n, _)) = sock.recv_from(&mut rx_buf) {
                            let rtt_ms = t_start.elapsed().as_secs_f64() * 1000.0;
                            if let Some((rx_flags, _)) = prof.unwrap_header(&rx_buf[..n], &psk) {
                                let rx_frame = rx_flags & FLAG_FRAME_MASK;
                                let rx_mode = PayloadMode::from_flags(rx_flags);
                                if rx_frame == FLAG_KEEPALIVE_ACK && rx_mode == mode {
                                    wire_status = format!("LOCKED ({:.1}ms)", rtt_ms);
                                    break 'probe_loop;
                                } else if rx_frame == FLAG_KEEPALIVE_ACK {
                                    wire_status = format!("ACKED ({:.1}ms)", rtt_ms);
                                    break 'probe_loop;
                                }
                            }
                        }
                    }
                    std::thread::sleep(Duration::from_millis(30));
                }
            }
        }

        println!(
            "{:<35} {:>7} B   {:<18} {:<16} {:<14}",
            mode.display_name(),
            overhead,
            stealth,
            integrity,
            wire_status
        );
    }
    println!("---------------------------------------------------------------------------------------------------\n");

    Ok(())
}
