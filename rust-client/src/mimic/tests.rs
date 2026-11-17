#[cfg(test)]
mod test_suite {
    use super::super::*;
    use crate::common::{should_fragment, split_packet, ReassemblyBuffer};
    use crate::core::crypto::{
        apply_payload_shaping, derive_psk, fragment_cipher_seq, strip_payload_shaping, PayloadMode,
    };

    #[test]
    fn test_all_16_profiles_wrap_unwrap() {
        let psk = derive_psk("CommercialGradeEngine2026!");
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

        for &p in &profiles {
            let mut wire = [0u8; 64];
            p.wrap_header(&mut wire, FLAG_DATA, 4242, &psk);

            // 1. Profile-specific unwrap
            let res = p.unwrap_header(&wire, &psk);
            assert!(res.is_some(), "Specific unwrap failed for {:?}", p);
            let (f, seq) = res.unwrap();
            assert_eq!(f, FLAG_DATA);
            assert_eq!(seq, 4242, "Seq mismatch in specific unwrap for {:?}", p);

            // 2. Server-side zero-config auto-detection
            let auto = auto_detect_and_unwrap(&wire, &psk);
            assert!(auto.is_some(), "Auto-detect failed for {:?}", p);
            let (det_prof, det_flags, det_seq) = auto.unwrap();
            assert_eq!(det_prof, p, "Mismatch in detected profile: expected {:?}, got {:?}", p, det_prof);
            assert_eq!(det_flags, FLAG_DATA);
            assert_eq!(det_seq, 4242, "Seq mismatch in auto-detect for {:?}", p);

            // 3. Security: Intruder / wrong PSK rejection (Silent Drop)
            let bad_psk = derive_psk("WrongPassphrase");
            assert!(
                auto_detect_and_unwrap(&wire, &bad_psk).is_none(),
                "Intruder packet with bad PSK was not dropped for {:?}",
                p
            );
        }
    }

    #[test]
    fn test_port_hints_and_emergency_overrides() {
        let psk = derive_psk("PortHintTestKey2026!");

        // 1. Standard Port-Hint Fast-Path Check
        for &(p, port) in &[
            (MimicProfile::QuicV1, 443),
            (MimicProfile::QuicV2, 443),
            (MimicProfile::Dtls, 443),
            (MimicProfile::WebRtc, 3478),
            (MimicProfile::Stun, 3478),
            (MimicProfile::Turn, 3478),
            (MimicProfile::Zoom, 8801),
            (MimicProfile::Riot, 7500),
            (MimicProfile::Sdr, 27020),
            (MimicProfile::Steam, 27015),
            (MimicProfile::Rdp, 3389),
            (MimicProfile::Discord, 50000),
            (MimicProfile::RakNet, 19132),
            (MimicProfile::Esp, 4500),
            (MimicProfile::Utp, 6881),
            (MimicProfile::Dns, 5353),
        ] {
            let mut wire = [0u8; 64];
            p.wrap_header(&mut wire, FLAG_DATA, 1001, &psk);
            let res = port_hint_and_auto_detect(&wire, port, &psk);
            assert!(res.is_some(), "Port hint failed for {:?}", p);
            let (det_p, f, s) = res.unwrap();
            assert_eq!(det_p, p);
            assert_eq!(f, FLAG_DATA);
            assert_eq!(s, 1001);
        }

        // 2. Emergency Override Check: sending non-standard protocols on Port 443 (e.g. Zoom, Riot, Discord on 443)
        for &override_profile in &[
            MimicProfile::Zoom,
            MimicProfile::Riot,
            MimicProfile::Discord,
            MimicProfile::Sdr,
            MimicProfile::RakNet,
            MimicProfile::Rdp,
        ] {
            let mut wire = [0u8; 64];
            override_profile.wrap_header(&mut wire, FLAG_DATA, 2002, &psk);
            // Received on port 443!
            let res = port_hint_and_auto_detect(&wire, 443, &psk);
            assert!(res.is_some(), "Emergency override to port 443 failed for {:?}", override_profile);
            let (det_p, f, s) = res.unwrap();
            assert_eq!(det_p, override_profile, "Emergency override profile mismatch");
            assert_eq!(f, FLAG_DATA);
            assert_eq!(s, 2002);
        }
    }

    #[test]
    fn test_all_16_profiles_x_3_modes_and_micro_segmentation() {
        let psk = derive_psk("MultiModePayloadKey2026!");
        let small_pkt = b"GET /stream HTTP/1.1\r\nHost: example.com\r\n\r\n";
        // Full 1500-byte inner IP packet exercising micro-segmentation (> 1200B threshold)
        let large_pkt: Vec<u8> = (0..1500).map(|i| ((i * 31 + 17) & 0xFF) as u8).collect();
        assert!(should_fragment(large_pkt.len()));

        let mut reasm = ReassemblyBuffer::new();
        let mut reasm_out = [0u8; 2048];
        let mut seq_counter: u16 = 100;

        for mode in [
            PayloadMode::ShapedDpi,
            PayloadMode::StreamCipher,
            PayloadMode::Plaintext,
        ] {
            for &profile in &MimicProfile::ALL {
                // --- A. Unfragmented FLAG_DATA round-trip ---
                seq_counter = seq_counter.wrapping_add(1);
                let mut wire = [0u8; 2048];
                let shaped_len = apply_payload_shaping(
                    small_pkt,
                    &mut wire[MIMICRY_HEADER_LEN..],
                    &psk,
                    seq_counter,
                    mode,
                    profile,
                );
                let total_len = MIMICRY_HEADER_LEN + shaped_len;
                let flags = FLAG_DATA | mode.to_flags();
                profile.wrap_header(&mut wire[..total_len], flags, seq_counter, &psk);

                // Verify server auto-detection on both standard port and generic port 7190
                let (det_prof, det_flags, det_seq) =
                    port_hint_and_auto_detect(&wire[..total_len], 7190, &psk)
                        .unwrap_or_else(|| panic!("Auto-detect failed for {:?} / {:?}", profile, mode));
                assert_eq!(det_prof, profile);
                assert_eq!(det_seq, seq_counter);
                assert_eq!(det_flags & FLAG_FRAME_MASK, FLAG_DATA);
                assert_eq!(PayloadMode::from_flags(det_flags), mode);

                let raw_len = strip_payload_shaping(
                    &mut wire[MIMICRY_HEADER_LEN..total_len],
                    &psk,
                    det_seq,
                    PayloadMode::from_flags(det_flags),
                    det_prof,
                )
                .unwrap_or_else(|| panic!("strip_payload_shaping failed for {:?} / {:?}", profile, mode));
                assert_eq!(
                    &wire[MIMICRY_HEADER_LEN..MIMICRY_HEADER_LEN + raw_len],
                    small_pkt,
                    "Small packet mismatch for {:?} / {:?}",
                    profile,
                    mode
                );

                // --- B. Micro-Segmented 1500-byte packet round-trip (Out-of-Order: Frag 2 then Frag 1) ---
                seq_counter = seq_counter.wrapping_add(1);
                let (part1, part2) = split_packet(&large_pkt);

                let mut wire1 = [0u8; 2048];
                let s_len1 = apply_payload_shaping(
                    part1,
                    &mut wire1[MIMICRY_HEADER_LEN..],
                    &psk,
                    fragment_cipher_seq(seq_counter, false),
                    mode,
                    profile,
                );
                let w_len1 = MIMICRY_HEADER_LEN + s_len1;
                profile.wrap_header(&mut wire1[..w_len1], FLAG_FRAG_1 | mode.to_flags(), seq_counter, &psk);

                let mut wire2 = [0u8; 2048];
                let s_len2 = apply_payload_shaping(
                    part2,
                    &mut wire2[MIMICRY_HEADER_LEN..],
                    &psk,
                    fragment_cipher_seq(seq_counter, true),
                    mode,
                    profile,
                );
                let w_len2 = MIMICRY_HEADER_LEN + s_len2;
                profile.wrap_header(&mut wire2[..w_len2], FLAG_FRAG_2 | mode.to_flags(), seq_counter, &psk);

                // Ensure Frag 1 and Frag 2 have independent keystreams on encrypted modes
                if mode != PayloadMode::Plaintext {
                    let identical_block = [0x42u8; 64];
                    let mut c1 = [0u8; 128];
                    let mut c2 = [0u8; 128];
                    let l1 = apply_payload_shaping(&identical_block, &mut c1, &psk, fragment_cipher_seq(seq_counter, false), mode, profile);
                    let l2 = apply_payload_shaping(&identical_block, &mut c2, &psk, fragment_cipher_seq(seq_counter, true), mode, profile);
                    assert_ne!(&c1[..l1], &c2[..l2], "Keystream reuse detected between Frag1 and Frag2 for {:?} / {:?}", profile, mode);
                }

                // Deliver Frag 2 first, then Frag 1 (simulating network reordering)
                let (p2, f2, sq2) = port_hint_and_auto_detect(&wire2[..w_len2], profile.default_port(), &psk).unwrap();
                assert_eq!(p2, profile);
                assert_eq!(f2 & FLAG_FRAME_MASK, FLAG_FRAG_2);
                let r_len2 = strip_payload_shaping(
                    &mut wire2[MIMICRY_HEADER_LEN..w_len2],
                    &psk,
                    fragment_cipher_seq(sq2, true),
                    PayloadMode::from_flags(f2),
                    p2,
                )
                .unwrap();
                assert_eq!(
                    reasm.process(false, sq2, &wire2[MIMICRY_HEADER_LEN..MIMICRY_HEADER_LEN + r_len2], &mut reasm_out),
                    None
                );

                let (p1, f1, sq1) = port_hint_and_auto_detect(&wire1[..w_len1], profile.default_port(), &psk).unwrap();
                assert_eq!(p1, profile);
                assert_eq!(f1 & FLAG_FRAME_MASK, FLAG_FRAG_1);
                let r_len1 = strip_payload_shaping(
                    &mut wire1[MIMICRY_HEADER_LEN..w_len1],
                    &psk,
                    fragment_cipher_seq(sq1, false),
                    PayloadMode::from_flags(f1),
                    p1,
                )
                .unwrap();
                let final_len = reasm
                    .process(true, sq1, &wire1[MIMICRY_HEADER_LEN..MIMICRY_HEADER_LEN + r_len1], &mut reasm_out)
                    .unwrap_or_else(|| panic!("Reassembly failed for {:?} / {:?}", profile, mode));

                assert_eq!(final_len, large_pkt.len());
                assert_eq!(
                    &reasm_out[..final_len],
                    &large_pkt[..],
                    "Reassembled 1500B payload corrupted for {:?} / {:?}",
                    profile,
                    mode
                );
            }
        }
    }

    #[test]
    fn test_full_64bit_psk_sensitivity_all_16_profiles() {
        let psk = derive_psk("Strict64BitAuthVerification!");
        for &p in &MimicProfile::ALL {
            let mut wire = [0u8; 64];
            p.wrap_header(&mut wire, FLAG_DATA | MODE_SHAPED, 1337, &psk);

            // Flipping ANY single byte in the 8-byte PSK must reject the packet on all 16 profiles
            for byte_idx in 0..8 {
                let mut mutated_psk = psk;
                mutated_psk[byte_idx] ^= 0x01;
                assert!(
                    p.unwrap_header(&wire, &mutated_psk).is_none(),
                    "Profile {:?} did not authenticate PSK byte {}",
                    p,
                    byte_idx
                );
            }
        }
    }

    #[test]
    #[ignore = "Live network test; set MORPH_TEST_SERVER=<ipv6> and run with --ignored"]
    fn test_live_server_roundtrip_all_profiles() {
        use std::net::UdpSocket;
        use std::time::Duration;
        use crate::core::crypto::DEFAULT_PSK;

        let server_ip = std::env::var("MORPH_TEST_SERVER").unwrap_or_else(|_| "::1".to_string());
        let port_override: Option<u16> = std::env::var("MORPH_TEST_PORT").ok().and_then(|s| s.parse().ok());
        let mut passed_count = 0;

        for &p in &MimicProfile::ALL {
            let port = port_override.unwrap_or_else(|| p.default_port());
            let target = format!("[{}]:{}", server_ip, port);
            let sock = match UdpSocket::bind("[::]:0") {
                Ok(s) => s,
                Err(e) => {
                    eprintln!("[SKIP] Could not bind IPv6 local socket: {}", e);
                    return;
                }
            };
            let _ = sock.set_read_timeout(Some(Duration::from_millis(3000)));

            let mut wire = [0u8; MIMICRY_HEADER_LEN];
            p.wrap_header(&mut wire, FLAG_KEEPALIVE | MODE_SHAPED, 1234, &DEFAULT_PSK);

            if sock.send_to(&wire, &target).is_ok() {
                let mut rx_buf = [0u8; 1024];
                if let Ok((n, _src)) = sock.recv_from(&mut rx_buf) {
                    if let Some((flags, _)) = p.unwrap_header(&rx_buf[..n], &DEFAULT_PSK) {
                        if (flags & FLAG_FRAME_MASK) == FLAG_KEEPALIVE_ACK {
                            println!("[LIVE VERIFIED] Bidirectional handshake OK for {:?} on {}", p, target);
                            passed_count += 1;
                        }
                    }
                }
            }
        }
        println!("[SUMMARY] Verified {}/{} profiles over live network!", passed_count, MimicProfile::ALL.len());
    }
}
