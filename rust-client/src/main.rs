//! Pure Connected UDP RAW IP Tunnel - Unified Multi-User Architecture (Engine v8.5)
//! Client: Pure credential consumer with encrypted subscription tokens (`fudp://<base64>`)
//! Server: Multi-subscriber authentication, dynamic PMTU, and embedded admin dashboard.

#![deny(warnings)]

pub mod common;
pub mod core;
pub mod mimic;

#[cfg(target_os = "windows")]
pub mod client;

#[cfg(target_os = "windows")]
pub mod gui_bridge;

#[cfg(target_os = "linux")]
pub mod server;

use std::error::Error;
use crate::common::{IpPreference, SubscriptionToken};
use crate::core::crypto::{derive_psk, PayloadMode};
use crate::mimic::MimicProfile;

fn main() -> Result<(), Box<dyn Error>> {
    #[cfg(target_os = "windows")]
    if std::env::args().len() == 1 {
        return crate::gui_bridge::run_gui();
    }

    // Install graceful termination handler for Windows CLI mode
    #[cfg(target_os = "windows")]
    let _ = ctrlc::set_handler(move || {
        println!("\n[CLIENT] Received termination signal. Restoring routes & shutting down...");
        crate::core::metrics::TunnelTelemetry::global().shutdown_requested.store(true, std::sync::atomic::Ordering::SeqCst);
    });

    let mut args = std::env::args().skip(1);
    let mut mode = if cfg!(target_os = "linux") { "server".to_string() } else { "client".to_string() };

    let mut server_host = String::new();
    let mut server_host_specified = false;
    let mut port_override: Option<u16> = None;
    let mut profile_opt: Option<MimicProfile> = None;
    let mut payload_mode_opt: Option<PayloadMode> = None;
    let mut ip_preference = IpPreference::Auto;
    let mut key_str: Option<String> = None;
    let mut os_profile_str: Option<String> = None;
    let mut provisioned_users: usize = 10;

    // Server-specific options
    let mut admin_port: u16 = 9090;
    let mut admin_pass: Option<String> = None;
    let mut server_v4_advertised: Option<String> = None;
    let mut server_v6_advertised: Option<String> = None;

    // Client-specific token actions
    #[allow(unused_variables, unused_assignments)]
    let mut import_token_str: Option<String> = None;
    #[allow(unused_variables, unused_assignments)]
    let mut list_profiles_cmd = false;
    #[allow(unused_variables, unused_assignments)]
    let mut connect_index_opt: Option<usize> = None;
    let mut active_token: Option<SubscriptionToken> = None;

    while let Some(arg) = args.next() {
        match arg.as_str() {
            "--help" | "-h" => {
                println!("Morph Core — Ultra-Fast UDP Multi-User Tunnel (v8.5)");
                println!("Usage: fast-udp-tunnel [options] [server_address | morph://token]");
                println!();
                println!("Client Subscription Commands:");
                println!("  --import <morph://token>       Import and save a subscription token to morph_profiles.dat");
                println!("  --list                         List all saved subscription profiles");
                println!("  --connect <INDEX>              Connect directly to saved profile by index");
                println!("  <morph://token>                Directly connect and save provided subscription token");
                println!();
                println!("Options:");
                println!("  -m, --mode <client|server>     Operation mode (default: auto by OS)");
                println!("  -s, --server <ADDR>            Manual remote tunnel server address");
                println!("  -p, --port <PORT>              Tunnel port override (default: auto by profile)");
                println!("  -4, --ipv4                     Force IPv4 endpoint connection");
                println!("  -6, --ipv6                     Force IPv6 endpoint connection");
                println!("      --mimic <PROFILE>          Stealth camouflage protocol [quic_v1, quic_v2, webrtc, ...]");
                println!("      --payload <MODE>           Payload protection [shaped, stream, plaintext]");
                println!("  -k, --key, --psk <PASSWORD>    Secret passphrase for manual tunnel connection");
                println!();
                println!("Server Options:");
                println!("      --admin-port <PORT>        Embedded Admin Web Dashboard port (default: 9090)");
                println!("      --admin-pass <PASSWORD>    Admin Web Dashboard password (default: 'admin')");
                println!("      --server-v4 <IP>           Public IPv4 advertised in generated client tokens");
                println!("      --server-v6 <IP>           Public IPv6 advertised in generated client tokens");
                println!("      --os-profile <PROFILE>     OS adaptation profile [auto, alpine, debian, generic]");
                println!("  -u, --provisioned-users <N>    Target concurrent capacity [1-10, 11-25, 26-50+]");
                println!("  -b, --bench                    Run live benchmark suite");
                return Ok(());
            }
            "--import" => {
                if let Some(tok) = args.next() {
                    import_token_str = Some(tok);
                }
            }
            "--list" => {
                list_profiles_cmd = true;
            }
            "--connect" => {
                if let Some(idx_str) = args.next() {
                    connect_index_opt = idx_str.parse().ok();
                }
            }
            "-m" | "--mode" => {
                if let Some(m) = args.next() {
                    mode = m;
                }
            }
            "-b" | "--bench" | "--test-live" => {
                mode = "bench".to_string();
            }
            "--chaos" | "--chaos-audit" => {
                mode = "chaos".to_string();
            }
            "-s" | "--server" => {
                if let Some(ep) = args.next() {
                    server_host_specified = true;
                    if let Some(pos) = ep.rfind(':') {
                        if !ep.starts_with('[') && ep.contains(':') && ep.matches(':').count() > 1 {
                            server_host = format!("[{}]", ep);
                        } else if ep.starts_with('[') && ep.ends_with(']') {
                            server_host = ep;
                        } else {
                            server_host = ep[..pos].to_string();
                            port_override = ep[pos + 1..].parse().ok();
                        }
                    } else {
                        server_host = ep;
                    }
                }
            }
            "-p" | "--port" => {
                if let Some(p) = args.next() {
                    port_override = p.parse().ok();
                }
            }
            "-4" | "--ipv4" => {
                ip_preference = IpPreference::ForceV4;
            }
            "-6" | "--ipv6" => {
                ip_preference = IpPreference::ForceV6;
            }
            "--admin-port" => {
                if let Some(p) = args.next() {
                    if let Ok(val) = p.parse::<u16>() {
                        admin_port = val;
                    }
                }
            }
            "--admin-pass" => {
                if let Some(pass) = args.next() {
                    admin_pass = Some(pass);
                }
            }
            "--server-v4" => {
                if let Some(ip) = args.next() {
                    server_v4_advertised = Some(ip);
                }
            }
            "--server-v6" => {
                if let Some(ip) = args.next() {
                    server_v6_advertised = Some(ip);
                }
            }
            "--mimic" => {
                if let Some(prof_str) = args.next() {
                    if let Some(p) = MimicProfile::parse(&prof_str) {
                        profile_opt = Some(p);
                    } else {
                        eprintln!("[WARN] Unknown mimic profile '{}'.", prof_str);
                    }
                }
            }
            "--payload" => {
                if let Some(pm_str) = args.next() {
                    payload_mode_opt = PayloadMode::parse(&pm_str);
                }
            }
            "-u" | "--provisioned-users" | "--users" => {
                if let Some(u_str) = args.next() {
                    if let Ok(u) = u_str.parse::<usize>() {
                        provisioned_users = u;
                    }
                }
            }
            "-k" | "--key" | "--psk" => {
                if let Some(k) = args.next() {
                    key_str = Some(k);
                }
            }
            "--os-profile" => {
                if let Some(p) = args.next() {
                    os_profile_str = Some(p);
                }
            }
            tok if tok.starts_with("morph://") || tok.starts_with("MORPH://") || tok.starts_with("fudp://") || tok.starts_with("FUDP://") => {
                match SubscriptionToken::from_uri(tok) {
                    Ok(t) => {
                        active_token = Some(t);
                    }
                    Err(e) => {
                        eprintln!("[ERROR] Invalid subscription token: {}", e);
                        return Err(e.into());
                    }
                }
            }
            val if !val.starts_with('-') => {
                server_host_specified = true;
                if let Some(pos) = val.rfind(':') {
                    if !val.starts_with('[') && val.contains(':') && val.matches(':').count() > 1 {
                        server_host = format!("[{}]", val);
                    } else if val.starts_with('[') && val.ends_with(']') {
                        server_host = val.to_string();
                    } else {
                        server_host = val[..pos].to_string();
                        port_override = val[pos + 1..].parse().ok();
                    }
                } else {
                    server_host = val.to_string();
                }
            }
            unknown => {
                eprintln!("[WARN] Unknown argument: {}", unknown);
            }
        }
    }

    // Handle Client Command Flags: --import, --list, --connect
    #[cfg(target_os = "windows")]
    {
        if let Some(ref tok_str) = import_token_str {
            match client::config_manager::import_token(tok_str) {
                Ok(p) => {
                    println!("[SUCCESS] Imported subscription profile '{}' (User: {})", p.token.name, p.token.user_id);
                    println!("Saved to '{}'. Use 'fast-udp-tunnel' or 'fast-udp-tunnel --connect <ID>' to launch.", client::config_manager::PROFILES_FILENAME);
                    return Ok(());
                }
                Err(e) => {
                    eprintln!("[ERROR] Failed to import token: {}", e);
                    return Err(e.into());
                }
            }
        }

        if list_profiles_cmd {
            let profiles = client::config_manager::load_profiles();
            if profiles.is_empty() {
                println!("[INFO] No saved subscription profiles found in '{}'.", client::config_manager::PROFILES_FILENAME);
            } else {
                client::config_manager::print_profile_list(&profiles);
            }
            return Ok(());
        }

        if let Some(idx) = connect_index_opt {
            let profiles = client::config_manager::load_profiles();
            if idx == 0 || idx > profiles.len() {
                eprintln!("[ERROR] Profile index {} out of range (1..{})", idx, profiles.len());
                return Err("Index out of range".into());
            }
            active_token = Some(profiles[idx - 1].token.clone());
        }
    }

    let psk = match key_str {
        Some(ref k) => derive_psk(k),
        None => crate::core::crypto::DEFAULT_PSK,
    };

    let _ = provisioned_users;
    let _ = (&import_token_str, list_profiles_cmd, connect_index_opt);

    if mode == "bench" {
        let bench_target = if server_host.is_empty() {
            "127.0.0.1".to_string()
        } else {
            server_host
        };
        return common::run_live_benchmark(&bench_target, psk);
    }

    if mode == "chaos" {
        let chaos_target = if server_host.is_empty() {
            "127.0.0.1".to_string()
        } else {
            server_host
        };
        let chosen_profile = profile_opt.unwrap_or(MimicProfile::QuicV2);
        let chosen_port = port_override.unwrap_or_else(|| chosen_profile.default_port());
        let pass_ref = admin_pass.as_deref().unwrap_or("admin");
        let cfg = common::ChaosAuditConfig {
            server_host: &chaos_target,
            server_port: chosen_port,
            profile: chosen_profile,
            user_id: "usr_admin_01",
            psk,
            admin_port,
            admin_prefix: "/admin",
            admin_user: "admin",
            admin_pass: pass_ref,
        };
        return common::run_chaos_audit(&cfg);
    }

    if mode == "server" {
        #[cfg(target_os = "linux")]
        {
            let primary_port = port_override.unwrap_or(core::DEFAULT_PORT);
            let os_prof = os_profile_str
                .as_deref()
                .and_then(server::OsProfile::parse)
                .unwrap_or(server::OsProfile::Auto);
            server::run_server(
                primary_port,
                admin_port,
                admin_pass,
                server_v4_advertised,
                server_v6_advertised,
                psk,
                os_prof,
                provisioned_users,
            )
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = os_profile_str;
            let _ = admin_port;
            let _ = admin_pass;
            let _ = server_v4_advertised;
            let _ = server_v6_advertised;
            eprintln!("[ERROR] Server mode is only supported on Linux!");
            Ok(())
        }
    } else {
        #[cfg(target_os = "windows")]
        {
            client::run_client(
                &server_host,
                server_host_specified,
                port_override,
                profile_opt,
                payload_mode_opt,
                ip_preference,
                psk,
                active_token,
            )
        }
        #[cfg(not(target_os = "windows"))]
        {
            let _ = active_token;
            let _ = server_host_specified;
            let _ = port_override;
            let _ = profile_opt;
            let _ = payload_mode_opt;
            let _ = ip_preference;
            eprintln!("[ERROR] Client mode with Wintun is currently targeted for Windows!");
            Ok(())
        }
    }
}
