//! Client module entry point with subscription token manager and interactive menus.
//! Pure credential consumer: no hardcoded remote IPs.

pub mod config_manager;
pub mod dns_snooper;
pub mod engine;
pub mod routes;
pub mod routing;
pub mod socket;
pub mod tun_io;
pub mod wintun;

use std::error::Error;
use std::io::{self, Write};
use std::time::SystemTime;

use crate::common::{IpPreference, SubscriptionToken};
use crate::core::crypto::PayloadMode;
use crate::mimic::MimicProfile;

pub fn is_elevated() -> bool {
    std::process::Command::new("net")
        .arg("session")
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map_or(false, |s| s.success())
}

pub fn prompt_interactive_options(default_host: &str, host_specified: bool) -> (String, MimicProfile, u16, PayloadMode) {
    println!("==================================================================");
    println!("  Morph Core — Manual Edge Client Setup (v8.5)");
    println!("==================================================================");

    let host = if host_specified {
        default_host.to_string()
    } else {
        println!("Enter Remote Server Hostname or IP (IPv4 or [IPv6]):");
        print!("> ");
        let _ = io::stdout().flush();

        let mut input_ip = String::new();
        if io::stdin().read_line(&mut input_ip).is_ok() && !input_ip.trim().is_empty() {
            let c = input_ip.trim();
            if !c.starts_with('[') && c.contains(':') && c.matches(':').count() > 1 {
                format!("[{}]", c)
            } else {
                c.to_string()
            }
        } else {
            default_host.to_string()
        }
    };

    println!("[SELECT] Target Server IP: {}\n", host);

    println!("------------------------------------------------------------------");
    println!("Step 1: Select your Stealth Camouflage Protocol:");
    println!("  [1]  QUIC v1 / HTTP/3   (Default - RFC 9000 - Best for 4K Streaming & Web - Port 443)");
    println!("  [2]  QUIC v2 / RFC 9369 (Next-Gen QUIC - Unmatched DPI Evasion - Port 443)");
    println!("  [3]  WebRTC / SRTP      (Best for Low-Latency Calls & Gaming - Port 3478)");
    println!("  [4]  DTLS 1.2           (Cisco AnyConnect / Corporate TLS mimic - Port 443)");
    println!("  [5]  DNS Query / mDNS   (RFC 6762 / Standard DNS - Bypass ISP Hijack - Port 5353)");
    println!("  [6]  IPsec NAT-T ESP    (Enterprise encrypted IPsec tunnel - RFC 3948 - Port 4500)");
    println!("  [7]  uTP BitTorrent     (P2P File Transfer - IANA BitTorrent Standard - Port 6881)");
    println!("  [8]  RakNet Game Stream (Minecraft / Mobile Gaming - Port 19132)");
    println!("  [9]  STUN / ICE Media   (WebRTC media discovery & NAT traversal - Port 3478)");
    println!("  [10] TURN ChannelData   (Relayed Media Stream - Port 3478)");
    println!("  [11] Steam / Valve      (CS:GO / Dota 2 Gaming - Port 27015)");
    println!("  [12] Valve SDR          (Steam Datagram Relay - CS2 / Deadlock - Port 27020)");
    println!("  [13] Riot Games         (Valorant / LoL Live Game Stream - Port 7500)");
    println!("  [14] Zoom Media         (Enterprise Video Conferencing - Port 8801)");
    println!("  [15] Microsoft RDP      (Enterprise Remote Desktop over UDP - Port 3389)");
    println!("  [16] Discord Voice      (Discord Voice & Opus Media Stream - Port 50000)");
    println!("------------------------------------------------------------------");
    print!("Enter choice [1-16] (Default: 1): ");
    let _ = io::stdout().flush();

    let mut input_prof = String::new();
    let profile = if io::stdin().read_line(&mut input_prof).is_ok() && !input_prof.trim().is_empty() {
        MimicProfile::parse(input_prof.trim()).unwrap_or(MimicProfile::QuicV1)
    } else {
        MimicProfile::QuicV1
    };

    println!("[SELECT] Chosen Protocol: {}\n", profile.display_name());

    let default_port = profile.default_port();
    println!("------------------------------------------------------------------");
    println!("Step 1b: Select Port Configuration for {}:", profile.as_str().to_uppercase());
    println!("  [1] Standard Global Port : {} (Recommended - IANA / Vendor Official)", default_port);
    println!("  [2] Emergency Port 443   : (HTTPS Camouflage - Evades Non-Standard UDP Blocks)");
    println!("  [3] Custom Active Port   : (Allowed server ports: 443, 3478, 19132, 27015, 27020, 7500, 8801, 3389, 50000, 5353, 4500, 6881)");
    println!("------------------------------------------------------------------");
    print!("Enter choice [1-3] (Default: 1 - Port {}): ", default_port);
    let _ = io::stdout().flush();

    let mut input_port_choice = String::new();
    let chosen_port = if io::stdin().read_line(&mut input_port_choice).is_ok() && !input_port_choice.trim().is_empty() {
        match input_port_choice.trim() {
            "2" => 443,
            "3" => {
                print!("Enter custom server port: ");
                let _ = io::stdout().flush();
                let mut custom_p = String::new();
                let _ = io::stdin().read_line(&mut custom_p);
                if let Ok(p) = custom_p.trim().parse::<u16>() {
                    const ACTIVE_PORTS: [u16; 13] = [443, 3478, 19132, 27015, 27020, 7500, 8801, 3389, 50000, 5353, 4500, 6881, 7190];
                    if !ACTIVE_PORTS.contains(&p) {
                        println!("[WARNING] Port {} is not in the server's standard active list. Server might drop if port is not bound.", p);
                    }
                    p
                } else {
                    default_port
                }
            }
            _ => default_port,
        }
    } else {
        default_port
    };

    println!("[SELECT] Chosen Target Port: {}\n", chosen_port);

    println!("------------------------------------------------------------------");
    println!("Step 2: Select Payload Protection Mode:");
    println!("  [1] Protocol-Conforming Shaping (Recommended - Anti-DPI & Shannon Entropy Evasion)");
    println!("  [2] Fast Stream Cipher          (High-Entropy Ciphertext - Protection against sniffing)");
    println!("  [3] Plaintext IP Passthrough    (Maximum Speed for HTTPS/TLS traffic)");
    println!("------------------------------------------------------------------");
    print!("Enter choice [1-3] (Default: 1): ");
    let _ = io::stdout().flush();

    let mut input_mode = String::new();
    let mode = if io::stdin().read_line(&mut input_mode).is_ok() && !input_mode.trim().is_empty() {
        match input_mode.trim() {
            "2" => PayloadMode::StreamCipher,
            "3" => PayloadMode::Plaintext,
            _ => PayloadMode::ShapedDpi,
        }
    } else {
        PayloadMode::ShapedDpi
    };

    println!("[SELECT] Chosen Payload Mode: {}\n", mode.display_name());

    (host, profile, chosen_port, mode)
}

/// Connect using an explicit SubscriptionToken with optional overrides
pub fn run_client_with_token(
    token: &SubscriptionToken,
    port_override: Option<u16>,
    profile_override: Option<MimicProfile>,
    mode_override: Option<PayloadMode>,
    ip_preference: IpPreference,
) -> Result<(), Box<dyn Error>> {
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    if token.is_expired(now) {
        return Err(format!("Subscription token for '{}' has expired! Please renew with administrator.", token.name).into());
    }

    let endpoint = config_manager::resolve_optimal_endpoint(token, ip_preference, port_override)?;
    let profile = profile_override.unwrap_or_else(|| token.mimic_profile());
    let mode = mode_override.unwrap_or_else(|| token.payload_protection_mode());

    println!("==================================================================");
    println!("  Morph Core — Connected Edge Subscription Client");
    println!("  User Profile: {} ({})", token.name, token.user_id);
    println!("  Endpoint    : {}", endpoint);
    println!("  Camouflage  : {}", profile.display_name());
    println!("  Protection  : {}", mode.display_name());
    println!("  Validity    : {}", token.remaining_time_str(now));
    println!("  Data Quota  : {}", token.quota_str());
    println!("==================================================================");

    engine::run_engine(
        &endpoint,
        profile,
        mode,
        token.psk,
        token.assigned_ipv4.as_deref(),
        token.assigned_ipv6.as_deref(),
    )
}

/// Run client with interactive token selection or fallback manual parameters
pub fn run_client(
    server_host: &str,
    host_specified: bool,
    port_override: Option<u16>,
    profile_opt: Option<MimicProfile>,
    mode_opt: Option<PayloadMode>,
    ip_preference: IpPreference,
    psk: [u8; 8],
    token_opt: Option<SubscriptionToken>,
) -> Result<(), Box<dyn Error>> {
    if let Some(token) = token_opt {
        return run_client_with_token(&token, port_override, profile_opt, mode_opt, ip_preference);
    }

    // If host was not explicitly specified via CLI, check saved profiles / prompt for token
    if !host_specified {
        match config_manager::select_or_prompt_token() {
            Ok(selected) => {
                let final_ip_pref = if ip_preference != IpPreference::Auto {
                    ip_preference
                } else {
                    selected.ip_preference
                };
                let final_port = port_override.or(selected.port_override);
                let final_profile = profile_opt.or(selected.profile_override);
                let final_mode = mode_opt.or(selected.payload_mode_override);

                return run_client_with_token(
                    &selected.token,
                    final_port,
                    final_profile,
                    final_mode,
                    final_ip_pref,
                );
            }
            Err(e) => {
                eprintln!("[ERROR] {}", e);
                return Err(e);
            }
        }
    }

    // Manual developer / CLI parameter mode
    let (target_host, profile, target_port, mode) = match (profile_opt, mode_opt) {
        (Some(p), Some(m)) => {
            let port = port_override.unwrap_or_else(|| p.default_port());
            (server_host.to_string(), p, port, m)
        }
        (Some(p), None) => {
            let port = port_override.unwrap_or_else(|| p.default_port());
            (server_host.to_string(), p, port, PayloadMode::ShapedDpi)
        }
        _ => {
            let (h, p, port, m) = prompt_interactive_options(server_host, host_specified);
            let final_port = port_override.unwrap_or(port);
            (h, p, final_port, m)
        }
    };

    let server_endpoint = format!("{}:{}", target_host, target_port);
    engine::run_engine(&server_endpoint, profile, mode, psk, None, None)
}
