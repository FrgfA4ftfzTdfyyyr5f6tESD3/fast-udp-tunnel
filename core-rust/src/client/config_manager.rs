//! Client Configuration & Subscription Profile Manager.
//! Stores, imports, verifies, and updates subscription tokens in `profiles.dat`.
//! Eliminates all hardcoded server IPs, converting the client into a pure credential consumer.

use std::error::Error;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use serde::{Deserialize, Serialize};

use crate::common::SubscriptionToken;
use crate::core::crypto::PayloadMode;
use crate::mimic::MimicProfile;

pub use crate::common::IpPreference;

#[derive(Debug, Clone)]
pub struct SelectedConnection {
    pub token: SubscriptionToken,
    pub ip_preference: IpPreference,
    pub port_override: Option<u16>,
    pub profile_override: Option<MimicProfile>,
    pub payload_mode_override: Option<PayloadMode>,
}

pub const PROFILES_FILENAME: &str = "morph_profiles.dat";
pub const LEGACY_PROFILES_FILENAME: &str = "profiles.dat";

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ClientProfile {
    pub token: SubscriptionToken,
    pub raw_uri: String,
    pub added_at: u64,
}

/// Locate `morph_profiles.dat` in current directory or next to executable (with legacy migration)
pub fn profiles_path() -> PathBuf {
    let cwd_path = Path::new(PROFILES_FILENAME);
    if cwd_path.exists() {
        return cwd_path.to_path_buf();
    }

    // Auto-migrate from legacy profiles.dat if present in CWD
    let legacy_cwd = Path::new(LEGACY_PROFILES_FILENAME);
    if legacy_cwd.exists() {
        let _ = fs::copy(legacy_cwd, cwd_path);
        return cwd_path.to_path_buf();
    }

    if let Ok(exe_path) = std::env::current_exe() {
        if let Some(parent) = exe_path.parent() {
            let next_to_exe = parent.join(PROFILES_FILENAME);
            if next_to_exe.exists() {
                return next_to_exe;
            }
            let legacy_exe = parent.join(LEGACY_PROFILES_FILENAME);
            if legacy_exe.exists() {
                let _ = fs::copy(&legacy_exe, &next_to_exe);
                return next_to_exe;
            }
        }
    }
    Path::new(PROFILES_FILENAME).to_path_buf()
}

/// Load all saved subscription profiles from `profiles.dat`
pub fn load_profiles() -> Vec<ClientProfile> {
    let path = profiles_path();
    if !path.exists() {
        return Vec::new();
    }

    match fs::read_to_string(&path) {
        Ok(content) => serde_json::from_str::<Vec<ClientProfile>>(&content).unwrap_or_default(),
        Err(_) => Vec::new(),
    }
}

/// Save profiles to `profiles.dat` atomically via temporary file replacement
pub fn save_profiles(profiles: &[ClientProfile]) -> Result<(), String> {
    let path = profiles_path();
    let json = serde_json::to_string_pretty(profiles)
        .map_err(|e| format!("Serialization error: {}", e))?;
    let tmp_path = path.with_extension("tmp");
    fs::write(&tmp_path, json).map_err(|e| format!("Failed to write temporary profiles to {:?}: {}", tmp_path, e))?;
    fs::rename(&tmp_path, &path).map_err(|e| format!("Failed to atomically replace profiles at {:?}: {}", path, e))?;
    Ok(())
}

/// Import a new `fudp://` subscription token into `profiles.dat`
pub fn import_token(uri: &str) -> Result<ClientProfile, String> {
    let token = SubscriptionToken::from_uri(uri)?;
    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let mut profiles = load_profiles();

    // Check if profile for this user ID already exists, update if found
    let mut updated = false;
    let new_profile = ClientProfile {
        token: token.clone(),
        raw_uri: uri.trim().to_string(),
        added_at: now,
    };

    for p in profiles.iter_mut() {
        if p.token.user_id == token.user_id {
            *p = new_profile.clone();
            updated = true;
            break;
        }
    }

    if !updated {
        profiles.push(new_profile.clone());
    }

    save_profiles(&profiles)?;
    Ok(new_profile)
}

/// Delete a profile by 1-based index
pub fn delete_profile(index: usize) -> Result<ClientProfile, String> {
    let mut profiles = load_profiles();
    if index == 0 || index > profiles.len() {
        return Err(format!("Invalid profile index: {}", index));
    }
    let removed = profiles.remove(index - 1);
    save_profiles(&profiles)?;
    Ok(removed)
}

/// Print formatted table of saved profiles
pub fn print_profile_list(profiles: &[ClientProfile]) {
    println!("=========================================================================================================");
    println!("  #  | Profile Name        | Target Host / IP       | Port  | Camouflage | Mode     | Remaining   | Quota");
    println!("=========================================================================================================");

    let now = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    for (idx, p) in profiles.iter().enumerate() {
        let t = &p.token;
        let host_display = if let Some(ref v6) = t.server_v6 {
            v6.clone()
        } else if let Some(ref v4) = t.server_v4 {
            v4.clone()
        } else {
            "Unknown".to_string()
        };

        let host_trunc = if host_display.chars().count() > 22 {
            format!("{}...", host_display.chars().take(19).collect::<String>())
        } else {
            host_display
        };

        let name_trunc = if t.name.chars().count() > 19 {
            format!("{}...", t.name.chars().take(16).collect::<String>())
        } else {
            t.name.clone()
        };

        println!(
            " [{:>1}] | {:<19} | {:<22} | {:<5} | {:<10} | {:<8} | {:<11} | {:<8}",
            idx + 1,
            name_trunc,
            host_trunc,
            t.port,
            t.mimic_profile().as_str().to_uppercase(),
            t.payload_protection_mode().as_str(),
            t.remaining_time_str(now),
            t.quota_str()
        );
    }
    println!("---------------------------------------------------------------------------------------------------------");
}

fn prompt_profile_options(token: SubscriptionToken) -> Result<SelectedConnection, Box<dyn Error>> {
    println!("\n[>] Selected Profile: '{}' ({})", token.name, token.user_id);
    println!("  [Enter / 1] Connect immediately with default settings");
    println!("  [2] Customize connection (IP version, protocol, port, encryption)");
    print!("Choose [1]: ");
    let _ = io::stdout().flush();

    let mut choice = String::new();
    io::stdin().read_line(&mut choice)?;
    let trimmed = choice.trim();

    if trimmed == "2" || trimmed.eq_ignore_ascii_case("c") || trimmed.eq_ignore_ascii_case("custom") {
        println!("\n--- Custom Connection Parameters ---");
        // 1. IP preference
        println!("Select IP Version:");
        println!("  [1] Auto (Prefer IPv6, fallback IPv4)");
        println!("  [2] Force IPv4");
        println!("  [3] Force IPv6");
        print!("Choice [1]: ");
        let _ = io::stdout().flush();
        let mut ip_choice = String::new();
        io::stdin().read_line(&mut ip_choice)?;
        let ip_pref = match ip_choice.trim() {
            "2" | "4" | "v4" => IpPreference::ForceV4,
            "3" | "6" | "v6" => IpPreference::ForceV6,
            _ => IpPreference::Auto,
        };

        // 2. Camouflage Protocol
        println!("\nSelect Camouflage Protocol (or press Enter to keep '{}'):", token.mimic_profile().display_name());
        for (idx, p) in MimicProfile::ALL.iter().enumerate() {
            println!("  [{:>2}] {:<18} ({})", idx + 1, p.display_name(), p.as_str());
        }
        print!("Choice [Enter = keep default]: ");
        let _ = io::stdout().flush();
        let mut prof_choice = String::new();
        io::stdin().read_line(&mut prof_choice)?;
        let prof_trimmed = prof_choice.trim();
        let profile_override = if prof_trimmed.is_empty() {
            None
        } else if let Ok(idx) = prof_trimmed.parse::<usize>() {
            MimicProfile::from_1_based_index(idx)
        } else {
            MimicProfile::parse(prof_trimmed)
        };

        // 3. Port override
        println!("\nTunnel Port Override (or press Enter to keep default: {}):", token.port);
        print!("Port: ");
        let _ = io::stdout().flush();
        let mut port_in = String::new();
        io::stdin().read_line(&mut port_in)?;
        let port_override = port_in.trim().parse::<u16>().ok();

        // 4. Payload mode
        println!("\nPayload Protection Mode (or press Enter to keep '{}'):", token.payload_protection_mode().display_name());
        println!("  [1] Protocol-Conforming Shaping (Recommended - Anti-DPI & Shannon Entropy Evasion)");
        println!("  [2] Fast Stream Cipher          (High-Entropy Ciphertext - Fast line encryption)");
        println!("  [3] Plaintext IP Passthrough    (Maximum Line Speed / Zero Crypto Overhead)");
        print!("Choice [Enter = keep default]: ");
        let _ = io::stdout().flush();
        let mut mode_in = String::new();
        io::stdin().read_line(&mut mode_in)?;
        let payload_mode_override = if mode_in.trim().is_empty() {
            None
        } else {
            PayloadMode::parse(mode_in.trim())
        };

        Ok(SelectedConnection {
            token,
            ip_preference: ip_pref,
            port_override,
            profile_override,
            payload_mode_override,
        })
    } else {
        Ok(SelectedConnection {
            token,
            ip_preference: IpPreference::Auto,
            port_override: None,
            profile_override: None,
            payload_mode_override: None,
        })
    }
}

/// Interactively select or import a subscription token
pub fn select_or_prompt_token() -> Result<SelectedConnection, Box<dyn Error>> {
    loop {
        let profiles = load_profiles();
        if profiles.is_empty() {
            println!("==================================================================");
            println!("  Morph Core — Edge Client Connection Manager (v8.5)");
            println!("==================================================================");
            println!("[NOTICE] No saved subscription profiles found in 'morph_profiles.dat'.");
            println!("Please paste your encrypted subscription token (morph://...):");
            print!("> ");
            let _ = io::stdout().flush();

            let mut input = String::new();
            io::stdin().read_line(&mut input)?;
            let token_str = input.trim();
            if token_str.is_empty() {
                return Err("No subscription token provided. Exiting.".into());
            }

            match import_token(token_str) {
                Ok(p) => {
                    println!("[SUCCESS] Imported Profile: '{}' (User: {})", p.token.name, p.token.user_id);
                    return prompt_profile_options(p.token);
                }
                Err(e) => {
                    eprintln!("[ERROR] {}", e);
                    continue;
                }
            }
        }

        println!("=========================================================================================================");
        println!("  Morph Core — Saved Subscription Profiles");
        print_profile_list(&profiles);
        println!("  [+] Import a new morph:// subscription token");
        println!("  [-] Delete a saved profile");
        println!("  [q] Quit");
        println!("---------------------------------------------------------------------------------------------------------");
        print!("Select profile [1-{}] or option: ", profiles.len());
        let _ = io::stdout().flush();

        let mut choice = String::new();
        io::stdin().read_line(&mut choice)?;
        let trimmed = choice.trim();

        if trimmed.eq_ignore_ascii_case("q") {
            return Err("Operation cancelled by user.".into());
        }

        if trimmed == "+" || trimmed.eq_ignore_ascii_case("import") {
            print!("Paste your morph:// token: ");
            let _ = io::stdout().flush();
            let mut tok_in = String::new();
            io::stdin().read_line(&mut tok_in)?;
            match import_token(tok_in.trim()) {
                Ok(p) => {
                    println!("[SUCCESS] Imported: '{}' (User: {})", p.token.name, p.token.user_id);
                    return prompt_profile_options(p.token);
                }
                Err(e) => {
                    eprintln!("[ERROR] {}", e);
                }
            }
            continue;
        }

        if trimmed == "-" || trimmed.eq_ignore_ascii_case("delete") {
            print!("Enter profile # to delete [1-{}]: ", profiles.len());
            let _ = io::stdout().flush();
            let mut del_in = String::new();
            io::stdin().read_line(&mut del_in)?;
            if let Ok(idx) = del_in.trim().parse::<usize>() {
                match delete_profile(idx) {
                    Ok(p) => println!("[SUCCESS] Deleted profile '{}'", p.token.name),
                    Err(e) => eprintln!("[ERROR] {}", e),
                }
            }
            continue;
        }

        if let Ok(idx) = trimmed.parse::<usize>() {
            if idx >= 1 && idx <= profiles.len() {
                let token = profiles[idx - 1].token.clone();
                return prompt_profile_options(token);
            }
        }

        // Check if user directly pasted a morph:// or fudp:// token into the prompt
        if trimmed.starts_with("morph://") || trimmed.starts_with("MORPH://") || trimmed.starts_with("fudp://") || trimmed.starts_with("FUDP://") {
            match import_token(trimmed) {
                Ok(p) => {
                    println!("[SUCCESS] Imported & Selected: '{}'", p.token.name);
                    return prompt_profile_options(p.token);
                }
                Err(e) => eprintln!("[ERROR] {}", e),
            }
        }

        println!("[WARN] Invalid selection. Please choose an option from the menu.");
    }
}

/// Automatically select the optimal remote endpoint (IPv6 preferred, IPv4 fallback, or forced by preference)
pub fn resolve_optimal_endpoint(
    token: &SubscriptionToken,
    ip_preference: IpPreference,
    port_override: Option<u16>,
) -> Result<String, Box<dyn Error>> {
    let port = port_override.unwrap_or(token.port);

    match ip_preference {
        IpPreference::ForceV4 => {
            if let Some(ref v4_host) = token.server_v4 {
                return Ok(format!("{}:{}", v4_host.trim(), port));
            } else {
                return Err("IPv4 forced via CLI/option, but token does not contain a server IPv4 address!".into());
            }
        }
        IpPreference::ForceV6 => {
            if let Some(ref v6_host) = token.server_v6 {
                let clean = v6_host.trim();
                let formatted = if clean.starts_with('[') && clean.ends_with(']') {
                    clean.to_string()
                } else {
                    format!("[{}]", clean)
                };
                return Ok(format!("{}:{}", formatted, port));
            } else {
                return Err("IPv6 forced via CLI/option, but token does not contain a server IPv6 address!".into());
            }
        }
        IpPreference::Auto => {
            let has_v6 = token.server_v6.is_some();
            let has_v4 = token.server_v4.is_some();

            if !has_v6 && !has_v4 {
                return Err("Token does not contain any server IP addresses (v4 or v6)".into());
            }

            // Check if client machine has active physical IPv6 gateway
            let (_phys_v4, phys_v6) = crate::client::routing::TunnelRoutes::detect_physical_gateways();

            if let (true, Some(ref v6_host)) = (phys_v6.is_some(), &token.server_v6) {
                let clean = v6_host.trim();
                let formatted = if clean.starts_with('[') && clean.ends_with(']') {
                    clean.to_string()
                } else {
                    format!("[{}]", clean)
                };
                return Ok(format!("{}:{}", formatted, port));
            }

            // Fallback to IPv4
            if let Some(ref v4_host) = token.server_v4 {
                return Ok(format!("{}:{}", v4_host.trim(), port));
            }

            // If only IPv6 was in token but client has no local IPv6 default route, attempt IPv6 anyway
            if let Some(ref v6_host) = token.server_v6 {
                let clean = v6_host.trim();
                let formatted = if clean.starts_with('[') && clean.ends_with(']') {
                    clean.to_string()
                } else {
                    format!("[{}]", clean)
                };
                return Ok(format!("{}:{}", formatted, port));
            }

            Err("Could not resolve valid endpoint from token".into())
        }
    }
}
