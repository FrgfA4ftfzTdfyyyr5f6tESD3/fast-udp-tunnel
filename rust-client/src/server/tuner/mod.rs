//! Server Auto-Tuner & OS Adaptation Subsystem.
//! Automatically detects Linux distribution, init system (OpenRC vs systemd),
//! and hardware resources (RAM/CPU), applying optimized kernel and networking parameters.

pub mod alpine;
pub mod common;
pub mod debian;
pub mod detector;

use std::process::Command;
use crate::common::SERVER_TUN_CEILING_MTU;
pub use detector::{detect_environment, EnvironmentInfo, MemoryTier, InitSystem};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OsProfile {
    Auto,
    Alpine,
    DebianUbuntu,
    Generic,
}

impl OsProfile {
    pub fn as_str(&self) -> &'static str {
        match self {
            OsProfile::Auto => "auto",
            OsProfile::Alpine => "alpine",
            OsProfile::DebianUbuntu => "debian",
            OsProfile::Generic => "generic",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.trim().to_ascii_lowercase().as_str() {
            "auto" => Some(OsProfile::Auto),
            "alpine" | "alpine-linux" | "openrc" => Some(OsProfile::Alpine),
            "debian" | "ubuntu" | "debianubuntu" | "systemd" => Some(OsProfile::DebianUbuntu),
            "generic" | "fallback" => Some(OsProfile::Generic),
            _ => None,
        }
    }
}

pub fn apply_pre_tun_tuning(configured_profile: OsProfile) -> (OsProfile, EnvironmentInfo) {
    let env = detect_environment();

    let resolved_profile = match configured_profile {
        OsProfile::Auto => {
            if env.is_alpine {
                OsProfile::Alpine
            } else if env.is_debian_ubuntu {
                OsProfile::DebianUbuntu
            } else {
                OsProfile::Generic
            }
        }
        manual => manual,
    };

    println!("==================================================================");
    println!("  Server Auto-Tuner & OS Adaptation Subsystem");
    println!("==================================================================");
    println!("[TUNER] Host Distribution : {} (id: {})", env.distro_name, env.distro_id);
    println!("[TUNER] Init System       : {}", env.init_system.as_str());
    println!("[TUNER] Hardware Specs    : {} MB RAM ({} Cores | {})", env.total_ram_mb, env.cpu_cores, env.memory_tier.as_str());
    println!("[TUNER] Applied Profile   : {:?} (Config: {:?})", resolved_profile, configured_profile);
    println!("------------------------------------------------------------------");

    // 1. Universal Kernel & Socket Tuning
    common::tune_universal_kernel(&env);

    // 2. Distribution-Specific Tuning & Firewall Configuration
    match resolved_profile {
        OsProfile::Alpine => {
            alpine::tune_alpine(&env);
        }
        OsProfile::DebianUbuntu => {
            debian::tune_debian(&env);
        }
        OsProfile::Generic | OsProfile::Auto => {
            alpine::tune_alpine(&env);
        }
    }

    (resolved_profile, env)
}

pub fn configure_tun_interface() {
    println!("[TUNER] Configuring tun0 Interface & Routing...");
    let _ = Command::new("ip").args(["link", "set", "dev", "tun0", "mtu", &format!("{}", SERVER_TUN_CEILING_MTU)]).status();
    let _ = Command::new("ip").args(["link", "set", "dev", "tun0", "txqueuelen", "10000"]).status();
    let _ = Command::new("ip").args(["link", "set", "dev", "tun0", "up"]).status();
    let _ = Command::new("ip").args(["addr", "add", "10.8.0.1/24", "dev", "tun0"]).status();
    let _ = Command::new("ip").args(["-6", "addr", "del", "fd00::1/64", "dev", "tun0"]).status();
    let _ = Command::new("ip").args(["-6", "addr", "add", "fd00:8:0::1/64", "dev", "tun0"]).status();
    let _ = Command::new("ip").args(["route", "replace", "10.8.0.0/24", "dev", "tun0", "mtu", "lock", &format!("{}", SERVER_TUN_CEILING_MTU)]).status();
    let _ = Command::new("ip").args(["-6", "route", "del", "fd00::/64", "dev", "tun0"]).status();
    let _ = Command::new("ip").args(["-6", "route", "replace", "fd00:8:0::/64", "dev", "tun0", "mtu", "lock", &format!("{}", SERVER_TUN_CEILING_MTU)]).status();
    let _ = Command::new("tc").args(["qdisc", "del", "dev", "tun0", "root"]).status();

    // Restart dnsmasq if installed so it binds immediately to 10.8.0.1:53 & fd00:8:0::1:53 on tun0
    let _ = Command::new("rc-service").args(["dnsmasq", "restart"]).status();
    let _ = Command::new("systemctl").args(["restart", "dnsmasq"]).status();

    println!("  -> [TUN0] IP Addresses assigned (10.8.0.1/24 & fd00:8:0::1/64), Interface UP, Kernel Ceiling MTU: {}", SERVER_TUN_CEILING_MTU);
    println!("==================================================================\n");
}

pub fn apply_system_tuning(configured_profile: OsProfile) {
    let _ = apply_pre_tun_tuning(configured_profile);
    configure_tun_interface();
}
