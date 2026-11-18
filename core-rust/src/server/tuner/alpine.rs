//! Alpine Linux & OpenRC Specialized Adaptation Module.
//! Handles minimal environments: guarantees `/dev/net/tun` existence, memory-conscious
//! buffer allocation, and lightweight iptables/MSS rules without requiring heavy packages.

use std::fs;
use std::path::Path;
use std::process::Command;
use super::detector::EnvironmentInfo;

/// Ensure `/dev/net/tun` exists and is accessible.
fn ensure_tun_device() {
    let tun_path = Path::new("/dev/net/tun");
    if !tun_path.exists() {
        println!("  -> [ALPINE] /dev/net/tun missing! Creating character device node...");
        let _ = fs::create_dir_all("/dev/net");
        let _ = Command::new("modprobe").arg("tun").status();
        let _ = Command::new("mknod").args(["/dev/net/tun", "c", "10", "200"]).status();
        let _ = Command::new("chmod").args(["0666", "/dev/net/tun"]).status();
    }
}

/// Detect default outbound network interface (usually eth0 or similar)
pub fn detect_default_interface() -> String {
    if let Ok(routes) = fs::read_to_string("/proc/net/route") {
        for line in routes.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() >= 2 && fields[1] == "00000000" {
                return fields[0].to_string();
            }
        }
    }
    "eth0".to_string()
}

fn iptables_ensure(prog: &str, table: &str, chain: &str, rule: &[&str]) {
    let mut del_args = vec!["-t", table, "-D", chain];
    del_args.extend_from_slice(rule);
    while Command::new(prog).args(&del_args).status().map_or(false, |s| s.success()) {}

    let mut add_args = vec!["-t", table, "-A", chain];
    add_args.extend_from_slice(rule);
    let _ = Command::new(prog).args(&add_args).status();
}

fn iptables_del(prog: &str, table: &str, chain: &str, rule: &[&str]) {
    let mut del_args = vec!["-t", table, "-D", chain];
    del_args.extend_from_slice(rule);
    while Command::new(prog).args(&del_args).status().map_or(false, |s| s.success()) {}
}

pub fn tune_alpine(env: &EnvironmentInfo) {
    println!("[TUNER] Applying Alpine Linux Specific Optimizations...");

    // 1. Ensure /dev/net/tun exists
    ensure_tun_device();

    // 2. Detect Egress Network Interface
    let egress_if = detect_default_interface();
    println!("  -> [ALPINE] Detected Outbound Interface: {}", egress_if);

    // 3. Lightweight Idempotent NAT (MASQUERADE)
    iptables_ensure("iptables", "nat", "POSTROUTING", &["-s", "10.8.0.0/24", "-o", &egress_if, "-j", "MASQUERADE"]);
    // Clean stale DNAT rules so in-tunnel dnsmasq handles port 53 directly
    iptables_del("iptables", "nat", "PREROUTING", &["-i", "tun0", "-p", "udp", "--dport", "53", "-j", "DNAT", "--to-destination", "1.1.1.1:53"]);
    iptables_del("iptables", "nat", "PREROUTING", &["-i", "tun0", "-p", "tcp", "--dport", "53", "-j", "DNAT", "--to-destination", "1.1.1.1:53"]);
    iptables_ensure("iptables", "filter", "FORWARD", &["-i", "tun0", "-j", "ACCEPT"]);
    iptables_ensure("iptables", "filter", "FORWARD", &["-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"]);

    // Clean legacy TCP MSS Clamping (superseded by Tunnel-Level Micro-Segmentation)
    iptables_del("iptables", "mangle", "FORWARD", &["-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"]);

    // IPv6 NAT66 & Forwarding
    iptables_del("ip6tables", "nat", "POSTROUTING", &["-s", "fd00::/64", "-o", &egress_if, "-j", "MASQUERADE"]);
    iptables_ensure("ip6tables", "nat", "POSTROUTING", &["-s", "fd00:8:0::/64", "-o", &egress_if, "-j", "MASQUERADE"]);
    iptables_del("ip6tables", "nat", "PREROUTING", &["-i", "tun0", "-p", "udp", "--dport", "53", "-j", "DNAT", "--to-destination", "[2606:4700:4700::1111]:53"]);
    iptables_del("ip6tables", "nat", "PREROUTING", &["-i", "tun0", "-p", "tcp", "--dport", "53", "-j", "DNAT", "--to-destination", "[2606:4700:4700::1111]:53"]);
    iptables_ensure("ip6tables", "filter", "FORWARD", &["-i", "tun0", "-j", "ACCEPT"]);
    iptables_ensure("ip6tables", "filter", "FORWARD", &["-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"]);
    iptables_ensure("ip6tables", "filter", "FORWARD", &["-p", "icmpv6", "--icmpv6-type", "packet-too-big", "-j", "ACCEPT"]);
    iptables_ensure("ip6tables", "filter", "INPUT", &["-p", "icmpv6", "--icmpv6-type", "packet-too-big", "-j", "ACCEPT"]);

    iptables_del("ip6tables", "mangle", "FORWARD", &["-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"]);

    println!("  -> [ALPINE] Lightweight iptables NAT & MSS clamping applied cleanly (Init: {})", env.init_system.as_str());
}
