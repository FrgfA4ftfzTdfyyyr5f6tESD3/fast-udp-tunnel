//! Ubuntu & Debian Full-Linux Specialized Adaptation Module.
//! Handles full-featured systemd environments: high-throughput UDP memory allocation,
//! firewall backend auto-detection (nftables vs iptables-nft), and MSS Clamping.

use std::process::Command;
use super::common::write_proc_sys;
use super::detector::EnvironmentInfo;
use super::alpine::detect_default_interface;

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

pub fn tune_debian(env: &EnvironmentInfo) {
    println!("[TUNER] Applying Ubuntu/Debian Full-Linux Optimizations...");

    // 1. High-Throughput Kernel Memory Allocation for UDP
    let _ = write_proc_sys("net/ipv4/udp_mem", "65536 131072 262144");
    let _ = write_proc_sys("net/core/optmem_max", "2097152");
    let _ = write_proc_sys("net/ipv4/udp_rmem_min", "16384");
    let _ = write_proc_sys("net/ipv4/udp_wmem_min", "16384");
    println!("  -> [DEBIAN/UBUNTU] High-Throughput udp_mem & optmem_max tuned");

    // 2. Detect Egress Network Interface
    let egress_if = detect_default_interface();
    println!("  -> [DEBIAN/UBUNTU] Detected Outbound Interface: {}", egress_if);

    // 3. Detect Firewall backend (nftables vs iptables)
    let has_nft = Command::new("nft").arg("--version").status().map_or(false, |s| s.success());
    if has_nft {
        println!("  -> [DEBIAN/UBUNTU] Firewall Backend: nftables-capable (using nft-compatible rules)");
    } else {
        println!("  -> [DEBIAN/UBUNTU] Firewall Backend: standard iptables");
    }

    // 4. Idempotent NAT (MASQUERADE) & MSS Clamping
    iptables_ensure("iptables", "nat", "POSTROUTING", &["-s", "10.8.0.0/24", "-o", &egress_if, "-j", "MASQUERADE"]);
    // Clean stale DNAT rules so in-tunnel dnsmasq handles port 53 directly
    iptables_del("iptables", "nat", "PREROUTING", &["-i", "tun0", "-p", "udp", "--dport", "53", "-j", "DNAT", "--to-destination", "1.1.1.1:53"]);
    iptables_del("iptables", "nat", "PREROUTING", &["-i", "tun0", "-p", "tcp", "--dport", "53", "-j", "DNAT", "--to-destination", "1.1.1.1:53"]);
    iptables_ensure("iptables", "filter", "FORWARD", &["-i", "tun0", "-j", "ACCEPT"]);
    iptables_ensure("iptables", "filter", "FORWARD", &["-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"]);

    // Clean legacy TCP MSS Clamping (superseded by Tunnel-Level Micro-Segmentation)
    iptables_del("iptables", "mangle", "FORWARD", &["-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"]);

    // IPv6 Rules
    iptables_del("ip6tables", "nat", "POSTROUTING", &["-s", "fd00::/64", "-o", &egress_if, "-j", "MASQUERADE"]);
    iptables_ensure("ip6tables", "nat", "POSTROUTING", &["-s", "fd00:8:0::/64", "-o", &egress_if, "-j", "MASQUERADE"]);
    iptables_del("ip6tables", "nat", "PREROUTING", &["-i", "tun0", "-p", "udp", "--dport", "53", "-j", "DNAT", "--to-destination", "[2606:4700:4700::1111]:53"]);
    iptables_del("ip6tables", "nat", "PREROUTING", &["-i", "tun0", "-p", "tcp", "--dport", "53", "-j", "DNAT", "--to-destination", "[2606:4700:4700::1111]:53"]);
    iptables_ensure("ip6tables", "filter", "FORWARD", &["-i", "tun0", "-j", "ACCEPT"]);
    iptables_ensure("ip6tables", "filter", "FORWARD", &["-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"]);
    iptables_ensure("ip6tables", "filter", "FORWARD", &["-p", "icmpv6", "--icmpv6-type", "packet-too-big", "-j", "ACCEPT"]);
    iptables_ensure("ip6tables", "filter", "INPUT", &["-p", "icmpv6", "--icmpv6-type", "packet-too-big", "-j", "ACCEPT"]);
    iptables_del("ip6tables", "mangle", "FORWARD", &["-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--clamp-mss-to-pmtu"]);

    println!("  -> [DEBIAN/UBUNTU] Full-stack network optimizations applied (Init: {})", env.init_system.as_str());
}
