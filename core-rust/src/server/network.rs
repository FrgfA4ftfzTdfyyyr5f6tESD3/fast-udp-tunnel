//! Idempotent Linux network configuration, iptables NAT/NAT66 rules,
//! and sysctl IP forwarding for multi-user tunnel.

use std::process::Command;
use crate::core::{TCP_MSS_IPV4, TCP_MSS_IPV6};

fn iptables_ensure_rule(prog: &str, table: &str, chain: &str, rule: &[&str]) {
    let mut check_args = vec!["-t", table, "-C", chain];
    check_args.extend_from_slice(rule);
    let check_status = Command::new(prog).args(&check_args).status();
    if check_status.map_or(false, |s| s.success()) {
        return; // rule already exists
    }
    let mut add_args = vec!["-t", table, "-A", chain];
    add_args.extend_from_slice(rule);
    let _ = Command::new(prog).args(&add_args).status();
}

pub fn configure_server_network() {
    // Enable Linux kernel IP routing (both IPv4 and IPv6)
    let _ = Command::new("sysctl").args(["-w", "net.ipv4.ip_forward=1"]).status();
    let _ = Command::new("sysctl").args(["-w", "net.ipv6.conf.all.forwarding=1"]).status();
    let _ = Command::new("sysctl").args(["-w", "net.ipv4.conf.all.send_redirects=0"]).status();

    let max_mtu = crate::common::MAX_TUNNEL_MTU;
    let _ = Command::new("ip").args(["link", "set", "dev", "tun0", "mtu", &format!("{}", max_mtu)]).status();
    let _ = Command::new("ip").args(["link", "set", "dev", "tun0", "txqueuelen", "10000"]).status();
    let _ = Command::new("ip").args(["link", "set", "dev", "tun0", "up"]).status();
    let _ = Command::new("ip").args(["addr", "add", "10.8.0.1/24", "dev", "tun0"]).status();
    let _ = Command::new("ip").args(["-6", "addr", "add", "fd00:8:0::1/64", "dev", "tun0"]).status();
    let _ = Command::new("ip").args(["route", "replace", "10.8.0.0/24", "dev", "tun0", "mtu", "lock", &format!("{}", max_mtu)]).status();
    let _ = Command::new("ip").args(["-6", "route", "replace", "fd00:8:0::/64", "dev", "tun0", "mtu", "lock", &format!("{}", max_mtu)]).status();

    let _ = Command::new("tc").args(["qdisc", "del", "dev", "tun0", "root"]).status();

    // Idempotent IPv4 NAT & Forwarding
    // Enforce In-Tunnel DNS: Redirect any port 53 DNS queries on tun0 directly into dnsmasq
    iptables_ensure_rule("iptables", "nat", "PREROUTING", &["-i", "tun0", "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", "53"]);
    iptables_ensure_rule("iptables", "nat", "PREROUTING", &["-i", "tun0", "-p", "tcp", "--dport", "53", "-j", "REDIRECT", "--to-ports", "53"]);
    iptables_ensure_rule("iptables", "nat", "POSTROUTING", &["-s", "10.8.0.0/24", "-o", "eth0", "-j", "MASQUERADE"]);
    iptables_ensure_rule("iptables", "filter", "FORWARD", &["-i", "tun0", "-j", "ACCEPT"]);
    iptables_ensure_rule("iptables", "filter", "FORWARD", &["-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"]);

    let mss_v4_str = format!("{}", TCP_MSS_IPV4);
    let _ = Command::new("iptables").args(["-t", "mangle", "-F", "FORWARD"]).status();
    let _ = Command::new("iptables").args(["-t", "mangle", "-A", "FORWARD", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--set-mss", &mss_v4_str]).status();

    // Idempotent IPv6 NAT66 & Forwarding
    // Enforce In-Tunnel DNS: Redirect any port 53 DNS queries on tun0 directly into dnsmasq
    iptables_ensure_rule("ip6tables", "nat", "PREROUTING", &["-i", "tun0", "-p", "udp", "--dport", "53", "-j", "REDIRECT", "--to-ports", "53"]);
    iptables_ensure_rule("ip6tables", "nat", "PREROUTING", &["-i", "tun0", "-p", "tcp", "--dport", "53", "-j", "REDIRECT", "--to-ports", "53"]);
    iptables_ensure_rule("ip6tables", "nat", "POSTROUTING", &["-s", "fd00:8:0::/64", "-o", "eth0", "-j", "MASQUERADE"]);
    iptables_ensure_rule("ip6tables", "filter", "FORWARD", &["-i", "tun0", "-j", "ACCEPT"]);
    iptables_ensure_rule("ip6tables", "filter", "FORWARD", &["-m", "state", "--state", "RELATED,ESTABLISHED", "-j", "ACCEPT"]);
    iptables_ensure_rule("ip6tables", "filter", "FORWARD", &["-p", "icmpv6", "--icmpv6-type", "packet-too-big", "-j", "ACCEPT"]);
    iptables_ensure_rule("ip6tables", "filter", "INPUT", &["-p", "icmpv6", "--icmpv6-type", "packet-too-big", "-j", "ACCEPT"]);

    let mss_v6_str = format!("{}", TCP_MSS_IPV6);
    let _ = Command::new("ip6tables").args(["-t", "mangle", "-F", "FORWARD"]).status();
    let _ = Command::new("ip6tables").args(["-t", "mangle", "-A", "FORWARD", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--set-mss", &mss_v6_str]).status();

    // If dnsmasq service is installed, restart it so it binds immediately to 10.8.0.1 & fd00:8:0::1 on tun0
    let _ = Command::new("rc-service").args(["dnsmasq", "restart"]).status();
}

/// Dynamically update tun0 interface MTU and TCP MSS clamping on client negotiation
#[allow(dead_code)]
pub fn update_tun_mtu_and_mss(mtu: u32) {
    let _ = Command::new("ip").args(["link", "set", "dev", "tun0", "mtu", &format!("{}", mtu)]).status();
    let _ = Command::new("ip").args(["route", "replace", "10.8.0.0/24", "dev", "tun0", "mtu", "lock", &format!("{}", mtu)]).status();
    let _ = Command::new("ip").args(["-6", "route", "replace", "fd00:8:0::/64", "dev", "tun0", "mtu", "lock", &format!("{}", mtu)]).status();

    let mss_v4 = (mtu.saturating_sub(40)) as u16;
    let mss_v6 = (mtu.saturating_sub(60)) as u16;

    let _ = Command::new("iptables").args(["-t", "mangle", "-F", "FORWARD"]).status();
    let _ = Command::new("iptables").args(["-t", "mangle", "-A", "FORWARD", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--set-mss", &format!("{}", mss_v4)]).status();

    let _ = Command::new("ip6tables").args(["-t", "mangle", "-F", "FORWARD"]).status();
    let _ = Command::new("ip6tables").args(["-t", "mangle", "-A", "FORWARD", "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN", "-j", "TCPMSS", "--set-mss", &format!("{}", mss_v6)]).status();
}
