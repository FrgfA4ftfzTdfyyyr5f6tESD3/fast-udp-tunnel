//! Universal Kernel Tuning Module (Common across all Linux distributions).
//! Configures core routing forwarding and TCP congestion control without duplicate buffer writes.

use super::detector::EnvironmentInfo;
pub use crate::common::write_proc_sys;

pub fn tune_universal_kernel(_env: &EnvironmentInfo) {
    println!("[TUNER] Applying Universal Linux Kernel & Network Routing Tuning...");

    // 1. Enable IPv4 and IPv6 IP Forwarding
    let v4_fwd = write_proc_sys("net/ipv4/ip_forward", "1");
    let v6_fwd = write_proc_sys("net/ipv6/conf/all/forwarding", "1");
    let _ = write_proc_sys("net/ipv4/conf/all/send_redirects", "0");
    let _ = write_proc_sys("net/ipv4/conf/default/send_redirects", "0");
    println!("  -> Kernel IP Routing: IPv4 Forwarding={}, IPv6 Forwarding={}", v4_fwd, v6_fwd);

    // 2. Fair Queue (FQ) & BBR Congestion Control (if supported by kernel)
    let fq_ok = write_proc_sys("net/core/default_qdisc", "fq");
    let bbr_ok = write_proc_sys("net/ipv4/tcp_congestion_control", "bbr");
    if fq_ok && bbr_ok {
        println!("  -> TCP Congestion Control: FQ + BBR enabled");
    } else {
        println!("  -> TCP Congestion Control: Standard (Cubic/Default)");
    }
}
