//! Clean, cross-platform friendly Windows routing table automation,
//! RFC 6724 IPv6 Precedence elevation for clean AI/Gemini traffic,
//! Zero-Leak Firewall barrier, and physical gateway protection.

use std::process::Command;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[allow(non_snake_case)]
struct NetRouteEntry {
    NextHop: String,
    InterfaceIndex: u32,
}

#[derive(Clone)]
pub struct TunnelRoutes {
    pub wintun_if_index: u32,
    pub server_host: String,
    pub physical_v6: Option<(u32, String)>,
    pub physical_v4: Option<(u32, String)>,
}

impl TunnelRoutes {
    pub fn new(
        wintun_if_index: u32,
        server_host: String,
        physical_v6: Option<(u32, String)>,
        physical_v4: Option<(u32, String)>,
    ) -> Self {
        Self {
            wintun_if_index,
            server_host,
            physical_v6,
            physical_v4,
        }
    }

    /// Automatically discover default gateway interface index and next-hop IPs
    pub fn detect_physical_gateways() -> (Option<(u32, String)>, Option<(u32, String)>) {
        let mut phys_v4 = None;
        let mut phys_v6 = None;

        // 1. Detect IPv4 Default Route with lowest metric (physical primary interface)
        let out_v4 = Command::new("powershell")
            .args(["-NoProfile", "-Command", "Get-NetRoute -DestinationPrefix '0.0.0.0/0' | Sort-Object RouteMetric | Select-Object -First 1 InterfaceIndex, NextHop | ConvertTo-Json"])
            .output();
        if let Ok(output) = out_v4 {
            if let Ok(entry) = serde_json::from_slice::<NetRouteEntry>(&output.stdout) {
                if !entry.NextHop.is_empty() && entry.NextHop != "0.0.0.0" {
                    println!("[ROUTING] Detected Physical IPv4: IF #{}, Gateway: {}", entry.InterfaceIndex, entry.NextHop);
                    phys_v4 = Some((entry.InterfaceIndex, entry.NextHop));
                }
            }
        }

        // 2. Detect IPv6 Default Route with lowest metric (physical primary interface)
        let out_v6 = Command::new("powershell")
            .args(["-NoProfile", "-Command", "Get-NetRoute -DestinationPrefix '::/0' | Sort-Object RouteMetric | Select-Object -First 1 InterfaceIndex, NextHop | ConvertTo-Json"])
            .output();
        if let Ok(output) = out_v6 {
            if let Ok(entry) = serde_json::from_slice::<NetRouteEntry>(&output.stdout) {
                if !entry.NextHop.is_empty() && entry.NextHop != "::" {
                    println!("[ROUTING] Detected Physical IPv6: IF #{}, Gateway: {}", entry.InterfaceIndex, entry.NextHop);
                    phys_v6 = Some((entry.InterfaceIndex, entry.NextHop));
                }
            }
        }

        (phys_v4, phys_v6)
    }

    /// Pin server endpoint routes to physical interface, apply selective routes, elevate IPv6, and activate Anti-Leak Firewall
    pub fn apply(&self) {
        let clean_host = self.server_host.trim_matches('[').trim_matches(']');

        // Protect Server Endpoint Route to prevent recursive routing loops
        if clean_host.contains(':') {
            if let Some((idx, ref gw)) = self.physical_v6 {
                println!("[ROUTING] Protecting server IPv6 endpoint route to {} via IF #{} ...", clean_host, idx);
                let _ = Command::new("netsh")
                    .args(["interface", "ipv6", "add", "route", &format!("{}/128", clean_host), &format!("interface={}", idx), &format!("nexthop={}", gw), "metric=1", "store=active"])
                    .output();
            }
        } else if let Some((idx, ref gw)) = self.physical_v4 {
            println!("[ROUTING] Protecting server IPv4 endpoint route to {} via IF #{} ...", clean_host, idx);
            let _ = Command::new("netsh")
                .args(["interface", "ipv4", "add", "route", &format!("{}/32", clean_host), &format!("interface={}", idx), &format!("nexthop={}", gw), "metric=1", "store=active"])
                .output();
        }

        // 2. Inject High-Speed Policy-Based Split-Tunnel Routes (Categorized Base CIDRs)
        println!("[ROUTING] Injecting High-Speed Policy-Based Split Routes to Wintun IF #{} ...", self.wintun_if_index);
        let (v4_cnt, v6_cnt) = crate::client::routes::apply_all_routes(self.wintun_if_index);
        println!("[ROUTING] Policy-Based Split Tunneling Active: {} IPv4 and {} IPv6 base CIDRs loaded.", v4_cnt, v6_cnt);
        println!("[ROUTING] Dynamic DNS Snooper armed: All domain-resolved IPs will be dynamically routed to Wintun.");

        // Elevate RFC 6724 IPv6 Prefix Policy so Windows Happy Eyeballs prefers clean IPv6 (Precedence 50 > IPv4 35)
        println!("[ROUTING] Elevating IPv6 Prefix Policy (Precedence 50) for Clean Gemini/Google AI traffic...");
        let _ = Command::new("netsh")
            .args(["interface", "ipv6", "add", "prefixpolicy", "fd00:8:0::/64", "50", "0", "store=active"])
            .output();

        // 1. Activate Zero-Leak Firewall Rules (Blocks all outbound port 53 DNS leaks on physical wireless, LAN, and WWAN/Cellular adapters)
        println!("[ROUTING] Activating Zero-Leak Firewall Barrier (Blocking physical DNS leaks to ISP)...");
        let _ = Command::new("netsh").args(["advfirewall", "firewall", "add", "rule", "name=FastUDPTunnel-AntiLeak-UDP-Wifi", "dir=out", "action=block", "protocol=UDP", "remoteport=53", "interfacetype=wireless"]).output();
        let _ = Command::new("netsh").args(["advfirewall", "firewall", "add", "rule", "name=FastUDPTunnel-AntiLeak-UDP-Lan", "dir=out", "action=block", "protocol=UDP", "remoteport=53", "interfacetype=lan"]).output();
        let _ = Command::new("netsh").args(["advfirewall", "firewall", "add", "rule", "name=FastUDPTunnel-AntiLeak-UDP-Wwan", "dir=out", "action=block", "protocol=UDP", "remoteport=53", "interfacetype=ras"]).output();
        let _ = Command::new("netsh").args(["advfirewall", "firewall", "add", "rule", "name=FastUDPTunnel-AntiLeak-TCP-Wifi", "dir=out", "action=block", "protocol=TCP", "remoteport=53", "interfacetype=wireless"]).output();
        let _ = Command::new("netsh").args(["advfirewall", "firewall", "add", "rule", "name=FastUDPTunnel-AntiLeak-TCP-Lan", "dir=out", "action=block", "protocol=TCP", "remoteport=53", "interfacetype=lan"]).output();
        let _ = Command::new("netsh").args(["advfirewall", "firewall", "add", "rule", "name=FastUDPTunnel-AntiLeak-TCP-Wwan", "dir=out", "action=block", "protocol=TCP", "remoteport=53", "interfacetype=ras"]).output();

        // 2. Disable Windows Smart Multi-Homed Name Resolution (Prevents parallel querying of ISP DNS)
        let _ = Command::new("reg")
            .args(["add", "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient", "/v", "DisableSmartNameResolution", "/t", "REG_DWORD", "/d", "1", "/f"])
            .output();

        let _ = Command::new("powershell")
            .args(["-NoProfile", "-Command", "Clear-DnsClientCache"])
            .output();
    }

    /// Restore clean network routes and remove anti-leak barriers and prefix policy
    pub fn restore(&self) {
        println!("\n[ROUTING] Restoring network routing table, firewall barriers and prefix policies...");

        // Remove firewall anti-leak rules
        let _ = Command::new("netsh").args(["advfirewall", "firewall", "delete", "rule", "name=FastUDPTunnel-AntiLeak-UDP-Wifi"]).output();
        let _ = Command::new("netsh").args(["advfirewall", "firewall", "delete", "rule", "name=FastUDPTunnel-AntiLeak-UDP-Lan"]).output();
        let _ = Command::new("netsh").args(["advfirewall", "firewall", "delete", "rule", "name=FastUDPTunnel-AntiLeak-UDP-Wwan"]).output();
        let _ = Command::new("netsh").args(["advfirewall", "firewall", "delete", "rule", "name=FastUDPTunnel-AntiLeak-TCP-Wifi"]).output();
        let _ = Command::new("netsh").args(["advfirewall", "firewall", "delete", "rule", "name=FastUDPTunnel-AntiLeak-TCP-Lan"]).output();
        let _ = Command::new("netsh").args(["advfirewall", "firewall", "delete", "rule", "name=FastUDPTunnel-AntiLeak-TCP-Wwan"]).output();
        let _ = Command::new("netsh").args(["advfirewall", "firewall", "delete", "rule", "name=FastUDPTunnel-AntiLeak-UDP"]).output();
        let _ = Command::new("netsh").args(["advfirewall", "firewall", "delete", "rule", "name=FastUDPTunnel-AntiLeak-TCP"]).output();

        // Restore Windows Smart Multi-Homed Name Resolution
        let _ = Command::new("reg")
            .args(["delete", "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient", "/v", "DisableSmartNameResolution", "/f"])
            .output();

        // Remove elevated IPv6 prefix policy
        let _ = Command::new("netsh")
            .args(["interface", "ipv6", "delete", "prefixpolicy", "fd00:8:0::/64"])
            .output();

        // Delete Split Routes from Wintun interface
        let _ = crate::client::routes::restore_all_routes(self.wintun_if_index);

        // Delete Full-Tunnel routes from Wintun interface if any lingered
        let _ = Command::new("netsh").args(["interface", "ipv4", "delete", "route", "0.0.0.0/1", &format!("interface={}", self.wintun_if_index)]).output();
        let _ = Command::new("netsh").args(["interface", "ipv4", "delete", "route", "128.0.0.0/1", &format!("interface={}", self.wintun_if_index)]).output();
        let _ = Command::new("netsh").args(["interface", "ipv6", "delete", "route", "::/1", &format!("interface={}", self.wintun_if_index)]).output();
        let _ = Command::new("netsh").args(["interface", "ipv6", "delete", "route", "8000::/1", &format!("interface={}", self.wintun_if_index)]).output();

        let clean_host = self.server_host.trim_matches('[').trim_matches(']');
        if clean_host.contains(':') {
            if let Some((idx, _)) = self.physical_v6 {
                let _ = Command::new("netsh").args(["interface", "ipv6", "delete", "route", &format!("{}/128", clean_host), &format!("interface={}", idx)]).output();
            }
        } else if let Some((idx, _)) = self.physical_v4 {
            let _ = Command::new("netsh").args(["interface", "ipv4", "delete", "route", &format!("{}/32", clean_host), &format!("interface={}", idx)]).output();
        }

        let _ = Command::new("powershell")
            .args(["-NoProfile", "-Command", "Clear-DnsClientCache"])
            .output();
    }
}

/// Proactive Self-Healing: Purge any lingering stale routes, firewall rules, or policies from previous crashed sessions.
pub fn clean_stale_routes_and_nrpt() {
    let _ = Command::new("powershell")
        .args(["-NoProfile", "-Command", "Get-DnsClientNrptRule | Where-Object {$_.Comment -eq 'FastUDPTunnel'} | Remove-DnsClientNrptRule -Force -ErrorAction SilentlyContinue; Clear-DnsClientCache"])
        .output();

    // Clean any lingering anti-leak firewall rules
    let _ = Command::new("netsh").args(["advfirewall", "firewall", "delete", "rule", "name=FastUDPTunnel-AntiLeak-UDP-Wifi"]).output();
    let _ = Command::new("netsh").args(["advfirewall", "firewall", "delete", "rule", "name=FastUDPTunnel-AntiLeak-UDP-Lan"]).output();
    let _ = Command::new("netsh").args(["advfirewall", "firewall", "delete", "rule", "name=FastUDPTunnel-AntiLeak-UDP-Wwan"]).output();
    let _ = Command::new("netsh").args(["advfirewall", "firewall", "delete", "rule", "name=FastUDPTunnel-AntiLeak-TCP-Wifi"]).output();
    let _ = Command::new("netsh").args(["advfirewall", "firewall", "delete", "rule", "name=FastUDPTunnel-AntiLeak-TCP-Lan"]).output();
    let _ = Command::new("netsh").args(["advfirewall", "firewall", "delete", "rule", "name=FastUDPTunnel-AntiLeak-TCP-Wwan"]).output();
    let _ = Command::new("netsh").args(["advfirewall", "firewall", "delete", "rule", "name=FastUDPTunnel-AntiLeak-UDP"]).output();
    let _ = Command::new("netsh").args(["advfirewall", "firewall", "delete", "rule", "name=FastUDPTunnel-AntiLeak-TCP"]).output();

    // Clean any lingering DNSClient DisableSmartNameResolution override
    let _ = Command::new("reg")
        .args(["delete", "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows NT\\DNSClient", "/v", "DisableSmartNameResolution", "/f"])
        .output();

    // Remove any stale prefix policies
    let _ = Command::new("netsh").args(["interface", "ipv6", "delete", "prefixpolicy", "fd00:8:0::/64"]).output();

    // Ensure no stale default routes exist on FastUDPTunnel
    let _ = Command::new("netsh").args(["interface", "ipv4", "delete", "route", "0.0.0.0/0", "FastUDPTunnel"]).output();
    let _ = Command::new("netsh").args(["interface", "ipv6", "delete", "route", "::/0", "FastUDPTunnel"]).output();

    // Remove legacy full-tunnel split routes if any remained from old builds
    let _ = Command::new("netsh").args(["interface", "ipv4", "delete", "route", "0.0.0.0/1"]).output();
    let _ = Command::new("netsh").args(["interface", "ipv4", "delete", "route", "128.0.0.0/1"]).output();
    let _ = Command::new("netsh").args(["interface", "ipv6", "delete", "route", "::/1"]).output();
    let _ = Command::new("netsh").args(["interface", "ipv6", "delete", "route", "8000::/1"]).output();
}
