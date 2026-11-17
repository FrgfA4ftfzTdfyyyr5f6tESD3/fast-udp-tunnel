//! Wintun adapter lifecycle, ring buffer session, native Win32 IP/MTU configuration,
//! and resilient packet allocation (enhanced with surgical patterns from tun-rs).

use std::error::Error;
use std::net::IpAddr;
use std::process::Command;
use std::sync::Arc;
use wintun::{Adapter, Session, Wintun};

use windows_sys::Win32::Foundation::{ERROR_OBJECT_ALREADY_EXISTS, NO_ERROR};
use windows_sys::Win32::NetworkManagement::IpHelper::{
    CreateUnicastIpAddressEntry, GetIpInterfaceEntry, InitializeUnicastIpAddressEntry,
    SetIpInterfaceEntry, MIB_IPINTERFACE_ROW, MIB_UNICASTIPADDRESS_ROW,
};
use windows_sys::Win32::Networking::WinSock::{
    IpDadStatePreferred, AF_INET, AF_INET6, SOCKADDR_INET,
};

fn sockaddr_inet_from_ip(ip: IpAddr) -> SOCKADDR_INET {
    let mut sa: SOCKADDR_INET = unsafe { std::mem::zeroed() };
    match ip {
        IpAddr::V4(v4) => {
            sa.Ipv4.sin_family = AF_INET;
            sa.Ipv4.sin_addr.S_un.S_addr = u32::from_ne_bytes(v4.octets());
        }
        IpAddr::V6(v6) => {
            sa.Ipv6.sin6_family = AF_INET6;
            sa.Ipv6.sin6_addr.u.Byte = v6.octets();
        }
    }
    sa
}

/// Native Win32 API to add a unicast IP address to interface in memory (< 1ms vs netsh process spawn).
/// Sets DadState = IpDadStatePreferred so the address is usable immediately with zero DAD delay.
pub fn add_ip_address_native(index: u32, address: IpAddr, prefix: u8) -> Result<(), u32> {
    let mut row: MIB_UNICASTIPADDRESS_ROW = unsafe { std::mem::zeroed() };
    unsafe { InitializeUnicastIpAddressEntry(&mut row) };
    row.InterfaceIndex = index;
    row.Address = sockaddr_inet_from_ip(address);
    row.OnLinkPrefixLength = prefix;
    row.DadState = IpDadStatePreferred;

    let code = unsafe { CreateUnicastIpAddressEntry(&row) };
    if code == NO_ERROR || code == ERROR_OBJECT_ALREADY_EXISTS {
        Ok(())
    } else {
        Err(code)
    }
}

/// Native Win32 API to set interface MTU and metric directly in kernel memory (< 1ms).
pub fn set_interface_mtu_and_metric_native(index: u32, mtu: u32, metric: u32, is_v4: bool) -> Result<(), u32> {
    let mut row: MIB_IPINTERFACE_ROW = unsafe { std::mem::zeroed() };
    row.Family = if is_v4 { AF_INET } else { AF_INET6 };
    row.InterfaceIndex = index;

    let get_code = unsafe { GetIpInterfaceEntry(&mut row) };
    if get_code != NO_ERROR {
        return Err(get_code);
    }

    row.NlMtu = mtu;
    row.Metric = metric;
    row.UseAutomaticMetric = 0;
    // Conventional workaround for Windows IPv4 SetIpInterfaceEntry bug (from tun-rs)
    row.SitePrefixLength = 0;

    let set_code = unsafe { SetIpInterfaceEntry(&mut row) };
    if set_code == NO_ERROR {
        Ok(())
    } else {
        Err(set_code)
    }
}

pub fn configure_wintun_ips_and_mtu(if_index: u32, tunnel_mtu: u32, assigned_v4: Option<&str>, assigned_v6: Option<&str>) {
    // 1. Try ultra-fast native Win32 in-memory APIs first (tun-rs pattern: < 2 ms total)
    let v4_str = assigned_v4.unwrap_or("10.8.0.2");
    let v6_str = assigned_v6.unwrap_or("fd00:8:0::2");
    let v4_ip: IpAddr = v4_str.parse().unwrap_or_else(|_| "10.8.0.2".parse().unwrap());
    let v6_ip: IpAddr = v6_str.parse().unwrap_or_else(|_| "fd00:8:0::2".parse().unwrap());

    let v4_ok = add_ip_address_native(if_index, v4_ip, 24).is_ok();
    let v6_ok = add_ip_address_native(if_index, v6_ip, 64).is_ok();
    let mtu_v4_ok = set_interface_mtu_and_metric_native(if_index, tunnel_mtu, 1, true).is_ok();
    let mtu_v6_ok = set_interface_mtu_and_metric_native(if_index, tunnel_mtu, 1, false).is_ok();

    // 2. If native calls failed (e.g. older OS build), transparently fall back to netsh
    if !v4_ok {
        let _ = Command::new("netsh")
            .args(["interface", "ipv4", "set", "address", "FastUDPTunnel", "static", &v4_ip.to_string(), "255.255.255.0", "none"])
            .output();
    }
    if !v6_ok {
        let _ = Command::new("netsh")
            .args(["interface", "ipv6", "set", "address", "FastUDPTunnel", &format!("{}/64", v6_ip)])
            .output();
    }
    if !mtu_v4_ok {
        let _ = Command::new("netsh")
            .args(["interface", "ipv4", "set", "subinterface", "FastUDPTunnel", &format!("mtu={}", tunnel_mtu), "store=active"])
            .output();
    }
    if !mtu_v6_ok {
        let _ = Command::new("netsh")
            .args(["interface", "ipv6", "set", "subinterface", "FastUDPTunnel", &format!("mtu={}", tunnel_mtu), "store=active"])
            .output();
    }

    // Zero-Proxy Kernel DNS: Configure in-tunnel DNS servers (fd00:8:0::1 primary IPv6, 10.8.0.1 secondary IPv4)
    let _ = Command::new("netsh")
        .args(["interface", "ipv6", "set", "dnsservers", "FastUDPTunnel", "static", "fd00:8:0::1", "primary", "validate=no"])
        .output();
    let _ = Command::new("netsh")
        .args(["interface", "ipv4", "set", "dnsservers", "FastUDPTunnel", "static", "10.8.0.1", "primary", "validate=no"])
        .output();
}

pub fn initialize_wintun(
    wintun: &Wintun,
    tunnel_mtu: u32,
    assigned_v4: Option<&str>,
    assigned_v6: Option<&str>,
) -> Result<(Arc<Adapter>, Arc<Session>, u32), Box<dyn Error>> {
    let adapter = match Adapter::open(wintun, "FastUDPTunnel") {
        Ok(a) => a,
        Err(_) => Adapter::create(wintun, "FastUDPTunnel", "FastUDPTunnel", None)?,
    };

    // Instant in-process index lookup (0.001 ms vs slow PowerShell invocation)
    let if_index = adapter.get_adapter_index()?;

    configure_wintun_ips_and_mtu(if_index, tunnel_mtu, assigned_v4, assigned_v6);

    let session = Arc::new(adapter.start_session(wintun::MAX_RING_CAPACITY)?);
    Ok((adapter, session, if_index))
}

/// Allocate a Wintun send packet with resilient retry upon momentary ring buffer congestion.
pub fn allocate_packet_resilient(session: &Arc<Session>, size: u16) -> Result<wintun::Packet, wintun::Error> {
    let mut pkt_res = session.allocate_send_packet(size);
    if pkt_res.is_err() {
        for _ in 0..50 {
            std::thread::yield_now();
            pkt_res = session.allocate_send_packet(size);
            if pkt_res.is_ok() {
                break;
            }
        }
    }
    pkt_res
}
