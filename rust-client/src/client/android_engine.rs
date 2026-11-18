#![cfg(target_os = "android")]
//! Android VpnService Full-Duplex High-Throughput Engine for Morph Core (v8.7).
//!
//! Architecture engineered to match the 21+ Mbps Windows Wintun client on mobile LTE/5G:
//! - Batch UDP Receive via `libc::recvmmsg` (up to 32 packets per syscall, zero heap allocation in hot loop)
//! - Non-blocking TUN Burst Drain (up to 64 IP packets per poll wakeup, 0% idle CPU)
//! - Adaptive Kernel Socket Buffers (8MB -> 4MB -> 2MB fallback via `SO_RCVBUF`/`SO_SNDBUF`)
//! - Golden 1200-byte Micro-Segmentation (zero carrier fragmentation on cellular networks)
//! - RFC 6296 Checksum-Neutral NPTv6 (`2001:db8:0:cf4f::/64` <-> `fd00:8:0::/64`):
//!   Elevates Android TUN IPv6 above IPv4 in RFC 6724 (`::/0` prec=40 > `::ffff:0:0/96` prec=35)
//!   so Chrome, Gemini, and Android apps always exit via the server's clean IPv6 first while
//!   preserving IPv4 fallback — with zero checksum recomputation (`0x2001+0x0db8+0x0000+0xcf4f == 0xfd08`).

use std::net::{Ipv4Addr, SocketAddr, UdpSocket};
use std::os::unix::io::{AsRawFd, RawFd};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::common::{
    should_fragment, split_packet, ReassemblyBuffer, SubscriptionToken, FLAG_DATA, FLAG_FRAG_1,
    FLAG_FRAG_2, FLAG_FRAME_MASK, FLAG_KEEPALIVE, FLAG_KEEPALIVE_ACK, KEEPALIVE_JITTER_MAX_MS,
    KEEPALIVE_JITTER_MIN_MS, KEEPALIVE_PADDING_MAX_BYTES, KEEPALIVE_PADDING_MIN_BYTES,
    MIMICRY_HEADER_LEN, MTU_HANDSHAKE_MAGIC, TUNNEL_MTU,
};
use crate::core::build_icmp_probe_packet;
use crate::core::crypto::{apply_payload_shaping, strip_payload_shaping, PayloadMode};
use crate::core::metrics::{MetricTracker, TunnelStatus, TunnelTelemetry};
use crate::mimic::MimicProfile;

const RX_BATCH_SIZE: usize = 32;
const TX_BURST_MAX: usize = 64;
const PACKET_SLOT_SIZE: usize = 2048;

/// Global-scope IPv6 /64 prefix assigned to Android's VpnService TUN (`2001:db8:0:cf4f::/64`).
/// Checksum sum: 0x2001 + 0x0db8 + 0x0000 + 0xcf4f = 0xFD08 (identical to `fd00:0008:0000:0000`).
const ANDROID_GLOBAL_V6_PREFIX: [u8; 8] = [0x20, 0x01, 0x0d, 0xb8, 0x00, 0x00, 0xcf, 0x4f];

/// Server tunnel internal ULA IPv6 /64 prefix (`fd00:8::/64`).
/// Checksum sum: 0xfd00 + 0x0008 + 0x0000 + 0x0000 = 0xFD08.
const TUNNEL_ULA_V6_PREFIX: [u8; 8] = [0xfd, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00];

/// Checksum-neutral stateless NPTv6 rewrite for outbound IPv6 packets (Android TUN -> Server).
#[inline(always)]
fn translate_v6_outbound(pkt: &mut [u8]) {
    if pkt.len() >= 40 && (pkt[0] >> 4) == 6 {
        if pkt[8..16] == ANDROID_GLOBAL_V6_PREFIX {
            pkt[8..16].copy_from_slice(&TUNNEL_ULA_V6_PREFIX);
        }
        if pkt[24..32] == ANDROID_GLOBAL_V6_PREFIX {
            pkt[24..32].copy_from_slice(&TUNNEL_ULA_V6_PREFIX);
        }
    }
}

/// Checksum-neutral stateless NPTv6 rewrite for inbound IPv6 packets (Server -> Android TUN).
#[inline(always)]
fn translate_v6_inbound(pkt: &mut [u8]) {
    if pkt.len() >= 40 && (pkt[0] >> 4) == 6 {
        if pkt[24..32] == TUNNEL_ULA_V6_PREFIX {
            pkt[24..32].copy_from_slice(&ANDROID_GLOBAL_V6_PREFIX);
        }
        if pkt[8..16] == TUNNEL_ULA_V6_PREFIX {
            pkt[8..16].copy_from_slice(&ANDROID_GLOBAL_V6_PREFIX);
        }
    }
}

struct PreparedSession {
    socket: UdpSocket,
    profile: MimicProfile,
    mode: PayloadMode,
    psk: [u8; 8],
    src_v4_bytes: [u8; 4],
}

struct ActiveTunnel {
    running: Arc<AtomicBool>,
    handles: Vec<JoinHandle<()>>,
}

struct AndroidCounters {
    rx_packets: AtomicU64,
    tx_packets: AtomicU64,
}

static ENGINE_STATE: OnceLock<Mutex<EngineState>> = OnceLock::new();
static ANDROID_COUNTERS: OnceLock<AndroidCounters> = OnceLock::new();

struct EngineState {
    prepared: Option<PreparedSession>,
    active: Option<ActiveTunnel>,
    metrics: Option<Arc<MetricTracker>>,
}

fn state_lock() -> &'static Mutex<EngineState> {
    ENGINE_STATE.get_or_init(|| {
        Mutex::new(EngineState {
            prepared: None,
            active: None,
            metrics: None,
        })
    })
}

fn counters() -> &'static AndroidCounters {
    ANDROID_COUNTERS.get_or_init(|| AndroidCounters {
        rx_packets: AtomicU64::new(0),
        tx_packets: AtomicU64::new(0),
    })
}

fn configure_android_socket_buffers(socket: &UdpSocket) {
    let fd = socket.as_raw_fd();
    // Try largest buffer down to 1 MB so Android grants the maximum allowed by net.core.{r,w}mem_max
    for &size in &[
        8 * 1024 * 1024 as libc::c_int,
        4 * 1024 * 1024 as libc::c_int,
        2 * 1024 * 1024 as libc::c_int,
        1 * 1024 * 1024 as libc::c_int,
    ] {
        let rc_r = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_RCVBUF,
                &size as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if rc_r == 0 {
            break;
        }
    }
    for &size in &[
        8 * 1024 * 1024 as libc::c_int,
        4 * 1024 * 1024 as libc::c_int,
        2 * 1024 * 1024 as libc::c_int,
        1 * 1024 * 1024 as libc::c_int,
    ] {
        let rc_s = unsafe {
            libc::setsockopt(
                fd,
                libc::SOL_SOCKET,
                libc::SO_SNDBUF,
                &size as *const _ as *const libc::c_void,
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if rc_s == 0 {
            break;
        }
    }
}

fn set_fd_nonblocking(fd: RawFd, nonblocking: bool) {
    unsafe {
        let flags = libc::fcntl(fd, libc::F_GETFL, 0);
        if flags >= 0 {
            let new_flags = if nonblocking {
                flags | libc::O_NONBLOCK
            } else {
                flags & !libc::O_NONBLOCK
            };
            let _ = libc::fcntl(fd, libc::F_SETFL, new_flags);
        }
    }
}

fn format_v6_endpoint(host: &str, port: u16) -> String {
    let clean = host.trim();
    if clean.starts_with('[') && clean.ends_with(']') {
        format!("{}:{}", clean, port)
    } else {
        format!("[{}]:{}", clean, port)
    }
}

fn try_connect_v6(v6_host: &str, port: u16) -> Option<UdpSocket> {
    let ep_str = format_v6_endpoint(v6_host, port);
    let addr = ep_str.parse::<SocketAddr>().ok()?;
    let sock = UdpSocket::bind("[::]:0").ok()?;
    sock.connect(addr).ok()?;
    configure_android_socket_buffers(&sock);
    let _ = sock.set_read_timeout(Some(Duration::from_millis(100)));
    Some(sock)
}

fn try_connect_v4(v4_host: &str, port: u16) -> Option<UdpSocket> {
    let ep_str = format!("{}:{}", v4_host.trim(), port);
    let addr = ep_str.parse::<SocketAddr>().ok()?;
    let sock = UdpSocket::bind("0.0.0.0:0").ok()?;
    sock.connect(addr).ok()?;
    configure_android_socket_buffers(&sock);
    let _ = sock.set_read_timeout(Some(Duration::from_millis(100)));
    Some(sock)
}

/// Bind and connect a UDP socket respecting `transport_override` (`"auto"`, `"ipv6"`, `"ipv4"`)
/// and optional `port_override` (`1..=65535`).
fn create_connected_android_socket(
    token: &SubscriptionToken,
    transport_override: Option<&str>,
    port_override: u16,
) -> Result<UdpSocket, String> {
    let port = if port_override > 0 {
        port_override
    } else {
        token.port
    };

    let pref = transport_override
        .map(str::trim)
        .unwrap_or("auto")
        .to_ascii_lowercase();

    match pref.as_str() {
        "ipv4" | "v4" | "4" => {
            if let Some(ref v4) = token.server_v4 {
                if let Some(sock) = try_connect_v4(v4, port) {
                    return Ok(sock);
                }
            }
            if let Some(ref v6) = token.server_v6 {
                if let Some(sock) = try_connect_v6(v6, port) {
                    return Ok(sock);
                }
            }
        }
        "ipv6" | "v6" | "6" => {
            if let Some(ref v6) = token.server_v6 {
                if let Some(sock) = try_connect_v6(v6, port) {
                    return Ok(sock);
                }
            }
            // Fallback to IPv4 if current network has no IPv6 default route (e.g. IPv4-only Wi-Fi);
            // inner tunnel egress still prioritizes clean IPv6 via NPTv6!
            if let Some(ref v4) = token.server_v4 {
                if let Some(sock) = try_connect_v4(v4, port) {
                    return Ok(sock);
                }
            }
        }
        _ => {
            // Auto: prefer IPv6 transport when routable, seamless IPv4 fallback
            if let Some(ref v6) = token.server_v6 {
                if let Some(sock) = try_connect_v6(v6, port) {
                    return Ok(sock);
                }
            }
            if let Some(ref v4) = token.server_v4 {
                if let Some(sock) = try_connect_v4(v4, port) {
                    return Ok(sock);
                }
            }
        }
    }

    Err("No reachable IPv6 or IPv4 endpoint available in token".to_string())
}

#[inline(always)]
fn is_routable_unicast(packet: &[u8]) -> bool {
    if packet.is_empty() {
        return false;
    }
    let ver = packet[0] >> 4;
    if ver == 4 {
        if packet.len() < 20 {
            return false;
        }
        let d = &packet[16..20];
        if d == [255, 255, 255, 255] {
            return false;
        }
        if d[0] == 10 && d[1] == 8 && d[2] == 0 && d[3] == 255 {
            return false;
        }
        if d[0] >= 224 && d[0] <= 239 {
            return false;
        }
        if d == [0, 0, 0, 0] {
            return false;
        }
        true
    } else if ver == 6 {
        if packet.len() < 40 {
            return false;
        }
        if packet[24] == 0xFF {
            return false;
        }
        if packet[24..40].iter().all(|&b| b == 0) {
            return false;
        }
        true
    } else {
        false
    }
}

/// Step 1 of Android VpnService flow (extended with transport & port override):
/// Parses the `morph://` token and optional overrides, creates & connects the UDP socket,
/// stores the prepared session, and returns the raw `udp_socket_fd` for `VpnService.protect(fd)`.
pub fn prepare_socket_ex(
    token_uri: &str,
    mimic_override: Option<&str>,
    payload_mode_override: Option<&str>,
    transport_override: Option<&str>,
    port_override: u16,
) -> Result<RawFd, String> {
    stop_tunnel();

    let token = SubscriptionToken::from_uri(token_uri)?;
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    if token.is_expired(now) {
        return Err("Subscription token has expired".to_string());
    }

    let profile = mimic_override
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .and_then(MimicProfile::parse)
        .unwrap_or_else(|| token.mimic_profile());

    let mode = payload_mode_override
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .and_then(PayloadMode::parse)
        .unwrap_or_else(|| token.payload_protection_mode());

    let src_v4_bytes: [u8; 4] = token
        .assigned_ipv4
        .as_deref()
        .and_then(|s| s.parse::<Ipv4Addr>().ok())
        .map(|ip| ip.octets())
        .unwrap_or([10, 8, 0, 2]);

    let socket = create_connected_android_socket(&token, transport_override, port_override)?;
    let raw_fd = socket.as_raw_fd();

    let telem = TunnelTelemetry::global();
    telem.shutdown_requested.store(false, Ordering::SeqCst);
    telem.set_status(TunnelStatus::Connecting);
    telem.pmtu.store(TUNNEL_MTU as u16, Ordering::Relaxed);

    if let Ok(mut guard) = state_lock().lock() {
        guard.prepared = Some(PreparedSession {
            socket,
            profile,
            mode,
            psk: token.psk,
            src_v4_bytes,
        });
    } else {
        return Err("Failed to lock engine state".to_string());
    }

    Ok(raw_fd)
}

/// Backwards-compatible wrapper for `prepareSocket(token, mimicOverride, payloadModeOverride)`.
pub fn prepare_socket(
    token_uri: &str,
    mimic_override: Option<&str>,
    payload_mode_override: Option<&str>,
) -> Result<RawFd, String> {
    prepare_socket_ex(token_uri, mimic_override, payload_mode_override, None, 0)
}

#[inline(always)]
fn deliver_inbound_packet(
    tun_fd: RawFd,
    ip_pkt: &mut [u8],
    metrics: &MetricTracker,
) {
    if ip_pkt.is_empty() {
        return;
    }

    // Demux in-band ICMP Echo Reply for live RTT telemetry
    if metrics.handle_possible_probe_reply(ip_pkt) {
        return;
    }

    // Checksum-neutral NPTv6 rewrite (`fd00:8::/64` -> `2001:db8:0:cf4f::/64`)
    translate_v6_inbound(ip_pkt);

    let written = unsafe {
        libc::write(
            tun_fd,
            ip_pkt.as_ptr() as *const libc::c_void,
            ip_pkt.len(),
        )
    };
    if written > 0 {
        counters().rx_packets.fetch_add(1, Ordering::Relaxed);
    }
}

/// Step 2 of Android VpnService flow (called AFTER `VpnService.protect(udpFd)` succeeds):
/// Starts high-throughput full-duplex Rust worker threads bridging Android `tun_fd` <-> protected UDP socket.
/// Rust NEVER closes `tun_fd`; Android's `ParcelFileDescriptor` retains ownership.
pub fn start_tunnel(tun_fd: RawFd) -> Result<(), String> {
    if tun_fd < 0 {
        return Err("Invalid Android TUN file descriptor".to_string());
    }

    let prepared = {
        let mut guard = state_lock()
            .lock()
            .map_err(|_| "Failed to lock engine state".to_string())?;
        guard
            .prepared
            .take()
            .ok_or_else(|| "prepareSocket() must be called before startTunnel()".to_string())?
    };

    let PreparedSession {
        socket,
        profile,
        mode,
        psk,
        src_v4_bytes,
    } = prepared;

    // Reset telemetry & packet counters
    let c = counters();
    c.rx_packets.store(0, Ordering::Relaxed);
    c.tx_packets.store(0, Ordering::Relaxed);

    let telem = TunnelTelemetry::global();
    telem.shutdown_requested.store(false, Ordering::SeqCst);
    telem.total_tx_bytes.store(0, Ordering::Relaxed);
    telem.total_rx_bytes.store(0, Ordering::Relaxed);
    telem.tx_rate_bps.store(0, Ordering::Relaxed);
    telem.rx_rate_bps.store(0, Ordering::Relaxed);
    telem.ping_ms.store(0, Ordering::Relaxed);
    telem.pmtu.store(TUNNEL_MTU as u16, Ordering::Relaxed);
    telem.set_status(TunnelStatus::Connected);

    // Enable non-blocking mode on TUN fd for zero-jitter burst draining
    set_fd_nonblocking(tun_fd, true);

    let running = Arc::new(AtomicBool::new(true));
    let metrics = Arc::new(MetricTracker::new());
    let seq_counter = Arc::new(AtomicU32::new(1));
    let last_tx_epoch = Arc::new(AtomicU64::new(0));
    let tunnel_start = Instant::now();

    // Send initial MTU handshake keepalives (1500B inner MTU backed by 1200B micro-segmentation)
    for _ in 0..2 {
        let mut init_wire = [0u8; MIMICRY_HEADER_LEN + 4];
        let init_seq = (seq_counter.fetch_add(1, Ordering::Relaxed) & 0xFFFF) as u16;
        let init_flags = FLAG_KEEPALIVE | mode.to_flags();
        init_wire[MIMICRY_HEADER_LEN..MIMICRY_HEADER_LEN + 2]
            .copy_from_slice(&MTU_HANDSHAKE_MAGIC);
        init_wire[MIMICRY_HEADER_LEN + 2..MIMICRY_HEADER_LEN + 4]
            .copy_from_slice(&(TUNNEL_MTU as u16).to_be_bytes());
        profile.wrap_header(&mut init_wire, init_flags, init_seq, &psk);
        let _ = socket.send(&init_wire);
    }

    let socket_t2u = socket
        .try_clone()
        .map_err(|e| format!("Failed to clone UDP socket for TX thread: {}", e))?;
    let socket_prober = socket
        .try_clone()
        .map_err(|e| format!("Failed to clone UDP socket for prober thread: {}", e))?;

    // Thread 1: Android TUN (Non-blocking Burst Drain) -> NPTv6 -> 1200B Micro-Segmentation -> Connected UDP
    let running_t2u = Arc::clone(&running);
    let metrics_t2u = Arc::clone(&metrics);
    let seq_t2u = Arc::clone(&seq_counter);
    let last_tx_t2u = Arc::clone(&last_tx_epoch);

    let handle_t2u = thread::Builder::new()
        .name("android_tun_to_udp".into())
        .spawn(move || {
            let mut tun_buf = [0u8; PACKET_SLOT_SIZE];
            let mut wire_buf = [0u8; PACKET_SLOT_SIZE];
            let mut pfd = libc::pollfd {
                fd: tun_fd,
                events: libc::POLLIN,
                revents: 0,
            };

            while running_t2u.load(Ordering::Relaxed) {
                pfd.revents = 0;
                let poll_res = unsafe { libc::poll(&mut pfd as *mut libc::pollfd, 1, 100) };
                if poll_res <= 0 {
                    continue;
                }
                if (pfd.revents & (libc::POLLERR | libc::POLLHUP | libc::POLLNVAL)) != 0 {
                    break;
                }
                if (pfd.revents & libc::POLLIN) == 0 {
                    continue;
                }

                // Drain up to TX_BURST_MAX packets per kernel wakeup without extra poll() syscalls
                let mut batch_bytes: u64 = 0;
                let mut batch_pkts: u64 = 0;

                for _ in 0..TX_BURST_MAX {
                    let n = unsafe {
                        libc::read(
                            tun_fd,
                            tun_buf.as_mut_ptr() as *mut libc::c_void,
                            tun_buf.len(),
                        )
                    };
                    if n <= 0 {
                        break;
                    }

                    let len = n as usize;
                    let pkt_slice = &mut tun_buf[..len];
                    if !is_routable_unicast(pkt_slice) {
                        continue;
                    }

                    // Checksum-neutral NPTv6 rewrite (`2001:db8:0:cf4f::/64` -> `fd00:8::/64`)
                    translate_v6_outbound(pkt_slice);

                    if should_fragment(len) {
                        let seq = (seq_t2u.fetch_add(1, Ordering::Relaxed) & 0xFFFF) as u16;
                        let (frag1, frag2) = split_packet(pkt_slice);

                        // Frag 1
                        let payload_out1 = &mut wire_buf[MIMICRY_HEADER_LEN..];
                        let shaped_len1 =
                            apply_payload_shaping(frag1, payload_out1, &psk, seq, mode, profile);
                        let wire_len1 = MIMICRY_HEADER_LEN + shaped_len1;
                        let flags1 = FLAG_FRAG_1 | mode.to_flags();
                        profile.wrap_header(&mut wire_buf[..wire_len1], flags1, seq, &psk);
                        let _ = socket_t2u.send(&wire_buf[..wire_len1]);

                        // Frag 2
                        let payload_out2 = &mut wire_buf[MIMICRY_HEADER_LEN..];
                        let shaped_len2 =
                            apply_payload_shaping(frag2, payload_out2, &psk, seq, mode, profile);
                        let wire_len2 = MIMICRY_HEADER_LEN + shaped_len2;
                        let flags2 = FLAG_FRAG_2 | mode.to_flags();
                        profile.wrap_header(&mut wire_buf[..wire_len2], flags2, seq, &psk);
                        let _ = socket_t2u.send(&wire_buf[..wire_len2]);

                        batch_bytes += (wire_len1 + wire_len2) as u64;
                        batch_pkts += 1;
                    } else {
                        let seq = (seq_t2u.fetch_add(1, Ordering::Relaxed) & 0xFFFF) as u16;
                        let payload_out = &mut wire_buf[MIMICRY_HEADER_LEN..];
                        let shaped_len =
                            apply_payload_shaping(pkt_slice, payload_out, &psk, seq, mode, profile);
                        let total_wire_len = MIMICRY_HEADER_LEN + shaped_len;
                        let full_flags = FLAG_DATA | mode.to_flags();
                        profile.wrap_header(&mut wire_buf[..total_wire_len], full_flags, seq, &psk);

                        if socket_t2u.send(&wire_buf[..total_wire_len]).is_ok() {
                            batch_bytes += total_wire_len as u64;
                            batch_pkts += 1;
                        }
                    }
                }

                if batch_pkts > 0 {
                    metrics_t2u
                        .total_tx_bytes
                        .fetch_add(batch_bytes, Ordering::Relaxed);
                    counters().tx_packets.fetch_add(batch_pkts, Ordering::Relaxed);
                    last_tx_t2u.store(
                        tunnel_start.elapsed().as_millis() as u64,
                        Ordering::Relaxed,
                    );
                }
            }
        })
        .map_err(|e| format!("Failed to spawn android_tun_to_udp thread: {}", e))?;

    // Thread 2: Connected UDP (Batch `recvmmsg` 32 pkts/syscall) -> Unwrap -> Reassembly -> NPTv6 -> Android TUN
    let running_u2t = Arc::clone(&running);
    let metrics_u2t = Arc::clone(&metrics);

    let handle_u2t = thread::Builder::new()
        .name("android_udp_to_tun".into())
        .spawn(move || {
            let sock_fd = socket.as_raw_fd();
            let mut rx_bufs: Box<[[u8; PACKET_SLOT_SIZE]; RX_BATCH_SIZE]> =
                Box::new([[0u8; PACKET_SLOT_SIZE]; RX_BATCH_SIZE]);
            let mut iovecs: [libc::iovec; RX_BATCH_SIZE] = unsafe { std::mem::zeroed() };
            let mut msgs: [libc::mmsghdr; RX_BATCH_SIZE] = unsafe { std::mem::zeroed() };

            for i in 0..RX_BATCH_SIZE {
                iovecs[i].iov_base = rx_bufs[i].as_mut_ptr() as *mut libc::c_void;
                iovecs[i].iov_len = PACKET_SLOT_SIZE;
                msgs[i].msg_hdr.msg_iov = &mut iovecs[i] as *mut libc::iovec;
                msgs[i].msg_hdr.msg_iovlen = 1;
            }

            let mut reasm = Box::new(ReassemblyBuffer::new());
            let mut reasm_out = [0u8; PACKET_SLOT_SIZE];

            while running_u2t.load(Ordering::Relaxed) {
                let mut timeout = libc::timespec {
                    tv_sec: 0,
                    tv_nsec: 100_000_000, // 100 ms shutdown responsiveness
                };

                let count = unsafe {
                    libc::recvmmsg(
                        sock_fd,
                        msgs.as_mut_ptr(),
                        RX_BATCH_SIZE as libc::c_uint,
                        libc::MSG_WAITFORONE,
                        &mut timeout as *mut libc::timespec,
                    )
                };

                if count <= 0 {
                    continue;
                }

                let mut batch_rx_bytes: u64 = 0;

                for i in 0..(count as usize) {
                    let n = msgs[i].msg_len as usize;
                    if n < MIMICRY_HEADER_LEN || n > PACKET_SLOT_SIZE {
                        continue;
                    }
                    batch_rx_bytes += n as u64;

                    let pkt = &mut rx_bufs[i][..n];
                    if let Some((flags, seq)) = profile.unwrap_header(pkt, &psk) {
                        let frame_type = flags & FLAG_FRAME_MASK;
                        if frame_type == FLAG_KEEPALIVE_ACK || frame_type == FLAG_KEEPALIVE {
                            continue;
                        }

                        let incoming_mode = PayloadMode::from_flags(flags);
                        let payload_data = &mut pkt[MIMICRY_HEADER_LEN..n];

                        if frame_type == FLAG_DATA {
                            if let Some(raw_len) = strip_payload_shaping(
                                payload_data,
                                &psk,
                                seq,
                                incoming_mode,
                                profile,
                            ) {
                                deliver_inbound_packet(
                                    tun_fd,
                                    &mut payload_data[..raw_len],
                                    &metrics_u2t,
                                );
                            }
                        } else if frame_type == FLAG_FRAG_1 || frame_type == FLAG_FRAG_2 {
                            if let Some(raw_len) = strip_payload_shaping(
                                payload_data,
                                &psk,
                                seq,
                                incoming_mode,
                                profile,
                            ) {
                                let is_frag1 = frame_type == FLAG_FRAG_1;
                                if let Some(reassembled_len) = reasm.process(
                                    is_frag1,
                                    seq,
                                    &payload_data[..raw_len],
                                    &mut reasm_out,
                                ) {
                                    deliver_inbound_packet(
                                        tun_fd,
                                        &mut reasm_out[..reassembled_len],
                                        &metrics_u2t,
                                    );
                                }
                            }
                        }
                    }
                }

                if batch_rx_bytes > 0 {
                    metrics_u2t
                        .total_rx_bytes
                        .fetch_add(batch_rx_bytes, Ordering::Relaxed);
                }
            }
            drop(socket);
        })
        .map_err(|e| format!("Failed to spawn android_udp_to_tun thread: {}", e))?;

    // Thread 3: WireGuard-Style Idle Keepalive + In-Band ICMP RTT Prober + Telemetry Sync
    let running_prober = Arc::clone(&running);
    let metrics_prober = Arc::clone(&metrics);
    let seq_prober = Arc::clone(&seq_counter);
    let last_tx_prober = Arc::clone(&last_tx_epoch);

    let handle_prober = thread::Builder::new()
        .name("android_prober".into())
        .spawn(move || {
            let mut icmp_seq: u16 = 0;
            let mut prev_tx: u64 = 0;
            let mut prev_rx: u64 = 0;
            let mut prev_time = Instant::now();

            let mut rng_state: u64 = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_nanos() as u64)
                .unwrap_or(0xFEED_FACE_CAFE_BABE)
                ^ (psk[0] as u64 | ((psk[1] as u64) << 8));

            let rand_u64 = |min: u64, max: u64, state: &mut u64| -> u64 {
                *state ^= *state << 13;
                *state ^= *state >> 7;
                *state ^= *state << 17;
                min + (*state % (max - min + 1))
            };

            let mut next_ka_interval_ms =
                rand_u64(KEEPALIVE_JITTER_MIN_MS, KEEPALIVE_JITTER_MAX_MS, &mut rng_state);

            while running_prober.load(Ordering::Relaxed) {
                for _ in 0..20 {
                    if !running_prober.load(Ordering::Relaxed) {
                        break;
                    }
                    thread::sleep(Duration::from_millis(50));
                }
                if !running_prober.load(Ordering::Relaxed) {
                    break;
                }

                let current_elapsed_ms = tunnel_start.elapsed().as_millis() as u64;
                let last_user_tx_ms = last_tx_prober.load(Ordering::Relaxed);
                let idle_ms = current_elapsed_ms.saturating_sub(last_user_tx_ms);

                // Anti-NAT Idle-Only Keepalive (20-25s jittered interval)
                if idle_ms >= next_ka_interval_ms {
                    let padding_len = rand_u64(
                        KEEPALIVE_PADDING_MIN_BYTES as u64,
                        KEEPALIVE_PADDING_MAX_BYTES as u64,
                        &mut rng_state,
                    ) as usize;
                    let total_ka_len = MIMICRY_HEADER_LEN + padding_len;
                    let mut ka_pkt = [0u8; MIMICRY_HEADER_LEN + KEEPALIVE_PADDING_MAX_BYTES];

                    for i in 0..padding_len {
                        ka_pkt[MIMICRY_HEADER_LEN + i] =
                            (rand_u64(0, 255, &mut rng_state) & 0xFF) as u8;
                    }

                    let seq = (seq_prober.fetch_add(1, Ordering::Relaxed) & 0xFFFF) as u16;
                    let ka_flags = FLAG_KEEPALIVE | mode.to_flags();
                    profile.wrap_header(&mut ka_pkt[..total_ka_len], ka_flags, seq, &psk);
                    let _ = socket_prober.send(&ka_pkt[..total_ka_len]);

                    last_tx_prober.store(current_elapsed_ms, Ordering::Relaxed);
                    next_ka_interval_ms = rand_u64(
                        KEEPALIVE_JITTER_MIN_MS,
                        KEEPALIVE_JITTER_MAX_MS,
                        &mut rng_state,
                    );
                }

                // In-band ICMP Echo RTT probe (every 1s while active, every 5s while idle)
                let should_probe = if idle_ms < 5000 {
                    true
                } else {
                    (current_elapsed_ms / 1000) % 5 == 0
                };

                if should_probe {
                    icmp_seq = icmp_seq.wrapping_add(1);
                    let icmp_inner = build_icmp_probe_packet(icmp_seq, src_v4_bytes);
                    let mut probe_wire = [0u8; MIMICRY_HEADER_LEN + 64];
                    let seq = (seq_prober.fetch_add(1, Ordering::Relaxed) & 0xFFFF) as u16;

                    let shaped_len = apply_payload_shaping(
                        &icmp_inner,
                        &mut probe_wire[MIMICRY_HEADER_LEN..],
                        &psk,
                        seq,
                        mode,
                        profile,
                    );
                    let total_len = MIMICRY_HEADER_LEN + shaped_len;
                    let full_flags = FLAG_DATA | mode.to_flags();
                    profile.wrap_header(&mut probe_wire[..total_len], full_flags, seq, &psk);

                    if socket_prober.send(&probe_wire[..total_len]).is_ok() {
                        metrics_prober.record_probe_sent(icmp_seq);
                    }
                }

                // Sync live telemetry
                let now = Instant::now();
                let dt = now.duration_since(prev_time).as_secs_f64();
                prev_time = now;

                let tx_now = metrics_prober.total_tx_bytes.load(Ordering::Relaxed);
                let rx_now = metrics_prober.total_rx_bytes.load(Ordering::Relaxed);
                let tx_speed = if dt > 0.0 {
                    (tx_now.saturating_sub(prev_tx)) as f64 / dt
                } else {
                    0.0
                };
                let rx_speed = if dt > 0.0 {
                    (rx_now.saturating_sub(prev_rx)) as f64 / dt
                } else {
                    0.0
                };
                prev_tx = tx_now;
                prev_rx = rx_now;

                let ping = metrics_prober.current_ping_ms.load(Ordering::Relaxed);
                let t = TunnelTelemetry::global();
                t.tx_rate_bps.store(tx_speed as u64, Ordering::Relaxed);
                t.rx_rate_bps.store(rx_speed as u64, Ordering::Relaxed);
                t.total_tx_bytes.store(tx_now, Ordering::Relaxed);
                t.total_rx_bytes.store(rx_now, Ordering::Relaxed);
                t.ping_ms.store(ping, Ordering::Relaxed);
            }
        })
        .map_err(|e| format!("Failed to spawn android_prober thread: {}", e))?;

    if let Ok(mut guard) = state_lock().lock() {
        guard.metrics = Some(metrics);
        guard.active = Some(ActiveTunnel {
            running,
            handles: vec![handle_t2u, handle_u2t, handle_prober],
        });
    }

    Ok(())
}

/// Gracefully stops the background Android tunnel worker threads and releases the UDP socket.
pub fn stop_tunnel() {
    let telem = TunnelTelemetry::global();
    telem.shutdown_requested.store(true, Ordering::SeqCst);

    let active_opt = if let Ok(mut guard) = state_lock().lock() {
        guard.prepared = None;
        guard.active.take()
    } else {
        None
    };

    if let Some(active) = active_opt {
        active.running.store(false, Ordering::SeqCst);
        for handle in active.handles {
            let _ = handle.join();
        }
    }

    telem.set_status(TunnelStatus::Disconnected);
    telem.tx_rate_bps.store(0, Ordering::Relaxed);
    telem.rx_rate_bps.store(0, Ordering::Relaxed);
    telem.ping_ms.store(0, Ordering::Relaxed);
}

/// Returns `[rx_bytes, tx_bytes, rx_packets, tx_packets, rtt_ms]` for live Android UI updates.
pub fn get_telemetry() -> [i64; 5] {
    let (rx_bytes, tx_bytes, rtt_ms) = if let Ok(guard) = state_lock().lock() {
        if let Some(ref m) = guard.metrics {
            (
                m.total_rx_bytes.load(Ordering::Relaxed) as i64,
                m.total_tx_bytes.load(Ordering::Relaxed) as i64,
                m.current_ping_ms.load(Ordering::Relaxed) as i64,
            )
        } else {
            let t = TunnelTelemetry::global();
            (
                t.total_rx_bytes.load(Ordering::Relaxed) as i64,
                t.total_tx_bytes.load(Ordering::Relaxed) as i64,
                t.ping_ms.load(Ordering::Relaxed) as i64,
            )
        }
    } else {
        (0, 0, 0)
    };

    let c = counters();
    let rx_packets = c.rx_packets.load(Ordering::Relaxed) as i64;
    let tx_packets = c.tx_packets.load(Ordering::Relaxed) as i64;

    [rx_bytes, tx_bytes, rx_packets, tx_packets, rtt_ms]
}

/// Decode a `morph://` subscription token into a clean JSON summary for Android UI & VpnService.Builder.
pub fn decode_token_json(token_uri: &str) -> Result<String, String> {
    let token = SubscriptionToken::from_uri(token_uri)?;
    let obj = serde_json::json!({
        "user_id": token.user_id,
        "name": token.name,
        "server_v4": token.server_v4,
        "server_v6": token.server_v6,
        "port": token.port,
        "profile": token.mimic_profile().as_str(),
        "profile_display": token.mimic_profile().display_name(),
        "payload_mode": token.payload_protection_mode().as_str(),
        "assigned_ipv4": token.assigned_ipv4.unwrap_or_else(|| "10.8.0.2".to_string()),
        "assigned_ipv6": token.assigned_ipv6.unwrap_or_else(|| "fd00:8:0::2".to_string()),
        "expires_at": token.expires_at,
        "quota_bytes": token.quota_bytes,
    });
    serde_json::to_string(&obj).map_err(|e| e.to_string())
}
