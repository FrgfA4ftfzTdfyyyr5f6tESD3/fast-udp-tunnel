//! Central Unified Network Constants & Boundaries.
//! Eliminates magic numbers and duplicate definitions across Client, Server, Mimic, Tuner, and Capacity modules.

/// Total maximum UDP wire datagram size on the physical network (guarantees zero MTU fragmentation).
/// 1420 bytes safely encapsulates 1360 MTU + 20-byte mimicry header + shaping overhead
/// while remaining well within physical PMTU (1500 - 40 IPv6 - 8 UDP = 1452 bytes).
pub const WIRE_MTU: usize = 1420;

/// Inner RAW IP MTU for Wintun (Windows). Standard full 1500 MTU backed by Micro-Segmentation.
pub const TUNNEL_MTU: u32 = 1500;

/// Linux Kernel TUN interface maximum MTU ceiling.
/// Synchronized with TUNNEL_MTU (1500) so all modern protocols (TCP, QUIC, UDP) operate natively.
pub const SERVER_TUN_CEILING_MTU: u32 = 1500;

/// Modern and Legacy subscription token URI prefixes
pub const TOKEN_URI_PREFIX: &str = "morph://";
pub const LEGACY_TOKEN_URI_PREFIX: &str = "fudp://";

/// Standard TCP Maximum Segment Size for IPv4 tunnels (1500 - 20 IP - 20 TCP = 1460).
pub const TCP_MSS_IPV4: u16 = 1460;

/// Standard TCP Maximum Segment Size for IPv6 tunnels (1500 - 40 IPv6 - 20 TCP = 1440).
pub const TCP_MSS_IPV6: u16 = 1440;

/// Standard listening UDP ports bound concurrently by the server across all 16 profiles.
pub const STANDARD_PORTS: &[u16] = &[
    443, 3478, 19132, 27015, 27020, 7500, 8801, 3389, 50000, 5353, 4500, 6881, 7190, 53,
];

/// Default primary tunnel listening port.
pub const DEFAULT_PORT: u16 = 7190;

/// Fixed 20-byte wire header length for all 16 camouflage protocols.
pub const MIMICRY_HEADER_LEN: usize = 20;

/// Mimicry Frame Type Flags (Mask: 0x000F)
pub const FLAG_DATA: u16 = 0x0001;
pub const FLAG_KEEPALIVE: u16 = 0x0002;
pub const FLAG_KEEPALIVE_ACK: u16 = 0x0003;
pub const FLAG_FRAG_1: u16 = 0x0004;
pub const FLAG_FRAG_2: u16 = 0x0005;
pub const FLAG_FRAME_MASK: u16 = 0x000F;

/// Threshold above which IP packets are split into two micro-segments on wire (1200 bytes)
pub const FRAGMENT_THRESHOLD: usize = 1200;

/// Payload Protection Mode Flags (Mask: 0x00F0)
pub const MODE_SHAPED: u16 = 0x0000;
pub const MODE_STREAM: u16 = 0x0010;
pub const MODE_PLAIN: u16 = 0x0020;

/// Master built-in fallback PSK authentication token
pub const DEFAULT_PSK: [u8; 8] = [0xA5, 0x5C, 0x3E, 0x7F, 0x91, 0x2D, 0x4B, 0x88];

/// Socket buffer sizes
pub const CLIENT_SOCKET_BUFFER_SIZE: i32 = 16 * 1024 * 1024; // 16 MB for Windows client
pub const SERVER_SOCKET_BUFFER_SIZE: i32 = 2 * 1024 * 1024;  // 2 MB safe baseline for Linux VPS

/// Anti-DPI WireGuard-Style Keepalive Timing & Padding
pub const KEEPALIVE_JITTER_MIN_MS: u64 = 20_000;
pub const KEEPALIVE_JITTER_MAX_MS: u64 = 25_000;
pub const KEEPALIVE_PADDING_MIN_BYTES: usize = 32;
pub const KEEPALIVE_PADDING_MAX_BYTES: usize = 128;

/// IP version preference when connecting with subscription tokens
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpPreference {
    Auto,
    ForceV4,
    ForceV6,
}

/// Server Session Life-Cycle & Pruning Boundaries
pub const SESSION_IDLE_TIMEOUT_SECS: u64 = 60;
pub const MAX_PINNED_SESSIONS: usize = 128;
