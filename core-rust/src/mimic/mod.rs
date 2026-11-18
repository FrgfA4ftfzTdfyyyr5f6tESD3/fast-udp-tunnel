//! Multi-Profile Protocol Mimicry Subsystem
//! Supports 16 real-world UDP protocols with zero-config auto-detection:
//! QUIC v1, QUIC v2, WebRTC, DTLS, DNS, IPsec ESP, uTP BitTorrent, RakNet,
//! STUN, TURN, Steam, SDR, Riot Games, Zoom, RDP, and Discord.

#![allow(dead_code)]

pub mod discord;
pub mod dns;
pub mod dtls;
pub mod esp;
pub mod quic;
pub mod quic_v1;
pub mod quic_v2;
pub mod raknet;
pub mod rdp;
pub mod riot;
pub mod sdr;
pub mod steam;
pub mod stun;
pub mod turn;
pub mod utp;
pub mod webrtc;
pub mod zoom;

#[cfg(test)]
mod tests;

pub use crate::common::{
    FLAG_DATA, FLAG_FRAG_1, FLAG_FRAG_2, FLAG_FRAME_MASK, FLAG_KEEPALIVE, FLAG_KEEPALIVE_ACK, MIMICRY_HEADER_LEN,
    MODE_PLAIN, MODE_SHAPED, MODE_STREAM,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MimicProfile {
    QuicV1,
    QuicV2,
    WebRtc,
    Dtls,
    Dns,
    Esp,
    Utp,
    RakNet,
    Stun,
    Turn,
    Steam,
    Sdr,
    Riot,
    Zoom,
    Rdp,
    Discord,
}

impl MimicProfile {
    pub const ALL: [MimicProfile; 16] = [
        MimicProfile::QuicV1,
        MimicProfile::QuicV2,
        MimicProfile::WebRtc,
        MimicProfile::Dtls,
        MimicProfile::Dns,
        MimicProfile::Esp,
        MimicProfile::Utp,
        MimicProfile::RakNet,
        MimicProfile::Stun,
        MimicProfile::Turn,
        MimicProfile::Steam,
        MimicProfile::Sdr,
        MimicProfile::Riot,
        MimicProfile::Zoom,
        MimicProfile::Rdp,
        MimicProfile::Discord,
    ];

    #[inline(always)]
    pub fn from_1_based_index(idx: usize) -> Option<Self> {
        if idx >= 1 && idx <= Self::ALL.len() {
            Some(Self::ALL[idx - 1])
        } else {
            None
        }
    }

    pub fn to_id(&self) -> u8 {
        match self {
            MimicProfile::QuicV1 => 0,
            MimicProfile::QuicV2 => 1,
            MimicProfile::WebRtc => 2,
            MimicProfile::Dtls => 3,
            MimicProfile::Dns => 4,
            MimicProfile::Esp => 5,
            MimicProfile::Utp => 6,
            MimicProfile::RakNet => 7,
            MimicProfile::Stun => 8,
            MimicProfile::Turn => 9,
            MimicProfile::Steam => 10,
            MimicProfile::Sdr => 11,
            MimicProfile::Riot => 12,
            MimicProfile::Zoom => 13,
            MimicProfile::Rdp => 14,
            MimicProfile::Discord => 15,
        }
    }

    pub fn from_id(id: u8) -> Option<Self> {
        match id {
            0 => Some(MimicProfile::QuicV1),
            1 => Some(MimicProfile::QuicV2),
            2 => Some(MimicProfile::WebRtc),
            3 => Some(MimicProfile::Dtls),
            4 => Some(MimicProfile::Dns),
            5 => Some(MimicProfile::Esp),
            6 => Some(MimicProfile::Utp),
            7 => Some(MimicProfile::RakNet),
            8 => Some(MimicProfile::Stun),
            9 => Some(MimicProfile::Turn),
            10 => Some(MimicProfile::Steam),
            11 => Some(MimicProfile::Sdr),
            12 => Some(MimicProfile::Riot),
            13 => Some(MimicProfile::Zoom),
            14 => Some(MimicProfile::Rdp),
            15 => Some(MimicProfile::Discord),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            MimicProfile::QuicV1 => "quic_v1",
            MimicProfile::QuicV2 => "quic_v2",
            MimicProfile::WebRtc => "webrtc",
            MimicProfile::Dtls => "dtls",
            MimicProfile::Dns => "dns",
            MimicProfile::Esp => "esp",
            MimicProfile::Utp => "utp",
            MimicProfile::RakNet => "raknet",
            MimicProfile::Stun => "stun",
            MimicProfile::Turn => "turn",
            MimicProfile::Steam => "steam",
            MimicProfile::Sdr => "sdr",
            MimicProfile::Riot => "riot",
            MimicProfile::Zoom => "zoom",
            MimicProfile::Rdp => "rdp",
            MimicProfile::Discord => "discord",
        }
    }

    pub fn display_name(&self) -> &'static str {
        match self {
            MimicProfile::QuicV1 => "QUIC v1 / HTTP/3 (Web & 4K Streaming - Port 443)",
            MimicProfile::QuicV2 => "QUIC v2 / RFC 9369 (Next-Gen HTTP/3 - Port 443)",
            MimicProfile::WebRtc => "WebRTC / SRTP (Low-Latency VoIP & Gaming - Port 3478)",
            MimicProfile::Dtls => "DTLS 1.2 (Cisco AnyConnect / Corporate VPN - Port 443)",
            MimicProfile::Dns => "DNS Query / mDNS (RFC 6762 / Standard DNS - Port 5353)",
            MimicProfile::Esp => "IPsec NAT-T ESP (Enterprise Encrypted IPsec Tunnel - Port 4500)",
            MimicProfile::Utp => "uTP BitTorrent (P2P High-Throughput Download - Port 6881)",
            MimicProfile::RakNet => "RakNet Game Stream (Minecraft / Mobile Gaming - Port 19132)",
            MimicProfile::Stun => "STUN / ICE Media (WebRTC NAT Traversal - Port 3478)",
            MimicProfile::Turn => "TURN ChannelData (Relayed Media Stream - Port 3478)",
            MimicProfile::Steam => "Steam / Valve Source (CS:GO / Dota 2 Gaming - Port 27015)",
            MimicProfile::Sdr => "Steam Datagram Relay (CS2 / Deadlock / Valve SDR - Port 27020)",
            MimicProfile::Riot => "Riot Games / Valorant (LoL / Valorant Network - Port 7500)",
            MimicProfile::Zoom => "Zoom Media Stream (Enterprise Video Conferencing - Port 8801)",
            MimicProfile::Rdp => "Microsoft RDP over UDP (Enterprise Remote Desktop - Port 3389)",
            MimicProfile::Discord => "Discord Voice & Media (Opus Voice Transport - Port 50000)",
        }
    }

    pub fn default_port(&self) -> u16 {
        match self {
            MimicProfile::QuicV1 | MimicProfile::QuicV2 | MimicProfile::Dtls => 443,
            MimicProfile::WebRtc | MimicProfile::Stun | MimicProfile::Turn => 3478,
            MimicProfile::Dns => 5353,
            MimicProfile::Esp => 4500,
            MimicProfile::Utp => 6881,
            MimicProfile::RakNet => 19132,
            MimicProfile::Steam => 27015,
            MimicProfile::Sdr => 27020,
            MimicProfile::Riot => 7500,
            MimicProfile::Zoom => 8801,
            MimicProfile::Rdp => 3389,
            MimicProfile::Discord => 50000,
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        let clean = s.trim().to_ascii_lowercase().replace('_', "").replace('-', "");
        match clean.as_str() {
            "1" | "quic" | "quic1" | "quicv1" | "http3" | "h3" => Some(MimicProfile::QuicV1),
            "2" | "quic2" | "quicv2" | "rfc9369" => Some(MimicProfile::QuicV2),
            "3" | "webrtc" | "srtp" | "rtp" => Some(MimicProfile::WebRtc),
            "4" | "dtls" | "tls" => Some(MimicProfile::Dtls),
            "5" | "dns" | "mdns" => Some(MimicProfile::Dns),
            "6" | "esp" | "ipsec" => Some(MimicProfile::Esp),
            "7" | "utp" | "torrent" | "bittorrent" => Some(MimicProfile::Utp),
            "8" | "raknet" | "game" | "minecraft" => Some(MimicProfile::RakNet),
            "9" | "stun" | "ice" => Some(MimicProfile::Stun),
            "10" | "turn" | "channeldata" => Some(MimicProfile::Turn),
            "11" | "steam" | "valve" | "source" => Some(MimicProfile::Steam),
            "12" | "sdr" | "valvesdr" | "cs2" => Some(MimicProfile::Sdr),
            "13" | "riot" | "riotgames" | "valorant" => Some(MimicProfile::Riot),
            "14" | "zoom" => Some(MimicProfile::Zoom),
            "15" | "rdp" | "msrdp" | "rdpudp" => Some(MimicProfile::Rdp),
            "16" | "discord" => Some(MimicProfile::Discord),
            _ => None,
        }
    }

    #[inline(always)]
    pub fn wrap_header(&self, buf: &mut [u8], flags: u16, seq: u16, psk: &[u8; 8]) {
        match self {
            MimicProfile::QuicV1 => quic_v1::wrap_quic_v1_header(buf, flags, seq, psk),
            MimicProfile::QuicV2 => quic_v2::wrap_quic_v2_header(buf, flags, seq, psk),
            MimicProfile::WebRtc => webrtc::wrap_webrtc_header(buf, flags, seq, psk),
            MimicProfile::Dtls => dtls::wrap_dtls_header(buf, flags, seq, psk),
            MimicProfile::Dns => dns::wrap_dns_header(buf, flags, seq, psk),
            MimicProfile::Esp => esp::wrap_esp_header(buf, flags, seq, psk),
            MimicProfile::Utp => utp::wrap_utp_header(buf, flags, seq, psk),
            MimicProfile::RakNet => raknet::wrap_raknet_header(buf, flags, seq, psk),
            MimicProfile::Stun => stun::wrap_stun_header(buf, flags, seq, psk),
            MimicProfile::Turn => turn::wrap_turn_header(buf, flags, seq, psk),
            MimicProfile::Steam => steam::wrap_steam_header(buf, flags, seq, psk),
            MimicProfile::Sdr => sdr::wrap_sdr_header(buf, flags, seq, psk),
            MimicProfile::Riot => riot::wrap_riot_header(buf, flags, seq, psk),
            MimicProfile::Zoom => zoom::wrap_zoom_header(buf, flags, seq, psk),
            MimicProfile::Rdp => rdp::wrap_rdp_header(buf, flags, seq, psk),
            MimicProfile::Discord => discord::wrap_discord_header(buf, flags, seq, psk),
        }
    }

    #[inline(always)]
    pub fn unwrap_header(&self, packet: &[u8], psk: &[u8; 8]) -> Option<(u16, u16)> {
        match self {
            MimicProfile::QuicV1 => quic_v1::unwrap_quic_v1_header(packet, psk),
            MimicProfile::QuicV2 => quic_v2::unwrap_quic_v2_header(packet, psk),
            MimicProfile::WebRtc => webrtc::unwrap_webrtc_header(packet, psk),
            MimicProfile::Dtls => dtls::unwrap_dtls_header(packet, psk),
            MimicProfile::Dns => dns::unwrap_dns_header(packet, psk),
            MimicProfile::Esp => esp::unwrap_esp_header(packet, psk),
            MimicProfile::Utp => utp::unwrap_utp_header(packet, psk),
            MimicProfile::RakNet => raknet::unwrap_raknet_header(packet, psk),
            MimicProfile::Stun => stun::unwrap_stun_header(packet, psk),
            MimicProfile::Turn => turn::unwrap_turn_header(packet, psk),
            MimicProfile::Steam => steam::unwrap_steam_header(packet, psk),
            MimicProfile::Sdr => sdr::unwrap_sdr_header(packet, psk),
            MimicProfile::Riot => riot::unwrap_riot_header(packet, psk),
            MimicProfile::Zoom => zoom::unwrap_zoom_header(packet, psk),
            MimicProfile::Rdp => rdp::unwrap_rdp_header(packet, psk),
            MimicProfile::Discord => discord::unwrap_discord_header(packet, psk),
        }
    }
}

/// Zero-Config Server-Side Auto-Detection:
/// Detects profile from distinct magic signatures across all 16 supported protocols.
#[inline(always)]
pub fn auto_detect_and_unwrap(packet: &[u8], psk: &[u8; 8]) -> Option<(MimicProfile, u16, u16)> {
    if packet.len() < MIMICRY_HEADER_LEN {
        return None;
    }

    // 1. Steam / Valve Source Engine: 0xFF 0xFF 0xFF 0xFF 0x55
    if packet.len() >= 5 && &packet[0..4] == &steam::MAGIC_A2S_HEADER && packet[4] == steam::MAGIC_A2S_OPCODE {
        if let Some((f, s)) = steam::unwrap_steam_header(packet, psk) {
            return Some((MimicProfile::Steam, f, s));
        }
    }

    // 2. Microsoft RDP over UDP: 0xFF 0xFF 0xFF 0xFF 0x00 0x00 0x00 0x01
    if packet.len() >= 8 && &packet[0..4] == &rdp::MAGIC_RDP_PREFIX && packet[4] == 0x00 && &packet[6..8] == &rdp::MAGIC_RDP_SYN_FLAGS {
        if let Some((f, s)) = rdp::unwrap_rdp_header(packet, psk) {
            return Some((MimicProfile::Rdp, f, s));
        }
    }

    // 3. Steam Datagram Relay (SDR): 0x08 0x00 "sdping"
    if packet.len() >= 8 && &packet[0..2] == &sdr::MAGIC_SDR_PREFIX && &packet[2..8] == sdr::MAGIC_SDR_TAG {
        if let Some((f, s)) = sdr::unwrap_sdr_header(packet, psk) {
            return Some((MimicProfile::Sdr, f, s));
        }
    }

    // 4. QUIC v2: 0xD3 [0x6B, 0x33, 0x43, 0xCF]
    if packet[0] == quic_v2::MAGIC_INITIAL && &packet[1..5] == &quic_v2::QUIC_V2_VERSION {
        if let Some((f, s)) = quic_v2::unwrap_quic_v2_header(packet, psk) {
            return Some((MimicProfile::QuicV2, f, s));
        }
    }

    // 5. WebRTC: 0x80 0x60 and SSRC
    if packet[0] == webrtc::MAGIC_V2 && packet[1] == webrtc::MAGIC_PT96 && packet.len() >= 12 && &packet[8..12] == &webrtc::MAGIC_SSRC {
        if let Some((f, s)) = webrtc::unwrap_webrtc_header(packet, psk) {
            return Some((MimicProfile::WebRtc, f, s));
        }
    }

    // 6. Discord Voice / Media: 0x80 0x78 and SSRC
    if packet[0] == discord::MAGIC_DISCORD_RTP[0] && packet[1] == discord::MAGIC_DISCORD_RTP[1] && packet.len() >= 8 && &packet[4..8] == &discord::MAGIC_DISCORD_SSRC {
        if let Some((f, s)) = discord::unwrap_discord_header(packet, psk) {
            return Some((MimicProfile::Discord, f, s));
        }
    }

    // 7. RakNet: 0x84 and (flags & 0x0F) == 0
    if packet[0] == raknet::MAGIC_RAKNET_FRAME && packet.len() >= 5 && (packet[4] & 0x0F) == 0 {
        if let Some((f, s)) = raknet::unwrap_raknet_header(packet, psk) {
            return Some((MimicProfile::RakNet, f, s));
        }
    }

    // 8. DTLS: 0x17 0xFE 0xFD
    if packet[0] == dtls::MAGIC_CONTENT_TYPE && packet[1] == dtls::MAGIC_VERSION_MAJOR && packet[2] == dtls::MAGIC_VERSION_MINOR {
        if let Some((f, s)) = dtls::unwrap_dtls_header(packet, psk) {
            return Some((MimicProfile::Dtls, f, s));
        }
    }

    // 9. IPsec ESP: 0x19 0x84 0x07 0x10
    if packet.starts_with(&esp::MAGIC_SPI) {
        if let Some((f, s)) = esp::unwrap_esp_header(packet, psk) {
            return Some((MimicProfile::Esp, f, s));
        }
    }

    // 10. TURN ChannelData: 0x40 0x01
    if packet[0] == turn::MAGIC_CHANNEL_NUM[0] && packet[1] == turn::MAGIC_CHANNEL_NUM[1] {
        if let Some((f, s)) = turn::unwrap_turn_header(packet, psk) {
            return Some((MimicProfile::Turn, f, s));
        }
    }

    // 11. Zoom Media Stream: 0x01 0x00 0x03 0x00 (non-blocking fallback to uTP if PSK fails)
    if packet.len() >= 4 && &packet[0..3] == &zoom::MAGIC_ZOOM_PREFIX && packet[3] == 0x00 {
        if let Some((f, s)) = zoom::unwrap_zoom_header(packet, psk) {
            return Some((MimicProfile::Zoom, f, s));
        }
    }

    // 12. uTP BitTorrent: 0x01 0x00
    if packet[0] == utp::MAGIC_TYPE_DATA && packet[1] == utp::MAGIC_EXT_NONE {
        if let Some((f, s)) = utp::unwrap_utp_header(packet, psk) {
            return Some((MimicProfile::Utp, f, s));
        }
    }

    // 13. Riot Games: 0x00 0x01 0x52 0x47
    if packet.len() >= 4 && &packet[0..4] == &riot::MAGIC_RIOT_PREFIX {
        if let Some((f, s)) = riot::unwrap_riot_header(packet, psk) {
            return Some((MimicProfile::Riot, f, s));
        }
    }

    // 14. STUN / ICE: 0x00 0x01 and Cookie
    if packet[0] == stun::MAGIC_STUN_TYPE[0] && packet[1] == stun::MAGIC_STUN_TYPE[1] && packet.len() >= 8 && &packet[4..8] == &stun::MAGIC_STUN_COOKIE {
        if let Some((f, s)) = stun::unwrap_stun_header(packet, psk) {
            return Some((MimicProfile::Stun, f, s));
        }
    }

    // 15. DNS: bytes 2..6 == 0x01 0x00 0x00 0x01
    if packet.len() >= 6 && &packet[2..6] == &dns::MAGIC_DNS_FLAGS {
        if let Some((f, s)) = dns::unwrap_dns_header(packet, psk) {
            return Some((MimicProfile::Dns, f, s));
        }
    }

    // 16. QUIC v1: 0x43
    if packet[0] == quic_v1::MAGIC_BYTE {
        if let Some((f, s)) = quic_v1::unwrap_quic_v1_header(packet, psk) {
            return Some((MimicProfile::QuicV1, f, s));
        }
    }

    None
}

/// Hybrid Port-Hint Fast-Path & Fallback Auto-Detection:
/// Tries the official protocols associated with `local_port` first. If unmatched (e.g. emergency
/// port override by client), falls back to full 16-profile auto-detection.
#[inline(always)]
pub fn port_hint_and_auto_detect(packet: &[u8], local_port: u16, psk: &[u8; 8]) -> Option<(MimicProfile, u16, u16)> {
    if packet.len() < MIMICRY_HEADER_LEN {
        return None;
    }

    // 1. Port-Specific Fast Hints
    match local_port {
        443 => {
            if packet[0] == quic_v1::MAGIC_BYTE {
                if let Some((f, s)) = quic_v1::unwrap_quic_v1_header(packet, psk) {
                    return Some((MimicProfile::QuicV1, f, s));
                }
            }
            if packet[0] == quic_v2::MAGIC_INITIAL && &packet[1..5] == &quic_v2::QUIC_V2_VERSION {
                if let Some((f, s)) = quic_v2::unwrap_quic_v2_header(packet, psk) {
                    return Some((MimicProfile::QuicV2, f, s));
                }
            }
            if packet[0] == dtls::MAGIC_CONTENT_TYPE && packet[1] == dtls::MAGIC_VERSION_MAJOR && packet[2] == dtls::MAGIC_VERSION_MINOR {
                if let Some((f, s)) = dtls::unwrap_dtls_header(packet, psk) {
                    return Some((MimicProfile::Dtls, f, s));
                }
            }
        }
        3478 => {
            if packet[0] == webrtc::MAGIC_V2 && packet[1] == webrtc::MAGIC_PT96 && packet.len() >= 12 && &packet[8..12] == &webrtc::MAGIC_SSRC {
                if let Some((f, s)) = webrtc::unwrap_webrtc_header(packet, psk) {
                    return Some((MimicProfile::WebRtc, f, s));
                }
            }
            if packet[0] == stun::MAGIC_STUN_TYPE[0] && packet[1] == stun::MAGIC_STUN_TYPE[1] && packet.len() >= 8 && &packet[4..8] == &stun::MAGIC_STUN_COOKIE {
                if let Some((f, s)) = stun::unwrap_stun_header(packet, psk) {
                    return Some((MimicProfile::Stun, f, s));
                }
            }
            if packet[0] == turn::MAGIC_CHANNEL_NUM[0] && packet[1] == turn::MAGIC_CHANNEL_NUM[1] {
                if let Some((f, s)) = turn::unwrap_turn_header(packet, psk) {
                    return Some((MimicProfile::Turn, f, s));
                }
            }
        }
        8801 => {
            if packet.len() >= 4 && &packet[0..3] == &zoom::MAGIC_ZOOM_PREFIX && packet[3] == 0x00 {
                if let Some((f, s)) = zoom::unwrap_zoom_header(packet, psk) {
                    return Some((MimicProfile::Zoom, f, s));
                }
            }
        }
        7500 => {
            if packet.len() >= 4 && &packet[0..4] == &riot::MAGIC_RIOT_PREFIX {
                if let Some((f, s)) = riot::unwrap_riot_header(packet, psk) {
                    return Some((MimicProfile::Riot, f, s));
                }
            }
        }
        27020 => {
            if packet.len() >= 8 && &packet[0..2] == &sdr::MAGIC_SDR_PREFIX && &packet[2..8] == sdr::MAGIC_SDR_TAG {
                if let Some((f, s)) = sdr::unwrap_sdr_header(packet, psk) {
                    return Some((MimicProfile::Sdr, f, s));
                }
            }
        }
        27015 => {
            if packet.len() >= 5 && &packet[0..4] == &steam::MAGIC_A2S_HEADER && packet[4] == steam::MAGIC_A2S_OPCODE {
                if let Some((f, s)) = steam::unwrap_steam_header(packet, psk) {
                    return Some((MimicProfile::Steam, f, s));
                }
            }
        }
        3389 => {
            if packet.len() >= 8 && &packet[0..4] == &rdp::MAGIC_RDP_PREFIX && packet[4] == 0x00 && &packet[6..8] == &rdp::MAGIC_RDP_SYN_FLAGS {
                if let Some((f, s)) = rdp::unwrap_rdp_header(packet, psk) {
                    return Some((MimicProfile::Rdp, f, s));
                }
            }
        }
        50000 => {
            if packet[0] == discord::MAGIC_DISCORD_RTP[0] && packet[1] == discord::MAGIC_DISCORD_RTP[1] && packet.len() >= 8 && &packet[4..8] == &discord::MAGIC_DISCORD_SSRC {
                if let Some((f, s)) = discord::unwrap_discord_header(packet, psk) {
                    return Some((MimicProfile::Discord, f, s));
                }
            }
        }
        19132 => {
            if packet[0] == raknet::MAGIC_RAKNET_FRAME && packet.len() >= 5 && (packet[4] & 0x0F) == 0 {
                if let Some((f, s)) = raknet::unwrap_raknet_header(packet, psk) {
                    return Some((MimicProfile::RakNet, f, s));
                }
            }
        }
        4500 => {
            if packet.starts_with(&esp::MAGIC_SPI) {
                if let Some((f, s)) = esp::unwrap_esp_header(packet, psk) {
                    return Some((MimicProfile::Esp, f, s));
                }
            }
        }
        6881 => {
            if packet[0] == utp::MAGIC_TYPE_DATA && packet[1] == utp::MAGIC_EXT_NONE {
                if let Some((f, s)) = utp::unwrap_utp_header(packet, psk) {
                    return Some((MimicProfile::Utp, f, s));
                }
            }
        }
        5353 => {
            if packet.len() >= 6 && &packet[2..6] == &dns::MAGIC_DNS_FLAGS {
                if let Some((f, s)) = dns::unwrap_dns_header(packet, psk) {
                    return Some((MimicProfile::Dns, f, s));
                }
            }
        }
        _ => {}
    }

    // 2. Fallback: Full zero-config auto-detection across all 16 profiles
    auto_detect_and_unwrap(packet, psk)
}
