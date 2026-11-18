package com.morphcore.vpn.data

enum class VpnStatus {
    DISCONNECTED,
    CONNECTING,
    CONNECTED,
    ERROR
}

enum class MainTab {
    TUNNEL,
    TOKENS,
    OPTIONS
}

enum class TransportIpMode(val key: String) {
    AUTO("auto"),
    IPV6("ipv6"),
    IPV4("ipv4");

    companion object {
        fun fromKey(key: String?): TransportIpMode =
            entries.firstOrNull { it.key.equals(key, ignoreCase = true) } ?: AUTO
    }
}

enum class CamouflageProtocol(
    val key: String?,
    val displayName: String,
    val defaultPort: Int?
) {
    AUTO(null, "Auto (Token Profile Default)", null),
    QUIC_V1("quic_v1", "QUIC v1 / HTTP/3", 443),
    QUIC_V2("quic_v2", "QUIC v2 / RFC 9369", 443),
    WEBRTC("webrtc", "WebRTC / SRTP Audio-Video", 3478),
    DTLS("dtls", "DTLS v1.2 / v1.3 VPN", 443),
    STEAM("steam", "Steam A2S Query Engine", 27015),
    SDR("sdr", "Valve Steam Datagram Relay (CS2)", 27020),
    RIOT("riot", "Riot Games League Protocol", 7500),
    ZOOM("zoom", "Zoom Teleconference", 8801),
    DNS("dns", "DNS / mDNS Bypass", 5353),
    ESP("esp", "IPsec ESP Stealth", 4500),
    UTP("utp", "µTP BitTorrent Transport", 6881),
    RAKNET("raknet", "RakNet Game Engine", 19132),
    STUN("stun", "STUN NAT Traversal", 3478),
    TURN("turn", "TURN Relay Protocol", 3478),
    RDP("rdp", "RDP UDP Remote Desktop", 3389),
    DISCORD("discord", "Discord Voice Transport", 50000);

    companion object {
        fun fromKey(key: String?): CamouflageProtocol =
            if (key.isNullOrBlank() || key.equals("auto", ignoreCase = true)) {
                AUTO
            } else {
                entries.firstOrNull { it.key.equals(key, ignoreCase = true) } ?: AUTO
            }
    }
}

enum class PayloadMode(val key: String?) {
    AUTO(null),
    SHAPED("shaped"),
    STREAM("stream"),
    PLAINTEXT("plaintext");

    companion object {
        fun fromKey(key: String?): PayloadMode =
            if (key.isNullOrBlank() || key.equals("auto", ignoreCase = true)) {
                AUTO
            } else {
                entries.firstOrNull { it.key.equals(key, ignoreCase = true) } ?: AUTO
            }
    }
}

data class MorphProfile(
    val id: String,
    val token: String,
    val userId: String,
    val name: String,
    val serverV4: String,
    val serverV6: String,
    val port: Int,
    val profile: String,
    val profileDisplay: String,
    val payloadMode: String,
    val assignedIpv4: String,
    val assignedIpv6: String,
    val expiresAtEpochSec: Long,
    val quotaBytes: Long
) {
    fun effectiveHost(transportIp: TransportIpMode): String {
        return when (transportIp) {
            TransportIpMode.IPV4 -> serverV4.ifBlank { serverV6 }
            TransportIpMode.IPV6 -> serverV6.ifBlank { serverV4 }
            TransportIpMode.AUTO -> serverV6.ifBlank { serverV4 }
        }.ifBlank { "--" }
    }

    fun formattedEndpoint(transportIp: TransportIpMode, portOverride: Int?): String {
        val host = effectiveHost(transportIp)
        val effectivePort = portOverride ?: port
        val displayHost = if (host.contains(":") && !host.startsWith("[")) "[$host]" else host
        return if (effectivePort > 0) "$displayHost:$effectivePort" else "[--:--]"
    }
}

data class TunnelSettings(
    val transportIp: TransportIpMode = TransportIpMode.AUTO,
    val camouflageProtocol: CamouflageProtocol = CamouflageProtocol.AUTO,
    val portOverride: Int? = null,
    val payloadMode: PayloadMode = PayloadMode.AUTO
)

data class TelemetryState(
    val rxBytes: Long = 0L,
    val txBytes: Long = 0L,
    val rxPackets: Long = 0L,
    val txPackets: Long = 0L,
    val rttMs: Long = 0L,
    val rxRateBps: Long = 0L,
    val txRateBps: Long = 0L,
    val rxWaveform: List<Float> = List(30) { 0f },
    val txWaveform: List<Float> = List(30) { 0f },
    val elapsedSeconds: Long = 0L
)
