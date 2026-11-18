package com.morphcore.vpn

object MorphNative {
    init {
        System.loadLibrary("morph_core")
    }

    external fun prepareSocket(
        token: String,
        mimicOverride: String?,
        payloadModeOverride: String?
    ): Int

    external fun prepareSocketEx(
        token: String,
        mimicOverride: String?,
        payloadModeOverride: String?,
        transportOverride: String?,
        portOverride: Int
    ): Int

    external fun startTunnel(tunFd: Int): Boolean

    external fun stopTunnel()

    external fun getTelemetry(): LongArray // [rx_bytes, tx_bytes, rx_packets, tx_packets, rtt_ms]

    external fun decodeTokenInfo(token: String): String // JSON or "" if invalid
}
