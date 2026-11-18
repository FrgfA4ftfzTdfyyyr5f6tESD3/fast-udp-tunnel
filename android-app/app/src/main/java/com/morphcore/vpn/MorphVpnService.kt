package com.morphcore.vpn

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.ServiceInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import android.os.SystemClock
import androidx.core.app.NotificationCompat
import androidx.core.content.ContextCompat
import com.example.MainActivity
import com.example.R
import com.morphcore.vpn.data.MorphProfile
import com.morphcore.vpn.data.TokenParser
import com.morphcore.vpn.data.VpnStatus
import com.morphcore.vpn.service.VpnStateManager
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.Job
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.cancelAndJoin
import kotlinx.coroutines.delay
import kotlinx.coroutines.isActive
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import java.net.Inet4Address
import java.net.Inet6Address
import java.net.InetAddress
import java.util.concurrent.atomic.AtomicBoolean

class MorphVpnService : VpnService() {

    private val serviceScope = CoroutineScope(SupervisorJob() + Dispatchers.IO)
    private val lifecycleMutex = Mutex()
    private var connectionJob: Job? = null
    private var telemetryJob: Job? = null

    @Volatile
    private var tunPfd: ParcelFileDescriptor? = null

    @Volatile
    private var tunnelStarted: Boolean = false

    private val isStopping = AtomicBoolean(false)

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        when (intent?.action) {
            ACTION_DISCONNECT -> {
                disconnectAndStop(preserveError = false)
                return START_NOT_STICKY
            }

            ACTION_CONNECT -> {
                val token = intent.getStringExtra(EXTRA_TOKEN).orEmpty()
                val mimicOverride = intent.getStringExtra(EXTRA_MIMIC_OVERRIDE)
                val payloadModeOverride = intent.getStringExtra(EXTRA_PAYLOAD_MODE_OVERRIDE)
                val transportOverride = intent.getStringExtra(EXTRA_TRANSPORT_OVERRIDE)
                val portOverride = intent.getIntExtra(EXTRA_PORT_OVERRIDE, 0)
                val profileName = intent.getStringExtra(EXTRA_PROFILE_NAME).orEmpty()

                if (token.isBlank()) {
                    VpnStateManager.setError(getString(R.string.token_invalid_error))
                    stopSelf()
                    return START_NOT_STICKY
                }

                startConnection(
                    token = token,
                    mimicOverride = mimicOverride,
                    payloadModeOverride = payloadModeOverride,
                    transportOverride = transportOverride,
                    portOverride = portOverride,
                    profileName = profileName
                )
                return START_STICKY
            }

            else -> {
                if (VpnStateManager.status.value == VpnStatus.DISCONNECTED) {
                    stopSelf()
                }
                return START_NOT_STICKY
            }
        }
    }

    private fun startConnection(
        token: String,
        mimicOverride: String?,
        payloadModeOverride: String?,
        transportOverride: String?,
        portOverride: Int,
        profileName: String
    ) {
        val previousConnJob = connectionJob
        val previousTeleJob = telemetryJob
        isStopping.set(false)

        VpnStateManager.setConnecting()
        ensureNotificationChannel()
        promoteToForeground(
            buildNotification(
                title = getString(R.string.vpn_notif_connecting),
                contentText = profileName.ifBlank { getString(R.string.app_name) }
            )
        )

        connectionJob = serviceScope.launch {
            lifecycleMutex.withLock {
                previousTeleJob?.cancelAndJoin()
                previousConnJob?.cancelAndJoin()
                tearDownNativeAndTun()

                try {
                    // 1. Decode morph:// token via native engine
                    val tokenJson = MorphNative.decodeTokenInfo(token)
                    val profile = TokenParser.parseDecodedJson(token, tokenJson)
                    if (profile == null) {
                        failAndStop(getString(R.string.token_invalid_error))
                        return@launch
                    }

                    // 2. Prepare connected UDP socket in Rust core before TUN establish
                    val udpFd = MorphNative.prepareSocketEx(
                        token = token,
                        mimicOverride = mimicOverride,
                        payloadModeOverride = payloadModeOverride,
                        transportOverride = transportOverride,
                        portOverride = portOverride
                    )
                    if (udpFd < 0) {
                        failAndStop("Unable to reach server endpoint — check network connection")
                        return@launch
                    }

                    // 3. Protect UDP socket directly from VPN routing loop
                    if (!protect(udpFd)) {
                        failAndStop("Failed to protect native socket from routing loop")
                        return@launch
                    }

                    // 4. Configure TUN interface with RFC 6724 Global-Scope IPv6 precedence (IPv6-First Egress)
                    //    + IPv4 fallback, matching the Windows 1500B MTU + 1200B Micro-Segmentation architecture.
                    val tunIpv4 = sanitizeIpv4(profile.assignedIpv4)
                    val tunIpv6 = toGlobalElevatedIpv6(profile.assignedIpv6)

                    val builder = Builder()
                        .setSession("Morph Core")
                        .setMtu(1500)
                        .addAddress(tunIpv6, 64)
                        .addAddress(tunIpv4, 24)
                        .addDnsServer(TUN_GLOBAL_V6_DNS)
                        .addDnsServer("2606:4700:4700::1111")
                        .addDnsServer("10.8.0.1")
                        .addRoute("::", 0)
                        .addRoute("0.0.0.0", 0)

                    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                        builder.setMetered(false)
                    }

                    val pfd = builder.establish()
                    if (pfd == null) {
                        failAndStop(getString(R.string.vpn_permission_denied))
                        return@launch
                    }
                    tunPfd = pfd

                    // 5. Start Rust full-duplex high-throughput engine (recvmmsg + TUN burst drain + NPTv6)
                    if (!MorphNative.startTunnel(pfd.fd)) {
                        failAndStop("Morph Core tunnel failed to initialize")
                        return@launch
                    }
                    tunnelStarted = true

                    VpnStateManager.setConnected()
                    updateNotification(
                        title = getString(R.string.vpn_notif_title),
                        contentText = profile.name
                    )

                    // 6. Lightweight 500ms telemetry polling loop for UI & notification
                    startTelemetryLoop(profile)
                } catch (t: Throwable) {
                    failAndStop(t.message ?: "Unexpected VPN connection error")
                }
            }
        }
    }

    private fun sanitizeIpv4(candidate: String): String {
        val valid = runCatching { InetAddress.getByName(candidate) is Inet4Address }.getOrDefault(false)
        return if (valid) candidate else "10.8.0.2"
    }

    /**
     * Maps internal ULA `fd00:8::/64` address to checksum-neutral Global-Scope `2001:db8:0:cf4f::/64`.
     * Elevates IPv6 above IPv4 in Android Bionic RFC 6724 (prec 40 > prec 35) so Chrome, Gemini, and
     * all dual-stack apps exit via the server's clean IPv6 first while preserving IPv4 fallback.
     */
    private fun toGlobalElevatedIpv6(candidate: String): String {
        val parsed = runCatching { InetAddress.getByName(candidate) as? Inet6Address }.getOrNull()
            ?: return "2001:db8:0:cf4f::2"
        val bytes = parsed.address
        if (bytes.size == 16 &&
            bytes[0] == 0xfd.toByte() && bytes[1] == 0x00.toByte() &&
            bytes[2] == 0x00.toByte() && bytes[3] == 0x08.toByte() &&
            bytes[4] == 0x00.toByte() && bytes[5] == 0x00.toByte() &&
            bytes[6] == 0x00.toByte() && bytes[7] == 0x00.toByte()
        ) {
            val mapped = bytes.clone()
            mapped[0] = 0x20.toByte()
            mapped[1] = 0x01.toByte()
            mapped[2] = 0x0d.toByte()
            mapped[3] = 0xb8.toByte()
            mapped[4] = 0x00.toByte()
            mapped[5] = 0x00.toByte()
            mapped[6] = 0xcf.toByte()
            mapped[7] = 0x4f.toByte()
            return InetAddress.getByAddress(mapped).hostAddress ?: "2001:db8:0:cf4f::2"
        }
        return candidate
    }

    private fun startTelemetryLoop(profile: MorphProfile) {
        telemetryJob?.cancel()
        telemetryJob = serviceScope.launch {
            val connectedAtMs = SystemClock.elapsedRealtime()
            var prevTimeMs = connectedAtMs
            var prevRxBytes = 0L
            var prevTxBytes = 0L
            var hasPreviousSample = false
            var tickCount = 0

            while (isActive && tunnelStarted && !isStopping.get()) {
                val stats = runCatching { MorphNative.getTelemetry() }.getOrNull()
                val nowMs = SystemClock.elapsedRealtime()

                if (stats != null && stats.size >= 5) {
                    val rxBytes = stats[0].coerceAtLeast(0L)
                    val txBytes = stats[1].coerceAtLeast(0L)
                    val rxPackets = stats[2].coerceAtLeast(0L)
                    val txPackets = stats[3].coerceAtLeast(0L)
                    val rttMs = stats[4].coerceAtLeast(0L)

                    val dtMs = (nowMs - prevTimeMs).coerceAtLeast(1L)
                    val rxRateBps = if (hasPreviousSample && rxBytes >= prevRxBytes) {
                        ((rxBytes - prevRxBytes) * 1000L) / dtMs
                    } else {
                        0L
                    }
                    val txRateBps = if (hasPreviousSample && txBytes >= prevTxBytes) {
                        ((txBytes - prevTxBytes) * 1000L) / dtMs
                    } else {
                        0L
                    }

                    prevRxBytes = rxBytes
                    prevTxBytes = txBytes
                    prevTimeMs = nowMs
                    hasPreviousSample = true

                    val elapsedSec = ((nowMs - connectedAtMs) / 1000L).coerceAtLeast(0L)
                    tickCount++

                    VpnStateManager.updateTelemetry(
                        rxBytes = rxBytes,
                        txBytes = txBytes,
                        rxPackets = rxPackets,
                        txPackets = txPackets,
                        rttMs = rttMs,
                        rxRateBps = rxRateBps,
                        txRateBps = txRateBps,
                        elapsedSeconds = elapsedSec
                    )

                    if (tickCount % 2 == 0) {
                        val (dlVal, dlUnit) = TokenParser.formatSpeed(rxRateBps)
                        val (ulVal, ulUnit) = TokenParser.formatSpeed(txRateBps)
                        val rttText = if (rttMs > 0L) " • ${rttMs}ms" else ""
                        updateNotification(
                            title = "${getString(R.string.vpn_notif_title)} (${profile.name})",
                            contentText = "↓ $dlVal $dlUnit  ↑ $ulVal $ulUnit$rttText"
                        )
                    }
                }
                delay(TELEMETRY_POLL_MS)
            }
        }
    }

    private fun failAndStop(message: String) {
        VpnStateManager.setError(message)
        disconnectAndStop(preserveError = true)
    }

    private fun disconnectAndStop(preserveError: Boolean) {
        if (!isStopping.compareAndSet(false, true)) return
        connectionJob?.cancel()
        telemetryJob?.cancel()

        tearDownNativeAndTun()

        if (!preserveError) {
            VpnStateManager.setDisconnected()
        }
        stopForeground(STOP_FOREGROUND_REMOVE)
        stopSelf()
    }

    private fun tearDownNativeAndTun() {
        if (tunnelStarted) {
            runCatching { MorphNative.stopTunnel() }
            tunnelStarted = false
        }
        val pfd = tunPfd
        tunPfd = null
        if (pfd != null) {
            runCatching { pfd.close() }
        }
    }

    override fun onRevoke() {
        super.onRevoke()
        disconnectAndStop(preserveError = false)
    }

    override fun onDestroy() {
        connectionJob?.cancel()
        telemetryJob?.cancel()
        tearDownNativeAndTun()
        if (VpnStateManager.status.value != VpnStatus.ERROR) {
            VpnStateManager.setDisconnected()
        }
        stopForeground(STOP_FOREGROUND_REMOVE)
        serviceScope.cancel()
        super.onDestroy()
    }

    private fun promoteToForeground(notification: Notification) {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
            startForeground(
                NOTIFICATION_ID,
                notification,
                ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
            )
        } else {
            startForeground(NOTIFICATION_ID, notification)
        }
    }

    private fun updateNotification(title: String, contentText: String) {
        val manager = getSystemService(NotificationManager::class.java) ?: return
        manager.notify(NOTIFICATION_ID, buildNotification(title, contentText))
    }

    private fun buildNotification(title: String, contentText: String): Notification {
        val openAppIntent = Intent(this, MainActivity::class.java).apply {
            flags = Intent.FLAG_ACTIVITY_SINGLE_TOP or Intent.FLAG_ACTIVITY_CLEAR_TOP
        }
        val contentPendingIntent = PendingIntent.getActivity(
            this,
            0,
            openAppIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        val disconnectIntent = Intent(this, MorphVpnService::class.java).apply {
            action = ACTION_DISCONNECT
        }
        val disconnectPendingIntent = PendingIntent.getService(
            this,
            1,
            disconnectIntent,
            PendingIntent.FLAG_UPDATE_CURRENT or PendingIntent.FLAG_IMMUTABLE
        )

        return NotificationCompat.Builder(this, getString(R.string.vpn_channel_id))
            .setSmallIcon(R.drawable.ic_vpn_shield)
            .setContentTitle(title)
            .setContentText(contentText)
            .setContentIntent(contentPendingIntent)
            .setOngoing(true)
            .setOnlyAlertOnce(true)
            .setCategory(NotificationCompat.CATEGORY_SERVICE)
            .setPriority(NotificationCompat.PRIORITY_LOW)
            .addAction(
                0,
                getString(R.string.vpn_notif_disconnect),
                disconnectPendingIntent
            )
            .build()
    }

    private fun ensureNotificationChannel() {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val channelId = getString(R.string.vpn_channel_id)
            val manager = getSystemService(NotificationManager::class.java) ?: return
            if (manager.getNotificationChannel(channelId) == null) {
                val channel = NotificationChannel(
                    channelId,
                    getString(R.string.vpn_channel_name),
                    NotificationManager.IMPORTANCE_LOW
                ).apply {
                    description = getString(R.string.vpn_channel_description)
                    setShowBadge(false)
                }
                manager.createNotificationChannel(channel)
            }
        }
    }

    companion object {
        private const val NOTIFICATION_ID = 1087
        private const val TELEMETRY_POLL_MS = 500L
        private const val TUN_GLOBAL_V6_DNS = "2001:db8:0:cf4f::1"

        const val ACTION_CONNECT = "com.morphcore.vpn.action.CONNECT"
        const val ACTION_DISCONNECT = "com.morphcore.vpn.action.DISCONNECT"

        const val EXTRA_TOKEN = "extra_token"
        const val EXTRA_MIMIC_OVERRIDE = "extra_mimic_override"
        const val EXTRA_PAYLOAD_MODE_OVERRIDE = "extra_payload_mode_override"
        const val EXTRA_TRANSPORT_OVERRIDE = "extra_transport_override"
        const val EXTRA_PORT_OVERRIDE = "extra_port_override"
        const val EXTRA_PROFILE_NAME = "extra_profile_name"

        fun startConnect(
            context: Context,
            token: String,
            mimicOverride: String?,
            payloadModeOverride: String?,
            transportOverride: String?,
            portOverride: Int?,
            profileName: String
        ) {
            val intent = Intent(context, MorphVpnService::class.java).apply {
                action = ACTION_CONNECT
                putExtra(EXTRA_TOKEN, token)
                putExtra(EXTRA_MIMIC_OVERRIDE, mimicOverride)
                putExtra(EXTRA_PAYLOAD_MODE_OVERRIDE, payloadModeOverride)
                putExtra(EXTRA_TRANSPORT_OVERRIDE, transportOverride)
                putExtra(EXTRA_PORT_OVERRIDE, portOverride ?: 0)
                putExtra(EXTRA_PROFILE_NAME, profileName)
            }
            ContextCompat.startForegroundService(context, intent)
        }

        fun startDisconnect(context: Context) {
            val intent = Intent(context, MorphVpnService::class.java).apply {
                action = ACTION_DISCONNECT
            }
            context.startService(intent)
        }
    }
}
