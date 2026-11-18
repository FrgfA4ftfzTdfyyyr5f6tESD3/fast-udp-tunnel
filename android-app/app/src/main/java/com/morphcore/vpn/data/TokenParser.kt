package com.morphcore.vpn.data

import org.json.JSONObject
import java.util.Locale
import java.util.UUID

object TokenParser {

    private fun optCleanString(obj: JSONObject, key: String, fallback: String = ""): String {
        if (!obj.has(key) || obj.isNull(key)) return fallback
        val value = obj.optString(key, "").trim()
        return if (value.isEmpty() || value.equals("null", ignoreCase = true)) {
            fallback
        } else {
            value
        }
    }

    fun parseDecodedJson(token: String, jsonString: String): MorphProfile? {
        if (jsonString.isBlank()) return null
        return runCatching {
            val obj = JSONObject(jsonString)
            val userId = optCleanString(obj, "user_id")
            val rawName = optCleanString(obj, "name")
            val serverV4 = optCleanString(obj, "server_v4")
            val serverV6 = optCleanString(obj, "server_v6")
            val port = obj.optInt("port", 443).let { if (it in 1..65535) it else 443 }
            val profile = optCleanString(obj, "profile")
                .ifBlank { optCleanString(obj, "profile_id", "auto") }
            val profileDisplay = optCleanString(obj, "profile_display", profile.uppercase(Locale.US))
            val payloadMode = optCleanString(obj, "payload_mode", "shaped")
            val assignedIpv4 = optCleanString(obj, "assigned_ipv4", "10.8.0.2")
            val assignedIpv6 = optCleanString(obj, "assigned_ipv6", "fd00:8:0::2")
            val expiresAt = if (obj.isNull("expires_at")) 0L else obj.optLong("expires_at", 0L)
            val quotaBytes = if (obj.isNull("quota_bytes")) 0L else obj.optLong("quota_bytes", 0L)

            val fallbackName = when {
                rawName.isNotBlank() -> rawName
                userId.isNotBlank() -> "Morph ($userId)"
                serverV4.isNotBlank() -> serverV4
                serverV6.isNotBlank() -> serverV6
                else -> "Morph Node"
            }

            val id = if (userId.isNotBlank()) {
                "${userId}_${serverV4}_${serverV6}_$port"
            } else {
                UUID.nameUUIDFromBytes(token.trim().toByteArray()).toString()
            }

            MorphProfile(
                id = id,
                token = token.trim(),
                userId = userId,
                name = fallbackName,
                serverV4 = serverV4,
                serverV6 = serverV6,
                port = port,
                profile = profile,
                profileDisplay = profileDisplay,
                payloadMode = payloadMode,
                assignedIpv4 = assignedIpv4,
                assignedIpv6 = assignedIpv6,
                expiresAtEpochSec = expiresAt,
                quotaBytes = quotaBytes
            )
        }.getOrNull()
    }

    fun formatQuota(quotaBytes: Long): String {
        if (quotaBytes <= 0L) return "Unlimited"
        val gb = quotaBytes / (1024.0 * 1024.0 * 1024.0)
        if (gb >= 1.0) return String.format(Locale.US, "%.1f GB", gb)
        val mb = quotaBytes / (1024.0 * 1024.0)
        return String.format(Locale.US, "%.0f MB", mb.coerceAtLeast(1.0))
    }

    fun formatTimeRemaining(expiresAtEpochSec: Long, nowEpochSec: Long = System.currentTimeMillis() / 1000L): String {
        if (expiresAtEpochSec <= 0L) return "Unlimited"
        val remaining = expiresAtEpochSec - nowEpochSec
        if (remaining <= 0L) return "Expired"
        val days = remaining / 86_400L
        val hours = (remaining % 86_400L) / 3_600L
        val mins = (remaining % 3_600L) / 60L
        return when {
            days > 0L -> "${days}d ${hours}h"
            hours > 0L -> "${hours}h ${mins}m"
            else -> "${mins.coerceAtLeast(1L)}m"
        }
    }

    fun formatSpeed(bytesPerSec: Long): Pair<String, String> {
        val kbps = bytesPerSec / 1024.0
        return if (kbps >= 1024.0) {
            String.format(Locale.US, "%.1f", kbps / 1024.0) to "MB/s"
        } else {
            String.format(Locale.US, "%.1f", kbps) to "KB/s"
        }
    }

    fun formatBytes(bytes: Long): Pair<String, String> {
        val mb = bytes / (1024.0 * 1024.0)
        return if (mb >= 1024.0) {
            String.format(Locale.US, "%.2f", mb / 1024.0) to "GB"
        } else {
            String.format(Locale.US, "%.1f", mb) to "MB"
        }
    }

    fun formatDuration(elapsedSeconds: Long): String {
        val hrs = elapsedSeconds / 3600L
        val mins = (elapsedSeconds % 3600L) / 60L
        val secs = elapsedSeconds % 60L
        return String.format(Locale.US, "%02d:%02d:%02d", hrs, mins, secs)
    }
}
