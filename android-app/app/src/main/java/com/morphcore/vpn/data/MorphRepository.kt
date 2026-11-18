package com.morphcore.vpn.data

import android.content.Context
import androidx.datastore.core.DataStore
import androidx.datastore.preferences.core.Preferences
import androidx.datastore.preferences.core.edit
import androidx.datastore.preferences.core.intPreferencesKey
import androidx.datastore.preferences.core.stringPreferencesKey
import androidx.datastore.preferences.preferencesDataStore
import kotlinx.coroutines.flow.Flow
import kotlinx.coroutines.flow.map
import org.json.JSONArray
import org.json.JSONObject

private val Context.morphDataStore: DataStore<Preferences> by preferencesDataStore(name = "morph_core_prefs")

class MorphRepository(private val context: Context) {

    private object Keys {
        val PROFILES_JSON = stringPreferencesKey("saved_profiles_json")
        val ACTIVE_PROFILE_ID = stringPreferencesKey("active_profile_id")
        val TRANSPORT_IP = stringPreferencesKey("transport_ip")
        val CAMOUFLAGE_PROTOCOL = stringPreferencesKey("camouflage_protocol")
        val PORT_OVERRIDE = intPreferencesKey("port_override")
        val PAYLOAD_MODE = stringPreferencesKey("payload_mode")
    }

    val profilesFlow: Flow<List<MorphProfile>> = context.morphDataStore.data.map { prefs ->
        decodeProfilesList(prefs[Keys.PROFILES_JSON])
    }

    val activeProfileIdFlow: Flow<String?> = context.morphDataStore.data.map { prefs ->
        prefs[Keys.ACTIVE_PROFILE_ID]
    }

    val settingsFlow: Flow<TunnelSettings> = context.morphDataStore.data.map { prefs ->
        val transportIp = TransportIpMode.fromKey(prefs[Keys.TRANSPORT_IP])
        val mimic = CamouflageProtocol.fromKey(prefs[Keys.CAMOUFLAGE_PROTOCOL])
        val port = prefs[Keys.PORT_OVERRIDE]?.takeIf { it in 1..65535 }
        val payload = PayloadMode.fromKey(prefs[Keys.PAYLOAD_MODE])
        TunnelSettings(
            transportIp = transportIp,
            camouflageProtocol = mimic,
            portOverride = port,
            payloadMode = payload
        )
    }

    suspend fun saveOrUpdateProfile(profile: MorphProfile, setAsActive: Boolean = true): Boolean {
        var wasUpdated = false
        context.morphDataStore.edit { prefs ->
            val current = decodeProfilesList(prefs[Keys.PROFILES_JSON]).toMutableList()
            val existingIdx = current.indexOfFirst { it.id == profile.id || it.token == profile.token }
            if (existingIdx >= 0) {
                current[existingIdx] = profile
                wasUpdated = true
            } else {
                current.add(0, profile)
            }
            prefs[Keys.PROFILES_JSON] = encodeProfilesList(current)
            if (setAsActive || prefs[Keys.ACTIVE_PROFILE_ID].isNullOrBlank()) {
                prefs[Keys.ACTIVE_PROFILE_ID] = profile.id
            }
        }
        return wasUpdated
    }

    suspend fun setActiveProfile(profileId: String) {
        context.morphDataStore.edit { prefs ->
            prefs[Keys.ACTIVE_PROFILE_ID] = profileId
        }
    }

    suspend fun deleteProfile(profileId: String) {
        context.morphDataStore.edit { prefs ->
            val updated = decodeProfilesList(prefs[Keys.PROFILES_JSON]).filterNot { it.id == profileId }
            prefs[Keys.PROFILES_JSON] = encodeProfilesList(updated)
            if (prefs[Keys.ACTIVE_PROFILE_ID] == profileId) {
                val nextId = updated.firstOrNull()?.id
                if (nextId != null) {
                    prefs[Keys.ACTIVE_PROFILE_ID] = nextId
                } else {
                    prefs.remove(Keys.ACTIVE_PROFILE_ID)
                }
            }
        }
    }

    suspend fun saveSettings(settings: TunnelSettings) {
        context.morphDataStore.edit { prefs ->
            prefs[Keys.TRANSPORT_IP] = settings.transportIp.key
            prefs[Keys.CAMOUFLAGE_PROTOCOL] = settings.camouflageProtocol.key ?: "auto"
            val port = settings.portOverride
            if (port != null && port in 1..65535) {
                prefs[Keys.PORT_OVERRIDE] = port
            } else {
                prefs.remove(Keys.PORT_OVERRIDE)
            }
            prefs[Keys.PAYLOAD_MODE] = settings.payloadMode.key ?: "auto"
        }
    }

    private fun encodeProfilesList(profiles: List<MorphProfile>): String {
        val arr = JSONArray()
        profiles.forEach { p ->
            val obj = JSONObject().apply {
                put("id", p.id)
                put("token", p.token)
                put("user_id", p.userId)
                put("name", p.name)
                put("server_v4", p.serverV4)
                put("server_v6", p.serverV6)
                put("port", p.port)
                put("profile", p.profile)
                put("profile_display", p.profileDisplay)
                put("payload_mode", p.payloadMode)
                put("assigned_ipv4", p.assignedIpv4)
                put("assigned_ipv6", p.assignedIpv6)
                put("expires_at", p.expiresAtEpochSec)
                put("quota_bytes", p.quotaBytes)
            }
            arr.put(obj)
        }
        return arr.toString()
    }

    private fun decodeProfilesList(raw: String?): List<MorphProfile> {
        if (raw.isNullOrBlank()) return emptyList()
        return runCatching {
            val arr = JSONArray(raw)
            buildList {
                for (i in 0 until arr.length()) {
                    val obj = arr.optJSONObject(i) ?: continue
                    add(
                        MorphProfile(
                            id = obj.optString("id"),
                            token = obj.optString("token"),
                            userId = obj.optString("user_id"),
                            name = obj.optString("name"),
                            serverV4 = obj.optString("server_v4"),
                            serverV6 = obj.optString("server_v6"),
                            port = obj.optInt("port", 443),
                            profile = obj.optString("profile", "auto"),
                            profileDisplay = obj.optString("profile_display", "AUTO"),
                            payloadMode = obj.optString("payload_mode", "shaped"),
                            assignedIpv4 = obj.optString("assigned_ipv4", "10.8.0.2"),
                            assignedIpv6 = obj.optString("assigned_ipv6", "fd00:8:0::2"),
                            expiresAtEpochSec = obj.optLong("expires_at", 0L),
                            quotaBytes = obj.optLong("quota_bytes", 0L)
                        )
                    )
                }
            }
        }.getOrDefault(emptyList())
    }
}
