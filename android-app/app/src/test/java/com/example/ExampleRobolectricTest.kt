package com.example

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import com.morphcore.vpn.data.CamouflageProtocol
import com.morphcore.vpn.data.PayloadMode
import com.morphcore.vpn.data.TokenParser
import com.morphcore.vpn.data.TransportIpMode
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Test
import org.junit.runner.RunWith
import org.robolectric.RobolectricTestRunner
import org.robolectric.annotation.Config

@RunWith(RobolectricTestRunner::class)
@Config(sdk = [36])
class ExampleRobolectricTest {

    @Test
    fun `read string from context`() {
        val context = ApplicationProvider.getApplicationContext<Context>()
        val appName = context.getString(R.string.app_name)
        assertEquals("Morph Core", appName)
    }

    @Test
    fun `parse decoded token json populates profile and fallbacks`() {
        val sampleJson = """
            {
              "user_id": "u_42",
              "name": "Frankfurt Edge",
              "server_v4": "198.51.100.10",
              "server_v6": "2001:db8::1",
              "port": 443,
              "profile": "quic_v1",
              "profile_display": "QUIC_V1",
              "payload_mode": "shaped",
              "assigned_ipv4": "10.8.0.5",
              "assigned_ipv6": "fd00:8:0::5",
              "expires_at": 0,
              "quota_bytes": 53687091200
            }
        """.trimIndent()

        val profile = TokenParser.parseDecodedJson("morph://sample", sampleJson)
        assertNotNull(profile)
        requireNotNull(profile)
        assertEquals("Frankfurt Edge", profile.name)
        assertEquals("10.8.0.5", profile.assignedIpv4)
        assertEquals("fd00:8:0::5", profile.assignedIpv6)
        assertEquals("50.0 GB", TokenParser.formatQuota(profile.quotaBytes))
        assertEquals("[2001:db8::1]:443", profile.formattedEndpoint(TransportIpMode.AUTO, null))
        assertEquals("198.51.100.10:8443", profile.formattedEndpoint(TransportIpMode.IPV4, 8443))
    }

    @Test
    fun `empty or invalid token json returns null`() {
        assertNull(TokenParser.parseDecodedJson("morph://bad", ""))
        assertNull(TokenParser.parseDecodedJson("morph://bad", "{not_json"))
    }

    @Test
    fun `json null fields fall back safely without literal null string`() {
        val jsonWithNulls = """
            {
              "user_id": "u_9",
              "name": null,
              "server_v4": "203.0.113.5",
              "server_v6": null,
              "port": 443,
              "profile_id": "webrtc",
              "assigned_ipv4": null,
              "assigned_ipv6": null,
              "expires_at": null,
              "quota_bytes": null
            }
        """.trimIndent()
        val profile = TokenParser.parseDecodedJson("morph://nulltest", jsonWithNulls)
        assertNotNull(profile)
        requireNotNull(profile)
        assertEquals("", profile.serverV6)
        assertEquals("10.8.0.2", profile.assignedIpv4)
        assertEquals("fd00:8:0::2", profile.assignedIpv6)
        assertEquals("webrtc", profile.profile)
        assertEquals("203.0.113.5:443", profile.formattedEndpoint(TransportIpMode.AUTO, null))
    }

    @Test
    fun `protocol enum maps all 16 protocols plus auto`() {
        assertEquals(17, CamouflageProtocol.entries.size)
        assertNull(CamouflageProtocol.AUTO.key)
        assertEquals(CamouflageProtocol.DISCORD, CamouflageProtocol.fromKey("discord"))
        assertNull(PayloadMode.AUTO.key)
        assertEquals(PayloadMode.SHAPED, PayloadMode.fromKey("shaped"))
    }
}
