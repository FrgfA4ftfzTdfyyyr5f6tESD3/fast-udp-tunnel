package com.morphcore.vpn.ui.screens

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.ArrowDownward
import androidx.compose.material.icons.rounded.ArrowUpward
import androidx.compose.material.icons.rounded.Close
import androidx.compose.material.icons.rounded.DataUsage
import androidx.compose.material.icons.rounded.ErrorOutline
import androidx.compose.material.icons.rounded.NetworkPing
import androidx.compose.material.icons.rounded.Token
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.example.R
import com.example.ui.theme.BlueBright
import com.example.ui.theme.CyberBorderBright
import com.example.ui.theme.DangerBright
import com.example.ui.theme.DangerCore
import com.example.ui.theme.EmeraldBright
import com.example.ui.theme.EmeraldCore
import com.example.ui.theme.JetBrainsMonoFontFamily
import com.example.ui.theme.PurpleBright
import com.example.ui.theme.TextMuted
import com.example.ui.theme.TextPrimary
import com.example.ui.theme.TextSecondary
import com.morphcore.vpn.data.CamouflageProtocol
import com.morphcore.vpn.data.PayloadMode
import com.morphcore.vpn.data.TokenParser
import com.morphcore.vpn.data.VpnStatus
import com.morphcore.vpn.ui.MorphUiState
import com.morphcore.vpn.ui.components.GlassCard
import com.morphcore.vpn.ui.components.PowerRingButton
import com.morphcore.vpn.ui.components.ThroughputWaveformChart
import java.util.Locale

@Composable
fun TunnelDashboardScreen(
    uiState: MorphUiState,
    onPowerClick: () -> Unit,
    onNavigateToTokens: () -> Unit,
    onDismissError: () -> Unit,
    modifier: Modifier = Modifier
) {
    val scrollState = rememberScrollState()
    val telemetry = uiState.telemetry
    val isConnected = uiState.vpnStatus == VpnStatus.CONNECTED
    val (dlVal, dlUnit) = TokenParser.formatSpeed(if (isConnected) telemetry.rxRateBps else 0L)
    val (ulVal, ulUnit) = TokenParser.formatSpeed(if (isConnected) telemetry.txRateBps else 0L)
    val (totalVal, totalUnit) = TokenParser.formatBytes(
        if (isConnected) telemetry.rxBytes + telemetry.txBytes else 0L
    )

    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(scrollState)
            .padding(bottom = 16.dp),
        horizontalAlignment = Alignment.CenterHorizontally,
        verticalArrangement = Arrangement.spacedBy(14.dp)
    ) {
        AnimatedVisibility(visible = !uiState.vpnErrorMessage.isNullOrBlank()) {
            Surface(
                modifier = Modifier.fillMaxWidth(),
                shape = MaterialTheme.shapes.medium,
                color = DangerCore.copy(alpha = 0.16f),
                border = BorderStroke(1.dp, DangerCore.copy(alpha = 0.45f))
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 12.dp, vertical = 10.dp),
                    verticalAlignment = Alignment.CenterVertically
                ) {
                    Icon(
                        imageVector = Icons.Rounded.ErrorOutline,
                        contentDescription = null,
                        tint = DangerBright,
                        modifier = Modifier.size(20.dp)
                    )
                    Spacer(modifier = Modifier.width(10.dp))
                    Text(
                        text = uiState.vpnErrorMessage.orEmpty(),
                        style = MaterialTheme.typography.bodySmall,
                        color = DangerBright,
                        modifier = Modifier.weight(1f)
                    )
                    if (uiState.activeProfile == null) {
                        TextButton(
                            onClick = onNavigateToTokens,
                            modifier = Modifier.testTag("error_action_button")
                        ) {
                            Text(
                                text = stringResource(R.string.tab_tokens),
                                color = EmeraldBright
                            )
                        }
                    }
                    IconButton(
                        onClick = onDismissError,
                        modifier = Modifier.size(48.dp)
                    ) {
                        Icon(
                            imageVector = Icons.Rounded.Close,
                            contentDescription = stringResource(R.string.btn_reset),
                            tint = DangerBright,
                            modifier = Modifier.size(18.dp)
                        )
                    }
                }
            }
        }

        // Big Circular Power Button
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .padding(vertical = 4.dp),
            contentAlignment = Alignment.Center
        ) {
            PowerRingButton(
                vpnStatus = uiState.vpnStatus,
                elapsedSeconds = telemetry.elapsedSeconds,
                rttMs = telemetry.rttMs,
                onClick = onPowerClick
            )
        }

        // Active Profile Quick Card
        ActiveProfileSummaryCard(
            uiState = uiState,
            onClickSelectToken = onNavigateToTokens
        )

        // 2x2 Telemetry Grid (matches Windows Desktop UI)
        Column(
            modifier = Modifier.fillMaxWidth(),
            verticalArrangement = Arrangement.spacedBy(10.dp)
        ) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                TelemetryMetricCard(
                    title = stringResource(R.string.metric_ping_rtt),
                    value = if (isConnected && telemetry.rttMs > 0L) telemetry.rttMs.toString() else "--",
                    unit = "ms",
                    icon = Icons.Rounded.NetworkPing,
                    accent = PurpleBright,
                    modifier = Modifier.weight(1f)
                )
                TelemetryMetricCard(
                    title = stringResource(R.string.metric_download),
                    value = dlVal,
                    unit = dlUnit,
                    icon = Icons.Rounded.ArrowDownward,
                    accent = EmeraldBright,
                    modifier = Modifier.weight(1f)
                )
            }
            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                TelemetryMetricCard(
                    title = stringResource(R.string.metric_upload),
                    value = ulVal,
                    unit = ulUnit,
                    icon = Icons.Rounded.ArrowUpward,
                    accent = BlueBright,
                    modifier = Modifier.weight(1f)
                )
                TelemetryMetricCard(
                    title = stringResource(R.string.metric_data_usage),
                    value = totalVal,
                    unit = totalUnit,
                    icon = Icons.Rounded.DataUsage,
                    accent = TextSecondary,
                    modifier = Modifier.weight(1f)
                )
            }
        }

        // Live Real-Time Speed Waveform Canvas
        ThroughputWaveformChart(
            rxWaveform = telemetry.rxWaveform,
            txWaveform = telemetry.txWaveform
        )
    }
}

@Composable
private fun ActiveProfileSummaryCard(
    uiState: MorphUiState,
    onClickSelectToken: () -> Unit
) {
    val active = uiState.activeProfile
    val settings = uiState.savedSettings

    val effectiveMimic = if (settings.camouflageProtocol != CamouflageProtocol.AUTO) {
        settings.camouflageProtocol.key?.uppercase(Locale.US) ?: "AUTO"
    } else {
        active?.profileDisplay?.uppercase(Locale.US) ?: "AUTO"
    }

    val effectiveMode = if (settings.payloadMode != PayloadMode.AUTO) {
        settings.payloadMode.key?.uppercase(Locale.US) ?: "AUTO"
    } else {
        active?.payloadMode?.uppercase(Locale.US) ?: "AUTO"
    }

    Surface(
        onClick = onClickSelectToken,
        modifier = Modifier
            .fillMaxWidth()
            .testTag("active_profile_card"),
        shape = MaterialTheme.shapes.large,
        color = Color(0xCC121826),
        border = BorderStroke(
            1.dp,
            if (active != null) EmeraldCore.copy(alpha = 0.25f) else CyberBorderBright
        )
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.SpaceBetween
        ) {
            Column(modifier = Modifier.weight(1f)) {
                Text(
                    text = stringResource(R.string.active_profile_label),
                    style = MaterialTheme.typography.labelSmall,
                    color = TextMuted
                )
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = active?.name ?: stringResource(R.string.no_profile_selected),
                    style = MaterialTheme.typography.titleMedium,
                    color = TextPrimary,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                Spacer(modifier = Modifier.height(2.dp))
                Text(
                    text = active?.formattedEndpoint(
                        transportIp = settings.transportIp,
                        portOverride = settings.portOverride
                    ) ?: stringResource(R.string.select_token_hint),
                    style = MaterialTheme.typography.bodySmall.copy(
                        fontFamily = if (active != null) JetBrainsMonoFontFamily else MaterialTheme.typography.bodySmall.fontFamily
                    ),
                    color = TextSecondary,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
            }

            Spacer(modifier = Modifier.width(10.dp))

            if (active != null) {
                Column(
                    horizontalAlignment = Alignment.End,
                    verticalArrangement = Arrangement.spacedBy(6.dp)
                ) {
                    ProfileBadge(
                        text = effectiveMimic,
                        color = EmeraldBright,
                        container = EmeraldCore.copy(alpha = 0.14f)
                    )
                    ProfileBadge(
                        text = effectiveMode,
                        color = BlueBright,
                        container = BlueCore.copy(alpha = 0.14f)
                    )
                }
            } else {
                Icon(
                    imageVector = Icons.Rounded.Token,
                    contentDescription = stringResource(R.string.tab_tokens),
                    tint = EmeraldBright,
                    modifier = Modifier.size(24.dp)
                )
            }
        }
    }
}

private val BlueCore = Color(0xFF3B82F6)

@Composable
private fun ProfileBadge(
    text: String,
    color: Color,
    container: Color
) {
    Surface(
        shape = RoundedCornerShape(8.dp),
        color = container,
        border = BorderStroke(1.dp, color.copy(alpha = 0.35f))
    ) {
        Text(
            text = text,
            style = MaterialTheme.typography.labelSmall,
            color = color,
            maxLines = 1,
            overflow = TextOverflow.Ellipsis,
            modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp)
        )
    }
}

@Composable
private fun TelemetryMetricCard(
    title: String,
    value: String,
    unit: String,
    icon: ImageVector,
    accent: Color,
    modifier: Modifier = Modifier
) {
    GlassCard(modifier = modifier) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Text(
                text = title,
                style = MaterialTheme.typography.labelMedium,
                color = TextMuted,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
            Icon(
                imageVector = icon,
                contentDescription = null,
                tint = accent,
                modifier = Modifier.size(16.dp)
            )
        }
        Spacer(modifier = Modifier.height(8.dp))
        Row(
            verticalAlignment = Alignment.Bottom,
            horizontalArrangement = Arrangement.spacedBy(4.dp)
        ) {
            Text(
                text = value,
                style = MaterialTheme.typography.headlineSmall.copy(
                    fontFamily = JetBrainsMonoFontFamily,
                    fontWeight = FontWeight.Bold
                ),
                color = TextPrimary,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
            Text(
                text = unit,
                style = MaterialTheme.typography.labelMedium,
                color = TextSecondary,
                modifier = Modifier.padding(bottom = 3.dp)
            )
        }
    }
}
