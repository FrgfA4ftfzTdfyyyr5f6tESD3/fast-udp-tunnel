package com.morphcore.vpn.ui.components

import androidx.compose.animation.animateColorAsState
import androidx.compose.animation.core.FastOutSlowInEasing
import androidx.compose.animation.core.LinearEasing
import androidx.compose.animation.core.RepeatMode
import androidx.compose.animation.core.animateFloat
import androidx.compose.animation.core.animateFloatAsState
import androidx.compose.animation.core.infiniteRepeatable
import androidx.compose.animation.core.rememberInfiniteTransition
import androidx.compose.animation.core.tween
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.Canvas
import androidx.compose.foundation.background
import androidx.compose.foundation.border
import androidx.compose.foundation.clickable
import androidx.compose.foundation.horizontalScroll
import androidx.compose.foundation.interaction.MutableInteractionSource
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.ColumnScope
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.CircleShape
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.PowerSettingsNew
import androidx.compose.material.ripple.rememberRipple
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.ripple
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.remember
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.draw.drawBehind
import androidx.compose.ui.draw.scale
import androidx.compose.ui.geometry.Offset
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.Path
import androidx.compose.ui.graphics.StrokeCap
import androidx.compose.ui.graphics.StrokeJoin
import androidx.compose.ui.graphics.drawscope.Stroke
import androidx.compose.ui.graphics.drawscope.rotate
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.semantics.Role
import androidx.compose.ui.semantics.contentDescription
import androidx.compose.ui.semantics.semantics
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import androidx.compose.ui.unit.sp
import com.example.R
import com.example.ui.theme.AmberCore
import com.example.ui.theme.BlueBright
import com.example.ui.theme.BlueCore
import com.example.ui.theme.CyberBgSurface
import com.example.ui.theme.CyberBorderBright
import com.example.ui.theme.CyberGlassBorder
import com.example.ui.theme.CyberGlassSurface
import com.example.ui.theme.DangerBright
import com.example.ui.theme.DangerCore
import com.example.ui.theme.EmeraldBright
import com.example.ui.theme.EmeraldCore
import com.example.ui.theme.JetBrainsMonoFontFamily
import com.example.ui.theme.PurpleBright
import com.example.ui.theme.PurpleCore
import com.example.ui.theme.TextMuted
import com.example.ui.theme.TextPrimary
import com.example.ui.theme.TextSecondary
import com.morphcore.vpn.data.TokenParser
import com.morphcore.vpn.data.VpnStatus

@Composable
fun MorphBrandHeader(
    vpnStatus: VpnStatus,
    modifier: Modifier = Modifier
) {
    Column(modifier = modifier.fillMaxWidth()) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Row(
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                GlowingOrbIndicator(vpnStatus = vpnStatus)
                Text(
                    text = stringResource(R.string.brand_title),
                    style = MaterialTheme.typography.headlineSmall.copy(
                        letterSpacing = 3.sp,
                        fontWeight = FontWeight.Bold
                    ),
                    color = TextPrimary
                )
                Surface(
                    shape = RoundedCornerShape(6.dp),
                    color = EmeraldCore.copy(alpha = 0.16f),
                    border = BorderStroke(1.dp, EmeraldCore.copy(alpha = 0.35f))
                ) {
                    Text(
                        text = stringResource(R.string.brand_version),
                        style = MaterialTheme.typography.labelSmall,
                        color = EmeraldBright,
                        modifier = Modifier.padding(horizontal = 7.dp, vertical = 3.dp)
                    )
                }
            }
        }

        Spacer(modifier = Modifier.height(10.dp))

        Row(
            modifier = Modifier
                .fillMaxWidth()
                .horizontalScroll(rememberScrollState()),
            horizontalArrangement = Arrangement.spacedBy(8.dp)
        ) {
            FeaturePill(
                label = stringResource(R.string.pill_gemini_ipv6),
                dotColor = EmeraldBright,
                containerColor = EmeraldCore.copy(alpha = 0.12f),
                borderColor = EmeraldCore.copy(alpha = 0.28f)
            )
            FeaturePill(
                label = stringResource(R.string.pill_hagezi_adblock),
                dotColor = BlueBright,
                containerColor = BlueCore.copy(alpha = 0.12f),
                borderColor = BlueCore.copy(alpha = 0.28f)
            )
            FeaturePill(
                label = stringResource(R.string.pill_zero_leak),
                dotColor = PurpleBright,
                containerColor = PurpleCore.copy(alpha = 0.12f),
                borderColor = PurpleCore.copy(alpha = 0.28f)
            )
        }
    }
}

@Composable
private fun GlowingOrbIndicator(vpnStatus: VpnStatus) {
    val color by animateColorAsState(
        targetValue = when (vpnStatus) {
            VpnStatus.CONNECTED -> EmeraldBright
            VpnStatus.CONNECTING -> AmberCore
            VpnStatus.ERROR -> DangerBright
            VpnStatus.DISCONNECTED -> EmeraldCore
        },
        label = "orbColor"
    )
    Box(
        modifier = Modifier
            .size(12.dp)
            .drawBehind {
                drawCircle(
                    color = color.copy(alpha = 0.45f),
                    radius = size.minDimension * 0.9f
                )
            }
            .clip(CircleShape)
            .background(color)
    )
}

@Composable
private fun FeaturePill(
    label: String,
    dotColor: Color,
    containerColor: Color,
    borderColor: Color
) {
    Surface(
        shape = CircleShape,
        color = containerColor,
        border = BorderStroke(1.dp, borderColor)
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 10.dp, vertical = 5.dp),
            verticalAlignment = Alignment.CenterVertically,
            horizontalArrangement = Arrangement.spacedBy(6.dp)
        ) {
            Box(
                modifier = Modifier
                    .size(6.dp)
                    .clip(CircleShape)
                    .background(dotColor)
            )
            Text(
                text = label,
                style = MaterialTheme.typography.labelMedium,
                color = dotColor,
                maxLines = 1,
                overflow = TextOverflow.Ellipsis
            )
        }
    }
}

@Composable
fun GlassCard(
    modifier: Modifier = Modifier,
    borderColor: Color = CyberGlassBorder,
    containerColor: Color = CyberGlassSurface,
    content: @Composable ColumnScope.() -> Unit
) {
    Surface(
        modifier = modifier,
        shape = MaterialTheme.shapes.large,
        color = containerColor,
        border = BorderStroke(1.dp, borderColor)
    ) {
        Column(
            modifier = Modifier.padding(16.dp),
            content = content
        )
    }
}

@Composable
fun PowerRingButton(
    vpnStatus: VpnStatus,
    elapsedSeconds: Long,
    rttMs: Long,
    onClick: () -> Unit,
    modifier: Modifier = Modifier
) {
    val infiniteTransition = rememberInfiniteTransition(label = "powerRingAnim")
    val pulseScale by infiniteTransition.animateFloat(
        initialValue = 1.0f,
        targetValue = 1.12f,
        animationSpec = infiniteRepeatable(
            animation = tween(1600, easing = FastOutSlowInEasing),
            repeatMode = RepeatMode.Reverse
        ),
        label = "pulseScale"
    )
    val rotationAngle by infiniteTransition.animateFloat(
        initialValue = 0f,
        targetValue = 360f,
        animationSpec = infiniteRepeatable(
            animation = tween(1300, easing = LinearEasing),
            repeatMode = RepeatMode.Restart
        ),
        label = "connectingSpin"
    )

    val ringColor by animateColorAsState(
        targetValue = when (vpnStatus) {
            VpnStatus.CONNECTED -> EmeraldCore
            VpnStatus.CONNECTING -> AmberCore
            VpnStatus.ERROR -> DangerCore
            VpnStatus.DISCONNECTED -> CyberBorderBright
        },
        animationSpec = tween(350),
        label = "ringColor"
    )

    val iconColor by animateColorAsState(
        targetValue = when (vpnStatus) {
            VpnStatus.CONNECTED -> EmeraldBright
            VpnStatus.CONNECTING -> AmberCore
            VpnStatus.ERROR -> DangerBright
            VpnStatus.DISCONNECTED -> TextSecondary
        },
        animationSpec = tween(350),
        label = "iconColor"
    )

    val buttonScale by animateFloatAsState(
        targetValue = if (vpnStatus == VpnStatus.CONNECTED) 1.02f else 1.0f,
        label = "buttonScale"
    )

    val statusLabel = when (vpnStatus) {
        VpnStatus.DISCONNECTED -> stringResource(R.string.status_disconnected)
        VpnStatus.CONNECTING -> stringResource(R.string.status_connecting)
        VpnStatus.CONNECTED -> stringResource(R.string.status_connected)
        VpnStatus.ERROR -> stringResource(R.string.status_error)
    }

    val cdText = stringResource(R.string.power_button_cd)

    Box(
        modifier = modifier
            .size(216.dp)
            .scale(buttonScale),
        contentAlignment = Alignment.Center
    ) {
        // Outer ambient pulse aura
        if (vpnStatus == VpnStatus.CONNECTED || vpnStatus == VpnStatus.CONNECTING) {
            val auraColor = if (vpnStatus == VpnStatus.CONNECTED) EmeraldCore else AmberCore
            Box(
                modifier = Modifier
                    .size(204.dp)
                    .scale(pulseScale)
                    .clip(CircleShape)
                    .background(
                        Brush.radialGradient(
                            colors = listOf(
                                auraColor.copy(alpha = 0.24f),
                                auraColor.copy(alpha = 0.0f)
                            )
                        )
                    )
            )
        }

        // Main tactile circular ring
        Box(
            modifier = Modifier
                .size(184.dp)
                .clip(CircleShape)
                .background(
                    Brush.verticalGradient(
                        colors = listOf(
                            Color(0xFF172033),
                            CyberBgSurface
                        )
                    )
                )
                .border(
                    width = 2.5.dp,
                    color = if (vpnStatus == VpnStatus.CONNECTING) Color.Transparent else ringColor,
                    shape = CircleShape
                )
                .drawBehind {
                    if (vpnStatus == VpnStatus.CONNECTING) {
                        val strokeWidth = 3.5.dp.toPx()
                        drawCircle(
                            color = AmberCore.copy(alpha = 0.2f),
                            style = Stroke(width = strokeWidth)
                        )
                        rotate(degrees = rotationAngle) {
                            drawArc(
                                brush = Brush.sweepGradient(
                                    colors = listOf(
                                        Color.Transparent,
                                        AmberCore,
                                        EmeraldBright
                                    )
                                ),
                                startAngle = 0f,
                                sweepAngle = 240f,
                                useCenter = false,
                                style = Stroke(width = strokeWidth, cap = StrokeCap.Round)
                            )
                        }
                    }
                }
                .semantics { contentDescription = cdText }
                .testTag("power_toggle_button")
                .clickable(
                    interactionSource = remember { MutableInteractionSource() },
                    indication = ripple(bounded = true, color = ringColor),
                    role = Role.Button,
                    onClick = onClick
                ),
            contentAlignment = Alignment.Center
        ) {
            Column(
                horizontalAlignment = Alignment.CenterHorizontally,
                verticalArrangement = Arrangement.Center,
                modifier = Modifier.padding(horizontal = 14.dp)
            ) {
                Icon(
                    imageVector = Icons.Rounded.PowerSettingsNew,
                    contentDescription = null,
                    tint = iconColor,
                    modifier = Modifier.size(38.dp)
                )
                Spacer(modifier = Modifier.height(8.dp))
                Text(
                    text = statusLabel,
                    style = MaterialTheme.typography.labelLarge.copy(
                        letterSpacing = 1.1.sp,
                        fontWeight = FontWeight.Bold
                    ),
                    color = iconColor,
                    maxLines = 1,
                    overflow = TextOverflow.Ellipsis
                )
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = TokenParser.formatDuration(elapsedSeconds),
                    style = MaterialTheme.typography.titleMedium.copy(
                        fontFamily = JetBrainsMonoFontFamily,
                        fontWeight = FontWeight.SemiBold
                    ),
                    color = if (vpnStatus == VpnStatus.CONNECTED) TextPrimary else TextMuted
                )
                if (vpnStatus == VpnStatus.CONNECTED) {
                    Spacer(modifier = Modifier.height(4.dp))
                    Text(
                        text = if (rttMs > 0L) {
                            stringResource(R.string.rtt_badge_format, rttMs)
                        } else {
                            stringResource(R.string.rtt_badge_placeholder)
                        },
                        style = MaterialTheme.typography.labelSmall,
                        color = EmeraldBright
                    )
                }
            }
        }
    }
}

@Composable
fun ThroughputWaveformChart(
    rxWaveform: List<Float>,
    txWaveform: List<Float>,
    modifier: Modifier = Modifier
) {
    GlassCard(modifier = modifier.fillMaxWidth()) {
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.SpaceBetween,
            verticalAlignment = Alignment.CenterVertically
        ) {
            Column {
                Text(
                    text = stringResource(R.string.telemetry_chart_title),
                    style = MaterialTheme.typography.labelMedium.copy(letterSpacing = 1.sp),
                    color = TextSecondary
                )
                Text(
                    text = stringResource(R.string.telemetry_chart_subtitle),
                    style = MaterialTheme.typography.bodySmall,
                    color = TextMuted
                )
            }
            Row(
                horizontalArrangement = Arrangement.spacedBy(10.dp),
                verticalAlignment = Alignment.CenterVertically
            ) {
                LegendChip(color = EmeraldBright, label = stringResource(R.string.rx_legend))
                LegendChip(color = BlueBright, label = stringResource(R.string.tx_legend))
            }
        }

        Spacer(modifier = Modifier.height(12.dp))

        Canvas(
            modifier = Modifier
                .fillMaxWidth()
                .height(84.dp)
                .clip(RoundedCornerShape(12.dp))
                .background(Color(0xFF0A0F18))
        ) {
            val w = size.width
            val h = size.height
            if (w <= 0f || h <= 0f) return@Canvas

            // Subtle horizontal reference grid lines
            val gridColor = Color.White.copy(alpha = 0.05f)
            for (step in 1..3) {
                val y = h * (step / 4f)
                drawLine(
                    color = gridColor,
                    start = Offset(0f, y),
                    end = Offset(w, y),
                    strokeWidth = 1.dp.toPx()
                )
            }

            val rxSamples = if (rxWaveform.size >= 2) rxWaveform else listOf(0f, 0f)
            val txSamples = if (txWaveform.size >= 2) txWaveform else listOf(0f, 0f)
            val peak = maxOf(
                rxSamples.maxOrNull() ?: 0f,
                txSamples.maxOrNull() ?: 0f,
                50f
            )

            // Draw TX (Upload) subtle curve first
            val txPath = Path()
            val txStep = w / (txSamples.size - 1).coerceAtLeast(1)
            txSamples.forEachIndexed { index, value ->
                val x = index * txStep
                val y = h - ((value / peak).coerceIn(0f, 1f) * (h - 10.dp.toPx())) - 3.dp.toPx()
                if (index == 0) txPath.moveTo(x, y) else txPath.lineTo(x, y)
            }
            drawPath(
                path = txPath,
                color = BlueBright.copy(alpha = 0.75f),
                style = Stroke(
                    width = 1.6.dp.toPx(),
                    cap = StrokeCap.Round,
                    join = StrokeJoin.Round
                )
            )

            // Draw RX (Download) filled area + bright emerald stroke
            val rxFillPath = Path()
            val rxStrokePath = Path()
            val rxStep = w / (rxSamples.size - 1).coerceAtLeast(1)
            rxFillPath.moveTo(0f, h)
            rxSamples.forEachIndexed { index, value ->
                val x = index * rxStep
                val y = h - ((value / peak).coerceIn(0f, 1f) * (h - 10.dp.toPx())) - 3.dp.toPx()
                rxFillPath.lineTo(x, y)
                if (index == 0) rxStrokePath.moveTo(x, y) else rxStrokePath.lineTo(x, y)
            }
            rxFillPath.lineTo(w, h)
            rxFillPath.close()

            drawPath(
                path = rxFillPath,
                brush = Brush.verticalGradient(
                    colors = listOf(
                        EmeraldCore.copy(alpha = 0.36f),
                        EmeraldCore.copy(alpha = 0.0f)
                    )
                )
            )
            drawPath(
                path = rxStrokePath,
                color = EmeraldBright,
                style = Stroke(
                    width = 2.2.dp.toPx(),
                    cap = StrokeCap.Round,
                    join = StrokeJoin.Round
                )
            )
        }
    }
}

@Composable
private fun LegendChip(color: Color, label: String) {
    Row(
        verticalAlignment = Alignment.CenterVertically,
        horizontalArrangement = Arrangement.spacedBy(5.dp)
    ) {
        Box(
            modifier = Modifier
                .size(8.dp)
                .clip(CircleShape)
                .background(color)
        )
        Text(
            text = label,
            style = MaterialTheme.typography.labelSmall,
            color = TextSecondary
        )
    }
}
