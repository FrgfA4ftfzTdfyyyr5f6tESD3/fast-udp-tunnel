package com.morphcore.vpn.ui.screens

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.size
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.foundation.text.KeyboardOptions
import androidx.compose.foundation.verticalScroll
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.Check
import androidx.compose.material.icons.rounded.KeyboardArrowDown
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.ExperimentalMaterial3Api
import androidx.compose.material3.Icon
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.ModalBottomSheet
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.RadioButton
import androidx.compose.material3.RadioButtonDefaults
import androidx.compose.material3.SegmentedButton
import androidx.compose.material3.SegmentedButtonDefaults
import androidx.compose.material3.SingleChoiceSegmentedButtonRow
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.rememberModalBottomSheetState
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.example.R
import com.example.ui.theme.CyberBgPrimary
import com.example.ui.theme.CyberBgSurface
import com.example.ui.theme.CyberBgSurfaceElevated
import com.example.ui.theme.CyberBorderBright
import com.example.ui.theme.CyberGlassBorder
import com.example.ui.theme.DangerBright
import com.example.ui.theme.EmeraldBright
import com.example.ui.theme.EmeraldCore
import com.example.ui.theme.JetBrainsMonoFontFamily
import com.example.ui.theme.TextMuted
import com.example.ui.theme.TextPrimary
import com.example.ui.theme.TextSecondary
import com.morphcore.vpn.data.CamouflageProtocol
import com.morphcore.vpn.data.PayloadMode
import com.morphcore.vpn.data.TransportIpMode
import com.morphcore.vpn.ui.MorphUiState
import com.morphcore.vpn.ui.components.GlassCard

@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun OptionsScreen(
    uiState: MorphUiState,
    onTransportIpChange: (TransportIpMode) -> Unit,
    onCamouflageProtocolChange: (CamouflageProtocol) -> Unit,
    onPortTextChange: (String) -> Unit,
    onResetPort: () -> Unit,
    onPayloadModeChange: (PayloadMode) -> Unit,
    onSaveOptions: () -> Unit,
    modifier: Modifier = Modifier
) {
    val draft = uiState.draftSettings
    var showCamouflageSheet by remember { mutableStateOf(false) }

    if (showCamouflageSheet) {
        val sheetState = rememberModalBottomSheetState(skipPartiallyExpanded = true)
        ModalBottomSheet(
            onDismissRequest = { showCamouflageSheet = false },
            sheetState = sheetState,
            containerColor = CyberBgSurface,
            contentColor = TextPrimary
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 16.dp)
                    .padding(bottom = 24.dp)
            ) {
                Text(
                    text = stringResource(R.string.options_camouflage_title),
                    style = MaterialTheme.typography.titleLarge,
                    color = TextPrimary
                )
                Spacer(modifier = Modifier.height(4.dp))
                Text(
                    text = stringResource(R.string.options_camouflage_subtitle),
                    style = MaterialTheme.typography.bodySmall,
                    color = TextSecondary
                )
                Spacer(modifier = Modifier.height(12.dp))

                LazyColumn(
                    modifier = Modifier.fillMaxWidth(),
                    verticalArrangement = Arrangement.spacedBy(8.dp)
                ) {
                    items(CamouflageProtocol.entries) { protocol ->
                        val selected = protocol == draft.camouflageProtocol
                        Surface(
                            onClick = {
                                onCamouflageProtocolChange(protocol)
                                showCamouflageSheet = false
                            },
                            modifier = Modifier
                                .fillMaxWidth()
                                .testTag("camouflage_option_${protocol.key ?: "auto"}"),
                            shape = MaterialTheme.shapes.medium,
                            color = if (selected) EmeraldCore.copy(alpha = 0.14f) else CyberBgSurfaceElevated,
                            border = BorderStroke(
                                1.dp,
                                if (selected) EmeraldCore.copy(alpha = 0.6f) else CyberGlassBorder
                            )
                        ) {
                            Row(
                                modifier = Modifier
                                    .fillMaxWidth()
                                    .padding(horizontal = 14.dp, vertical = 14.dp),
                                verticalAlignment = Alignment.CenterVertically,
                                horizontalArrangement = Arrangement.SpaceBetween
                            ) {
                                Column(modifier = Modifier.weight(1f)) {
                                    Text(
                                        text = protocol.displayName,
                                        style = MaterialTheme.typography.titleSmall,
                                        color = TextPrimary
                                    )
                                    val portLabel = protocol.defaultPort?.let { "Port $it" }
                                        ?: stringResource(R.string.protocol_auto)
                                    Text(
                                        text = portLabel,
                                        style = MaterialTheme.typography.bodySmall.copy(
                                            fontFamily = JetBrainsMonoFontFamily
                                        ),
                                        color = if (selected) EmeraldBright else TextMuted
                                    )
                                }
                                if (selected) {
                                    Icon(
                                        imageVector = Icons.Rounded.Check,
                                        contentDescription = null,
                                        tint = EmeraldBright
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    Column(
        modifier = modifier
            .fillMaxSize()
            .verticalScroll(rememberScrollState())
            .padding(bottom = 24.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        // 1. Transport IP Protocol
        GlassCard(modifier = Modifier.fillMaxWidth()) {
            Text(
                text = stringResource(R.string.options_transport_title),
                style = MaterialTheme.typography.titleMedium,
                color = TextPrimary
            )
            Spacer(modifier = Modifier.height(8.dp))

            TransportOptionRow(
                selected = draft.transportIp == TransportIpMode.AUTO,
                title = stringResource(R.string.transport_auto),
                subtitle = stringResource(R.string.transport_auto_desc),
                tag = "transport_radio_auto",
                onClick = { onTransportIpChange(TransportIpMode.AUTO) }
            )
            TransportOptionRow(
                selected = draft.transportIp == TransportIpMode.IPV6,
                title = stringResource(R.string.transport_ipv6),
                subtitle = stringResource(R.string.transport_ipv6_desc),
                tag = "transport_radio_ipv6",
                onClick = { onTransportIpChange(TransportIpMode.IPV6) }
            )
            TransportOptionRow(
                selected = draft.transportIp == TransportIpMode.IPV4,
                title = stringResource(R.string.transport_ipv4),
                subtitle = stringResource(R.string.transport_ipv4_desc),
                tag = "transport_radio_ipv4",
                onClick = { onTransportIpChange(TransportIpMode.IPV4) }
            )
        }

        // 2. Camouflage Protocol Override
        GlassCard(modifier = Modifier.fillMaxWidth()) {
            Text(
                text = stringResource(R.string.options_camouflage_title),
                style = MaterialTheme.typography.titleMedium,
                color = TextPrimary
            )
            Spacer(modifier = Modifier.height(4.dp))
            Text(
                text = stringResource(R.string.options_camouflage_subtitle),
                style = MaterialTheme.typography.bodySmall,
                color = TextSecondary
            )
            Spacer(modifier = Modifier.height(10.dp))

            Surface(
                onClick = { showCamouflageSheet = true },
                modifier = Modifier
                    .fillMaxWidth()
                    .testTag("camouflage_selector_button"),
                shape = MaterialTheme.shapes.medium,
                color = CyberBgPrimary.copy(alpha = 0.7f),
                border = BorderStroke(1.dp, CyberBorderBright)
            ) {
                Row(
                    modifier = Modifier
                        .fillMaxWidth()
                        .padding(horizontal = 14.dp, vertical = 14.dp),
                    verticalAlignment = Alignment.CenterVertically,
                    horizontalArrangement = Arrangement.SpaceBetween
                ) {
                    Column(modifier = Modifier.weight(1f)) {
                        Text(
                            text = draft.camouflageProtocol.displayName,
                            style = MaterialTheme.typography.titleSmall,
                            color = TextPrimary,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                        val portDesc = draft.camouflageProtocol.defaultPort?.let { "Default UDP Port $it" }
                            ?: stringResource(R.string.protocol_auto)
                        Text(
                            text = portDesc,
                            style = MaterialTheme.typography.bodySmall.copy(
                                fontFamily = JetBrainsMonoFontFamily
                            ),
                            color = EmeraldBright
                        )
                    }
                    Icon(
                        imageVector = Icons.Rounded.KeyboardArrowDown,
                        contentDescription = stringResource(R.string.options_camouflage_title),
                        tint = TextSecondary
                    )
                }
            }
        }

        // 3. Server Port Override
        GlassCard(modifier = Modifier.fillMaxWidth()) {
            Text(
                text = stringResource(R.string.options_port_title),
                style = MaterialTheme.typography.titleMedium,
                color = TextPrimary
            )
            Spacer(modifier = Modifier.height(10.dp))

            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.spacedBy(10.dp)
            ) {
                OutlinedTextField(
                    value = uiState.draftPortText,
                    onValueChange = onPortTextChange,
                    modifier = Modifier
                        .weight(1f)
                        .testTag("port_override_input"),
                    placeholder = {
                        Text(
                            text = stringResource(R.string.options_port_placeholder),
                            style = MaterialTheme.typography.bodyMedium,
                            color = TextMuted
                        )
                    },
                    singleLine = true,
                    keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
                    textStyle = MaterialTheme.typography.bodyMedium.copy(
                        fontFamily = JetBrainsMonoFontFamily,
                        color = TextPrimary
                    ),
                    shape = MaterialTheme.shapes.medium,
                    colors = OutlinedTextFieldDefaults.colors(
                        focusedBorderColor = EmeraldCore,
                        unfocusedBorderColor = CyberBorderBright,
                        focusedContainerColor = CyberBgPrimary.copy(alpha = 0.7f),
                        unfocusedContainerColor = CyberBgPrimary.copy(alpha = 0.7f),
                        cursorColor = EmeraldBright
                    )
                )

                OutlinedButton(
                    onClick = onResetPort,
                    modifier = Modifier
                        .height(52.dp)
                        .testTag("reset_port_button"),
                    shape = MaterialTheme.shapes.medium,
                    border = BorderStroke(1.dp, CyberBorderBright),
                    colors = ButtonDefaults.outlinedButtonColors(contentColor = TextSecondary)
                ) {
                    Text(text = stringResource(R.string.btn_reset))
                }
            }
        }

        // 4. Payload Mode Segmented Selector
        GlassCard(modifier = Modifier.fillMaxWidth()) {
            Text(
                text = stringResource(R.string.options_payload_title),
                style = MaterialTheme.typography.titleMedium,
                color = TextPrimary
            )
            Spacer(modifier = Modifier.height(10.dp))

            val modes = PayloadMode.entries
            SingleChoiceSegmentedButtonRow(modifier = Modifier.fillMaxWidth()) {
                modes.forEachIndexed { index, mode ->
                    val label = when (mode) {
                        PayloadMode.AUTO -> stringResource(R.string.payload_auto)
                        PayloadMode.SHAPED -> stringResource(R.string.payload_shaped)
                        PayloadMode.STREAM -> stringResource(R.string.payload_stream)
                        PayloadMode.PLAINTEXT -> stringResource(R.string.payload_plaintext)
                    }
                    val selected = draft.payloadMode == mode
                    SegmentedButton(
                        selected = selected,
                        onClick = { onPayloadModeChange(mode) },
                        shape = SegmentedButtonDefaults.itemShape(
                            index = index,
                            count = modes.size,
                            baseShape = RoundedCornerShape(12.dp)
                        ),
                        modifier = Modifier
                            .height(48.dp)
                            .testTag("payload_segment_${mode.key ?: "auto"}"),
                        colors = SegmentedButtonDefaults.colors(
                            activeContainerColor = EmeraldCore.copy(alpha = 0.22f),
                            activeContentColor = EmeraldBright,
                            activeBorderColor = EmeraldCore,
                            inactiveContainerColor = CyberBgPrimary.copy(alpha = 0.7f),
                            inactiveContentColor = TextSecondary,
                            inactiveBorderColor = CyberGlassBorder
                        )
                    ) {
                        Text(
                            text = label,
                            style = MaterialTheme.typography.labelMedium,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                    }
                }
            }
        }

        // Save Button & Status Message
        Button(
            onClick = onSaveOptions,
            modifier = Modifier
                .fillMaxWidth()
                .height(52.dp)
                .testTag("save_options_button"),
            shape = MaterialTheme.shapes.medium,
            colors = ButtonDefaults.buttonColors(
                containerColor = EmeraldCore,
                contentColor = CyberBgPrimary
            )
        ) {
            Text(
                text = stringResource(R.string.btn_save_options),
                style = MaterialTheme.typography.titleMedium,
                fontWeight = FontWeight.Bold
            )
        }

        AnimatedVisibility(visible = uiState.settingsMessage != null) {
            val msg = uiState.settingsMessage
            if (msg != null) {
                Text(
                    text = msg.text,
                    style = MaterialTheme.typography.bodySmall,
                    color = if (msg.isError) DangerBright else EmeraldBright,
                    modifier = Modifier.padding(horizontal = 4.dp)
                )
            }
        }
    }
}

@Composable
private fun TransportOptionRow(
    selected: Boolean,
    title: String,
    subtitle: String,
    tag: String,
    onClick: () -> Unit
) {
    Row(
        modifier = Modifier
            .fillMaxWidth()
            .clickable(onClick = onClick)
            .padding(vertical = 6.dp)
            .testTag(tag),
        verticalAlignment = Alignment.CenterVertically
    ) {
        RadioButton(
            selected = selected,
            onClick = onClick,
            colors = RadioButtonDefaults.colors(
                selectedColor = EmeraldBright,
                unselectedColor = TextMuted
            )
        )
        Spacer(modifier = Modifier.width(6.dp))
        Column(modifier = Modifier.weight(1f)) {
            Text(
                text = title,
                style = MaterialTheme.typography.titleSmall,
                color = if (selected) TextPrimary else TextSecondary
            )
            Text(
                text = subtitle,
                style = MaterialTheme.typography.bodySmall,
                color = TextMuted
            )
        }
    }
}
