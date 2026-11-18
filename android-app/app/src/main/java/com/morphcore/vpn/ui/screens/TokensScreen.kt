package com.morphcore.vpn.ui.screens

import androidx.compose.animation.AnimatedVisibility
import androidx.compose.foundation.BorderStroke
import androidx.compose.foundation.layout.Arrangement
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.PaddingValues
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
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.rounded.CheckCircle
import androidx.compose.material.icons.rounded.ContentPaste
import androidx.compose.material.icons.rounded.DeleteOutline
import androidx.compose.material.icons.rounded.Key
import androidx.compose.material3.AlertDialog
import androidx.compose.material3.Button
import androidx.compose.material3.ButtonDefaults
import androidx.compose.material3.Icon
import androidx.compose.material3.IconButton
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.OutlinedButton
import androidx.compose.material3.OutlinedTextField
import androidx.compose.material3.OutlinedTextFieldDefaults
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.material3.TextButton
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.runtime.mutableStateOf
import androidx.compose.runtime.remember
import androidx.compose.runtime.setValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.platform.LocalClipboardManager
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextAlign
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import com.example.R
import com.example.ui.theme.CyberBgPrimary
import com.example.ui.theme.CyberBgSurfaceElevated
import com.example.ui.theme.CyberBorderBright
import com.example.ui.theme.CyberGlassBorder
import com.example.ui.theme.DangerBright
import com.example.ui.theme.DangerCore
import com.example.ui.theme.EmeraldBright
import com.example.ui.theme.EmeraldCore
import com.example.ui.theme.JetBrainsMonoFontFamily
import com.example.ui.theme.TextMuted
import com.example.ui.theme.TextPrimary
import com.example.ui.theme.TextSecondary
import com.morphcore.vpn.data.MorphProfile
import com.morphcore.vpn.data.TokenParser
import com.morphcore.vpn.ui.MorphUiState
import com.morphcore.vpn.ui.components.GlassCard

@Composable
fun TokensScreen(
    uiState: MorphUiState,
    onTokenInputChange: (String) -> Unit,
    onClipboardEmpty: () -> Unit,
    onImportToken: (String) -> Unit,
    onSelectProfile: (String) -> Unit,
    onDeleteProfile: (String) -> Unit,
    modifier: Modifier = Modifier
) {
    @Suppress("DEPRECATION")
    val clipboardManager = LocalClipboardManager.current
    var pendingDeleteProfile by remember { mutableStateOf<MorphProfile?>(null) }

    pendingDeleteProfile?.let { profileToDelete ->
        AlertDialog(
            onDismissRequest = { pendingDeleteProfile = null },
            containerColor = CyberBgSurfaceElevated,
            titleContentColor = TextPrimary,
            textContentColor = TextSecondary,
            title = {
                Text(text = stringResource(R.string.delete_profile_cd))
            },
            text = {
                Text(text = "Delete '${profileToDelete.name}' from saved tokens?")
            },
            confirmButton = {
                TextButton(
                    onClick = {
                        onDeleteProfile(profileToDelete.id)
                        pendingDeleteProfile = null
                    }
                ) {
                    Text(
                        text = stringResource(R.string.delete_profile_cd),
                        color = DangerBright
                    )
                }
            },
            dismissButton = {
                TextButton(onClick = { pendingDeleteProfile = null }) {
                    Text(text = stringResource(R.string.btn_reset), color = TextSecondary)
                }
            }
        )
    }

    LazyColumn(
        modifier = modifier.fillMaxSize(),
        contentPadding = PaddingValues(bottom = 20.dp),
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        item {
            GlassCard(modifier = Modifier.fillMaxWidth()) {
                Text(
                    text = stringResource(R.string.tokens_import_title),
                    style = MaterialTheme.typography.titleMedium,
                    color = TextPrimary
                )
                Spacer(modifier = Modifier.height(10.dp))

                OutlinedTextField(
                    value = uiState.tokenInput,
                    onValueChange = onTokenInputChange,
                    modifier = Modifier
                        .fillMaxWidth()
                        .testTag("token_input_field"),
                    placeholder = {
                        Text(
                            text = stringResource(R.string.token_input_placeholder),
                            style = MaterialTheme.typography.bodyMedium,
                            color = TextMuted
                        )
                    },
                    singleLine = true,
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

                Spacer(modifier = Modifier.height(10.dp))

                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(10.dp)
                ) {
                    OutlinedButton(
                        onClick = {
                            val clipText = clipboardManager.getText()?.text?.trim().orEmpty()
                            if (clipText.isEmpty()) {
                                onClipboardEmpty()
                            } else {
                                onTokenInputChange(clipText)
                            }
                        },
                        modifier = Modifier
                            .weight(1f)
                            .height(48.dp)
                            .testTag("paste_token_button"),
                        shape = MaterialTheme.shapes.medium,
                        border = BorderStroke(1.dp, CyberBorderBright),
                        colors = ButtonDefaults.outlinedButtonColors(contentColor = TextPrimary)
                    ) {
                        Icon(
                            imageVector = Icons.Rounded.ContentPaste,
                            contentDescription = null,
                            modifier = Modifier.size(18.dp)
                        )
                        Spacer(modifier = Modifier.width(6.dp))
                        Text(text = stringResource(R.string.btn_paste))
                    }

                    Button(
                        onClick = { onImportToken(uiState.tokenInput) },
                        modifier = Modifier
                            .weight(1f)
                            .height(48.dp)
                            .testTag("import_token_button"),
                        shape = MaterialTheme.shapes.medium,
                        colors = ButtonDefaults.buttonColors(
                            containerColor = EmeraldCore,
                            contentColor = CyberBgPrimary
                        )
                    ) {
                        Text(
                            text = stringResource(R.string.btn_import),
                            fontWeight = FontWeight.Bold
                        )
                    }
                }

                AnimatedVisibility(visible = uiState.importMessage != null) {
                    val msg = uiState.importMessage
                    if (msg != null) {
                        Text(
                            text = msg.text,
                            style = MaterialTheme.typography.bodySmall,
                            color = if (msg.isError) DangerBright else EmeraldBright,
                            modifier = Modifier.padding(top = 10.dp)
                        )
                    }
                }
            }
        }

        item {
            Row(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(horizontal = 4.dp, vertical = 2.dp),
                horizontalArrangement = Arrangement.SpaceBetween,
                verticalAlignment = Alignment.CenterVertically
            ) {
                Text(
                    text = stringResource(R.string.saved_profiles_title),
                    style = MaterialTheme.typography.labelLarge,
                    color = TextSecondary
                )
                Surface(
                    shape = RoundedCornerShape(8.dp),
                    color = CyberBgSurfaceElevated,
                    border = BorderStroke(1.dp, CyberGlassBorder)
                ) {
                    Text(
                        text = uiState.profiles.size.toString(),
                        style = MaterialTheme.typography.labelSmall,
                        color = EmeraldBright,
                        modifier = Modifier.padding(horizontal = 8.dp, vertical = 3.dp)
                    )
                }
            }
        }

        if (uiState.profiles.isEmpty()) {
            item {
                GlassCard(modifier = Modifier.fillMaxWidth()) {
                    Column(
                        modifier = Modifier
                            .fillMaxWidth()
                            .padding(vertical = 24.dp),
                        horizontalAlignment = Alignment.CenterHorizontally
                    ) {
                        Icon(
                            imageVector = Icons.Rounded.Key,
                            contentDescription = null,
                            tint = TextMuted,
                            modifier = Modifier.size(36.dp)
                        )
                        Spacer(modifier = Modifier.height(10.dp))
                        Text(
                            text = stringResource(R.string.no_saved_profiles),
                            style = MaterialTheme.typography.titleMedium,
                            color = TextPrimary,
                            textAlign = TextAlign.Center
                        )
                        Spacer(modifier = Modifier.height(4.dp))
                        Text(
                            text = stringResource(R.string.no_saved_profiles_sub),
                            style = MaterialTheme.typography.bodySmall,
                            color = TextMuted,
                            textAlign = TextAlign.Center
                        )
                    }
                }
            }
        } else {
            items(uiState.profiles, key = { it.id }) { profile ->
                val isActive = profile.id == uiState.activeProfile?.id
                ProfileItemCard(
                    profile = profile,
                    isActive = isActive,
                    uiState = uiState,
                    onSelect = { onSelectProfile(profile.id) },
                    onRequestDelete = { pendingDeleteProfile = profile }
                )
            }
        }
    }
}

@Composable
private fun ProfileItemCard(
    profile: MorphProfile,
    isActive: Boolean,
    uiState: MorphUiState,
    onSelect: () -> Unit,
    onRequestDelete: () -> Unit
) {
    val endpoint = profile.formattedEndpoint(
        transportIp = uiState.savedSettings.transportIp,
        portOverride = uiState.savedSettings.portOverride
    )
    val quotaText = TokenParser.formatQuota(profile.quotaBytes)
    val expiryText = TokenParser.formatTimeRemaining(profile.expiresAtEpochSec)

    Surface(
        onClick = onSelect,
        modifier = Modifier
            .fillMaxWidth()
            .testTag("profile_card_${profile.id}"),
        shape = MaterialTheme.shapes.large,
        color = if (isActive) Color(0xCC0D2322) else Color(0xCC121826),
        border = BorderStroke(
            width = if (isActive) 1.5.dp else 1.dp,
            color = if (isActive) EmeraldCore.copy(alpha = 0.6f) else CyberGlassBorder
        )
    ) {
        Column(modifier = Modifier.padding(16.dp)) {
            Row(
                modifier = Modifier.fillMaxWidth(),
                verticalAlignment = Alignment.CenterVertically,
                horizontalArrangement = Arrangement.SpaceBetween
            ) {
                Column(modifier = Modifier.weight(1f)) {
                    Row(
                        verticalAlignment = Alignment.CenterVertically,
                        horizontalArrangement = Arrangement.spacedBy(8.dp)
                    ) {
                        Text(
                            text = profile.name,
                            style = MaterialTheme.typography.titleMedium,
                            color = TextPrimary,
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis,
                            modifier = Modifier.weight(1f, fill = false)
                        )
                        if (isActive) {
                            Surface(
                                shape = RoundedCornerShape(6.dp),
                                color = EmeraldCore.copy(alpha = 0.2f),
                                border = BorderStroke(1.dp, EmeraldCore.copy(alpha = 0.5f))
                            ) {
                                Row(
                                    modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
                                    verticalAlignment = Alignment.CenterVertically,
                                    horizontalArrangement = Arrangement.spacedBy(4.dp)
                                ) {
                                    Icon(
                                        imageVector = Icons.Rounded.CheckCircle,
                                        contentDescription = null,
                                        tint = EmeraldBright,
                                        modifier = Modifier.size(12.dp)
                                    )
                                    Text(
                                        text = stringResource(R.string.active_badge),
                                        style = MaterialTheme.typography.labelSmall,
                                        color = EmeraldBright
                                    )
                                }
                            }
                        }
                    }
                    Spacer(modifier = Modifier.height(3.dp))
                    Text(
                        text = endpoint,
                        style = MaterialTheme.typography.bodySmall.copy(
                            fontFamily = JetBrainsMonoFontFamily
                        ),
                        color = TextSecondary,
                        maxLines = 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }

                IconButton(
                    onClick = onRequestDelete,
                    modifier = Modifier
                        .size(48.dp)
                        .testTag("delete_profile_button_${profile.id}")
                ) {
                    Icon(
                        imageVector = Icons.Rounded.DeleteOutline,
                        contentDescription = stringResource(R.string.delete_profile_cd),
                        tint = DangerBright
                    )
                }
            }

            Spacer(modifier = Modifier.height(10.dp))

            Row(
                modifier = Modifier.fillMaxWidth(),
                horizontalArrangement = Arrangement.spacedBy(16.dp)
            ) {
                Box {
                    Text(
                        text = "${stringResource(R.string.quota_label)}: $quotaText",
                        style = MaterialTheme.typography.bodySmall,
                        color = TextSecondary
                    )
                }
                Box {
                    Text(
                        text = "${stringResource(R.string.expires_label)}: $expiryText",
                        style = MaterialTheme.typography.bodySmall,
                        color = if (expiryText == "Expired") DangerBright else TextSecondary
                    )
                }
            }
        }
    }
}
