package com.morphcore.vpn.ui

import android.Manifest
import android.app.Activity
import android.content.pm.PackageManager
import android.os.Build
import androidx.activity.compose.BackHandler
import androidx.activity.compose.rememberLauncherForActivityResult
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.background
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.BoxWithConstraints
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.Row
import androidx.compose.foundation.layout.Spacer
import androidx.compose.foundation.layout.WindowInsets
import androidx.compose.foundation.layout.fillMaxHeight
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.fillMaxWidth
import androidx.compose.foundation.layout.height
import androidx.compose.foundation.layout.navigationBarsPadding
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.safeDrawing
import androidx.compose.foundation.layout.statusBarsPadding
import androidx.compose.foundation.layout.widthIn
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.outlined.Key
import androidx.compose.material.icons.outlined.Shield
import androidx.compose.material.icons.outlined.Tune
import androidx.compose.material.icons.rounded.Key
import androidx.compose.material.icons.rounded.Shield
import androidx.compose.material.icons.rounded.Tune
import androidx.compose.material3.Icon
import androidx.compose.material3.NavigationBar
import androidx.compose.material3.NavigationBarItem
import androidx.compose.material3.NavigationBarItemDefaults
import androidx.compose.material3.NavigationRail
import androidx.compose.material3.NavigationRailItem
import androidx.compose.material3.NavigationRailItemDefaults
import androidx.compose.material3.Scaffold
import androidx.compose.material3.Text
import androidx.compose.runtime.Composable
import androidx.compose.runtime.getValue
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.graphics.vector.ImageVector
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.testTag
import androidx.compose.ui.res.stringResource
import androidx.compose.ui.unit.dp
import androidx.core.content.ContextCompat
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import androidx.lifecycle.viewmodel.compose.viewModel
import com.example.R
import com.example.ui.theme.CyberBgPrimary
import com.example.ui.theme.CyberBgRadialTop
import com.example.ui.theme.CyberBgSurface
import com.example.ui.theme.EmeraldBright
import com.example.ui.theme.EmeraldCore
import com.example.ui.theme.TextMuted
import com.morphcore.vpn.data.MainTab
import com.morphcore.vpn.data.VpnStatus
import com.morphcore.vpn.ui.components.MorphBrandHeader
import com.morphcore.vpn.ui.screens.OptionsScreen
import com.morphcore.vpn.ui.screens.TokensScreen
import com.morphcore.vpn.ui.screens.TunnelDashboardScreen

private data class NavDestination(
    val tab: MainTab,
    val labelRes: Int,
    val selectedIcon: ImageVector,
    val unselectedIcon: ImageVector,
    val testTag: String
)

private val Destinations = listOf(
    NavDestination(
        tab = MainTab.TUNNEL,
        labelRes = R.string.tab_tunnel,
        selectedIcon = Icons.Rounded.Shield,
        unselectedIcon = Icons.Outlined.Shield,
        testTag = "nav_tab_tunnel"
    ),
    NavDestination(
        tab = MainTab.TOKENS,
        labelRes = R.string.tab_tokens,
        selectedIcon = Icons.Rounded.Key,
        unselectedIcon = Icons.Outlined.Key,
        testTag = "nav_tab_tokens"
    ),
    NavDestination(
        tab = MainTab.OPTIONS,
        labelRes = R.string.tab_options,
        selectedIcon = Icons.Rounded.Tune,
        unselectedIcon = Icons.Outlined.Tune,
        testTag = "nav_tab_options"
    )
)

@Composable
fun MorphApp(
    viewModel: MorphViewModel = viewModel()
) {
    val uiState by viewModel.uiState.collectAsStateWithLifecycle()
    val context = LocalContext.current

    val vpnPermissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.StartActivityForResult()
    ) { result ->
        if (result.resultCode == Activity.RESULT_OK) {
            viewModel.startVpnTunnel(context)
        } else {
            viewModel.onVpnPermissionDenied(context)
        }
    }

    fun proceedWithVpnConsentAndConnect() {
        val prepareIntent = viewModel.prepareVpnIntent(context)
        if (prepareIntent != null) {
            vpnPermissionLauncher.launch(prepareIntent)
        } else {
            viewModel.startVpnTunnel(context)
        }
    }

    val notificationPermissionLauncher = rememberLauncherForActivityResult(
        contract = ActivityResultContracts.RequestPermission()
    ) {
        proceedWithVpnConsentAndConnect()
    }

    fun handlePowerToggle() {
        when (uiState.vpnStatus) {
            VpnStatus.CONNECTED, VpnStatus.CONNECTING -> {
                viewModel.requestDisconnect(context)
            }
            VpnStatus.DISCONNECTED, VpnStatus.ERROR -> {
                if (uiState.activeProfile == null) {
                    viewModel.startVpnTunnel(context)
                    return
                }
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
                    val granted = ContextCompat.checkSelfPermission(
                        context,
                        Manifest.permission.POST_NOTIFICATIONS
                    ) == PackageManager.PERMISSION_GRANTED
                    if (!granted) {
                        notificationPermissionLauncher.launch(Manifest.permission.POST_NOTIFICATIONS)
                        return
                    }
                }
                proceedWithVpnConsentAndConnect()
            }
        }
    }

    BackHandler(enabled = uiState.selectedTab != MainTab.TUNNEL) {
        viewModel.selectTab(MainTab.TUNNEL)
    }

    Box(
        modifier = Modifier
            .fillMaxSize()
            .background(
                Brush.verticalGradient(
                    colors = listOf(
                        CyberBgRadialTop,
                        CyberBgPrimary,
                        CyberBgPrimary
                    )
                )
            )
    ) {
        BoxWithConstraints(modifier = Modifier.fillMaxSize()) {
            val useNavigationRail = maxWidth >= 600.dp

            Scaffold(
                containerColor = Color.Transparent,
                contentWindowInsets = WindowInsets.safeDrawing,
                bottomBar = {
                    if (!useNavigationRail) {
                        NavigationBar(
                            containerColor = CyberBgSurface.copy(alpha = 0.96f),
                            modifier = Modifier.navigationBarsPadding()
                        ) {
                            Destinations.forEach { dest ->
                                val selected = uiState.selectedTab == dest.tab
                                NavigationBarItem(
                                    selected = selected,
                                    onClick = { viewModel.selectTab(dest.tab) },
                                    modifier = Modifier.testTag(dest.testTag),
                                    icon = {
                                        Icon(
                                            imageVector = if (selected) dest.selectedIcon else dest.unselectedIcon,
                                            contentDescription = stringResource(dest.labelRes)
                                        )
                                    },
                                    label = {
                                        Text(text = stringResource(dest.labelRes))
                                    },
                                    colors = NavigationBarItemDefaults.colors(
                                        selectedIconColor = EmeraldBright,
                                        selectedTextColor = EmeraldBright,
                                        indicatorColor = EmeraldCore.copy(alpha = 0.18f),
                                        unselectedIconColor = TextMuted,
                                        unselectedTextColor = TextMuted
                                    )
                                )
                            }
                        }
                    }
                }
            ) { innerPadding ->
                Row(
                    modifier = Modifier
                        .fillMaxSize()
                        .padding(innerPadding)
                ) {
                    if (useNavigationRail) {
                        NavigationRail(
                            containerColor = CyberBgSurface.copy(alpha = 0.92f),
                            modifier = Modifier
                                .fillMaxHeight()
                                .statusBarsPadding()
                        ) {
                            Spacer(modifier = Modifier.height(16.dp))
                            Destinations.forEach { dest ->
                                val selected = uiState.selectedTab == dest.tab
                                NavigationRailItem(
                                    selected = selected,
                                    onClick = { viewModel.selectTab(dest.tab) },
                                    modifier = Modifier.testTag(dest.testTag),
                                    icon = {
                                        Icon(
                                            imageVector = if (selected) dest.selectedIcon else dest.unselectedIcon,
                                            contentDescription = stringResource(dest.labelRes)
                                        )
                                    },
                                    label = {
                                        Text(text = stringResource(dest.labelRes))
                                    },
                                    colors = NavigationRailItemDefaults.colors(
                                        selectedIconColor = EmeraldBright,
                                        selectedTextColor = EmeraldBright,
                                        indicatorColor = EmeraldCore.copy(alpha = 0.18f),
                                        unselectedIconColor = TextMuted,
                                        unselectedTextColor = TextMuted
                                    )
                                )
                            }
                        }
                    }

                    Box(
                        modifier = Modifier
                            .weight(1f)
                            .fillMaxHeight(),
                        contentAlignment = Alignment.TopCenter
                    ) {
                        Column(
                            modifier = Modifier
                                .fillMaxSize()
                                .widthIn(max = 640.dp)
                                .padding(horizontal = 16.dp, vertical = 12.dp)
                        ) {
                            MorphBrandHeader(vpnStatus = uiState.vpnStatus)
                            Spacer(modifier = Modifier.height(14.dp))

                            Box(modifier = Modifier.weight(1f).fillMaxWidth()) {
                                when (uiState.selectedTab) {
                                    MainTab.TUNNEL -> TunnelDashboardScreen(
                                        uiState = uiState,
                                        onPowerClick = ::handlePowerToggle,
                                        onNavigateToTokens = { viewModel.selectTab(MainTab.TOKENS) },
                                        onDismissError = { viewModel.clearVpnError() }
                                    )
                                    MainTab.TOKENS -> TokensScreen(
                                        uiState = uiState,
                                        onTokenInputChange = viewModel::onTokenInputChanged,
                                        onClipboardEmpty = viewModel::showClipboardEmptyMessage,
                                        onImportToken = viewModel::importToken,
                                        onSelectProfile = viewModel::selectProfile,
                                        onDeleteProfile = viewModel::deleteProfile
                                    )
                                    MainTab.OPTIONS -> OptionsScreen(
                                        uiState = uiState,
                                        onTransportIpChange = viewModel::updateDraftTransportIp,
                                        onCamouflageProtocolChange = viewModel::updateDraftCamouflageProtocol,
                                        onPortTextChange = viewModel::updateDraftPortText,
                                        onResetPort = viewModel::resetDraftPort,
                                        onPayloadModeChange = viewModel::updateDraftPayloadMode,
                                        onSaveOptions = viewModel::saveOptions
                                    )
                                }
                            }
                        }
                    }
                }
            }
        }
    }
}
