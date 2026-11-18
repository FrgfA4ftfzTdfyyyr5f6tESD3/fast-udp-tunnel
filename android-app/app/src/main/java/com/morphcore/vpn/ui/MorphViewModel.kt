package com.morphcore.vpn.ui

import android.app.Application
import android.content.Context
import android.net.VpnService
import androidx.lifecycle.AndroidViewModel
import androidx.lifecycle.viewModelScope
import com.example.R
import com.morphcore.vpn.MorphNative
import com.morphcore.vpn.MorphVpnService
import com.morphcore.vpn.data.CamouflageProtocol
import com.morphcore.vpn.data.MainTab
import com.morphcore.vpn.data.MorphProfile
import com.morphcore.vpn.data.MorphRepository
import com.morphcore.vpn.data.PayloadMode
import com.morphcore.vpn.data.TelemetryState
import com.morphcore.vpn.data.TokenParser
import com.morphcore.vpn.data.TransportIpMode
import com.morphcore.vpn.data.TunnelSettings
import com.morphcore.vpn.data.VpnStatus
import com.morphcore.vpn.service.VpnStateManager
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.SharingStarted
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.combine
import kotlinx.coroutines.flow.stateIn
import kotlinx.coroutines.flow.update
import kotlinx.coroutines.launch
import kotlinx.coroutines.withContext

data class StatusBannerMessage(
    val text: String,
    val isError: Boolean
)

data class MorphUiState(
    val selectedTab: MainTab = MainTab.TUNNEL,
    val vpnStatus: VpnStatus = VpnStatus.DISCONNECTED,
    val vpnErrorMessage: String? = null,
    val telemetry: TelemetryState = TelemetryState(),
    val profiles: List<MorphProfile> = emptyList(),
    val activeProfileId: String? = null,
    val savedSettings: TunnelSettings = TunnelSettings(),
    val draftSettings: TunnelSettings = TunnelSettings(),
    val draftPortText: String = "",
    val tokenInput: String = "",
    val importMessage: StatusBannerMessage? = null,
    val settingsMessage: StatusBannerMessage? = null
) {
    val activeProfile: MorphProfile?
        get() = profiles.firstOrNull { it.id == activeProfileId } ?: profiles.firstOrNull()
}

class MorphViewModel(application: Application) : AndroidViewModel(application) {

    private val repository = MorphRepository(application.applicationContext)

    private val selectedTabFlow = MutableStateFlow(MainTab.TUNNEL)
    private val tokenInputFlow = MutableStateFlow("")
    private val importMessageFlow = MutableStateFlow<StatusBannerMessage?>(null)
    private val settingsMessageFlow = MutableStateFlow<StatusBannerMessage?>(null)
    private val draftSettingsFlow = MutableStateFlow(TunnelSettings())
    private val draftPortTextFlow = MutableStateFlow("")
    private var draftInitialized = false

    init {
        viewModelScope.launch {
            repository.settingsFlow.collect { saved ->
                if (!draftInitialized) {
                    draftSettingsFlow.value = saved
                    draftPortTextFlow.value = saved.portOverride?.toString().orEmpty()
                    draftInitialized = true
                }
            }
        }
    }

    private data class CoreSnapshot(
        val selectedTab: MainTab,
        val vpnStatus: VpnStatus,
        val vpnError: String?,
        val telemetry: TelemetryState,
        val profiles: List<MorphProfile>,
        val activeProfileId: String?,
        val savedSettings: TunnelSettings
    )

    private val coreSnapshotFlow = combine(
        selectedTabFlow,
        VpnStateManager.status,
        VpnStateManager.errorMessage,
        VpnStateManager.telemetry,
        repository.profilesFlow,
        repository.activeProfileIdFlow,
        repository.settingsFlow
    ) { values ->
        @Suppress("UNCHECKED_CAST")
        CoreSnapshot(
            selectedTab = values[0] as MainTab,
            vpnStatus = values[1] as VpnStatus,
            vpnError = values[2] as String?,
            telemetry = values[3] as TelemetryState,
            profiles = values[4] as List<MorphProfile>,
            activeProfileId = values[5] as String?,
            savedSettings = values[6] as TunnelSettings
        )
    }

    val uiState: StateFlow<MorphUiState> = combine(
        coreSnapshotFlow,
        draftSettingsFlow,
        draftPortTextFlow,
        tokenInputFlow,
        importMessageFlow,
        settingsMessageFlow
    ) { values ->
        val core = values[0] as CoreSnapshot
        val draftSettings = values[1] as TunnelSettings
        val draftPortText = values[2] as String
        val tokenInput = values[3] as String
        val importMsg = values[4] as StatusBannerMessage?
        val settingsMsg = values[5] as StatusBannerMessage?

        MorphUiState(
            selectedTab = core.selectedTab,
            vpnStatus = core.vpnStatus,
            vpnErrorMessage = core.vpnError,
            telemetry = core.telemetry,
            profiles = core.profiles,
            activeProfileId = core.activeProfileId,
            savedSettings = core.savedSettings,
            draftSettings = draftSettings,
            draftPortText = draftPortText,
            tokenInput = tokenInput,
            importMessage = importMsg,
            settingsMessage = settingsMsg
        )
    }.stateIn(
        scope = viewModelScope,
        started = SharingStarted.WhileSubscribed(5_000L),
        initialValue = MorphUiState()
    )

    fun selectTab(tab: MainTab) {
        selectedTabFlow.value = tab
    }

    fun onTokenInputChanged(value: String) {
        tokenInputFlow.value = value
        if (importMessageFlow.value != null) {
            importMessageFlow.value = null
        }
    }

    fun showClipboardEmptyMessage() {
        importMessageFlow.value = StatusBannerMessage(
            text = getApplication<Application>().getString(R.string.clipboard_empty),
            isError = true
        )
    }

    fun importToken(rawInput: String = tokenInputFlow.value) {
        val ctx = getApplication<Application>()
        val trimmed = rawInput.trim()
        if (trimmed.isEmpty()) {
            importMessageFlow.value = StatusBannerMessage(
                text = ctx.getString(R.string.token_empty_error),
                isError = true
            )
            return
        }

        viewModelScope.launch {
            val decodedJson = withContext(Dispatchers.Default) {
                runCatching { MorphNative.decodeTokenInfo(trimmed) }.getOrDefault("")
            }
            val parsed = TokenParser.parseDecodedJson(trimmed, decodedJson)
            if (parsed == null) {
                importMessageFlow.value = StatusBannerMessage(
                    text = ctx.getString(R.string.token_invalid_error),
                    isError = true
                )
                return@launch
            }

            val updated = repository.saveOrUpdateProfile(parsed, setAsActive = true)
            tokenInputFlow.value = ""
            importMessageFlow.value = StatusBannerMessage(
                text = ctx.getString(
                    if (updated) R.string.token_duplicate_updated else R.string.token_imported_success
                ),
                isError = false
            )
        }
    }

    fun selectProfile(profileId: String) {
        viewModelScope.launch {
            repository.setActiveProfile(profileId)
        }
    }

    fun deleteProfile(profileId: String) {
        viewModelScope.launch {
            repository.deleteProfile(profileId)
        }
    }

    fun updateDraftTransportIp(mode: TransportIpMode) {
        draftSettingsFlow.update { it.copy(transportIp = mode) }
        settingsMessageFlow.value = null
    }

    fun updateDraftCamouflageProtocol(protocol: CamouflageProtocol) {
        draftSettingsFlow.update { it.copy(camouflageProtocol = protocol) }
        settingsMessageFlow.value = null
    }

    fun updateDraftPortText(raw: String) {
        val filtered = raw.filter { it.isDigit() }.take(5)
        draftPortTextFlow.value = filtered
        settingsMessageFlow.value = null
    }

    fun resetDraftPort() {
        draftPortTextFlow.value = ""
        draftSettingsFlow.update { it.copy(portOverride = null) }
        settingsMessageFlow.value = null
    }

    fun updateDraftPayloadMode(mode: PayloadMode) {
        draftSettingsFlow.update { it.copy(payloadMode = mode) }
        settingsMessageFlow.value = null
    }

    fun saveOptions() {
        val ctx = getApplication<Application>()
        val portRaw = draftPortTextFlow.value.trim()
        val parsedPort: Int? = if (portRaw.isEmpty()) {
            null
        } else {
            val p = portRaw.toIntOrNull()
            if (p == null || p !in 1..65535) {
                settingsMessageFlow.value = StatusBannerMessage(
                    text = ctx.getString(R.string.options_port_invalid),
                    isError = true
                )
                return
            }
            p
        }

        val finalSettings = draftSettingsFlow.value.copy(portOverride = parsedPort)
        draftSettingsFlow.value = finalSettings

        viewModelScope.launch {
            repository.saveSettings(finalSettings)
            settingsMessageFlow.value = StatusBannerMessage(
                text = ctx.getString(R.string.options_saved_message),
                isError = false
            )
        }
    }

    fun requestDisconnect(context: Context) {
        MorphVpnService.startDisconnect(context)
    }

    fun startVpnTunnel(context: Context) {
        val state = uiState.value
        val active = state.activeProfile
        if (active == null) {
            VpnStateManager.setError(context.getString(R.string.select_token_hint))
            return
        }
        val settings = state.savedSettings
        MorphVpnService.startConnect(
            context = context,
            token = active.token,
            mimicOverride = settings.camouflageProtocol.key,
            payloadModeOverride = settings.payloadMode.key,
            transportOverride = settings.transportIp.key,
            portOverride = settings.portOverride,
            profileName = active.name
        )
    }

    fun onVpnPermissionDenied(context: Context) {
        VpnStateManager.setError(context.getString(R.string.vpn_permission_denied))
    }

    fun clearVpnError() {
        VpnStateManager.clearError()
    }

    fun prepareVpnIntent(context: Context) = VpnService.prepare(context)
}
