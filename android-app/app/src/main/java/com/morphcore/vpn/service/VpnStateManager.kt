package com.morphcore.vpn.service

import com.morphcore.vpn.data.TelemetryState
import com.morphcore.vpn.data.VpnStatus
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.flow.update

object VpnStateManager {

    private const val WAVEFORM_POINTS = 30

    private val _status = MutableStateFlow(VpnStatus.DISCONNECTED)
    val status: StateFlow<VpnStatus> = _status.asStateFlow()

    private val _errorMessage = MutableStateFlow<String?>(null)
    val errorMessage: StateFlow<String?> = _errorMessage.asStateFlow()

    private val _telemetry = MutableStateFlow(TelemetryState())
    val telemetry: StateFlow<TelemetryState> = _telemetry.asStateFlow()

    fun setConnecting() {
        _errorMessage.value = null
        _status.value = VpnStatus.CONNECTING
        _telemetry.value = TelemetryState()
    }

    fun setConnected() {
        _errorMessage.value = null
        _status.value = VpnStatus.CONNECTED
    }

    fun setDisconnected() {
        _errorMessage.value = null
        _status.value = VpnStatus.DISCONNECTED
        _telemetry.value = TelemetryState()
    }

    fun setError(message: String) {
        _errorMessage.value = message
        _status.value = VpnStatus.ERROR
        _telemetry.value = TelemetryState()
    }

    fun clearError() {
        _errorMessage.value = null
        if (_status.value == VpnStatus.ERROR) {
            _status.value = VpnStatus.DISCONNECTED
        }
    }

    fun updateTelemetry(
        rxBytes: Long,
        txBytes: Long,
        rxPackets: Long,
        txPackets: Long,
        rttMs: Long,
        rxRateBps: Long,
        txRateBps: Long,
        elapsedSeconds: Long
    ) {
        _telemetry.update { current ->
            val nextRxHistory = (current.rxWaveform.drop(1) + (rxRateBps / 1024f)).let { list ->
                if (list.size == WAVEFORM_POINTS) list else List(WAVEFORM_POINTS - list.size) { 0f } + list
            }
            val nextTxHistory = (current.txWaveform.drop(1) + (txRateBps / 1024f)).let { list ->
                if (list.size == WAVEFORM_POINTS) list else List(WAVEFORM_POINTS - list.size) { 0f } + list
            }
            current.copy(
                rxBytes = rxBytes,
                txBytes = txBytes,
                rxPackets = rxPackets,
                txPackets = txPackets,
                rttMs = rttMs,
                rxRateBps = rxRateBps,
                txRateBps = txRateBps,
                rxWaveform = nextRxHistory,
                txWaveform = nextTxHistory,
                elapsedSeconds = elapsedSeconds
            )
        }
    }
}
