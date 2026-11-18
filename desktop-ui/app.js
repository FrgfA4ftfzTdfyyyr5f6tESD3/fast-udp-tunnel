// Morph Core — High-Performance UI Controller
// Communicates with Rust core via Tauri IPC invoke

const invoke = window.__TAURI__?.core?.invoke
  || window.__TAURI__?.invoke
  || window.__TAURI_INTERNALS__?.invoke
  || (async (cmd, args) => {
  console.log(`[IPC Mock] ${cmd}`, args);
  return null;
});

// State Management
let currentStatus = 0; // 0: Disconnected, 1: Connecting, 2: Connected, 3: Error
let activeProfileIndex = 0;
let connectionStartTime = null;
let timerInterval = null;
let telemetryInterval = null;

// Speed Waveform Canvas Buffer
const canvas = document.getElementById('speed-canvas');
const ctx = canvas ? canvas.getContext('2d') : null;
const speedHistory = new Array(30).fill(0);

// Initialize on DOM Ready
document.addEventListener('DOMContentLoaded', () => {
  initTabs();
  initWindowControls();
  initTunnelToggle();
  initSubscriptions();
  initSettings();

  // Initial Data Fetch
  loadProfiles();
  loadSettings();
  startTelemetryPolling();
});

// ================= TAB NAVIGATION =================
function initTabs() {
  const tabs = document.querySelectorAll('.nav-item');
  const panes = document.querySelectorAll('.tab-pane');

  tabs.forEach(tab => {
    tab.addEventListener('click', () => {
      const target = tab.getAttribute('data-tab');
      tabs.forEach(t => t.classList.remove('active'));
      panes.forEach(p => p.classList.remove('active'));

      tab.classList.add('active');
      document.getElementById(target)?.classList.add('active');

      if (target === 'tab-subscriptions') {
        loadProfiles();
      }
    });
  });
}

// ================= WINDOW CONTROLS =================
function initWindowControls() {
  document.getElementById('btn-minimize')?.addEventListener('click', () => {
    invoke('minimize_window').catch(console.error);
  });

  document.getElementById('btn-close')?.addEventListener('click', () => {
    invoke('close_window').catch(console.error);
  });
}

// ================= TUNNEL TOGGLE & TELEMETRY =================
function initTunnelToggle() {
  const btn = document.getElementById('btn-toggle-tunnel');
  btn?.addEventListener('click', async () => {
    if (currentStatus === 2 || currentStatus === 1) {
      // Disconnect
      updateUiStatus(0);
      try {
        await invoke('disconnect_tunnel');
      } catch (err) {
        console.error('Disconnect error:', err);
      }
    } else {
      // Connect
      updateUiStatus(1);
      try {
        const res = await invoke('connect_tunnel');
        console.log('Tunnel started:', res);
      } catch (err) {
        alert('Connection failed: ' + err);
        updateUiStatus(0);
      }
    }
  });
}

function updateUiStatus(status) {
  currentStatus = status;
  const btn = document.getElementById('btn-toggle-tunnel');
  const label = document.getElementById('tunnel-status-label');
  const timer = document.getElementById('tunnel-timer');

  btn.classList.remove('state-disconnected', 'state-connecting', 'state-connected', 'state-error');

  if (status === 2) {
    btn.classList.add('state-connected');
    label.innerText = 'CONNECTED';
    if (!connectionStartTime) {
      connectionStartTime = Date.now();
      timerInterval = setInterval(updateTimerDisplay, 1000);
    }
  } else if (status === 1) {
    btn.classList.add('state-connecting');
    label.innerText = 'CONNECTING...';
  } else if (status === 3) {
    btn.classList.add('state-error');
    label.innerText = 'ERROR';
    clearInterval(timerInterval);
    timerInterval = null;
    connectionStartTime = null;
    timer.innerText = '00:00:00';
    resetTelemetryDisplay();
  } else {
    btn.classList.add('state-disconnected');
    label.innerText = 'DISCONNECTED';
    clearInterval(timerInterval);
    timerInterval = null;
    connectionStartTime = null;
    timer.innerText = '00:00:00';
    resetTelemetryDisplay();
  }
}

function updateTimerDisplay() {
  if (!connectionStartTime) return;
  const elapsedSec = Math.floor((Date.now() - connectionStartTime) / 1000);
  const hrs = String(Math.floor(elapsedSec / 3600)).padStart(2, '0');
  const mins = String(Math.floor((elapsedSec % 3600) / 60)).padStart(2, '0');
  const secs = String(elapsedSec % 60).padStart(2, '0');
  document.getElementById('tunnel-timer').innerText = `${hrs}:${mins}:${secs}`;
}

function startTelemetryPolling() {
  if (telemetryInterval) clearInterval(telemetryInterval);
  telemetryInterval = setInterval(async () => {
    try {
      const data = await invoke('get_telemetry');
      if (!data) return;

      if (data.status !== currentStatus) {
        updateUiStatus(data.status);
      }

      if (data.status === 2) {
        // Ping
        document.getElementById('val-ping').innerText = data.ping_ms > 0 ? data.ping_ms : '--';

        // Down speed
        const down = formatSpeed(data.rx_rate_bps);
        document.getElementById('val-down-speed').innerText = down.val;
        document.getElementById('unit-down-speed').innerText = down.unit;

        // Up speed
        const up = formatSpeed(data.tx_rate_bps);
        document.getElementById('val-up-speed').innerText = up.val;
        document.getElementById('unit-up-speed').innerText = up.unit;

        // Total usage
        const total = formatBytes(data.total_rx_bytes + data.total_tx_bytes);
        document.getElementById('val-total-bytes').innerText = total.val;
        document.getElementById('unit-total-bytes').innerText = total.unit;

        // PMTU
        if (data.pmtu > 0) {
          document.getElementById('val-pmtu').innerText = `PMTU: ${data.pmtu}`;
        }

        // Draw Canvas Graph
        speedHistory.push(data.rx_rate_bps / 1024); // in KB/s
        speedHistory.shift();
        drawWaveform();
      }
    } catch (err) {
      // ignore poll err
    }
  }, 1000);
}

function resetTelemetryDisplay() {
  document.getElementById('val-ping').innerText = '--';
  document.getElementById('val-down-speed').innerText = '0.0';
  document.getElementById('unit-down-speed').innerText = 'KB/s';
  document.getElementById('val-up-speed').innerText = '0.0';
  document.getElementById('unit-up-speed').innerText = 'KB/s';
  document.getElementById('val-total-bytes').innerText = '0.0';
  document.getElementById('unit-total-bytes').innerText = 'MB';
  document.getElementById('val-pmtu').innerText = 'PMTU: --';
  speedHistory.fill(0);
  drawWaveform();
}

function formatSpeed(bytesPerSec) {
  const kb = bytesPerSec / 1024;
  if (kb >= 1024) {
    return { val: (kb / 1024).toFixed(1), unit: 'MB/s' };
  }
  return { val: kb.toFixed(1), unit: 'KB/s' };
}

function formatBytes(bytes) {
  const mb = bytes / (1024 * 1024);
  if (mb >= 1024) {
    return { val: (mb / 1024).toFixed(2), unit: 'GB' };
  }
  return { val: mb.toFixed(1), unit: 'MB' };
}

function drawWaveform() {
  if (!ctx || !canvas) return;
  const w = canvas.width;
  const h = canvas.height;

  ctx.clearRect(0, 0, w, h);

  const max = Math.max(...speedHistory, 50);
  const step = w / (speedHistory.length - 1);

  ctx.beginPath();
  ctx.moveTo(0, h);

  for (let i = 0; i < speedHistory.length; i++) {
    const y = h - (speedHistory[i] / max) * (h - 8);
    ctx.lineTo(i * step, y);
  }

  ctx.lineTo(w, h);
  ctx.closePath();

  const grad = ctx.createLinearGradient(0, 0, 0, h);
  grad.addColorStop(0, 'rgba(16, 185, 129, 0.4)');
  grad.addColorStop(1, 'rgba(16, 185, 129, 0.0)');
  ctx.fillStyle = grad;
  ctx.fill();

  ctx.beginPath();
  for (let i = 0; i < speedHistory.length; i++) {
    const y = h - (speedHistory[i] / max) * (h - 8);
    if (i === 0) ctx.moveTo(0, y);
    else ctx.lineTo(i * step, y);
  }
  ctx.strokeStyle = '#10b981';
  ctx.lineWidth = 1.8;
  ctx.stroke();
}

// ================= SUBSCRIPTIONS & TOKENS =================
function initSubscriptions() {
  document.getElementById('btn-import-token')?.addEventListener('click', async () => {
    const input = document.getElementById('input-token-link');
    const msg = document.getElementById('import-msg');
    const val = input.value.trim();

    if (!val) {
      msg.className = 'status-msg error';
      msg.innerText = 'Please paste a valid morph:// token link';
      return;
    }

    try {
      const added = await invoke('import_profile', { token: val });
      msg.className = 'status-msg success';
      msg.innerText = `Imported profile: ${added.name || 'Success'}`;
      input.value = '';
      loadProfiles();
    } catch (err) {
      msg.className = 'status-msg error';
      msg.innerText = `Error: ${err}`;
    }
  });
}

async function loadProfiles() {
  try {
    const profiles = await invoke('list_profiles');
    if (!profiles) return;

    document.getElementById('profile-count').innerText = profiles.length;
    const container = document.getElementById('profiles-list');
    container.innerHTML = '';

    if (profiles.length === 0) {
      container.innerHTML = '<div style="text-align:center; padding: 20px; color: #64748b; font-size: 11px;">No tokens saved. Paste a morph:// link above to add one.</div>';
      document.getElementById('active-profile-name').innerText = 'No Profile Selected';
      document.getElementById('active-profile-endpoint').innerText = '[--:--]';
      document.getElementById('active-profile-mimic').innerText = 'AUTO';
      document.getElementById('active-profile-mode').innerText = 'AUTO';
      return;
    }

    profiles.forEach((p, idx) => {
      const card = document.createElement('div');
      card.className = `sub-card ${p.is_active ? 'active-sub' : ''}`;
      card.innerHTML = `
        <div class="sub-top">
          <span class="sub-name">${escapeHtml(p.name)}</span>
          <span class="sub-host">${escapeHtml(p.server_host)}:${p.port}</span>
        </div>
        <div class="sub-metrics">
          <span>Quota: <b>${escapeHtml(p.quota_remaining)}</b></span>
          <span>Time: <b>${escapeHtml(p.time_remaining)}</b></span>
        </div>
        <div class="sub-actions">
          <button class="btn-card-select" data-idx="${idx}">${p.is_active ? 'Active' : 'Select'}</button>
          <button class="btn-card-delete" data-idx="${idx}" title="Delete Token">&#128465;</button>
        </div>
      `;

      card.querySelector('.btn-card-select').addEventListener('click', async () => {
        await invoke('set_active_profile', { index: idx });
        loadProfiles();
        updateActiveProfileQuickView(p);
      });

      card.querySelector('.btn-card-delete').addEventListener('click', async (e) => {
        e.stopPropagation();
        if (confirm(`Delete profile '${p.name}'?`)) {
          await invoke('delete_profile', { index: idx });
          loadProfiles();
        }
      });

      container.appendChild(card);

      if (p.is_active) {
        updateActiveProfileQuickView(p);
      }
    });
  } catch (err) {
    console.error('Failed to load profiles:', err);
  }
}

let cachedSettings = { camouflage_protocol: 'auto', payload_mode: 'auto', port_override: null };
let cachedActiveProfile = null;

function updateActiveProfileQuickView(p) {
  if (p) cachedActiveProfile = p;
  const prof = cachedActiveProfile;
  if (!prof) return;
  document.getElementById('active-profile-name').innerText = prof.name;
  const effPort = cachedSettings.port_override || prof.port;
  document.getElementById('active-profile-endpoint').innerText = `${prof.server_host}:${effPort}`;
  const effMimic = cachedSettings.camouflage_protocol && cachedSettings.camouflage_protocol !== 'auto'
    ? cachedSettings.camouflage_protocol.toUpperCase()
    : prof.mimic_protocol;
  const effMode = cachedSettings.payload_mode && cachedSettings.payload_mode !== 'auto'
    ? cachedSettings.payload_mode
    : prof.payload_mode;
  document.getElementById('active-profile-mimic').innerText = effMimic;
  document.getElementById('active-profile-mode').innerText = effMode;
}

function escapeHtml(str) {
  return String(str || '').replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// ================= SETTINGS =================
function initSettings() {
  document.getElementById('btn-save-settings')?.addEventListener('click', async () => {
    const ipMode = document.querySelector('input[name="transport-ip"]:checked')?.value || 'auto';
    const mimic = document.getElementById('select-mimic-protocol').value;
    const portVal = document.getElementById('input-port-override').value.trim();
    const payload = document.getElementById('select-payload-mode').value;
    const msg = document.getElementById('settings-status-msg');

    const portOverride = portVal ? parseInt(portVal, 10) : null;

    try {
      const newSettings = {
        transport_ip: ipMode,
        camouflage_protocol: mimic,
        port_override: portOverride,
        payload_mode: payload,
      };
      await invoke('update_tunnel_settings', { settings: newSettings });
      cachedSettings = newSettings;
      updateActiveProfileQuickView(null);
      msg.className = 'status-msg success';
      msg.innerText = 'Settings saved successfully';
      setTimeout(() => { msg.innerText = ''; }, 3000);
    } catch (err) {
      msg.className = 'status-msg error';
      msg.innerText = `Save failed: ${err}`;
    }
  });

  document.getElementById('btn-reset-port')?.addEventListener('click', () => {
    document.getElementById('input-port-override').value = '';
  });
}

async function loadSettings() {
  try {
    const s = await invoke('get_tunnel_settings');
    if (!s) return;
    cachedSettings = s;

    const r = document.querySelector(`input[name="transport-ip"][value="${s.transport_ip}"]`);
    if (r) r.checked = true;

    if (s.camouflage_protocol) {
      document.getElementById('select-mimic-protocol').value = s.camouflage_protocol;
    }
    if (s.port_override) {
      document.getElementById('input-port-override').value = s.port_override;
    }
    if (s.payload_mode) {
      document.getElementById('select-payload-mode').value = s.payload_mode;
    }
    updateActiveProfileQuickView(null);
  } catch (err) {
    console.error('Failed to load settings:', err);
  }
}
