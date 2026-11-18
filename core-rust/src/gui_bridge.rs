//! Tauri v2 Desktop GUI Bridge for Morph Fast UDP Tunnel.
//! Connects vanilla HTML5/CSS/JS frontend to the native Rust engine.

#![cfg(target_os = "windows")]

use std::error::Error;
use std::sync::{Arc, Mutex};
use std::sync::atomic::Ordering;
use serde::{Deserialize, Serialize};
use tauri::Manager;

use crate::common::IpPreference;
use crate::core::crypto::PayloadMode;
use crate::mimic::MimicProfile;
use crate::client::config_manager;
use crate::core::metrics::{TunnelStatus, TunnelTelemetry};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TelemetryDto {
    pub status: u8,
    pub ping_ms: u16,
    pub tx_rate_bps: u64,
    pub rx_rate_bps: u64,
    pub total_tx_bytes: u64,
    pub total_rx_bytes: u64,
    pub pmtu: u16,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProfileDto {
    pub index: usize,
    pub name: String,
    pub user_id: String,
    pub server_host: String,
    pub port: u16,
    pub quota_remaining: String,
    pub time_remaining: String,
    pub mimic_protocol: String,
    pub payload_mode: String,
    pub is_active: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettingsDto {
    pub transport_ip: String,
    pub camouflage_protocol: String,
    pub port_override: Option<u16>,
    pub payload_mode: String,
}

impl Default for SettingsDto {
    fn default() -> Self {
        Self {
            transport_ip: "auto".into(),
            camouflage_protocol: "auto".into(),
            port_override: None,
            payload_mode: "auto".into(),
        }
    }
}

pub struct GuiState {
    pub active_profile_index: usize,
    pub settings: SettingsDto,
    pub tunnel_thread: Option<std::thread::JoinHandle<()>>,
}

#[tauri::command]
pub fn get_telemetry() -> TelemetryDto {
    let telem = TunnelTelemetry::global();
    TelemetryDto {
        status: telem.status.load(Ordering::Relaxed),
        ping_ms: telem.ping_ms.load(Ordering::Relaxed),
        tx_rate_bps: telem.tx_rate_bps.load(Ordering::Relaxed),
        rx_rate_bps: telem.rx_rate_bps.load(Ordering::Relaxed),
        total_tx_bytes: telem.total_tx_bytes.load(Ordering::Relaxed),
        total_rx_bytes: telem.total_rx_bytes.load(Ordering::Relaxed),
        pmtu: telem.pmtu.load(Ordering::Relaxed),
    }
}

#[tauri::command]
pub fn connect_tunnel(state: tauri::State<Arc<Mutex<GuiState>>>) -> Result<String, String> {
    let telem = TunnelTelemetry::global();
    let current_st = telem.get_status();
    let mut state_guard = state.lock().map_err(|e| e.to_string())?;

    if current_st == TunnelStatus::Connected || current_st == TunnelStatus::Connecting {
        return Err("Tunnel is already active or connecting. Disconnect first.".into());
    }
    if let Some(old_handle) = state_guard.tunnel_thread.take() {
        let _ = old_handle.join();
    }

    let profiles = config_manager::load_profiles();
    if profiles.is_empty() {
        return Err("No subscription profiles found. Please import a morph:// token first.".into());
    }

    let active_idx = if state_guard.active_profile_index < profiles.len() {
        state_guard.active_profile_index
    } else {
        0
    };

    let p = &profiles[active_idx];
    let token = p.token.clone();

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    if token.is_expired(now) {
        return Err(format!("Subscription token '{}' has expired on {}.", token.name, token.remaining_time_str(now)));
    }

    // Map IP preference
    let ip_pref = match state_guard.settings.transport_ip.as_str() {
        "ipv4" => IpPreference::ForceV4,
        "ipv6" => IpPreference::ForceV6,
        _ => IpPreference::Auto,
    };

    // Map camouflage profile override
    let profile = if state_guard.settings.camouflage_protocol != "auto" {
        MimicProfile::parse(&state_guard.settings.camouflage_protocol).unwrap_or(token.mimic_profile())
    } else {
        token.mimic_profile()
    };

    // Map payload mode override
    let mode = if state_guard.settings.payload_mode != "auto" {
        PayloadMode::parse(&state_guard.settings.payload_mode).unwrap_or(token.payload_protection_mode())
    } else {
        token.payload_protection_mode()
    };

    let port_override = state_guard.settings.port_override;
    let psk = token.psk;
    let assigned_v4 = token.assigned_ipv4.clone();
    let assigned_v6 = token.assigned_ipv6.clone();

    telem.shutdown_requested.store(false, Ordering::SeqCst);
    telem.set_status(TunnelStatus::Connecting);

    let endpoint = config_manager::resolve_optimal_endpoint(&token, ip_pref, port_override)
        .map_err(|e| {
            telem.set_status(TunnelStatus::Disconnected);
            format!("Failed to resolve endpoint: {}", e)
        })?;

    let ep_cloned = endpoint.clone();
    let handle = std::thread::Builder::new()
        .name("tunnel_engine".into())
        .spawn(move || {
            if let Err(e) = crate::client::engine::run_engine(
                &ep_cloned,
                profile,
                mode,
                psk,
                assigned_v4.as_deref(),
                assigned_v6.as_deref(),
            ) {
                eprintln!("[GUI_BRIDGE] Tunnel engine terminated: {}", e);
                let telem = TunnelTelemetry::global();
                telem.set_status(TunnelStatus::Error);
            }
        })
        .map_err(|e| format!("Failed to spawn tunnel thread: {}", e))?;

    state_guard.tunnel_thread = Some(handle);
    Ok(format!("Connected to {}", endpoint))
}

#[tauri::command]
pub fn disconnect_tunnel(state: tauri::State<Arc<Mutex<GuiState>>>) -> Result<(), String> {
    let telem = TunnelTelemetry::global();
    telem.shutdown_requested.store(true, Ordering::SeqCst);

    let mut state_guard = state.lock().map_err(|e| e.to_string())?;
    if let Some(handle) = state_guard.tunnel_thread.take() {
        // Wait for engine thread to cleanly restore routes, drop adapter, and finish
        let _ = handle.join();
    }
    telem.set_status(TunnelStatus::Disconnected);
    telem.tx_rate_bps.store(0, Ordering::Relaxed);
    telem.rx_rate_bps.store(0, Ordering::Relaxed);
    telem.ping_ms.store(0, Ordering::Relaxed);
    Ok(())
}

#[tauri::command]
pub fn list_profiles(state: tauri::State<Arc<Mutex<GuiState>>>) -> Result<Vec<ProfileDto>, String> {
    let profiles = config_manager::load_profiles();
    let state_guard = state.lock().map_err(|e| e.to_string())?;

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let dtos = profiles.iter().enumerate().map(|(idx, p)| {
        let t = &p.token;
        let host = if let Some(ref v6) = t.server_v6 {
            v6.clone()
        } else if let Some(ref v4) = t.server_v4 {
            v4.clone()
        } else {
            "Unknown".to_string()
        };

        ProfileDto {
            index: idx,
            name: t.name.clone(),
            user_id: t.user_id.clone(),
            server_host: host,
            port: t.port,
            quota_remaining: t.quota_str(),
            time_remaining: t.remaining_time_str(now),
            mimic_protocol: t.mimic_profile().as_str().to_uppercase(),
            payload_mode: t.payload_protection_mode().as_str().to_string(),
            is_active: idx == state_guard.active_profile_index,
        }
    }).collect();

    Ok(dtos)
}

#[tauri::command]
pub fn import_profile(token: String, state: tauri::State<Arc<Mutex<GuiState>>>) -> Result<ProfileDto, String> {
    let p = config_manager::import_token(&token)?;
    let profiles = config_manager::load_profiles();
    let idx = profiles.iter().position(|x| x.token.user_id == p.token.user_id).unwrap_or(0);

    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);

    let host = if let Some(ref v6) = p.token.server_v6 {
        v6.clone()
    } else if let Some(ref v4) = p.token.server_v4 {
        v4.clone()
    } else {
        "Unknown".to_string()
    };

    let mut state_guard = state.lock().map_err(|e| e.to_string())?;
    state_guard.active_profile_index = idx;

    Ok(ProfileDto {
        index: idx,
        name: p.token.name.clone(),
        user_id: p.token.user_id.clone(),
        server_host: host,
        port: p.token.port,
        quota_remaining: p.token.quota_str(),
        time_remaining: p.token.remaining_time_str(now),
        mimic_protocol: p.token.mimic_profile().as_str().to_uppercase(),
        payload_mode: p.token.payload_protection_mode().as_str().to_string(),
        is_active: true,
    })
}

#[tauri::command]
pub fn delete_profile(index: usize, state: tauri::State<Arc<Mutex<GuiState>>>) -> Result<(), String> {
    config_manager::delete_profile(index + 1)?;
    let mut state_guard = state.lock().map_err(|e| e.to_string())?;
    if state_guard.active_profile_index >= index && state_guard.active_profile_index > 0 {
        state_guard.active_profile_index -= 1;
    }
    Ok(())
}

#[tauri::command]
pub fn set_active_profile(index: usize, state: tauri::State<Arc<Mutex<GuiState>>>) -> Result<(), String> {
    let mut state_guard = state.lock().map_err(|e| e.to_string())?;
    state_guard.active_profile_index = index;
    Ok(())
}

#[tauri::command]
pub fn get_tunnel_settings(state: tauri::State<Arc<Mutex<GuiState>>>) -> Result<SettingsDto, String> {
    let state_guard = state.lock().map_err(|e| e.to_string())?;
    Ok(state_guard.settings.clone())
}

#[tauri::command]
pub fn update_tunnel_settings(settings: SettingsDto, state: tauri::State<Arc<Mutex<GuiState>>>) -> Result<(), String> {
    let mut state_guard = state.lock().map_err(|e| e.to_string())?;
    state_guard.settings = settings;
    Ok(())
}

#[tauri::command]
pub fn minimize_window(window: tauri::Window) -> Result<(), String> {
    window.minimize().map_err(|e| e.to_string())
}

#[tauri::command]
pub fn close_window(window: tauri::Window) -> Result<(), String> {
    // Hide to system tray on window close button
    window.hide().map_err(|e| e.to_string())
}

pub fn run_gui() -> Result<(), Box<dyn Error>> {
    let state = Arc::new(Mutex::new(GuiState {
        active_profile_index: 0,
        settings: SettingsDto::default(),
        tunnel_thread: None,
    }));
    let state_for_tray = state.clone();

    tauri::Builder::default()
        .manage(state.clone())
        .invoke_handler(tauri::generate_handler![
            get_telemetry,
            connect_tunnel,
            disconnect_tunnel,
            list_profiles,
            import_profile,
            delete_profile,
            set_active_profile,
            get_tunnel_settings,
            update_tunnel_settings,
            minimize_window,
            close_window,
        ])
        .setup(move |app| {
            // Setup tray icon menu and click handlers
            use tauri::menu::{Menu, MenuItem};
            use tauri::tray::{TrayIconBuilder, TrayIconEvent, MouseButton, MouseButtonState};

            let show_item = MenuItem::with_id(app, "show", "Show Morph Tunnel", true, None::<&str>)?;
            let sep1 = tauri::menu::PredefinedMenuItem::separator(app)?;
            let quit_item = MenuItem::with_id(app, "quit", "Exit & Clean Up", true, None::<&str>)?;
            let menu = Menu::with_items(app, &[&show_item, &sep1, &quit_item])?;

            let _tray = TrayIconBuilder::new()
                .menu(&menu)
                .show_menu_on_left_click(false)
                .on_menu_event(move |app, event| {
                    match event.id.as_ref() {
                        "show" => {
                            if let Some(window) = app.get_webview_window("main") {
                                let _ = window.show();
                                let _ = window.unminimize();
                                let _ = window.set_focus();
                            }
                        }
                        "quit" => {
                            let telem = TunnelTelemetry::global();
                            telem.shutdown_requested.store(true, Ordering::SeqCst);
                            if let Ok(mut g) = state_for_tray.lock() {
                                if let Some(handle) = g.tunnel_thread.take() {
                                    let _ = handle.join();
                                }
                            }
                            crate::client::routing::clean_stale_routes_and_nrpt();
                            app.exit(0);
                        }
                        _ => {}
                    }
                })
                .on_tray_icon_event(|tray, event| {
                    if let TrayIconEvent::Click { button: MouseButton::Left, button_state: MouseButtonState::Up, .. } = event {
                        let app = tray.app_handle();
                        if let Some(window) = app.get_webview_window("main") {
                            let _ = window.show();
                            let _ = window.unminimize();
                            let _ = window.set_focus();
                        }
                    }
                })
                .build(app)?;

            Ok(())
        })
        .run(tauri::generate_context!())
        .map_err(|e| Box::new(e) as Box<dyn Error>)
}
