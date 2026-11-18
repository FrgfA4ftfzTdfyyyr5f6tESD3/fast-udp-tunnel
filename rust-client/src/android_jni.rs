#![cfg(target_os = "android")]
//! JNI Bridge for Android (`com.morphcore.vpn.MorphNative`) -> `libmorph_core.so`.
//! Exposes a minimal, panic-safe native interface for Android `VpnService` and Jetpack Compose UI.

use jni::objects::{JClass, JString};
use jni::sys::{jboolean, jint, jlongArray, jstring, JNI_FALSE, JNI_TRUE};
use jni::JNIEnv;

use crate::client::android_engine;

fn extract_optional_string<'local>(
    env: &mut JNIEnv<'local>,
    input: &JString<'local>,
) -> Option<String> {
    if input.is_null() {
        return None;
    }
    env.get_string(input)
        .ok()
        .map(|s| s.into())
        .filter(|s: &String| !s.trim().is_empty())
}

/// Kotlin signature:
/// `external fun prepareSocket(token: String, mimicOverride: String?, payloadModeOverride: String?): Int`
///
/// Parses the `morph://` subscription token and optional overrides, creates and connects the UDP socket,
/// stores session state, and returns the raw `udp_socket_fd` (or `-1` on error) so Android can immediately
/// call `vpnService.protect(udpFd)` before any packet is transmitted.
#[no_mangle]
pub extern "system" fn Java_com_morphcore_vpn_MorphNative_prepareSocket<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    token: JString<'local>,
    mimic_override: JString<'local>,
    payload_mode_override: JString<'local>,
) -> jint {
    let token_str = match extract_optional_string(&mut env, &token) {
        Some(s) => s,
        None => return -1,
    };

    let mimic_opt = extract_optional_string(&mut env, &mimic_override);
    let mode_opt = extract_optional_string(&mut env, &payload_mode_override);

    match android_engine::prepare_socket(&token_str, mimic_opt.as_deref(), mode_opt.as_deref()) {
        Ok(fd) => fd as jint,
        Err(_) => -1,
    }
}

/// Kotlin signature:
/// `external fun prepareSocketEx(token: String, mimicOverride: String?, payloadModeOverride: String?, transportOverride: String?, portOverride: Int): Int`
///
/// Extended socket preparation supporting transport preference (`"auto"`, `"ipv6"`, `"ipv4"`)
/// and custom port override (`0` = use token default).
#[no_mangle]
pub extern "system" fn Java_com_morphcore_vpn_MorphNative_prepareSocketEx<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    token: JString<'local>,
    mimic_override: JString<'local>,
    payload_mode_override: JString<'local>,
    transport_override: JString<'local>,
    port_override: jint,
) -> jint {
    let token_str = match extract_optional_string(&mut env, &token) {
        Some(s) => s,
        None => return -1,
    };

    let mimic_opt = extract_optional_string(&mut env, &mimic_override);
    let mode_opt = extract_optional_string(&mut env, &payload_mode_override);
    let transport_opt = extract_optional_string(&mut env, &transport_override);
    let port_u16 = if (1..=65535).contains(&port_override) {
        port_override as u16
    } else {
        0
    };

    match android_engine::prepare_socket_ex(
        &token_str,
        mimic_opt.as_deref(),
        mode_opt.as_deref(),
        transport_opt.as_deref(),
        port_u16,
    ) {
        Ok(fd) => fd as jint,
        Err(_) => -1,
    }
}

/// Kotlin signature:
/// `external fun startTunnel(tunFd: Int): Boolean`
///
/// Launches background full-duplex Rust worker threads bridging Android's VpnService `tunFd`
/// to the protected UDP socket. Rust never closes `tunFd`.
#[no_mangle]
pub extern "system" fn Java_com_morphcore_vpn_MorphNative_startTunnel<'local>(
    _env: JNIEnv<'local>,
    _class: JClass<'local>,
    tun_fd: jint,
) -> jboolean {
    match android_engine::start_tunnel(tun_fd) {
        Ok(()) => JNI_TRUE,
        Err(_) => JNI_FALSE,
    }
}

/// Kotlin signature:
/// `external fun stopTunnel()`
///
/// Gracefully signals shutdown and joins all background tunnel worker threads.
#[no_mangle]
pub extern "system" fn Java_com_morphcore_vpn_MorphNative_stopTunnel<'local>(
    _env: JNIEnv<'local>,
    _class: JClass<'local>,
) {
    android_engine::stop_tunnel();
}

/// Kotlin signature:
/// `external fun getTelemetry(): LongArray`
///
/// Returns a 5-element `LongArray`: `[rx_bytes, tx_bytes, rx_packets, tx_packets, rtt_ms]`.
#[no_mangle]
pub extern "system" fn Java_com_morphcore_vpn_MorphNative_getTelemetry<'local>(
    env: JNIEnv<'local>,
    _class: JClass<'local>,
) -> jlongArray {
    let stats = android_engine::get_telemetry();
    match env.new_long_array(5) {
        Ok(arr) => {
            if env.set_long_array_region(&arr, 0, &stats).is_ok() {
                arr.into_raw()
            } else {
                std::ptr::null_mut()
            }
        }
        Err(_) => std::ptr::null_mut(),
    }
}

/// Kotlin signature (helper for VpnService.Builder & UI profile display):
/// `external fun decodeTokenInfo(token: String): String`
///
/// Decrypts a `morph://` subscription token and returns a JSON string with `assigned_ipv4`,
/// `assigned_ipv6`, `name`, `user_id`, `profile`, `payload_mode`, `port`, `quota_bytes`, `expires_at`
/// (or empty string `""` if invalid).
#[no_mangle]
pub extern "system" fn Java_com_morphcore_vpn_MorphNative_decodeTokenInfo<'local>(
    mut env: JNIEnv<'local>,
    _class: JClass<'local>,
    token: JString<'local>,
) -> jstring {
    let json = extract_optional_string(&mut env, &token)
        .and_then(|t| android_engine::decode_token_json(&t).ok())
        .unwrap_or_default();

    match env.new_string(json) {
        Ok(s) => s.into_raw(),
        Err(_) => std::ptr::null_mut(),
    }
}
