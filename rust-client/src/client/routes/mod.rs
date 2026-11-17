//! Modular Compile-Time Split Routing Engine.
//! Uses `include_str!` to hardcode categorized IP CIDR prefixes directly into the client binary
//! at compile-time. Users cannot modify or tamper with routes, while developers can easily
//! add new service categories by placing a new .txt file in this directory and registering it.

use std::fs;
use std::process::Command;

/// Metadata and raw CIDR data for a categorized service route block
pub struct RouteCategory {
    pub name: &'static str,
    pub raw_data: &'static str,
}

// -----------------------------------------------------------------------------
// Compile-Time Embedded Category Files
// -----------------------------------------------------------------------------
pub const GOOGLE_SERVICES_RAW: &str = include_str!("google_services.txt");
pub const LEAK_TEST_SERVICES_RAW: &str = include_str!("leak_test_services.txt");
pub const SOCIAL_AND_CDN_SERVICES_RAW: &str = include_str!("social_and_cdn_services.txt");

/// Active route categories compiled directly into the binary.
/// To add a new service (e.g. Cloudflare, Telegram), create a `<service>_services.txt`
/// file, include it above via `include_str!`, and add an entry here.
pub const ACTIVE_ROUTE_CATEGORIES: &[RouteCategory] = &[
    RouteCategory {
        name: "Google Services & YouTube",
        raw_data: GOOGLE_SERVICES_RAW,
    },
    RouteCategory {
        name: "Diagnostic & Leak Test Services",
        raw_data: LEAK_TEST_SERVICES_RAW,
    },
    RouteCategory {
        name: "Global CDN, Messaging & Social (Cloudflare, Telegram, Meta, X)",
        raw_data: SOCIAL_AND_CDN_SERVICES_RAW,
    },
];

/// Parse all active categories and return clean lists of (IPv4 prefixes, IPv6 prefixes)
pub fn parse_all_active_routes() -> (Vec<String>, Vec<String>) {
    let mut v4_routes = Vec::with_capacity(256);
    let mut v6_routes = Vec::with_capacity(64);

    for category in ACTIVE_ROUTE_CATEGORIES {
        for line in category.raw_data.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            if trimmed.contains(':') {
                v6_routes.push(trimmed.to_string());
            } else if trimmed.contains('.') {
                v4_routes.push(trimmed.to_string());
            }
        }
    }

    (v4_routes, v6_routes)
}

/// Ultra-Fast Batch Application of Categorized Split Routes & DNS to Wintun interface (< 200 ms).
/// Generates a single consolidated netsh script and executes it in one single process call.
pub fn apply_all_routes(wintun_if_index: u32) -> (usize, usize) {
    let (v4_prefixes, v6_prefixes) = parse_all_active_routes();
    let mut script = String::with_capacity(32768);

    // 1. Injected IPv4 Prefixes
    for prefix in &v4_prefixes {
        script.push_str(&format!(
            "interface ipv4 add route {} interface={} nexthop=10.8.0.1 metric=2 store=active\n",
            prefix, wintun_if_index
        ));
    }

    // 2. Injected IPv6 Prefixes
    for prefix in &v6_prefixes {
        script.push_str(&format!(
            "interface ipv6 add route {} interface={} nexthop=fd00:8::1 metric=2 store=active\n",
            prefix, wintun_if_index
        ));
    }

    let temp_script_path = std::env::temp_dir().join("morph_split_routes_add.txt");
    if fs::write(&temp_script_path, script.as_bytes()).is_ok() {
        let _ = Command::new("netsh")
            .args(["-f", temp_script_path.to_str().unwrap_or_default()])
            .output();
        let _ = fs::remove_file(&temp_script_path);
    }

    (v4_prefixes.len(), v6_prefixes.len())
}

/// Ultra-Fast Clean Deletion of Categorized Split Routes from Wintun interface on exit (< 200 ms).
pub fn restore_all_routes(wintun_if_index: u32) -> (usize, usize) {
    let (v4_prefixes, v6_prefixes) = parse_all_active_routes();
    let mut script = String::with_capacity(32768);

    for prefix in &v4_prefixes {
        script.push_str(&format!(
            "interface ipv4 delete route {} interface={} nexthop=10.8.0.1 store=active\n",
            prefix, wintun_if_index
        ));
    }

    for prefix in &v6_prefixes {
        script.push_str(&format!(
            "interface ipv6 delete route {} interface={} nexthop=fd00:8::1 store=active\n",
            prefix, wintun_if_index
        ));
    }

    let temp_script_path = std::env::temp_dir().join("morph_split_routes_del.txt");
    if fs::write(&temp_script_path, script.as_bytes()).is_ok() {
        let _ = Command::new("netsh")
            .args(["-f", temp_script_path.to_str().unwrap_or_default()])
            .output();
        let _ = fs::remove_file(&temp_script_path);
    }

    (v4_prefixes.len(), v6_prefixes.len())
}
