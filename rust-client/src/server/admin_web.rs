//! Ultra-Lightweight Embedded Admin Web UI Server (< 200 KB RAM footprint).
//! Protected by multi-level nested secret path anti-scanner cloaking,
//! dual-stack IPv6/IPv4 binding, HTTP Basic Auth, and persistent config (`server_config.json`).

use std::error::Error;
use std::fs;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::path::Path;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};

use crate::common::base64_decode;
use crate::server::users::UserManager;

const ADMIN_HTML: &str = include_str!("web/admin.html");
pub const SERVER_CONFIG_FILE: &str = "server_config.json";

#[derive(Clone, Serialize, Deserialize)]
pub struct PersistedServerConfig {
    pub secret_token: String,
    pub secret_prefix: String,
    pub admin_user: String,
    pub admin_pass: String,
}

pub struct AdminServerConfig {
    pub port: u16,
    pub username: String,
    pub password_override: Option<String>,
    pub server_v4: Option<String>,
    pub server_v6: Option<String>,
    pub tunnel_primary_port: u16,
}

pub fn start_admin_server(
    config: AdminServerConfig,
    user_mgr: UserManager,
    running: Arc<AtomicBool>,
    active_sessions_count: Arc<std::sync::atomic::AtomicU32>,
    total_rx_bytes: Arc<std::sync::atomic::AtomicU64>,
    total_tx_bytes: Arc<std::sync::atomic::AtomicU64>,
) -> Result<thread::JoinHandle<()>, Box<dyn Error>> {
    // 1. Load or Generate Persistent Secret Path and Password
    let persisted_cfg = load_or_init_server_config(&config.password_override)?;

    let secret_prefix = persisted_cfg.secret_prefix.clone();
    let auth_token = format!("{}:{}", persisted_cfg.admin_user, persisted_cfg.admin_pass);

    // 2. Dual-Stack Binding: Bind both IPv6 [::] and IPv4 0.0.0.0 for seamless access
    let mut listeners = Vec::new();
    let v6_addr = format!("[::]:{}", config.port);
    if let Ok(l6) = TcpListener::bind(&v6_addr) {
        let _ = l6.set_nonblocking(true);
        listeners.push(l6);
    }

    let v4_addr = format!("0.0.0.0:{}", config.port);
    if let Ok(l4) = TcpListener::bind(&v4_addr) {
        let _ = l4.set_nonblocking(true);
        listeners.push(l4);
    }

    if listeners.is_empty() {
        return Err(format!("Failed to bind admin dashboard to port {}", config.port).into());
    }

    let console_subpath = format!("{}/console", secret_prefix);
    let v6_display = config.server_v6.as_deref().unwrap_or("[::1]");
    let v4_display = config.server_v4.as_deref().unwrap_or("127.0.0.1");

    println!("==================================================================");
    println!("  MORPH CORE — EDGE MANAGER (ADMIN CONSOLE)");
    println!("  Access URL (IPv6): http://{}:{}{}", v6_display, config.port, console_subpath);
    println!("  Access URL (IPv4): http://{}:{}{}", v4_display, config.port, console_subpath);
    println!("  Username         : {}", persisted_cfg.admin_user);
    println!("  Password         : {}", persisted_cfg.admin_pass);
    println!("  Cloaking Status  : Anti-Scanner Active (All '/' & decoy paths return 404)");
    println!("==================================================================");

    let start_time = Instant::now();

    let handle = thread::Builder::new()
        .name("morph_admin_worker".into())
        .spawn(move || {
            let mut sync_timer = Instant::now();

            while running.load(Ordering::Relaxed) {
                // Periodically flush subscriber traffic to users.json every 30s
                if sync_timer.elapsed().as_secs() >= 30 {
                    let _ = user_mgr.save_to_disk();
                    sync_timer = Instant::now();
                }

                let mut accepted_any = false;

                for listener in &listeners {
                    match listener.accept() {
                        Ok((mut stream, _client_addr)) => {
                            accepted_any = true;
                            let _ = stream.set_nonblocking(false);
                            let _ = stream.set_read_timeout(Some(Duration::from_secs(5)));
                            let _ = stream.set_write_timeout(Some(Duration::from_secs(5)));

                            let mut buf = Vec::with_capacity(8192);
                            let mut temp = [0u8; 4096];
                            let n = match stream.read(&mut temp) {
                                Ok(bytes) => bytes,
                                Err(_) => continue,
                            };
                            if n == 0 {
                                continue;
                            }
                            buf.extend_from_slice(&temp[..n]);

                            // Check Content-Length for complete HTTP body retrieval
                            let req_head = String::from_utf8_lossy(&buf);
                            let mut content_len = 0usize;
                            for line in req_head.lines() {
                                if line.to_ascii_lowercase().starts_with("content-length:") {
                                    if let Some(val) = line.split(':').nth(1) {
                                        content_len = val.trim().parse().unwrap_or(0);
                                    }
                                }
                            }

                            let header_end = req_head.find("\r\n\r\n").map(|p| p + 4)
                                .or_else(|| req_head.find("\n\n").map(|p| p + 2));

                            if let Some(pos) = header_end {
                                let mut body_read = buf.len().saturating_sub(pos);
                                while body_read < content_len && buf.len() < 128 * 1024 {
                                    match stream.read(&mut temp) {
                                        Ok(bytes) if bytes > 0 => {
                                            buf.extend_from_slice(&temp[..bytes]);
                                            body_read += bytes;
                                        }
                                        _ => break,
                                    }
                                }
                            }

                            let req_str = String::from_utf8_lossy(&buf);
                            let (method, path, auth_header, body) = parse_http_request(&req_str);

                            // Anti-Scanner Cloak: If path does not start with secret prefix, silently return 404
                            if !path.starts_with(&secret_prefix) {
                                send_404(&mut stream);
                                continue;
                            }

                            // Enforce Basic Authentication on secret console path
                            if !is_authorized(&auth_header, &auth_token) {
                                send_unauthorized(&mut stream);
                                continue;
                            }

                            // Dispatch Routes under secret prefix
                            handle_route(
                                &mut stream,
                                &method,
                                &path,
                                &secret_prefix,
                                &body,
                                &config,
                                &user_mgr,
                                &start_time,
                                &active_sessions_count,
                                &total_rx_bytes,
                                &total_tx_bytes,
                            );
                        }
                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                        Err(_) => {}
                    }
                }

                if !accepted_any {
                    thread::sleep(Duration::from_millis(40));
                }
            }

            println!("[ADMIN-WEB] Flushing user database and terminating admin thread...");
            let _ = user_mgr.save_to_disk();
        })?;

    Ok(handle)
}

fn load_or_init_server_config(password_override: &Option<String>) -> Result<PersistedServerConfig, Box<dyn Error>> {
    let path = Path::new(SERVER_CONFIG_FILE);
    if path.exists() {
        if let Ok(content) = fs::read_to_string(path) {
            if let Ok(mut cfg) = serde_json::from_str::<PersistedServerConfig>(&content) {
                if let Some(ref pass) = password_override {
                    cfg.admin_pass = pass.clone();
                    let _ = fs::write(path, serde_json::to_string_pretty(&cfg)?);
                }
                return Ok(cfg);
            }
        }
    }

    // Generate cryptographically secure random secret token and password
    let mut rand_bytes = [0u8; 16];
    crate::server::users::secure_random_bytes(&mut rand_bytes);
    let secret_token = format!("{:02x}{:02x}{:02x}{:02x}", rand_bytes[0], rand_bytes[1], rand_bytes[2], rand_bytes[3]);
    let secret_prefix = format!("/v2/sys/telemetry/node-{}/auth", secret_token);

    let admin_pass = if let Some(ref pass) = password_override {
        pass.clone()
    } else {
        format!("morph_{:02x}{:02x}{:02x}{:02x}{:02x}{:02x}", rand_bytes[4], rand_bytes[5], rand_bytes[6], rand_bytes[7], rand_bytes[8], rand_bytes[9])
    };

    let cfg = PersistedServerConfig {
        secret_token,
        secret_prefix,
        admin_user: "admin".to_string(),
        admin_pass,
    };

    let json = serde_json::to_string_pretty(&cfg)?;
    let _ = fs::write(path, json);

    Ok(cfg)
}

fn parse_http_request<'a>(raw: &'a str) -> (String, String, Option<String>, String) {
    let mut lines = raw.lines();
    let first_line = lines.next().unwrap_or("");
    let mut parts = first_line.split_whitespace();
    let method = parts.next().unwrap_or("GET").to_string();
    let path = parts.next().unwrap_or("/").to_string();

    let mut auth_header = None;
    for line in lines.by_ref() {
        if line.is_empty() || line == "\r" {
            break;
        }
        if line.to_ascii_lowercase().starts_with("authorization: basic ") {
            auth_header = Some(line[21..].trim().to_string());
        }
    }

    let body = if let Some(pos) = raw.find("\r\n\r\n") {
        raw[pos + 4..].to_string()
    } else if let Some(pos) = raw.find("\n\n") {
        raw[pos + 2..].to_string()
    } else {
        String::new()
    };

    (method, path, auth_header, body)
}

fn is_authorized(auth_header: &Option<String>, expected_pair: &str) -> bool {
    let b64 = match auth_header {
        Some(h) => h,
        None => return false,
    };

    if let Some(decoded) = base64_decode(b64) {
        if let Ok(s) = String::from_utf8(decoded) {
            return s == expected_pair;
        }
    }
    false
}

fn send_404(stream: &mut TcpStream) {
    let resp = "HTTP/1.1 404 Not Found\r\n\
                Content-Type: text/plain; charset=utf-8\r\n\
                Content-Length: 13\r\n\
                Connection: close\r\n\r\n\
                404 Not Found";
    let _ = stream.write_all(resp.as_bytes());
    let _ = stream.flush();
}

fn send_unauthorized(stream: &mut TcpStream) {
    let resp = "HTTP/1.1 401 Unauthorized\r\n\
                WWW-Authenticate: Basic realm=\"Morph Edge Manager\"\r\n\
                Content-Type: text/html; charset=utf-8\r\n\
                Content-Length: 68\r\n\
                Connection: close\r\n\r\n\
                <html><body><h1>401 Unauthorized - Morph Edge Console</h1></body></html>";
    let _ = stream.write_all(resp.as_bytes());
    let _ = stream.flush();
}

fn send_json(stream: &mut TcpStream, status_code: u16, json: &serde_json::Value) {
    let body = json.to_string();
    let resp = format!(
        "HTTP/1.1 {} OK\r\n\
         Content-Type: application/json\r\n\
         Content-Length: {}\r\n\
         Access-Control-Allow-Origin: *\r\n\
         Connection: close\r\n\r\n\
         {}",
        status_code,
        body.len(),
        body
    );
    let _ = stream.write_all(resp.as_bytes());
    let _ = stream.flush();
}

fn send_html(stream: &mut TcpStream, html: &str) {
    let resp = format!(
        "HTTP/1.1 200 OK\r\n\
         Content-Type: text/html; charset=utf-8\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n\
         {}",
        html.len(),
        html
    );
    let _ = stream.write_all(resp.as_bytes());
    let _ = stream.flush();
}

fn send_error(stream: &mut TcpStream, status_code: u16, msg: &str) {
    let resp = format!(
        "HTTP/1.1 {} Error\r\n\
         Content-Type: text/plain\r\n\
         Content-Length: {}\r\n\
         Connection: close\r\n\r\n\
         {}",
        status_code,
        msg.len(),
        msg
    );
    let _ = stream.write_all(resp.as_bytes());
    let _ = stream.flush();
}

fn handle_route(
    stream: &mut TcpStream,
    method: &str,
    full_path: &str,
    secret_prefix: &str,
    body: &str,
    config: &AdminServerConfig,
    user_mgr: &UserManager,
    start_time: &Instant,
    active_sessions: &Arc<std::sync::atomic::AtomicU32>,
    total_rx_bytes: &Arc<std::sync::atomic::AtomicU64>,
    total_tx_bytes: &Arc<std::sync::atomic::AtomicU64>,
) {
    // Relative path inside secret prefix
    let subpath = if full_path.len() >= secret_prefix.len() {
        &full_path[secret_prefix.len()..]
    } else {
        "/"
    };

    match (method, subpath) {
        ("GET", "") | ("GET", "/") | ("GET", "/console") | ("GET", "/console/") => {
            send_html(stream, ADMIN_HTML);
        }
        ("GET", "/api/status") => {
            let uptime_secs = start_time.elapsed().as_secs();
            let sessions = active_sessions.load(Ordering::Relaxed);
            let rx = total_rx_bytes.load(Ordering::Relaxed);
            let tx = total_tx_bytes.load(Ordering::Relaxed);
            let users_count = user_mgr.list_user_views().len();
            let (ram_used_mb, ram_total_mb) = get_linux_ram_usage_mb();

            let json = serde_json::json!({
                "online": true,
                "uptime_secs": uptime_secs,
                "active_sessions": sessions,
                "total_users": users_count,
                "total_rx_bytes": rx,
                "total_tx_bytes": tx,
                "total_traffic_bytes": rx + tx,
                "ram_used_mb": ram_used_mb,
                "ram_total_mb": ram_total_mb,
            });
            send_json(stream, 200, &json);
        }
        ("GET", "/api/users") => {
            let views = user_mgr.list_user_views();
            send_json(stream, 200, &serde_json::Value::Array(views));
        }
        ("POST", "/api/users") => {
            fn default_one_u32() -> u32 { 1 }

            #[derive(Deserialize)]
            struct CreateUserPayload {
                name: String,
                #[serde(default)]
                days: u64,
                #[serde(default)]
                quota_gb: u64,
                #[serde(default)]
                speed_mbps: u64,
                #[serde(default)]
                profile_id: u8,
                #[serde(default = "default_one_u32")]
                max_connections: u32,
            }

            if let Ok(req) = serde_json::from_str::<CreateUserPayload>(body) {
                let max_conn = req.max_connections.clamp(1, 3);
                match user_mgr.create_user(
                    &req.name,
                    req.days,
                    req.quota_gb,
                    req.speed_mbps,
                    req.profile_id,
                    max_conn,
                    config.server_v4.clone(),
                    config.server_v6.clone(),
                    config.tunnel_primary_port,
                ) {
                    Ok((record, token_uri)) => {
                        let json = serde_json::json!({
                            "user": record,
                            "token_uri": token_uri,
                        });
                        send_json(stream, 200, &json);
                    }
                    Err(e) => send_error(stream, 400, &e),
                }
            } else {
                send_error(stream, 400, "Invalid JSON payload for user creation");
            }
        }
        ("POST", p) if p.starts_with("/api/users/") && p.ends_with("/toggle") => {
            let parts: Vec<&str> = p.split('/').collect();
            if parts.len() >= 4 {
                let user_id = parts[3];
                match user_mgr.toggle_user(user_id) {
                    Ok(new_status) => {
                        send_json(stream, 200, &serde_json::json!({ "enabled": new_status }));
                    }
                    Err(e) => send_error(stream, 404, &e),
                }
            } else {
                send_error(stream, 400, "Malformed URL");
            }
        }
        ("POST", p) if p.starts_with("/api/users/") && p.ends_with("/update") => {
            let parts: Vec<&str> = p.split('/').collect();
            if parts.len() >= 4 {
                let user_id = parts[3];
                #[derive(Deserialize)]
                struct UpdateUserPayload {
                    name: Option<String>,
                    days_from_now: Option<u64>,
                    add_quota_gb: Option<u64>,
                    set_quota_gb: Option<u64>,
                    speed_mbps: Option<u64>,
                    max_connections: Option<u32>,
                    enabled: Option<bool>,
                    reset_traffic: Option<bool>,
                }
                if let Ok(req) = serde_json::from_str::<UpdateUserPayload>(body) {
                    let max_conn_opt = req.max_connections.map(|c| c.clamp(1, 3));
                    match user_mgr.update_user(
                        user_id,
                        req.name,
                        req.days_from_now,
                        req.add_quota_gb,
                        req.set_quota_gb,
                        req.speed_mbps,
                        max_conn_opt,
                        req.enabled,
                        req.reset_traffic.unwrap_or(false),
                    ) {
                        Ok(rec) => send_json(stream, 200, &serde_json::to_value(&rec).unwrap_or_default()),
                        Err(e) => send_error(stream, 404, &e),
                    }
                } else {
                    send_error(stream, 400, "Invalid JSON payload");
                }
            } else {
                send_error(stream, 400, "Malformed URL");
            }
        }
        ("POST", p) if p.starts_with("/api/users/") && p.ends_with("/extend") => {
            let parts: Vec<&str> = p.split('/').collect();
            if parts.len() >= 4 {
                let user_id = parts[3];
                #[derive(Deserialize)]
                struct ExtendPayload {
                    days: u64,
                    quota_gb: u64,
                }
                if let Ok(req) = serde_json::from_str::<ExtendPayload>(body) {
                    match user_mgr.extend_user(user_id, req.days, req.quota_gb) {
                        Ok(()) => send_json(stream, 200, &serde_json::json!({ "success": true })),
                        Err(e) => send_error(stream, 404, &e),
                    }
                } else {
                    send_error(stream, 400, "Invalid JSON payload");
                }
            } else {
                send_error(stream, 400, "Malformed URL");
            }
        }
        ("GET", p) if p.starts_with("/api/users/") && p.ends_with("/token") => {
            let parts: Vec<&str> = p.split('/').collect();
            if parts.len() >= 4 {
                let user_id = parts[3];
                match user_mgr.get_token_uri(
                    user_id,
                    config.server_v4.clone(),
                    config.server_v6.clone(),
                    config.tunnel_primary_port,
                ) {
                    Ok(token_uri) => {
                        send_json(stream, 200, &serde_json::json!({ "token_uri": token_uri }));
                    }
                    Err(e) => send_error(stream, 404, &e),
                }
            } else {
                send_error(stream, 400, "Malformed URL");
            }
        }
        ("DELETE", p) if p.starts_with("/api/users/") => {
            let parts: Vec<&str> = p.split('/').collect();
            if parts.len() >= 4 {
                let user_id = parts[3];
                match user_mgr.delete_user(user_id) {
                    Ok(()) => send_json(stream, 200, &serde_json::json!({ "deleted": true })),
                    Err(e) => send_error(stream, 404, &e),
                }
            } else {
                send_error(stream, 400, "Malformed URL");
            }
        }
        _ => {
            send_404(stream);
        }
    }
}

fn get_linux_ram_usage_mb() -> (u64, u64) {
    #[cfg(target_os = "linux")]
    {
        if let Ok(content) = std::fs::read_to_string("/proc/meminfo") {
            let mut total = 0u64;
            let mut available = 0u64;
            for line in content.lines() {
                if line.starts_with("MemTotal:") {
                    total = parse_meminfo_kb(line);
                } else if line.starts_with("MemAvailable:") {
                    available = parse_meminfo_kb(line);
                }
            }
            let total_mb = total / 1024;
            let used_mb = if total > available {
                (total - available) / 1024
            } else {
                0
            };
            return (used_mb, total_mb);
        }
    }
    (0, 0)
}

#[cfg(target_os = "linux")]
fn parse_meminfo_kb(line: &str) -> u64 {
    let mut parts = line.split_whitespace();
    let _ = parts.next();
    parts.next().and_then(|v| v.parse::<u64>().ok()).unwrap_or(0)
}
