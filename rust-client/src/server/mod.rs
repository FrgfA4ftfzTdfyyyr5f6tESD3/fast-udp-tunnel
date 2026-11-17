//! Pure Rust Linux TUN Server Module (Commercial Engine v8.5)
//! Features multi-port concurrent binding, dynamic PMTU zero-fragmentation adaptation,
//! persistent multi-user subscriber store (`users.json`), and embedded admin web dashboard.

pub mod admin_web;
pub mod capacity;
pub mod engine;
pub mod network;
pub mod tun;
pub mod tuner;
pub mod users;

use std::error::Error;
use std::net::UdpSocket;
use std::os::unix::io::FromRawFd;
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use crate::common::SERVER_TUN_CEILING_MTU;
pub use self::tuner::OsProfile;
use self::tun::TunDevice;

pub fn run_server(
    primary_port: u16,
    admin_port: u16,
    admin_pass: Option<String>,
    server_v4: Option<String>,
    server_v6: Option<String>,
    default_psk: [u8; 8],
    os_profile: OsProfile,
    provisioned_users: usize,
) -> Result<(), Box<dyn Error>> {
    println!("==================================================================");
    println!("  Morph Core — Ultra-Fast UDP Multi-User Server (Engine v8.5)");
    println!("  Multi-User Architecture | Embedded Admin Dashboard | Multi-Port");
    println!("==================================================================");

    // 1. Automatic OS & Kernel Adaptation & Tuning (Alpine vs Ubuntu/Debian)
    let (_resolved_profile, env) = tuner::apply_pre_tun_tuning(os_profile);

    // 2. Dynamic Capacity & Self-Tuning Resource Scaler
    let (_capacity_mgr, capacity_params) = capacity::CapacityManager::init(provisioned_users, &env);

    // 3. Open TUN Device in standard blocking mode (instant kernel wakeup, 0% idle CPU)
    let tun = Arc::new(TunDevice::create("tun0")?);

    // 4. Configure tun0 network parameters, IP addresses, and routes now that tun0 exists
    tuner::configure_tun_interface();
    println!("[SERVER] Interface: tun0 active (Kernel Ceiling MTU: {}, Dynamic Per-Client Memory MTU Active, txqueuelen: 10000)", SERVER_TUN_CEILING_MTU);

    // Standard ports to bind concurrently across all 16 supported protocols
    let mut candidate_ports = vec![primary_port];
    for &p in crate::common::STANDARD_PORTS {
        if !candidate_ports.contains(&p) {
            candidate_ports.push(p);
        }
    }
    let mut bound_sockets = Vec::new();
    let mut bound_ports = Vec::new();

    // Sizing socket buffer safely according to CapacityManager's calculated boundaries
    let bufsize: i32 = capacity_params.socket_buf_size;

    for &p in &candidate_ports {
        if bound_ports.contains(&p) {
            continue;
        }
        match create_reuseport_listener(p, bufsize) {
            Ok(sock) => {
                bound_sockets.push(Arc::new(sock));
                bound_ports.push(p);
            }
            Err(e) => {
                if p == primary_port {
                    return Err(format!("Failed to bind primary port {}: {}", p, e).into());
                }
                eprintln!("[SERVER] Note: Could not bind optional standard port {} ({})", p, e);
            }
        }
    }

    println!("[SERVER] Active Listening Ports: {:?}", bound_ports);
    println!("[SERVER] Supported Mimic Profiles: [QUIC_V1, QUIC_V2, WEBRTC, DTLS, DNS, ESP, UTP, RAKNET, STUN, TURN, STEAM, SDR, RIOT, ZOOM, RDP, DISCORD]");

    // Initialize Multi-User Store
    let user_mgr = users::UserManager::load_or_init(users::DEFAULT_USERS_FILE, default_psk);
    let subscriber_count = user_mgr.list_user_views().len();
    println!("[SERVER] Multi-User Store Initialized: {} subscribers loaded from '{}'", subscriber_count, users::DEFAULT_USERS_FILE);

    let active_sessions_count = Arc::new(AtomicU32::new(0));
    let total_rx_bytes = Arc::new(AtomicU64::new(0));
    let total_tx_bytes = Arc::new(AtomicU64::new(0));
    let running = Arc::new(AtomicBool::new(true));

    // Launch Embedded Admin Web UI Server
    let admin_cfg = admin_web::AdminServerConfig {
        port: admin_port,
        username: "admin".to_string(),
        password_override: admin_pass,
        server_v4,
        server_v6,
        tunnel_primary_port: primary_port,
    };
    let _admin_handle = admin_web::start_admin_server(
        admin_cfg,
        user_mgr.clone(),
        Arc::clone(&running),
        Arc::clone(&active_sessions_count),
        Arc::clone(&total_rx_bytes),
        Arc::clone(&total_tx_bytes),
    )?;

    let r_sig = Arc::clone(&running);
    let _ = ctrlc::set_handler(move || {
        println!("\n[SERVER] Received shutdown signal. Terminating gracefully...");
        r_sig.store(false, Ordering::SeqCst);
    });

    let engine_res = engine::run_engine(
        bound_sockets,
        tun,
        running,
        user_mgr,
        active_sessions_count,
        total_rx_bytes,
        total_tx_bytes,
    );

    let _ = _admin_handle.join();
    engine_res?;

    println!("[SERVER] Clean exit.");
    Ok(())
}

fn create_reuseport_listener(port: u16, bufsize: i32) -> Result<UdpSocket, Box<dyn Error>> {
    unsafe {
        let fd = libc::socket(libc::AF_INET6, libc::SOCK_DGRAM, 0);
        if fd < 0 {
            return Err("Failed to create listener socket".into());
        }
        let one: libc::c_int = 1;
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEADDR,
            &one as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_REUSEPORT,
            &one as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
        let zero: libc::c_int = 0; // dual-stack
        libc::setsockopt(
            fd,
            libc::IPPROTO_IPV6,
            libc::IPV6_V6ONLY,
            &zero as *const _ as *const libc::c_void,
            std::mem::size_of::<libc::c_int>() as libc::socklen_t,
        );
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVBUF,
            &bufsize as *const _ as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        );
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_SNDBUF,
            &bufsize as *const _ as *const libc::c_void,
            std::mem::size_of::<i32>() as libc::socklen_t,
        );

        let mut sin6: libc::sockaddr_in6 = std::mem::zeroed();
        sin6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
        sin6.sin6_port = port.to_be();
        sin6.sin6_addr = libc::in6addr_any;

        if libc::bind(
            fd,
            &sin6 as *const _ as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
        ) < 0
        {
            libc::close(fd);
            return Err(format!("bind failed for port {}", port).into());
        }

        let sock = UdpSocket::from_raw_fd(fd);
        let _ = sock.set_read_timeout(Some(Duration::from_millis(500)));
        Ok(sock)
    }
}
