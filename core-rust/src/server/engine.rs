//! Linux server forwarding engine with multi-user authentication,
//! dynamic PMTU negotiation, multi-port concurrent sockets, quota enforcement, and zero-leak session pruning.
//! Implements Two-Stage Connected UDP (Cloudflare/QUIC Demuxing):
//! Unconnected listener socket on candidate ports + Immediate upgrade to dedicated Connected UDP socket
//! with kernel FIB routing bypass (`sk_dst_cache`) upon authentication.

use std::collections::HashMap;
use std::error::Error;
use std::net::{IpAddr, SocketAddr, UdpSocket};
use std::os::unix::io::{AsRawFd, FromRawFd};
use std::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, RwLock};
use std::thread;
use std::time::Instant;

use crate::common::{
    parse_ip_destination, parse_ip_source, ReassemblyBuffer, FLAG_DATA, FLAG_FRAG_1,
    FLAG_FRAG_2, FLAG_FRAME_MASK, FLAG_KEEPALIVE, FLAG_KEEPALIVE_ACK, MAX_PINNED_SESSIONS,
    MIMICRY_HEADER_LEN, SESSION_IDLE_TIMEOUT_SECS,
};
use crate::core::crypto::{apply_payload_shaping, strip_payload_shaping, PayloadMode};
use crate::mimic::{auto_detect_and_unwrap, port_hint_and_auto_detect, MimicProfile};
use crate::server::tun::TunDevice;
use crate::server::users::UserManager;

fn current_epoch_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

#[derive(Clone)]
pub struct ClientSession {
    pub addr: SocketAddr,
    pub profile: MimicProfile,
    pub mode: PayloadMode,
    pub socket: Arc<UdpSocket>,
    pub last_seen: Arc<AtomicU64>,
    pub mtu: Arc<AtomicU32>,
    pub user_id: String,
    pub psk: [u8; 8],
}

#[derive(Clone)]
struct PinnedEntry {
    profile: MimicProfile,
    mode: PayloadMode,
    last_seen: Instant,
    user_id: String,
    psk: [u8; 8],
}

#[derive(Clone)]
struct ConnectedSocketEntry {
    socket: Arc<UdpSocket>,
    user_id: String,
    psk: [u8; 8],
    profile: MimicProfile,
    mode: PayloadMode,
    client_addr: SocketAddr,
    last_seen: Arc<RwLock<Instant>>,
}

pub fn run_engine(
    sockets: Vec<Arc<UdpSocket>>,
    tun: Arc<TunDevice>,
    running: Arc<AtomicBool>,
    user_mgr: UserManager,
    active_sessions_count: Arc<AtomicU32>,
    total_rx_bytes: Arc<AtomicU64>,
    total_tx_bytes: Arc<AtomicU64>,
) -> Result<(), Box<dyn Error>> {
    let client_session: Arc<RwLock<Option<ClientSession>>> = Arc::new(RwLock::new(None));
    let session_cache: Arc<RwLock<HashMap<SocketAddr, PinnedEntry>>> = Arc::new(RwLock::new(HashMap::new()));
    let ip_routing_table: Arc<RwLock<HashMap<IpAddr, ClientSession>>> = Arc::new(RwLock::new(HashMap::new()));

    // Dynamic Core-Aware Connected Socket Sharding (Partitioned Worker Pool)
    let num_workers = std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1);
    println!(
        "[SERVER] CPU Topology Detected: {} core(s) | Spawning {} sharded Connected UDP worker thread(s) (Least-Loaded assignment)",
        num_workers, num_workers
    );

    let mut worker_registries: Vec<Arc<RwLock<HashMap<SocketAddr, ConnectedSocketEntry>>>> = Vec::with_capacity(num_workers);
    for _ in 0..num_workers {
        worker_registries.push(Arc::new(RwLock::new(HashMap::new())));
    }
    let socket_to_worker: Arc<RwLock<HashMap<SocketAddr, usize>>> = Arc::new(RwLock::new(HashMap::new()));
    let seq_counter = Arc::new(AtomicU32::new(1));
    let active_mtu = Arc::new(AtomicU32::new(crate::common::TUNNEL_MTU));

    // Launch a concurrent receiver thread for each bound listener UDP socket (Stage 1: Handshake Listener)
    let mut rx_handles = Vec::new();

    for sock in sockets {
        let sock_rx = Arc::clone(&sock);
        let tun_rx = Arc::clone(&tun);
        let session_rx = Arc::clone(&client_session);
        let cache_rx = Arc::clone(&session_cache);
        let ip_table_rx = Arc::clone(&ip_routing_table);
        let worker_registries_rx = worker_registries.clone();
        let socket_to_worker_rx = Arc::clone(&socket_to_worker);
        let run_rx = Arc::clone(&running);
        let mtu_rx = Arc::clone(&active_mtu);
        let user_mgr_rx = user_mgr.clone();
        let total_rx_rx = Arc::clone(&total_rx_bytes);
        let active_cnt_rx = Arc::clone(&active_sessions_count);

        let local_port = sock.local_addr().map(|a| a.port()).unwrap_or(0);
        let handle = thread::Builder::new()
            .name(format!("udp_rx_{}", local_port))
            .spawn(move || {
                let mut buf = [0u8; 65536];
                let mut reasm: Option<Box<ReassemblyBuffer>> = None;
                let mut reasm_out = [0u8; 2048];
                while run_rx.load(Ordering::Relaxed) {
                    match sock_rx.recv_from(&mut buf) {
                        Ok((n, src_addr)) if n >= MIMICRY_HEADER_LEN => {
                            let now = Instant::now();

                            // Step 1: Session Pinning Fast-Path
                            let pinned_hint = if let Ok(cache) = cache_rx.read() {
                                cache.get(&src_addr).cloned()
                            } else {
                                None
                            };

                            let (profile, flags, seq, user_id, psk) = if let Some(ref pinned_entry) = pinned_hint {
                                if let Some((f, s)) = pinned_entry.profile.unwrap_header(&buf[..n], &pinned_entry.psk) {
                                    if pinned_entry.last_seen.elapsed().as_secs() >= 5 {
                                        if let Ok(mut cache_w) = cache_rx.write() {
                                            if let Some(entry) = cache_w.get_mut(&src_addr) {
                                                entry.last_seen = now;
                                            }
                                        }
                                        if let Ok(s2w) = socket_to_worker_rx.read() {
                                            if let Some(&w_idx) = s2w.get(&src_addr) {
                                                if let Some(w_reg) = worker_registries_rx.get(w_idx) {
                                                    if let Ok(reg_r) = w_reg.read() {
                                                        if let Some(entry) = reg_r.get(&src_addr) {
                                                            if let Ok(mut ls) = entry.last_seen.write() {
                                                                *ls = now;
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        }
                                    }
                                    (pinned_entry.profile, f, s, pinned_entry.user_id.clone(), pinned_entry.psk)
                                } else {
                                    match detect_any_user(&buf[..n], local_port, &user_mgr_rx) {
                                        Some(val) => val,
                                        None => continue,
                                    }
                                }
                            } else {
                                match detect_any_user(&buf[..n], local_port, &user_mgr_rx) {
                                    Some(val) => val,
                                    None => continue,
                                }
                            };

                            // Step 2: Validate User Subscription Status
                            let user_rec = match user_mgr_rx.authenticate_psk(&psk) {
                                Some(rec) => rec,
                                None => continue,
                            };

                            total_rx_rx.fetch_add(n as u64, Ordering::Relaxed);

                            let mode = PayloadMode::from_flags(flags);

                            // Step 3: Upgrade to Connected UDP Socket (Stage 2)
                            let need_repin = match pinned_hint {
                                Some(ref entry) => entry.profile != profile || entry.mode != mode,
                                None => true,
                            };

                            let active_socket = if need_repin {
                                if let Some(evicted_addr) = user_mgr_rx.register_active_session(&user_id, src_addr) {
                                    if let Ok(mut cache_w) = cache_rx.write() {
                                        cache_w.remove(&evicted_addr);
                                    }
                                    if let Ok(mut ip_w) = ip_table_rx.write() {
                                        ip_w.retain(|_, s| s.addr != evicted_addr);
                                    }
                                    if let Ok(mut s2w) = socket_to_worker_rx.write() {
                                        if let Some(w_idx) = s2w.remove(&evicted_addr) {
                                            if let Some(w_reg) = worker_registries_rx.get(w_idx) {
                                                if let Ok(mut reg_w) = w_reg.write() {
                                                    reg_w.remove(&evicted_addr);
                                                }
                                            }
                                        }
                                    }
                                    println!(
                                        "[SERVER] Handover: Evicted older socket {} for subscriber '{}'",
                                        evicted_addr, user_rec.name
                                    );
                                }

                                if let Ok(mut cache_w) = cache_rx.write() {
                                    if cache_w.len() >= MAX_PINNED_SESSIONS {
                                        cache_w.retain(|_, v| v.last_seen.elapsed().as_secs() < SESSION_IDLE_TIMEOUT_SECS);
                                        for reg in worker_registries_rx.iter() {
                                            if let Ok(mut reg_w) = reg.write() {
                                                reg_w.retain(|_, v| v.last_seen.read().map(|t| t.elapsed().as_secs() < SESSION_IDLE_TIMEOUT_SECS).unwrap_or(false));
                                            }
                                        }
                                    }
                                    cache_w.insert(
                                        src_addr,
                                        PinnedEntry {
                                            profile,
                                            mode,
                                            last_seen: now,
                                            user_id: user_id.clone(),
                                            psk,
                                        },
                                    );
                                    active_cnt_rx.store(cache_w.len() as u32, Ordering::Relaxed);
                                }

                                // Create or Lock Connected UDP Socket directly to client
                                let connected_sock = match create_connected_socket(local_port, src_addr, 2 * 1024 * 1024) {
                                    Ok(s) => Arc::new(s),
                                    Err(e) => {
                                        eprintln!("[SERVER] Note: Could not create connected socket for {}: {} (fallback to listener)", src_addr, e);
                                        Arc::clone(&sock_rx)
                                    }
                                };

                                // Assign to Least-Loaded Worker
                                let mut min_load = usize::MAX;
                                let mut chosen_worker = 0;
                                for (idx, reg) in worker_registries_rx.iter().enumerate() {
                                    let load = reg.read().map(|r| r.len()).unwrap_or(0);
                                    if load < min_load {
                                        min_load = load;
                                        chosen_worker = idx;
                                    }
                                }

                                if let Ok(mut s2w) = socket_to_worker_rx.write() {
                                    if let Some(old_worker) = s2w.insert(src_addr, chosen_worker) {
                                        if old_worker != chosen_worker {
                                            if let Some(w_reg) = worker_registries_rx.get(old_worker) {
                                                if let Ok(mut reg_w) = w_reg.write() {
                                                    reg_w.remove(&src_addr);
                                                }
                                            }
                                        }
                                    }
                                }

                                if let Some(w_reg) = worker_registries_rx.get(chosen_worker) {
                                    if let Ok(mut reg_w) = w_reg.write() {
                                        reg_w.insert(
                                            src_addr,
                                            ConnectedSocketEntry {
                                                socket: Arc::clone(&connected_sock),
                                                user_id: user_id.clone(),
                                                psk,
                                                profile,
                                                mode,
                                                client_addr: src_addr,
                                                last_seen: Arc::new(RwLock::new(now)),
                                            },
                                        );
                                    }
                                }

                                if let Ok(mut ip_w) = ip_table_rx.write() {
                                    for (_, s) in ip_w.iter_mut() {
                                        if s.user_id == user_id {
                                            s.addr = src_addr;
                                            s.profile = profile;
                                            s.mode = mode;
                                            s.socket = Arc::clone(&connected_sock);
                                            s.psk = psk;
                                        }
                                    }
                                }

                                if let Ok(mut sess_w) = session_rx.write() {
                                    *sess_w = Some(ClientSession {
                                        addr: src_addr,
                                        profile,
                                        mode,
                                        socket: Arc::clone(&connected_sock),
                                        last_seen: Arc::new(AtomicU64::new(current_epoch_secs())),
                                        mtu: Arc::new(AtomicU32::new(mtu_rx.load(Ordering::Relaxed))),
                                        user_id: user_id.clone(),
                                        psk,
                                    });
                                    println!(
                                        "[SERVER] Subscriber '{}' (ID: {}) Authenticated | IP: {} | Connected UDP Locked (dst_cache Active) -> Worker #{} | Profile: [{}] | Mode: [{}] | Port: {}",
                                        user_rec.name,
                                        user_id,
                                        src_addr,
                                        chosen_worker,
                                        profile.as_str().to_uppercase(),
                                        mode.as_str(),
                                        local_port
                                    );
                                }
                                connected_sock
                            } else if let Ok(s2w) = socket_to_worker_rx.read() {
                                if let Some(&w_idx) = s2w.get(&src_addr) {
                                    if let Some(w_reg) = worker_registries_rx.get(w_idx) {
                                        if let Ok(reg_r) = w_reg.read() {
                                            reg_r.get(&src_addr).map(|e| Arc::clone(&e.socket)).unwrap_or_else(|| Arc::clone(&sock_rx))
                                        } else {
                                            Arc::clone(&sock_rx)
                                        }
                                    } else {
                                        Arc::clone(&sock_rx)
                                    }
                                } else {
                                    Arc::clone(&sock_rx)
                                }
                            } else {
                                Arc::clone(&sock_rx)
                            };

                            // Process packet payload
                            process_payload(
                                &mut buf[..n],
                                src_addr,
                                profile,
                                mode,
                                flags,
                                seq,
                                &user_id,
                                &psk,
                                now,
                                &tun_rx,
                                &session_rx,
                                &ip_table_rx,
                                &mtu_rx,
                                &active_socket,
                                &user_mgr_rx,
                                &mut reasm,
                                &mut reasm_out,
                            );
                        }
                        Ok(_) => {}
                        Err(_) => {
                            if !run_rx.load(Ordering::Relaxed) {
                                break;
                            }
                        }
                    }
                }
            })?;
        rx_handles.push(handle);
    }

    // Stage 2: Launch Dynamic Sharded Connected Socket Receiver Workers
    for worker_id in 0..num_workers {
        let conn_reg_worker = Arc::clone(&worker_registries[worker_id]);
        let s2w_worker = Arc::clone(&socket_to_worker);
        let tun_conn = Arc::clone(&tun);
        let session_conn = Arc::clone(&client_session);
        let ip_table_conn = Arc::clone(&ip_routing_table);
        let cache_conn = Arc::clone(&session_cache);
        let active_cnt_conn = Arc::clone(&active_sessions_count);
        let run_conn = Arc::clone(&running);
        let mtu_conn = Arc::clone(&active_mtu);
        let user_mgr_conn = user_mgr.clone();
        let total_rx_conn = Arc::clone(&total_rx_bytes);

        let handle_conn_rx = thread::Builder::new()
            .name(format!("connected_udp_rx_{}", worker_id))
            .spawn(move || {
                #[cfg(target_os = "linux")]
                if num_workers > 1 {
                    unsafe {
                        let mut cpuset: libc::cpu_set_t = std::mem::zeroed();
                        libc::CPU_SET(worker_id % 1024, &mut cpuset);
                        let _ = libc::sched_setaffinity(0, std::mem::size_of::<libc::cpu_set_t>(), &cpuset);
                    }
                }

                let mut buf = [0u8; 65536];
                let mut reasm: Option<Box<ReassemblyBuffer>> = None;
                let mut reasm_out = [0u8; 2048];
                let mut last_scavenge = Instant::now();
                let mut active_entries: Vec<ConnectedSocketEntry> = Vec::with_capacity(32);
                let mut poll_fds: Vec<libc::pollfd> = Vec::with_capacity(32);

                while run_conn.load(Ordering::Relaxed) {
                    let now = Instant::now();

                    // Periodic 5-Second Idle Session & Stale Socket Scavenger
                    if last_scavenge.elapsed().as_secs() >= 5 {
                        last_scavenge = now;
                        let mut to_evict = Vec::new();
                        if let Ok(reg_r) = conn_reg_worker.read() {
                            for (addr, e) in reg_r.iter() {
                                let idle = if let Ok(ls) = e.last_seen.read() {
                                    ls.elapsed().as_secs() >= SESSION_IDLE_TIMEOUT_SECS
                                } else {
                                    false
                                };
                                let auth = user_mgr_conn.authenticate_psk(&e.psk).is_some();
                                if idle || !auth {
                                    to_evict.push((*addr, e.user_id.clone()));
                                }
                            }
                        }

                        if !to_evict.is_empty() {
                            if let Ok(mut reg_w) = conn_reg_worker.write() {
                                for (addr, _) in &to_evict {
                                    reg_w.remove(addr);
                                }
                            }
                            if let Ok(mut s2w) = s2w_worker.write() {
                                for (addr, _) in &to_evict {
                                    s2w.remove(addr);
                                }
                            }
                            if let Ok(mut cache_w) = cache_conn.write() {
                                for (addr, _) in &to_evict {
                                    cache_w.remove(addr);
                                }
                            }
                            if let Ok(mut ip_w) = ip_table_conn.write() {
                                for (addr, _) in &to_evict {
                                    ip_w.retain(|_, s| s.addr != *addr);
                                }
                            }
                            for (addr, uid) in &to_evict {
                                user_mgr_conn.unregister_session(uid, addr);
                            }
                            if let Ok(cache_r) = cache_conn.read() {
                                active_cnt_conn.store(cache_r.len() as u32, Ordering::Relaxed);
                            }
                        }
                    }

                    active_entries.clear();
                    if let Ok(guard) = conn_reg_worker.read() {
                        for e in guard.values() {
                            active_entries.push(e.clone());
                        }
                    }

                    if active_entries.is_empty() {
                        thread::sleep(std::time::Duration::from_millis(15));
                        continue;
                    }

                    poll_fds.clear();
                    for e in &active_entries {
                        poll_fds.push(libc::pollfd {
                            fd: e.socket.as_raw_fd(),
                            events: libc::POLLIN,
                            revents: 0,
                        });
                    }

                    let ret = unsafe {
                        libc::poll(
                            poll_fds.as_mut_ptr(),
                            poll_fds.len() as libc::nfds_t,
                            25,
                        )
                    };

                    if ret <= 0 {
                        continue;
                    }

                    for (i, pfd) in poll_fds.iter().enumerate() {
                        if (pfd.revents & libc::POLLIN) != 0 {
                            if let Some(entry) = active_entries.get(i) {
                                // Zero-allocation fast-path validity check once per poll batch
                                if !user_mgr_conn.is_user_valid(&entry.user_id) {
                                    if let Ok(mut reg_w) = conn_reg_worker.write() {
                                        reg_w.remove(&entry.client_addr);
                                    }
                                    if let Ok(mut s2w) = s2w_worker.write() {
                                        s2w.remove(&entry.client_addr);
                                    }
                                    if let Ok(mut cache_w) = cache_conn.write() {
                                        cache_w.remove(&entry.client_addr);
                                    }
                                    if let Ok(mut ip_w) = ip_table_conn.write() {
                                        ip_w.retain(|_, s| s.addr != entry.client_addr);
                                    }
                                    user_mgr_conn.unregister_session(&entry.user_id, &entry.client_addr);
                                    continue;
                                }

                                if let Ok(mut ls) = entry.last_seen.write() {
                                    *ls = now;
                                }

                                loop {
                                    match entry.socket.recv(&mut buf) {
                                        Ok(n) if n >= MIMICRY_HEADER_LEN => {
                                             total_rx_conn.fetch_add(n as u64, Ordering::Relaxed);

                                             let detected = if let Some((flags, seq)) = entry.profile.unwrap_header(&buf[..n], &entry.psk) {
                                                 Some((entry.profile, flags, seq))
                                             } else {
                                                 auto_detect_and_unwrap(&buf[..n], &entry.psk)
                                             };

                                             if let Some((packet_profile, flags, seq)) = detected {
                                                 let packet_mode = PayloadMode::from_flags(flags);
                                                 if entry.mode != packet_mode || entry.profile != packet_profile {
                                                     if let Ok(mut reg_w) = conn_reg_worker.write() {
                                                         if let Some(e) = reg_w.get_mut(&entry.client_addr) {
                                                             e.mode = packet_mode;
                                                             e.profile = packet_profile;
                                                         }
                                                     }
                                                     if let Ok(mut cache_w) = cache_conn.write() {
                                                         if let Some(c) = cache_w.get_mut(&entry.client_addr) {
                                                             c.mode = packet_mode;
                                                             c.profile = packet_profile;
                                                         }
                                                     }
                                                     if let Ok(mut sess_w) = session_conn.write() {
                                                         if let Some(ref mut s) = *sess_w {
                                                             if s.addr == entry.client_addr {
                                                                 s.mode = packet_mode;
                                                                 s.profile = packet_profile;
                                                             }
                                                         }
                                                     }
                                                     if let Ok(mut ip_w) = ip_table_conn.write() {
                                                         for (_, s) in ip_w.iter_mut() {
                                                             if s.addr == entry.client_addr {
                                                                 s.mode = packet_mode;
                                                                 s.profile = packet_profile;
                                                             }
                                                         }
                                                     }
                                                 }
                                                 process_payload(
                                                     &mut buf[..n],
                                                     entry.client_addr,
                                                     packet_profile,
                                                     packet_mode,
                                                     flags,
                                                     seq,
                                                     &entry.user_id,
                                                     &entry.psk,
                                                     now,
                                                     &tun_conn,
                                                     &session_conn,
                                                     &ip_table_conn,
                                                     &mtu_conn,
                                                     &entry.socket,
                                                     &user_mgr_conn,
                                                     &mut reasm,
                                                     &mut reasm_out,
                                                 );
                                             }
                                        }
                                        Ok(_) => break,
                                        Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => break,
                                        Err(_) => break,
                                    }
                                }
                            }
                        }
                    }
                }
            })?;
        rx_handles.push(handle_conn_rx);
    }

    // Thread: Linux TUN -> Destination IP Routing -> Payload Shaping -> Mimicry Encapsulation -> Client Connected UDP Egress
    let tun_tx = Arc::clone(&tun);
    let ip_table_tx = Arc::clone(&ip_routing_table);
    let run_tx = Arc::clone(&running);
    let seq_tx = Arc::clone(&seq_counter);
    let user_mgr_tx = user_mgr;
    let total_tx_tx = Arc::clone(&total_tx_bytes);

    let handle_tx = thread::Builder::new()
        .name("tun_to_udp".into())
        .spawn(move || {
            let mut tun_buf = [0u8; 2048];
            let mut wire_buf = [0u8; 2048];

            while run_tx.load(Ordering::Relaxed) {
                let n = tun_tx.read(&mut tun_buf);
                if n <= 0 {
                    if !run_tx.load(Ordering::Relaxed) {
                        break;
                    }
                    continue;
                }

                let len = n as usize;

                let dst_ip = parse_ip_destination(&tun_buf[..len]);
                let session_opt = if let Some(ip) = dst_ip {
                    if let Ok(ip_map) = ip_table_tx.read() {
                        ip_map.get(&ip).cloned()
                    } else {
                        None
                    }
                } else {
                    None
                };

                if let Some(session) = session_opt {
                    // Zero-copy fast-path validation (checks enabled, quota, expiration without heap-cloning UserRecord)
                    if !user_mgr_tx.is_user_valid(&session.user_id) {
                        continue;
                    }

                    if len > session.mtu.load(Ordering::Relaxed) as usize {
                        continue;
                    }

                    let mode_flags = session.mode.to_flags();

                    if crate::common::should_fragment(len) {
                        let seq = (seq_tx.fetch_add(1, Ordering::Relaxed) & 0xFFFF) as u16;
                        let (part1, part2) = crate::common::split_packet(&tun_buf[..len]);

                        // Fragment 1
                        let payload_out1 = &mut wire_buf[MIMICRY_HEADER_LEN..];
                        let shaped_len1 = apply_payload_shaping(part1, payload_out1, &session.psk, seq, session.mode, session.profile);
                        let wire_len1 = MIMICRY_HEADER_LEN + shaped_len1;
                        let flags1 = FLAG_FRAG_1 | mode_flags;
                        session.profile.wrap_header(&mut wire_buf[..wire_len1], flags1, seq, &session.psk);
                        let _ = session.socket.send(&wire_buf[..wire_len1]).or_else(|_| session.socket.send_to(&wire_buf[..wire_len1], session.addr));

                        // Fragment 2
                        let payload_out2 = &mut wire_buf[MIMICRY_HEADER_LEN..];
                        let shaped_len2 = apply_payload_shaping(part2, payload_out2, &session.psk, seq, session.mode, session.profile);
                        let wire_len2 = MIMICRY_HEADER_LEN + shaped_len2;
                        let flags2 = FLAG_FRAG_2 | mode_flags;
                        session.profile.wrap_header(&mut wire_buf[..wire_len2], flags2, seq, &session.psk);
                        let _ = session.socket.send(&wire_buf[..wire_len2]).or_else(|_| session.socket.send_to(&wire_buf[..wire_len2], session.addr));

                        let total_wire_len = (wire_len1 + wire_len2) as u64;
                        user_mgr_tx.record_traffic(&session.user_id, total_wire_len);
                        total_tx_tx.fetch_add(total_wire_len, Ordering::Relaxed);
                    } else {
                        let seq = (seq_tx.fetch_add(1, Ordering::Relaxed) & 0xFFFF) as u16;
                        let full_flags = FLAG_DATA | mode_flags;

                        let payload_out = &mut wire_buf[MIMICRY_HEADER_LEN..];
                        let shaped_len = apply_payload_shaping(&tun_buf[..len], payload_out, &session.psk, seq, session.mode, session.profile);

                        let total_wire_len = MIMICRY_HEADER_LEN + shaped_len;
                        session.profile.wrap_header(&mut wire_buf[..total_wire_len], full_flags, seq, &session.psk);

                        // Fast-Path: Send directly on Connected UDP socket bypassing kernel route lookup (dst_cache active)
                        let send_res = session.socket.send(&wire_buf[..total_wire_len]);
                        if send_res.is_ok() || session.socket.send_to(&wire_buf[..total_wire_len], session.addr).is_ok() {
                            user_mgr_tx.record_traffic(&session.user_id, total_wire_len as u64);
                            total_tx_tx.fetch_add(total_wire_len as u64, Ordering::Relaxed);
                        }
                    }
                }
            }
        })?;

    for h in rx_handles {
        let _ = h.join();
    }
    let _ = handle_tx.join();

    Ok(())
}

fn deliver_inbound_ip(
    ip_pkt: &[u8],
    src_addr: SocketAddr,
    profile: MimicProfile,
    mode: PayloadMode,
    user_id: &str,
    psk: &[u8; 8],
    tun: &Arc<TunDevice>,
    ip_table: &Arc<RwLock<HashMap<IpAddr, ClientSession>>>,
    active_mtu: &Arc<AtomicU32>,
    socket: &Arc<UdpSocket>,
    user_mgr: &UserManager,
) {
    if let Some(src_ip) = parse_ip_source(ip_pkt) {
        if !user_mgr.is_ip_assigned_to_user(user_id, &src_ip) {
            return;
        }

        let now_secs = current_epoch_secs();
        let mut needs_insert = true;

        if let Ok(ip_r) = ip_table.read() {
            if let Some(existing) = ip_r.get(&src_ip) {
                if existing.addr == src_addr && existing.mode == mode && existing.profile == profile {
                    existing.last_seen.store(now_secs, Ordering::Relaxed);
                    needs_insert = false;
                }
            }
        }

        if needs_insert {
            if let Ok(mut ip_w) = ip_table.write() {
                if let Some(existing) = ip_w.get_mut(&src_ip) {
                    existing.last_seen.store(now_secs, Ordering::Relaxed);
                    existing.addr = src_addr;
                    existing.profile = profile;
                    existing.mode = mode;
                    existing.socket = Arc::clone(socket);
                    existing.user_id = user_id.to_string();
                    existing.psk = *psk;
                } else {
                    if ip_w.len() >= MAX_PINNED_SESSIONS {
                        ip_w.retain(|_, s| {
                            let ls = s.last_seen.load(Ordering::Relaxed);
                            now_secs.saturating_sub(ls) < SESSION_IDLE_TIMEOUT_SECS
                        });
                    }
                    ip_w.insert(
                        src_ip,
                        ClientSession {
                            addr: src_addr,
                            profile,
                            mode,
                            socket: Arc::clone(socket),
                            last_seen: Arc::new(AtomicU64::new(now_secs)),
                            mtu: Arc::new(AtomicU32::new(active_mtu.load(Ordering::Relaxed))),
                            user_id: user_id.to_string(),
                            psk: *psk,
                        },
                    );
                }
            }
        }
    }

    let mut w = tun.write(ip_pkt);
    if w < 0 {
        for _ in 0..10 {
            std::thread::yield_now();
            w = tun.write(ip_pkt);
            if w >= 0 {
                break;
            }
        }
    }
}

fn process_payload(
    raw_buf: &mut [u8],
    src_addr: SocketAddr,
    profile: MimicProfile,
    mode: PayloadMode,
    flags: u16,
    seq: u16,
    user_id: &str,
    psk: &[u8; 8],
    _now: Instant,
    tun: &Arc<TunDevice>,
    session_rx: &Arc<RwLock<Option<ClientSession>>>,
    ip_table: &Arc<RwLock<HashMap<IpAddr, ClientSession>>>,
    active_mtu: &Arc<AtomicU32>,
    socket: &Arc<UdpSocket>,
    user_mgr: &UserManager,
    reasm: &mut Option<Box<ReassemblyBuffer>>,
    reasm_out: &mut [u8; 2048],
) {
    let frame_type = flags & FLAG_FRAME_MASK;
    if frame_type == FLAG_KEEPALIVE {
        if raw_buf.len() >= MIMICRY_HEADER_LEN + 4
            && raw_buf[MIMICRY_HEADER_LEN..MIMICRY_HEADER_LEN + 2] == crate::common::MTU_HANDSHAKE_MAGIC
        {
            let requested_mtu = u16::from_be_bytes([
                raw_buf[MIMICRY_HEADER_LEN + 2],
                raw_buf[MIMICRY_HEADER_LEN + 3],
            ]) as u32;

            if (crate::common::MIN_TUNNEL_MTU..=crate::common::MAX_TUNNEL_MTU).contains(&requested_mtu) {
                if let Ok(mut sess_w) = session_rx.write() {
                    if let Some(ref mut s) = *sess_w {
                        if s.addr == src_addr {
                            s.mtu.store(requested_mtu, Ordering::Relaxed);
                            s.profile = profile;
                            s.mode = mode;
                        }
                    }
                }
                if let Ok(mut ip_w) = ip_table.write() {
                    for (_, s) in ip_w.iter_mut() {
                        if s.addr == src_addr || s.user_id == user_id {
                            s.mtu.store(requested_mtu, Ordering::Relaxed);
                            s.profile = profile;
                            s.mode = mode;
                        }
                    }
                }
                active_mtu.store(requested_mtu, Ordering::SeqCst);
            }
        }

        let mut ack = [0u8; MIMICRY_HEADER_LEN];
        let ack_flags = FLAG_KEEPALIVE_ACK | mode.to_flags();
        profile.wrap_header(&mut ack, ack_flags, seq, psk);
        let _ = socket.send(&ack).or_else(|_| socket.send_to(&ack, src_addr));
        return;
    }

    if frame_type == FLAG_DATA {
        let total_wire_len = raw_buf.len() as u64;
        let payload_slice = &mut raw_buf[MIMICRY_HEADER_LEN..];
        if let Some(raw_len) = strip_payload_shaping(payload_slice, psk, seq, mode, profile) {
            let ip_pkt = &payload_slice[..raw_len];
            if !ip_pkt.is_empty() {
                user_mgr.record_traffic(user_id, total_wire_len);
                deliver_inbound_ip(
                    ip_pkt,
                    src_addr,
                    profile,
                    mode,
                    user_id,
                    psk,
                    tun,
                    ip_table,
                    active_mtu,
                    socket,
                    user_mgr,
                );
            }
        }
    } else if frame_type == FLAG_FRAG_1 || frame_type == FLAG_FRAG_2 {
        let total_wire_len = raw_buf.len() as u64;
        let is_frag1 = frame_type == FLAG_FRAG_1;
        let payload_slice = &mut raw_buf[MIMICRY_HEADER_LEN..];
        if let Some(raw_len) = strip_payload_shaping(payload_slice, psk, seq, mode, profile) {
            user_mgr.record_traffic(user_id, total_wire_len);
            let reasm_buf = reasm.get_or_insert_with(|| Box::new(ReassemblyBuffer::new()));
            if let Some(reassembled_len) = reasm_buf.process(is_frag1, seq, &payload_slice[..raw_len], reasm_out) {
                let ip_pkt = &reasm_out[..reassembled_len];
                if !ip_pkt.is_empty() {
                    deliver_inbound_ip(
                        ip_pkt,
                        src_addr,
                        profile,
                        mode,
                        user_id,
                        psk,
                        tun,
                        ip_table,
                        active_mtu,
                        socket,
                        user_mgr,
                    );
                }
            }
        }
    }
}

/// Create a dedicated Connected UDP socket with SO_REUSEADDR & SO_REUSEPORT locked to client address
pub fn create_connected_socket(
    local_port: u16,
    client_addr: SocketAddr,
    bufsize: i32,
) -> Result<UdpSocket, Box<dyn Error>> {
    unsafe {
        let (family, is_v6) = match client_addr {
            SocketAddr::V4(_) => (libc::AF_INET, false),
            SocketAddr::V6(_) => (libc::AF_INET6, true),
        };
        let fd = libc::socket(family, libc::SOCK_DGRAM, 0);
        if fd < 0 {
            return Err("Failed to create connected socket".into());
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

        if is_v6 {
            let mut sin6: libc::sockaddr_in6 = std::mem::zeroed();
            sin6.sin6_family = libc::AF_INET6 as libc::sa_family_t;
            sin6.sin6_port = local_port.to_be();
            sin6.sin6_addr = libc::in6addr_any;

            if libc::bind(
                fd,
                &sin6 as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in6>() as libc::socklen_t,
            ) < 0
            {
                libc::close(fd);
                return Err(format!("bind connected v6 failed on port {}", local_port).into());
            }
        } else {
            let mut sin: libc::sockaddr_in = std::mem::zeroed();
            sin.sin_family = libc::AF_INET as libc::sa_family_t;
            sin.sin_port = local_port.to_be();
            sin.sin_addr.s_addr = libc::INADDR_ANY;

            if libc::bind(
                fd,
                &sin as *const _ as *const libc::sockaddr,
                std::mem::size_of::<libc::sockaddr_in>() as libc::socklen_t,
            ) < 0
            {
                libc::close(fd);
                return Err(format!("bind connected v4 failed on port {}", local_port).into());
            }
        }

        let sock = UdpSocket::from_raw_fd(fd);
        sock.connect(client_addr)?;
        let _ = sock.set_nonblocking(true);
        Ok(sock)
    }
}

/// Detect matching subscriber PSK and camouflage profile across active users
fn detect_any_user(
    buf: &[u8],
    local_port: u16,
    user_mgr: &UserManager,
) -> Option<(MimicProfile, u16, u16, String, [u8; 8])> {
    let psk_guard = user_mgr.psk_map.read().ok()?;
    for (&cand_psk, cand_user_id) in psk_guard.iter() {
        if let Some((prof, flags, seq)) = port_hint_and_auto_detect(buf, local_port, &cand_psk) {
            return Some((prof, flags, seq, cand_user_id.clone(), cand_psk));
        }
    }
    None
}
