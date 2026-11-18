# Morph Core — Ultra-Fast Stealth UDP Tunnel (v8.7)

**Morph Core** is a high-throughput, multi-platform Layer-3 RAW IP UDP tunnel written in pure Rust (`core-rust`), featuring a native **Linux Multi-User Server**, a **Windows Tauri Desktop Client (`Wintun`)**, and a streamlined **Android VPN App (`VpnService` + Jetpack Compose)** backed by a shared native JNI engine (`libmorph_core.so`).

Engineered for hostile cellular/ISP networks with strict Deep Packet Inspection (DPI), MTU black holes, and IPv4 reputation filtering — delivering **20+ Mbps** throughput, **0% idle server CPU**, and **IPv6-First clean egress**.

---

## Repository Architecture

```text
fast-udp-tunnel/
├── core-rust/                      # Shared Rust Engine (Linux Server + Windows Client + Android JNI)
│   ├── Cargo.toml                  # Unified workspace crate (binary `fast-udp-tunnel` + cdylib `morph_core`)
│   ├── tauri.conf.json             # Windows Desktop GUI config (points to ../desktop-ui)
│   ├── src/
│   │   ├── common/                 # Token codec (morph://), 1200B micro-segmentation, PMTU, benchmarks
│   │   ├── core/                   # 3-mode payload shaping & stream cipher, lock-free RTT/rate metrics
│   │   ├── mimic/                  # 16 stealth camouflage protocols with full 64-bit PSK auth
│   │   ├── server/                 # Linux TUN server, sharded Connected UDP workers, OS tuner, Web Admin
│   │   ├── client/                 # Windows Wintun engine, DNS snooper, routing + Android JNI engine
│   │   ├── android_jni.rs          # Panic-safe JNI bridge (`com.morphcore.vpn.MorphNative`)
│   │   ├── gui_bridge.rs           # Tauri v2 desktop bridge & system tray
│   │   ├── lib.rs                  # Shared library entry point (`libmorph_core.so`)
│   │   └── main.rs                 # Unified Linux Server & Windows CLI/GUI entry point
│   └── dist/android/               # Prebuilt reference Android native libraries (16 KB page-aligned)
│       ├── arm64-v8a/libmorph_core.so
│       └── x86_64/libmorph_core.so
├── desktop-ui/                     # Minimal 3-tab Windows Desktop UI (HTML/CSS/JS)
├── android-app/                    # Minimal 3-tab Android App (Kotlin + Jetpack Compose + VpnService)
│   ├── gradlew / gradlew.bat       # Self-contained Gradle 9.3.1 wrapper
│   └── app/src/main/jniLibs/       # Bundled native `arm64-v8a` & `x86_64` cores
└── releases/                       # Local build outputs (git-ignored)
    ├── windows/                    # Windows executable + wintun.dll
    └── android/                    # Built MorphCore-arm64.apk
```

---

## Key Capabilities

### 1. Golden 1200-Byte Micro-Segmentation & 1500B Inner MTU
- Both Windows (`Wintun`), Android (`VpnService`), and Linux Server (`tun0`) operate at a full standard **1500-byte inner MTU** so TCP, QUIC, and applications run natively without MSS clamping artifacts.
- Any inner IP packet larger than **1200 bytes** (`FRAGMENT_THRESHOLD`) is transparently split into two lightweight ~650-byte tunnel micro-segments with O(1) cache-aligned reassembly (`ReassemblyBuffer`).
- Every wire UDP datagram stays far below cellular APN/CGNAT/IPv6 minimum MTU limits (1280B–1400B), eliminating silent carrier drops and restoring full physical line speed (**21+ Mbps** over international links).

### 2. High-Throughput Android Native Engine (`libmorph_core.so`)
- **Batch UDP Receive (`libc::recvmmsg`):** Drains up to **32 UDP packets per syscall** into pre-allocated zero-allocation buffers, cutting kernel context switches by up to 30x.
- **Non-Blocking TUN Burst Drain:** Drains up to **64 IP packets per `poll()` wakeup** with **0% idle CPU**.
- **Adaptive Kernel Socket Buffers:** Automatically negotiates up to **8 MB** (`SO_RCVBUF` / `SO_SNDBUF`) with graceful fallback (`8MB → 4MB → 2MB → 1MB`).
- **Dual-ABI Native Packaging:** Ships both `arm64-v8a` (real Android devices) and `x86_64` (native emulator speed without ARM binary translation), compiled with **16 KB ELF page alignment** (`-z max-page-size=16384`) for Android 15/16 & Google Play compliance.
- **Streamlined 3-Tab Compose UI:** Matches the Windows Desktop app 1-to-1 (**Tunnel**, **Tokens**, **Options**) with zero background bloat.

### 3. Clean IPv6-First Egress (Zero-CAPTCHA Access to Google & AI)
- Regardless of whether the client connects to the server over IPv4 or IPv6, inner tunnel traffic prioritizes the server's **clean global IPv6 address** first while retaining **IPv4 as seamless fallback** for IPv4-only hosts:
  - **Windows:** Elevates `fd00:8::/64` in the OS RFC 6724 prefix policy table (`precedence=60`) with in-tunnel kernel DNS (`fd00:8:0::1` & `10.8.0.1`) and Policy-Based Selective Split Tunneling.
  - **Android:** Uses **RFC 6296 Checksum-Neutral NPTv6** (`2001:db8:0:cf4f::/64 ↔ fd00:8:0::/64`, identical 16-bit one's complement sum `0xFD08` — zero checksum recomputation!) so Android Bionic's RFC 6724 resolver assigns Global-Scope IPv6 precedence (**40 > IPv4 35**) without requiring root, paired with IPv6-first DNS (`2001:db8:0:cf4f::1`, `2606:4700:4700::1111`, fallback `10.8.0.1`).

### 4. 16 Stealth Camouflage Protocols (Full 64-Bit PSK Authentication)
The server listens concurrently across **14 standard UDP ports** (`7190, 443, 3478, 19132, 27015, 27020, 7500, 8801, 3389, 50000, 5353, 4500, 6881, 53`) and auto-detects all **16** protocols with per-packet 64-bit PSK verification:

| # | Protocol Key | Camouflage Target | Default Port |
|---:|:---|:---|---:|
| 1 | `quic_v1` | QUIC v1 / HTTP/3 (RFC 9000) | `443` |
| 2 | `quic_v2` | QUIC v2 (RFC 9369) | `443` |
| 3 | `webrtc` | WebRTC / SRTP Audio-Video | `3478` |
| 4 | `dtls` | DTLS 1.2 / 1.3 VPN | `443` |
| 5 | `dns` | DNS / mDNS (RFC 1035 / 6762) | `5353` |
| 6 | `esp` | IPsec NAT-T ESP (RFC 3948) | `4500` |
| 7 | `utp` | µTP BitTorrent Transport | `6881` |
| 8 | `raknet` | RakNet Game Engine | `19132` |
| 9 | `stun` | STUN NAT Traversal (RFC 5389) | `3478` |
| 10 | `turn` | TURN ChannelData Relay | `3478` |
| 11 | `steam` | Steam / Valve A2S Query | `27015` |
| 12 | `sdr` | Valve Steam Datagram Relay (CS2) | `27020` |
| 13 | `riot` | Riot Games Live Stream | `7500` |
| 14 | `zoom` | Zoom Media Conferencing | `8801` |
| 15 | `rdp` | Microsoft RDPEUDP | `3389` |
| 16 | `discord` | Discord Voice / Opus | `50000` |

### 5. Three Payload Protection Modes
- **`shaped` (Default):** Protocol-conforming framing headers (Opus voice, STUN TLV, DNS QCLASS, TPKT/RDP, game channel opcodes, or native ciphertext for AEAD protocols) + dynamic stream cipher to defeat Shannon entropy & DPI inspection.
- **`stream`:** Lightweight 64-bit high-entropy stream cipher for sniffing resistance with zero framing overhead.
- **`plaintext`:** Raw IP passthrough for maximum speed when carrying already-encrypted TLS/HTTPS traffic.

### 6. Ultra-Light Linux Server & Edge Manager Console
- **Minimal Footprint:** Runs smoothly on 93 MB RAM Alpine VPS instances (~38 MB RSS, **0.0% idle CPU** via kernel blocking TUN I/O and `poll()` Connected UDP workers).
- **Auto-Tuner & Capacity Guardrails:** Automatically configures `tun0`, IPv4/IPv6 NAT (`iptables`/`ip6tables`), `dnsmasq` DNS with HaGeZi AdBlock support, and kernel socket limits for Alpine, Debian, and Ubuntu.
- **Multi-User Subscriptions & Anti-Scanner Admin Panel:** Persistent `users.json` with per-user data quotas, expiry dates, isolated `morph://` encrypted subscription tokens, and a cloaked web dashboard (returns `404` on `/` and decoy scanner paths).

---

## Quick Build Guide

### 1. Linux Server (Static `musl` Binary)
```bash
cd core-rust
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
# Output: core-rust/target/x86_64-unknown-linux-musl/release/fast-udp-tunnel
```

Run on VPS (Alpine / Debian / Ubuntu):
```bash
./fast-udp-tunnel --mode server --admin-port 9090 --server-v4 <PUBLIC_V4> --server-v6 "[<PUBLIC_V6>]"
```

### 2. Windows Desktop Client (Tauri GUI + CLI)
```powershell
cd core-rust
cargo build --release
# Output: core-rust/target/release/fast-udp-tunnel.exe (place wintun.dll alongside it)
```

### 3. Android Native Core (`libmorph_core.so`)
Prebuilt `arm64-v8a` and `x86_64` libraries are already included in `android-app/app/src/main/jniLibs/` and `core-rust/dist/android/`. To rebuild them with `cargo-ndk`:
```bash
cd core-rust
rustup target add aarch64-linux-android x86_64-linux-android
cargo ndk -t arm64-v8a -t x86_64 -o ../android-app/app/src/main/jniLibs build --lib --release
```

### 4. Android APK (`MorphCore-arm64.apk`)
Requires JDK 17 and Android SDK (`platform-tools`, `platforms;android-36.1`, `build-tools;36.0.0`). Set `sdk.dir` in `android-app/local.properties`, then:
```powershell
cd android-app
.\gradlew.bat assembleDebug
# Output: android-app/app/build/outputs/apk/debug/app-debug.apk
```

---

## License

Released under the [MIT License](LICENSE).
