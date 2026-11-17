//! High-precision in-band RTT telemetry, loss tracking, and GUI state hooks.

use std::sync::atomic::{AtomicBool, AtomicU16, AtomicU64, AtomicU8, Ordering};
use std::sync::OnceLock;
use std::time::Instant;

static GLOBAL_TELEMETRY: OnceLock<TunnelTelemetry> = OnceLock::new();

#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TunnelStatus {
    Disconnected = 0,
    Connecting = 1,
    Connected = 2,
    Error = 3,
}

/// Decoupled, lock-free telemetry structure for seamless GUI (egui/eframe) integration.
/// Read every frame at 60fps with zero mutex contention and zero jitter on packet forwarding.
pub struct TunnelTelemetry {
    pub status: AtomicU8,
    pub ping_ms: AtomicU16,
    pub tx_rate_bps: AtomicU64,
    pub rx_rate_bps: AtomicU64,
    pub total_tx_bytes: AtomicU64,
    pub total_rx_bytes: AtomicU64,
    pub pmtu: AtomicU16,
    pub shutdown_requested: AtomicBool,
}

impl TunnelTelemetry {
    pub fn global() -> &'static TunnelTelemetry {
        GLOBAL_TELEMETRY.get_or_init(|| TunnelTelemetry::new())
    }

    pub fn new() -> Self {
        Self {
            status: AtomicU8::new(TunnelStatus::Disconnected as u8),
            ping_ms: AtomicU16::new(0),
            tx_rate_bps: AtomicU64::new(0),
            rx_rate_bps: AtomicU64::new(0),
            total_tx_bytes: AtomicU64::new(0),
            total_rx_bytes: AtomicU64::new(0),
            pmtu: AtomicU16::new(0),
            shutdown_requested: AtomicBool::new(false),
        }
    }

    pub fn get_status(&self) -> TunnelStatus {
        match self.status.load(Ordering::Relaxed) {
            1 => TunnelStatus::Connecting,
            2 => TunnelStatus::Connected,
            3 => TunnelStatus::Error,
            _ => TunnelStatus::Disconnected,
        }
    }

    pub fn set_status(&self, s: TunnelStatus) {
        self.status.store(s as u8, Ordering::Relaxed);
    }
}

pub struct MetricTracker {
    pub total_tx_bytes: AtomicU64,
    pub total_rx_bytes: AtomicU64,
    pub current_ping_ms: AtomicU16,
    sent_probes: std::sync::Mutex<[Option<(u16, Instant)>; 64]>,
}

impl MetricTracker {
    pub fn new() -> Self {
        Self {
            total_tx_bytes: AtomicU64::new(0),
            total_rx_bytes: AtomicU64::new(0),
            current_ping_ms: AtomicU16::new(0),
            sent_probes: std::sync::Mutex::new([None; 64]),
        }
    }

    pub fn record_probe_sent(&self, seq: u16) {
        if let Ok(mut lock) = self.sent_probes.lock() {
            let idx = (seq as usize) % 64;
            lock[idx] = Some((seq, Instant::now()));
        }
    }

    pub fn handle_possible_probe_reply(&self, data: &[u8]) -> bool {
        // Demux IPv4 ICMP Echo Reply (Type 0, Code 0)
        if data.len() >= 28 && (data[0] >> 4) == 4 && data[9] == 0x01 && data[20] == 0x00 && data[21] == 0x00 {
            if data[24] == 0x13 && data[25] == 0x37 {
                let seq = u16::from_be_bytes([data[26], data[27]]);
                if let Ok(mut lock) = self.sent_probes.lock() {
                    let idx = (seq as usize) % 64;
                    if let Some((s, sent_time)) = lock[idx] {
                        if s == seq {
                            let rtt = sent_time.elapsed().as_millis() as u16;
                            self.current_ping_ms.store(rtt, Ordering::Relaxed);
                            lock[idx] = None;
                            return true;
                        }
                    }
                }
                return true;
            }
        }
        false
    }
}

pub fn format_size(bytes: f64) -> String {
    const KB: f64 = 1024.0;
    const MB: f64 = KB * 1024.0;
    const GB: f64 = MB * 1024.0;

    if bytes >= GB {
        format!("{:.2} GB", bytes / GB)
    } else if bytes >= MB {
        format!("{:.2} MB", bytes / MB)
    } else if bytes >= KB {
        format!("{:.1} KB", bytes / KB)
    } else {
        format!("{:.0} B", bytes)
    }
}
