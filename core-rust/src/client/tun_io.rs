//! Cross-platform Layer 3 TUN Device Abstraction (Windows Wintun & Android VpnService RawFd).
//! Pure Layer 3 IP packets only — zero TAP / Ethernet framing.
//! Inspired by tun-rs architecture patterns.

use std::error::Error;

#[cfg(target_os = "windows")]
use std::sync::Arc;
#[cfg(target_os = "windows")]
use wintun::{Adapter, Session};

#[derive(Clone)]
pub enum TunIoDevice {
    #[cfg(target_os = "windows")]
    Windows {
        adapter: Arc<Adapter>,
        session: Arc<Session>,
    },
    #[cfg(any(target_os = "android", target_os = "linux"))]
    PosixFd {
        fd: i32,
        borrow: bool,
    },
}

impl TunIoDevice {
    #[cfg(target_os = "windows")]
    pub fn from_wintun(adapter: Arc<Adapter>, session: Arc<Session>) -> Self {
        Self::Windows { adapter, session }
    }

    #[cfg(any(target_os = "android", target_os = "linux"))]
    pub unsafe fn from_raw_fd(fd: i32, borrow: bool) -> Self {
        Self::PosixFd { fd, borrow }
    }

    /// Write raw Layer 3 packet to TUN device
    pub fn write_packet(&self, packet_bytes: &[u8]) -> Result<(), Box<dyn Error>> {
        match self {
            #[cfg(target_os = "windows")]
            Self::Windows { session, .. } => {
                let mut pkt = session.allocate_send_packet(packet_bytes.len() as u16)?;
                pkt.bytes_mut().copy_from_slice(packet_bytes);
                session.send_packet(pkt);
                Ok(())
            }
            #[cfg(any(target_os = "android", target_os = "linux"))]
            Self::PosixFd { fd, .. } => {
                let res = unsafe { libc::write(*fd, packet_bytes.as_ptr() as *const libc::c_void, packet_bytes.len()) };
                if res < 0 {
                    Err(std::io::Error::last_os_error().into())
                } else {
                    Ok(())
                }
            }
        }
    }

    /// Graceful shutdown: unblocks any pending blocking reads
    pub fn shutdown(&self) {
        match self {
            #[cfg(target_os = "windows")]
            Self::Windows { session, .. } => {
                let _ = session.shutdown();
            }
            #[cfg(any(target_os = "android", target_os = "linux"))]
            Self::PosixFd { .. } => {
                // Handled via lifecycle on Android
            }
        }
    }
}
