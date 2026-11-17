//! High-throughput connected UDP socket management with kernel WinSock2 optimizations.

use std::error::Error;
use std::net::{SocketAddr, UdpSocket};
use std::os::windows::io::AsRawSocket;

use crate::core::CLIENT_SOCKET_BUFFER_SIZE;

#[link(name = "ws2_32")]
extern "system" {
    fn setsockopt(s: usize, level: i32, optname: i32, optval: *const u8, optlen: i32) -> i32;
    fn WSAIoctl(
        s: usize,
        dwIoControlCode: u32,
        lpvInBuffer: *mut std::ffi::c_void,
        cbInBuffer: u32,
        lpvOutBuffer: *mut std::ffi::c_void,
        cbOutBuffer: u32,
        lpcbBytesReturned: *mut u32,
        lpOverlapped: *mut std::ffi::c_void,
        lpCompletionRoutine: *mut std::ffi::c_void,
    ) -> i32;
}

const SOL_SOCKET: i32 = 0xffff;
const SO_RCVBUF: i32 = 0x1002;
const SO_SNDBUF: i32 = 0x1001;
const SIO_UDP_CONNRESET: u32 = 0x9800000C;

/// Enable Don't Fragment flag (DF=1) to activate OS Path MTU Discovery
pub fn set_dont_fragment(socket: &UdpSocket, is_ipv6: bool) {
    crate::common::pmtu::set_socket_dont_fragment(socket, is_ipv6);
}

/// Configure 16MB WinSock2 ring buffers and disable SIO_UDP_CONNRESET to prevent resets on ICMP drops.
pub fn tune_socket_buffers_and_connreset(socket: &UdpSocket) {
    let raw = socket.as_raw_socket();
    let size: i32 = CLIENT_SOCKET_BUFFER_SIZE;
    unsafe {
        let _ = setsockopt(
            raw as usize,
            SOL_SOCKET,
            SO_RCVBUF,
            &size as *const _ as *const u8,
            std::mem::size_of::<i32>() as i32,
        );
        let _ = setsockopt(
            raw as usize,
            SOL_SOCKET,
            SO_SNDBUF,
            &size as *const _ as *const u8,
            std::mem::size_of::<i32>() as i32,
        );

        let mut enabled: u32 = 0;
        let mut bytes_returned: u32 = 0;
        let _ = WSAIoctl(
            raw as usize,
            SIO_UDP_CONNRESET,
            &mut enabled as *mut _ as *mut std::ffi::c_void,
            std::mem::size_of::<u32>() as u32,
            std::ptr::null_mut(),
            0,
            &mut bytes_returned,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        );
    }
}

/// Create a connected UDP socket locked directly into the Windows TCP/IP kernel stack (FIB Early Demux).
pub fn create_connected_socket(server_addr: SocketAddr) -> Result<UdpSocket, Box<dyn Error>> {
    let bind_addr = if server_addr.is_ipv6() {
        "[::]:0"
    } else {
        "0.0.0.0:0"
    };

    let socket = UdpSocket::bind(bind_addr)?;
    socket.connect(server_addr)?;
    tune_socket_buffers_and_connreset(&socket);
    set_dont_fragment(&socket, server_addr.is_ipv6());
    Ok(socket)
}
