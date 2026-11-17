//! Direct libc Linux TUN device management with O_CLOEXEC, TUNSETOFFLOAD reset,
//! and non-blocking I/O support (inspired by tun-rs Linux layer).

use std::error::Error;

const IFF_TUN: u16 = 0x0001;
const IFF_NO_PI: u16 = 0x1000;
const TUNSETIFF: u64 = 0x400454ca;
const TUNSETOFFLOAD: u64 = 0x400454d0;

pub struct TunDevice {
    fd: i32,
}

impl TunDevice {
    pub fn create(dev_name: &str) -> Result<Self, Box<dyn Error>> {
        let path = b"/dev/net/tun\0";
        // tun-rs pattern: Open with O_CLOEXEC so the descriptor is never leaked into child processes (iptables, rc-service)
        let fd = unsafe { libc::open(path.as_ptr() as *const libc::c_char, libc::O_RDWR | libc::O_CLOEXEC) };
        if fd < 0 {
            return Err(format!("Failed to open /dev/net/tun: errno {}", std::io::Error::last_os_error()).into());
        }

        #[repr(C)]
        struct Ifreq {
            ifr_name: [u8; 16],
            ifr_flags: u16,
            ifr_padding: [u8; 22],
        }

        let mut ifr = Ifreq {
            ifr_name: [0; 16],
            ifr_flags: IFF_TUN | IFF_NO_PI,
            ifr_padding: [0; 22],
        };

        let bytes = dev_name.as_bytes();
        let len = bytes.len().min(15);
        ifr.ifr_name[..len].copy_from_slice(&bytes[..len]);

        let res = unsafe { libc::ioctl(fd, TUNSETIFF as _, &mut ifr as *mut _ as *mut std::ffi::c_void) };
        if res < 0 {
            unsafe { libc::close(fd) };
            return Err(format!("ioctl(TUNSETIFF) failed: {}", std::io::Error::last_os_error()).into());
        }

        // tun-rs pattern: Explicitly reset kernel offload mask to 0.
        // The TUN_F_* offload mask is device-wide state in Linux. If a previous process
        // configured offload=true, resetting it to 0 guarantees clean Layer 3 packet boundaries.
        let _ = unsafe { libc::ioctl(fd, TUNSETOFFLOAD as _, 0 as libc::c_ulong) };

        Ok(TunDevice { fd })
    }

    pub fn set_nonblocking(&self, nonblocking: bool) -> Result<(), std::io::Error> {
        let mut nb: libc::c_int = if nonblocking { 1 } else { 0 };
        let res = unsafe { libc::ioctl(self.fd, libc::FIONBIO, &mut nb) };
        if res < 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    }

    pub fn read(&self, buf: &mut [u8]) -> isize {
        unsafe { libc::read(self.fd, buf.as_mut_ptr() as *mut libc::c_void, buf.len()) }
    }

    pub fn write(&self, buf: &[u8]) -> isize {
        unsafe { libc::write(self.fd, buf.as_ptr() as *const libc::c_void, buf.len()) }
    }

    pub fn as_raw_fd(&self) -> i32 {
        self.fd
    }
}

impl Drop for TunDevice {
    fn drop(&mut self) {
        if self.fd >= 0 {
            unsafe { libc::close(self.fd) };
        }
    }
}
