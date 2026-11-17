//! Capacity Parameters Kernel Applier.
//! Safely applies dynamic socket buffers, netdev backlogs, conntrack limits, and process
//! resource limits (`RLIMIT_NOFILE`) to the Linux kernel.

use super::tiers::CapacityParams;
use crate::common::write_proc_sys;

pub fn apply_kernel_tuning(params: &CapacityParams) {
    // 1. Socket Buffers
    let rmem_str = params.rmem_max.to_string();
    let wmem_str = params.wmem_max.to_string();
    let def_buf = std::cmp::min(params.rmem_max / 4, 2_097_152).to_string();

    let _ = write_proc_sys("net/core/rmem_max", &rmem_str);
    let _ = write_proc_sys("net/core/wmem_max", &wmem_str);
    let _ = write_proc_sys("net/core/rmem_default", &def_buf);
    let _ = write_proc_sys("net/core/wmem_default", &def_buf);

    // 2. Netdev Queue Backlog
    let backlog_str = params.netdev_max_backlog.to_string();
    let _ = write_proc_sys("net/core/netdev_max_backlog", &backlog_str);

    // 3. Conntrack Table Size
    let conntrack_str = params.nf_conntrack_max.to_string();
    let _ = write_proc_sys("net/netfilter/nf_conntrack_max", &conntrack_str);
    let _ = write_proc_sys("net/ipv4/netfilter/ip_conntrack_max", &conntrack_str);
    let _ = write_proc_sys("net/nf_conntrack_max", &conntrack_str);

    // 4. File Descriptor Limits (RLIMIT_NOFILE) via libc system call
    #[cfg(target_os = "linux")]
    unsafe {
        let mut rlim = libc::rlimit {
            rlim_cur: params.rlimit_nofile,
            rlim_max: params.rlimit_nofile,
        };
        if libc::setrlimit(libc::RLIMIT_NOFILE, &rlim) != 0 {
            // Query current max if higher value was rejected by unprivileged namespace
            let mut curr = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
            if libc::getrlimit(libc::RLIMIT_NOFILE, &mut curr) == 0 {
                rlim.rlim_cur = curr.rlim_max;
                rlim.rlim_max = curr.rlim_max;
                let _ = libc::setrlimit(libc::RLIMIT_NOFILE, &rlim);
            }
        }
    }
}
