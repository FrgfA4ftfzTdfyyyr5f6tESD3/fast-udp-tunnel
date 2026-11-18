//! Environment Profiler & OS Detector.
//! Inspects `/etc/os-release`, init systems (OpenRC vs systemd), and system hardware
//! resources (RAM / CPU cores) to categorize the server platform.

use std::fs;
use std::path::Path;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryTier {
    /// < 256 MB RAM (e.g. 128MB Alpine VPS - Ultra-light buffers)
    Nano,
    /// 256 MB - 1024 MB RAM (typical 512MB Alpine VPS, minimal buffers to prevent OOM)
    Low,
    /// 1024 MB - 4096 MB RAM (Standard cloud instance, optimal high-speed buffers)
    Standard,
    /// > 4096 MB RAM (High-performance dedicated / high-spec VPS)
    High,
}

impl MemoryTier {
    pub fn as_str(&self) -> &'static str {
        match self {
            MemoryTier::Nano => "Nano Memory (<256MB RAM - Ultra-Light Buffers)",
            MemoryTier::Low => "Low Memory (<1GB RAM - Conservative Buffers)",
            MemoryTier::Standard => "Standard Memory (1-4GB RAM - High-Throughput Buffers)",
            MemoryTier::High => "High Memory (>4GB RAM - Enterprise Uncapped Buffers)",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum InitSystem {
    OpenRC,
    Systemd,
    Other(String),
}

impl InitSystem {
    pub fn as_str(&self) -> &'static str {
        match self {
            InitSystem::OpenRC => "OpenRC (Lightweight Init)",
            InitSystem::Systemd => "systemd (Standard Linux Init)",
            InitSystem::Other(_) => "Generic / Container Init",
        }
    }
}

#[derive(Debug, Clone)]
pub struct EnvironmentInfo {
    pub distro_name: String,
    pub distro_id: String,
    pub is_alpine: bool,
    pub is_debian_ubuntu: bool,
    pub init_system: InitSystem,
    pub total_ram_mb: u64,
    pub cpu_cores: usize,
    pub memory_tier: MemoryTier,
}

pub fn detect_environment() -> EnvironmentInfo {
    let mut distro_name = "Linux Generic".to_string();
    let mut distro_id = "generic".to_string();
    let mut is_alpine = false;
    let mut is_debian_ubuntu = false;

    // 1. Detect Distribution from /etc/os-release
    if let Ok(content) = fs::read_to_string("/etc/os-release") {
        for line in content.lines() {
            let line = line.trim();
            if line.starts_with("NAME=") {
                distro_name = line.trim_start_matches("NAME=").trim_matches('"').to_string();
            } else if line.starts_with("ID=") {
                distro_id = line.trim_start_matches("ID=").trim_matches('"').to_ascii_lowercase();
            }
        }
    }

    if distro_id == "alpine" || Path::new("/etc/alpine-release").exists() {
        is_alpine = true;
        distro_id = "alpine".to_string();
        if distro_name == "Linux Generic" {
            distro_name = "Alpine Linux".to_string();
        }
    } else if distro_id == "ubuntu" || distro_id == "debian" || distro_id.contains("debian") || Path::new("/etc/debian_version").exists() {
        is_debian_ubuntu = true;
    }

    // 2. Detect Init System
    let init_system = if Path::new("/run/openrc").exists() || Path::new("/sbin/openrc").exists() || Path::new("/sbin/rc-service").exists() {
        InitSystem::OpenRC
    } else if Path::new("/run/systemd/system").exists() || Path::new("/bin/systemctl").exists() || Path::new("/usr/bin/systemctl").exists() {
        InitSystem::Systemd
    } else {
        InitSystem::Other("Unknown/SysV/Container".to_string())
    };

    // 3. Detect RAM size from /proc/meminfo
    let mut total_ram_kb = 1048576u64; // Fallback 1GB
    if let Ok(mem_content) = fs::read_to_string("/proc/meminfo") {
        for line in mem_content.lines() {
            if line.starts_with("MemTotal:") {
                let parts: Vec<&str> = line.split_whitespace().collect();
                if parts.len() >= 2 {
                    if let Ok(kb) = parts[1].parse::<u64>() {
                        total_ram_kb = kb;
                        break;
                    }
                }
            }
        }
    }
    let total_ram_mb = total_ram_kb / 1024;

    let memory_tier = if total_ram_mb < 256 {
        MemoryTier::Nano
    } else if total_ram_mb < 1024 {
        MemoryTier::Low
    } else if total_ram_mb <= 4096 {
        MemoryTier::Standard
    } else {
        MemoryTier::High
    };

    // 4. Detect CPU Cores
    let mut cpu_cores = 1usize;
    if let Ok(cpu_content) = fs::read_to_string("/proc/cpuinfo") {
        let count = cpu_content.lines().filter(|l| l.starts_with("processor")).count();
        if count > 0 {
            cpu_cores = count;
        }
    }

    EnvironmentInfo {
        distro_name,
        distro_id,
        is_alpine,
        is_debian_ubuntu,
        init_system,
        total_ram_mb,
        cpu_cores,
        memory_tier,
    }
}
