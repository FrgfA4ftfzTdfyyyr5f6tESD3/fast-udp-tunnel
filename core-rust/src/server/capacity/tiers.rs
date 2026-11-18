//! Capacity Tiers Definition Module.
//! Defines 4 progressive hardware & network capacity tiers scaled by provisioned user count.

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum CapacityTier {
    /// Tier 1: Micro / Personal (1–10 Provisioned Users)
    Tier1,
    /// Tier 2: Small Team (11–25 Provisioned Users)
    Tier2,
    /// Tier 3: Medium Server (26–50 Provisioned Users)
    Tier3,
    /// Tier 4: High-Density (51–100+ Provisioned Users)
    Tier4,
}

impl CapacityTier {
    pub fn name(&self) -> &'static str {
        match self {
            CapacityTier::Tier1 => "Tier 1: Micro / Personal",
            CapacityTier::Tier2 => "Tier 2: Small Team",
            CapacityTier::Tier3 => "Tier 3: Medium Server",
            CapacityTier::Tier4 => "Tier 4: High-Density",
        }
    }

    pub fn user_range(&self) -> &'static str {
        match self {
            CapacityTier::Tier1 => "1 - 10 Users",
            CapacityTier::Tier2 => "11 - 25 Users",
            CapacityTier::Tier3 => "26 - 50 Users",
            CapacityTier::Tier4 => "51 - 100+ Users",
        }
    }

    pub fn from_user_count(users: usize) -> Self {
        match users {
            0..=10 => CapacityTier::Tier1,
            11..=25 => CapacityTier::Tier2,
            26..=50 => CapacityTier::Tier3,
            _ => CapacityTier::Tier4,
        }
    }

    pub fn baseline_params(&self, provisioned_users: usize) -> CapacityParams {
        match self {
            CapacityTier::Tier1 => CapacityParams {
                tier: CapacityTier::Tier1,
                provisioned_users,
                rmem_max: 4_194_304,           // 4 MB
                wmem_max: 4_194_304,           // 4 MB
                netdev_max_backlog: 4_096,
                nf_conntrack_max: 32_768,
                rlimit_nofile: 16_384,
                internal_channel_capacity: 1_024,
                worker_threads: 1,
                socket_buf_size: 4 * 1024 * 1024,
            },
            CapacityTier::Tier2 => CapacityParams {
                tier: CapacityTier::Tier2,
                provisioned_users,
                rmem_max: 8_388_608,           // 8 MB
                wmem_max: 8_388_608,           // 8 MB
                netdev_max_backlog: 8_192,
                nf_conntrack_max: 65_536,
                rlimit_nofile: 32_768,
                internal_channel_capacity: 2_048,
                worker_threads: 2,
                socket_buf_size: 8 * 1024 * 1024,
            },
            CapacityTier::Tier3 => CapacityParams {
                tier: CapacityTier::Tier3,
                provisioned_users,
                rmem_max: 16_777_216,          // 16 MB
                wmem_max: 16_777_216,          // 16 MB
                netdev_max_backlog: 16_384,
                nf_conntrack_max: 131_072,
                rlimit_nofile: 65_535,
                internal_channel_capacity: 4_096,
                worker_threads: 4,
                socket_buf_size: 16 * 1024 * 1024,
            },
            CapacityTier::Tier4 => CapacityParams {
                tier: CapacityTier::Tier4,
                provisioned_users,
                rmem_max: 33_554_432,          // 32 MB
                wmem_max: 33_554_432,          // 32 MB
                netdev_max_backlog: 32_768,
                nf_conntrack_max: 262_144,
                rlimit_nofile: 262_144,
                internal_channel_capacity: 8_192,
                worker_threads: 8,
                socket_buf_size: 32 * 1024 * 1024,
            },
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CapacityParams {
    pub tier: CapacityTier,
    pub provisioned_users: usize,
    pub rmem_max: usize,
    pub wmem_max: usize,
    pub netdev_max_backlog: usize,
    pub nf_conntrack_max: usize,
    pub rlimit_nofile: u64,
    pub internal_channel_capacity: usize,
    pub worker_threads: usize,
    pub socket_buf_size: i32,
}
