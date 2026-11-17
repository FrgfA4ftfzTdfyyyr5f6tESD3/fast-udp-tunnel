//! Dynamic Capacity & Resource Scaler Module.
//! Manages automatic and progressive hardware resource scaling based on provisioned
//! user count (`provisioned_users`) and server physical limits (RAM and CPU Cores).

pub mod applier;
pub mod guardrail;
pub mod tiers;

use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, RwLock};

pub use guardrail::{GuardrailEngine, GuardrailResult};
pub use tiers::{CapacityParams, CapacityTier};
use crate::server::tuner::EnvironmentInfo;

pub struct CapacityManager {
    provisioned_users: Arc<AtomicUsize>,
    current_params: Arc<RwLock<CapacityParams>>,
    guardrail_active: Arc<AtomicBool>,
    total_ram_mb: u64,
    cpu_cores: usize,
}

impl CapacityManager {
    /// Initialize CapacityManager at server startup and apply tuned kernel parameters.
    pub fn init(provisioned_users: usize, env: &EnvironmentInfo) -> (Self, CapacityParams) {
        let guard_res = GuardrailEngine::evaluate(provisioned_users, env.total_ram_mb, env.cpu_cores);
        let effective_params = guard_res.effective_params.clone();

        // Apply to Linux kernel (/proc/sys and rlimit)
        applier::apply_kernel_tuning(&effective_params);

        let mgr = Self {
            provisioned_users: Arc::new(AtomicUsize::new(provisioned_users)),
            current_params: Arc::new(RwLock::new(effective_params.clone())),
            guardrail_active: Arc::new(AtomicBool::new(guard_res.guardrail_applied)),
            total_ram_mb: env.total_ram_mb,
            cpu_cores: env.cpu_cores,
        };

        mgr.print_startup_banner(
            &effective_params,
            guard_res.requested_tier,
            guard_res.guardrail_applied,
            guard_res.warning.as_deref(),
        );

        (mgr, effective_params)
    }

    /// Dynamically recalculate and re-apply capacity parameters when provisioned user count changes (live re-tune).
    pub fn recalculate(&self, new_user_count: usize) -> (CapacityParams, bool, Option<String>) {
        let guard_res = GuardrailEngine::evaluate(new_user_count, self.total_ram_mb, self.cpu_cores);
        let effective_params = guard_res.effective_params.clone();

        applier::apply_kernel_tuning(&effective_params);

        self.provisioned_users.store(new_user_count, Ordering::SeqCst);
        self.guardrail_active.store(guard_res.guardrail_applied, Ordering::SeqCst);
        if let Ok(mut lock) = self.current_params.write() {
            *lock = effective_params.clone();
        }

        println!("[CAPACITY-MANAGER] Dynamic Live Re-tune applied for {} users (Tier: {})", new_user_count, effective_params.tier.name());
        if let Some(ref w) = guard_res.warning {
            println!("  [GUARDRAIL WARNING] {}", w);
        }

        (effective_params, guard_res.guardrail_applied, guard_res.warning)
    }

    pub fn current_params(&self) -> CapacityParams {
        self.current_params.read().unwrap().clone()
    }

    pub fn provisioned_users(&self) -> usize {
        self.provisioned_users.load(Ordering::Relaxed)
    }

    pub fn is_guardrail_active(&self) -> bool {
        self.guardrail_active.load(Ordering::Relaxed)
    }

    pub fn print_startup_banner(
        &self,
        params: &CapacityParams,
        requested_tier: CapacityTier,
        guardrail_applied: bool,
        warning: Option<&str>,
    ) {
        println!("==================================================================");
        println!("  DYNAMIC CAPACITY & SELF-TUNING RESOURCE SCALER");
        println!("==================================================================");
        println!("[CAPACITY] Host Specs         : {} MB RAM | {} CPU Core(s)", self.total_ram_mb, self.cpu_cores);
        println!("[CAPACITY] Provisioned Users  : {} users", params.provisioned_users);
        println!("[CAPACITY] Requested Tier     : {} ({})", requested_tier.name(), requested_tier.user_range());
        println!("[CAPACITY] Effective Tier     : {} ({})", params.tier.name(), params.tier.user_range());
        println!(
            "[CAPACITY] Hardware Guardrail : {}",
            if guardrail_applied { "TRIGGERED (Safe Ceiling Enforced)" } else { "INACTIVE (Within Safe Limits)" }
        );
        if let Some(msg) = warning {
            println!("  -> [GUARDRAIL WARNING] {}", msg);
        }
        println!("------------------------------------------------------------------");
        println!("  Final Applied Kernel & Resource Boundaries:");
        println!("  -> Socket Buffer Max   : {} MB (RcvBufMax: {}B, SndBufMax: {}B)", params.rmem_max / (1024 * 1024), params.rmem_max, params.wmem_max);
        println!("  -> Netdev Queue Backlog: {} packets", params.netdev_max_backlog);
        println!("  -> Conntrack Max (NAT) : {} entries", params.nf_conntrack_max);
        println!("  -> File Limit (NOFILE) : {} descriptors", params.rlimit_nofile);
        println!("  -> Packet Worker Tasks : {} concurrent worker(s)", params.worker_threads);
        println!("  -> Internal Ring Queue : {} slots", params.internal_channel_capacity);
        println!("==================================================================\n");
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_5_users_on_1gb_ram() {
        let res = GuardrailEngine::evaluate(5, 1024, 2);
        assert_eq!(res.requested_tier, CapacityTier::Tier1);
        assert_eq!(res.effective_params.tier, CapacityTier::Tier1);
        assert_eq!(res.guardrail_applied, false);
        assert_eq!(res.effective_params.rmem_max, 4_194_304);
        assert_eq!(res.effective_params.worker_threads, 1);
    }

    #[test]
    fn test_100_users_on_8gb_ram() {
        let res = GuardrailEngine::evaluate(100, 8192, 8);
        assert_eq!(res.requested_tier, CapacityTier::Tier4);
        assert_eq!(res.effective_params.tier, CapacityTier::Tier4);
        assert_eq!(res.guardrail_applied, false);
        assert_eq!(res.effective_params.rmem_max, 33_554_432);
        assert_eq!(res.effective_params.nf_conntrack_max, 262_144);
        assert_eq!(res.effective_params.worker_threads, 8);
    }

    #[test]
    fn test_100_users_on_512mb_ram_guardrail() {
        // 100 users requests Tier 4 (needs ~150MB budget).
        // 512MB RAM has a 25% budget of 128MB. Tier 4 will exceed this, triggering guardrail clamp!
        let res = GuardrailEngine::evaluate(100, 512, 1);
        assert_eq!(res.requested_tier, CapacityTier::Tier4);
        assert!(res.guardrail_applied);
        assert!(res.effective_params.tier < CapacityTier::Tier4);
        assert!(res.warning.is_some());
        // CPU clamp: 1 core -> 1 worker thread
        assert_eq!(res.effective_params.worker_threads, 1);
    }

    #[test]
    fn test_100_users_on_93mb_ram_nano_guardrail() {
        // Nano VPS scenario: 93 MB RAM (< 256MB)
        let res = GuardrailEngine::evaluate(100, 93, 1);
        assert_eq!(res.requested_tier, CapacityTier::Tier4);
        assert!(res.guardrail_applied);
        assert_eq!(res.effective_params.tier, CapacityTier::Tier1);
        assert_eq!(res.effective_params.rmem_max, 2_097_152);
        assert_eq!(res.effective_params.socket_buf_size, 2 * 1024 * 1024);
        assert_eq!(res.effective_params.worker_threads, 1);
        assert!(res.warning.unwrap().contains("<256MB"));
    }

    #[test]
    fn test_live_recalculate() {
        let env = EnvironmentInfo {
            distro_name: "Alpine Linux".into(),
            distro_id: "alpine".into(),
            is_alpine: true,
            is_debian_ubuntu: false,
            init_system: crate::server::tuner::InitSystem::OpenRC,
            total_ram_mb: 2048,
            cpu_cores: 4,
            memory_tier: crate::server::tuner::MemoryTier::Standard,
        };

        let (mgr, initial) = CapacityManager::init(5, &env);
        assert_eq!(initial.tier, CapacityTier::Tier1);
        assert_eq!(mgr.provisioned_users(), 5);

        // Recalculate to 40 users (Tier 3)
        let (updated, guard, _) = mgr.recalculate(40);
        assert_eq!(updated.tier, CapacityTier::Tier3);
        assert_eq!(mgr.provisioned_users(), 40);
        assert_eq!(guard, false);
        assert_eq!(updated.rmem_max, 16_777_216);
    }
}
