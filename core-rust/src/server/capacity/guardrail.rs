//! Hardware Guardrail Engine.
//! Protects low-spec cloud instances (e.g. 128MB/512MB Alpine VPS) against out-of-memory
//! crashes (OOM) by capping buffer sizes and conntrack limits within a strict 25% RAM ceiling.

use super::tiers::{CapacityParams, CapacityTier};

#[derive(Debug, Clone)]
pub struct GuardrailResult {
    pub effective_params: CapacityParams,
    pub requested_tier: CapacityTier,
    pub guardrail_applied: bool,
    pub warning: Option<String>,
}

pub struct GuardrailEngine;

impl GuardrailEngine {
    /// Calculate the estimated kernel memory consumption of a given CapacityParams (in bytes).
    pub fn estimate_memory_footprint(params: &CapacityParams) -> u64 {
        // Average kernel slab allocation:
        // ~2 socket pairs actively buffered (wire + tun)
        let socket_buffer_est = (params.rmem_max as u64 + params.wmem_max as u64) * 2;
        // nf_conntrack struct in Linux kernel is approximately 320 bytes per tracked flow
        let conntrack_est = params.nf_conntrack_max as u64 * 320;
        socket_buffer_est + conntrack_est
    }

    /// Evaluates requested tier against actual server RAM and CPU cores, applying guardrails if needed.
    pub fn evaluate(provisioned_users: usize, total_ram_mb: u64, cpu_cores: usize) -> GuardrailResult {
        let requested_tier = CapacityTier::from_user_count(provisioned_users);
        let mut params = requested_tier.baseline_params(provisioned_users);

        let total_ram_bytes = total_ram_mb * 1024 * 1024;
        let max_safe_budget_bytes = total_ram_bytes * 25 / 100; // 25% hardware safety ceiling

        let mut guardrail_applied = false;
        let mut warning = None;

        // 1. Check for Ultra-Low RAM VPS (< 256MB RAM, such as 93MB Alpine VPS)
        if total_ram_mb < 256 {
            let nano_params = CapacityParams {
                tier: CapacityTier::Tier1,
                provisioned_users,
                rmem_max: 2_097_152,           // 2 MB max
                wmem_max: 2_097_152,           // 2 MB max
                netdev_max_backlog: 2_048,
                nf_conntrack_max: 16_384,
                rlimit_nofile: 8_192,
                internal_channel_capacity: 512,
                worker_threads: 1,
                socket_buf_size: 2 * 1024 * 1024,
            };

            if requested_tier > CapacityTier::Tier1 {
                guardrail_applied = true;
                warning = Some(format!(
                    "Provisioned users ({}) requested {}, but host RAM is only {} MB (<256MB). Clamped to Nano-Tier to prevent OOM crash.",
                    provisioned_users,
                    requested_tier.name(),
                    total_ram_mb
                ));
            } else if params.rmem_max > 2_097_152 {
                // Tier 1 baseline is 4MB, clamp to 2MB for <256MB RAM
                guardrail_applied = true;
                warning = Some(format!(
                    "Host RAM is {} MB (<256MB). Clamped socket buffers to 2 MB for ultra-light stability.",
                    total_ram_mb
                ));
            }

            params = nano_params;
        } else {
            // Standard Cloud VPS (>= 256MB RAM)
            let est_mem = Self::estimate_memory_footprint(&params);

            if est_mem > max_safe_budget_bytes {
                guardrail_applied = true;
                let original_tier = requested_tier;

                // Candidate fallback tiers in descending order
                let fallbacks = [CapacityTier::Tier3, CapacityTier::Tier2, CapacityTier::Tier1];
                let mut chosen_tier = CapacityTier::Tier1;

                for fb in fallbacks {
                    if fb < original_tier {
                        let candidate_params = fb.baseline_params(provisioned_users);
                        let candidate_mem = Self::estimate_memory_footprint(&candidate_params);
                        if candidate_mem <= max_safe_budget_bytes {
                            chosen_tier = fb;
                            params = candidate_params;
                            break;
                        }
                    }
                }

                if chosen_tier == CapacityTier::Tier1 {
                    params = CapacityTier::Tier1.baseline_params(provisioned_users);
                }

                warning = Some(format!(
                    "Provisioned users ({}) requested {} requiring ~{} MB budget (> 25% of {} MB RAM). Clamped to {} to prevent OOM crash.",
                    provisioned_users,
                    original_tier.name(),
                    est_mem / (1024 * 1024),
                    total_ram_mb,
                    params.tier.name()
                ));
            }
        }

        // 2. CPU Cores Guardrail
        let original_workers = params.worker_threads;
        params.worker_threads = std::cmp::min(cpu_cores, params.worker_threads);
        if cpu_cores == 1 {
            params.worker_threads = 1;
        }

        if params.worker_threads < original_workers && warning.is_none() {
            guardrail_applied = true;
            warning = Some(format!(
                "Host CPU has {} core(s). Worker threads adjusted from {} to {} to minimize context-switch overhead.",
                cpu_cores, original_workers, params.worker_threads
            ));
        }

        GuardrailResult {
            effective_params: params,
            requested_tier,
            guardrail_applied,
            warning,
        }
    }
}
