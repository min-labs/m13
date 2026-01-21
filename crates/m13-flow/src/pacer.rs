#![forbid(unsafe_code)]
use crate::bbr::RateEstimator;

/// The Token Bucket Traffic Shaper.
pub struct Pacer {
    estimator: RateEstimator,
    last_update_us: u64,
    tokens: i64, // Bytes allowed to send
    min_rate_floor: u64, // CBR Floor (Bytes/sec)
}

impl Pacer {
    pub fn new(min_cbr_bps: u64) -> Self {
        Self {
            estimator: RateEstimator::new(),
            last_update_us: 0,
            tokens: 0,
            min_rate_floor: min_cbr_bps / 8,
        }
    }

    /// Update token bucket based on elapsed time.
    /// Returns: Bytes allowed to send NOW.
    pub fn tick(&mut self, now_us: u64) -> u64 {
        if self.last_update_us == 0 {
            self.last_update_us = now_us;
            return 0;
        }

        let delta = now_us.saturating_sub(self.last_update_us);
        self.last_update_us = now_us;

        // Target Rate = Max(BBR_Estimate, CBR_Floor)
        // This enforces security (Chaff) even if BBR estimates low bandwidth.
        let target_rate = core::cmp::max(
            self.estimator.get_pacing_rate_bps(now_us) / 8,
            self.min_rate_floor
        );

        // Add tokens: (Bytes/sec * us) / 1M
        // Use u128 to prevent overflow
        let new_tokens = (target_rate as u128 * delta as u128) / 1_000_000;
        
        // Cap bucket size to avoid massive bursts (Max Burst = 100ms worth)
        let max_burst = target_rate / 10; 
        
        self.tokens = core::cmp::min(self.tokens + new_tokens as i64, max_burst as i64);

        if self.tokens > 0 { self.tokens as u64 } else { 0 }
    }

    /// Deduce tokens for a packet.
    pub fn consume(&mut self, bytes: usize) {
        self.tokens -= bytes as i64;
    }

    /// Security: Should we inject Chaff?
    /// If the bucket is full (idle) and we have unused bandwidth capacity.
    /// "Silence is a vulnerability."
    pub fn chaff_needed(&self, packet_mtu: usize) -> bool {
        self.tokens >= (packet_mtu as i64)
    }
    
    // Pass-through
    pub fn on_ack(&mut self, delivered_bps: u64, rtt_us: u64, now: u64) {
        self.estimator.on_ack(delivered_bps, rtt_us, now);
    }
}