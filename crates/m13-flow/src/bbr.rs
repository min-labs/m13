#![forbid(unsafe_code)]

use crate::filter::{WindowedMaxFilter, WindowedMinFilter};

// Constants (Microseconds)
const BTL_BW_WINDOW: u64 = 10_000_000; // 10s (~10 RTTs)
const RT_PROP_WINDOW: u64 = 10_000_000;

#[derive(Debug, Clone, Copy, PartialEq)]
#[allow(dead_code)] // Valid BBR states reserved for future logic
pub enum BbrState {
    Startup,
    Drain,
    ProbeBw,
    ProbeRtt,
}

pub struct RateEstimator {
    #[allow(dead_code)]
    state: BbrState,
    
    // Filters
    btl_bw_filter: WindowedMaxFilter,
    rt_prop_filter: WindowedMinFilter,
    
    // State
    #[allow(dead_code)]
    last_rtt_probe: u64,
    /// Scaled by 100 (e.g. 100 = 1.0x, 125 = 1.25x)
    pacing_gain: u64, 
}

impl RateEstimator {
    pub fn new() -> Self {
        Self {
            state: BbrState::Startup,
            btl_bw_filter: WindowedMaxFilter::new(BTL_BW_WINDOW),
            rt_prop_filter: WindowedMinFilter::new(RT_PROP_WINDOW),
            last_rtt_probe: 0,
            pacing_gain: 289, // Startup Gain 2.89 (2/ln2)
        }
    }

    /// Update model with ACK info
    pub fn on_ack(&mut self, delivered_bps: u64, rtt_us: u64, now: u64) {
        self.btl_bw_filter.update(delivered_bps, now);
        self.rt_prop_filter.update(rtt_us, now);

        // NOTE: State machine transitions (Startup -> Drain) require 
        // full_pipe detection (3 rounds of non-increasing BW).
        // For this sprint, we remain in Startup to validate Gain logic.
    }

    pub fn get_pacing_rate_bps(&self, now: u64) -> u64 {
        let btl_bw = self.btl_bw_filter.get_best(now);
        // Fallback floor 1Mbps
        let bw = if btl_bw == 0 { 1_000_000 } else { btl_bw };
        
        // Rate = BW * Gain / 100
        (bw * self.pacing_gain) / 100
    }
}