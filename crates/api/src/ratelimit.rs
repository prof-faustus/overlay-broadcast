//! Per-caller fixed-window rate limiting (REQ-API-005). Each caller may perform up to
//! `limit` signed operations per `window_secs`; further requests in the same window are
//! refused until the window rolls over.
use std::collections::HashMap;

/// A fixed-window per-caller rate limiter.
#[derive(Clone, Debug)]
pub struct RateLimiter {
    limit: u32,
    window_secs: u64,
    windows: HashMap<String, (u64, u32)>,
}

impl RateLimiter {
    /// Create a limiter allowing `limit` requests per `window_secs`.
    #[must_use]
    pub fn new(limit: u32, window_secs: u64) -> Self {
        Self {
            limit,
            window_secs: window_secs.max(1),
            windows: HashMap::new(),
        }
    }

    /// Account for a request at `now` (Unix seconds); returns `true` if within budget.
    pub fn allow(&mut self, caller: &str, now: u64) -> bool {
        let current = now / self.window_secs;
        let entry = self
            .windows
            .entry(caller.to_owned())
            .or_insert((current, 0));
        if entry.0 != current {
            *entry = (current, 0);
        }
        if entry.1 >= self.limit {
            return false;
        }
        entry.1 = entry.1.saturating_add(1);
        true
    }
}
