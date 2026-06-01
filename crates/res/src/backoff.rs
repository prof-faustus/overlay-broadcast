//! Bounded exponential backoff (REQ-RES-001). The delay doubles each attempt and is
//! capped at a maximum, so retries never grow unbounded.
/// A bounded exponential backoff schedule.
#[derive(Clone, Copy, Debug)]
pub struct BoundedBackoff {
    base_millis: u64,
    max_millis: u64,
}

impl BoundedBackoff {
    /// A schedule starting at `base_millis`, capped at `max_millis`.
    #[must_use]
    pub fn new(base_millis: u64, max_millis: u64) -> Self {
        Self {
            base_millis,
            max_millis,
        }
    }

    /// The delay before retry `attempt` (0-based): `base * 2^attempt`, capped at the max.
    #[must_use]
    pub fn delay_millis(&self, attempt: u32) -> u64 {
        let factor = 1u64.checked_shl(attempt).unwrap_or(u64::MAX);
        self.base_millis.saturating_mul(factor).min(self.max_millis)
    }
}
