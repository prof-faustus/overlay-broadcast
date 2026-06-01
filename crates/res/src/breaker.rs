//! A circuit breaker for a persistently-unreachable BSV node (REQ-RES-001). After a
//! threshold of consecutive failures the breaker opens and reports the node down (so
//! readiness fails closed). A half-open trial after recovery closes the breaker on the
//! next success, or reopens it on a further failure.
/// The breaker state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BreakerState {
    /// Requests flow normally.
    Closed,
    /// The node is considered down; readiness should fail.
    Open,
    /// A single trial request is permitted to test recovery.
    HalfOpen,
}

/// A consecutive-failure circuit breaker.
#[derive(Clone, Copy, Debug)]
pub struct CircuitBreaker {
    threshold: u32,
    failures: u32,
    state: BreakerState,
}

impl CircuitBreaker {
    /// A closed breaker that opens after `threshold` consecutive failures.
    #[must_use]
    pub fn new(threshold: u32) -> Self {
        Self {
            threshold: threshold.max(1),
            failures: 0,
            state: BreakerState::Closed,
        }
    }

    /// The current state.
    #[must_use]
    pub fn state(&self) -> BreakerState {
        self.state
    }

    /// Whether the breaker is open (the node is considered unavailable).
    #[must_use]
    pub fn is_tripped(&self) -> bool {
        matches!(self.state, BreakerState::Open)
    }

    /// Record a successful node interaction: resets failures and closes the breaker.
    pub fn record_success(&mut self) {
        self.failures = 0;
        self.state = BreakerState::Closed;
    }

    /// Record a failed node interaction: opens the breaker once the threshold is reached.
    pub fn record_failure(&mut self) {
        self.failures = self.failures.saturating_add(1);
        if self.failures >= self.threshold {
            self.state = BreakerState::Open;
        }
    }

    /// Permit a half-open trial after the breaker has opened.
    pub fn trial(&mut self) {
        if matches!(self.state, BreakerState::Open) {
            self.state = BreakerState::HalfOpen;
        }
    }
}
