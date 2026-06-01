//! Resilience and state recovery (Section 18).
//!
//! - [`backoff`] / [`breaker`] — bounded-backoff retry and a circuit breaker that fails
//!   readiness when the node is persistently unreachable (REQ-RES-001).
//! - [`resubmit`] — idempotent txid-keyed resubmission with eviction re-broadcast, no fee
//!   bumping (REQ-RES-002).
//! - [`quorum`] — threshold availability: tolerate `n-k` unavailable, fail cleanly below
//!   quorum (REQ-RES-003).
//! - [`recovery`] — deterministic rebuild of session state from the on-chain ledger
//!   (REQ-RES-004).
//! - [`shutdown`] — graceful shutdown that never leaves a half-signed session
//!   transaction (REQ-RES-005).
#![forbid(unsafe_code)]

pub mod backoff;
pub mod breaker;
pub mod error;
pub mod quorum;
pub mod recovery;
pub mod resubmit;
pub mod shutdown;

pub use backoff::BoundedBackoff;
pub use breaker::{BreakerState, CircuitBreaker};
pub use error::ResError;
pub use quorum::{check_quorum, tolerable_unavailable};
pub use recovery::{rebuild_from_chain, LedgerSnapshot, MemberRecord, MemberStatus, SessionState};
pub use resubmit::{Resubmitter, SubmitOutcome};
pub use shutdown::{InFlightSession, ShutdownOutcome};

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;
    use obs::{readiness, DependencyProbe};

    struct NodeProbe(bool);
    impl DependencyProbe for NodeProbe {
        fn name(&self) -> &str {
            "bsv-node"
        }
        fn is_up(&self) -> bool {
            self.0
        }
    }

    // TST-RES-001: the breaker opens after a threshold of consecutive failures (failing
    // readiness), backoff grows and caps, and a half-open trial success recovers it.
    #[test]
    fn tst_res_001_backoff_breaker_recovery() {
        let backoff = BoundedBackoff::new(100, 2_000);
        assert_eq!(backoff.delay_millis(0), 100);
        assert_eq!(backoff.delay_millis(1), 200);
        assert_eq!(backoff.delay_millis(4), 1_600);
        assert_eq!(backoff.delay_millis(10), 2_000, "delay is capped");
        assert_eq!(
            backoff.delay_millis(64),
            2_000,
            "huge attempt does not overflow"
        );

        let mut breaker = CircuitBreaker::new(3);
        breaker.record_failure();
        breaker.record_failure();
        assert!(!breaker.is_tripped(), "not yet at threshold");
        breaker.record_failure();
        assert!(breaker.is_tripped(), "breaker opens at threshold");

        // readiness fails closed while the breaker is open
        let down: Vec<Box<dyn DependencyProbe>> = vec![Box::new(NodeProbe(!breaker.is_tripped()))];
        assert!(
            !readiness(&down).ready,
            "readiness fails while node is down"
        );

        // recovery: half-open trial then success closes the breaker
        breaker.trial();
        assert_eq!(breaker.state(), BreakerState::HalfOpen);
        breaker.record_success();
        assert!(!breaker.is_tripped(), "breaker closes after recovery");
        let up: Vec<Box<dyn DependencyProbe>> = vec![Box::new(NodeProbe(!breaker.is_tripped()))];
        assert!(readiness(&up).ready, "readiness recovers");
    }

    // TST-RES-002: resubmission is idempotent by txid; eviction triggers a single rebroadcast.
    #[test]
    fn tst_res_002_idempotent_resubmission() {
        let mut resubmitter = Resubmitter::new();
        let txid = [0x11u8; 32];
        assert_eq!(resubmitter.submit(txid), SubmitOutcome::Broadcast);
        assert_eq!(
            resubmitter.submit(txid),
            SubmitOutcome::AlreadyKnown,
            "repeat is a no-op"
        );

        resubmitter.mark_evicted(txid);
        assert_eq!(
            resubmitter.resubmit_evicted(txid),
            SubmitOutcome::Rebroadcast
        );
        assert_eq!(
            resubmitter.resubmit_evicted(txid),
            SubmitOutcome::AlreadyKnown,
            "only rebroadcast once"
        );

        // an unknown txid cannot be marked evicted / rebroadcast
        let other = [0x22u8; 32];
        resubmitter.mark_evicted(other);
        assert_eq!(
            resubmitter.resubmit_evicted(other),
            SubmitOutcome::AlreadyKnown
        );
    }

    // TST-RES-003: quorum tolerates up to n-k unavailable; below quorum fails cleanly.
    #[test]
    fn tst_res_003_quorum_tolerance() {
        // 3-of-5: tolerate 2 unavailable
        assert_eq!(tolerable_unavailable(3, 5), 2);
        assert!(check_quorum(3, 3, 5).is_ok(), "exactly quorum signs");
        assert!(check_quorum(5, 3, 5).is_ok(), "all available signs");
        assert_eq!(
            check_quorum(2, 3, 5),
            Err(ResError::BelowQuorum),
            "below quorum fails cleanly"
        );
        assert_eq!(
            check_quorum(3, 6, 5),
            Err(ResError::BadParams),
            "threshold > n is rejected"
        );
    }

    // TST-RES-004: session state rebuilds deterministically from the on-chain snapshot
    // (kill-restart reproduces the exact pre-restart state).
    #[test]
    fn tst_res_004_state_rebuild() {
        let snapshot = LedgerSnapshot {
            members: vec![
                MemberRecord {
                    member_id: 3,
                    output_spent: true,
                    expiry: 100,
                },
                MemberRecord {
                    member_id: 1,
                    output_spent: false,
                    expiry: 2_000,
                },
                MemberRecord {
                    member_id: 2,
                    output_spent: false,
                    expiry: 100,
                },
            ],
            graph_root: [0xABu8; 32],
            now: 1_000,
        };
        let before = rebuild_from_chain(&snapshot);
        // member 1 active (unspent, not expired), 2 revoked (unspent, expired), 3 renewed (spent)
        assert_eq!(
            before.statuses,
            vec![
                (1, MemberStatus::Active),
                (2, MemberStatus::Revoked),
                (3, MemberStatus::Renewed)
            ]
        );

        // "restart": rebuild from the same chain snapshot yields identical state
        let after = rebuild_from_chain(&snapshot);
        assert_eq!(before, after, "kill-restart rebuilds the exact state");
    }

    // TST-RES-005: graceful shutdown never leaves a half-signed transaction; committed work
    // is preserved, partial work is rolled back to clean.
    #[test]
    fn tst_res_005_graceful_shutdown() {
        // half-signed (member only): shutdown rolls back to clean
        let mut partial = InFlightSession::new();
        partial.sign_member();
        assert!(partial.is_half_signed(), "one signature, not committed");
        assert_eq!(partial.graceful_shutdown(), ShutdownOutcome::RolledBack);
        assert!(
            !partial.is_half_signed(),
            "no half-signed transaction remains"
        );

        // fully committed: shutdown preserves it
        let mut complete = InFlightSession::new();
        complete.sign_member();
        complete.sign_broadcaster();
        complete.commit();
        assert!(!complete.is_half_signed());
        assert_eq!(complete.graceful_shutdown(), ShutdownOutcome::Completed);
    }
}
