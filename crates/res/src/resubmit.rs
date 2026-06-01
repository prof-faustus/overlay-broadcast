//! Idempotent transaction resubmission keyed by txid (REQ-RES-002). Resubmitting a known
//! transaction is a no-op (never a double-spend); a mempool eviction is detected and
//! triggers a re-broadcast. Fee bumping is NOT used: BSV fees are stable (stated, not
//! assumed), so there is deliberately no fee-bump path.
use std::collections::HashSet;

/// The outcome of a submission attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SubmitOutcome {
    /// A new transaction was broadcast.
    Broadcast,
    /// The transaction is already known; submission is a no-op.
    AlreadyKnown,
    /// A previously-evicted transaction was re-broadcast.
    Rebroadcast,
}

/// Tracks known and evicted transactions for idempotent resubmission.
#[derive(Clone, Debug, Default)]
pub struct Resubmitter {
    known: HashSet<[u8; 32]>,
    evicted: HashSet<[u8; 32]>,
}

impl Resubmitter {
    /// An empty resubmitter.
    #[must_use]
    pub fn new() -> Self {
        Self {
            known: HashSet::new(),
            evicted: HashSet::new(),
        }
    }

    /// Submit a transaction by txid. A first submission broadcasts; a repeat is a no-op.
    pub fn submit(&mut self, txid: [u8; 32]) -> SubmitOutcome {
        if self.known.contains(&txid) {
            return SubmitOutcome::AlreadyKnown;
        }
        let _ = self.known.insert(txid);
        SubmitOutcome::Broadcast
    }

    /// Record that the node evicted a transaction from its mempool.
    pub fn mark_evicted(&mut self, txid: [u8; 32]) {
        if self.known.contains(&txid) {
            let _ = self.evicted.insert(txid);
        }
    }

    /// Re-broadcast an evicted transaction; a no-op if it was not evicted.
    pub fn resubmit_evicted(&mut self, txid: [u8; 32]) -> SubmitOutcome {
        if self.evicted.remove(&txid) {
            SubmitOutcome::Rebroadcast
        } else {
            SubmitOutcome::AlreadyKnown
        }
    }
}
