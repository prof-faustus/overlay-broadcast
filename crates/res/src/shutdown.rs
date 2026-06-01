//! Graceful shutdown (REQ-RES-005). An in-flight session transaction must never be left
//! half-signed in a way that could be abused: on shutdown an operation either completes (if
//! already committed) or rolls back to a clean state, discarding any partial signatures.
/// The signing progress of an in-flight session transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InFlightSession {
    member_signed: bool,
    broadcaster_signed: bool,
    committed: bool,
}

/// The result of a graceful shutdown for one in-flight session.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ShutdownOutcome {
    /// The transaction was fully committed and is left intact.
    Completed,
    /// Partial signatures were discarded, leaving a clean state.
    RolledBack,
}

impl InFlightSession {
    /// A fresh, unsigned in-flight session.
    #[must_use]
    pub fn new() -> Self {
        Self {
            member_signed: false,
            broadcaster_signed: false,
            committed: false,
        }
    }

    /// Apply the member signature.
    pub fn sign_member(&mut self) {
        self.member_signed = true;
    }

    /// Apply the broadcaster signature.
    pub fn sign_broadcaster(&mut self) {
        self.broadcaster_signed = true;
    }

    /// Commit the fully-signed transaction.
    pub fn commit(&mut self) {
        if self.member_signed && self.broadcaster_signed {
            self.committed = true;
        }
    }

    /// Whether the transaction is half-signed (one signature present, not committed) — the
    /// abusable state that shutdown must never leave behind.
    #[must_use]
    pub fn is_half_signed(&self) -> bool {
        !self.committed && (self.member_signed != self.broadcaster_signed)
    }

    /// Gracefully shut down: complete if committed, otherwise roll back to a clean state.
    pub fn graceful_shutdown(&mut self) -> ShutdownOutcome {
        if self.committed {
            return ShutdownOutcome::Completed;
        }
        self.member_signed = false;
        self.broadcaster_signed = false;
        ShutdownOutcome::RolledBack
    }
}

impl Default for InFlightSession {
    fn default() -> Self {
        Self::new()
    }
}
