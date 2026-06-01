//! Typed resilience errors.
use thiserror::Error;

/// Errors from the resilience layer.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ResError {
    /// Invalid parameters (e.g. threshold greater than the party count).
    #[error("invalid parameters")]
    BadParams,
    /// Fewer than the threshold signers are available; the operation fails cleanly.
    #[error("below signing quorum")]
    BelowQuorum,
    /// The BSV node is unavailable (the circuit breaker is open).
    #[error("node unavailable")]
    NodeUnavailable,
}
