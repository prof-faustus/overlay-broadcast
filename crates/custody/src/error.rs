//! Typed custody errors (REQ-GOV-012); no secret material in any message.
use thiserror::Error;

/// Errors from the custody layer.
#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum CustodyError {
    /// Invalid threshold parameters (e.g. threshold > shares).
    #[error("invalid threshold parameters")]
    BadParams,
    /// Too few shares to sign / reconstruct.
    #[error("insufficient shares")]
    InsufficientShares,
    /// A share or key was invalid.
    #[error("invalid share or key")]
    BadShare,
    /// A revealed nonce did not match its round-one commitment.
    #[error("nonce commitment mismatch")]
    BadCommitment,
    /// A signing operation failed.
    #[error("signing failed")]
    Signing,
    /// The key has been revoked.
    #[error("key is revoked")]
    Revoked,
    /// A secure-random draw failed.
    #[error("randomness failure")]
    Random,
}
