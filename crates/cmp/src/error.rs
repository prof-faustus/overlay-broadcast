//! Typed compliance errors.
use thiserror::Error;

/// Errors from the compliance layer.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CmpError {
    /// Cleartext personal data was offered to the on-chain write path (REQ-CMP-001).
    #[error("cleartext personal data must never be written on-chain")]
    CleartextPersonalData,
    /// Cleartext content (any) was offered to the on-chain write path (REQ-CMP-001).
    #[error("plaintext content must never be written on-chain")]
    PlaintextOnChain,
}
