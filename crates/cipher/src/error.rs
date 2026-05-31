//! Typed cipher errors (REQ-GOV-012); never embed secret material.
use thiserror::Error;

/// Errors from the cipher layer.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum CipherError {
    /// A key did not have the required length.
    #[error("bad key length")]
    BadKeyLength,
    /// AEAD encryption/decryption failed (tamper, wrong key, or wrong nonce).
    #[error("AEAD operation failed")]
    Aead,
    /// The per-key nonce space was exhausted; the key must be rotated.
    #[error("nonce space exhausted; rotate the key")]
    NonceExhausted,
    /// A signing operation failed.
    #[error("signing failed")]
    Signing,
    /// A secure-random draw failed.
    #[error("randomness failure")]
    Random,
    /// An ECIES operation failed.
    #[error("ECIES failure")]
    Ecies,
}
