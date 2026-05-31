//! Typed overlay errors (REQ-GOV-012).
use thiserror::Error;

/// Errors from the EP overlay layer.
#[derive(Debug, Error)]
pub enum OverlayError {
    /// A child key derivation failed.
    #[error("key derivation failed: {0}")]
    Ckd(#[from] ckd::CkdError),
    /// A cipher (obfuscation / signing) operation failed.
    #[error("cipher failure: {0}")]
    Cipher(#[from] cipher::CipherError),
    /// A graph operation failed.
    #[error("graph error: {0}")]
    Graph(#[from] keygraph::KgError),
    /// A transaction-construction or BSV operation failed.
    #[error("bsv error: {0}")]
    Bsv(#[from] bsv::BsvError),
    /// A node client operation failed.
    #[error("node error: {0}")]
    Node(#[from] bsv::NodeError),
    /// A secure-random draw failed.
    #[error("randomness failure")]
    Random,
    /// A node had no position (it does not exist).
    #[error("unknown node position")]
    UnknownPosition,
}
