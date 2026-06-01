//! The backend seam (REQ-API-001). The service handles every cross-cutting boundary
//! concern (validation, auth, replay, rate limiting, audit, termination) and then delegates
//! the actual work to a [`Backend`], which routes to the overlay/broadcast/session/custody
//! crates. Dependency injection keeps the boundary independent of the concrete wiring and
//! makes every operation path unit-testable.
use crate::error::ApiError;
use crate::request::Operation;
use bsv::Hash256;

/// A backend operation result.
pub struct OperationResponse {
    /// The opaque response payload.
    pub data: Vec<u8>,
    /// For a chain-terminating verification, the merkle root the result claims; the service
    /// accepts it only if it terminates in the HeaderChain trust root (REQ-API-007).
    pub chain_root: Option<Hash256>,
}

impl OperationResponse {
    /// A plain (non-chain-terminating) response.
    #[must_use]
    pub fn plain(data: Vec<u8>) -> Self {
        Self {
            data,
            chain_root: None,
        }
    }

    /// A chain-terminating response carrying the merkle root to validate.
    #[must_use]
    pub fn chain_terminating(data: Vec<u8>, root: Hash256) -> Self {
        Self {
            data,
            chain_root: Some(root),
        }
    }
}

/// Executes operations after the boundary has admitted them.
pub trait Backend {
    /// Perform `operation` with `payload`, returning its response or a typed error.
    ///
    /// # Errors
    /// Any [`ApiError`] the operation produces (e.g. [`ApiError::BadRequest`] for an invalid
    /// payload, [`ApiError::Internal`] for an execution failure).
    fn execute(
        &mut self,
        operation: Operation,
        payload: &[u8],
    ) -> Result<OperationResponse, ApiError>;
}
