//! Typed API errors (REQ-API-002). Each maps to an HTTP-equivalent status; messages are
//! static and never contain secrets.
use thiserror::Error;

/// Errors returned at the service boundary.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ApiError {
    /// Malformed / invalid input (400).
    #[error("bad request: {0}")]
    BadRequest(&'static str),
    /// Missing or invalid caller signature (401).
    #[error("unauthorized")]
    Unauthorized,
    /// A replayed request nonce (401).
    #[error("replayed nonce")]
    Replay,
    /// An expired request (401).
    #[error("expired request")]
    Expired,
    /// Payload exceeds the configured size limit (413).
    #[error("payload too large")]
    Oversize,
    /// Per-caller rate limit exceeded (429).
    #[error("rate limit exceeded")]
    RateLimited,
    /// The operation exceeded its timeout budget (504).
    #[error("operation timed out")]
    Timeout,
    /// A chain-terminating result did not terminate in the HeaderChain trust root (409).
    #[error("verification does not terminate in the header chain")]
    NotTerminated,
    /// Invalid configuration at startup (500, fail-fast).
    #[error("invalid configuration: {0}")]
    Config(&'static str),
    /// A backend operation failed (500).
    #[error("internal error")]
    Internal,
}

impl ApiError {
    /// The HTTP-equivalent status code (REQ-API-002).
    #[must_use]
    pub fn status(&self) -> u16 {
        match self {
            ApiError::BadRequest(_) => 400,
            ApiError::Unauthorized | ApiError::Replay | ApiError::Expired => 401,
            ApiError::Oversize => 413,
            ApiError::RateLimited => 429,
            ApiError::Timeout => 504,
            ApiError::NotTerminated => 409,
            ApiError::Config(_) | ApiError::Internal => 500,
        }
    }
}
