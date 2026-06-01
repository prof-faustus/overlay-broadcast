//! Typed observability errors.
use thiserror::Error;

/// Errors from the observability layer.
#[derive(Debug, Error)]
pub enum ObsError {
    /// A metric could not be registered (e.g. a duplicate series).
    #[error("metric registration failed")]
    Registration,
    /// Encoding the metrics exposition format failed.
    #[error("metrics encoding failed")]
    Encoding,
    /// Initializing structured logging/tracing failed (e.g. already initialized).
    #[error("logging initialization failed")]
    Logging,
}
