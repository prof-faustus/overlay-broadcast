//! Structured JSON logging/tracing setup (REQ-OBS-002/004). Installs a level-configurable
//! JSON `tracing-subscriber` as the global default. Span/event fields must route secrets
//! through [`crate::Redacted`]; this module provides the transport, not the redaction.
use crate::error::ObsError;
use tracing_subscriber::fmt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::EnvFilter;

/// Initialize JSON structured logging globally with the given default level filter (e.g.
/// `"info"`); the `RUST_LOG` environment variable overrides it.
///
/// # Errors
/// [`ObsError::Logging`] if the filter is invalid or a global subscriber is already set.
pub fn init_json(default_level: &str) -> Result<(), ObsError> {
    let filter = EnvFilter::try_new(default_level).map_err(|_| ObsError::Logging)?;
    fmt()
        .json()
        .with_env_filter(filter)
        .finish()
        .try_init()
        .map_err(|_| ObsError::Logging)
}
