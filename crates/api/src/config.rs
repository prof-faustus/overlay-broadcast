//! Service configuration, validated at startup (REQ-API-006). Invalid configuration fails
//! fast with a clear, non-secret error.
use crate::error::ApiError;

/// Boundary limits and budgets for the service.
#[derive(Clone, Debug)]
pub struct ApiConfig {
    /// Maximum accepted request payload size in bytes (REQ-API-005).
    pub max_payload_bytes: usize,
    /// Allowed signed operations per caller per window (REQ-API-005).
    pub rate_limit_per_window: u32,
    /// The rate-limit window length in seconds.
    pub rate_window_secs: u64,
    /// Per-operation timeout budget in milliseconds (REQ-API-005).
    pub op_timeout_millis: u128,
}

impl ApiConfig {
    /// Validate the configuration.
    ///
    /// # Errors
    /// [`ApiError::Config`] naming the first invalid field.
    pub fn validate(&self) -> Result<(), ApiError> {
        if self.max_payload_bytes == 0 {
            return Err(ApiError::Config("max_payload_bytes must be > 0"));
        }
        if self.rate_limit_per_window == 0 {
            return Err(ApiError::Config("rate_limit_per_window must be > 0"));
        }
        if self.rate_window_secs == 0 {
            return Err(ApiError::Config("rate_window_secs must be > 0"));
        }
        if self.op_timeout_millis == 0 {
            return Err(ApiError::Config("op_timeout_millis must be > 0"));
        }
        Ok(())
    }
}
