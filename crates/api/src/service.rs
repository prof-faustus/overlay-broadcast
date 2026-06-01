//! The service orchestrator. Admits a [`Request`] through the boundary checks in order —
//! size limit, authentication (signature + expiry + replay), rate limit — then executes it
//! on the [`Backend`], audits the outcome, enforces the timeout budget, and accepts a
//! chain-terminating result only if it roots in the [`HeaderChain`] (REQ-API-001..007).
use crate::audit::{AuditEntry, AuditLog};
use crate::auth::{CallerRegistry, NonceStore};
use crate::backend::Backend;
use crate::config::ApiConfig;
use crate::error::ApiError;
use crate::ratelimit::RateLimiter;
use crate::request::Request;
use bsv::{Hash256, HeaderChain};
use std::time::Instant;

/// The boundary service over a concrete [`Backend`].
pub struct ApiService<B: Backend> {
    config: ApiConfig,
    callers: CallerRegistry,
    nonces: NonceStore,
    limiter: RateLimiter,
    audit: AuditLog,
    header_chain: HeaderChain,
    backend: B,
}

impl<B: Backend> ApiService<B> {
    /// Construct the service, validating configuration up front (REQ-API-006).
    ///
    /// # Errors
    /// [`ApiError::Config`] if the configuration is invalid.
    pub fn new(
        config: ApiConfig,
        callers: CallerRegistry,
        header_chain: HeaderChain,
        backend: B,
    ) -> Result<Self, ApiError> {
        config.validate()?;
        let limiter = RateLimiter::new(config.rate_limit_per_window, config.rate_window_secs);
        Ok(Self {
            config,
            callers,
            nonces: NonceStore::new(),
            limiter,
            audit: AuditLog::new(),
            header_chain,
            backend,
        })
    }

    /// Handle one request at wall-clock time `now_unix` (Unix seconds).
    ///
    /// # Errors
    /// A typed [`ApiError`] for any rejected boundary condition or backend failure.
    pub fn handle(&mut self, request: &Request, now_unix: u64) -> Result<Vec<u8>, ApiError> {
        if request.payload.len() > self.config.max_payload_bytes {
            return Err(ApiError::Oversize);
        }
        if request.operation.requires_auth() {
            self.authenticate(request, now_unix)?;
        }
        let started = Instant::now();
        let result = self.backend.execute(request.operation, &request.payload);
        let elapsed = started.elapsed().as_millis();
        let outcome = if result.is_ok() { "ok" } else { "error" };
        self.audit.record(
            now_unix,
            &request.caller,
            request.operation.name(),
            request.position.clone(),
            outcome,
        );
        if elapsed > self.config.op_timeout_millis {
            return Err(ApiError::Timeout);
        }
        let response = result?;
        if let Some(root) = response.chain_root {
            self.assert_terminates(&root)?;
        }
        Ok(response.data)
    }

    fn authenticate(&mut self, request: &Request, now_unix: u64) -> Result<(), ApiError> {
        let public_key = self
            .callers
            .public_key(&request.caller)
            .ok_or(ApiError::Unauthorized)?;
        if request.expiry_unix < now_unix {
            return Err(ApiError::Expired);
        }
        let prehash = request.signing_prehash();
        if !ckd::verify_der_prehash(public_key, &prehash, &request.signature) {
            return Err(ApiError::Unauthorized);
        }
        if !self.nonces.check_and_record(&request.caller, request.nonce) {
            return Err(ApiError::Replay);
        }
        if !self.limiter.allow(&request.caller, now_unix) {
            return Err(ApiError::RateLimited);
        }
        Ok(())
    }

    /// Confirm a chain-terminating verification roots in the header chain (REQ-API-007).
    ///
    /// # Errors
    /// [`ApiError::NotTerminated`] if the root is not in the chain.
    pub fn assert_terminates(&self, root: &Hash256) -> Result<(), ApiError> {
        if self.header_chain.contains_merkle_root(root).is_some() {
            Ok(())
        } else {
            Err(ApiError::NotTerminated)
        }
    }

    /// The audit log.
    #[must_use]
    pub fn audit_entries(&self) -> &[AuditEntry] {
        self.audit.entries()
    }
}
