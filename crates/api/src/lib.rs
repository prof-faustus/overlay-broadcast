//! Service interface (Section 14): the boundary that admits external requests.
//!
//! - [`Operation`] / [`Request`] — every exposed operation and the signed request model
//!   (REQ-API-001/003).
//! - [`ApiService`] — orchestrates size validation, signature auth + nonce/expiry replay
//!   protection, per-caller rate limiting, audit logging, timeout budget, and HeaderChain
//!   termination (REQ-API-001..007).
//! - [`Backend`] — the injected seam to the overlay/broadcast/session/custody crates.
//!
//! The HTTP transport that maps these onto network requests lives in the cli/deployment
//! layer; this crate is the sync, fully-testable boundary logic.
#![forbid(unsafe_code)]

pub mod audit;
pub mod auth;
pub mod backend;
pub mod config;
pub mod error;
pub mod ratelimit;
pub mod request;
pub mod service;

pub use audit::{AuditEntry, AuditLog};
pub use auth::{CallerRegistry, NonceStore};
pub use backend::{Backend, OperationResponse};
pub use config::ApiConfig;
pub use error::ApiError;
pub use ratelimit::RateLimiter;
pub use request::{Operation, Request};
pub use service::ApiService;

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;
    use bsv::{double_sha256, BlockHeader, Hash256, HeaderChain};
    use k256::ecdsa::SigningKey;
    use k256::elliptic_curve::sec1::ToEncodedPoint;

    const ALL_OPERATIONS: [Operation; 20] = [
        Operation::OverlayWrite,
        Operation::OverlaySignalPosition,
        Operation::OverlayResolvePosition,
        Operation::OverlayObfuscate,
        Operation::OverlayDeobfuscate,
        Operation::BroadcastSessionOpen,
        Operation::BroadcastRekeyUser,
        Operation::BroadcastRekeyKey,
        Operation::BroadcastRekeyGroup,
        Operation::BroadcastMessage,
        Operation::BroadcastDecrypt,
        Operation::SessionSubscribeOffChain,
        Operation::SessionSubscribeOnBlock,
        Operation::SessionRenew,
        Operation::SessionRevoke,
        Operation::CustodyKeygen,
        Operation::CustodyRotate,
        Operation::CustodyRevoke,
        Operation::Health,
        Operation::Readiness,
    ];

    struct RecordingBackend {
        fail_on: Option<Operation>,
        chain_root: Option<Hash256>,
        calls: Vec<Operation>,
    }

    impl RecordingBackend {
        fn ok() -> Self {
            Self {
                fail_on: None,
                chain_root: None,
                calls: Vec::new(),
            }
        }
    }

    impl Backend for RecordingBackend {
        fn execute(
            &mut self,
            operation: Operation,
            _payload: &[u8],
        ) -> Result<OperationResponse, ApiError> {
            self.calls.push(operation);
            if Some(operation) == self.fail_on {
                return Err(ApiError::Internal);
            }
            match self.chain_root {
                Some(root) => Ok(OperationResponse::chain_terminating(vec![0x01], root)),
                None => Ok(OperationResponse::plain(vec![0x01])),
            }
        }
    }

    fn default_config() -> ApiConfig {
        ApiConfig {
            max_payload_bytes: 1024,
            rate_limit_per_window: 100,
            rate_window_secs: 60,
            op_timeout_millis: 5_000,
        }
    }

    fn keypair(seed: u8) -> ([u8; 32], Vec<u8>) {
        let private = [seed; 32];
        let signing = SigningKey::from_slice(&private).unwrap();
        let public = signing
            .verifying_key()
            .as_affine()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec();
        (private, public)
    }

    fn signed(
        private: &[u8; 32],
        caller: &str,
        operation: Operation,
        nonce: u64,
        expiry: u64,
    ) -> Request {
        let mut request = Request {
            caller: caller.to_owned(),
            operation,
            payload: vec![0xAA, 0xBB],
            position: None,
            nonce,
            expiry_unix: expiry,
            signature: Vec::new(),
        };
        let prehash = request.signing_prehash();
        request.signature = ckd::sign_prehash_der(private, &prehash).unwrap();
        request
    }

    fn service(
        backend: RecordingBackend,
        callers: CallerRegistry,
        chain: HeaderChain,
    ) -> ApiService<RecordingBackend> {
        ApiService::new(default_config(), callers, chain, backend).unwrap()
    }

    // TST-API-001: every operation is exposed and dispatched; the error path propagates a
    // typed error rather than panicking.
    #[test]
    fn tst_api_001_all_operations_dispatch() {
        let (private, public) = keypair(0x11);
        let mut callers = CallerRegistry::new();
        callers.register("svc", &public);
        let mut svc = service(RecordingBackend::ok(), callers, HeaderChain::new(0));
        for (index, operation) in ALL_OPERATIONS.into_iter().enumerate() {
            let nonce = u64::try_from(index).unwrap();
            let request = if operation.requires_auth() {
                signed(&private, "svc", operation, nonce, 10_000)
            } else {
                Request {
                    caller: "anon".to_owned(),
                    operation,
                    payload: Vec::new(),
                    position: None,
                    nonce,
                    expiry_unix: 0,
                    signature: Vec::new(),
                }
            };
            assert!(
                svc.handle(&request, 1_000).is_ok(),
                "{} dispatches",
                operation.name()
            );
        }

        // error path: a backend failure surfaces as a typed error
        let (p2, pk2) = keypair(0x22);
        let mut callers2 = CallerRegistry::new();
        callers2.register("svc", &pk2);
        let backend = RecordingBackend {
            fail_on: Some(Operation::OverlayWrite),
            chain_root: None,
            calls: Vec::new(),
        };
        let mut svc2 = service(backend, callers2, HeaderChain::new(0));
        let request = signed(&p2, "svc", Operation::OverlayWrite, 1, 10_000);
        assert_eq!(svc2.handle(&request, 1_000), Err(ApiError::Internal));
    }

    // TST-API-002: oversized and malformed input are rejected with typed errors; no panic.
    #[test]
    fn tst_api_002_input_validation() {
        let (private, public) = keypair(0x11);
        let mut callers = CallerRegistry::new();
        callers.register("svc", &public);
        let mut svc = service(RecordingBackend::ok(), callers, HeaderChain::new(0));

        let mut oversize = signed(&private, "svc", Operation::OverlayWrite, 1, 10_000);
        oversize.payload = vec![0u8; 2048];
        assert_eq!(svc.handle(&oversize, 1_000), Err(ApiError::Oversize));

        // an empty / malformed signature is refused, not panicked on
        let mut malformed = signed(&private, "svc", Operation::OverlayWrite, 2, 10_000);
        malformed.signature = Vec::new();
        assert_eq!(svc.handle(&malformed, 1_000), Err(ApiError::Unauthorized));
        let mut truncated = signed(&private, "svc", Operation::OverlayWrite, 3, 10_000);
        truncated.signature.truncate(4);
        assert_eq!(svc.handle(&truncated, 1_000), Err(ApiError::Unauthorized));
    }

    // TST-API-003: valid signed accepted; tampered/unsigned/replayed/expired rejected.
    #[test]
    fn tst_api_003_auth_and_replay() {
        let (private, public) = keypair(0x33);
        let mut callers = CallerRegistry::new();
        callers.register("svc", &public);
        let mut svc = service(RecordingBackend::ok(), callers, HeaderChain::new(0));

        let request = signed(&private, "svc", Operation::CustodyKeygen, 7, 10_000);
        assert!(
            svc.handle(&request, 1_000).is_ok(),
            "valid signed request accepted"
        );

        // replay of the same nonce is rejected
        assert_eq!(svc.handle(&request, 1_000), Err(ApiError::Replay));

        // tampering after signing invalidates the signature
        let mut tampered = signed(&private, "svc", Operation::CustodyKeygen, 8, 10_000);
        tampered.payload.push(0xFF);
        assert_eq!(svc.handle(&tampered, 1_000), Err(ApiError::Unauthorized));

        // an unknown caller (bare identifier, no registered key) is refused
        let stranger = signed(&private, "nobody", Operation::CustodyKeygen, 9, 10_000);
        assert_eq!(svc.handle(&stranger, 1_000), Err(ApiError::Unauthorized));

        // an expired request is rejected
        let expired = signed(&private, "svc", Operation::CustodyKeygen, 10, 500);
        assert_eq!(svc.handle(&expired, 1_000), Err(ApiError::Expired));
    }

    // TST-API-004: the audit log records operation metadata (incl. node position) and never
    // a secret — AuditEntry structurally has no payload/secret field.
    #[test]
    fn tst_api_004_audit_records_metadata() {
        let (private, public) = keypair(0x44);
        let mut callers = CallerRegistry::new();
        callers.register("svc", &public);
        let mut svc = service(RecordingBackend::ok(), callers, HeaderChain::new(0));

        let mut request = signed(&private, "svc", Operation::OverlaySignalPosition, 1, 10_000);
        request.position = Some("node-7".to_owned());
        // resign over the new position
        request.signature = ckd::sign_prehash_der(&private, &request.signing_prehash()).unwrap();
        svc.handle(&request, 1_000).unwrap();

        let entries = svc.audit_entries();
        assert_eq!(entries.len(), 1);
        let entry = &entries[0];
        assert_eq!(entry.caller, "svc");
        assert_eq!(entry.operation, "overlay.signal_position");
        assert_eq!(entry.node_position, Some("node-7".to_owned()));
        assert_eq!(entry.outcome, "ok");
    }

    // TST-API-005: per-caller rate limiting triggers under load; the timeout budget is
    // enforced.
    #[test]
    fn tst_api_005_rate_limit_and_timeout() {
        let (private, public) = keypair(0x55);
        let mut callers = CallerRegistry::new();
        callers.register("svc", &public);
        let config = ApiConfig {
            max_payload_bytes: 1024,
            rate_limit_per_window: 2,
            rate_window_secs: 60,
            op_timeout_millis: 5_000,
        };
        let mut svc =
            ApiService::new(config, callers, HeaderChain::new(0), RecordingBackend::ok()).unwrap();
        assert!(svc
            .handle(
                &signed(&private, "svc", Operation::OverlayObfuscate, 1, 10_000),
                1_000
            )
            .is_ok());
        assert!(svc
            .handle(
                &signed(&private, "svc", Operation::OverlayObfuscate, 2, 10_000),
                1_000
            )
            .is_ok());
        assert_eq!(
            svc.handle(
                &signed(&private, "svc", Operation::OverlayObfuscate, 3, 10_000),
                1_000
            ),
            Err(ApiError::RateLimited)
        );

        // timeout: a backend slower than the 1ms budget is rejected
        let (p2, pk2) = keypair(0x56);
        let mut callers2 = CallerRegistry::new();
        callers2.register("svc", &pk2);
        let slow_config = ApiConfig {
            max_payload_bytes: 1024,
            rate_limit_per_window: 10,
            rate_window_secs: 60,
            op_timeout_millis: 1,
        };
        let mut slow =
            ApiService::new(slow_config, callers2, HeaderChain::new(0), SlowBackend).unwrap();
        assert_eq!(
            slow.handle(
                &signed(&p2, "svc", Operation::OverlayObfuscate, 1, 10_000),
                1_000
            ),
            Err(ApiError::Timeout)
        );
    }

    struct SlowBackend;
    impl Backend for SlowBackend {
        fn execute(
            &mut self,
            _operation: Operation,
            _payload: &[u8],
        ) -> Result<OperationResponse, ApiError> {
            std::thread::sleep(std::time::Duration::from_millis(8));
            Ok(OperationResponse::plain(Vec::new()))
        }
    }

    // TST-API-006: invalid configuration fails fast at startup with a non-secret error.
    #[test]
    fn tst_api_006_config_validation() {
        let bad = ApiConfig {
            max_payload_bytes: 0,
            rate_limit_per_window: 1,
            rate_window_secs: 1,
            op_timeout_millis: 1,
        };
        assert_eq!(
            bad.validate(),
            Err(ApiError::Config("max_payload_bytes must be > 0"))
        );
        let result = ApiService::new(
            bad,
            CallerRegistry::new(),
            HeaderChain::new(0),
            RecordingBackend::ok(),
        );
        assert!(result.is_err());
        assert!(default_config().validate().is_ok());
    }

    // TST-API-007: a chain-terminating result is accepted only if its merkle root roots in
    // the HeaderChain trust root.
    #[test]
    fn tst_api_007_header_chain_termination() {
        let rooted = double_sha256(b"overlay-state-root");
        let unrooted = double_sha256(b"not-in-chain");

        // self-mine a minimal-difficulty header committing to `rooted`
        let mut header = BlockHeader {
            version: 1,
            prev_block_hash: Hash256::from_internal([0u8; 32]),
            merkle_root: rooted,
            time: 1_700_000_000,
            bits: 0x207f_ffff,
            nonce: 0,
        };
        while !header.meets_target() {
            header.nonce = header.nonce.checked_add(1).unwrap();
        }
        let mut chain = HeaderChain::new(700_000);
        chain.add(header).unwrap();

        let (private, public) = keypair(0x77);
        let mut callers = CallerRegistry::new();
        callers.register("svc", &public);

        let accept_backend = RecordingBackend {
            fail_on: None,
            chain_root: Some(rooted),
            calls: Vec::new(),
        };
        let mut accepting =
            ApiService::new(default_config(), callers.clone(), chain, accept_backend).unwrap();
        assert!(accepting
            .handle(
                &signed(
                    &private,
                    "svc",
                    Operation::OverlayResolvePosition,
                    1,
                    10_000
                ),
                1_000
            )
            .is_ok());

        // a result not rooted in the chain is refused
        let mut empty_chain = HeaderChain::new(700_000);
        let mut header2 = BlockHeader {
            version: 1,
            prev_block_hash: Hash256::from_internal([0u8; 32]),
            merkle_root: double_sha256(b"other"),
            time: 1_700_000_001,
            bits: 0x207f_ffff,
            nonce: 0,
        };
        while !header2.meets_target() {
            header2.nonce = header2.nonce.checked_add(1).unwrap();
        }
        empty_chain.add(header2).unwrap();
        let reject_backend = RecordingBackend {
            fail_on: None,
            chain_root: Some(unrooted),
            calls: Vec::new(),
        };
        let mut rejecting =
            ApiService::new(default_config(), callers, empty_chain, reject_backend).unwrap();
        assert_eq!(
            rejecting.handle(
                &signed(
                    &private,
                    "svc",
                    Operation::OverlayResolvePosition,
                    1,
                    10_000
                ),
                1_000
            ),
            Err(ApiError::NotTerminated)
        );
    }
}
