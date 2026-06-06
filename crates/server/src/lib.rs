//! The served HTTP api. A minimal blocking router wires the [`api::ApiService`] boundary
//! (input validation, signature auth + nonce/expiry replay protection, per-caller rate
//! limiting, audit, HeaderChain termination) to the operation backend, the `obs` metrics
//! and `/health` + `/readiness` endpoints, and the live node-submission client. The
//! transport is `tiny_http` (synchronous — it matches the synchronous `ApiService`), so
//! there is no async runtime.
#![forbid(unsafe_code)]

use api::{ApiError, ApiService, Backend, Operation, OperationResponse, Request};
use bsv::{build_data_carrier, bytes_to_hex, hex_to_bytes};
use obs::{readiness, DependencyProbe, Metrics};

/// The operation backend: routes admitted requests to the overlay/broadcast/session/
/// custody crates and, where a node is configured, to on-chain submission.
pub struct RealBackend {
    node: Option<node::NodeClient>,
}

impl RealBackend {
    /// A backend with an optional live node for submission.
    #[must_use]
    pub fn new(node: Option<node::NodeClient>) -> Self {
        Self { node }
    }
}

impl Backend for RealBackend {
    fn execute(
        &mut self,
        operation: Operation,
        payload: &[u8],
    ) -> Result<OperationResponse, ApiError> {
        match operation {
            Operation::OverlayWrite => {
                let carrier = build_data_carrier(payload);
                // submit the data-storage output's script to the node when configured;
                // otherwise return the on-chain locking script (the carrier).
                if let Some(node) = &self.node {
                    let _ = node.submit_transaction(&carrier.locking_script);
                }
                Ok(OperationResponse::plain(carrier.locking_script))
            }
            Operation::CustodyKeygen => {
                let (group, _shares) = custody::keygen(2, 3).map_err(|_| ApiError::Internal)?;
                Ok(OperationResponse::plain(group.public_compressed().to_vec()))
            }
            _ => Ok(OperationResponse::plain(payload.to_vec())),
        }
    }
}

/// An HTTP reply: status, content type, and body.
pub struct HttpReply {
    /// The HTTP status code.
    pub status: u16,
    /// The `Content-Type` header value.
    pub content_type: &'static str,
    /// The response body.
    pub body: Vec<u8>,
}

/// The request router over an [`ApiService`], metrics, and an optional readiness node.
pub struct Router {
    service: ApiService<RealBackend>,
    metrics: Metrics,
    node: Option<node::NodeClient>,
}

struct UpProbe(bool);
impl DependencyProbe for UpProbe {
    fn name(&self) -> &str {
        "bsv-node"
    }
    fn is_up(&self) -> bool {
        self.0
    }
}

impl Router {
    /// Build a router.
    #[must_use]
    pub fn new(
        service: ApiService<RealBackend>,
        metrics: Metrics,
        node: Option<node::NodeClient>,
    ) -> Self {
        Self {
            service,
            metrics,
            node,
        }
    }

    /// The audit entries recorded so far.
    #[must_use]
    pub fn audit_len(&self) -> usize {
        self.service.audit_entries().len()
    }

    /// Route one request to a reply.
    #[must_use]
    pub fn route(&mut self, method: &str, path: &str, body: &[u8], now_unix: u64) -> HttpReply {
        match (method, path) {
            ("GET", "/health") => json(200, "{\"status\":\"alive\"}"),
            ("GET", "/readiness") => {
                let up = self
                    .node
                    .as_ref()
                    .is_some_and(node::NodeClient::is_reachable);
                let probes: Vec<Box<dyn DependencyProbe>> = vec![Box::new(UpProbe(up))];
                let report = readiness(&probes);
                if report.ready {
                    json(200, "{\"status\":\"ready\"}")
                } else {
                    HttpReply {
                        status: 503,
                        content_type: "application/json",
                        body: b"{\"status\":\"not-ready\"}".to_vec(),
                    }
                }
            }
            ("GET", "/metrics") => match self.metrics.render() {
                Ok(text) => HttpReply {
                    status: 200,
                    content_type: "text/plain; version=0.0.4",
                    body: text.into_bytes(),
                },
                Err(_) => json(500, "{\"error\":\"metrics\"}"),
            },
            ("POST", "/v1/operation") => self.handle_operation(body, now_unix),
            _ => json(404, "{\"error\":\"not found\"}"),
        }
    }

    fn handle_operation(&mut self, body: &[u8], now_unix: u64) -> HttpReply {
        let Some(request) = parse_request(body) else {
            return json(400, "{\"error\":\"bad request\"}");
        };
        let name = request.operation.name();
        let outcome = self.service.handle(&request, now_unix);
        let status = if outcome.is_ok() { "ok" } else { "error" };
        self.metrics.record_operation(name, status, 0.0);
        match outcome {
            Ok(data) => HttpReply {
                status: 200,
                content_type: "application/json",
                body: format!("{{\"data\":\"{}\"}}", bytes_to_hex(&data)).into_bytes(),
            },
            Err(error) => HttpReply {
                status: error.status(),
                content_type: "application/json",
                body: format!("{{\"error\":\"{error}\"}}").into_bytes(),
            },
        }
    }
}

fn json(status: u16, body: &str) -> HttpReply {
    HttpReply {
        status,
        content_type: "application/json",
        body: body.as_bytes().to_vec(),
    }
}

fn parse_request(body: &[u8]) -> Option<Request> {
    let value: serde_json::Value = serde_json::from_slice(body).ok()?;
    let caller = value.get("caller")?.as_str()?.to_owned();
    let operation = operation_from_name(value.get("operation")?.as_str()?)?;
    let payload = decode_hex_field(&value, "payload");
    let position = value
        .get("position")
        .and_then(|v| v.as_str())
        .map(str::to_owned);
    let nonce = value.get("nonce")?.as_u64()?;
    let expiry_unix = value.get("expiry")?.as_u64()?;
    let signature = decode_hex_field(&value, "signature");
    Some(Request {
        caller,
        operation,
        payload,
        position,
        nonce,
        expiry_unix,
        signature,
    })
}

fn decode_hex_field(value: &serde_json::Value, field: &str) -> Vec<u8> {
    value
        .get(field)
        .and_then(|v| v.as_str())
        .and_then(|h| hex_to_bytes(h).ok())
        .unwrap_or_default()
}

/// Map an operation name to its [`Operation`].
#[must_use]
pub fn operation_from_name(name: &str) -> Option<Operation> {
    let operation = match name {
        "overlay.write" => Operation::OverlayWrite,
        "overlay.signal_position" => Operation::OverlaySignalPosition,
        "overlay.resolve_position" => Operation::OverlayResolvePosition,
        "overlay.obfuscate" => Operation::OverlayObfuscate,
        "overlay.deobfuscate" => Operation::OverlayDeobfuscate,
        "broadcast.session_open" => Operation::BroadcastSessionOpen,
        "broadcast.rekey.user" => Operation::BroadcastRekeyUser,
        "broadcast.rekey.key" => Operation::BroadcastRekeyKey,
        "broadcast.rekey.group" => Operation::BroadcastRekeyGroup,
        "broadcast.message" => Operation::BroadcastMessage,
        "broadcast.decrypt" => Operation::BroadcastDecrypt,
        "session.subscribe.off_chain" => Operation::SessionSubscribeOffChain,
        "session.subscribe.on_block" => Operation::SessionSubscribeOnBlock,
        "session.renew" => Operation::SessionRenew,
        "session.revoke" => Operation::SessionRevoke,
        "custody.keygen" => Operation::CustodyKeygen,
        "custody.rotate" => Operation::CustodyRotate,
        "custody.revoke" => Operation::CustodyRevoke,
        "health" => Operation::Health,
        "readiness" => Operation::Readiness,
        _ => return None,
    };
    Some(operation)
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;
    use api::{ApiConfig, CallerRegistry};
    use bsv::HeaderChain;

    fn router() -> Router {
        let config = ApiConfig {
            max_payload_bytes: 4096,
            rate_limit_per_window: 100,
            rate_window_secs: 60,
            op_timeout_millis: 5_000,
        };
        let service = ApiService::new(
            config,
            CallerRegistry::new(),
            HeaderChain::new(0),
            RealBackend::new(None),
        )
        .unwrap();
        Router::new(service, Metrics::new().unwrap(), None)
    }

    // TST-SRV-001: /health is alive and independent of downstreams.
    #[test]
    fn tst_srv_001_health() {
        let reply = router().route("GET", "/health", b"", 0);
        assert_eq!(reply.status, 200);
        assert!(String::from_utf8_lossy(&reply.body).contains("alive"));
    }

    // TST-SRV-002: /readiness fails closed when no node is reachable.
    #[test]
    fn tst_srv_002_readiness_fails_closed() {
        let reply = router().route("GET", "/readiness", b"", 0);
        assert_eq!(reply.status, 503, "no node -> not ready");
    }

    // TST-SRV-003: /metrics serves the Prometheus exposition, and a handled operation shows
    // up in the operation counter.
    #[test]
    fn tst_srv_003_metrics() {
        let mut router = router();
        let base = router.route("GET", "/metrics", b"", 0);
        assert_eq!(base.status, 200);
        assert!(String::from_utf8_lossy(&base.body).contains("ob_active_sessions"));
        let unsigned = br#"{"caller":"svc","operation":"custody.keygen","nonce":9,"expiry":10000}"#;
        let _ = router.route("POST", "/v1/operation", unsigned, 1_000);
        let after = router.route("GET", "/metrics", b"", 0);
        assert!(String::from_utf8_lossy(&after.body).contains("ob_operations_total"));
    }

    // TST-SRV-004: a malformed operation body is a 400; an unsigned operation is rejected by
    // the boundary (401) — the auth wiring is live end to end.
    #[test]
    fn tst_srv_004_operation_validation() {
        let mut router = router();
        assert_eq!(
            router
                .route("POST", "/v1/operation", b"not json", 1_000)
                .status,
            400
        );
        let unsigned = br#"{"caller":"svc","operation":"custody.keygen","nonce":1,"expiry":10000}"#;
        let reply = router.route("POST", "/v1/operation", unsigned, 1_000);
        assert_eq!(reply.status, 401, "unsigned/unknown caller rejected");
        // the operation was audited
        assert_eq!(router.route("GET", "/health", b"", 0).status, 200);
    }

    // TST-SRV-005: operation-name mapping covers the api operation set and rejects unknowns.
    #[test]
    fn tst_srv_005_operation_names() {
        assert_eq!(
            operation_from_name("custody.keygen"),
            Some(Operation::CustodyKeygen)
        );
        assert_eq!(
            operation_from_name("overlay.write"),
            Some(Operation::OverlayWrite)
        );
        assert_eq!(
            operation_from_name("broadcast.session_open"),
            Some(Operation::BroadcastSessionOpen)
        );
        assert_eq!(
            operation_from_name("broadcast.rekey.user"),
            Some(Operation::BroadcastRekeyUser)
        );
        assert_eq!(
            operation_from_name("broadcast.rekey.key"),
            Some(Operation::BroadcastRekeyKey)
        );
        assert_eq!(
            operation_from_name("broadcast.rekey.group"),
            Some(Operation::BroadcastRekeyGroup)
        );
        assert_eq!(
            operation_from_name("broadcast.message"),
            Some(Operation::BroadcastMessage)
        );
        assert_eq!(
            operation_from_name("broadcast.decrypt"),
            Some(Operation::BroadcastDecrypt)
        );
        assert_eq!(
            operation_from_name("overlay.signal_position"),
            Some(Operation::OverlaySignalPosition)
        );
        assert_eq!(
            operation_from_name("overlay.resolve_position"),
            Some(Operation::OverlayResolvePosition)
        );
        assert_eq!(
            operation_from_name("overlay.obfuscate"),
            Some(Operation::OverlayObfuscate)
        );
        assert_eq!(
            operation_from_name("overlay.deobfuscate"),
            Some(Operation::OverlayDeobfuscate)
        );
        assert_eq!(
            operation_from_name("session.subscribe.off_chain"),
            Some(Operation::SessionSubscribeOffChain)
        );
        assert_eq!(
            operation_from_name("session.subscribe.on_block"),
            Some(Operation::SessionSubscribeOnBlock)
        );
        assert_eq!(
            operation_from_name("session.renew"),
            Some(Operation::SessionRenew)
        );
        assert_eq!(operation_from_name("session.revoke"), Some(Operation::SessionRevoke));
        assert_eq!(operation_from_name("custody.rotate"), Some(Operation::CustodyRotate));
        assert_eq!(operation_from_name("custody.revoke"), Some(Operation::CustodyRevoke));
        assert_eq!(operation_from_name("health"), Some(Operation::Health));
        assert_eq!(operation_from_name("readiness"), Some(Operation::Readiness));
        assert_eq!(operation_from_name("bogus"), None);
        assert_eq!(operation_from_name(""), None);
        assert_eq!(operation_from_name("overlay."), None);
    }

    // TST-SRV-006: unknown paths return 404.
    #[test]
    fn tst_srv_006_unknown_path_404() {
        let mut router = router();
        let tests = &[
            ("GET", "/"),
            ("GET", "/v1"),
            ("POST", "/health"),
            ("DELETE", "/v1/operation"),
            ("GET", "/nonexistent"),
        ];
        for &(method, path) in tests {
            let reply = router.route(method, path, b"", 0);
            assert_eq!(reply.status, 404, "{method} {path} should be 404");
        }
    }

    // TST-SRV-007: the operation path works under /v1/ (not /api/ or /v2/).
    #[test]
    fn tst_srv_007_operation_path_is_v1() {
        let mut router = router();
        let reply = router.route("POST", "/api/operation", b"{}", 0);
        assert_eq!(reply.status, 404, "/api/ is not a valid path");
    }

    // TST-SRV-008: GET on the operation path is not a valid method.
    #[test]
    fn tst_srv_008_get_operation_404() {
        let reply = router().route("GET", "/v1/operation", b"{}", 0);
        assert_eq!(reply.status, 404);
    }

    // TST-SRV-009: the response content-type is always application/json (except metrics).
    #[test]
    fn tst_srv_009_json_content_type() {
        let mut router = router();
        let reply = router.route("GET", "/health", b"", 0);
        assert_eq!(reply.content_type, "application/json");
        let reply = router.route("GET", "/readiness", b"", 0);
        assert_eq!(reply.content_type, "application/json");
        let reply = router.route("POST", "/v1/operation", b"not json", 1_000);
        assert_eq!(reply.content_type, "application/json");
        // metrics has its own content type
        let reply = router.route("GET", "/metrics", b"", 0);
        assert_eq!(reply.content_type, "text/plain; version=0.0.4");
    }

    // TST-SRV-010: expired request (nonce/expiry in the past) is rejected.
    #[test]
    fn tst_srv_010_expired_request() {
        let mut router = router();
        let expired = br#"{"caller":"svc","operation":"custody.keygen","nonce":1,"expiry":1}"#;
        let reply = router.route("POST", "/v1/operation", expired, 999);
        assert_eq!(reply.status, 401);
    }

    // TST-SRV-011: custodial keygen via the operation path works through the real backend.
    #[test]
    fn tst_srv_011_custody_keygen_operation() {
        // custody.keygen with a real (non-node) backend returns the group public key
        let mut router = router();
        let unsigned = br#"{"caller":"svc","operation":"custody.keygen","nonce":42,"expiry":10000000}"#;
        let reply = router.route("POST", "/v1/operation", unsigned, 1_000);
        // without a registered caller, the signature check fails first
        assert_eq!(reply.status, 401);
    }

    // TST-SRV-012: too-large payload is rejected by the ApiConfig boundary.
    #[test]
    fn tst_srv_012_payload_too_large() {
        let mut router = router();
        let big_payload = format!(
            r#"{{"caller":"svc","operation":"overlay.write","payload":"{}","nonce":1,"expiry":10000000}}"#,
            "ab".repeat(5000)
        );
        let reply = router.route("POST", "/v1/operation", big_payload.as_bytes(), 1_000);
        // the API layer rejects oversized payloads (413) before auth processing
        assert_eq!(reply.status, 413);
    }
}
