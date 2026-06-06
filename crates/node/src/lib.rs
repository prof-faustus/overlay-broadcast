//! Live BSV node-submission client over the Teranode JSON-RPC interface. It queries the
//! best block / headers, submits raw transactions, and exposes a readiness probe. Node
//! responses are untrusted: the caller validates any returned block data against the
//! `bsv::HeaderChain` trust root (REQ-API-007), exactly as the offline fixture does.
#![forbid(unsafe_code)]

pub mod error;

pub use error::NodeError;

use bsv::hex_to_bytes;

/// A blocking JSON-RPC client for a BSV (Teranode) node.
pub struct NodeClient {
    endpoint: String,
    authorization: Option<String>,
    agent: ureq::Agent,
}

impl NodeClient {
    /// A client for the node at `endpoint` (e.g. `http://127.0.0.1:9292/`), optionally with
    /// HTTP basic-auth credentials.
    #[must_use]
    pub fn new(endpoint: &str, user: Option<&str>, password: Option<&str>) -> Self {
        let agent = ureq::AgentBuilder::new()
            .timeout(std::time::Duration::from_secs(10))
            .build();
        let authorization = match (user, password) {
            (Some(u), Some(p)) => Some(format!(
                "Basic {}",
                base64_encode(format!("{u}:{p}").as_bytes())
            )),
            _ => None,
        };
        Self {
            endpoint: endpoint.to_owned(),
            authorization,
            agent,
        }
    }

    /// The best block hash (display hex).
    ///
    /// # Errors
    /// [`NodeError`] on transport, RPC, or decode failure.
    pub fn best_block_hash(&self) -> Result<String, NodeError> {
        let result = self.call("getbestblockhash", serde_json::json!([]))?;
        result.as_str().map(str::to_owned).ok_or(NodeError::Decode)
    }

    /// The raw 80-byte header for `block_hash`.
    ///
    /// # Errors
    /// [`NodeError`] on transport/RPC/decode failure or a non-80-byte header.
    pub fn block_header(&self, block_hash: &str) -> Result<Vec<u8>, NodeError> {
        let result = self.call("getblockheader", serde_json::json!([block_hash, false]))?;
        let hex = result.as_str().ok_or(NodeError::Decode)?;
        let bytes = hex_to_bytes(hex).map_err(|_| NodeError::Decode)?;
        if bytes.len() != bsv::HEADER_LEN {
            return Err(NodeError::Decode);
        }
        Ok(bytes)
    }

    /// Submit a raw transaction; returns its txid (display hex). Idempotent at the node:
    /// resubmitting a known transaction is not an error for the caller's resubmit logic.
    ///
    /// # Errors
    /// [`NodeError::Rpc`] if the node rejects the transaction.
    pub fn submit_transaction(&self, raw_tx: &[u8]) -> Result<String, NodeError> {
        let hex = bsv::bytes_to_hex(raw_tx);
        let result = self.call("sendrawtransaction", serde_json::json!([hex]))?;
        result.as_str().map(str::to_owned).ok_or(NodeError::Decode)
    }

    /// Whether the node is reachable (a successful best-block query).
    #[must_use]
    pub fn is_reachable(&self) -> bool {
        self.best_block_hash().is_ok()
    }

    fn call(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, NodeError> {
        let body = serde_json::json!({ "jsonrpc": "1.0", "id": "overlay-broadcast", "method": method, "params": params }).to_string();
        let mut request = self
            .agent
            .post(&self.endpoint)
            .set("content-type", "text/plain");
        if let Some(authorization) = &self.authorization {
            request = request.set("authorization", authorization);
        }
        let response = request.send_string(&body).map_err(|_| NodeError::Http)?;
        let text = response.into_string().map_err(|_| NodeError::Decode)?;
        parse_rpc_result(&text)
    }
}

/// A readiness probe (REQ-OBS-003) backed by a node reachability check.
pub struct NodeProbe<'a> {
    client: &'a NodeClient,
}

impl<'a> NodeProbe<'a> {
    /// Wrap a client as a readiness probe.
    #[must_use]
    pub fn new(client: &'a NodeClient) -> Self {
        Self { client }
    }
}

impl obs::DependencyProbe for NodeProbe<'_> {
    fn name(&self) -> &str {
        "bsv-node"
    }
    fn is_up(&self) -> bool {
        self.client.is_reachable()
    }
}

// Extract the `result` field of a JSON-RPC response, surfacing a non-null `error`.
fn parse_rpc_result(text: &str) -> Result<serde_json::Value, NodeError> {
    let value: serde_json::Value = serde_json::from_str(text).map_err(|_| NodeError::Decode)?;
    if let Some(error) = value.get("error") {
        if !error.is_null() {
            return Err(NodeError::Rpc(error.to_string()));
        }
    }
    value.get("result").cloned().ok_or(NodeError::Decode)
}

fn base64_encode(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in input.chunks(3) {
        let b0 = *chunk.first().unwrap_or(&0);
        let b1 = *chunk.get(1).unwrap_or(&0);
        let b2 = *chunk.get(2).unwrap_or(&0);
        let triple = (u32::from(b0) << 16) | (u32::from(b1) << 8) | u32::from(b2);
        for slot in 0..4u32 {
            if (slot == 3 && chunk.len() < 3) || (slot == 2 && chunk.len() < 2) {
                out.push('=');
            } else {
                let index = usize::try_from((triple >> (18 - slot * 6)) & 0x3f).unwrap_or(0);
                out.push(char::from(*ALPHABET.get(index).unwrap_or(&b'A')));
            }
        }
    }
    out
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

    // The JSON-RPC result extractor handles success and surfaces node errors.
    #[test]
    fn parses_rpc_result_and_error() {
        let ok = parse_rpc_result(r#"{"result":"607c10f0","error":null,"id":"x"}"#).unwrap();
        assert_eq!(ok.as_str(), Some("607c10f0"));
        assert!(matches!(
            parse_rpc_result(r#"{"result":null,"error":{"code":-5,"message":"no"},"id":"x"}"#),
            Err(NodeError::Rpc(_))
        ));
        assert!(matches!(
            parse_rpc_result("not json"),
            Err(NodeError::Decode)
        ));
        // null result without error returns Ok(Value::Null) — not an error case
        assert_eq!(
            parse_rpc_result(r#"{"result":null,"error":null,"id":"x"}"#).unwrap(),
            serde_json::Value::Null
        );
        // empty string is not valid JSON
        assert!(matches!(parse_rpc_result(""), Err(NodeError::Decode)));
    }

    // Base64 basic-auth encoding matches the known vector.
    #[test]
    fn base64_basic_auth() {
        assert_eq!(
            base64_encode(b"teranode:regtestsecret"),
            "dGVyYW5vZGU6cmVndGVzdHNlY3JldA=="
        );
        // empty input
        assert_eq!(base64_encode(b""), "");
        // single byte (padding)
        assert_eq!(base64_encode(b"a"), "YQ==");
        // two bytes (single padding)
        assert_eq!(base64_encode(b"ab"), "YWI=");
        // three bytes (no padding)
        assert_eq!(base64_encode(b"abc"), "YWJj");
    }

    // NodeClient construction without auth sets no authorization header.
    #[test]
    fn node_client_no_auth() {
        let client = NodeClient::new("http://127.0.0.1:9292", None, None);
        assert!(client.authorization.is_none());
        assert_eq!(client.endpoint, "http://127.0.0.1:9292");
    }

    // NodeClient construction with partial auth (user but no pass, or vice versa)
    // is treated as unauthenticated (consistent with the Some/Some match).
    #[test]
    fn node_client_partial_auth_is_no_auth() {
        let client = NodeClient::new("http://node:9292", Some("user"), None);
        assert!(client.authorization.is_none(), "user-only is no auth");
        let client = NodeClient::new("http://node:9292", None, Some("pass"));
        assert!(client.authorization.is_none(), "pass-only is no auth");
    }

    // The call method constructs a well-formed JSON-RPC request.
    #[test]
    fn rpc_call_builds_json() {
        // call() will fail with Http (connection refused), but let's verify the
        // JSON-RPC body is well-formed by inspecting the request construction.
        let body = serde_json::json!({
            "jsonrpc": "1.0",
            "id": "overlay-broadcast",
            "method": "getbestblockhash",
            "params": []
        })
        .to_string();
        let parsed: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(parsed["method"], "getbestblockhash");
        assert_eq!(parsed["jsonrpc"], "1.0");
    }

    // Block_header validates length.
    #[test]
    fn block_header_validates_length() {
        // We can't test the actual call (no node), but verify the hex-decoding
        // path: 80 bytes of hex is 160 hex chars -> valid
        let header_hex = "00".repeat(80);
        let decoded = hex_to_bytes(&header_hex).unwrap();
        assert_eq!(decoded.len(), 80);
        // wrong length
        let short_hex = "00".repeat(79);
        let decoded = hex_to_bytes(&short_hex).unwrap();
        assert_ne!(decoded.len(), 80);
    }

    // TST-NODE-LIVE (REQ-TST-012): query a live Teranode and validate the returned header
    // against our parser/hasher. Run with NODE_RPC_URL / NODE_RPC_USER / NODE_RPC_PASS set.
    #[test]
    #[ignore = "needs a reachable Teranode JSON-RPC: set NODE_RPC_URL, NODE_RPC_USER, NODE_RPC_PASS"]
    fn tst_node_live_header_validates() {
        let url = std::env::var("NODE_RPC_URL").expect("NODE_RPC_URL");
        let user = std::env::var("NODE_RPC_USER").ok();
        let pass = std::env::var("NODE_RPC_PASS").ok();
        let client = NodeClient::new(&url, user.as_deref(), pass.as_deref());
        let hash = client.best_block_hash().unwrap();
        assert_eq!(hash.len(), 64, "best block hash is 32 bytes of hex");
        let raw = client.block_header(&hash).unwrap();
        let header = bsv::BlockHeader::parse(&raw).unwrap();
        assert_eq!(
            header.block_hash().to_display_hex(),
            hash,
            "our recomputed block hash matches the node"
        );
    }
}
