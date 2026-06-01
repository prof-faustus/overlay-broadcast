//! End-to-end selftest (REQ-CLI-002): exercises every layer with a pass/fail result per
//! layer, so an operator can confirm the whole stack works on the target host.
use api::{ApiConfig, RateLimiter};
use broadcast::BroadcastGraph;
use bsv::double_sha256;
use cipher::{open, seal};
use custody::{keygen, reconstruction};
use kst::{EncryptedFileKeyStore, KeyStore};
use obs::Metrics;
use overlay::{resolve_key, signal_position, Position};
use res::check_quorum;
use secmem::SecretBytes;
use session::{Subscription, SubscriptionMode};

/// The pass/fail result for one layer.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LayerResult {
    /// The layer name.
    pub layer: &'static str,
    /// Whether the layer's representative operation succeeded.
    pub passed: bool,
}

/// Exercise every layer end to end, returning a per-layer result.
#[must_use]
pub fn run_selftest() -> Vec<LayerResult> {
    vec![
        LayerResult {
            layer: "secmem",
            passed: check_secmem(),
        },
        LayerResult {
            layer: "bsv",
            passed: check_bsv(),
        },
        LayerResult {
            layer: "cipher",
            passed: check_cipher(),
        },
        LayerResult {
            layer: "ckd",
            passed: check_ckd(),
        },
        LayerResult {
            layer: "keygraph+broadcast",
            passed: check_broadcast(),
        },
        LayerResult {
            layer: "overlay",
            passed: check_overlay(),
        },
        LayerResult {
            layer: "session",
            passed: check_session(),
        },
        LayerResult {
            layer: "custody",
            passed: check_custody(),
        },
        LayerResult {
            layer: "kst",
            passed: check_kst(),
        },
        LayerResult {
            layer: "obs",
            passed: check_obs(),
        },
        LayerResult {
            layer: "res",
            passed: check_res(),
        },
        LayerResult {
            layer: "api",
            passed: check_api(),
        },
    ]
}

/// Whether every layer passed.
#[must_use]
pub fn all_passed(results: &[LayerResult]) -> bool {
    results.iter().all(|result| result.passed)
}

fn check_secmem() -> bool {
    SecretBytes::from_slice(&[1, 2, 3]).expose() == [1, 2, 3]
}

fn check_bsv() -> bool {
    double_sha256(b"overlay-broadcast")
        .internal()
        .iter()
        .any(|byte| *byte != 0)
}

fn check_cipher() -> bool {
    let key = [7u8; 32];
    let nonce = [0u8; 12];
    let Ok(ciphertext) = seal(&key, &nonce, b"plain", b"aad") else {
        return false;
    };
    matches!(open(&key, &nonce, &ciphertext, b"aad"), Ok(plain) if plain.expose() == b"plain")
}

fn check_ckd() -> bool {
    let Ok(mut store) = EncryptedFileKeyStore::new(b"selftest") else {
        return false;
    };
    let Ok(public) = store.generate("ckd", true) else {
        return false;
    };
    let Ok(private) = store.export("ckd") else {
        return false;
    };
    let Ok(key) = <[u8; 32]>::try_from(private.expose()) else {
        return false;
    };
    let prehash = [0x21u8; 32];
    matches!(ckd::sign_prehash_der(&key, &prehash), Ok(der) if ckd::verify_der_prehash(&public, &prehash, &der))
}

fn check_broadcast() -> bool {
    let Ok(graph) = BroadcastGraph::build(&[1, 2, 3, 4]) else {
        return false;
    };
    graph.encrypt_message(b"hello").is_ok()
}

fn check_overlay() -> bool {
    let position = Position::new(vec![1, 2, 3]);
    let coords = signal_position(&position);
    resolve_key(&coords, &[9u8; 32]).is_ok()
}

fn check_session() -> bool {
    matches!(Subscription::new(SubscriptionMode::OffChain, 1_000, 100), Ok(subscription) if subscription.sessions_funded() == 10)
}

fn check_custody() -> bool {
    let Ok((group, shares)) = keygen(2, 3) else {
        return false;
    };
    let quorum = [shares.first().cloned(), shares.get(1).cloned()];
    let [Some(a), Some(b)] = quorum else {
        return false;
    };
    let parts = vec![a, b];
    let prehash = [0x42u8; 32];
    let Ok(der) = reconstruction::sign_prehash(&parts, 2, &prehash) else {
        return false;
    };
    ckd::verify_der_prehash(&group.public_compressed(), &prehash, &der)
}

fn check_kst() -> bool {
    let Ok(mut store) = EncryptedFileKeyStore::new(b"selftest") else {
        return false;
    };
    let Ok(public) = store.generate("kst", false) else {
        return false;
    };
    let prehash = [0x11u8; 32];
    matches!(store.sign_prehash("kst", &prehash), Ok(der) if ckd::verify_der_prehash(&public, &prehash, &der))
}

fn check_obs() -> bool {
    matches!(Metrics::new(), Ok(metrics) if matches!(metrics.render(), Ok(text) if !text.is_empty()))
}

fn check_res() -> bool {
    check_quorum(2, 2, 3).is_ok() && check_quorum(1, 2, 3).is_err()
}

fn check_api() -> bool {
    let config = ApiConfig {
        max_payload_bytes: 1024,
        rate_limit_per_window: 2,
        rate_window_secs: 60,
        op_timeout_millis: 1_000,
    };
    if config.validate().is_err() {
        return false;
    }
    let mut limiter = RateLimiter::new(2, 60);
    limiter.allow("svc", 0) && limiter.allow("svc", 0) && !limiter.allow("svc", 0)
}
