//! Pluggable caller authentication and replay protection (REQ-API-003). Callers are
//! identified by a registered secp256k1 public key; a request is accepted only if its
//! signature verifies over the canonical pre-image, its nonce has not been seen, and it has
//! not expired. A bare caller identifier without a valid signature is refused.
use std::collections::{HashMap, HashSet};

/// Maps caller identifiers to their registered SEC1 public keys. This is the pluggable,
/// configured authentication source (not hard-coded): callers are registered at startup.
#[derive(Clone, Debug, Default)]
pub struct CallerRegistry {
    keys: HashMap<String, Vec<u8>>,
}

impl CallerRegistry {
    /// An empty registry.
    #[must_use]
    pub fn new() -> Self {
        Self {
            keys: HashMap::new(),
        }
    }

    /// Register (or replace) a caller's public key.
    pub fn register(&mut self, caller: &str, public_key_sec1: &[u8]) {
        let _ = self
            .keys
            .insert(caller.to_owned(), public_key_sec1.to_vec());
    }

    /// The registered public key for a caller, if any.
    #[must_use]
    pub fn public_key(&self, caller: &str) -> Option<&[u8]> {
        self.keys.get(caller).map(Vec::as_slice)
    }
}

/// Tracks seen `(caller, nonce)` pairs to reject replays.
#[derive(Clone, Debug, Default)]
pub struct NonceStore {
    seen: HashSet<(String, u64)>,
}

impl NonceStore {
    /// An empty store.
    #[must_use]
    pub fn new() -> Self {
        Self {
            seen: HashSet::new(),
        }
    }

    /// Record a nonce; returns `true` if it was fresh, `false` if already seen (replay).
    pub fn check_and_record(&mut self, caller: &str, nonce: u64) -> bool {
        self.seen.insert((caller.to_owned(), nonce))
    }
}
