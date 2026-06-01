//! Seed isolation and position→path mapping (REQ-CKD-004/005/006/007, EP cl.3,7,16).
//!
//! The first/second/third seeds are independent derivation domains, each a zeroizing
//! `SecretBytes`. They are derivable from a single master seed by a documented,
//! domain-separated HMAC-SHA512 KDF, and are also independently importable. A node
//! POSITION maps deterministically to a derivation path; the first (writing) key set
//! uses HARDENED derivation so that leakage of a derived writing key cannot recover
//! the parent or a sibling (REQ-CKD-004) — verified by a negative test.
use crate::ckd::{XPriv, HARDENED};
use crate::error::CkdError;
use hmac::{Hmac, Mac};
use secmem::SecretBytes;
use sha2::Sha512;

type HmacSha512 = Hmac<Sha512>;

const FIRST_DOMAIN: &[u8] = b"overlay-broadcast/seed/first/v1";
const SECOND_DOMAIN: &[u8] = b"overlay-broadcast/seed/second/v1";
const THIRD_DOMAIN: &[u8] = b"overlay-broadcast/seed/third/v1";

/// A node position in a key graph: ordered coordinates from the root to the node.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Position(Vec<u32>);

impl Position {
    /// Construct a position from its coordinates (each expected `< 2^31`).
    #[must_use]
    pub fn new(coords: Vec<u32>) -> Self {
        Self(coords)
    }

    /// The coordinates.
    #[must_use]
    pub fn coords(&self) -> &[u32] {
        &self.0
    }

    /// The HARDENED derivation path for this position (the writing key set,
    /// REQ-CKD-004): every coordinate is mapped to a hardened index.
    #[must_use]
    pub fn hardened_path(&self) -> Vec<u32> {
        self.0.iter().map(|c| c | HARDENED).collect()
    }

    /// The non-hardened derivation path for this position (for key sets that permit
    /// public derivation and carry no co-located private/public hazard).
    #[must_use]
    pub fn path(&self) -> Vec<u32> {
        self.0.iter().map(|c| c & !HARDENED).collect()
    }
}

/// The three independent seed domains, each a zeroizing secret.
#[derive(Debug)]
pub struct Seeds {
    first: SecretBytes,
    second: SecretBytes,
    third: SecretBytes,
}

impl Seeds {
    /// Derive the three seeds from a single master seed by domain separation
    /// (REQ-CKD-006, EP cl.7). Each seed is `HMAC-SHA512(master, domain)[0..32]`.
    ///
    /// # Errors
    /// [`CkdError::DerivationFailed`] only on an internal MAC failure (does not occur).
    pub fn from_master(master: &[u8]) -> Result<Self, CkdError> {
        Ok(Self {
            first: derive_seed(master, FIRST_DOMAIN)?,
            second: derive_seed(master, SECOND_DOMAIN)?,
            third: derive_seed(master, THIRD_DOMAIN)?,
        })
    }

    /// Construct from independently-imported seeds (EP para 0028).
    #[must_use]
    pub fn from_parts(first: SecretBytes, second: SecretBytes, third: SecretBytes) -> Self {
        Self {
            first,
            second,
            third,
        }
    }

    /// The first (writing) seed.
    #[must_use]
    pub fn first(&self) -> &SecretBytes {
        &self.first
    }
    /// The second seed.
    #[must_use]
    pub fn second(&self) -> &SecretBytes {
        &self.second
    }
    /// The third seed.
    #[must_use]
    pub fn third(&self) -> &SecretBytes {
        &self.third
    }

    /// Derive the first/writing key at a position (HARDENED; REQ-CKD-004/007).
    ///
    /// # Errors
    /// Propagates derivation errors.
    pub fn writing_key(&self, position: &Position) -> Result<XPriv, CkdError> {
        XPriv::from_seed(self.first.expose())?.derive_path(&position.hardened_path())
    }

    /// Derive the second-function key at a position.
    ///
    /// # Errors
    /// Propagates derivation errors.
    pub fn second_function_key(&self, position: &Position) -> Result<XPriv, CkdError> {
        XPriv::from_seed(self.second.expose())?.derive_path(&position.hardened_path())
    }

    /// Derive the third-function key at a position.
    ///
    /// # Errors
    /// Propagates derivation errors.
    pub fn third_function_key(&self, position: &Position) -> Result<XPriv, CkdError> {
        XPriv::from_seed(self.third.expose())?.derive_path(&position.hardened_path())
    }
}

fn derive_seed(master: &[u8], domain: &[u8]) -> Result<SecretBytes, CkdError> {
    let mut mac = HmacSha512::new_from_slice(master).map_err(|_| CkdError::DerivationFailed)?;
    mac.update(domain);
    let out = mac.finalize().into_bytes();
    let half = out.get(..32).ok_or(CkdError::DerivationFailed)?;
    Ok(SecretBytes::from_slice(half))
}
