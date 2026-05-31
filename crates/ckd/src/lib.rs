#![forbid(unsafe_code)]
//! `ckd`: child key derivation (BIP32-style HMAC-SHA512 over secp256k1) for the EP
//! key sets, plus the pinned secp256k1 signature primitives verified for low-S and
//! RFC-6979 (REQ-CKD-010, REQ-UNI-007). The full hierarchical derivation, hardened/
//! non-hardened modes, seed isolation, and position→path mapping build on this.

mod ckd;
mod error;
mod pin;
mod seeds;

pub use ckd::{XPriv, XPub, HARDENED};
pub use error::CkdError;
pub use pin::{
    is_low_s, sign, sign_prehash_der, verify, verify_der_prehash, verify_strict, verifying_key,
};
pub use seeds::{Position, Seeds};
