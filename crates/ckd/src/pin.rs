//! The pinned secp256k1 signature primitives, verified by test to provide low-S
//! normalization and RFC-6979 deterministic nonces (REQ-CKD-010, REQ-BSV-032,
//! REQ-UNI-007: verify, do not assume). The chosen crate is `k256` (RustCrypto,
//! NCC-audited). Higher layers use this via the cipher Signer/Verifier wrapper
//! (REQ-CIPH-001); this module is the verified foundation.
use crate::error::CkdError;
use k256::ecdsa::signature::hazmat::{PrehashSigner, PrehashVerifier};
use k256::ecdsa::signature::{Signer, Verifier};
use k256::ecdsa::{Signature, SigningKey, VerifyingKey};

/// Deterministically sign `message` (RFC-6979) under `private_key`, producing a
/// low-S normalized ECDSA signature.
///
/// # Errors
/// [`CkdError::BadKey`] if the private key is not a valid scalar.
pub fn sign(private_key: &[u8; 32], message: &[u8]) -> Result<Signature, CkdError> {
    let key = SigningKey::from_slice(private_key).map_err(|_| CkdError::BadKey)?;
    let signature: Signature = key.sign(message);
    // Defence in depth: enforce low-S even if the backend ever changed (REQ-BSV-032).
    Ok(signature.normalize_s().unwrap_or(signature))
}

/// The verifying (public) key for a private key.
///
/// # Errors
/// [`CkdError::BadKey`] if the private key is not a valid scalar.
pub fn verifying_key(private_key: &[u8; 32]) -> Result<VerifyingKey, CkdError> {
    let key = SigningKey::from_slice(private_key).map_err(|_| CkdError::BadKey)?;
    Ok(*key.verifying_key())
}

/// Whether a signature is low-S (canonical, non-malleable).
#[must_use]
pub fn is_low_s(signature: &Signature) -> bool {
    signature.normalize_s().is_none()
}

/// Verify a signature (accepts any valid ECDSA signature).
#[must_use]
pub fn verify(key: &VerifyingKey, message: &[u8], signature: &Signature) -> bool {
    key.verify(message, signature).is_ok()
}

/// Verify STRICTLY: reject non-canonical high-S signatures (REQ-BSV-032).
#[must_use]
pub fn verify_strict(key: &VerifyingKey, message: &[u8], signature: &Signature) -> bool {
    is_low_s(signature) && verify(key, message, signature)
}

/// Sign a 32-byte PREHASH (e.g. a BSV sighash) directly, low-S normalized, returning
/// the DER-encoded signature. The prehash is the ECDSA digest; it is not re-hashed.
///
/// # Errors
/// [`CkdError::BadKey`] if the private key is invalid or the prehash is malformed.
pub fn sign_prehash_der(private_key: &[u8; 32], prehash: &[u8]) -> Result<Vec<u8>, CkdError> {
    let key = SigningKey::from_slice(private_key).map_err(|_| CkdError::BadKey)?;
    let signature: Signature = key.sign_prehash(prehash).map_err(|_| CkdError::BadKey)?;
    let low_s = signature.normalize_s().unwrap_or(signature);
    Ok(low_s.to_der().as_bytes().to_vec())
}

/// Verify a DER-encoded signature over a 32-byte PREHASH against a SEC1 public key,
/// rejecting high-S (REQ-BSV-032).
#[must_use]
pub fn verify_der_prehash(public_key_sec1: &[u8], prehash: &[u8], signature_der: &[u8]) -> bool {
    let Ok(key) = VerifyingKey::from_sec1_bytes(public_key_sec1) else {
        return false;
    };
    let Ok(signature) = Signature::from_der(signature_der) else {
        return false;
    };
    is_low_s(&signature) && key.verify_prehash(prehash, &signature).is_ok()
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

    // TST-CKD-010 / TST-BSV-032: the pinned crate signs deterministically (RFC-6979),
    // produces low-S signatures, verifies them, and rejects a wrong message; a
    // high-S (malleated) signature verifies loosely but is rejected strictly.
    #[test]
    fn tst_ckd_010_low_s_and_rfc6979() {
        let private_key = [0x11u8; 32];
        let message = b"pin verification message";

        let first = sign(&private_key, message).unwrap();
        let second = sign(&private_key, message).unwrap();
        assert_eq!(
            first, second,
            "RFC-6979: same key+message yields the same signature"
        );
        assert!(is_low_s(&first), "signatures are low-S normalized");

        let key = verifying_key(&private_key).unwrap();
        assert!(verify(&key, message, &first));
        assert!(verify_strict(&key, message, &first));
        assert!(!verify(&key, b"a different message", &first));

        // The malleated high-S counterpart (r, n - s) is non-canonical. The pinned
        // crate rejects it on verification natively (REQ-BSV-032); strict verification
        // rejects it too.
        let (r, s) = first.split_scalars();
        let high = Signature::from_scalars(r.to_bytes(), (-(*s)).to_bytes()).unwrap();
        assert!(!is_low_s(&high));
        assert!(
            !verify(&key, message, &high),
            "the pinned crate rejects high-S on verification"
        );
        assert!(!verify_strict(&key, message, &high));
    }
}
