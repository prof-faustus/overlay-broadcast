//! Authenticated key-wrap: the {k_parent}_{k_child} operation (GB cl.1, REQ-CIPH-012)
//! is an AEAD, NEVER a raw XOR. A tampered wrap is rejected on unwrap.
use crate::aead::{open, seal, NONCE_LEN};
use crate::error::CipherError;
use secmem::{OsRandom, SecretBytes, SecureRandom};

const KEYWRAP_AAD: &[u8] = b"overlay-broadcast/keywrap/v1";

/// A wrapped key: its nonce and AEAD ciphertext.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct WrappedKey {
    /// The GCM nonce.
    pub nonce: [u8; NONCE_LEN],
    /// The AEAD ciphertext-with-tag.
    pub bytes: Vec<u8>,
}

/// Wrap `key_to_wrap` under `wrapping_key` with a fresh random nonce (REQ-CIPH-012).
///
/// # Errors
/// [`CipherError`] on a randomness or AEAD failure.
pub fn wrap(wrapping_key: &[u8], key_to_wrap: &[u8]) -> Result<WrappedKey, CipherError> {
    let mut nonce = [0u8; NONCE_LEN];
    OsRandom.fill(&mut nonce).map_err(|_| CipherError::Random)?;
    let bytes = seal(wrapping_key, &nonce, key_to_wrap, KEYWRAP_AAD)?;
    Ok(WrappedKey { nonce, bytes })
}

/// Unwrap a wrapped key; a tampered wrap is rejected by the AEAD tag.
///
/// # Errors
/// [`CipherError::Aead`] on tamper or wrong wrapping key.
pub fn unwrap(wrapping_key: &[u8], wrapped: &WrappedKey) -> Result<SecretBytes, CipherError> {
    open(wrapping_key, &wrapped.nonce, &wrapped.bytes, KEYWRAP_AAD)
}
