//! AES-256-GCM authenticated encryption (REQ-CIPH-010/013). Nonces are provably
//! unique per key: an [`AeadCipher`] forms each nonce as `epoch || counter` with a
//! strictly monotonic 64-bit counter, so reuse under a key is impossible by
//! construction (counter exhaustion is a typed error, not a wrap-around). Decrypted
//! plaintext is zeroized after it is copied into a `SecretBytes`.
use crate::error::CipherError;
use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use secmem::SecretBytes;
use zeroize::Zeroize;

/// The AES-256 key length in bytes.
pub const KEY_LEN: usize = 32;
/// The GCM nonce length in bytes.
pub const NONCE_LEN: usize = 12;

/// One-shot AEAD seal with an explicit nonce. The caller guarantees nonce
/// uniqueness; prefer [`AeadCipher`] for managed nonces.
///
/// # Errors
/// [`CipherError::BadKeyLength`] / [`CipherError::Aead`].
pub fn seal(
    key: &[u8],
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>, CipherError> {
    let cipher = cipher_for(key)?;
    cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| CipherError::Aead)
}

/// One-shot AEAD open; returns the plaintext as a zeroizing secret.
///
/// # Errors
/// [`CipherError::BadKeyLength`] / [`CipherError::Aead`] on any tamper/wrong key.
pub fn open(
    key: &[u8],
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<SecretBytes, CipherError> {
    let cipher = cipher_for(key)?;
    let mut plaintext = cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| CipherError::Aead)?;
    let secret = SecretBytes::from_slice(&plaintext);
    plaintext.zeroize();
    Ok(secret)
}

fn cipher_for(key: &[u8]) -> Result<Aes256Gcm, CipherError> {
    if key.len() != KEY_LEN {
        return Err(CipherError::BadKeyLength);
    }
    Aes256Gcm::new_from_slice(key).map_err(|_| CipherError::BadKeyLength)
}

/// A ciphertext with its nonce.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Ciphertext {
    /// The GCM nonce used.
    pub nonce: [u8; NONCE_LEN],
    /// The ciphertext-with-tag bytes.
    pub bytes: Vec<u8>,
}

/// An AEAD cipher with managed, provably-unique nonces (REQ-CIPH-010).
#[derive(Debug)]
pub struct AeadCipher {
    key: SecretBytes,
    epoch: u32,
    counter: u64,
}

impl AeadCipher {
    /// Create a cipher bound to a 32-byte key and a key epoch.
    ///
    /// # Errors
    /// [`CipherError::BadKeyLength`] if the key is not 32 bytes.
    pub fn new(key: SecretBytes, epoch: u32) -> Result<Self, CipherError> {
        if key.len() != KEY_LEN {
            return Err(CipherError::BadKeyLength);
        }
        Ok(Self {
            key,
            epoch,
            counter: 0,
        })
    }

    /// Encrypt with the next unique nonce.
    ///
    /// # Errors
    /// [`CipherError::NonceExhausted`] if the counter would overflow; AEAD errors.
    pub fn encrypt(&mut self, plaintext: &[u8], aad: &[u8]) -> Result<Ciphertext, CipherError> {
        let nonce = self.next_nonce()?;
        let bytes = seal(self.key.expose(), &nonce, plaintext, aad)?;
        Ok(Ciphertext { nonce, bytes })
    }

    /// Decrypt a ciphertext produced under this key.
    ///
    /// # Errors
    /// [`CipherError::Aead`] on tamper/wrong key/wrong aad.
    pub fn decrypt(&self, ciphertext: &Ciphertext, aad: &[u8]) -> Result<SecretBytes, CipherError> {
        open(self.key.expose(), &ciphertext.nonce, &ciphertext.bytes, aad)
    }

    fn next_nonce(&mut self) -> Result<[u8; NONCE_LEN], CipherError> {
        let counter = self.counter;
        self.counter = self
            .counter
            .checked_add(1)
            .ok_or(CipherError::NonceExhausted)?;
        let epoch_bytes = self.epoch.to_be_bytes();
        let counter_bytes = counter.to_be_bytes();
        let mut nonce = [0u8; NONCE_LEN];
        if let Some(dst) = nonce.get_mut(0..4) {
            dst.copy_from_slice(&epoch_bytes);
        }
        if let Some(dst) = nonce.get_mut(4..NONCE_LEN) {
            dst.copy_from_slice(&counter_bytes);
        }
        Ok(nonce)
    }
}
