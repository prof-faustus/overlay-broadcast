//! Project-owned Signer/Verifier traits wrapping the verified secp256k1 pin
//! (REQ-CIPH-001). The rest of the system signs and verifies only through these, so
//! low-S + RFC-6979 enforcement (on sign) and high-S rejection (on verify) are
//! guaranteed at one seam.
use crate::error::CipherError;
use k256::ecdsa::{Signature, VerifyingKey};
use secmem::SecretBytes;

/// Something that can produce ECDSA signatures (low-S, RFC-6979).
pub trait Signer {
    /// Sign a message.
    ///
    /// # Errors
    /// [`CipherError::Signing`] if the key is invalid.
    fn sign(&self, message: &[u8]) -> Result<Signature, CipherError>;

    /// The corresponding public (verifying) key.
    ///
    /// # Errors
    /// [`CipherError::Signing`] if the key is invalid.
    fn verifying_key(&self) -> Result<VerifyingKey, CipherError>;
}

/// Something that can verify ECDSA signatures (rejecting high-S).
pub trait Verifier {
    /// Verify a signature strictly (canonical low-S only).
    fn verify(&self, message: &[u8], signature: &Signature) -> bool;
}

/// A secp256k1 signer holding a private key as a zeroizing secret.
#[derive(Debug)]
pub struct Secp256k1Signer {
    private_key: SecretBytes,
}

impl Secp256k1Signer {
    /// Construct from a 32-byte private key.
    ///
    /// # Errors
    /// [`CipherError::BadKeyLength`] if not 32 bytes.
    pub fn new(private_key: SecretBytes) -> Result<Self, CipherError> {
        if private_key.len() != 32 {
            return Err(CipherError::BadKeyLength);
        }
        Ok(Self { private_key })
    }

    fn key_array(&self) -> Result<[u8; 32], CipherError> {
        self.private_key
            .expose()
            .try_into()
            .map_err(|_| CipherError::BadKeyLength)
    }
}

impl Signer for Secp256k1Signer {
    fn sign(&self, message: &[u8]) -> Result<Signature, CipherError> {
        ckd::sign(&self.key_array()?, message).map_err(|_| CipherError::Signing)
    }
    fn verifying_key(&self) -> Result<VerifyingKey, CipherError> {
        ckd::verifying_key(&self.key_array()?).map_err(|_| CipherError::Signing)
    }
}

/// A secp256k1 verifier over a public key.
#[derive(Clone, Debug)]
pub struct Secp256k1Verifier {
    key: VerifyingKey,
}

impl Secp256k1Verifier {
    /// Construct from a verifying key.
    #[must_use]
    pub fn new(key: VerifyingKey) -> Self {
        Self { key }
    }
}

impl Verifier for Secp256k1Verifier {
    fn verify(&self, message: &[u8], signature: &Signature) -> bool {
        ckd::verify_strict(&self.key, message, signature)
    }
}
