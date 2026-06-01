//! The [`KeyStore`] trait (REQ-KST-001): a backend-abstracting interface for where seeds
//! and long-term keys live. Every operation returns a typed [`KstError`] result. Backends
//! (encrypted file, HSM, KMS) differ in *where* the private key lives and whether it can
//! be exported; the trait is the seam the rest of the system codes against, so the api
//! layer never depends on a concrete backend.
use crate::error::KstError;
use cipher::WrappedKey;
use secmem::SecretBytes;

/// A Shamir backup share whose body is itself KeyStore-protected (wrapped under the
/// store's KEK), per REQ-KST-020.
#[derive(Clone, Debug)]
pub struct WrappedShare {
    /// The Shamir evaluation point.
    pub index: u8,
    /// The wrapped (AEAD-protected) share body.
    pub wrapped: WrappedKey,
}

/// Abstraction over where seeds and long-term keys live.
pub trait KeyStore {
    /// Generate a fresh secp256k1 private key under `id`, returning its public key. The
    /// private key never leaves the store except via [`KeyStore::export`] (and only if
    /// `exportable`).
    ///
    /// # Errors
    /// [`KstError`] on a backend or randomness failure.
    fn generate(&mut self, id: &str, exportable: bool) -> Result<[u8; 33], KstError>;

    /// Import an existing 32-byte private key under `id`.
    ///
    /// # Errors
    /// [`KstError`] on a backend failure or bad key length.
    fn import(&mut self, id: &str, secret: &SecretBytes, exportable: bool) -> Result<(), KstError>;

    /// Compute the public key for `id` without exporting the private key (derive-or-use).
    ///
    /// # Errors
    /// [`KstError::NotFound`] / [`KstError::WrongKey`].
    fn public_key(&self, id: &str) -> Result<[u8; 33], KstError>;

    /// Sign a 32-byte prehash with the key for `id`, where the backend performs the sign;
    /// returns a low-S DER ECDSA signature (derive-or-use).
    ///
    /// # Errors
    /// [`KstError::NotFound`] / [`KstError::WrongKey`] / [`KstError::Crypto`].
    fn sign_prehash(&self, id: &str, prehash: &[u8]) -> Result<Vec<u8>, KstError>;

    /// Wrap arbitrary secret bytes under the store's key-encryption key.
    ///
    /// # Errors
    /// [`KstError::Crypto`].
    fn wrap(&self, plaintext: &[u8]) -> Result<WrappedKey, KstError>;

    /// Unwrap bytes previously [`KeyStore::wrap`]ped; a tampered wrap is rejected.
    ///
    /// # Errors
    /// [`KstError::WrongKey`] on tamper or wrong store key.
    fn unwrap(&self, wrapped: &WrappedKey) -> Result<SecretBytes, KstError>;

    /// Crypto-shred the entry for `id` (the only ciphertext is dropped and zeroized).
    ///
    /// # Errors
    /// [`KstError::NotFound`].
    fn delete(&mut self, id: &str) -> Result<(), KstError>;

    /// Export the raw private key for `id`. Fails for a non-exportable key.
    ///
    /// # Errors
    /// [`KstError::NotFound`] / [`KstError::NonExportable`] / [`KstError::WrongKey`].
    fn export(&self, id: &str) -> Result<SecretBytes, KstError>;

    /// Back up the seed for `id` as a `threshold`-of-`shares` Shamir split, each share
    /// KeyStore-protected (REQ-KST-020).
    ///
    /// # Errors
    /// [`KstError`] on bad parameters or a backend failure.
    fn backup(&self, id: &str, threshold: u8, shares: u8) -> Result<Vec<WrappedShare>, KstError>;

    /// Restore an entry under `id` from at least `threshold` wrapped shares.
    ///
    /// # Errors
    /// [`KstError::InsufficientShares`] / [`KstError::WrongKey`] / [`KstError::BadParams`].
    fn restore(
        &mut self,
        id: &str,
        shares: &[WrappedShare],
        exportable: bool,
    ) -> Result<(), KstError>;
}
