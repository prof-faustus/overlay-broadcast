//! Encrypted-file KeyStore backend (REQ-KST-012), the lowest-assurance tier. Seeds are
//! encrypted at rest with AES-256-GCM under a key-encryption key (KEK) derived from an
//! operator passphrase via Argon2id (memory-hard). No plaintext seed ever leaves the
//! process: entries hold only `{nonce, ciphertext}`, and the entry id is bound as AEAD
//! associated data so a ciphertext cannot be replayed under a different id. A wrong
//! passphrase yields a different KEK and the AEAD tag check fails ([`KstError::WrongKey`]).
use crate::error::KstError;
use crate::shamir256::{reconstruct, split, SeedShare};
use crate::store::{KeyStore, WrappedShare};
use argon2::Argon2;
use cipher::{open, seal, wrap, WrappedKey, NONCE_LEN};
use k256::ecdsa::SigningKey;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use secmem::{OsRandom, SecretBytes, SecureRandom};
use std::collections::HashMap;
use zeroize::Zeroize;

const SALT_LEN: usize = 16;
const KEY_BYTES: usize = 32;

struct Entry {
    nonce: [u8; NONCE_LEN],
    ciphertext: Vec<u8>,
    exportable: bool,
}

/// An encrypted-file KeyStore. Holds entries in memory; persistence is the caller's
/// concern (the serialized form is `{salt, per-entry nonce, ciphertext}`, never plaintext).
pub struct EncryptedFileKeyStore {
    kek: SecretBytes,
    salt: [u8; SALT_LEN],
    entries: HashMap<String, Entry>,
}

impl EncryptedFileKeyStore {
    /// Open a store with a fresh random salt (a new store).
    ///
    /// # Errors
    /// [`KstError`] on a randomness or KDF failure.
    pub fn new(passphrase: &[u8]) -> Result<Self, KstError> {
        let mut salt = [0u8; SALT_LEN];
        OsRandom.fill(&mut salt).map_err(|_| KstError::Random)?;
        Self::with_salt(passphrase, salt)
    }

    /// Re-open a store with a known salt (so the same passphrase yields the same KEK).
    ///
    /// # Errors
    /// [`KstError::Crypto`] if the KDF fails.
    pub fn with_salt(passphrase: &[u8], salt: [u8; SALT_LEN]) -> Result<Self, KstError> {
        let kek = derive_kek(passphrase, &salt)?;
        Ok(Self {
            kek,
            salt,
            entries: HashMap::new(),
        })
    }

    /// The store's salt (needed to re-open the persisted store).
    #[must_use]
    pub fn salt(&self) -> [u8; SALT_LEN] {
        self.salt
    }

    /// The raw ciphertext at rest for `id` (for persistence / encrypt-at-rest checks).
    #[must_use]
    pub fn ciphertext_at_rest(&self, id: &str) -> Option<&[u8]> {
        self.entries
            .get(id)
            .map(|entry| entry.ciphertext.as_slice())
    }

    fn encrypt_seed(&self, id: &str, secret: &[u8], exportable: bool) -> Result<Entry, KstError> {
        let mut nonce = [0u8; NONCE_LEN];
        OsRandom.fill(&mut nonce).map_err(|_| KstError::Random)?;
        let ciphertext =
            seal(self.kek.expose(), &nonce, secret, id.as_bytes()).map_err(|_| KstError::Crypto)?;
        Ok(Entry {
            nonce,
            ciphertext,
            exportable,
        })
    }

    fn decrypt_seed(&self, id: &str) -> Result<SecretBytes, KstError> {
        let entry = self.entries.get(id).ok_or(KstError::NotFound)?;
        open(
            self.kek.expose(),
            &entry.nonce,
            &entry.ciphertext,
            id.as_bytes(),
        )
        .map_err(|_| KstError::WrongKey)
    }
}

impl KeyStore for EncryptedFileKeyStore {
    fn generate(&mut self, id: &str, exportable: bool) -> Result<[u8; 33], KstError> {
        let mut key = random_private_key()?;
        let public = public_key_compressed(&key)?;
        let entry = self.encrypt_seed(id, &key, exportable)?;
        key.zeroize();
        let _ = self.entries.insert(id.to_owned(), entry);
        Ok(public)
    }

    fn import(&mut self, id: &str, secret: &SecretBytes, exportable: bool) -> Result<(), KstError> {
        if secret.expose().len() != KEY_BYTES {
            return Err(KstError::BadParams);
        }
        let entry = self.encrypt_seed(id, secret.expose(), exportable)?;
        let _ = self.entries.insert(id.to_owned(), entry);
        Ok(())
    }

    fn public_key(&self, id: &str) -> Result<[u8; 33], KstError> {
        let seed = self.decrypt_seed(id)?;
        public_key_compressed(seed.expose())
    }

    fn sign_prehash(&self, id: &str, prehash: &[u8]) -> Result<Vec<u8>, KstError> {
        let seed = self.decrypt_seed(id)?;
        let mut key = key_array(seed.expose())?;
        let signature = ckd::sign_prehash_der(&key, prehash).map_err(|_| KstError::Crypto);
        key.zeroize();
        signature
    }

    fn wrap(&self, plaintext: &[u8]) -> Result<WrappedKey, KstError> {
        wrap(self.kek.expose(), plaintext).map_err(|_| KstError::Crypto)
    }

    fn unwrap(&self, wrapped: &WrappedKey) -> Result<SecretBytes, KstError> {
        cipher::unwrap(self.kek.expose(), wrapped).map_err(|_| KstError::WrongKey)
    }

    fn delete(&mut self, id: &str) -> Result<(), KstError> {
        let mut entry = self.entries.remove(id).ok_or(KstError::NotFound)?;
        entry.ciphertext.zeroize();
        Ok(())
    }

    fn export(&self, id: &str) -> Result<SecretBytes, KstError> {
        let entry = self.entries.get(id).ok_or(KstError::NotFound)?;
        if !entry.exportable {
            return Err(KstError::NonExportable);
        }
        self.decrypt_seed(id)
    }

    fn backup(&self, id: &str, threshold: u8, shares: u8) -> Result<Vec<WrappedShare>, KstError> {
        let seed = self.decrypt_seed(id)?;
        let parts = split(seed.expose(), threshold, shares)?;
        let mut out = Vec::with_capacity(parts.len());
        for part in parts {
            let wrapped = wrap(self.kek.expose(), part.body()).map_err(|_| KstError::Crypto)?;
            out.push(WrappedShare {
                index: part.index,
                wrapped,
            });
        }
        Ok(out)
    }

    fn restore(
        &mut self,
        id: &str,
        shares: &[WrappedShare],
        exportable: bool,
    ) -> Result<(), KstError> {
        if shares.len() < 2 {
            return Err(KstError::InsufficientShares);
        }
        let mut parts = Vec::with_capacity(shares.len());
        for share in shares {
            let body = cipher::unwrap(self.kek.expose(), &share.wrapped)
                .map_err(|_| KstError::WrongKey)?;
            parts.push(SeedShare::new(share.index, body.expose().to_vec()));
        }
        let mut seed = reconstruct(&parts)?;
        let entry = self.encrypt_seed(id, &seed, exportable)?;
        seed.zeroize();
        let _ = self.entries.insert(id.to_owned(), entry);
        Ok(())
    }
}

fn derive_kek(passphrase: &[u8], salt: &[u8]) -> Result<SecretBytes, KstError> {
    let mut out = [0u8; KEY_BYTES];
    Argon2::default()
        .hash_password_into(passphrase, salt, &mut out)
        .map_err(|_| KstError::Crypto)?;
    let kek = SecretBytes::from_slice(&out);
    out.zeroize();
    Ok(kek)
}

fn random_private_key() -> Result<[u8; KEY_BYTES], KstError> {
    for _ in 0..16u8 {
        let mut bytes = [0u8; KEY_BYTES];
        OsRandom.fill(&mut bytes).map_err(|_| KstError::Random)?;
        if SigningKey::from_slice(&bytes).is_ok() {
            return Ok(bytes);
        }
        bytes.zeroize();
    }
    Err(KstError::Random)
}

fn key_array(bytes: &[u8]) -> Result<[u8; KEY_BYTES], KstError> {
    if bytes.len() != KEY_BYTES {
        return Err(KstError::BadParams);
    }
    let slice = bytes.get(..KEY_BYTES).ok_or(KstError::BadParams)?;
    let mut out = [0u8; KEY_BYTES];
    out.copy_from_slice(slice);
    Ok(out)
}

fn public_key_compressed(private_key: &[u8]) -> Result<[u8; 33], KstError> {
    let signing = SigningKey::from_slice(private_key).map_err(|_| KstError::WrongKey)?;
    let encoded = signing.verifying_key().as_affine().to_encoded_point(true);
    let bytes = encoded.as_bytes();
    if bytes.len() != 33 {
        return Err(KstError::Crypto);
    }
    let mut out = [0u8; 33];
    out.copy_from_slice(bytes);
    Ok(out)
}
