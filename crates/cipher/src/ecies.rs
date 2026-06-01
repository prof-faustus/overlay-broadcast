//! ECIES over secp256k1 (REQ-CIPH-011) and the symmetric/asymmetric selector
//! (REQ-CIPH-014). ECIES = ephemeral ECDH (the shared secret is the x-coordinate of
//! the shared point) → HKDF-SHA256 (domain-separated) → AES-256-GCM AEAD. The AES key
//! and nonce are both derived from the per-message ephemeral shared secret, so each
//! message uses fresh, unique key material.
use crate::aead::{open, seal, Ciphertext, NONCE_LEN};
use crate::error::CipherError;
use hkdf::Hkdf;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{ProjectivePoint, PublicKey, SecretKey};
use secmem::{OsRandom, SecretBytes, SecureRandom};
use sha2::Sha256;
use zeroize::Zeroize;

const ECIES_INFO: &[u8] = b"overlay-broadcast/ecies/v1";

/// An ECIES ciphertext: the ephemeral public key and the AEAD ciphertext.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EciesCiphertext {
    /// The ephemeral public key (compressed).
    pub ephemeral_public_key: [u8; 33],
    /// The AEAD ciphertext-with-tag.
    pub bytes: Vec<u8>,
}

/// Encrypt `plaintext` to a recipient's compressed public key (REQ-CIPH-011).
///
/// # Errors
/// [`CipherError::Ecies`] / [`CipherError`] on a bad key or AEAD failure.
pub fn ecies_encrypt(
    recipient_public_key: &[u8; 33],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<EciesCiphertext, CipherError> {
    let (ephemeral_secret, ephemeral_public_key) = ephemeral_keypair()?;
    let recipient =
        PublicKey::from_sec1_bytes(recipient_public_key).map_err(|_| CipherError::Ecies)?;
    let shared = recipient.to_projective() * *ephemeral_secret.to_nonzero_scalar();
    let mut shared_x = shared_secret_x(&shared)?;
    let mut key = [0u8; 32];
    let mut nonce = [0u8; NONCE_LEN];
    derive_key_nonce(&shared_x, &mut key, &mut nonce)?;
    shared_x.zeroize();
    let bytes = seal(&key, &nonce, plaintext, aad);
    key.zeroize();
    Ok(EciesCiphertext {
        ephemeral_public_key,
        bytes: bytes?,
    })
}

/// Decrypt an ECIES ciphertext with the recipient's private key.
///
/// # Errors
/// [`CipherError`] on a bad key, malformed ephemeral key, or AEAD failure.
pub fn ecies_decrypt(
    recipient_private_key: &[u8],
    ciphertext: &EciesCiphertext,
    aad: &[u8],
) -> Result<SecretBytes, CipherError> {
    let recipient =
        SecretKey::from_slice(recipient_private_key).map_err(|_| CipherError::BadKeyLength)?;
    let ephemeral = PublicKey::from_sec1_bytes(&ciphertext.ephemeral_public_key)
        .map_err(|_| CipherError::Ecies)?;
    let shared = ephemeral.to_projective() * *recipient.to_nonzero_scalar();
    let mut shared_x = shared_secret_x(&shared)?;
    let mut key = [0u8; 32];
    let mut nonce = [0u8; NONCE_LEN];
    derive_key_nonce(&shared_x, &mut key, &mut nonce)?;
    shared_x.zeroize();
    let result = open(&key, &nonce, &ciphertext.bytes, aad);
    key.zeroize();
    result
}

fn ephemeral_keypair() -> Result<(SecretKey, [u8; 33]), CipherError> {
    for _ in 0..8u8 {
        let mut bytes = [0u8; 32];
        OsRandom.fill(&mut bytes).map_err(|_| CipherError::Random)?;
        if let Ok(secret) = SecretKey::from_slice(&bytes) {
            bytes.zeroize();
            let public = encode_compressed(&secret.public_key().to_projective())?;
            return Ok((secret, public));
        }
        bytes.zeroize();
    }
    Err(CipherError::Ecies)
}

fn shared_secret_x(point: &ProjectivePoint) -> Result<[u8; 32], CipherError> {
    let encoded = point.to_affine().to_encoded_point(true);
    let x = encoded.as_bytes().get(1..33).ok_or(CipherError::Ecies)?;
    x.try_into().map_err(|_| CipherError::Ecies)
}

fn encode_compressed(point: &ProjectivePoint) -> Result<[u8; 33], CipherError> {
    point
        .to_affine()
        .to_encoded_point(true)
        .as_bytes()
        .try_into()
        .map_err(|_| CipherError::Ecies)
}

fn derive_key_nonce(
    shared_x: &[u8],
    key: &mut [u8; 32],
    nonce: &mut [u8; NONCE_LEN],
) -> Result<(), CipherError> {
    let hk = Hkdf::<Sha256>::new(None, shared_x);
    let mut okm = [0u8; 44];
    hk.expand(ECIES_INFO, &mut okm)
        .map_err(|_| CipherError::Ecies)?;
    let key_part = okm.get(0..32).ok_or(CipherError::Ecies)?;
    let nonce_part = okm.get(32..44).ok_or(CipherError::Ecies)?;
    key.copy_from_slice(key_part);
    nonce.copy_from_slice(nonce_part);
    okm.zeroize();
    Ok(())
}

/// A recipient for the symmetric/asymmetric selector (REQ-CIPH-014).
#[derive(Clone, Copy, Debug)]
pub enum Recipient<'a> {
    /// A shared 32-byte symmetric key.
    Symmetric(&'a [u8]),
    /// A recipient compressed public key.
    Asymmetric(&'a [u8; 33]),
}

/// A sealed message tagged with the mode used.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SealedMessage {
    /// A symmetric AEAD ciphertext.
    Symmetric(Ciphertext),
    /// An ECIES ciphertext.
    Asymmetric(EciesCiphertext),
}

/// Seal a message for a recipient, selecting symmetric or asymmetric per the recipient
/// (REQ-CIPH-014, EP para 0126, GB §5). The symmetric path uses a fresh random nonce.
///
/// # Errors
/// [`CipherError`] on a randomness or AEAD failure.
pub fn seal_for(
    recipient: Recipient<'_>,
    plaintext: &[u8],
    aad: &[u8],
) -> Result<SealedMessage, CipherError> {
    match recipient {
        Recipient::Symmetric(key) => {
            let mut nonce = [0u8; NONCE_LEN];
            OsRandom.fill(&mut nonce).map_err(|_| CipherError::Random)?;
            let bytes = seal(key, &nonce, plaintext, aad)?;
            Ok(SealedMessage::Symmetric(Ciphertext { nonce, bytes }))
        }
        Recipient::Asymmetric(public_key) => Ok(SealedMessage::Asymmetric(ecies_encrypt(
            public_key, plaintext, aad,
        )?)),
    }
}

/// Open a sealed message with the matching key.
///
/// # Errors
/// [`CipherError::Aead`] on a mode mismatch or any AEAD failure.
pub fn open_for(
    symmetric_key: Option<&[u8]>,
    private_key: Option<&[u8]>,
    sealed: &SealedMessage,
    aad: &[u8],
) -> Result<SecretBytes, CipherError> {
    match sealed {
        SealedMessage::Symmetric(ct) => open(
            symmetric_key.ok_or(CipherError::Aead)?,
            &ct.nonce,
            &ct.bytes,
            aad,
        ),
        SealedMessage::Asymmetric(ct) => {
            ecies_decrypt(private_key.ok_or(CipherError::Aead)?, ct, aad)
        }
    }
}
