#![forbid(unsafe_code)]
//! `cipher`: the project's symmetric AEAD (AES-256-GCM), authenticated key-wrap, and
//! the Signer/Verifier wrapper over the verified secp256k1 pin (REQ-CIPH-001/010/012/
//! 013). ECIES (the asymmetric path) and the symmetric/asymmetric selector build on
//! this. Secret inputs and outputs are `SecretBytes`; decrypted plaintext is zeroized.

mod aead;
mod ecies;
mod error;
mod keywrap;
mod sign;

pub use aead::{open, seal, AeadCipher, Ciphertext, KEY_LEN, NONCE_LEN};
pub use ecies::{
    ecies_decrypt, ecies_encrypt, open_for, seal_for, EciesCiphertext, Recipient, SealedMessage,
};
pub use error::CipherError;
pub use keywrap::{unwrap, wrap, WrappedKey};
pub use sign::{Secp256k1Signer, Secp256k1Verifier, Signer, Verifier};

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;
    use secmem::{OsRandom, SecretBytes, SecureRandom};
    use std::collections::HashSet;

    fn random_key() -> SecretBytes {
        SecretBytes::random(&mut OsRandom, KEY_LEN).unwrap()
    }

    // TST-CIPH-010: AES-256-GCM round-trips; a tampered ciphertext or wrong aad fails;
    // nonces are unique across many encryptions; nonce reuse is impossible.
    #[test]
    fn tst_ciph_010_aead_roundtrip_tamper_and_nonce_uniqueness() {
        let key = random_key();
        let mut cipher = AeadCipher::new(key, 1).unwrap();
        let ct = cipher.encrypt(b"top secret", b"context").unwrap();
        assert_eq!(
            cipher.decrypt(&ct, b"context").unwrap().expose(),
            b"top secret"
        );
        // wrong aad fails
        assert_eq!(
            cipher.decrypt(&ct, b"other").unwrap_err(),
            CipherError::Aead
        );
        // tampered ciphertext fails
        let mut bad = ct.clone();
        if let Some(b) = bad.bytes.first_mut() {
            *b ^= 0xff;
        }
        assert_eq!(
            cipher.decrypt(&bad, b"context").unwrap_err(),
            CipherError::Aead
        );

        // nonces are unique across many encryptions.
        let key2 = random_key();
        let mut c2 = AeadCipher::new(key2, 7).unwrap();
        let mut nonces = HashSet::new();
        for _ in 0..1000 {
            let out = c2.encrypt(b"x", b"").unwrap();
            assert!(
                nonces.insert(out.nonce),
                "nonce must never repeat under a key"
            );
        }
    }

    // TST-CIPH-012: authenticated key-wrap round-trips and rejects a tampered wrap.
    #[test]
    fn tst_ciph_012_authenticated_key_wrap() {
        let wrapping = random_key();
        let secret = random_key();
        let wrapped = wrap(wrapping.expose(), secret.expose()).unwrap();
        let unwrapped = unwrap(wrapping.expose(), &wrapped).unwrap();
        assert!(unwrapped.ct_eq(&secret));
        // a tampered wrap is rejected.
        let mut bad = wrapped.clone();
        if let Some(b) = bad.bytes.first_mut() {
            *b ^= 0xff;
        }
        assert_eq!(
            unwrap(wrapping.expose(), &bad).unwrap_err(),
            CipherError::Aead
        );
        // a wrong wrapping key is rejected.
        let other = random_key();
        assert!(unwrap(other.expose(), &wrapped).is_err());
    }

    // TST-CIPH-001: the Signer/Verifier wrapper signs (low-S, RFC-6979) and verifies;
    // a wrong message is rejected; signing the same message twice is deterministic.
    #[test]
    fn tst_ciph_001_signer_verifier() {
        let mut sk = [0u8; 32];
        OsRandom.fill(&mut sk).unwrap();
        let signer = Secp256k1Signer::new(SecretBytes::from_slice(&sk)).unwrap();
        let message = b"authorise the write";
        let sig = signer.sign(message).unwrap();
        let sig2 = signer.sign(message).unwrap();
        assert_eq!(sig, sig2, "RFC-6979 deterministic via the wrapper");
        let verifier = Secp256k1Verifier::new(signer.verifying_key().unwrap());
        assert!(verifier.verify(message, &sig));
        assert!(!verifier.verify(b"a different message", &sig));
    }

    fn recipient_keypair() -> (Vec<u8>, [u8; 33]) {
        let key = ckd::XPriv::from_seed(&[0x42u8; 32]).unwrap();
        (
            key.private_key_bytes().to_vec(),
            key.public_key_compressed().unwrap(),
        )
    }

    // TST-CIPH-011: ECIES round-trips; the wrong private key and a tampered ciphertext
    // both fail.
    #[test]
    fn tst_ciph_011_ecies() {
        let (priv_bytes, pub_bytes) = recipient_keypair();
        let message = b"asymmetric payload";
        let ct = ecies_encrypt(&pub_bytes, message, b"ctx").unwrap();
        assert_eq!(
            ecies_decrypt(&priv_bytes, &ct, b"ctx").unwrap().expose(),
            message
        );
        // wrong recipient key fails.
        let (other_priv, _) = {
            let key = ckd::XPriv::from_seed(&[0x99u8; 32]).unwrap();
            (key.private_key_bytes().to_vec(), ())
        };
        assert!(ecies_decrypt(&other_priv, &ct, b"ctx").is_err());
        // tampered ciphertext fails.
        let mut bad = ct.clone();
        if let Some(b) = bad.bytes.first_mut() {
            *b ^= 0xff;
        }
        assert!(ecies_decrypt(&priv_bytes, &bad, b"ctx").is_err());
        // a fresh encryption uses a fresh ephemeral key.
        let ct2 = ecies_encrypt(&pub_bytes, message, b"ctx").unwrap();
        assert_ne!(ct.ephemeral_public_key, ct2.ephemeral_public_key);
    }

    // TST-CIPH-014: both symmetric and asymmetric modes are selectable and round-trip.
    #[test]
    fn tst_ciph_014_symmetric_asymmetric_selector() {
        let message = b"mode-selectable message";
        // symmetric
        let key = random_key();
        let sym = seal_for(Recipient::Symmetric(key.expose()), message, b"a").unwrap();
        assert!(matches!(sym, SealedMessage::Symmetric(_)));
        assert_eq!(
            open_for(Some(key.expose()), None, &sym, b"a")
                .unwrap()
                .expose(),
            message
        );
        // asymmetric
        let (priv_bytes, pub_bytes) = recipient_keypair();
        let asym = seal_for(Recipient::Asymmetric(&pub_bytes), message, b"a").unwrap();
        assert!(matches!(asym, SealedMessage::Asymmetric(_)));
        assert_eq!(
            open_for(None, Some(&priv_bytes), &asym, b"a")
                .unwrap()
                .expose(),
            message
        );
        // a mode mismatch is refused.
        assert!(open_for(None, Some(&priv_bytes), &sym, b"a").is_err());
    }
}
