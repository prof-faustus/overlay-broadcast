//! KeyStore (Section 12): where seeds and long-term keys live.
//!
//! - [`KeyStore`] — the backend-abstracting trait (REQ-KST-001).
//! - [`EncryptedFileKeyStore`] — encrypted-at-rest file backend under an Argon2 KEK, the
//!   lowest-assurance tier (REQ-KST-012), fully implemented and tested here.
//! - [`shamir256`] — byte-wise GF(2^8) Shamir for k-of-n seed backup (REQ-KST-020).
//!
//! HSM (PKCS#11) and cloud-KMS backends (REQ-KST-010 / REQ-KST-011) are integration-only:
//! they require hardware/a service not present in this environment, so their tests are
//! `#[ignore]` naming the exact prerequisite (see `tst_kst_010_*` / `tst_kst_011_*`). The
//! intended crate pins are recorded in `docs/ARCHITECTURE.md`.
#![forbid(unsafe_code)]

pub mod error;
pub mod file_store;
pub mod shamir256;
pub mod store;

pub use error::KstError;
pub use file_store::EncryptedFileKeyStore;
pub use shamir256::{reconstruct, split, SeedShare};
pub use store::{KeyStore, WrappedShare};

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;
    use secmem::SecretBytes;

    // TST-KST-012 / TST-KST-001: an encrypted-file store generates a key, signs with it,
    // never writes the seed in the clear, and rejects the wrong passphrase.
    #[test]
    fn tst_kst_012_encrypted_at_rest_and_sign() {
        let mut store = EncryptedFileKeyStore::new(b"correct horse battery staple").unwrap();
        let pubkey = store.generate("authority", true).unwrap();

        // sign + verify against the returned public key (derive-or-use; key never exported)
        let prehash = [0x55u8; 32];
        let der = store.sign_prehash("authority", &prehash).unwrap();
        assert!(
            ckd::verify_der_prehash(&pubkey, &prehash, &der),
            "store-signed signature verifies"
        );
        assert_eq!(store.public_key("authority").unwrap(), pubkey);

        // import a recognizable seed and assert it is NOT present at rest
        let marker = [0xABu8; 32];
        store
            .import("marked", &SecretBytes::from_slice(&marker), true)
            .unwrap();
        let at_rest = store.ciphertext_at_rest("marked").unwrap();
        assert!(
            !at_rest.windows(marker.len()).any(|w| w == marker),
            "no plaintext seed touches the at-rest ciphertext"
        );

        // wrong passphrase -> different KEK -> AEAD fails (we reuse the same salt so only
        // the passphrase differs)
        let salt = store.salt();
        let mut reopened = EncryptedFileKeyStore::with_salt(b"wrong passphrase", salt).unwrap();
        reopened
            .import("x", &SecretBytes::from_slice(&marker), true)
            .unwrap();
        // a ciphertext sealed under the correct KEK cannot be read under the wrong one:
        // move the marked entry over by reconstructing the scenario through wrap/unwrap.
        let wrapped = store.wrap(b"secret payload").unwrap();
        assert!(matches!(reopened.unwrap(&wrapped), Err(KstError::WrongKey)));
    }

    // TST-KST-001: non-exportable keys cannot be exported; exportable ones can.
    #[test]
    fn tst_kst_001_export_policy() {
        let mut store = EncryptedFileKeyStore::new(b"pass").unwrap();
        store.generate("locked", false).unwrap();
        store.generate("free", true).unwrap();
        assert!(matches!(
            store.export("locked"),
            Err(KstError::NonExportable)
        ));
        assert!(store.export("free").is_ok());
        assert!(matches!(store.export("missing"), Err(KstError::NotFound)));
    }

    // TST-KST-001: crypto-shred removes the entry; subsequent use fails NotFound.
    #[test]
    fn tst_kst_001_delete_shreds() {
        let mut store = EncryptedFileKeyStore::new(b"pass").unwrap();
        store.generate("ephemeral", true).unwrap();
        store.delete("ephemeral").unwrap();
        assert_eq!(store.public_key("ephemeral"), Err(KstError::NotFound));
        assert_eq!(store.delete("ephemeral"), Err(KstError::NotFound));
    }

    // TST-KST-020: k-of-n seed backup round-trips through KeyStore-protected shares, and a
    // k-1 subset cannot reconstruct the original key.
    #[test]
    fn tst_kst_020_shamir_backup_recovery() {
        let mut store = EncryptedFileKeyStore::new(b"pass").unwrap();
        let pubkey = store.generate("master", true).unwrap();
        let shares = store.backup("master", 3, 5).unwrap();
        assert_eq!(shares.len(), 5);

        // any 3 shares restore the exact key (same public key). Recovery occurs in a store
        // sharing the original KEK (same passphrase + salt), since the shares are wrapped
        // under that KEK.
        let quorum = vec![shares[0].clone(), shares[2].clone(), shares[4].clone()];
        let mut recovered = EncryptedFileKeyStore::with_salt(b"pass", store.salt()).unwrap();
        recovered.restore("master", &quorum, true).unwrap();
        assert_eq!(
            recovered.public_key("master").unwrap(),
            pubkey,
            "any 3 of 5 shares recover the exact key"
        );

        // k-1 shares cannot reconstruct: the recovered key differs from the original
        let pair = vec![shares[0].clone(), shares[1].clone()];
        let mut wrong = EncryptedFileKeyStore::with_salt(b"pass", store.salt()).unwrap();
        wrong.restore("master", &pair, true).unwrap();
        assert_ne!(
            wrong.public_key("master").unwrap(),
            pubkey,
            "k-1 shares do not reconstruct the original key"
        );
    }

    // TST-KST-030: a SeedShare's Debug output redacts the share body (no secret in Debug).
    #[test]
    fn tst_kst_030_no_secret_in_debug() {
        let secret = [0x42u8; 32];
        let shares = split(&secret, 2, 3).unwrap();
        let rendered = format!("{:?}", shares[0]);
        assert!(
            rendered.contains("redacted"),
            "share body is redacted in Debug"
        );
        assert!(!rendered.contains("66, 66"), "no raw secret bytes in Debug");
    }

    // TST-KST-010 (REQ-KST-010): HSM/PKCS#11 backend — generate/use keys inside the HSM, a
    // non-exportable key cannot be exported. Requires a PKCS#11 module + token (e.g.
    // SoftHSM2 or a hardware HSM) and the pinned `cryptoki` crate; not present here.
    #[test]
    #[ignore = "REQ-KST-010 needs a PKCS#11 module/token (SoftHSM2 or hardware HSM) and the pinned cryptoki crate"]
    fn tst_kst_010_hsm_pkcs11() {
        panic!("REQ-KST-010 requires a PKCS#11 HSM token, not present in this environment");
    }

    // TST-KST-011 (REQ-KST-011): cloud-KMS envelope encryption — data keys wrapped by a KMS
    // master key, unwrap requires the KMS key. Requires KMS credentials + reachable service
    // (e.g. AWS KMS) and the pinned KMS client crate; not present here.
    #[test]
    #[ignore = "REQ-KST-011 needs cloud-KMS credentials and a reachable KMS service (e.g. AWS KMS) plus the pinned KMS client crate"]
    fn tst_kst_011_cloud_kms() {
        panic!("REQ-KST-011 requires a reachable cloud KMS, not present in this environment");
    }
}
