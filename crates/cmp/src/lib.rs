//! Compliance, privacy, and audit integrity (Section 20).
//!
//! - [`classify`] — on-chain write guard refusing cleartext/personal-data payloads
//!   (REQ-CMP-001).
//! - crypto-shredding erasure via the KeyStore (REQ-CMP-002, demonstrated in tests).
//! - [`audit`] — tamper-evident hash-chained audit log (REQ-CMP-003).
//! - recovery and incident drills referencing the runbooks (REQ-CMP-004).
//!
//! Runbooks: `docs/DISASTER_RECOVERY.md`, `docs/KEY_LOSS.md`,
//! `docs/INCIDENT_RESPONSE.md`; data policy: `docs/DATA_CLASSIFICATION.md`; service
//! objectives: `docs/SLOs.md` (REQ-CMP-005).
#![forbid(unsafe_code)]

pub mod audit;
pub mod classify;
pub mod error;

pub use audit::{verify_audit_chain, AuditRecord, TamperEvidentAudit};
pub use classify::{guard_on_chain_write, ContentClass, Sensitivity};
pub use error::CmpError;

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;
    use cipher::{open, seal};
    use custody::KeyCustodian;
    use kst::{EncryptedFileKeyStore, KeyStore};

    // TST-CMP-001: the on-chain write path refuses cleartext (personal data named
    // specifically); encrypted/obfuscated content is permitted.
    #[test]
    fn tst_cmp_001_write_guard_refuses_cleartext() {
        assert_eq!(
            guard_on_chain_write(ContentClass::Cleartext, Sensitivity::PersonalData),
            Err(CmpError::CleartextPersonalData)
        );
        assert_eq!(
            guard_on_chain_write(ContentClass::Cleartext, Sensitivity::Public),
            Err(CmpError::PlaintextOnChain)
        );
        assert!(guard_on_chain_write(ContentClass::Encrypted, Sensitivity::PersonalData).is_ok());
        assert!(guard_on_chain_write(ContentClass::Obfuscated, Sensitivity::PersonalData).is_ok());
    }

    // TST-CMP-002: right-to-erasure is crypto-shredding — an on-chain item is decryptable
    // while its key lives in the KeyStore, and permanently undecryptable once the key is
    // destroyed (the only copy is in the store).
    #[test]
    fn tst_cmp_002_crypto_shredding_erasure() {
        let mut store = EncryptedFileKeyStore::new(b"operator-pw").unwrap();
        store.generate("record-42", true).unwrap();
        let nonce = [0u8; 12];
        let plaintext = b"personal data for the subject";

        // encrypt the on-chain item under the record's key (held only in the store)
        let item = {
            let key = store.export("record-42").unwrap();
            let key_bytes = <[u8; 32]>::try_from(key.expose()).unwrap();
            seal(&key_bytes, &nonce, plaintext, b"record-42").unwrap()
        };

        // decryptable while the key exists
        let key = store.export("record-42").unwrap();
        let key_bytes = <[u8; 32]>::try_from(key.expose()).unwrap();
        assert_eq!(
            open(&key_bytes, &nonce, &item, b"record-42")
                .unwrap()
                .expose(),
            plaintext
        );

        // erasure: crypto-shred the key
        store.delete("record-42").unwrap();

        // the key is destroyed — no path remains to decrypt the on-chain item
        assert!(
            store.export("record-42").is_err(),
            "the key is permanently destroyed"
        );
        // a wrong key cannot open the item (the AEAD tag fails)
        assert!(open(&[0u8; 32], &nonce, &item, b"record-42").is_err());
    }

    // TST-CMP-003: the audit log is tamper-evident — the honest chain verifies and any
    // altered field is detected.
    #[test]
    fn tst_cmp_003_tamper_evident_audit() {
        let mut audit = TamperEvidentAudit::new();
        let genesis_head = audit.head_hash();
        audit.append(1, "svc", "custody.keygen");
        audit.append(2, "svc", "overlay.write");
        audit.append(3, "ops", "custody.rotate");
        assert!(
            verify_audit_chain(audit.records()),
            "the honest chain verifies"
        );
        assert_ne!(
            audit.head_hash().internal(),
            genesis_head.internal(),
            "the head advances (anchorable)"
        );

        let mut tampered = audit.records().to_vec();
        tampered[1].action = "overlay.delete".to_owned();
        assert!(
            !verify_audit_chain(&tampered),
            "a tampered entry is detected"
        );
    }

    // TST-CMP-004: the key-loss recovery drill (k-of-n Shamir restore) and the
    // incident-response drill (rotate off a compromised key, then revoke) execute as the
    // runbooks describe.
    #[test]
    fn tst_cmp_004_recovery_and_incident_drills() {
        // KEY_LOSS.md drill: master-seed loss + k-of-n recovery
        let mut store = EncryptedFileKeyStore::new(b"pw").unwrap();
        let pubkey = store.generate("master", true).unwrap();
        let shares = store.backup("master", 3, 5).unwrap();
        let quorum = vec![shares[0].clone(), shares[2].clone(), shares[4].clone()];
        let mut recovered = EncryptedFileKeyStore::with_salt(b"pw", store.salt()).unwrap();
        recovered.restore("master", &quorum, true).unwrap();
        assert_eq!(
            recovered.public_key("master").unwrap(),
            pubkey,
            "k-of-n recovery restores the master key"
        );

        // INCIDENT_RESPONSE.md drill: suspected compromise -> rotate -> revoke
        let mut custodian = KeyCustodian::new([0x01u8; 33], 1);
        let compromised = custodian.current_key();
        custodian.rotate([0x02u8; 33], 2).unwrap();
        assert_ne!(
            custodian.current_key(),
            compromised,
            "rotation moves off the compromised key"
        );
        custodian.revoke(3).unwrap();
        assert!(
            custodian.is_revoked(),
            "the compromised custody chain is revoked"
        );
    }
}
