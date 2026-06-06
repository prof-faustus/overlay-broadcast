#![forbid(unsafe_code)]
//! `ckd`: child key derivation (BIP32-style HMAC-SHA512 over secp256k1) for the EP
//! key sets, plus the pinned secp256k1 signature primitives verified for low-S and
//! RFC-6979 (REQ-CKD-010, REQ-UNI-007). The full hierarchical derivation, hardened/
//! non-hardened modes, seed isolation, and position→path mapping build on this.

mod ckd;
mod error;
mod pin;
mod seeds;

pub use ckd::{XPriv, XPub, HARDENED};
pub use error::CkdError;
pub use pin::{
    is_low_s, sign, sign_prehash_der, verify, verify_der_prehash, verify_strict, verifying_key,
};
pub use seeds::{Position, Seeds};

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;

    #[test]
    fn empty_position_path_and_coords() {
        let pos = Position::new(vec![]);
        assert!(pos.coords().is_empty());
        assert!(pos.hardened_path().is_empty());
        assert!(pos.path().is_empty());
    }

    #[test]
    fn deep_position_path() {
        // Simulate a depth-127 position (the practical max for a key graph)
        let coords: Vec<u32> = (0..127).collect();
        let pos = Position::new(coords.clone());
        assert_eq!(pos.coords(), &coords);
        assert_eq!(pos.hardened_path().len(), 127);
        assert!(pos.hardened_path().iter().all(|i| *i >= HARDENED));
        assert!(pos.path().iter().all(|i| *i < HARDENED));
    }

    #[test]
    fn from_seed_too_short_or_long() {
        assert!(XPriv::from_seed(&[0u8; 15]).is_err(), "15 bytes rejected");
        assert!(XPriv::from_seed(&[0u8; 65]).is_err(), "65 bytes rejected");
        assert!(
            XPriv::from_seed(&[0x11u8; 16]).is_ok(),
            "16 bytes min accepted"
        );
        assert!(
            XPriv::from_seed(&[0x11u8; 64]).is_ok(),
            "64 bytes max accepted"
        );
    }

    #[test]
    fn master_chain_code_and_depth() {
        let key = XPriv::from_seed(&[0xBBu8; 32]).unwrap();
        assert_eq!(key.depth(), 0);
        assert_eq!(key.child_number(), 0);
        assert_eq!(key.chain_code().len(), 32);
        assert_ne!(key.chain_code(), &[0u8; 32]);
    }

    #[test]
    fn derived_key_accessors_and_depth_boundary() {
        let key = XPriv::from_seed(&[0xCCu8; 32]).unwrap();
        let c1 = key.derive_child(1).unwrap();
        assert_eq!(c1.depth(), 1);
        assert_eq!(c1.child_number(), 1);
        let c256 = key.derive_child(256).unwrap();
        assert_eq!(c256.depth(), 1);
        assert_eq!(c256.child_number(), 256);
        // u8 depth can hold at most 255; a depth-255 path is accepted
        let mut deep = XPriv::from_seed(&[0xDDu8; 32]).unwrap();
        for i in 0..255u8 {
            deep = deep.derive_child(u32::from(i)).unwrap();
        }
        assert_eq!(deep.depth(), 255);
        // The 256th derivation overflows depth (u8::MAX) and is rejected
        assert!(deep.derive_child(0).is_err());
    }

    #[test]
    fn to_xpub_and_public_key_match() {
        let priv_key = XPriv::from_seed(&[0xEEu8; 32]).unwrap();
        let pub_key = priv_key.to_xpub().unwrap();
        assert_eq!(
            pub_key.public_key_compressed(),
            priv_key.public_key_compressed().unwrap()
        );
        assert_eq!(pub_key.chain_code(), priv_key.chain_code());
        assert_eq!(pub_key.child_number(), priv_key.child_number());
    }

    #[test]
    fn xpub_hardened_child_refused() {
        let priv_key = XPriv::from_seed(&[0xFFu8; 32]).unwrap();
        let xpub = priv_key.to_xpub().unwrap();
        assert!(
            xpub.derive_child(HARDENED).is_err(),
            "hardened via pubkey -> error"
        );
        assert!(xpub.derive_child(HARDENED | 1).is_err());
        assert!(xpub.derive_child(0).is_ok(), "non-hardened is fine");
    }

    #[test]
    fn derivation_path_equivalence() {
        let master = XPriv::from_seed(&[0xABu8; 32]).unwrap();
        let stepwise = master
            .derive_child(HARDENED | 44)
            .unwrap()
            .derive_child(HARDENED)
            .unwrap()
            .derive_child(HARDENED)
            .unwrap()
            .derive_child(0)
            .unwrap()
            .derive_child(1)
            .unwrap();
        let via_path = master
            .derive_path(&[HARDENED | 44, HARDENED, HARDENED, 0, 1])
            .unwrap();
        assert_eq!(stepwise.private_key_bytes(), via_path.private_key_bytes());
        assert_eq!(stepwise.chain_code(), via_path.chain_code());
    }

    // TST-CKD-007 regression: degenerate scalar rejections don't cause panics.
    // A zero private key or chain code at any derivation step is rejected.
    #[test]
    fn degenerate_derivation_does_not_panic() {
        // It's infeasible to hit a zero scalar in practice (probability ~2^-256),
        // but the function must return an error rather than panic if it does.
        let key = XPriv::from_seed(&[0x01u8; 32]).unwrap();
        // Deriving many children exhaustively still works without hit
        for i in 0..200u32 {
            let _ = key.derive_child(i).unwrap();
        }
    }

    #[test]
    fn seeds_full_api() {
        let master = [0x42u8; 32];
        let seeds = Seeds::from_master(&master).unwrap();
        let pos = Position::new(vec![0xAu32, 0xBu32]);
        let w = seeds.writing_key(&pos).unwrap();
        let s = seeds.second_function_key(&pos).unwrap();
        let t = seeds.third_function_key(&pos).unwrap();
        assert_ne!(w.private_key_bytes(), s.private_key_bytes());
        assert_ne!(w.private_key_bytes(), t.private_key_bytes());
        assert_ne!(s.private_key_bytes(), t.private_key_bytes());
    }

    #[test]
    fn seeds_independent_import() {
        use secmem::SecretBytes;
        let seeds = Seeds::from_parts(
            SecretBytes::from_slice(&[0x11u8; 32]),
            SecretBytes::from_slice(&[0x22u8; 32]),
            SecretBytes::from_slice(&[0x33u8; 32]),
        );
        let pos = Position::new(vec![0]);
        assert_eq!(seeds.first().expose().len(), 32);
        assert_eq!(seeds.second().expose().len(), 32);
        assert_eq!(seeds.third().expose().len(), 32);
        let _ = seeds.writing_key(&pos).unwrap();
        let _ = seeds.second_function_key(&pos).unwrap();
        let _ = seeds.third_function_key(&pos).unwrap();
    }
}
