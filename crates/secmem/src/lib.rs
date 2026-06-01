#![deny(unsafe_code)]
//! `secmem`: audited zeroizing secret containers with best-effort memory locking.
//!
//! This is the ONLY crate in the workspace that contains `unsafe` (REQ-GOV-010): the
//! crate root denies `unsafe_code` and the single `lock` module re-enables it
//! per-call with `// SAFETY:` justifications, for `mlock`/`VirtualLock` only. Every
//! secret value lives in [`Secret`] or [`SecretBytes`]: zeroized on drop, redacted in
//! `Debug`, never `Serialize`/`Display`, compared in constant time.

mod bytes;
mod error;
mod lock;
mod random;
mod secret;

pub use bytes::SecretBytes;
pub use error::{LockError, RandError};
pub use random::{OsRandom, SecureRandom};
pub use secret::Secret;

#[cfg(any(test, feature = "test-deterministic"))]
pub use random::DeterministicRng;

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;
    use crate::random::DeterministicRng;

    // TST-SECMEM-001: Debug redacts; the secret is still accessible via expose().
    #[test]
    fn tst_secmem_001_secret_redacts_debug() {
        let s = Secret::new(0xDEAD_BEEF_u64);
        assert_eq!(format!("{s:?}"), "Secret(<redacted>)");
        assert_eq!(*s.expose(), 0xDEAD_BEEF_u64);
    }

    // TST-SECMEM-002: constant-time equality and exposure behave as specified.
    #[test]
    fn tst_secmem_002_secretbytes_ct_eq_and_expose() {
        let a = SecretBytes::from_slice(&[1, 2, 3, 4]);
        let b = SecretBytes::from_slice(&[1, 2, 3, 4]);
        let c = SecretBytes::from_slice(&[1, 2, 3, 5]);
        let d = SecretBytes::from_slice(&[1, 2, 3]);
        assert!(a.ct_eq(&b));
        assert!(!a.ct_eq(&c));
        assert!(!a.ct_eq(&d), "different lengths are not equal");
        assert_eq!(a.expose(), &[1, 2, 3, 4]);
        assert!(format!("{a:?}").contains("redacted"));
        assert!(!a.is_empty());
    }

    // TST-SECMEM-003: lock attempt and fallback never panic; round-trip if available.
    #[test]
    fn tst_secmem_003_lock_roundtrip_no_panic() {
        let buf = [7u8; 64];
        if lock::lock_region(buf.as_ptr(), buf.len()).is_ok() {
            assert!(lock::unlock_region(buf.as_ptr(), buf.len()).is_ok());
        }
        assert!(
            lock::lock_region(buf.as_ptr(), 0).is_ok(),
            "zero length is a no-op"
        );
    }

    // TST-SECMEM-004/005: construction from a random source; determinism and
    // seed-sensitivity of the test RNG; OS RNG fills the requested length.
    #[test]
    fn tst_secmem_004_005_random_construction() {
        let mut rng = DeterministicRng::new(42);
        let s1 = SecretBytes::random(&mut rng, 32).unwrap();
        let mut rng_same = DeterministicRng::new(42);
        let s2 = SecretBytes::random(&mut rng_same, 32).unwrap();
        assert!(s1.ct_eq(&s2), "same seed reproduces the same bytes");

        let mut rng_diff = DeterministicRng::new(43);
        let s3 = SecretBytes::random(&mut rng_diff, 32).unwrap();
        assert!(!s1.ct_eq(&s3), "a different seed yields different bytes");
        assert_eq!(s1.len(), 32);

        let mut os = OsRandom;
        let r = SecretBytes::random(&mut os, 48).unwrap();
        assert_eq!(r.len(), 48);
    }

    // The zeroize path this crate relies on actually clears memory.
    #[test]
    fn zeroize_clears_buffer() {
        use zeroize::Zeroize;
        let mut v = vec![9u8; 16];
        v.zeroize();
        assert!(v.iter().all(|b| *b == 0));
    }
}
