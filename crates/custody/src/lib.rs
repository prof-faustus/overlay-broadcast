//! Custody (Section 11): threshold signing and key lifecycle.
//!
//! - [`gg20`] — GG20 true-threshold *ECDSA*: `partial_sign` + `combine` yield a standard
//!   low-S BSV ECDSA signature under the group key with NO reconstruction (REQ-CUS-004).
//! - [`threshold`] — FROST-style threshold *Schnorr*, key never reconstructed
//!   (REQ-CUS-001/003), for authority signatures off the on-chain input path.
//! - [`shamir`] — Shamir secret sharing over the secp256k1 scalar field (REQ-CUS-005).
//! - [`reconstruction`] — fallback that transiently reconstructs the key to produce a
//!   consensus-valid low-S ECDSA signature, then wipes it (REQ-CUS-005).
//! - [`lifecycle`] — anchorable, hash-chained rotation/revocation log (REQ-CUS-006).
//!
//! The default authority signature is true-threshold; the GG20 path serves REQ-CUS-004's
//! requirement that a combined signature be a standard ECDSA signature for a BSV input.
//! All three GG18/20 malicious-security ZK proofs are implemented and verified inside every
//! MtA in [`gg20::sign`]: the initiator range proof and the responder consistency proof Π′
//! ([`rangeproof`]) and the Paillier-modulus well-formedness proof ([`modulusproof`]).
//! [`gg20::sign_identifiable`] gives **identifiable abort** — a bad proof is attributed to
//! the exact party ([`gg20::AbortError`]) and equivocation is localized by the
//! echo-broadcast round ([`echo`]). The last refinement is type-7 final-signature
//! attribution — see `docs/ARCHITECTURE.md`.
#![forbid(unsafe_code)]

pub mod echo;
pub mod error;
pub mod gg20;
pub mod lifecycle;
pub mod modulusproof;
mod paillier;
pub mod rangeproof;
pub mod reconstruction;
pub mod shamir;
pub mod threshold;

pub use error::CustodyError;
pub use lifecycle::{verify_lifecycle, EventKind, KeyCustodian, LifecycleEvent};
pub use shamir::{random_scalar, reconstruct, split, Share};
pub use threshold::{
    aggregate, aggregated_nonce, keygen, verify, verify_commitments, GroupKey, NonceCommitment,
    NonceReveal, PartialSig, ThresholdParty, ThresholdSignature,
};

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;
    use k256::Scalar;

    // Run the full FROST round protocol for a chosen set of share indices over an
    // already-generated group, returning the combined signature. The private key is
    // never assembled — only per-share partials are combined.
    fn frost_sign(
        group: &GroupKey,
        shares: &[Share],
        signer_indices: &[usize],
        message: &[u8],
    ) -> ThresholdSignature {
        let mut parties: Vec<ThresholdParty> = signer_indices
            .iter()
            .map(|&i| ThresholdParty::new(shares[i].clone()))
            .collect();
        let signing_set: Vec<Scalar> = parties.iter().map(ThresholdParty::index).collect();
        let commitments: Vec<NonceCommitment> =
            parties.iter_mut().map(|p| p.commit().unwrap()).collect();
        let reveals: Vec<NonceReveal> = parties.iter().map(|p| p.reveal().unwrap()).collect();
        assert!(
            verify_commitments(&commitments, &reveals),
            "every nonce matches its commitment"
        );
        let aggregated_r = aggregated_nonce(&reveals);
        let partials: Vec<PartialSig> = parties
            .iter()
            .map(|p| {
                p.partial_sign(message, group, aggregated_r, &signing_set)
                    .unwrap()
            })
            .collect();
        aggregate(&reveals, &partials)
    }

    // TST-CUS-001 (REQ-CUS-001): a t-of-n threshold signature verifies against the group
    // key, combining k partial signatures. The key is never reconstructed: GroupKey only
    // exposes the public key, ThresholdParty holds a single share, and there is no API
    // that returns the whole private key.
    #[test]
    fn tst_cus_001_threshold_sign_and_verify() {
        let message = b"anchor this overlay state";
        let (group, shares) = keygen(3, 5).unwrap();
        let signature = frost_sign(&group, &shares, &[0, 2, 4], message);
        assert!(
            verify(&group, message, &signature),
            "threshold signature is valid"
        );
        assert!(
            !verify(&group, b"different message", &signature),
            "signature does not verify for another message"
        );
    }

    // TST-CUS-001 (REQ-CUS-001 / REQ-CUS-003): a sub-threshold signing set (k-1) cannot
    // produce a verifying signature — Lagrange interpolation over fewer than t shares does
    // not recover the group key, so no single share (nor any k-1 subset) can sign.
    #[test]
    fn tst_cus_001b_subthreshold_cannot_sign() {
        let message = b"k-1 must fail";
        let (group, shares) = keygen(3, 5).unwrap();
        let undersigned = frost_sign(&group, &shares, &[0, 1], message);
        assert!(
            !verify(&group, message, &undersigned),
            "k-1 shares do not yield a valid signature"
        );
    }

    // TST-CUS-003 (REQ-CUS-003): any quorum of exactly t shares from the same group
    // signs successfully — the group key is fixed, the signing subset is interchangeable.
    #[test]
    fn tst_cus_003_any_quorum_signs() {
        let message = b"second quorum";
        let (group, shares) = keygen(3, 5).unwrap();
        let signature = frost_sign(&group, &shares, &[1, 2, 3], message);
        assert!(verify(&group, message, &signature));
    }

    // TST-CUS-001 (round-one binding): a tampered nonce commitment is rejected, so a party
    // cannot adaptively choose its nonce after seeing others (rogue-nonce defence).
    #[test]
    fn tst_cus_001c_commitment_binding() {
        let (_group, shares) = keygen(2, 3).unwrap();
        let mut a = ThresholdParty::new(shares[0].clone());
        let mut b = ThresholdParty::new(shares[1].clone());
        let mut commitments = vec![a.commit().unwrap(), b.commit().unwrap()];
        let reveals = vec![a.reveal().unwrap(), b.reveal().unwrap()];
        commitments[0].commitment[0] ^= 0xFF;
        assert!(
            !verify_commitments(&commitments, &reveals),
            "a corrupted commitment fails to verify"
        );
    }

    // TST-CUS-004 (REQ-CUS-004): GG20 true-threshold ECDSA — partial_sign + combine yield a
    // standard low-S BSV ECDSA signature that verifies under the group public key WITHOUT
    // the key ever being reconstructed; any t-quorum signs; a k-1 quorum cannot forge a
    // signature under the group key. The decisive oracle is k256's standard ECDSA verifier.
    // A 1024-bit Paillier modulus is used for test speed (n > q² suffices for correctness;
    // production uses >= 2048 — see the gg20 module caveat).
    #[test]
    fn tst_cus_004_threshold_ecdsa() {
        let (group, parties) = gg20::dealer_keygen(3, 5, 1024).unwrap();
        let pubkey = group.public_compressed();
        let prehash = [0x44u8; 32];

        let quorum: Vec<_> = [0usize, 2, 4].iter().map(|&i| parties[i].clone()).collect();
        let der = gg20::sign(&quorum, &prehash).unwrap();
        assert!(
            ckd::verify_der_prehash(&pubkey, &prehash, &der),
            "GG20 combined signature verifies as a standard ECDSA signature under the group key"
        );

        let quorum2: Vec<_> = [1usize, 2, 3].iter().map(|&i| parties[i].clone()).collect();
        let der2 = gg20::sign(&quorum2, &prehash).unwrap();
        assert!(
            ckd::verify_der_prehash(&pubkey, &prehash, &der2),
            "a different t-quorum signs equally validly"
        );

        let undersized: Vec<_> = [0usize, 1].iter().map(|&i| parties[i].clone()).collect();
        let der3 = gg20::sign(&undersized, &prehash).unwrap();
        assert!(
            !ckd::verify_der_prehash(&pubkey, &prehash, &der3),
            "k-1 shares cannot forge a signature under the group key"
        );
    }

    // TST-CUS-004 (range proof): the GG18/20 MtA range proof (now exercised inside
    // gg20::sign) verifies for an in-range value and is bound to its ciphertext — a
    // malicious initiator cannot reuse a proof for a different (out-of-range) ciphertext.
    #[test]
    fn tst_cus_004c_mta_range_proof() {
        use crate::paillier::PaillierPrivate;
        use crate::rangeproof::{prove, verify, RingPedersen};
        use num_bigint_dig::BigUint;

        let paillier = PaillierPrivate::generate(1024).unwrap();
        let pedersen = RingPedersen::generate(1024).unwrap();
        let q = gg20::curve_order();
        let value = BigUint::from(1_234_567u64);
        let nonce = paillier.public().random_nonce().unwrap();
        let ciphertext = paillier.public().encrypt_with(&value, &nonce);

        let proof = prove(
            paillier.public(),
            &pedersen,
            &ciphertext,
            &value,
            &nonce,
            &q,
        )
        .unwrap();
        assert!(
            verify(paillier.public(), &pedersen, &ciphertext, &proof, &q),
            "honest range proof verifies"
        );

        let other = paillier
            .public()
            .encrypt_with(&BigUint::from(42u64), &nonce);
        assert!(
            !verify(paillier.public(), &pedersen, &other, &proof, &q),
            "the proof is bound to its ciphertext"
        );
    }

    // TST-CUS-004 (modulus proof): a valid Paillier modulus proves well-formed and the
    // proof does not transfer to a different modulus (REQ-CUS-004 hardening).
    #[test]
    fn tst_cus_004d_paillier_modulus_proof() {
        use crate::modulusproof::verify as verify_modulus;
        use crate::paillier::PaillierPrivate;

        let paillier = PaillierPrivate::generate(1024).unwrap();
        let proof = paillier.prove_modulus().unwrap();
        assert!(
            verify_modulus(paillier.public().modulus(), &proof),
            "valid modulus proof verifies"
        );

        let other = PaillierPrivate::generate(1024).unwrap();
        assert!(
            !verify_modulus(other.public().modulus(), &proof),
            "the proof does not transfer to another modulus"
        );
    }

    // TST-CUS-004 (responder proof): an honestly-formed MtA response c_b = c_a^b·Enc(beta')
    // verifies, and the proof is bound to its exact response (REQ-CUS-004 hardening).
    #[test]
    fn tst_cus_004e_mta_responder_proof() {
        use crate::paillier::PaillierPrivate;
        use crate::rangeproof::{prove_responder, verify_responder, RingPedersen};
        use num_bigint_dig::BigUint;

        let paillier = PaillierPrivate::generate(1024).unwrap();
        let pedersen = RingPedersen::generate(1024).unwrap();
        let public = paillier.public();
        let q = gg20::curve_order();

        let a = BigUint::from(7u64);
        let nonce_a = public.random_nonce().unwrap();
        let c_a = public.encrypt_with(&a, &nonce_a);
        let b = BigUint::from(9u64);
        let beta = BigUint::from(123u64);
        let s = public.random_nonce().unwrap();
        let c_b = public.add(&public.mul_const(&c_a, &b), &public.encrypt_with(&beta, &s));

        let proof = prove_responder(public, &pedersen, &c_a, &c_b, &b, &beta, &s, &q).unwrap();
        assert!(
            verify_responder(public, &pedersen, &c_a, &c_b, &proof, &q),
            "honest responder proof verifies"
        );

        let tampered = public.add(&c_b, &public.encrypt_with(&BigUint::from(1u64), &s));
        assert!(
            !verify_responder(public, &pedersen, &c_a, &tampered, &proof, &q),
            "the proof is bound to its response"
        );
    }

    // TST-CUS-004 (echo-broadcast / identifiable abort): the echo round accepts consistent
    // views and identifies the exact sender that equivocated (sent different round-one
    // messages to different receivers).
    #[test]
    fn tst_cus_004f_echo_broadcast_identifies_equivocator() {
        use crate::echo::{run_echo_round, EchoOutcome, PartyView};

        // three parties, all receiving the same three round-one messages
        let honest = vec![b"m0".to_vec(), b"m1".to_vec(), b"m2".to_vec()];
        let consistent: Vec<PartyView> = (0..3)
            .map(|receiver| PartyView {
                receiver,
                messages: honest.clone(),
            })
            .collect();
        assert!(
            matches!(run_echo_round(&consistent), EchoOutcome::Consistent(_)),
            "agreeing views are consistent"
        );

        // party 1 equivocates: sends a different m1 to receiver 2
        let view0 = PartyView {
            receiver: 0,
            messages: vec![b"m0".to_vec(), b"m1".to_vec(), b"m2".to_vec()],
        };
        let view1 = PartyView {
            receiver: 1,
            messages: vec![b"m0".to_vec(), b"m1".to_vec(), b"m2".to_vec()],
        };
        let view2 = PartyView {
            receiver: 2,
            messages: vec![b"m0".to_vec(), b"m1-EVIL".to_vec(), b"m2".to_vec()],
        };
        assert_eq!(
            run_echo_round(&[view0, view1, view2]),
            EchoOutcome::Equivocator(1),
            "the equivocating sender is identified"
        );
    }

    // TST-CUS-004 (identifiable abort): a party that publishes a modulus proof not matching
    // its own modulus is named precisely by sign_identifiable, rather than failing silently.
    #[test]
    fn tst_cus_004g_identifiable_abort_attributes_fault() {
        use gg20::{AbortError, FaultKind, SignError};

        let (_group, mut parties) = gg20::dealer_keygen(2, 3, 1024).unwrap();
        let prehash = [0x77u8; 32];

        // honest run produces a signature
        assert!(
            gg20::sign_identifiable(&parties, &prehash).is_ok(),
            "honest quorum signs"
        );

        // corrupt party 1's modulus proof (swap in party 2's) so it no longer matches
        let source = parties[2].clone();
        parties[1].corrupt_modulus_proof(&source);
        let outcome = gg20::sign_identifiable(&parties, &prehash);
        assert_eq!(
            outcome,
            Err(SignError::Fault(AbortError {
                party: 1,
                fault: FaultKind::ModulusProof
            })),
            "the cheating party is identified"
        );
    }

    // TST-CUS-005 (REQ-CUS-005): reconstruction-mode produces a consensus-valid low-S ECDSA
    // signature over a prehash, verifiable against the group public key; the recovered key
    // is wiped. This is the SEPARATE fallback; default authority signing is threshold mode.
    #[test]
    fn tst_cus_005_reconstruction_ecdsa() {
        let (group, shares) = keygen(3, 5).unwrap();
        let quorum = vec![shares[0].clone(), shares[1].clone(), shares[4].clone()];
        let prehash = [0x11u8; 32];
        let signature = reconstruction::sign_prehash(&quorum, 3, &prehash).unwrap();
        let recovered_pubkey = reconstruction::public_key(&quorum, 3).unwrap();
        assert_eq!(
            recovered_pubkey,
            group.public_compressed(),
            "reconstructed key matches the threshold group key"
        );
        assert!(
            ckd::verify_der_prehash(&recovered_pubkey, &prehash, &signature),
            "ECDSA signature verifies as a standard BSV signature"
        );
    }

    // TST-CUS-005 (REQ-CUS-005, primitive): Shamir split/reconstruct round-trips at exactly
    // the threshold and any threshold subset; a sub-threshold set does not recover the secret.
    #[test]
    fn tst_cus_005b_shamir_roundtrip() {
        let secret = random_scalar().unwrap();
        let shares = split(secret, 3, 5).unwrap();
        assert_eq!(
            reconstruct(&shares[0..3]),
            secret,
            "exactly threshold shares reconstruct"
        );
        assert_eq!(
            reconstruct(&[shares[1].clone(), shares[3].clone(), shares[4].clone()]),
            secret,
            "any threshold subset reconstructs"
        );
        assert_ne!(
            reconstruct(&shares[0..2]),
            secret,
            "fewer than threshold shares do not reconstruct"
        );
    }

    // TST-CUS-005 (REQ-CUS-005, negative): reconstruction signing refuses a sub-threshold set.
    #[test]
    fn tst_cus_005c_reconstruction_requires_threshold() {
        let (_group, shares) = keygen(3, 5).unwrap();
        let prehash = [0x22u8; 32];
        assert_eq!(
            reconstruction::sign_prehash(&shares[0..2], 3, &prehash),
            Err(CustodyError::InsufficientShares)
        );
    }

    // TST-CUS-006 (REQ-CUS-006): a genesis→rotation→revocation chain verifies, the head hash
    // (anchorable on chain) changes at each step, the old key cannot sign after rotation
    // (rotation moves current_key and a revoked chain refuses rotation), and tampering with
    // any recorded event is detected.
    #[test]
    fn tst_cus_006_lifecycle_chain() {
        let key_a = [0xA1u8; 33];
        let key_b = [0xB2u8; 33];
        let mut custodian = KeyCustodian::new(key_a, 100);
        let genesis_head = custodian.head_hash();
        custodian.rotate(key_b, 200).unwrap();
        let rotated_head = custodian.head_hash();
        assert_ne!(
            genesis_head.internal(),
            rotated_head.internal(),
            "rotation changes the anchorable head"
        );
        assert_eq!(custodian.current_key(), key_b);
        custodian.revoke(300).unwrap();
        assert!(custodian.is_revoked());
        assert!(
            verify_lifecycle(custodian.events()),
            "the honest chain verifies"
        );
        assert_eq!(custodian.rotate(key_a, 400), Err(CustodyError::Revoked));
        let mut tampered = custodian.events().to_vec();
        tampered[1].public_key[0] ^= 0xFF;
        assert!(!verify_lifecycle(&tampered), "a tampered event is detected");
    }

    // TST-CUS-006 (REQ-CUS-006, terminality): a revocation must be terminal — no event may
    // follow it in a valid log, even one with a structurally correct hash.
    #[test]
    fn tst_cus_006b_revocation_is_terminal() {
        let key = [0x07u8; 33];
        let mut custodian = KeyCustodian::new(key, 1);
        custodian.revoke(2).unwrap();
        let mut events = custodian.events().to_vec();
        let prev_hash = events[1].hash;
        let forged_hash = {
            let mut buf = Vec::new();
            buf.push(1u8); // Rotation tag
            buf.extend_from_slice(&key);
            buf.extend_from_slice(&3u64.to_be_bytes());
            buf.extend_from_slice(prev_hash.internal());
            bsv::double_sha256(&buf)
        };
        events.push(LifecycleEvent {
            kind: EventKind::Rotation,
            public_key: key,
            logical_time: 3,
            prev_hash,
            hash: forged_hash,
        });
        assert!(
            !verify_lifecycle(&events),
            "no event may follow a revocation"
        );
    }

    // TST-CUS-007 (REQ-CUS-007): GAP — threshold shares must be sourced/held by the
    // KeyStore (Section 12, the `kst` crate) and computed where the share lives, not held
    // in process memory beyond use. The KeyStore is built in a later step; this test is
    // enabled once `kst` exists.
    #[test]
    #[ignore = "REQ-CUS-007 requires the KeyStore (Section 12, kst crate), built in a later step"]
    fn tst_cus_007_shares_via_keystore() {
        panic!("REQ-CUS-007 blocked on the Section 12 KeyStore (kst crate)");
    }

    // TST-CUS-010 (REQ-CUS-010 / REQ-UNI-007): the signature produced through custody is a
    // standard, low-S BSV ECDSA signature — verifiable and already S-normalized.
    #[test]
    fn tst_cus_010_signature_is_low_s() {
        use k256::ecdsa::Signature;
        let (_group, shares) = keygen(3, 5).unwrap();
        let quorum = vec![shares[0].clone(), shares[2].clone(), shares[3].clone()];
        let prehash = [0x33u8; 32];
        let der = reconstruction::sign_prehash(&quorum, 3, &prehash).unwrap();
        let signature = Signature::from_der(&der).unwrap();
        assert!(
            signature.normalize_s().is_none(),
            "the combined custody signature is already low-S"
        );
    }
}
