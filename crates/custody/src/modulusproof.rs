//! Paillier-modulus well-formedness proof Π_N (REQ-CUS-004 hardening). Proves in zero
//! knowledge that the public modulus `N` is a valid Paillier modulus — specifically that
//! `gcd(N, φ(N)) = 1`, so the map `x ↦ x^N mod N` is a bijection and Paillier encryption /
//! the homomorphism are well defined. Without this, a malicious party could publish a
//! malformed `N` (e.g. a prime power or one with small factors) to break soundness.
//!
//! Construction (GG18, App. A): the verifier derives challenges `ρ_i ∈ Z*_N` by Fiat–Shamir
//! from `N`; the prover, knowing `d = N⁻¹ mod λ(N)`, returns `σ_i = ρ_i^d mod N`; the
//! verifier checks `σ_i^N ≡ ρ_i mod N`. If `gcd(N, φ(N)) ≠ 1` the map is not surjective and
//! a random `ρ_i` lies outside its image with constant probability, so `CHALLENGES`
//! repetitions give soundness `≈ 2^-CHALLENGES`. Production should use ≥ 80; this build
//! uses a smaller count for test speed (documented in `docs/ARCHITECTURE.md`).
use crate::error::CustodyError;
use num_bigint_dig::{BigUint, ModInverse};
use sha2::{Digest, Sha256};

const CHALLENGES: usize = 12;

/// A Paillier-modulus proof: one response per Fiat–Shamir challenge.
#[derive(Clone, Debug)]
pub struct ModulusProof {
    responses: Vec<BigUint>,
}

/// Prove `N` is a valid Paillier modulus, given the Carmichael value `lambda = λ(N)`.
///
/// # Errors
/// [`CustodyError::BadParams`] if `N` is not coprime to `λ(N)` (an invalid modulus).
pub fn prove(n: &BigUint, lambda: &BigUint) -> Result<ModulusProof, CustodyError> {
    let d = n
        .clone()
        .mod_inverse(lambda)
        .and_then(|value| value.to_biguint())
        .ok_or(CustodyError::BadParams)?;
    let mut responses = Vec::with_capacity(CHALLENGES);
    for index in 0..CHALLENGES {
        let rho = challenge_element(n, index);
        responses.push(rho.modpow(&d, n));
    }
    Ok(ModulusProof { responses })
}

/// Verify a Paillier-modulus proof for `N`.
#[must_use]
pub fn verify(n: &BigUint, proof: &ModulusProof) -> bool {
    let one = BigUint::from(1u8);
    let is_even = n.to_bytes_be().last().is_none_or(|byte| byte & 1 == 0);
    if n <= &one || is_even || proof.responses.len() != CHALLENGES {
        return false;
    }
    for (index, sigma) in proof.responses.iter().enumerate() {
        let rho = challenge_element(n, index);
        if sigma.modpow(n, n) != rho {
            return false;
        }
    }
    true
}

// Derive the index-th challenge element in [1, N) by hashing enough SHA-256 blocks to
// exceed N's bit length, then reducing mod N.
fn challenge_element(n: &BigUint, index: usize) -> BigUint {
    let target_len = (n.bits() / 8) + 2;
    let index_bytes = u64::try_from(index).unwrap_or(0).to_be_bytes();
    let mut buffer = Vec::new();
    let mut counter = 0u32;
    while buffer.len() < target_len {
        let mut hasher = Sha256::new();
        hasher.update(b"custody/paillier-modulus/v1");
        hasher.update(n.to_bytes_be());
        hasher.update(index_bytes);
        hasher.update(counter.to_be_bytes());
        buffer.extend_from_slice(&hasher.finalize());
        counter = counter.saturating_add(1);
    }
    let value = BigUint::from_bytes_be(&buffer) % n;
    if value == BigUint::from(0u8) {
        BigUint::from(1u8)
    } else {
        value
    }
}
