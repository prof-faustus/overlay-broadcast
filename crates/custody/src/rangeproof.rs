//! GG18/20 MtA range proof — "Alice's proof" Π (REQ-CUS-004 malicious-security
//! hardening). When the MtA initiator sends `c = Enc_A(a; r)` for her secret share `a`,
//! she proves in zero knowledge that the plaintext lies in `[0, q³]` (the relaxed MtA
//! bound), so a malicious initiator cannot smuggle an out-of-range value to leak the
//! responder's secret. The proof is a Schnorr-style sigma protocol over a ring-Pedersen
//! commitment, made non-interactive by Fiat–Shamir.
//!
//! Construction (Gennaro–Goldfeder 2018/2020, App. A; Lindell 2017): with auxiliary
//! ring-Pedersen parameters `(Ñ, h1, h2 = h1^λ mod Ñ)` whose discrete log λ the prover does
//! not know, the prover commits `z = h1^a·h2^ρ`, `u = Γ^α·β^n` (a Paillier encryption of a
//! random `α`), `w = h1^α·h2^γ`; the verifier's challenge `e` binds them; the responses
//! `s = r^e·β`, `s1 = e·a+α`, `s2 = e·ρ+γ` satisfy `Γ^{s1}·s^n = u·c^e (mod n²)` and
//! `h1^{s1}·h2^{s2} = w·z^e (mod Ñ)` with `s1 ≤ q³`.
//!
//! This closes the *initiator* range proof. The responder consistency proof (Π′ / MtAwc)
//! and the Paillier-modulus well-formedness proof remain the next hardening items (see
//! `docs/ARCHITECTURE.md`).
use crate::error::CustodyError;
use crate::paillier::PaillierPublic;
use num_bigint_dig::{BigUint, RandBigInt, RandPrime};
use num_integer::Integer;
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};

/// Auxiliary ring-Pedersen parameters held by the proof verifier. `h2 = h1^λ mod n_tilde`
/// for a random λ that is generated and then discarded, so the prover cannot know it.
#[derive(Clone, Debug)]
pub struct RingPedersen {
    n_tilde: BigUint,
    h1: BigUint,
    h2: BigUint,
}

impl RingPedersen {
    /// Generate fresh parameters with an `modulus_bits`-wide RSA modulus.
    ///
    /// # Errors
    /// [`CustodyError::BadParams`] if the modulus is too small;
    /// [`CustodyError::Random`] if sampling fails.
    pub fn generate(modulus_bits: usize) -> Result<Self, CustodyError> {
        if modulus_bits < 512 {
            return Err(CustodyError::BadParams);
        }
        let mut rng = OsRng;
        let prime_bits = modulus_bits / 2;
        let p = rng.gen_prime(prime_bits);
        let mut q = rng.gen_prime(prime_bits);
        while q == p {
            q = rng.gen_prime(prime_bits);
        }
        let n_tilde = &p * &q;
        let base = nonzero_below(&n_tilde)?;
        let h1 = base.modpow(&BigUint::from(2u8), &n_tilde);
        let lambda = nonzero_below(&n_tilde)?;
        let h2 = h1.modpow(&lambda, &n_tilde);
        Ok(Self { n_tilde, h1, h2 })
    }
}

/// A non-interactive range proof.
#[derive(Clone, Debug)]
pub struct RangeProof {
    z: BigUint,
    u: BigUint,
    w: BigUint,
    s: BigUint,
    s1: BigUint,
    s2: BigUint,
}

/// Prove that `c = paillier.encrypt_with(a, r)` encrypts a value in `[0, q³]`.
///
/// # Errors
/// [`CustodyError::Signing`] if a valid proof cannot be assembled (negligible probability);
/// [`CustodyError::Random`] if sampling fails.
pub fn prove(
    paillier: &PaillierPublic,
    pedersen: &RingPedersen,
    c: &BigUint,
    a: &BigUint,
    r: &BigUint,
    q: &BigUint,
) -> Result<RangeProof, CustodyError> {
    let n = paillier.modulus();
    let nn = paillier.modulus_squared();
    let one = BigUint::from(1u8);
    let q3 = q * q * q;
    let mut rng = OsRng;
    for _ in 0..32u8 {
        let alpha = rng.gen_biguint_below(&q3);
        let rho = rng.gen_biguint_below(&(q * &pedersen.n_tilde));
        let gamma = rng.gen_biguint_below(&(&q3 * &pedersen.n_tilde));
        let beta = coprime_below(n)?;
        let z = (pedersen.h1.modpow(a, &pedersen.n_tilde)
            * pedersen.h2.modpow(&rho, &pedersen.n_tilde))
            % &pedersen.n_tilde;
        let u = (((&one + &alpha * n) % nn) * beta.modpow(n, nn)) % nn;
        let w = (pedersen.h1.modpow(&alpha, &pedersen.n_tilde)
            * pedersen.h2.modpow(&gamma, &pedersen.n_tilde))
            % &pedersen.n_tilde;
        let e = challenge(c, &z, &u, &w, n, &pedersen.n_tilde, q);
        let s1 = &e * a + &alpha;
        if s1 > q3 {
            continue;
        }
        let s = (r.modpow(&e, n) * &beta) % n;
        let s2 = &e * &rho + &gamma;
        return Ok(RangeProof { z, u, w, s, s1, s2 });
    }
    Err(CustodyError::Signing)
}

/// Verify a range proof for ciphertext `c`.
#[must_use]
pub fn verify(
    paillier: &PaillierPublic,
    pedersen: &RingPedersen,
    c: &BigUint,
    proof: &RangeProof,
    q: &BigUint,
) -> bool {
    let n = paillier.modulus();
    let nn = paillier.modulus_squared();
    let one = BigUint::from(1u8);
    let q3 = q * q * q;
    if proof.s1 > q3 {
        return false;
    }
    let e = challenge(c, &proof.z, &proof.u, &proof.w, n, &pedersen.n_tilde, q);
    let lhs_paillier = (((&one + &proof.s1 * n) % nn) * proof.s.modpow(n, nn)) % nn;
    let rhs_paillier = (&proof.u * c.modpow(&e, nn)) % nn;
    if lhs_paillier != rhs_paillier {
        return false;
    }
    let lhs_pedersen = (pedersen.h1.modpow(&proof.s1, &pedersen.n_tilde)
        * pedersen.h2.modpow(&proof.s2, &pedersen.n_tilde))
        % &pedersen.n_tilde;
    let rhs_pedersen = (&proof.w * proof.z.modpow(&e, &pedersen.n_tilde)) % &pedersen.n_tilde;
    lhs_pedersen == rhs_pedersen
}

fn challenge(
    c: &BigUint,
    z: &BigUint,
    u: &BigUint,
    w: &BigUint,
    n: &BigUint,
    n_tilde: &BigUint,
    q: &BigUint,
) -> BigUint {
    let mut hasher = Sha256::new();
    for value in [c, z, u, w, n, n_tilde] {
        let bytes = value.to_bytes_be();
        hasher.update((u32::try_from(bytes.len()).unwrap_or(0)).to_be_bytes());
        hasher.update(&bytes);
    }
    let digest = hasher.finalize();
    BigUint::from_bytes_be(&digest) % q
}

fn nonzero_below(bound: &BigUint) -> Result<BigUint, CustodyError> {
    let mut rng = OsRng;
    let zero = BigUint::from(0u8);
    for _ in 0..16u8 {
        let candidate = rng.gen_biguint_below(bound);
        if candidate != zero {
            return Ok(candidate);
        }
    }
    Err(CustodyError::Random)
}

fn coprime_below(modulus: &BigUint) -> Result<BigUint, CustodyError> {
    let mut rng = OsRng;
    let zero = BigUint::from(0u8);
    let one = BigUint::from(1u8);
    for _ in 0..32u8 {
        let candidate = rng.gen_biguint_below(modulus);
        if candidate != zero && candidate.gcd(modulus) == one {
            return Ok(candidate);
        }
    }
    Err(CustodyError::Random)
}
