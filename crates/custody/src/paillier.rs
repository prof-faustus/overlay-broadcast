//! Paillier additively-homomorphic encryption (REQ-CUS-004 support), the primitive
//! underpinning the GG20 multiplicative-to-additive (MtA) share conversion. With the
//! standard `g = n + 1` choice, `Enc(m) = (1 + m·n)·r^n mod n²` and decryption recovers
//! `m = L(c^λ mod n²)·μ mod n` where `L(x) = (x-1)/n`, `λ = lcm(p-1, q-1)`,
//! `μ = λ⁻¹ mod n`. The scheme is additively homomorphic: `Enc(a)·Enc(b) = Enc(a+b)`
//! and `Enc(a)^k = Enc(k·a)`, which is exactly what MtA needs.
//!
//! This is a from-scratch implementation (the maintainer chose to hand-roll GG20).
//! It provides correctness for the protocol; it does NOT include the Paillier-ciphertext
//! ZK range proofs that GG20 requires for *malicious* security / identifiable abort —
//! see the caveats in `gg20.rs` and `docs/ARCHITECTURE.md`.
use crate::error::CustodyError;
use num_bigint_dig::{BigUint, ModInverse, RandBigInt, RandPrime};
use num_integer::Integer;
use rand::rngs::OsRng;

/// A Paillier public key (`n` and the precomputed `n²`).
#[derive(Clone, Debug)]
pub struct PaillierPublic {
    n: BigUint,
    nn: BigUint,
}

/// A Paillier keypair; only the holder can decrypt.
#[derive(Clone, Debug)]
pub struct PaillierPrivate {
    public: PaillierPublic,
    lambda: BigUint,
    mu: BigUint,
}

impl PaillierPublic {
    /// Encrypt `m` (assumed `< n`) with a fresh random nonce.
    ///
    /// # Errors
    /// [`CustodyError::Random`] if a usable nonce cannot be drawn.
    pub fn encrypt(&self, m: &BigUint) -> Result<BigUint, CustodyError> {
        let mut rng = OsRng;
        let one = BigUint::from(1u8);
        let mut r = rng.gen_biguint_below(&self.n);
        if r == BigUint::from(0u8) {
            r = one.clone();
        }
        let gm = (&one + m * &self.n) % &self.nn;
        let rn = r.modpow(&self.n, &self.nn);
        Ok((gm * rn) % &self.nn)
    }

    /// Homomorphic addition of plaintexts: `Enc(a)·Enc(b) mod n² = Enc(a+b)`.
    #[must_use]
    pub fn add(&self, c1: &BigUint, c2: &BigUint) -> BigUint {
        (c1 * c2) % &self.nn
    }

    /// Homomorphic scalar multiplication: `Enc(a)^k mod n² = Enc(k·a)`.
    #[must_use]
    pub fn mul_const(&self, c: &BigUint, k: &BigUint) -> BigUint {
        c.modpow(k, &self.nn)
    }
}

impl PaillierPrivate {
    /// Generate a keypair with the given modulus bit-size (`n` is `modulus_bits` wide;
    /// each prime is half that). Production callers should use ≥ 2048; the MtA
    /// correctness bound only needs `n > q²` (≈ 512 bits for secp256k1).
    ///
    /// # Errors
    /// [`CustodyError::BadParams`] if the modulus is too small;
    /// [`CustodyError::Random`] if key material cannot be derived.
    pub fn generate(modulus_bits: usize) -> Result<Self, CustodyError> {
        if modulus_bits < 768 {
            return Err(CustodyError::BadParams);
        }
        let mut rng = OsRng;
        let prime_bits = modulus_bits / 2;
        let p = rng.gen_prime(prime_bits);
        let mut q = rng.gen_prime(prime_bits);
        while q == p {
            q = rng.gen_prime(prime_bits);
        }
        let one = BigUint::from(1u8);
        let n = &p * &q;
        let nn = &n * &n;
        let lambda = (&p - &one).lcm(&(&q - &one));
        let mu = lambda
            .clone()
            .mod_inverse(&n)
            .and_then(|value| value.to_biguint())
            .ok_or(CustodyError::BadParams)?;
        Ok(Self {
            public: PaillierPublic { n, nn },
            lambda,
            mu,
        })
    }

    /// The public key.
    #[must_use]
    pub fn public(&self) -> &PaillierPublic {
        &self.public
    }

    /// Decrypt a ciphertext to its plaintext residue mod `n`.
    #[must_use]
    pub fn decrypt(&self, c: &BigUint) -> BigUint {
        let one = BigUint::from(1u8);
        let u = c.modpow(&self.lambda, &self.public.nn);
        let l = (&u - &one) / &self.public.n;
        (l * &self.mu) % &self.public.n
    }
}
