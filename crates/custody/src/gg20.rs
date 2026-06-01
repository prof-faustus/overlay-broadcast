//! GG20 threshold ECDSA (REQ-CUS-004): Gennaro–Goldfeder, "One Round Threshold ECDSA
//! with Identifiable Abort" (2020). `k` parties of a `t`-of-`n` group each hold a Shamir
//! share `y_i`; converted to an additive share `w_i = λ_i·y_i` over the signing set, so
//! `Σ w_i = x` (the group secret) without any party ever holding `x`. Each party picks
//! `k_i, γ_i`; pairwise Paillier-based MtA turns the products `k_i·γ_j` and `k_i·w_j`
//! into additive shares, giving additive shares of `δ = k·γ` and `σ = k·x`. Revealing
//! `δ` (which hides `k`, `γ`) and `Γ_i = g^{γ_i}` yields `R = (Σ Γ_i)^{δ⁻¹} = g^{k⁻¹}`,
//! `r = R_x`, and each party's `s_i = m·k_i + r·σ_i` combine to the standard ECDSA
//! `s`. The private key is NEVER reconstructed.
//!
//! Rounds: this reference runs the protocol in-process (as the FROST tests do); the
//! pairwise MtA and the broadcast of `δ_i`, `Γ_i` map onto the network rounds of GG20.
//!
//! **Security status (REQ-CUS-002 known-attack disclosure):** every MtA in [`sign`] now
//! verifies all three GG18/20 ZK proofs — the initiator range proof and the responder
//! consistency proof Π′ ([`crate::rangeproof`]), and each party's Paillier-modulus
//! well-formedness proof ([`crate::modulusproof`], checked once up front). A malicious
//! initiator, a malicious responder, and a malformed Paillier modulus are all rejected.
//! The only residual item is *identifiable abort* (attributing a fault to a specific party
//! on failure), which needs the echo-broadcast consistency round; until then a bad party
//! causes a clean typed error, not an attributable one. Production Paillier modulus must be
//! ≥ 2048 bits; the correctness bound alone needs `n > q²`. See `docs/ARCHITECTURE.md`.
use crate::error::CustodyError;
use crate::modulusproof::{self, ModulusProof};
use crate::paillier::PaillierPrivate;
use crate::rangeproof::{self, RingPedersen};
use crate::shamir::{random_scalar, Share};
use crate::threshold::{keygen, lagrange_coefficient, GroupKey};
use k256::ecdsa::Signature;
use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::elliptic_curve::PrimeField;
use k256::{FieldBytes, ProjectivePoint, Scalar, U256};
use num_bigint_dig::BigUint;

/// secp256k1 group order `q`, big-endian.
const ORDER_BE: [u8; 32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFE,
    0xBA, 0xAE, 0xDC, 0xE6, 0xAF, 0x48, 0xA0, 0x3B, 0xBF, 0xD2, 0x5E, 0x8C, 0xD0, 0x36, 0x41, 0x41,
];

/// A GG20 signing party: a Shamir share, its own Paillier keypair, and the ring-Pedersen
/// parameters it uses to verify other parties' MtA range proofs (REQ-CUS-004).
#[derive(Clone, Debug)]
pub struct Gg20Party {
    share: Share,
    paillier: PaillierPrivate,
    ring_pedersen: RingPedersen,
    modulus_proof: ModulusProof,
}

impl Gg20Party {
    /// Create a party, generating its Paillier keypair, ring-Pedersen parameters, and a
    /// proof that its Paillier modulus is well-formed, all at `modulus_bits`.
    ///
    /// # Errors
    /// [`CustodyError`] if key generation or the modulus proof fails.
    pub fn new(share: Share, modulus_bits: usize) -> Result<Self, CustodyError> {
        let paillier = PaillierPrivate::generate(modulus_bits)?;
        let modulus_proof = paillier.prove_modulus()?;
        Ok(Self {
            share,
            paillier,
            ring_pedersen: RingPedersen::generate(modulus_bits)?,
            modulus_proof,
        })
    }

    /// The party's share index.
    #[must_use]
    pub fn index(&self) -> Scalar {
        self.share.x
    }
}

/// Trusted-dealer setup: split a group secret into `n` shares (threshold `t`) and wrap
/// each in a [`Gg20Party`] with a Paillier keypair. Returns the group public key too.
///
/// # Errors
/// [`CustodyError`] on bad parameters or key-generation failure.
pub fn dealer_keygen(
    threshold: usize,
    shares: usize,
    modulus_bits: usize,
) -> Result<(GroupKey, Vec<Gg20Party>), CustodyError> {
    let (group, share_vec) = keygen(threshold, shares)?;
    let mut parties = Vec::with_capacity(share_vec.len());
    for share in share_vec {
        parties.push(Gg20Party::new(share, modulus_bits)?);
    }
    Ok((group, parties))
}

/// Produce a threshold ECDSA signature (DER, low-S) over a 32-byte prehash with the
/// given quorum of parties. The signature verifies as a standard BSV ECDSA signature
/// under the group public key; the private key is never reconstructed.
///
/// # Errors
/// [`CustodyError::InsufficientShares`] for `< 2` parties; [`CustodyError::Signing`] if
/// the protocol degenerates (zero `r`/`s`, non-invertible `δ`).
pub fn sign(parties: &[Gg20Party], message_hash: &[u8; 32]) -> Result<Vec<u8>, CustodyError> {
    let count = parties.len();
    if count < 2 {
        return Err(CustodyError::InsufficientShares);
    }
    // Reject any party whose Paillier modulus is not provably well-formed before it is used.
    for party in parties {
        if !modulusproof::verify(party.paillier.public().modulus(), &party.modulus_proof) {
            return Err(CustodyError::BadShare);
        }
    }
    let q = curve_order();
    let indices: Vec<Scalar> = parties.iter().map(Gg20Party::index).collect();
    let w: Vec<Scalar> = parties
        .iter()
        .map(|p| lagrange_coefficient(&indices, p.share.x) * p.share.y)
        .collect();
    let mut k = Vec::with_capacity(count);
    let mut gamma = Vec::with_capacity(count);
    for _ in 0..count {
        k.push(random_scalar()?);
        gamma.push(random_scalar()?);
    }
    let (delta, sigma) = mta_accumulate(parties, &k, &gamma, &w, &q)?;
    let delta_sum = delta.iter().fold(Scalar::ZERO, |acc, d| acc + *d);
    let delta_inv = Option::<Scalar>::from(delta_sum.invert()).ok_or(CustodyError::Signing)?;
    let gamma_point = gamma.iter().fold(ProjectivePoint::IDENTITY, |acc, g| {
        acc + ProjectivePoint::GENERATOR * *g
    });
    let r = point_x_as_scalar(&(gamma_point * delta_inv))?;
    if r == Scalar::ZERO {
        return Err(CustodyError::Signing);
    }
    let m = scalar_from_hash(message_hash);
    let s = k
        .iter()
        .zip(sigma.iter())
        .fold(Scalar::ZERO, |acc, (ki, si)| acc + m * *ki + r * *si);
    if s == Scalar::ZERO {
        return Err(CustodyError::Signing);
    }
    assemble_der(r, s)
}

// Initialise δ_i = k_i·γ_i and σ_i = k_i·w_i, then fold in every ordered pair's MtA so
// that Σ δ_i = k·γ and Σ σ_i = k·x. Index access is bounds-checked (typed error, never
// a panic) though every index is in range by construction.
fn mta_accumulate(
    parties: &[Gg20Party],
    k: &[Scalar],
    gamma: &[Scalar],
    w: &[Scalar],
    q: &BigUint,
) -> Result<(Vec<Scalar>, Vec<Scalar>), CustodyError> {
    let count = parties.len();
    let mut delta: Vec<Scalar> = k
        .iter()
        .zip(gamma.iter())
        .map(|(ki, gi)| *ki * *gi)
        .collect();
    let mut sigma: Vec<Scalar> = k.iter().zip(w.iter()).map(|(ki, wi)| *ki * *wi).collect();
    for i in 0..count {
        for j in 0..count {
            if i == j {
                continue;
            }
            let ki = *k.get(i).ok_or(CustodyError::Signing)?;
            let gj = *gamma.get(j).ok_or(CustodyError::Signing)?;
            let wj = *w.get(j).ok_or(CustodyError::Signing)?;
            let initiator = parties.get(i).ok_or(CustodyError::Signing)?;
            let responder_pedersen = &parties.get(j).ok_or(CustodyError::Signing)?.ring_pedersen;
            let (alpha, beta) = mta(
                &initiator.paillier,
                &initiator.ring_pedersen,
                responder_pedersen,
                &ki,
                &gj,
                q,
            )?;
            let (mu, nu) = mta(
                &initiator.paillier,
                &initiator.ring_pedersen,
                responder_pedersen,
                &ki,
                &wj,
                q,
            )?;
            *delta.get_mut(i).ok_or(CustodyError::Signing)? += alpha;
            *delta.get_mut(j).ok_or(CustodyError::Signing)? += beta;
            *sigma.get_mut(i).ok_or(CustodyError::Signing)? += mu;
            *sigma.get_mut(j).ok_or(CustodyError::Signing)? += nu;
        }
    }
    Ok((delta, sigma))
}

// MtA: the `a`-holder (owning `holder`'s Paillier key) and a counterparty holding `b`
// convert the product `a·b` into additive shares `(alpha, beta)` with `alpha + beta =
// a·b mod q`, revealing neither input. `alpha` goes to the `a`-holder, `beta` to the
// counterparty. Correctness needs `a·b + beta' < n`, guaranteed by `n > q²`.
fn mta(
    holder: &PaillierPrivate,
    initiator_pedersen: &RingPedersen,
    responder_pedersen: &RingPedersen,
    a: &Scalar,
    b: &Scalar,
    q: &BigUint,
) -> Result<(Scalar, Scalar), CustodyError> {
    let public = holder.public();
    // Initiator (Alice) sends c_a = Enc(a) and proves a is in range; the responder verifies
    // it under the responder's ring-Pedersen params (REQ-CUS-004).
    let a_big = scalar_to_biguint(a);
    let nonce = public.random_nonce()?;
    let c_a = public.encrypt_with(&a_big, &nonce);
    let range_proof = rangeproof::prove(public, responder_pedersen, &c_a, &a_big, &nonce, q)?;
    if !rangeproof::verify(public, responder_pedersen, &c_a, &range_proof, q) {
        return Err(CustodyError::BadCommitment);
    }
    // Responder (Bob) forms c_b = c_a^b · Enc(beta') with explicit randomness and proves the
    // response is well-formed with b in range; the initiator verifies it under the
    // initiator's ring-Pedersen params.
    let beta_prime = random_scalar()?;
    let beta_big = scalar_to_biguint(&beta_prime);
    let b_big = scalar_to_biguint(b);
    let response_nonce = public.random_nonce()?;
    let c_mul = public.mul_const(&c_a, &b_big);
    let c_beta = public.encrypt_with(&beta_big, &response_nonce);
    let c_b = public.add(&c_mul, &c_beta);
    let responder_proof = rangeproof::prove_responder(
        public,
        initiator_pedersen,
        &c_a,
        &c_b,
        &b_big,
        &beta_big,
        &response_nonce,
        q,
    )?;
    if !rangeproof::verify_responder(public, initiator_pedersen, &c_a, &c_b, &responder_proof, q) {
        return Err(CustodyError::BadCommitment);
    }
    let alpha = scalar_from_biguint_mod_q(&holder.decrypt(&c_b), q)?;
    Ok((alpha, -beta_prime))
}

fn assemble_der(r: Scalar, s: Scalar) -> Result<Vec<u8>, CustodyError> {
    let signature =
        Signature::from_scalars(r.to_repr(), s.to_repr()).map_err(|_| CustodyError::Signing)?;
    let low_s = signature.normalize_s().unwrap_or(signature);
    Ok(low_s.to_der().as_bytes().to_vec())
}

pub(crate) fn curve_order() -> BigUint {
    BigUint::from_bytes_be(&ORDER_BE)
}

fn scalar_to_biguint(s: &Scalar) -> BigUint {
    BigUint::from_bytes_be(s.to_repr().as_slice())
}

fn scalar_from_biguint_mod_q(value: &BigUint, q: &BigUint) -> Result<Scalar, CustodyError> {
    let reduced = value % q;
    let bytes = reduced.to_bytes_be();
    let len = bytes.len();
    if len > 32 {
        return Err(CustodyError::BadShare);
    }
    let mut out = [0u8; 32];
    let slot = out.get_mut(32 - len..).ok_or(CustodyError::BadShare)?;
    slot.copy_from_slice(&bytes);
    Option::<Scalar>::from(Scalar::from_repr(FieldBytes::clone_from_slice(&out)))
        .ok_or(CustodyError::BadShare)
}

fn scalar_from_hash(hash: &[u8; 32]) -> Scalar {
    <Scalar as Reduce<U256>>::reduce_bytes(&FieldBytes::clone_from_slice(hash))
}

fn point_x_as_scalar(point: &ProjectivePoint) -> Result<Scalar, CustodyError> {
    let encoded = point.to_affine().to_encoded_point(true);
    let x = encoded.x().ok_or(CustodyError::Signing)?;
    Ok(<Scalar as Reduce<U256>>::reduce_bytes(x))
}
