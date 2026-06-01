//! Threshold Schnorr signing in which the private key is NEVER reconstructed
//! (REQ-CUS-001/003). FROST-style (Komlo-Goldberg, "FROST: Flexible Round-Optimized
//! Schnorr Threshold Signatures", 2020): each party contributes a partial signature
//! `s_j = k_j + e * lambda_j * y_j`, and the aggregate `s = sum s_j` satisfies
//! `s*G = R + e*P` because `sum lambda_j y_j = x` — yet no party holds more than its
//! own share times a public Lagrange coefficient. Nonces are committed in round one.
//!
//! Keygen here is a trusted-dealer split (the dealer transiently holds the group
//! secret, then discards it); the SIGNING operation never reconstructs the key. A
//! full distributed key generation is the upgrade path; it does not change the
//! signing property tested here.
use crate::error::CustodyError;
use crate::shamir::{random_scalar, split, Share};
use k256::elliptic_curve::ops::Reduce;
use k256::elliptic_curve::sec1::ToEncodedPoint;
use k256::{FieldBytes, ProjectivePoint, Scalar, U256};
use sha2::{Digest, Sha256};

/// A threshold group key (the public key `P = x*G`).
#[derive(Clone, Debug)]
pub struct GroupKey {
    public: ProjectivePoint,
}

impl GroupKey {
    /// The compressed group public key.
    #[must_use]
    pub fn public_compressed(&self) -> [u8; 33] {
        encode_point(&self.public)
    }
}

/// Trusted-dealer key generation: a group secret split into `n` shares with threshold
/// `t`, returning the group public key and the shares.
///
/// # Errors
/// [`CustodyError`] on bad parameters or a randomness failure.
pub fn keygen(threshold: usize, shares: usize) -> Result<(GroupKey, Vec<Share>), CustodyError> {
    let secret = random_scalar()?;
    let public = ProjectivePoint::GENERATOR * secret;
    let shares = split(secret, threshold, shares)?;
    Ok((GroupKey { public }, shares))
}

/// A round-one nonce commitment.
#[derive(Clone, Debug)]
pub struct NonceCommitment {
    /// The party's share index.
    pub index: Scalar,
    /// The hash commitment to the nonce point.
    pub commitment: [u8; 32],
}

/// A round-two nonce reveal.
#[derive(Clone, Debug)]
pub struct NonceReveal {
    /// The party's share index.
    pub index: Scalar,
    /// The revealed nonce point.
    pub point: ProjectivePoint,
}

/// A party's partial signature.
#[derive(Clone, Debug)]
pub struct PartialSig {
    /// The party's share index.
    pub index: Scalar,
    /// The partial signature scalar.
    pub s: Scalar,
}

/// An aggregated threshold Schnorr signature.
#[derive(Clone, Debug)]
pub struct ThresholdSignature {
    /// The aggregated nonce point.
    pub r: ProjectivePoint,
    /// The aggregated signature scalar.
    pub s: Scalar,
}

/// A signing party holding one share and, between rounds, its secret nonce.
#[derive(Debug)]
pub struct ThresholdParty {
    share: Share,
    nonce: Option<Scalar>,
    nonce_point: Option<ProjectivePoint>,
}

impl ThresholdParty {
    /// Create a party from its share.
    #[must_use]
    pub fn new(share: Share) -> Self {
        Self {
            share,
            nonce: None,
            nonce_point: None,
        }
    }

    /// The party's share index.
    #[must_use]
    pub fn index(&self) -> Scalar {
        self.share.x
    }

    /// Round one: pick a nonce and publish a commitment to its point.
    ///
    /// # Errors
    /// [`CustodyError::Random`] if entropy cannot be drawn.
    pub fn commit(&mut self) -> Result<NonceCommitment, CustodyError> {
        let nonce = random_scalar()?;
        let point = ProjectivePoint::GENERATOR * nonce;
        self.nonce = Some(nonce);
        self.nonce_point = Some(point);
        Ok(NonceCommitment {
            index: self.share.x,
            commitment: hash_commitment(&point),
        })
    }

    /// Round two: reveal the nonce point.
    ///
    /// # Errors
    /// [`CustodyError::Signing`] if `commit` was not called.
    pub fn reveal(&self) -> Result<NonceReveal, CustodyError> {
        let point = self.nonce_point.ok_or(CustodyError::Signing)?;
        Ok(NonceReveal {
            index: self.share.x,
            point,
        })
    }

    /// Round three: the partial signature over the aggregated nonce and group key.
    ///
    /// # Errors
    /// [`CustodyError::Signing`] if the rounds were not followed.
    pub fn partial_sign(
        &self,
        message: &[u8],
        group: &GroupKey,
        aggregated_r: ProjectivePoint,
        signing_set: &[Scalar],
    ) -> Result<PartialSig, CustodyError> {
        let nonce = self.nonce.ok_or(CustodyError::Signing)?;
        let challenge = challenge_scalar(&aggregated_r, &group.public, message);
        let lambda = lagrange_coefficient(signing_set, self.share.x);
        Ok(PartialSig {
            index: self.share.x,
            s: nonce + challenge * lambda * self.share.y,
        })
    }
}

/// Check that every revealed nonce matches its round-one commitment.
#[must_use]
pub fn verify_commitments(commitments: &[NonceCommitment], reveals: &[NonceReveal]) -> bool {
    if commitments.len() != reveals.len() {
        return false;
    }
    reveals.iter().all(|reveal| {
        commitments
            .iter()
            .find(|c| c.index == reveal.index)
            .is_some_and(|c| c.commitment == hash_commitment(&reveal.point))
    })
}

/// The aggregated nonce point `R = sum R_j`.
#[must_use]
pub fn aggregated_nonce(reveals: &[NonceReveal]) -> ProjectivePoint {
    reveals
        .iter()
        .fold(ProjectivePoint::IDENTITY, |acc, r| acc + r.point)
}

/// Aggregate reveals and partial signatures into one threshold signature.
#[must_use]
pub fn aggregate(reveals: &[NonceReveal], partials: &[PartialSig]) -> ThresholdSignature {
    let r = aggregated_nonce(reveals);
    let s = partials.iter().fold(Scalar::ZERO, |acc, p| acc + p.s);
    ThresholdSignature { r, s }
}

/// Verify a threshold Schnorr signature against the group key: `s*G == R + e*P`.
#[must_use]
pub fn verify(group: &GroupKey, message: &[u8], signature: &ThresholdSignature) -> bool {
    let challenge = challenge_scalar(&signature.r, &group.public, message);
    ProjectivePoint::GENERATOR * signature.s == signature.r + group.public * challenge
}

fn challenge_scalar(r: &ProjectivePoint, p: &ProjectivePoint, message: &[u8]) -> Scalar {
    let mut hasher = Sha256::new();
    hasher.update(encode_point(r));
    hasher.update(encode_point(p));
    hasher.update(message);
    let digest = hasher.finalize();
    <Scalar as Reduce<U256>>::reduce_bytes(&FieldBytes::clone_from_slice(&digest))
}

pub(crate) fn lagrange_coefficient(signing_set: &[Scalar], j: Scalar) -> Scalar {
    let mut numerator = Scalar::ONE;
    let mut denominator = Scalar::ONE;
    for &m in signing_set {
        if m == j {
            continue;
        }
        numerator *= m;
        denominator *= m - j;
    }
    numerator * Option::<Scalar>::from(denominator.invert()).unwrap_or(Scalar::ZERO)
}

fn hash_commitment(point: &ProjectivePoint) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(b"custody/nonce-commitment/v1");
    hasher.update(encode_point(point));
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

fn encode_point(point: &ProjectivePoint) -> [u8; 33] {
    let encoded = point.to_affine().to_encoded_point(true);
    let mut out = [0u8; 33];
    let bytes = encoded.as_bytes();
    if bytes.len() == 33 {
        out.copy_from_slice(bytes);
    }
    out
}
