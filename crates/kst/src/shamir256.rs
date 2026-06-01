//! Byte-wise Shamir secret sharing over GF(2^8) (REQ-KST-020), for splitting a master
//! seed of arbitrary length (BIP32 seeds are 16–64 bytes and need not fit in the curve
//! scalar field). Each byte of the secret is the constant term of an independent
//! degree-(t-1) polynomial over GF(2^8) (AES reduction polynomial 0x11B); a share is the
//! tuple of evaluations at a distinct nonzero point. Any t shares reconstruct by Lagrange
//! interpolation at 0; t-1 reveal nothing.
use crate::error::KstError;
use core::fmt;
use secmem::{OsRandom, SecureRandom};

/// One Shamir share of a seed: an evaluation point and the per-byte evaluations.
/// The body is secret material, so [`fmt::Debug`] redacts it (REQ-KST-030).
#[derive(Clone)]
pub struct SeedShare {
    /// The evaluation point (a distinct nonzero GF(2^8) element, 1..=n).
    pub index: u8,
    body: Vec<u8>,
}

impl SeedShare {
    /// Construct a share from its index and body.
    #[must_use]
    pub fn new(index: u8, body: Vec<u8>) -> Self {
        Self { index, body }
    }

    /// The share body (secret); callers must keep it protected.
    #[must_use]
    pub fn body(&self) -> &[u8] {
        &self.body
    }
}

impl fmt::Debug for SeedShare {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SeedShare")
            .field("index", &self.index)
            .field("body", &"[redacted]")
            .finish()
    }
}

fn gf_mul(a: u8, b: u8) -> u8 {
    let mut a = a;
    let mut b = b;
    let mut product = 0u8;
    for _ in 0..8u8 {
        if b & 1 != 0 {
            product ^= a;
        }
        let high = a & 0x80;
        a <<= 1;
        if high != 0 {
            a ^= 0x1b;
        }
        b >>= 1;
    }
    product
}

fn gf_pow(a: u8, exponent: u8) -> u8 {
    let mut result = 1u8;
    let mut base = a;
    let mut e = exponent;
    while e > 0 {
        if e & 1 == 1 {
            result = gf_mul(result, base);
        }
        base = gf_mul(base, base);
        e >>= 1;
    }
    result
}

// In GF(2^8), a^254 = a^-1 for a != 0.
fn gf_inv(a: u8) -> u8 {
    gf_pow(a, 254)
}

fn gf_eval(coeffs: &[u8], x: u8) -> u8 {
    coeffs.iter().rev().fold(0u8, |acc, c| gf_mul(acc, x) ^ *c)
}

/// Split `secret` into `shares` parts, any `threshold` of which reconstruct it.
///
/// # Errors
/// [`KstError::BadParams`] if `threshold == 0`, `threshold > shares`, or `shares == 0`;
/// [`KstError::Random`] if entropy cannot be drawn.
pub fn split(secret: &[u8], threshold: u8, shares: u8) -> Result<Vec<SeedShare>, KstError> {
    if threshold == 0 || shares == 0 || threshold > shares {
        return Err(KstError::BadParams);
    }
    let mut out: Vec<SeedShare> = (1..=shares)
        .map(|index| SeedShare {
            index,
            body: Vec::with_capacity(secret.len()),
        })
        .collect();
    let degree = usize::from(threshold - 1);
    for &byte in secret {
        let mut coeffs = vec![0u8; degree + 1];
        if let Some(first) = coeffs.first_mut() {
            *first = byte;
        }
        if degree > 0 {
            let tail = coeffs.get_mut(1..).ok_or(KstError::BadParams)?;
            OsRandom.fill(tail).map_err(|_| KstError::Random)?;
        }
        for share in &mut out {
            share.body.push(gf_eval(&coeffs, share.index));
        }
    }
    Ok(out)
}

/// Reconstruct the secret from `shares` (at least the original threshold many).
///
/// # Errors
/// [`KstError::InsufficientShares`] if fewer than two shares; [`KstError::BadParams`] if
/// share bodies are ragged or two shares collide on an index.
pub fn reconstruct(shares: &[SeedShare]) -> Result<Vec<u8>, KstError> {
    let first = shares.first().ok_or(KstError::InsufficientShares)?;
    let len = first.body.len();
    if shares.iter().any(|s| s.body.len() != len) {
        return Err(KstError::BadParams);
    }
    let mut secret = vec![0u8; len];
    for (position, out) in secret.iter_mut().enumerate() {
        *out = interpolate_byte(shares, position)?;
    }
    Ok(secret)
}

fn interpolate_byte(shares: &[SeedShare], position: usize) -> Result<u8, KstError> {
    let mut acc = 0u8;
    for (j, share_j) in shares.iter().enumerate() {
        let y_j = *share_j.body.get(position).ok_or(KstError::BadParams)?;
        let mut numerator = 1u8;
        let mut denominator = 1u8;
        for (m, share_m) in shares.iter().enumerate() {
            if m == j {
                continue;
            }
            numerator = gf_mul(numerator, share_m.index);
            let diff = share_j.index ^ share_m.index;
            if diff == 0 {
                return Err(KstError::BadParams);
            }
            denominator = gf_mul(denominator, diff);
        }
        acc ^= gf_mul(y_j, gf_mul(numerator, gf_inv(denominator)));
    }
    Ok(acc)
}
