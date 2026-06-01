//! Threshold-signing availability (REQ-RES-003). The scheme tolerates up to `n - k`
//! unavailable signers; below quorum the operation fails cleanly with a typed error and no
//! partial state is treated as complete.
use crate::error::ResError;

/// Check that a signing attempt has quorum. `available` signers out of `n`, threshold `k`.
///
/// # Errors
/// [`ResError::BadParams`] if `k == 0` or `k > n`; [`ResError::BelowQuorum`] if fewer than
/// `k` signers are available.
pub fn check_quorum(available: usize, threshold: usize, n: usize) -> Result<(), ResError> {
    if threshold == 0 || threshold > n {
        return Err(ResError::BadParams);
    }
    if available < threshold {
        return Err(ResError::BelowQuorum);
    }
    Ok(())
}

/// The maximum number of signers that may be unavailable while still retaining quorum.
#[must_use]
pub fn tolerable_unavailable(threshold: usize, n: usize) -> usize {
    n.saturating_sub(threshold)
}
