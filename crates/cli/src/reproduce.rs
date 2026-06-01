//! Deterministic reproduction (REQ-CLI-003). `reproduce` regenerates every deterministic
//! vector and diffs it against the committed expected set, returning an error (non-zero
//! exit) on any mismatch. The vectors are pure functions of fixed inputs, so a correct
//! build reproduces them byte-for-byte.
use crate::error::CliError;
use bsv::{bytes_to_hex, double_sha256, hash160, merkle_root, sha256};

/// One named deterministic vector and its hex value.
pub type Vector = (String, String);

/// Regenerate every deterministic vector.
#[must_use]
pub fn generate_vectors() -> Vec<Vector> {
    let merkle = match merkle_root(&[double_sha256(b"a"), double_sha256(b"b")]) {
        Ok(root) => bytes_to_hex(root.internal()),
        Err(_) => String::new(),
    };
    vec![
        (
            "sha256d/overlay-broadcast".to_owned(),
            bytes_to_hex(double_sha256(b"overlay-broadcast").internal()),
        ),
        ("sha256/abc".to_owned(), bytes_to_hex(&sha256(b"abc"))),
        ("hash160/abc".to_owned(), bytes_to_hex(&hash160(b"abc"))),
        ("merkle/a-b".to_owned(), merkle),
    ]
}

/// Diff regenerated vectors against the committed set.
///
/// # Errors
/// [`CliError::Reproduce`] naming the first vector that differs (or is missing).
pub fn reproduce(committed: &[Vector]) -> Result<(), CliError> {
    let regenerated = generate_vectors();
    for (name, value) in &regenerated {
        match committed
            .iter()
            .find(|(committed_name, _)| committed_name == name)
        {
            Some((_, committed_value)) if committed_value == value => {}
            _ => return Err(CliError::Reproduce(name.clone())),
        }
    }
    Ok(())
}
