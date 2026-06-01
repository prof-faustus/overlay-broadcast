//! On-chain content classification guard (REQ-CMP-001). No personal data or plaintext
//! content may ever be written on-chain: overlay payloads must carry only encrypted or
//! obfuscated content. The guard refuses any cleartext payload at the write boundary, and
//! names cleartext personal data specifically. See `docs/DATA_CLASSIFICATION.md`.
use crate::error::CmpError;

/// How a candidate on-chain payload is protected.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ContentClass {
    /// AEAD-encrypted content (e.g. broadcast message, ECIES).
    Encrypted,
    /// EP second-key obfuscated content.
    Obfuscated,
    /// Unprotected cleartext — never permitted on-chain.
    Cleartext,
}

/// The data-protection sensitivity of a payload.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sensitivity {
    /// Non-personal, non-sensitive data.
    Public,
    /// Personal data subject to data-protection rules.
    PersonalData,
}

/// Guard the on-chain write path: refuse any cleartext payload, naming cleartext personal
/// data specifically.
///
/// # Errors
/// [`CmpError::CleartextPersonalData`] for cleartext personal data;
/// [`CmpError::PlaintextOnChain`] for any other cleartext payload.
pub fn guard_on_chain_write(class: ContentClass, sensitivity: Sensitivity) -> Result<(), CmpError> {
    if matches!(class, ContentClass::Cleartext) {
        return match sensitivity {
            Sensitivity::PersonalData => Err(CmpError::CleartextPersonalData),
            Sensitivity::Public => Err(CmpError::PlaintextOnChain),
        };
    }
    Ok(())
}
