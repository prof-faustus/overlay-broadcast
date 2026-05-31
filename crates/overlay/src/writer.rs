//! Writing a node to the blockchain (REQ-OVL-010/011), the funding function (claim
//! 5b, REQ-OVL-021b), and the application-layer function (claim 5c, REQ-OVL-021c).
//! A node's data-storage transaction carries its payload in an OP_FALSE OP_RETURN
//! output and is authorised by SIGNING ITS INPUT with the position's first (writing)
//! key — low-S + RFC-6979 via the verified pin. Writing is idempotent on the node's
//! position.
use crate::error::OverlayError;
use crate::keys::{obfuscate, OverlayKeys};
use bsv::{
    build_data_carrier, hash160, p2pkh, parse_script, push_data, sighash, NodeClient, OutPoint,
    ScriptOp, Transaction, TxIn, TxOut, SIGHASH_ALL, SIGHASH_FORKID,
};
use cipher::Ciphertext;
use ckd::{Position, XPriv};
use std::collections::HashMap;

const SEQUENCE_FINAL: u32 = 0xffff_ffff;
const SIGHASH_FLAG: u8 = SIGHASH_ALL | SIGHASH_FORKID;

/// Options for writing a node.
#[derive(Clone, Copy, Debug)]
pub struct WritingOptions {
    /// Obfuscate the payload under the node's second-function key before writing.
    pub obfuscate: bool,
    /// The value (minor units) placed on the node's spendable output (which a child
    /// node links to).
    pub funding_value: u64,
}

/// A node written (or to-be-written) to the blockchain.
#[derive(Clone, Debug)]
pub struct WrittenNode {
    /// The node's position coordinates.
    pub position: Vec<u32>,
    /// The transaction id in display order.
    pub txid_display: String,
    /// The full data-storage transaction.
    pub transaction: Transaction,
    /// The obfuscation ciphertext, if the payload was obfuscated.
    pub obfuscation: Option<Ciphertext>,
    /// The writing public key whose input signature authorised the write.
    pub writing_public_key: [u8; 33],
}

/// Writes overlay nodes via a [`NodeClient`], idempotent on position.
#[derive(Debug)]
pub struct OverlayWriter<N: NodeClient> {
    keys: OverlayKeys,
    node: N,
    written: HashMap<Vec<u32>, WrittenNode>,
}

impl<N: NodeClient> OverlayWriter<N> {
    /// Create a writer over a key set and a node client.
    pub fn new(keys: OverlayKeys, node: N) -> Self {
        Self {
            keys,
            node,
            written: HashMap::new(),
        }
    }

    /// The key sets.
    pub fn keys(&self) -> &OverlayKeys {
        &self.keys
    }

    /// A previously-written node at `coords`, if any.
    pub fn written(&self, coords: &[u32]) -> Option<&WrittenNode> {
        self.written.get(coords)
    }

    /// Write a node: build its data-storage transaction, obfuscate the payload if
    /// selected, sign the input with the position's writing key, and submit it.
    /// Idempotent: re-writing an existing node returns the existing transaction.
    ///
    /// # Errors
    /// [`OverlayError`] on derivation, cipher, construction, or submission failure.
    pub fn write_node(
        &mut self,
        position: &Position,
        payload: &[u8],
        options: &WritingOptions,
        funding: OutPoint,
    ) -> Result<WrittenNode, OverlayError> {
        let coords = position.coords().to_vec();
        if let Some(existing) = self.written.get(&coords) {
            return Ok(existing.clone());
        }
        let writing = self.keys.writing_key(position)?;
        let writing_priv: [u8; 32] = writing
            .private_key_bytes()
            .try_into()
            .map_err(|_| OverlayError::Ckd(ckd::CkdError::BadKey))?;
        let writing_pub = writing.public_key_compressed()?;
        let prev_script = p2pkh(&hash160(&writing_pub));

        let (carrier_payload, obfuscation) = self.prepare_payload(position, payload, options)?;
        let mut transaction = build_skeleton(
            &carrier_payload,
            &prev_script,
            options.funding_value,
            funding,
        );
        sign_input(
            &mut transaction,
            &prev_script,
            options.funding_value,
            &writing_priv,
            &writing_pub,
        )?;

        let raw = transaction.serialize()?;
        let txid = self.node.submit_tx(&raw)?;
        let written = WrittenNode {
            position: coords.clone(),
            txid_display: txid.to_display_hex(),
            transaction,
            obfuscation,
            writing_public_key: writing_pub,
        };
        let _ = self.written.insert(coords, written.clone());
        Ok(written)
    }

    fn prepare_payload(
        &self,
        position: &Position,
        payload: &[u8],
        options: &WritingOptions,
    ) -> Result<(Vec<u8>, Option<Ciphertext>), OverlayError> {
        if options.obfuscate {
            let second = self.keys.second_key(position)?;
            let ciphertext = obfuscate(&second, payload)?;
            let mut blob = ciphertext.nonce.to_vec();
            blob.extend_from_slice(&ciphertext.bytes);
            Ok((blob, Some(ciphertext)))
        } else {
            Ok((payload.to_vec(), None))
        }
    }
}

fn build_skeleton(
    carrier_payload: &[u8],
    prev_script: &[u8],
    funding_value: u64,
    funding: OutPoint,
) -> Transaction {
    let data_output = build_data_carrier(carrier_payload);
    let funded_output = TxOut {
        value: funding_value,
        locking_script: prev_script.to_vec(),
    };
    let input = TxIn {
        outpoint: funding,
        unlocking_script: Vec::new(),
        sequence: SEQUENCE_FINAL,
    };
    Transaction {
        version: 1,
        inputs: vec![input],
        outputs: vec![data_output, funded_output],
        locktime: 0,
    }
}

fn sign_input(
    transaction: &mut Transaction,
    prev_script: &[u8],
    value: u64,
    writing_priv: &[u8; 32],
    writing_pub: &[u8; 33],
) -> Result<(), OverlayError> {
    let digest = sighash(transaction, 0, prev_script, value, SIGHASH_FLAG)?;
    let mut signature = ckd::sign_prehash_der(writing_priv, digest.internal())?;
    signature.push(SIGHASH_FLAG);
    let mut unlock = Vec::new();
    push_data(&mut unlock, &signature);
    push_data(&mut unlock, writing_pub);
    if let Some(input) = transaction.inputs.first_mut() {
        input.unlocking_script = unlock;
    }
    Ok(())
}

/// Verify that a written node's input was authorised by its writing key (the check a
/// node performs: the right first key signed the input; a wrong key is rejected).
///
/// # Errors
/// [`OverlayError`] on a sighash or script-parse failure.
pub fn verify_authorisation(
    written: &WrittenNode,
    funding_value: u64,
) -> Result<bool, OverlayError> {
    let prev_script = p2pkh(&hash160(&written.writing_public_key));
    let digest = sighash(
        &written.transaction,
        0,
        &prev_script,
        funding_value,
        SIGHASH_FLAG,
    )?;
    let input = written
        .transaction
        .inputs
        .first()
        .ok_or(OverlayError::UnknownPosition)?;
    match parse_script(&input.unlocking_script)?.as_slice() {
        [ScriptOp::Push(sig_with_flag), ScriptOp::Push(public_key)] => {
            let der_len = sig_with_flag
                .len()
                .checked_sub(1)
                .ok_or(OverlayError::UnknownPosition)?;
            let signature_der = sig_with_flag
                .get(..der_len)
                .ok_or(OverlayError::UnknownPosition)?;
            Ok(ckd::verify_der_prehash(
                public_key,
                digest.internal(),
                signature_der,
            ))
        }
        _ => Ok(false),
    }
}

/// The FUNDING function (claim 5b, REQ-OVL-021b): a P2PKH output to the node's
/// funding key (derived from the funding key set) that funds the data-storage
/// transaction. The output is spendable exactly by the funding key.
///
/// # Errors
/// [`OverlayError::Ckd`] if the funding key is invalid.
pub fn funding_output(funding_key: &XPriv, value: u64) -> Result<TxOut, OverlayError> {
    let pkh = hash160(&funding_key.public_key_compressed()?);
    Ok(TxOut {
        value,
        locking_script: p2pkh(&pkh),
    })
}

/// The APPLICATION-LAYER function (claim 5c, REQ-OVL-021c): a pluggable function
/// bound to a node's transaction and its application key.
pub trait ApplicationFunction {
    /// Apply the function to a written node using its application-layer key.
    ///
    /// # Errors
    /// An implementation-defined [`OverlayError`].
    fn apply(&self, node: &WrittenNode, application_key: &XPriv) -> Result<Vec<u8>, OverlayError>;
}
