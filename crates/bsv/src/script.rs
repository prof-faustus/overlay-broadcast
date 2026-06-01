//! Post-Genesis script assembly and a panic-free parser (REQ-BSV-020/021/022).
//! No 520-byte push cap; large data carriers permitted.
use crate::bytes::Cursor;
use crate::error::BsvError;

/// The opcode subset this system assembles.
pub mod op {
    /// Pushes an empty array (also OP_FALSE).
    pub const FALSE: u8 = 0x00;
    /// Next 1 byte is the push length.
    pub const PUSHDATA1: u8 = 0x4c;
    /// Next 2 bytes (LE) are the push length.
    pub const PUSHDATA2: u8 = 0x4d;
    /// Next 4 bytes (LE) are the push length.
    pub const PUSHDATA4: u8 = 0x4e;
    /// Marks the output unspendable; carries data.
    pub const RETURN: u8 = 0x6a;
    /// Duplicates the top stack item.
    pub const DUP: u8 = 0x76;
    /// Verifies equality, failing the script otherwise.
    pub const EQUALVERIFY: u8 = 0x88;
    /// SHA-256 then RIPEMD-160 of the top item.
    pub const HASH160: u8 = 0xa9;
    /// Checks a signature against a public key.
    pub const CHECKSIG: u8 = 0xac;
    /// Checks an m-of-n bare multisig.
    pub const CHECKMULTISIG: u8 = 0xae;
    /// Pushes the number 1.
    pub const N1: u8 = 0x51;
    /// Pushes the number 2.
    pub const N2: u8 = 0x52;
}

/// A parsed script element: a bare opcode or a data push.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScriptOp {
    /// A non-push opcode.
    Op(u8),
    /// A pushed data run.
    Push(Vec<u8>),
}

const MAX_SCRIPT_OPS: usize = 10_000_000;

/// Append a minimally-encoded data push of `data` to `out` (post-Genesis sizes).
pub fn push_data(out: &mut Vec<u8>, data: &[u8]) {
    let len = data.len();
    if len <= 75 {
        out.push(u8::try_from(len).unwrap_or(0));
    } else if len <= 0xFF {
        out.push(op::PUSHDATA1);
        out.push(u8::try_from(len).unwrap_or(0));
    } else if len <= 0xFFFF {
        out.push(op::PUSHDATA2);
        out.extend_from_slice(&u16::try_from(len).unwrap_or(0).to_le_bytes());
    } else {
        out.push(op::PUSHDATA4);
        out.extend_from_slice(&u32::try_from(len).unwrap_or(0).to_le_bytes());
    }
    out.extend_from_slice(data);
}

/// Build a P2PKH locking script: `OP_DUP OP_HASH160 <h160> OP_EQUALVERIFY OP_CHECKSIG`.
#[must_use]
pub fn p2pkh(hash160: &[u8; 20]) -> Vec<u8> {
    let mut s = vec![op::DUP, op::HASH160];
    push_data(&mut s, hash160);
    s.push(op::EQUALVERIFY);
    s.push(op::CHECKSIG);
    s
}

/// Build a 1-of-2 bare multisig: `OP_1 <P_a> <P_b> OP_2 OP_CHECKMULTISIG` (GB Tables 1-2).
#[must_use]
pub fn bare_multisig_1_of_2(pk_a: &[u8], pk_b: &[u8]) -> Vec<u8> {
    let mut s = vec![op::N1];
    push_data(&mut s, pk_a);
    push_data(&mut s, pk_b);
    s.push(op::N2);
    s.push(op::CHECKMULTISIG);
    s
}

/// Parse a script into ops, rejecting truncated pushes without panicking.
///
/// # Errors
/// [`BsvError::Truncated`] / [`BsvError::OutOfRange`] on malformed input.
pub fn parse_script(script: &[u8]) -> Result<Vec<ScriptOp>, BsvError> {
    let mut cur = Cursor::new(script);
    let mut ops = Vec::new();
    while !cur.is_empty() {
        if ops.len() >= MAX_SCRIPT_OPS {
            return Err(BsvError::OutOfRange);
        }
        let opcode = cur.u8()?;
        match opcode {
            0x01..=0x4b => {
                let n = usize::from(opcode);
                ops.push(ScriptOp::Push(cur.take(n)?.to_vec()));
            }
            op::PUSHDATA1 => push_n(&mut cur, 1, &mut ops)?,
            op::PUSHDATA2 => push_n(&mut cur, 2, &mut ops)?,
            op::PUSHDATA4 => push_n(&mut cur, 4, &mut ops)?,
            other => ops.push(ScriptOp::Op(other)),
        }
    }
    Ok(ops)
}

fn push_n(cur: &mut Cursor<'_>, len_bytes: usize, ops: &mut Vec<ScriptOp>) -> Result<(), BsvError> {
    let mut len = 0u64;
    for (i, b) in cur.take(len_bytes)?.iter().enumerate() {
        let shift = u32::try_from(i)
            .ok()
            .and_then(|i| i.checked_mul(8))
            .ok_or(BsvError::OutOfRange)?;
        len |= u64::from(*b)
            .checked_shl(shift)
            .ok_or(BsvError::OutOfRange)?;
    }
    let n = usize::try_from(len).map_err(|_| BsvError::OutOfRange)?;
    ops.push(ScriptOp::Push(cur.take(n)?.to_vec()));
    Ok(())
}
