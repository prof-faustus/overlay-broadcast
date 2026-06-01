//! The request model and its canonical signing pre-image (REQ-API-001/003). [`Operation`]
//! enumerates every operation the service exposes; [`Request`] carries the caller, payload,
//! replay-protection nonce/expiry, and the caller signature.
use bsv::double_sha256;

/// Every operation the api exposes (REQ-API-001).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Operation {
    /// Write a data-storage transaction to the overlay.
    OverlayWrite,
    /// Signal a position in the key-graph (seed-isolated).
    OverlaySignalPosition,
    /// Resolve a signalled position.
    OverlayResolvePosition,
    /// Apply the obfuscation function.
    OverlayObfuscate,
    /// Reverse the obfuscation function.
    OverlayDeobfuscate,
    /// Open a broadcast session.
    BroadcastSessionOpen,
    /// Rekey, user-oriented strategy.
    BroadcastRekeyUser,
    /// Rekey, key-oriented strategy.
    BroadcastRekeyKey,
    /// Rekey, group-oriented strategy.
    BroadcastRekeyGroup,
    /// Encrypt a broadcast message.
    BroadcastMessage,
    /// Decrypt a broadcast message.
    BroadcastDecrypt,
    /// Subscribe off-chain.
    SessionSubscribeOffChain,
    /// Subscribe on-block.
    SessionSubscribeOnBlock,
    /// Renew a subscription.
    SessionRenew,
    /// Revoke a subscription.
    SessionRevoke,
    /// Generate a custody (threshold) key.
    CustodyKeygen,
    /// Rotate a custody key.
    CustodyRotate,
    /// Revoke a custody key.
    CustodyRevoke,
    /// Liveness probe (unauthenticated).
    Health,
    /// Readiness probe (unauthenticated).
    Readiness,
}

impl Operation {
    /// The stable operation name (used in audit and the signing pre-image).
    #[must_use]
    pub fn name(&self) -> &'static str {
        match self {
            Operation::OverlayWrite => "overlay.write",
            Operation::OverlaySignalPosition => "overlay.signal_position",
            Operation::OverlayResolvePosition => "overlay.resolve_position",
            Operation::OverlayObfuscate => "overlay.obfuscate",
            Operation::OverlayDeobfuscate => "overlay.deobfuscate",
            Operation::BroadcastSessionOpen => "broadcast.session_open",
            Operation::BroadcastRekeyUser => "broadcast.rekey.user",
            Operation::BroadcastRekeyKey => "broadcast.rekey.key",
            Operation::BroadcastRekeyGroup => "broadcast.rekey.group",
            Operation::BroadcastMessage => "broadcast.message",
            Operation::BroadcastDecrypt => "broadcast.decrypt",
            Operation::SessionSubscribeOffChain => "session.subscribe.off_chain",
            Operation::SessionSubscribeOnBlock => "session.subscribe.on_block",
            Operation::SessionRenew => "session.renew",
            Operation::SessionRevoke => "session.revoke",
            Operation::CustodyKeygen => "custody.keygen",
            Operation::CustodyRotate => "custody.rotate",
            Operation::CustodyRevoke => "custody.revoke",
            Operation::Health => "health",
            Operation::Readiness => "readiness",
        }
    }

    /// Whether the operation requires caller authentication. The health/readiness probes
    /// are unauthenticated; every other operation must be signed.
    #[must_use]
    pub fn requires_auth(&self) -> bool {
        !matches!(self, Operation::Health | Operation::Readiness)
    }
}

/// A boundary request.
#[derive(Clone, Debug)]
pub struct Request {
    /// The caller identifier (looked up in the caller registry).
    pub caller: String,
    /// The requested operation.
    pub operation: Operation,
    /// The opaque operation payload.
    pub payload: Vec<u8>,
    /// An optional node position (recorded in the audit log for signalling events).
    pub position: Option<String>,
    /// A per-request nonce (replay protection).
    pub nonce: u64,
    /// The request expiry as a Unix timestamp (seconds).
    pub expiry_unix: u64,
    /// The caller's DER ECDSA signature over [`Request::signing_prehash`].
    pub signature: Vec<u8>,
}

impl Request {
    /// The 32-byte double-SHA-256 pre-image the caller signs, binding operation, caller,
    /// nonce, expiry, position, and payload so none can be altered without resigning.
    #[must_use]
    pub fn signing_prehash(&self) -> [u8; 32] {
        let mut buf = Vec::new();
        buf.extend_from_slice(self.operation.name().as_bytes());
        buf.push(0x1f);
        buf.extend_from_slice(self.caller.as_bytes());
        buf.push(0x1f);
        buf.extend_from_slice(&self.nonce.to_be_bytes());
        buf.extend_from_slice(&self.expiry_unix.to_be_bytes());
        buf.push(0x1f);
        if let Some(position) = &self.position {
            buf.extend_from_slice(position.as_bytes());
        }
        buf.push(0x1f);
        buf.extend_from_slice(&self.payload);
        *double_sha256(&buf).internal()
    }
}
