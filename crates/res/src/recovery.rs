//! On-chain state recovery (REQ-RES-004). The BSV ledger is the source of truth for
//! session state: a member output that is spent means the member renewed; an unspent
//! output past its expiry means revoked; otherwise active. The service holds only a
//! derived cache, which on restart is deterministically rebuilt from an on-chain snapshot
//! by [`rebuild_from_chain`] — so a kill-restart reproduces the exact pre-restart state.

/// A member's on-chain record at snapshot time.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MemberRecord {
    /// The member identifier.
    pub member_id: u64,
    /// Whether the member's session output has been spent (renewed).
    pub output_spent: bool,
    /// The member's expiry time (Unix seconds).
    pub expiry: u64,
}

/// A snapshot of the on-chain session state.
#[derive(Clone, Debug)]
pub struct LedgerSnapshot {
    /// The member records.
    pub members: Vec<MemberRecord>,
    /// The current key-graph root committed on chain.
    pub graph_root: [u8; 32],
    /// The observation time (Unix seconds).
    pub now: u64,
}

/// A member's derived status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemberStatus {
    /// Output spent: the member renewed.
    Renewed,
    /// Output unspent and not past expiry: active.
    Active,
    /// Output unspent past expiry: revoked.
    Revoked,
}

/// The derived session state (the rebuildable cache).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SessionState {
    /// Per-member status, sorted by member id for determinism.
    pub statuses: Vec<(u64, MemberStatus)>,
    /// The current key-graph root.
    pub graph_root: [u8; 32],
}

/// Rebuild the derived session state from an on-chain snapshot. Deterministic: the same
/// snapshot always yields the same state (the basis of kill-restart recovery).
#[must_use]
pub fn rebuild_from_chain(snapshot: &LedgerSnapshot) -> SessionState {
    let mut statuses: Vec<(u64, MemberStatus)> = snapshot
        .members
        .iter()
        .map(|member| (member.member_id, status_of(member, snapshot.now)))
        .collect();
    statuses.sort_by_key(|entry| entry.0);
    SessionState {
        statuses,
        graph_root: snapshot.graph_root,
    }
}

fn status_of(member: &MemberRecord, now: u64) -> MemberStatus {
    if member.output_spent {
        MemberStatus::Renewed
    } else if member.expiry < now {
        MemberStatus::Revoked
    } else {
        MemberStatus::Active
    }
}
