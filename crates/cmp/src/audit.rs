//! Tamper-evident, hash-chained audit log (REQ-CMP-003). Each entry commits to the prior
//! entry's hash via `double_sha256`, so the head hash is a single value that can be
//! anchored to BSV via the overlay (terminating the audit history in the header chain).
//! Tampering with any field of any entry breaks the chain and is detected by
//! [`verify_audit_chain`].
use bsv::{double_sha256, Hash256};

/// One tamper-evident audit entry.
#[derive(Clone, Debug)]
pub struct AuditRecord {
    /// The event time (Unix seconds).
    pub timestamp: u64,
    /// The actor (caller identifier; never a secret).
    pub actor: String,
    /// The action performed (operation name; never a secret).
    pub action: String,
    /// The previous entry's hash (all-zero for the first entry).
    pub prev_hash: Hash256,
    /// This entry's hash.
    pub hash: Hash256,
}

/// An append-only, hash-chained audit log.
#[derive(Clone, Debug, Default)]
pub struct TamperEvidentAudit {
    records: Vec<AuditRecord>,
}

fn record_hash(timestamp: u64, actor: &str, action: &str, prev: &Hash256) -> Hash256 {
    let mut buf = Vec::new();
    buf.extend_from_slice(&timestamp.to_be_bytes());
    buf.push(0x1f);
    buf.extend_from_slice(actor.as_bytes());
    buf.push(0x1f);
    buf.extend_from_slice(action.as_bytes());
    buf.push(0x1f);
    buf.extend_from_slice(prev.internal());
    double_sha256(&buf)
}

impl TamperEvidentAudit {
    /// An empty log.
    #[must_use]
    pub fn new() -> Self {
        Self {
            records: Vec::new(),
        }
    }

    /// Append an entry, chaining it to the current head.
    pub fn append(&mut self, timestamp: u64, actor: &str, action: &str) {
        let prev_hash = self.head_hash();
        let hash = record_hash(timestamp, actor, action, &prev_hash);
        self.records.push(AuditRecord {
            timestamp,
            actor: actor.to_owned(),
            action: action.to_owned(),
            prev_hash,
            hash,
        });
    }

    /// The head hash — the single value to anchor on chain.
    #[must_use]
    pub fn head_hash(&self) -> Hash256 {
        match self.records.last() {
            Some(record) => record.hash,
            None => Hash256::from_internal([0u8; 32]),
        }
    }

    /// The recorded entries.
    #[must_use]
    pub fn records(&self) -> &[AuditRecord] {
        &self.records
    }
}

/// Verify a hash-chained audit log: each entry re-hashes to its stored hash and links to
/// its predecessor. Returns `false` if any entry was tampered with.
#[must_use]
pub fn verify_audit_chain(records: &[AuditRecord]) -> bool {
    let mut prev = Hash256::from_internal([0u8; 32]);
    for record in records {
        if record.prev_hash != prev {
            return false;
        }
        let expected = record_hash(
            record.timestamp,
            &record.actor,
            &record.action,
            &record.prev_hash,
        );
        if expected != record.hash {
            return false;
        }
        prev = record.hash;
    }
    true
}
