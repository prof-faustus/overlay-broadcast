//! Append-only audit log (REQ-API-004). Records every signed operation and every
//! key/position-signalling event with timestamp, caller, operation, node position, and
//! outcome. By construction an [`AuditEntry`] has no field that can hold a seed, key,
//! key-share, or plaintext — only operation metadata.
/// One audit record. Contains only non-secret metadata.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct AuditEntry {
    /// The event time (Unix seconds).
    pub timestamp: u64,
    /// The caller identifier.
    pub caller: String,
    /// The operation name.
    pub operation: &'static str,
    /// The node position for signalling events, if any.
    pub node_position: Option<String>,
    /// The outcome (`"ok"` or `"error"`).
    pub outcome: &'static str,
}

/// An append-only audit log.
#[derive(Clone, Debug, Default)]
pub struct AuditLog {
    entries: Vec<AuditEntry>,
}

impl AuditLog {
    /// An empty log.
    #[must_use]
    pub fn new() -> Self {
        Self {
            entries: Vec::new(),
        }
    }

    /// Append an audit record.
    pub fn record(
        &mut self,
        timestamp: u64,
        caller: &str,
        operation: &'static str,
        node_position: Option<String>,
        outcome: &'static str,
    ) {
        self.entries.push(AuditEntry {
            timestamp,
            caller: caller.to_owned(),
            operation,
            node_position,
            outcome,
        });
    }

    /// The recorded entries, oldest first.
    #[must_use]
    pub fn entries(&self) -> &[AuditEntry] {
        &self.entries
    }
}
