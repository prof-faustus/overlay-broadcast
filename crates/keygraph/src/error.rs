//! Typed key-graph errors (REQ-GOV-012).
use thiserror::Error;

/// Errors from key-graph construction and mutation.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum KgError {
    /// The referenced node does not exist.
    #[error("no such node")]
    NoSuchNode,
    /// A configured bound (depth, breadth, or node count) would be exceeded.
    #[error("graph bound exceeded")]
    BoundExceeded,
    /// A structural invariant was violated.
    #[error("graph invariant violated")]
    Invariant,
    /// A parent-pointer cycle was detected during traversal.
    #[error("cycle detected")]
    Cycle,
    /// The root node cannot be removed.
    #[error("the root node cannot be removed")]
    CannotRemoveRoot,
}
