//! Typed CLI errors (REQ-CLI-001): no subcommand causes an unhandled panic.
use thiserror::Error;

/// Errors surfaced by the CLI.
#[derive(Debug, Error)]
pub enum CliError {
    /// A bad argument value (e.g. malformed hex, out-of-range count).
    #[error("invalid argument: {0}")]
    BadInput(&'static str),
    /// A layer operation failed during execution.
    #[error("operation failed: {0}")]
    Operation(&'static str),
    /// `selftest` found one or more failing layers.
    #[error("selftest failed: {0} layer(s) did not pass")]
    Selftest(usize),
    /// `reproduce` found a vector that does not match the committed value.
    #[error("reproduce mismatch in vector: {0}")]
    Reproduce(String),
}
