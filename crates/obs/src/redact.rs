//! Secret-redaction primitive for tracing/logging (REQ-OBS-002/004). Wrapping any value
//! in [`Redacted`] makes its `Debug` and `Display` render `[redacted]`, so a secret can be
//! attached to a span/log field site without ever emitting the underlying value.
use core::fmt;

/// A wrapper whose `Debug`/`Display` never reveal the inner value.
pub struct Redacted<T>(pub T);

impl<T> fmt::Debug for Redacted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}

impl<T> fmt::Display for Redacted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("[redacted]")
    }
}
