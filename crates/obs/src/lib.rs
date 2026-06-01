//! Observability (Section 13).
//!
//! - [`Metrics`] — Prometheus instruments and text rendering (REQ-OBS-001).
//! - [`health`] — liveness + fail-closed readiness logic (REQ-OBS-003).
//! - [`Redacted`] — wrap secrets so span/log fields never reveal them (REQ-OBS-002/004).
//! - [`logging::init_json`] — global JSON structured logging (REQ-OBS-004).
//!
//! The HTTP serving of the metrics/health endpoints lives in the api crate; this crate is
//! the sync, unit-testable logic behind them.
#![forbid(unsafe_code)]

pub mod error;
pub mod health;
pub mod logging;
pub mod metrics;
pub mod redact;

pub use error::ObsError;
pub use health::{liveness, readiness, DependencyProbe, ReadinessReport};
pub use metrics::Metrics;
pub use redact::Redacted;

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;
    use std::io;
    use std::sync::{Arc, Mutex};
    use tracing_subscriber::fmt::MakeWriter;

    #[derive(Clone)]
    struct SharedBuf(Arc<Mutex<Vec<u8>>>);

    impl io::Write for SharedBuf {
        fn write(&mut self, data: &[u8]) -> io::Result<usize> {
            let mut guard = self.0.lock().map_err(|_| io::Error::other("poisoned"))?;
            guard.extend_from_slice(data);
            Ok(data.len())
        }
        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    impl<'a> MakeWriter<'a> for SharedBuf {
        type Writer = SharedBuf;
        fn make_writer(&'a self) -> Self::Writer {
            self.clone()
        }
    }

    struct StubProbe {
        name: String,
        up: bool,
    }

    impl DependencyProbe for StubProbe {
        fn name(&self) -> &str {
            &self.name
        }
        fn is_up(&self) -> bool {
            self.up
        }
    }

    fn probe(name: &str, up: bool) -> Box<dyn DependencyProbe> {
        Box::new(StubProbe {
            name: name.to_owned(),
            up,
        })
    }

    // TST-OBS-001: all documented metric series are present after recording, and no secret
    // appears in the rendered exposition.
    #[test]
    fn tst_obs_001_metrics_present_no_secret() {
        let metrics = Metrics::new().unwrap();
        metrics.record_operation("overlay.write", "ok", 0.012);
        metrics.record_node_submission("accepted");
        metrics.record_threshold_round("round_one", 0.05);
        metrics.set_active_sessions(3);
        metrics.inc_key_derivations();
        let text = metrics.render().unwrap();
        for series in [
            "ob_operations_total",
            "ob_operation_latency_seconds",
            "ob_node_submissions_total",
            "ob_threshold_round_seconds",
            "ob_active_sessions",
            "ob_key_derivations_total",
        ] {
            assert!(text.contains(series), "series {series} present");
        }
        assert!(!text.contains("supersecret"), "no secret in metrics output");
    }

    // TST-OBS-003: liveness is independent; readiness fails closed when any dependency is
    // down and when no probes are configured.
    #[test]
    fn tst_obs_003_readiness_fails_closed() {
        assert!(liveness(), "liveness is independent of downstreams");

        let all_up = vec![probe("bsv", true), probe("kst", true)];
        assert!(readiness(&all_up).ready, "ready when all dependencies up");

        let one_down = vec![probe("bsv", true), probe("quorum", false)];
        let report = readiness(&one_down);
        assert!(!report.ready, "not ready when a dependency is down");
        assert_eq!(report.down, vec!["quorum".to_owned()]);

        let none: Vec<Box<dyn DependencyProbe>> = vec![];
        assert!(
            !readiness(&none).ready,
            "fails closed with no probes configured"
        );
    }

    // TST-OBS-002: a span carrying a redacted field emits the span/event but never the
    // secret value.
    #[test]
    fn tst_obs_002_span_redacts_secrets() {
        let buffer = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_writer(SharedBuf(Arc::clone(&buffer)))
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            let span =
                tracing::info_span!("overlay.write", session = %Redacted("topsecretsession"));
            let _entered = span.enter();
            tracing::info!("submitting node transaction");
        });
        let output = String::from_utf8(buffer.lock().unwrap().clone()).unwrap();
        assert!(output.contains("overlay.write"), "span name emitted");
        assert!(
            output.contains("submitting node transaction"),
            "event emitted"
        );
        assert!(
            !output.contains("topsecretsession"),
            "secret span field not leaked"
        );
    }

    // TST-OBS-004: structured JSON logs redact secrets routed through Redacted.
    #[test]
    fn tst_obs_004_logs_redact_secrets() {
        let buffer = Arc::new(Mutex::new(Vec::new()));
        let subscriber = tracing_subscriber::fmt()
            .json()
            .with_writer(SharedBuf(Arc::clone(&buffer)))
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            let seed = "supersecretseedvalue";
            tracing::info!(secret = %Redacted(seed), "key derived");
        });
        let output = String::from_utf8(buffer.lock().unwrap().clone()).unwrap();
        assert!(output.contains("key derived"), "event emitted");
        assert!(
            !output.contains("supersecretseedvalue"),
            "secret not leaked into logs"
        );
        assert!(output.contains("redacted"), "field rendered as redacted");
    }
}
