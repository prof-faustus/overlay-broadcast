//! Prometheus metrics (REQ-OBS-001). Exposes operation counts, latency histograms, error
//! rates, node-submission outcomes, threshold-signing round timings, active sessions, and
//! key-derivation throughput. Label values are operation/outcome identifiers chosen by the
//! caller from a fixed vocabulary — never secret/seed/key material — so no secret can
//! appear as a label or value.
use crate::error::ObsError;
use prometheus::{
    Encoder, HistogramOpts, HistogramVec, IntCounter, IntCounterVec, IntGauge, Opts, Registry,
    TextEncoder,
};

/// The metric registry and its instruments.
#[derive(Clone)]
pub struct Metrics {
    registry: Registry,
    operations: IntCounterVec,
    op_latency: HistogramVec,
    node_submissions: IntCounterVec,
    threshold_round: HistogramVec,
    active_sessions: IntGauge,
    key_derivations: IntCounter,
}

impl Metrics {
    /// Construct and register all instruments.
    ///
    /// # Errors
    /// [`ObsError::Registration`] if any series fails to register.
    pub fn new() -> Result<Self, ObsError> {
        let registry = Registry::new();
        let operations = IntCounterVec::new(
            Opts::new("ob_operations_total", "operation outcomes"),
            &["operation", "outcome"],
        )
        .map_err(|_| ObsError::Registration)?;
        let op_latency = HistogramVec::new(
            HistogramOpts::new("ob_operation_latency_seconds", "operation latency"),
            &["operation"],
        )
        .map_err(|_| ObsError::Registration)?;
        let node_submissions = IntCounterVec::new(
            Opts::new("ob_node_submissions_total", "BSV node submission outcomes"),
            &["outcome"],
        )
        .map_err(|_| ObsError::Registration)?;
        let threshold_round = HistogramVec::new(
            HistogramOpts::new(
                "ob_threshold_round_seconds",
                "threshold-signing round timings",
            ),
            &["round"],
        )
        .map_err(|_| ObsError::Registration)?;
        let active_sessions =
            IntGauge::new("ob_active_sessions", "currently active broadcast sessions")
                .map_err(|_| ObsError::Registration)?;
        let key_derivations =
            IntCounter::new("ob_key_derivations_total", "key derivations performed")
                .map_err(|_| ObsError::Registration)?;
        let metrics = Self {
            registry,
            operations,
            op_latency,
            node_submissions,
            threshold_round,
            active_sessions,
            key_derivations,
        };
        metrics.register_all()?;
        Ok(metrics)
    }

    fn register_all(&self) -> Result<(), ObsError> {
        self.registry
            .register(Box::new(self.operations.clone()))
            .map_err(|_| ObsError::Registration)?;
        self.registry
            .register(Box::new(self.op_latency.clone()))
            .map_err(|_| ObsError::Registration)?;
        self.registry
            .register(Box::new(self.node_submissions.clone()))
            .map_err(|_| ObsError::Registration)?;
        self.registry
            .register(Box::new(self.threshold_round.clone()))
            .map_err(|_| ObsError::Registration)?;
        self.registry
            .register(Box::new(self.active_sessions.clone()))
            .map_err(|_| ObsError::Registration)?;
        self.registry
            .register(Box::new(self.key_derivations.clone()))
            .map_err(|_| ObsError::Registration)?;
        Ok(())
    }

    /// Record an operation outcome and its latency.
    pub fn record_operation(&self, operation: &str, outcome: &str, latency_seconds: f64) {
        self.operations
            .with_label_values(&[operation, outcome])
            .inc();
        self.op_latency
            .with_label_values(&[operation])
            .observe(latency_seconds);
    }

    /// Record a BSV node submission outcome.
    pub fn record_node_submission(&self, outcome: &str) {
        self.node_submissions.with_label_values(&[outcome]).inc();
    }

    /// Record a threshold-signing round timing.
    pub fn record_threshold_round(&self, round: &str, seconds: f64) {
        self.threshold_round
            .with_label_values(&[round])
            .observe(seconds);
    }

    /// Set the active-session gauge.
    pub fn set_active_sessions(&self, count: i64) {
        self.active_sessions.set(count);
    }

    /// Increment the key-derivation counter.
    pub fn inc_key_derivations(&self) {
        self.key_derivations.inc();
    }

    /// Render the metrics in Prometheus text exposition format.
    ///
    /// # Errors
    /// [`ObsError::Encoding`] if encoding fails.
    pub fn render(&self) -> Result<String, ObsError> {
        let families = self.registry.gather();
        let mut buffer = Vec::new();
        TextEncoder::new()
            .encode(&families, &mut buffer)
            .map_err(|_| ObsError::Encoding)?;
        String::from_utf8(buffer).map_err(|_| ObsError::Encoding)
    }
}
