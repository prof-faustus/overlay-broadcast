//! Health and readiness logic (REQ-OBS-003). Liveness reports process health and is
//! independent of downstreams. Readiness probes that the actual downstreams (BSV node,
//! KeyStore, threshold quorum) are reachable and **fails closed**: it is ready only if at
//! least one probe is configured and every probe reports up. The HTTP exposure of these
//! lives in the api crate; here we provide the decision logic so it is unit-testable.

/// A probe of one downstream dependency.
pub trait DependencyProbe {
    /// The dependency name (for the readiness report; never a secret).
    fn name(&self) -> &str;
    /// Whether the dependency is currently reachable. An unknown/errored state must
    /// return `false` (fail closed).
    fn is_up(&self) -> bool;
}

/// Liveness: the process is running. Always live if this code executes.
#[must_use]
pub fn liveness() -> bool {
    true
}

/// The outcome of a readiness evaluation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReadinessReport {
    /// Whether the service is ready to serve.
    pub ready: bool,
    /// Names of dependencies currently down (empty when ready).
    pub down: Vec<String>,
}

/// Evaluate readiness across all probes, failing closed.
#[must_use]
pub fn readiness(probes: &[Box<dyn DependencyProbe>]) -> ReadinessReport {
    if probes.is_empty() {
        return ReadinessReport {
            ready: false,
            down: vec!["<no probes configured>".to_owned()],
        };
    }
    let down: Vec<String> = probes
        .iter()
        .filter(|probe| !probe.is_up())
        .map(|probe| probe.name().to_owned())
        .collect();
    ReadinessReport {
        ready: down.is_empty(),
        down,
    }
}
