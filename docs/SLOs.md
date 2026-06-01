# Service-level objectives (REQ-CMP-005)

Each SLO is measured by a metric series in the `obs` crate (Section 13, REQ-OBS-001), so
the objective is observable, not aspirational.

| SLO | Objective | Metric (obs) |
| --- | --- | --- |
| Availability | ≥ 99.9% monthly; `/readiness` fails closed when a dependency is down | readiness probe + `ob_operations_total{outcome}` error rate |
| Submission latency | p99 BSV submission < 2 s (offline fixture: < 50 ms) | `ob_operation_latency_seconds{operation="overlay.write"}`, `ob_node_submissions_total{outcome}` |
| Signing latency | p99 threshold-round latency < 1 s | `ob_threshold_round_seconds{round}` |
| Key-derivation throughput | ≥ 10k derivations/s on the stated bench host | `ob_key_derivations_total` |
| Active sessions | tracked for capacity planning | `ob_active_sessions` |

Latency/throughput numbers are this system's own measurements on the stated bench host
(Section 15 `bench`, REQ-BENCH-001/003); no external figure is restated as a measured
result. Availability and error-rate SLOs are evaluated from the Prometheus series above;
secrets never appear in any label or value (REQ-OBS-001).
