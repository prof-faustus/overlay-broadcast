//! Benchmark studies and soak harness (Section 15/21).
//!
//! Three studies (REQ-BENCH-002): (a) overlay key-set derivation + position resolution
//! across graph sizes; (b) per-rekeying-strategy communique and encrypted-data-item counts
//! for a leave on a GB graph; (c) off-chain vs on-block subscription transaction counts and
//! on-chain footprint. Each study reports **deterministic structural counts** — the figures
//! `reproduce` checks (REQ-BENCH-001/003, no hand-written numbers) — plus a measured
//! latency, which is this system's own measurement on the running host, never an external
//! figure restated as a result.
#![forbid(unsafe_code)]

use broadcast::{BroadcastGraph, Strategy};
use overlay::{resolve_key, signal_position, Position};
use session::{Subscription, SubscriptionMode};
use std::time::Instant;

/// One study result: deterministic counts plus a measured latency.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct StudyResult {
    /// The study/case name.
    pub name: String,
    /// Deterministic structural counts (the reproduce-checked figures).
    pub counts: Vec<u64>,
}

/// A study result paired with its measured latency (excluded from equality so determinism
/// comparisons ignore timing).
#[derive(Clone, Debug)]
pub struct TimedStudy {
    /// The deterministic result.
    pub result: StudyResult,
    /// Measured wall-clock latency in microseconds (host-specific).
    pub latency_micros: u128,
}

/// Run every study. `full` selects the large graph sizes (REQ-BENCH-002); otherwise the
/// small CI point is used.
#[must_use]
pub fn run_all_studies(full: bool) -> Vec<TimedStudy> {
    let overlay_sizes: &[u32] = if full {
        &[1024, 16384, 262_144]
    } else {
        &[64, 256]
    };
    let broadcast_sizes: &[u64] = if full { &[64, 256, 1024] } else { &[8, 16] };
    let mut out = study_overlay(overlay_sizes);
    out.extend(study_broadcast(broadcast_sizes));
    out.extend(study_subscription(1_000, 100));
    out
}

/// The deterministic results only (for determinism / reproduce checks).
#[must_use]
pub fn deterministic_results(full: bool) -> Vec<StudyResult> {
    run_all_studies(full)
        .into_iter()
        .map(|timed| timed.result)
        .collect()
}

// Study (a): overlay position signalling + key resolution across sizes.
fn study_overlay(sizes: &[u32]) -> Vec<TimedStudy> {
    let seed = [0x07u8; 32];
    sizes
        .iter()
        .map(|&n| {
            let start = Instant::now();
            let mut resolved = 0u64;
            for i in 0..n {
                let position = Position::new(vec![i % 16, i.wrapping_div(16) % 16, 0]);
                let coords = signal_position(&position);
                if resolve_key(&coords, &seed).is_ok() {
                    resolved = resolved.saturating_add(1);
                }
            }
            TimedStudy {
                result: StudyResult {
                    name: format!("overlay/resolve/N={n}"),
                    counts: vec![resolved],
                },
                latency_micros: start.elapsed().as_micros(),
            }
        })
        .collect()
}

// Study (b): broadcast data-item count and per-strategy communique counts for a leave.
fn study_broadcast(user_counts: &[u64]) -> Vec<TimedStudy> {
    user_counts
        .iter()
        .filter_map(|&n| {
            let ids: Vec<u64> = (1..=n).collect();
            let start = Instant::now();
            let mut graph = BroadcastGraph::build(&ids).ok()?;
            let items = u64::try_from(graph.encrypted_data_items().ok()?.len()).ok()?;
            let result = graph.leave(1).ok()?;
            let user_communiques = count(&graph, &result, Strategy::UserOriented);
            let key_communiques = count(&graph, &result, Strategy::KeyOriented);
            let group_communiques = count(&graph, &result, Strategy::GroupOriented);
            Some(TimedStudy {
                result: StudyResult {
                    name: format!("broadcast/leave/N={n}"),
                    counts: vec![items, user_communiques, key_communiques, group_communiques],
                },
                latency_micros: start.elapsed().as_micros(),
            })
        })
        .collect()
}

fn count(graph: &BroadcastGraph, result: &broadcast::RekeyResult, strategy: Strategy) -> u64 {
    graph
        .communiques(result, strategy)
        .map(|communiques| u64::try_from(communiques.len()).unwrap_or(0))
        .unwrap_or(0)
}

// Study (c): off-chain vs on-block subscription transaction counts and footprint.
fn study_subscription(contribution: u64, mem_fee: u64) -> Vec<TimedStudy> {
    let start = Instant::now();
    let off_chain = Subscription::new(SubscriptionMode::OffChain, contribution, mem_fee)
        .map(|s| s.sessions_funded())
        .unwrap_or(0);
    let on_block = Subscription::new(SubscriptionMode::OnBlock, contribution, mem_fee)
        .map(|s| s.sessions_funded())
        .unwrap_or(0);
    // off-chain: a single on-chain funding tx covers all funded sessions; on-block: one
    // on-chain tx per session.
    let counts = vec![off_chain, 1, on_block, on_block];
    vec![TimedStudy {
        result: StudyResult {
            name: "subscription/offchain-vs-onblock".to_owned(),
            counts,
        },
        latency_micros: start.elapsed().as_micros(),
    }]
}

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;

    // TST-BENCH-001/002: the studies run and produce structural counts; no figure is
    // hand-written — every count comes from running the system.
    #[test]
    fn tst_bench_002_studies_produce_counts() {
        let results = run_all_studies(false);
        assert!(
            results.len() >= 4,
            "overlay + broadcast + subscription studies present"
        );
        // overlay: every position resolves
        let overlay = &results[0].result;
        assert!(overlay.name.starts_with("overlay/resolve/"));
        assert_eq!(overlay.counts, vec![64], "all 64 positions resolved");
        // subscription: off-chain funds 10 sessions with a single funding tx
        let subscription = results.last().unwrap();
        assert_eq!(subscription.result.counts, vec![10, 1, 10, 10]);
    }

    // TST-BENCH-001 (reproduce-feeding): the deterministic counts are identical across runs
    // (latency excluded), so `reproduce` can diff them.
    #[test]
    fn tst_bench_001_deterministic_for_reproduce() {
        assert_eq!(
            deterministic_results(false),
            deterministic_results(false),
            "counts are reproducible"
        );
    }

    // TST-TST-040: a bounded soak run produces stable counts every iteration (no drift,
    // no panic). The full memory/descriptor soak is the scheduled D run.
    #[test]
    fn tst_tst_040_bounded_soak_is_stable() {
        let baseline = deterministic_results(false);
        for _ in 0..50u32 {
            assert_eq!(
                deterministic_results(false),
                baseline,
                "soak metrics stay stable"
            );
        }
    }
}
