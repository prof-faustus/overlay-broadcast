# Status — overlay-broadcast

_Last updated: 2026-06-01_

**Overall:** Active/in-progress

## What this is
A BSV-native Rust implementation of two inventions — EP 4 046 048 B1 (an overlay key-graph over data-storage transactions) and GB 2623780 B (key-graph broadcast encryption with three rekeying strategies and an on-chain session lifecycle) — graded to NPR 7150.2 / Power-of-Ten with a full requirements-traceability matrix.

## Current state
- Full Cargo workspace implemented: 22 crates including `secmem`, `bsv`, `ckd`, `cipher`, `keygraph`, `overlay` (EP), `broadcast` (GB), `session`, `custody` (FROST + hand-rolled GG20 threshold ECDSA + Shamir), `kst`, `obs`, `api`, `res`, `cli`, `cmp`, `bench`, `proptests`, `conformance`, `sec`, plus `node` and `server`, and a `fuzz/` libFuzzer set.
- CHANGELOG reports `cargo test --all` green with clippy/fmt/doc clean and CI gates wired (SBOM, cargo-deny/audit, coverage/mutation, reproduce, selftest). Results are as declared in the repo; not re-run this pass.
- Latest work (0.3.0) adds a live Teranode JSON-RPC node-submission client (`node`) and a served HTTP API (`server`), reported proven running inside the hardened distroless container against a live Teranode v0.15.1 node.
- Adversarial threat-model suite (`sec` crate) and full session lifecycle reported complete; RTM (`docs/RTM.csv`) reconciled.
- CHANGELOG `[Unreleased]` section is currently empty; the most recent tagged version is 0.3.0. No status doc declares the project finished, so classified as active rather than complete.
- No-agent-identity constraint applies (banned-tokens gate over source and commit messages) — this file adds no authorship identity.

## Version control
- Git: yes, branch master, last commit `656c93a Live deployment: node-submission client + served HTTP api, proven in the hardened container`, working tree clean.

## How to verify / build
- `cargo build --release`
- `cargo test --all`
- `cargo clippy --all-targets --all-features -- -D warnings`
- `cargo fmt --check`
- `cargo run -p xtask -- all` — banned-token, function-size, RTM, and SBOM gates.
- `cargo run --release --bin overlay-broadcast -- selftest` / `-- reproduce`.
- Docker: `docker build -t overlay-broadcast .` then `docker compose -f docker-compose.hardened.yml --profile test up --abort-on-container-exit`.
