# Operations (REQ-DOC-004)

How to deploy, run, configure, and operate the service.

## Deploy / run

- **Binary:** `cargo build --release --bin overlay-broadcast`; run subcommands (see
  `--help`). `selftest` exercises every layer; `reproduce` checks deterministic vectors.
- **Docker:** the hardened multi-stage image runs on distroless (no shell/toolchain),
  non-root UID 65532, read-only rootfs, all capabilities dropped. Build with
  `docker build -t overlay-broadcast .`.
- **Compose:** `docker-compose.hardened.yml` brings up the hardened `api` service, an
  `offline-node` fixture for CI, and a commented Teranode endpoint for live runs. The
  `test` profile runs the suite + reproduce + selftest in-container.

## Configuration

- **Service limits** (`api::ApiConfig`): `max_payload_bytes`, `rate_limit_per_window`,
  `rate_window_secs`, `op_timeout_millis` — validated at startup; invalid config fails
  fast with a clear, non-secret error (REQ-API-006).
- **Logging:** `RUST_LOG` (default `info`); JSON structured logs via `obs::logging`.
  Secrets are routed through `obs::Redacted` and never logged (REQ-OBS-004).
- **BSV node / Teranode:** set `TERANODE_ENDPOINT` (compose) for live runs; CI uses the
  OfflineNodeClient fixture with genuine recorded block data.
- **Secrets:** injected at runtime only (env from a secret store or a mounted tmpfs),
  never baked into image layers (REQ-CON-002).

## Custody operations

- **Key generation:** `overlay-broadcast custody keygen --threshold k --shares n` (FROST
  true-threshold by default; GG20 threshold ECDSA for on-chain input signatures; Shamir
  reconstruction fallback). See `docs/ARCHITECTURE.md`.
- **Rotation:** `custody rotate` re-shares to a new group key; the old key cannot sign
  after rotation, and the event is anchored on chain (REQ-CUS-006).
- **Revocation:** `custody revoke` is terminal and enforced.
- **KeyStore backup/recovery:** k-of-n Shamir of the master seed; recovery drill in
  `docs/KEY_LOSS.md`.

## Health, metrics, resilience

- `/health` (liveness) is independent; `/readiness` fails closed when the BSV node,
  KeyStore, or threshold quorum is unavailable (REQ-OBS-003, `obs::readiness`).
- Prometheus metrics expose operation/latency/error/submission/threshold-round/session/
  derivation series (REQ-OBS-001); no secret appears in any label.
- Node failure → bounded backoff + circuit breaker; resubmission is idempotent by txid; no
  fee bumping (`res`, REQ-RES-001/002). On restart, session state is rebuilt from chain
  (REQ-RES-004). Graceful shutdown never leaves a half-signed transaction (REQ-RES-005).

## Runbooks

`DISASTER_RECOVERY.md`, `KEY_LOSS.md`, `INCIDENT_RESPONSE.md` — each backed by a drill
test (`TST-CMP-004`, `TST-RES-004`).
