# Disaster recovery runbook (REQ-CMP-004)

The on-chain ledger is the source of truth for session state; the service holds only a
derived cache (REQ-RES-004). Recovery rebuilds that cache from chain + KeyStore.

## Node loss (BSV node unreachable)
1. The circuit breaker opens after persistent failures; `/readiness` fails closed
   (`res::CircuitBreaker`, REQ-RES-001). `/health` (liveness) stays up.
2. Repoint to a healthy node / Teranode endpoint (compose `TERANODE_ENDPOINT`).
3. On recovery a half-open trial closes the breaker; resubmission is idempotent by txid
   (`res::Resubmitter`, REQ-RES-002) — no double-spends.

## KeyStore loss
1. Stand up a KeyStore backend (file/HSM/KMS).
2. Restore the master seed from the k-of-n Shamir backup — see `KEY_LOSS.md`.
3. Re-derive all keys via CKD from the restored seed.

## Region failover
1. Bring up the service in the standby region pointed at the same KeyStore + node.
2. Rebuild session state from chain: `res::rebuild_from_chain` over an on-chain snapshot
   reproduces the exact pre-failover state (member spent = renewed; unspent past expiry =
   revoked; current graph root). **Drill:** `cmp` / `res` tests TST-RES-004.

## Custodian loss (threshold signer unavailable)
- Threshold signing tolerates up to `n-k` unavailable signers (`res::check_quorum`,
  REQ-RES-003); below quorum the operation fails cleanly and readiness reflects it.

**Drill:** the recovery path is exercised by `TST-RES-004` and `TST-CMP-004`.
