# Compliance, privacy, and audit integrity (REQ-DOC-004, Section 20)

## On-chain data policy (REQ-CMP-001)
No personal data and no plaintext content is ever written on-chain. Overlay payloads carry
only encrypted or obfuscated content; the write boundary (`cmp::guard_on_chain_write`)
refuses any cleartext payload and names cleartext personal data specifically. See
`docs/DATA_CLASSIFICATION.md` for the full table.

## Right to erasure — crypto-shredding (REQ-CMP-002)
Erasure destroys the per-record key in the KeyStore (`KeyStore::delete`). The on-chain
ciphertext then has no key path and is permanently undecryptable. The only copy of the key
lived in the KeyStore, so its destruction is irreversible. Tested by `TST-CMP-002`.

## Audit integrity (REQ-CMP-003)
The audit log is tamper-evident: each entry is hash-chained to its predecessor
(`cmp::TamperEvidentAudit`, `double_sha256`), and the head hash can be anchored to BSV via
the overlay so the history terminates in the header chain. Tampering with any field of any
entry breaks the chain and is detected by `verify_audit_chain` (`TST-CMP-003`). The api
audit log (REQ-API-004) records operation metadata only — never a seed, key, key-share, or
plaintext.

## Runbooks and drills (REQ-CMP-004)
- `DISASTER_RECOVERY.md` — node/KeyStore/custodian loss, region failover.
- `KEY_LOSS.md` — master-seed loss + k-of-n recovery drill.
- `INCIDENT_RESPONSE.md` — suspected compromise → rotate (custody) → re-encrypt (GB §6.5)
  → revoke.

Each runbook is backed by a drill test (`TST-CMP-004`, `TST-RES-004`).

## Service-level objectives (REQ-CMP-005)
SLOs for availability, submission latency, and signing latency are documented in
`docs/SLOs.md`, each mapped to the `obs` metric series that measures it. Secrets never
appear in any metric label or value.
