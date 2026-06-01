# Key-loss runbook — master-seed loss + k-of-n recovery (REQ-CMP-004)

The master seed is split into `n` Shamir shares with reconstruction threshold `k`
(`kst::shamir256`, REQ-KST-020). Each share is itself KeyStore-protected (wrapped under the
backend KEK). Any `k` shares reconstruct the exact key set; `k-1` reveal nothing.

## Recovery drill
1. Gather `k` custodian shares.
2. Open a KeyStore with the original backend KEK (passphrase + salt).
3. `KeyStore::restore(id, shares, exportable)` reconstructs the seed and re-imports it.
4. Confirm the restored public key equals the pre-loss public key.

This is the procedure tested by `TST-KST-020` and `TST-CMP-004`
(`tst_cmp_004_recovery_and_incident_drills`): generate → backup(3,5) → restore from 3
shares → public key matches.

## Crypto-shredding (right to erasure, REQ-CMP-002)
To honour an erasure request, destroy the per-record key in the KeyStore
(`KeyStore::delete`). The on-chain ciphertext then has no key path and is permanently
undecryptable. Tested by `TST-CMP-002`.
