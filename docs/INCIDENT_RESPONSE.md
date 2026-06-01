# Incident response runbook — suspected key compromise (REQ-CMP-004)

## Trigger
Suspected compromise of a custody key, broadcaster key, or member key.

## Procedure
1. **Rotate** the affected key via custody (`custody::KeyCustodian::rotate`). After
   rotation the old key is no longer current; the rotation is recorded in the
   tamper-evident lifecycle chain (REQ-CUS-006) and anchorable on chain.
2. **Re-encrypt** the broadcast group per GB §6.5: run a rekey (user/key/group-oriented,
   `broadcast::Strategy`) so the message key changes and the compromised key can no longer
   read new traffic; departed/compromised members are excluded from the new key graph.
3. **Revoke** the compromised custody chain (`KeyCustodian::revoke`); revocation is
   terminal and enforced (no further rotation), and is anchored on chain.
4. **Audit**: every step is appended to the tamper-evident audit log
   (`cmp::TamperEvidentAudit`, REQ-CMP-003); verify the chain afterward.

## Drill
Tested by `TST-CMP-004` (`tst_cmp_004_recovery_and_incident_drills`): rotate off the
compromised key (current key changes), then revoke (chain revoked). GB §6.5 rekeying is
covered by `TST-BCS-010/011/012`.
