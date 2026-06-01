# Security model and honest labelling

What the system secures, and what it does not — stated honestly (REQ terminology
honesty). Detail per crate is added as each crate is built.

## Trust root

All chain-terminating verification ends in `bsv::HeaderChain` (REQ-BSV-041/042):
prev-hash linkage, proof-of-work against the encoded target, monotonic height. A
result is accepted only if its root is the merkle root of a header in a validated
header chain. Node responses are untrusted and validated against this root.

## Secret hygiene

Seeds, chain codes, symmetric keys, key-shares, and plaintext-before-encryption are
held in `secmem::Secret`/`SecretBytes`: zeroize-on-drop, redacted `Debug`, no
`Serialize`, constant-time equality, best-effort memory locking. No secret appears in
any error, log, or audit record.

## What each mechanism conceals (no over-claiming)

- **Obfuscation keys (EP cl.5a):** strength is exactly AES-256-GCM under the derived
  key — no property is claimed beyond the cipher (REQ-OVL-022).
- **Position-only signalling (EP):** transmitting a node position reveals only the
  position; without the relevant seed the receiver cannot perform the seed-isolated
  function (e.g. cannot de-obfuscate). Held under hardened CKD so leakage of a derived
  writing key recovers neither parent, sibling, nor the second seed (REQ-CKD-004,
  REQ-OVL-052).
- **Broadcast key graph (GB):** an eligible user decrypts up the graph to the message
  key; a non-eligible user cannot. Key-wrap is authenticated AEAD, never raw XOR.

## SIGHASH discipline and broadcaster-last (GB §6.5)

Member inputs are signed `SIGHASH_SINGLE | FORKID` so a member commits only to its own
output and the funding input; the broadcaster signs **last** with `SIGHASH_ALL | FORKID`
over the whole transaction including the OP_RETURN session anchor. A member signature
therefore stays valid as the broadcaster fills in the rest, but any change to the
broadcaster-committed data (the OP_RETURN, other outputs) invalidates the broadcaster
signature — a member cannot alter the session record without detection (`TST-SES-002/003`).

## Custody boundary — threshold vs reconstruction (REQ-CUS-001/004/005)

Three modes, with an explicit boundary:

- **FROST true-threshold Schnorr** and **GG20 true-threshold ECDSA** never reassemble the
  private key — `k` parties combine partial signatures; the key exists whole at no point.
  GG20 yields a standard ECDSA signature for a BSV input; its malicious-security ZK range
  proofs are not yet implemented (semi-honest only — see `ARCHITECTURE.md`).
- **Shamir-reconstruction** is a *separate, clearly-labelled fallback* that **does**
  transiently reconstruct a quorum, signs a standard low-S ECDSA signature, and provably
  discards (zeroizes) the recovered key. It is for environments lacking threshold signing;
  the default authority signature is true-threshold.

The line is honest: threshold never reassembles; reconstruction does, transiently.

## Threat model (Section 16)

The adversarial threat model has one test per threat (REQ-SEC-*), distributed across the
crates that own each surface: forged authorisation and seed-isolation leakage (overlay/ckd
negatives), non-eligible decryption (broadcast), session-record tampering (session §6.5),
unsigned/replayed/expired/oversized requests (api), parser hostility (fuzzprop), node
dishonesty resolved against the header-chain trust root (bsv/api), and threshold key
non-materialisation (custody). No test is weakened to pass and no fixture contains
fabricated chain data (REQ-TST-050).

## Out of scope

The system secures existence, integrity, identity, authorisation, and confidentiality
of the on-chain/key-graph artifacts. It does not secure application semantics above
the obfuscation layer beyond the cipher's guarantee.
