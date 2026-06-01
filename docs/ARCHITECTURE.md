# Architecture

BSV-native Rust implementation of EP 4 046 048 B1 (overlay key-graph + seed-isolated
position signalling) and GB 2623780 B (key-graph broadcast encryption + session
lifecycle), graded to NPR 7150.2 / JPL Power-of-Ten / MC-DC.

## Layering and trust root

A Cargo workspace of layered crates; lower crates never depend on upper crates
(REQ-GOV-002). The single root of trust is the BSV block-header chain
(`bsv::HeaderChain`, REQ-BSV-041/042): no chain-terminating verification anywhere
accepts a result unless its root is the merkle root of a header in a validated
header chain (prev-hash linkage + proof-of-work + monotonic height).

```
secmem  -> bsv -> ckd -> cipher -> keygraph -> overlay   (EP)
                                             -> broadcast (GB) -> session
                  custody   kst   obs   api   cli   bench
```

Build order is Section 23 of the SRS; each step's full CI gate is green before the
next (REQ-BLD-001).

## Pinned dependencies (REQ-UNI-006/007, REQ-CKD-010, REQ-CUS-002/010, REQ-KST-010/011)

| concern | pin | rationale |
| --- | --- | --- |
| toolchain | Rust 1.96.0, components rustfmt/clippy/llvm-tools-preview | reproducible build (REQ-GOV-001) |
| secp256k1 | `k256` (RustCrypto), `default-features = false`, features `ecdsa`+`arithmetic`+`std` | pure-Rust (no C toolchain), NCC-audited; provides low-S normalization and RFC-6979 deterministic signing, both **proven by test** (REQ-BSV-032, REQ-CKD-010) rather than assumed; `Scalar` implements `Zeroize` (via the non-optional `elliptic-curve` zeroize dep), so reconstruction-mode custody wipes the transiently-recovered key (REQ-CUS-004) |
| hashing | `sha2`, `ripemd`, `hmac`, `hkdf` (RustCrypto) | KAT-verified; double-SHA-256, hash160, HMAC-SHA512 (CKD), HKDF-SHA256 (ECIES) |
| AEAD | `aes-gcm` (RustCrypto) | AES-256-GCM with enforced nonce-uniqueness invariant (REQ-CIPH-010) |
| secret hygiene | `zeroize`, `subtle` | zeroize-on-drop, constant-time equality (Section 3) |
| threshold ECDSA bignum | `num-bigint-dig` (features `prime`+`rand`), `num-integer`, `rand` | Paillier modular arithmetic + safe-prime generation for the hand-rolled GG20 MtA (REQ-CUS-004); same big-integer backend the RustCrypto `rsa` crate uses |
| passphrase KDF | `argon2` (RustCrypto), Argon2id defaults | memory-hard KEK derivation for the encrypted-file KeyStore (REQ-KST-012) |

### BSV SDK (REQ-UNI-006/007)

There is no established, audited Rust crate equivalent to a full "BSV SDK". Per
**REQ-UNI-007** ("where the pinned SDK does not provide a required property, the
build SHALL supply it at the project wrapper layer and SHALL NOT assume the SDK
provides it"), the `bsv` crate supplies BSV primitives — Hash256/byte-order,
txid, transaction parse/serialise, post-Genesis script, FORKID sighash, header
chain, data carrier — at the wrapper layer over the vetted RustCrypto hashing
crates and `k256` for curve/ECDSA. Every chain-facing property (low-S, RFC-6979,
sighash KATs, header-chain validation) is verified by test against genuine BSV
fixtures, never assumed. If a maintained, audited BSV SDK crate is later pinned,
the wrapper traits are the seam to adopt it behind.

### Threshold scheme (REQ-CUS-002) — ratify at step 10

The custody crate's *true threshold* (key never reconstructed) is pinned to
**FROST over secp256k1** (Chu–Komlo–Goldberg–et al.; "FROST: Flexible Round-Optimized
Schnorr Threshold Signatures", 2020), a published, peer-reviewed construction. Note
the consequence to ratify: FROST produces **Schnorr** group signatures, whereas a
BSV transaction input requires **ECDSA**. Therefore on-chain broadcaster ECDSA
signatures use the **Shamir-reconstruction custody** mode (REQ-CUS-005; reconstructs
a quorum, signs, provably discards the key) where a single valid BSV ECDSA signature
is required, while FROST provides true-threshold authority signatures off the input
path. The alternative — GG20 threshold ECDSA (Gennaro–Goldfeder, 2020) — yields
on-chain-valid ECDSA but has a thinner audited-Rust surface. This fork is flagged
for explicit ratification when custody is built.

**Ratified at step 10 (2026-06), maintainer decision = hand-roll GG20.** Three custody
signing modes are built:

1. **GG20 threshold ECDSA** (Gennaro–Goldfeder, "One Round Threshold ECDSA with
   Identifiable Abort", 2020) — the REQ-CUS-004 path. `partial_sign` + `combine` yield a
   standard low-S BSV ECDSA signature verifying under the group public key, with the key
   never reconstructed. Built from scratch (`gg20.rs` + a from-scratch Paillier in
   `paillier.rs`) over `num-bigint-dig`.
   - **Rounds:** the canonical GG20 flow is 1 offline round-set (commit `g^{γ_i}`,
     pairwise MtA for `δ=kγ` and `σ=kx`, reveal `δ_i`) + 1 online round (reveal `Γ_i`,
     broadcast `s_i`). This reference executes those rounds in-process.
   - **ZK proofs — ALL IMPLEMENTED (2026-06).** Every MtA in `gg20::sign` verifies the full
     GG18/20 malicious-security proof set, all hand-rolled over ring-Pedersen parameters
     with Fiat–Shamir:
     - **Initiator range proof** (Alice's Π; `custody::rangeproof::prove`/`verify`) — the
       initiator's ciphertext encrypts an in-range value (`TST-CUS-004`, `tst_cus_004c`).
     - **Responder consistency proof** (Bob's Π′; `rangeproof::prove_responder`/
       `verify_responder`) — `c_b = c_a^b·Enc(β')` is well-formed with `b` in range
       (`tst_cus_004e`).
     - **Paillier-modulus proof** (Π_N; `custody::modulusproof`) — each party's modulus
       satisfies `gcd(N, φ(N)) = 1`, checked once up front in `sign` (`tst_cus_004d`).
   - **Residual item — identifiable abort.** A malicious initiator/responder and a malformed
     modulus are all *rejected* (clean typed error). What remains is cryptographic
     *attribution* of a fault to a specific party on abort, which needs the echo-broadcast
     consistency round; that is the last GG20 hardening step. Paillier modulus **≥ 2048 bits
     in production** (the `n > q²` correctness bound alone needs ~512); tests use 1024, and
     the modulus proof uses 12 challenges for test speed (production ≥ 80).
2. **FROST true-threshold Schnorr** (Komlo–Goldberg 2020) — committed nonces, Lagrange on
   partial signatures, key never reconstructed; for authority signatures off the on-chain
   input path (REQ-CUS-001/003).
3. **Shamir-reconstruction ECDSA** — clearly-labelled fallback that transiently
   reconstructs a quorum, signs low-S ECDSA, and wipes the key (REQ-CUS-005).

### KeyStore backends (REQ-KST-010/011/012)

Three tiers, lowest-assurance to highest:

1. **Encrypted-file** (REQ-KST-012) — BUILT and tested (`kst::EncryptedFileKeyStore`).
   Seeds AEAD-encrypted at rest (AES-256-GCM) under an Argon2id KEK derived from an
   operator passphrase; the entry id is bound as AEAD associated data; no plaintext seed
   touches the at-rest blob; a wrong passphrase fails the tag check. k-of-n Shamir seed
   backup (GF(2^8), `kst::shamir256`) with each share KeyStore-protected (REQ-KST-020).
2. **PKCS#11 HSM** (REQ-KST-010) — intended pin `cryptoki` (provisional; the de-facto
   PKCS#11 Rust binding, dlopen-based so it builds without hardware). Integration test
   `#[ignore]` until a PKCS#11 module/token (SoftHSM2 or hardware) is present.
3. **Cloud KMS** (REQ-KST-011) — envelope encryption (data keys wrapped by a KMS master
   key). KMS client crate to be pinned when a target service is chosen; integration test
   `#[ignore]` until KMS credentials + a reachable service are present.

The HSM/KMS crate pins are provisional, to be ratified before those backends are coded
(they pull large dependency trees, so they are not added speculatively).

## Build-environment note (REQ-GOV-001 reproducibility)

`.cargo/config.toml` sets `http.check-revoke = false`. The build host cannot reach
the CA CRL/OCSP endpoints, so schannel otherwise fails the TLS handshake to
crates.io with `CRYPT_E_NO_REVOCATION_CHECK`. The certificate is still validated;
only the online revocation check is skipped. This is recorded here as required.

## Licensing vs patents

The source is dual-licensed MIT OR Apache-2.0. This is the **code** license and is
independent of the patent rights in EP 4 046 048 B1 and GB 2623780 B; implementing a
patented method under an open code license grants no patent license.
