# overlay-broadcast

A BSV-native Rust implementation of two inventions, graded to NPR 7150.2 / JPL
Power-of-Ten / MC-DC coverage with a full requirements-traceability matrix
([docs/RTM.csv](docs/RTM.csv)):

- **EP 4 046 048 B1** — an overlay key-graph over data-storage transactions, with
  first/second/third function key sets, the three claim-5 functions, and seed-isolated
  position-only signalling.
- **GB 2623780 B** — key-graph broadcast encryption, three rekeying strategies, and the
  on-chain session lifecycle.

BSV is the entire technical universe: post-Genesis protocol only, secp256k1 throughout,
on-chain value named exclusively in **minor units**. Verification terminates in the
validated BSV block-header chain (the trust root).

## The two layers

**Overlay layer (EP).** A key graph is laid over ordinary BSV data-storage transactions.
A node's key is re-derivable from its *position* plus a *seed* (CKD), so a sender can
signal **only a position** to a receiver — no key material crosses the wire (seed-isolated
signalling). Three EP function key sets act at a node:

- **first / writing** key set — authorises writing the node's data-storage transaction;
- **second / obfuscation** key set — obfuscates the node payload (AEAD, never raw XOR);
- **third / application** key set — the application-facing function over the node.

**Broadcast layer (GB).** A balanced key graph encrypts to a group: the root is the
message key, each leaf is a user key, and every child key wraps its parent (authenticated
key-wrap). A member decrypts up its path to the message key. Membership changes rekey via
one of **three rekeying strategies** (LKH packaging variants):

- **user-oriented** — one communique per affected user;
- **key-oriented** — one communique per changed key;
- **group-oriented** — communiques grouped by the key they are encrypted under.

## Sessions and keys

- **Off-chain vs on-block subscription.** A subscription funds *k* sessions. *Off-chain*
  carries a single on-chain funding transaction covering all *k* sessions (sub-sessions
  split off-chain); *on-block* anchors one transaction per session. Renewal spends the
  member output; an unspent output past its expiry is revocation.
- **Symmetric vs asymmetric keys.** Asymmetric secp256k1 keys (CKD-derived) sign
  transactions and seed ECIES; symmetric AES-256-GCM keys protect node payloads, broadcast
  messages, and wrapped child keys. Asymmetric keys establish; symmetric keys bulk-encrypt.

## Quickstart

```
cargo build --release
cargo run --release --bin overlay-broadcast -- selftest      # exercise every layer
cargo run --release --bin overlay-broadcast -- custody keygen --threshold 2 --shares 3
cargo run --release --bin overlay-broadcast -- broadcast open --users 1,2,3,4
cargo run --release --bin overlay-broadcast -- reproduce      # regenerate + diff vectors
```

### Docker quickstart

```
docker build -t overlay-broadcast .                           # hardened distroless image
docker run --rm --read-only --cap-drop ALL overlay-broadcast selftest
docker compose -f docker-compose.hardened.yml --profile test up --abort-on-container-exit
```

## Build and gate

```
cargo build --release
cargo test --all
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --check
cargo run -p xtask -- all      # banned-token, function-size, RTM, and SBOM gates
```

The build sets `http.check-revoke = false` in `.cargo/config.toml` (the sandbox cannot
reach the CA revocation endpoints); see [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Crates (built in the Section 23 order)

`secmem` (audited secret containers) · `bsv` (primitives + header-chain trust root) ·
`ckd` (child key derivation, EP) · `cipher` (AEAD, ECIES, key-wrap) · `keygraph` ·
`overlay` (EP) · `broadcast` (GB) · `session` (GB lifecycle) · `custody` (FROST + GG20
threshold + reconstruction) · `kst` (KeyStore: HSM/KMS/file) · `obs` · `api` · `res`
(resilience) · `cli` · `cmp` (compliance) · `bench` · `proptests` · `conformance` ·
`fuzzprop` (+ `fuzz/` libFuzzer targets) · `xtask` (gates).

## Documentation

- [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — layering, trust root, pinned deps.
- [docs/SECURITY.md](docs/SECURITY.md) — threat model and honest labelling.
- [docs/OPERATIONS.md](docs/OPERATIONS.md) — deploy, run, config, custody ops.
- [docs/REPRODUCIBILITY.md](docs/REPRODUCIBILITY.md) — how `reproduce` regenerates vectors.
- [docs/COMPLIANCE.md](docs/COMPLIANCE.md) · [docs/CODING_STANDARD.md](docs/CODING_STANDARD.md) · [docs/RTM.csv](docs/RTM.csv).
- Runbooks: [DISASTER_RECOVERY](docs/DISASTER_RECOVERY.md) · [KEY_LOSS](docs/KEY_LOSS.md) · [INCIDENT_RESPONSE](docs/INCIDENT_RESPONSE.md).

The source is dual-licensed MIT OR Apache-2.0; this code license is independent of the
patent rights in the two inventions.
