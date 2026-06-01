# Data classification — what may and may not go on-chain (REQ-CMP-001)

The BSV ledger is public and immutable. **No personal data and no plaintext content of any
kind is ever written on-chain.** Overlay payloads carry only encrypted or obfuscated
content; the write boundary enforces this with `cmp::guard_on_chain_write`, which refuses
any `Cleartext` payload (and names cleartext **personal data** specifically).

| Class | May go on-chain? | Mechanism |
| --- | --- | --- |
| AEAD-encrypted message/data item | Yes | `cipher` AES-256-GCM / ECIES; key in KeyStore |
| EP second-key obfuscated node payload | Yes | `overlay::obfuscate` |
| Key-graph **positions / coordinates** | Yes (no key material) | `overlay::signal_position` — positions only |
| Hashes / merkle roots / anchors | Yes | `bsv::double_sha256`, header chain |
| Public, non-personal cleartext | **No** | refused — write only encrypted/obfuscated |
| Personal data in cleartext | **No (never)** | refused as `CleartextPersonalData` |
| Seeds / private keys / key shares | **No (never)** | never leave the KeyStore |

Personal data placed in the system is encrypted under a per-record key held only in the
KeyStore; erasure is **crypto-shredding** (see `KEY_LOSS.md` / REQ-CMP-002): destroying the
key makes the on-chain ciphertext permanently undecryptable.
