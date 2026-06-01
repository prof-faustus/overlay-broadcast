//! Property tests (Section 21, REQ-TST-002) for the protocol invariants of keygraph, ckd,
//! overlay, and broadcast. The crate is exercised entirely through its property tests.
#![forbid(unsafe_code)]

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use broadcast::BroadcastGraph;
    use bsv::{double_sha256, hash160};
    use cipher::{open, seal};
    use overlay::{deobfuscate, obfuscate, resolve_key, signal_position, Position};
    use proptest::prelude::*;

    proptest! {
        // TST-TST-002 (ckd determinism + overlay/cipher round-trip): resolving the key at a
        // signalled position from a fixed seed is deterministic, and obfuscate∘deobfuscate is
        // the identity for any payload.
        #[test]
        fn prop_overlay_obfuscation_roundtrip(
            payload in proptest::collection::vec(any::<u8>(), 0..96),
            seed in proptest::array::uniform32(any::<u8>()),
            c0 in 0u32..64,
            c1 in 0u32..64,
        ) {
            let coords = signal_position(&Position::new(vec![c0, c1]));
            let key_a = resolve_key(&coords, &seed).unwrap();
            let key_b = resolve_key(&coords, &seed).unwrap();
            let ciphertext = obfuscate(&key_a, &payload).unwrap();
            let recovered = deobfuscate(&key_b, &ciphertext).unwrap();
            prop_assert_eq!(recovered.expose(), payload.as_slice());
        }

        // TST-TST-002 (keygraph + broadcast invariant): every member of the group can decrypt
        // any message sealed to it (varying the message and which member decrypts, over a
        // known-good four-member graph).
        #[test]
        fn prop_broadcast_member_decrypts(
            message in proptest::collection::vec(any::<u8>(), 1..48),
            member in 1u64..=4,
        ) {
            let graph = BroadcastGraph::build(&[1, 2, 3, 4]).unwrap();
            let sealed = graph.encrypt_message(&message).unwrap();
            let items = graph.encrypted_data_items().unwrap();
            let leaf = graph.user_leaf_key(member).unwrap();
            let recovered = graph.user_decrypt(member, &leaf, &items, &sealed).unwrap();
            prop_assert_eq!(recovered.expose(), message.as_slice());
        }

        // TST-TST-002 (cipher round-trip): AEAD seal∘open is the identity under the same key,
        // nonce, and AAD.
        #[test]
        fn prop_aead_roundtrip(
            plaintext in proptest::collection::vec(any::<u8>(), 0..128),
            key in proptest::array::uniform32(any::<u8>()),
            nonce in proptest::array::uniform12(any::<u8>()),
        ) {
            let ciphertext = seal(&key, &nonce, &plaintext, b"prop").unwrap();
            let recovered = open(&key, &nonce, &ciphertext, b"prop").unwrap();
            prop_assert_eq!(recovered.expose(), plaintext.as_slice());
        }

        // TST-TST-002 (hash determinism): the BSV hashes are pure functions of their input.
        #[test]
        fn prop_hash_determinism(data in proptest::collection::vec(any::<u8>(), 0..256)) {
            let first = double_sha256(&data);
            let second = double_sha256(&data);
            prop_assert_eq!(first.internal(), second.internal());
            prop_assert_eq!(hash160(&data), hash160(&data));
        }
    }
}
