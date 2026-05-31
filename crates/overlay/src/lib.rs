#![forbid(unsafe_code)]
//! `overlay`: EP 4 046 048 B1. An overlay key-graph over data-storage transactions
//! with first/second/third function key sets, the three claim-5 functions, and the
//! central property — seed-isolated, position-only signalling: a second module given
//! only a node position (and the first seed) can re-derive the writing key, yet
//! cannot perform the second function (e.g. cannot de-obfuscate) because it lacks the
//! second seed. Part 1 here covers the key sets, the obfuscation function, and the
//! signalling/seed-isolation properties; transaction writing and the funding /
//! application functions build on it.

mod error;
mod graph;
mod keys;
mod writer;

pub use bsv::{OfflineNodeClient, OutPoint, Txid};
pub use ckd::Position;
pub use error::OverlayError;
pub use graph::{OverlayGraph, OverlayNetwork};
pub use keygraph::{Bounds, NodeId};
pub use keys::{deobfuscate, obfuscate, resolve_key, signal_position, OverlayKeys};
pub use writer::{
    funding_output, verify_authorisation, ApplicationFunction, OverlayWriter, WritingOptions,
    WrittenNode,
};

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;
    use ckd::Seeds;

    const MASTER: &[u8] = &[0x11u8; 32];

    fn bounds() -> Bounds {
        Bounds {
            max_depth: 8,
            max_breadth: 8,
            max_nodes: 256,
        }
    }

    // TST-OVL-001/002: an overlay graph is built over data-storage-transaction nodes,
    // for Metanet and for a second generic instantiation.
    #[test]
    fn tst_ovl_001_002_graph_build() {
        let mut metanet = OverlayGraph::new(OverlayNetwork::Metanet, bounds());
        let root = metanet.root();
        let a = metanet.add_node(root, 0).unwrap();
        let a0 = metanet.add_node(a, 0).unwrap();
        assert_eq!(metanet.position_of(a0).unwrap().coords(), &[0, 0]);
        metanet.keygraph().verify_invariants().unwrap();
        assert_eq!(metanet.network(), &OverlayNetwork::Metanet);

        let mut generic =
            OverlayGraph::new(OverlayNetwork::Generic("acme-overlay".into()), bounds());
        let g0 = generic.add_node(generic.root(), 5).unwrap();
        assert_eq!(generic.position_of(g0).unwrap().coords(), &[5]);
    }

    // TST-OVL-031: the three key sets are derivable from one master seed and are
    // independent at a given position.
    #[test]
    fn tst_ovl_031_three_key_sets_independent() {
        let keys = OverlayKeys::from_master(MASTER).unwrap();
        let pos = Position::new(vec![2, 3]);
        let first = keys.writing_key(&pos).unwrap();
        let second = keys.second_key(&pos).unwrap();
        let third = keys.third_key(&pos).unwrap();
        assert_ne!(first.private_key_bytes(), second.private_key_bytes());
        assert_ne!(first.private_key_bytes(), third.private_key_bytes());
        assert_ne!(second.private_key_bytes(), third.private_key_bytes());
        // re-derivation is stable.
        let keys2 = OverlayKeys::from_master(MASTER).unwrap();
        assert_eq!(
            keys2.writing_key(&pos).unwrap().private_key_bytes(),
            first.private_key_bytes()
        );
    }

    // TST-OVL-021a: the obfuscation function round-trips; a tampered payload and a
    // wrong key are rejected.
    #[test]
    fn tst_ovl_021a_obfuscation() {
        let keys = OverlayKeys::from_master(MASTER).unwrap();
        let pos = Position::new(vec![1]);
        let second = keys.second_key(&pos).unwrap();
        let payload = b"node payload content";
        let obf = obfuscate(&second, payload).unwrap();
        assert_eq!(deobfuscate(&second, &obf).unwrap().expose(), payload);
        // tamper fails.
        let mut bad = obf.clone();
        if let Some(b) = bad.bytes.first_mut() {
            *b ^= 0xff;
        }
        assert!(deobfuscate(&second, &bad).is_err());
        // the wrong second key (a different position) fails.
        let other = keys.second_key(&Position::new(vec![2])).unwrap();
        assert!(deobfuscate(&other, &obf).is_err());
    }

    // TST-OVL-050/061: signalling transmits only a position; the receiver re-derives
    // the writing key from first seed + position, and the second-function key from
    // second seed + position.
    #[test]
    fn tst_ovl_050_061_position_signalling() {
        let seeds = Seeds::from_master(MASTER).unwrap();
        let keys = OverlayKeys::from_seeds(Seeds::from_master(MASTER).unwrap());
        let pos = Position::new(vec![4, 2]);
        let signalled = signal_position(&pos);
        assert_eq!(signalled, vec![4, 2]); // only the position travels

        let writing = resolve_key(&signalled, seeds.first().expose()).unwrap();
        assert_eq!(
            writing.private_key_bytes(),
            keys.writing_key(&pos).unwrap().private_key_bytes()
        );
        let second = resolve_key(&signalled, seeds.second().expose()).unwrap();
        assert_eq!(
            second.private_key_bytes(),
            keys.second_key(&pos).unwrap().private_key_bytes()
        );
    }

    // TST-OVL-051/052: a module holding only the first seed + a position can re-derive
    // the writing key but CANNOT de-obfuscate (it lacks the second seed); the writing
    // and second keys are independent, so leaking the writing key grants no
    // de-obfuscation ability.
    #[test]
    fn tst_ovl_051_052_seed_isolation_negative() {
        let seeds = Seeds::from_master(MASTER).unwrap();
        let keys = OverlayKeys::from_seeds(Seeds::from_master(MASTER).unwrap());
        let pos = Position::new(vec![7]);
        let signalled = signal_position(&pos);

        // the true obfuscation uses the SECOND key set.
        let second = keys.second_key(&pos).unwrap();
        let obf = obfuscate(&second, b"only the second seed can read this").unwrap();

        // B has only the FIRST seed: it can re-derive the writing key...
        let b_writing = resolve_key(&signalled, seeds.first().expose()).unwrap();
        assert_eq!(
            b_writing.private_key_bytes(),
            keys.writing_key(&pos).unwrap().private_key_bytes()
        );
        // ...but the best key B can form (from the first seed) does NOT de-obfuscate.
        assert!(
            deobfuscate(&b_writing, &obf).is_err(),
            "first-seed holder cannot de-obfuscate"
        );

        // writing and second keys at the position are independent.
        assert_ne!(b_writing.private_key_bytes(), second.private_key_bytes());
    }

    fn funding() -> OutPoint {
        OutPoint {
            txid: Txid::from_display_hex(&"11".repeat(32)).unwrap(),
            vout: 0,
        }
    }

    // TST-OVL-010/011: write a node (sign its input with the writing key); a node
    // verifies the authorisation; a wrong writing key is rejected; writing is
    // idempotent on position.
    #[test]
    fn tst_ovl_010_011_write_and_verify() {
        let keys = OverlayKeys::from_master(MASTER).unwrap();
        let mut writer = OverlayWriter::new(keys, OfflineNodeClient::new());
        let pos = Position::new(vec![0]);
        let opts = WritingOptions {
            obfuscate: true,
            funding_value: 5000,
        };
        let node = writer
            .write_node(&pos, b"hello overlay", &opts, funding())
            .unwrap();
        assert!(
            verify_authorisation(&node, 5000).unwrap(),
            "the writing key authorised the input"
        );

        // a wrong writing public key fails verification (the sighash no longer matches).
        let mut tampered = node.clone();
        tampered.writing_public_key = OverlayKeys::from_master(MASTER)
            .unwrap()
            .writing_key(&Position::new(vec![1]))
            .unwrap()
            .public_key_compressed()
            .unwrap();
        assert!(!verify_authorisation(&tampered, 5000).unwrap());

        // idempotent: re-writing the same position returns the same transaction.
        let again = writer
            .write_node(&pos, b"hello overlay", &opts, funding())
            .unwrap();
        assert_eq!(again.txid_display, node.txid_display);
    }

    // TST-OVL-021b: the funding output is a P2PKH spendable exactly by the funding key.
    #[test]
    fn tst_ovl_021b_funding() {
        let keys = OverlayKeys::from_master(MASTER).unwrap();
        let pos = Position::new(vec![2]);
        let funding_key = keys.second_key(&pos).unwrap();
        let output = funding_output(&funding_key, 9999).unwrap();
        assert_eq!(output.value, 9999);
        // the locking script is P2PKH to the funding key's hash160.
        let pkh = bsv::hash160(&funding_key.public_key_compressed().unwrap());
        assert_eq!(output.locking_script, bsv::p2pkh(&pkh));
    }

    struct TagApp;
    impl ApplicationFunction for TagApp {
        fn apply(
            &self,
            node: &WrittenNode,
            application_key: &ckd::XPriv,
        ) -> Result<Vec<u8>, OverlayError> {
            let mut out = node.txid_display.clone().into_bytes();
            out.extend_from_slice(&application_key.public_key_compressed()?);
            Ok(out)
        }
    }

    // TST-OVL-021c: a pluggable application-layer function is bound to the node's
    // transaction and its application key.
    #[test]
    fn tst_ovl_021c_application() {
        let keys = OverlayKeys::from_master(MASTER).unwrap();
        let mut writer = OverlayWriter::new(
            OverlayKeys::from_master(MASTER).unwrap(),
            OfflineNodeClient::new(),
        );
        let pos = Position::new(vec![3]);
        let opts = WritingOptions {
            obfuscate: false,
            funding_value: 1000,
        };
        let node = writer
            .write_node(&pos, b"app payload", &opts, funding())
            .unwrap();
        let app_key = keys.third_key(&pos).unwrap();
        let tag = TagApp.apply(&node, &app_key).unwrap();
        assert!(tag.starts_with(node.txid_display.as_bytes()));
        // deterministic and bound to the node.
        assert_eq!(TagApp.apply(&node, &app_key).unwrap(), tag);
    }

    // TST-OVL-053: both topologies — the receiver re-derives the same writing key from
    // a signalled position + first seed whether on the same or separate equipment (the
    // receiver shares no state beyond the position and the seed).
    #[test]
    fn tst_ovl_053_topologies() {
        let seeds = Seeds::from_master(MASTER).unwrap();
        let keys = OverlayKeys::from_master(MASTER).unwrap();
        let pos = Position::new(vec![6, 1]);
        let signalled = signal_position(&pos);
        // "separate equipment": only the signalled position + first seed are available.
        let separate = resolve_key(&signalled, seeds.first().expose()).unwrap();
        // "same equipment": the writer derives directly.
        let same = keys.writing_key(&pos).unwrap();
        assert_eq!(separate.private_key_bytes(), same.private_key_bytes());
    }

    // TST-OVL-054: commissioning — a second party holding only the FIRST seed writes
    // nodes (authorised) but cannot de-obfuscate; the first party can.
    #[test]
    fn tst_ovl_054_commissioning() {
        use secmem::SecretBytes;
        let first_party = OverlayKeys::from_master(MASTER).unwrap();
        let pos = Position::new(vec![5]);
        let real_second = first_party.second_key(&pos).unwrap();
        let obf = obfuscate(&real_second, b"commissioned secret").unwrap();

        // second party: the real first seed, but garbage second/third seeds.
        let seeds = Seeds::from_master(MASTER).unwrap();
        let second_party = OverlayKeys::from_seeds(Seeds::from_parts(
            SecretBytes::from_slice(seeds.first().expose()),
            SecretBytes::from_slice(&[0xAAu8; 32]),
            SecretBytes::from_slice(&[0xBBu8; 32]),
        ));
        let mut writer = OverlayWriter::new(second_party, OfflineNodeClient::new());
        let mut blob = obf.nonce.to_vec();
        blob.extend_from_slice(&obf.bytes);
        let node = writer
            .write_node(
                &pos,
                &blob,
                &WritingOptions {
                    obfuscate: false,
                    funding_value: 1000,
                },
                funding(),
            )
            .unwrap();
        // the commissioned writing key authorised the write...
        assert!(verify_authorisation(&node, 1000).unwrap());
        // ...but the second party cannot de-obfuscate (its second key is garbage).
        let garbage_second = writer.keys().second_key(&pos).unwrap();
        assert!(deobfuscate(&garbage_second, &obf).is_err());
        // the first party can.
        assert_eq!(
            deobfuscate(&real_second, &obf).unwrap().expose(),
            b"commissioned secret"
        );
    }

    // TST-OVL-060: the tree case — a tree-shaped overlay writes and verifies each node.
    #[test]
    fn tst_ovl_060_tree() {
        let mut graph = OverlayGraph::new(OverlayNetwork::Metanet, bounds());
        let mut writer = OverlayWriter::new(
            OverlayKeys::from_master(MASTER).unwrap(),
            OfflineNodeClient::new(),
        );
        let root = graph.root();
        let a = graph.add_node(root, 0).unwrap();
        let b = graph.add_node(root, 1).unwrap();
        let a0 = graph.add_node(a, 0).unwrap();
        for id in [root, a, b, a0] {
            let position = graph.position_of(id).unwrap();
            let node = writer
                .write_node(
                    &position,
                    b"tree node",
                    &WritingOptions {
                        obfuscate: false,
                        funding_value: 500,
                    },
                    funding(),
                )
                .unwrap();
            assert!(verify_authorisation(&node, 500).unwrap());
        }
        graph.keygraph().verify_invariants().unwrap();
    }
}
