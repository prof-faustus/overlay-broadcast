//! Property tests for the key graph (REQ-KGR-003/011/012): over randomly-grown
//! graphs, every node reaches the root by a deterministic path and all structural
//! invariants hold.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]

use keygraph::{Bounds, KeyGraph};
use proptest::prelude::*;

proptest! {
    // TST-KGR-003 / TST-KGR-011 / TST-KGR-012.
    #[test]
    fn every_node_reaches_root_with_stable_path(
        ops in proptest::collection::vec((0usize..64, 0u32..8), 0..80)
    ) {
        let mut graph = KeyGraph::with_root(Bounds { max_depth: 10, max_breadth: 6, max_nodes: 500 });
        let mut nodes = vec![graph.root()];
        for (target, coord) in ops {
            let parent = nodes[target % nodes.len()];
            if let Ok(child) = graph.add_child(parent, coord) {
                nodes.push(child);
            }
        }
        prop_assert!(graph.verify_invariants().is_ok());
        let root = graph.root();
        for node in &nodes {
            let path = graph.leaf_to_root(*node).unwrap();
            prop_assert_eq!(path.last().copied(), Some(root), "path must end at the root");
            prop_assert!(path.contains(&root));
            // the path is deterministic (stable position addressing).
            prop_assert_eq!(graph.leaf_to_root(*node).unwrap(), path);
        }
    }
}
