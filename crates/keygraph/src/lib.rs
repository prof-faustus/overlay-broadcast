#![forbid(unsafe_code)]
//! `keygraph`: a generic, bounded key graph (REQ-KGR-001..012). Nodes are bound to a
//! position and carry a key epoch; each non-root node has exactly one parent edge
//! (child→parent for GB encryption, child-of for EP); nodes are arranged in layers
//! (root = layer 0, increasing toward the leaves). Depth, breadth, and total node
//! count are bounded by validated configuration; structural invariants are guaranteed
//! by construction and checkable. No cryptography lives here — the overlay (EP) and
//! broadcast (GB) crates map positions and edges onto keys.

mod error;
mod graph;

pub use error::KgError;
pub use graph::{Bounds, KeyGraph, NodeId};

#[cfg(test)]
#[allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::panic,
    clippy::indexing_slicing
)]
mod tests {
    use super::*;

    fn bounds() -> Bounds {
        Bounds {
            max_depth: 8,
            max_breadth: 8,
            max_nodes: 1024,
        }
    }

    // TST-KGR-001: build a graph; structure is queryable; positions are assigned.
    #[test]
    fn tst_kgr_001_build_and_query() {
        let mut g = KeyGraph::with_root(bounds());
        let root = g.root();
        let a = g.add_child(root, 0).unwrap();
        let b = g.add_child(root, 1).unwrap();
        let a0 = g.add_child(a, 0).unwrap();
        assert_eq!(g.node_count(), 4);
        assert_eq!(g.depth(), 2);
        assert_eq!(g.position(a0).unwrap(), &[0, 0]);
        assert_eq!(g.position(b).unwrap(), &[1]);
        assert_eq!(g.layers().len(), 3); // root, inner, leaf
        g.verify_invariants().unwrap();
    }

    // TST-KGR-002: depth, breadth, and node-count bounds are enforced.
    #[test]
    fn tst_kgr_002_bounds_enforced() {
        let mut g = KeyGraph::with_root(Bounds {
            max_depth: 1,
            max_breadth: 2,
            max_nodes: 10,
        });
        let root = g.root();
        let a = g.add_child(root, 0).unwrap();
        let _b = g.add_child(root, 1).unwrap();
        // breadth: a third child of root exceeds max_breadth.
        assert!(matches!(g.add_child(root, 2), Err(KgError::BoundExceeded)));
        // depth: a child of `a` would be layer 2 > max_depth 1.
        assert!(matches!(g.add_child(a, 0), Err(KgError::BoundExceeded)));
    }

    // TST-KGR-011: leaf_to_root and reachable_set; a removed leaf no longer reaches root.
    #[test]
    fn tst_kgr_011_traversal_and_removal() {
        let mut g = KeyGraph::with_root(bounds());
        let root = g.root();
        let a = g.add_child(root, 0).unwrap();
        let leaf = g.add_child(a, 0).unwrap();
        assert_eq!(g.leaf_to_root(leaf).unwrap(), vec![leaf, a, root]);
        assert!(g.reachable_set(leaf).unwrap().contains(&root));
        // remove the leaf; it is gone and `a` still reaches root.
        g.remove_subtree(leaf).unwrap();
        assert!(g.position(leaf).is_none());
        assert_eq!(g.leaf_to_root(a).unwrap(), vec![a, root]);
        g.verify_invariants().unwrap();
    }

    // TST-KGR-010: GB-style update — grow, shrink, replace root; invariants hold.
    #[test]
    fn tst_kgr_010_update() {
        let mut g = KeyGraph::with_root(bounds());
        let root = g.root();
        let inner = g.add_child(root, 0).unwrap();
        let l1 = g.add_child(inner, 0).unwrap();
        let _l2 = g.add_child(inner, 1).unwrap();
        let epoch0 = g.root_epoch();
        assert_eq!(g.replace_root().unwrap(), epoch0 + 1);
        // remove an inner node (and its subtree); root remains the single root.
        g.remove_subtree(inner).unwrap();
        assert!(g.position(l1).is_none());
        assert_eq!(g.node_count(), 1);
        g.verify_invariants().unwrap();
        // the root cannot be removed.
        assert!(matches!(
            g.remove_subtree(root),
            Err(KgError::CannotRemoveRoot)
        ));
    }

    // TST-KGR-012: structural invariants — one root, single parent edge, consistent
    // parent/child links.
    #[test]
    fn tst_kgr_012_invariants() {
        let mut g = KeyGraph::with_root(bounds());
        let root = g.root();
        let a = g.add_child(root, 0).unwrap();
        let _aa = g.add_child(a, 0).unwrap();
        g.verify_invariants().unwrap();
        // every non-root has exactly one parent; the root has none.
        assert!(g.parent(root).is_none());
        assert_eq!(g.parent(a), Some(root));
    }
}
