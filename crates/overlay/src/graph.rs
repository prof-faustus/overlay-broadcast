//! The overlay graph: a key graph whose nodes correspond to data-storage
//! transactions and whose edges are overlay-layer links between them (REQ-OVL-001).
//! Generic over any overlay network; Metanet is the reference instantiation
//! (REQ-OVL-002).
use crate::error::OverlayError;
use ckd::Position;
use keygraph::{Bounds, KeyGraph, NodeId};

/// The overlay network an overlay graph instantiates.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OverlayNetwork {
    /// The Metanet reference instantiation (EP para 0013).
    Metanet,
    /// Any other overlay network meeting REQ-OVL-001, named.
    Generic(String),
}

/// An overlay graph over data-storage transactions. The graph structure equals the
/// key-set structure (the first/second/third keys share this shape).
#[derive(Debug)]
pub struct OverlayGraph {
    graph: KeyGraph,
    network: OverlayNetwork,
}

impl OverlayGraph {
    /// Create an overlay graph for `network` with the given structural bounds.
    #[must_use]
    pub fn new(network: OverlayNetwork, bounds: Bounds) -> Self {
        Self {
            graph: KeyGraph::with_root(bounds),
            network,
        }
    }

    /// The instantiated overlay network.
    #[must_use]
    pub fn network(&self) -> &OverlayNetwork {
        &self.network
    }

    /// The root node (the genesis data-storage transaction's node).
    #[must_use]
    pub fn root(&self) -> NodeId {
        self.graph.root()
    }

    /// Add a child node (a child data-storage transaction) under `parent`.
    ///
    /// # Errors
    /// [`OverlayError::Graph`] on a bound breach or missing parent.
    pub fn add_node(&mut self, parent: NodeId, coord: u32) -> Result<NodeId, OverlayError> {
        Ok(self.graph.add_child(parent, coord)?)
    }

    /// The position of a node (its coordinates from the root).
    ///
    /// # Errors
    /// [`OverlayError::UnknownPosition`] if the node does not exist.
    pub fn position_of(&self, id: NodeId) -> Result<Position, OverlayError> {
        self.graph
            .position(id)
            .map(|coords| Position::new(coords.to_vec()))
            .ok_or(OverlayError::UnknownPosition)
    }

    /// The underlying key graph (for traversal and invariants).
    #[must_use]
    pub fn keygraph(&self) -> &KeyGraph {
        &self.graph
    }
}
