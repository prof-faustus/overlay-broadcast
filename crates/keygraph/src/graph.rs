//! The bounded key graph (REQ-KGR-001..012).
use crate::error::KgError;
use std::collections::HashMap;

/// A node identifier, stable for the node's lifetime.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodeId(u64);

/// Validated structural bounds (REQ-KGR-002).
#[derive(Clone, Copy, Debug)]
pub struct Bounds {
    /// Maximum layer index (root is layer 0).
    pub max_depth: usize,
    /// Maximum number of children per node.
    pub max_breadth: usize,
    /// Maximum total node count.
    pub max_nodes: usize,
}

#[derive(Clone, Debug)]
struct Node {
    position: Vec<u32>,
    layer: usize,
    parent: Option<NodeId>,
    children: Vec<NodeId>,
    key_epoch: u64,
}

/// A bounded key graph with a single root and one parent edge per non-root node.
#[derive(Clone, Debug)]
pub struct KeyGraph {
    nodes: HashMap<NodeId, Node>,
    root: NodeId,
    next_id: u64,
    bounds: Bounds,
}

impl KeyGraph {
    /// Create a graph with a single root node at the empty position.
    #[must_use]
    pub fn with_root(bounds: Bounds) -> Self {
        let root = NodeId(0);
        let mut nodes = HashMap::new();
        nodes.insert(
            root,
            Node {
                position: Vec::new(),
                layer: 0,
                parent: None,
                children: Vec::new(),
                key_epoch: 0,
            },
        );
        Self {
            nodes,
            root,
            next_id: 1,
            bounds,
        }
    }

    /// The root node id.
    #[must_use]
    pub fn root(&self) -> NodeId {
        self.root
    }

    /// The total node count.
    #[must_use]
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// The maximum layer index present (the depth).
    #[must_use]
    pub fn depth(&self) -> usize {
        self.nodes.values().map(|n| n.layer).max().unwrap_or(0)
    }

    /// The position coordinates of a node, if it exists.
    #[must_use]
    pub fn position(&self, id: NodeId) -> Option<&[u32]> {
        self.nodes.get(&id).map(|n| n.position.as_slice())
    }

    /// The parent of a node (None for the root or a missing node).
    #[must_use]
    pub fn parent(&self, id: NodeId) -> Option<NodeId> {
        self.nodes.get(&id).and_then(|n| n.parent)
    }

    /// The current key epoch of the root (incremented by `replace_root`).
    #[must_use]
    pub fn root_epoch(&self) -> u64 {
        self.nodes.get(&self.root).map_or(0, |n| n.key_epoch)
    }

    /// Add a child node under `parent_id` at child coordinate `coord` (REQ-KGR-001/002).
    ///
    /// # Errors
    /// [`KgError::NoSuchNode`] / [`KgError::BoundExceeded`].
    pub fn add_child(&mut self, parent_id: NodeId, coord: u32) -> Result<NodeId, KgError> {
        let (layer, child_count, mut position) = {
            let parent = self.nodes.get(&parent_id).ok_or(KgError::NoSuchNode)?;
            let layer = parent.layer.checked_add(1).ok_or(KgError::BoundExceeded)?;
            (layer, parent.children.len(), parent.position.clone())
        };
        if layer > self.bounds.max_depth
            || child_count >= self.bounds.max_breadth
            || self.nodes.len() >= self.bounds.max_nodes
        {
            return Err(KgError::BoundExceeded);
        }
        position.push(coord);
        let id = NodeId(self.next_id);
        self.next_id = self.next_id.checked_add(1).ok_or(KgError::BoundExceeded)?;
        self.nodes.insert(
            id,
            Node {
                position,
                layer,
                parent: Some(parent_id),
                children: Vec::new(),
                key_epoch: 0,
            },
        );
        if let Some(parent) = self.nodes.get_mut(&parent_id) {
            parent.children.push(id);
        }
        Ok(id)
    }

    /// Rotate the root key (a new message-encryption-key root, GB cl.2/16).
    ///
    /// # Errors
    /// [`KgError::NoSuchNode`] / [`KgError::BoundExceeded`].
    pub fn replace_root(&mut self) -> Result<u64, KgError> {
        let root = self.nodes.get_mut(&self.root).ok_or(KgError::NoSuchNode)?;
        root.key_epoch = root
            .key_epoch
            .checked_add(1)
            .ok_or(KgError::BoundExceeded)?;
        Ok(root.key_epoch)
    }

    /// Remove a node and its whole subtree (consistent re-layering; REQ-KGR-010).
    ///
    /// # Errors
    /// [`KgError::CannotRemoveRoot`] / [`KgError::NoSuchNode`].
    pub fn remove_subtree(&mut self, id: NodeId) -> Result<(), KgError> {
        if id == self.root {
            return Err(KgError::CannotRemoveRoot);
        }
        if !self.nodes.contains_key(&id) {
            return Err(KgError::NoSuchNode);
        }
        let parent = self.nodes.get(&id).and_then(|n| n.parent);
        if let Some(parent_id) = parent {
            if let Some(parent_node) = self.nodes.get_mut(&parent_id) {
                parent_node.children.retain(|c| *c != id);
            }
        }
        let mut stack = vec![id];
        let mut guard = 0usize;
        while let Some(current) = stack.pop() {
            guard = guard.checked_add(1).ok_or(KgError::BoundExceeded)?;
            if guard
                > self
                    .bounds
                    .max_nodes
                    .checked_add(1)
                    .ok_or(KgError::BoundExceeded)?
            {
                return Err(KgError::Cycle);
            }
            if let Some(node) = self.nodes.remove(&current) {
                stack.extend(node.children);
            }
        }
        Ok(())
    }

    /// The ordered path from a node up to the root (REQ-KGR-011).
    ///
    /// # Errors
    /// [`KgError::NoSuchNode`] / [`KgError::Cycle`].
    pub fn leaf_to_root(&self, id: NodeId) -> Result<Vec<NodeId>, KgError> {
        let max_steps = self
            .bounds
            .max_depth
            .checked_add(2)
            .ok_or(KgError::BoundExceeded)?;
        let mut path = Vec::new();
        let mut current = Some(id);
        while let Some(node_id) = current {
            if path.len() > max_steps {
                return Err(KgError::Cycle);
            }
            let node = self.nodes.get(&node_id).ok_or(KgError::NoSuchNode)?;
            path.push(node_id);
            current = node.parent;
        }
        Ok(path)
    }

    /// The set of nodes a holder at `id` can derive/decrypt toward (its ancestors,
    /// including itself and the root). REQ-KGR-011.
    ///
    /// # Errors
    /// As [`KeyGraph::leaf_to_root`].
    pub fn reachable_set(&self, id: NodeId) -> Result<Vec<NodeId>, KgError> {
        self.leaf_to_root(id)
    }

    /// Nodes grouped by layer (index 0 = root layer).
    #[must_use]
    pub fn layers(&self) -> Vec<Vec<NodeId>> {
        let mut layers: Vec<Vec<NodeId>> = Vec::new();
        for (id, node) in &self.nodes {
            if layers.len() <= node.layer {
                layers.resize(node.layer.saturating_add(1), Vec::new());
            }
            if let Some(layer) = layers.get_mut(node.layer) {
                layer.push(*id);
            }
        }
        layers
    }

    /// Verify the structural invariants (REQ-KGR-012): exactly one root, every
    /// non-root has exactly one existing parent that lists it as a child.
    ///
    /// # Errors
    /// [`KgError::Invariant`].
    pub fn verify_invariants(&self) -> Result<(), KgError> {
        let mut roots = 0usize;
        for (id, node) in &self.nodes {
            match node.parent {
                None => {
                    roots = roots.checked_add(1).ok_or(KgError::Invariant)?;
                    if *id != self.root {
                        return Err(KgError::Invariant);
                    }
                }
                Some(parent_id) => {
                    let parent = self.nodes.get(&parent_id).ok_or(KgError::Invariant)?;
                    if !parent.children.contains(id) {
                        return Err(KgError::Invariant);
                    }
                }
            }
        }
        if roots == 1 {
            Ok(())
        } else {
            Err(KgError::Invariant)
        }
    }
}
