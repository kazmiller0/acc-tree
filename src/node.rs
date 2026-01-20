use accumulator_ads::{DynamicAccumulator, G1Affine, Set, digest_set_from_set};
use std::rc::Rc;

use crate::crypto::{Hash, empty_acc, empty_hash, leaf_hash_fids, nonleaf_hash};

#[derive(Debug, Clone)]
pub enum Node {
    Leaf {
        key: String,
        fids: Set<String>,
        level: usize,
        deleted: bool,
    },
    NonLeaf {
        hash: Hash,
        keys: Rc<Set<String>>,
        acc: G1Affine,
        level: usize,
        left: Box<Node>,
        right: Box<Node>,
    },
}

impl Node {
    pub fn level(&self) -> usize {
        match self {
            Node::Leaf { level, .. } => *level,
            Node::NonLeaf { level, .. } => *level,
        }
    }

    pub fn hash(&self) -> Hash {
        match self {
            Node::Leaf {
                key, fids, deleted, ..
            } => {
                if *deleted {
                    // tombstoned leaf contributes an empty hash
                    empty_hash()
                } else {
                    leaf_hash_fids(key, fids)
                }
            }
            Node::NonLeaf { hash, .. } => *hash,
        }
    }

    pub fn acc(&self) -> G1Affine {
        match self {
            Node::Leaf { key, deleted, .. } => {
                if *deleted {
                    // empty set accumulator
                    empty_acc()
                } else {
                    let digest_set = digest_set_from_set(&Set::from_vec(vec![key.clone()]));
                    DynamicAccumulator::calculate_commitment(&digest_set)
                }
            }
            Node::NonLeaf { acc, .. } => *acc,
        }
    }

    pub fn keys(&self) -> Set<String> {
        match self {
            Node::Leaf { key, deleted, .. } => {
                if *deleted {
                    Set::new()
                } else {
                    Set::from_vec(vec![key.clone()])
                }
            }
            Node::NonLeaf { keys, .. } => keys.as_ref().clone(),
        }
    }

    pub fn has_key(&self, target_key: &str) -> bool {
        match self {
            Node::Leaf { key, deleted, .. } => !*deleted && key == target_key,
            Node::NonLeaf { keys, .. } => keys.contains(&target_key.to_string()),
        }
    }

    pub fn collect_leaves(
        &self,
        exclude_key: Option<&str>,
    ) -> std::vec::IntoIter<(String, Set<String>)> {
        let mut v: Vec<(String, Set<String>)> = Vec::new();
        match self {
            Node::Leaf {
                key, fids, deleted, ..
            } => {
                if *deleted {
                    return v.into_iter();
                }
                if let Some(ex) = exclude_key
                    && ex == key.as_str()
                {
                    return v.into_iter();
                }
                v.push((key.clone(), fids.clone()));
            }
            Node::NonLeaf { left, right, .. } => {
                v.extend(left.collect_leaves(exclude_key));
                v.extend(right.collect_leaves(exclude_key));
            }
        }
        v.into_iter()
    }

    // ==========================================
    // Query operations
    // ==========================================

    /// Get document ID set for target_key recursively (inverted index semantics)
    pub fn select(&self, target_key: &str) -> Option<Set<String>> {
        match self {
            Node::Leaf {
                key, fids, deleted, ..
            } => {
                if key == target_key && !*deleted {
                    Some(fids.clone())
                } else {
                    None
                }
            }
            Node::NonLeaf { left, right, .. } => {
                if left.has_key(target_key) {
                    left.select(target_key)
                } else {
                    right.select(target_key)
                }
            }
        }
    }

    /// Build a path-proof for `target_key` within this node (internal recursive implementation).
    /// `path` is populated with sibling hashes on unwind; each entry is (sibling_hash, sibling_is_left).
    pub fn recurse_select_with_proof(
        &self,
        target_key: &str,
        path: &mut Vec<(Hash, bool)>,
    ) -> Option<Set<String>> {
        match self {
            Node::Leaf {
                key, fids, deleted, ..
            } => {
                if key == target_key && !*deleted {
                    Some(fids.clone())
                } else {
                    None
                }
            }
            Node::NonLeaf { left, right, .. } => {
                if left.has_key(target_key) {
                    if let Some(fids) = left.recurse_select_with_proof(target_key, path) {
                        path.push((right.hash(), false));
                        return Some(fids);
                    }
                    None
                } else if right.has_key(target_key) {
                    if let Some(fids) = right.recurse_select_with_proof(target_key, path) {
                        path.push((left.hash(), true));
                        return Some(fids);
                    }
                    None
                } else {
                    None
                }
            }
        }
    }

    /// Build a proof for `target_key` including leaves that may be tombstoned (internal recursive implementation).
    pub fn recurse_select_proof_including_deleted(
        &self,
        target_key: &str,
        path: &mut Vec<(Hash, bool)>,
    ) -> Option<Set<String>> {
        match self {
            Node::Leaf { key, fids, .. } => {
                if key == target_key {
                    Some(fids.clone())
                } else {
                    None
                }
            }
            Node::NonLeaf { left, right, .. } => {
                if let Some(fids) = left.recurse_select_proof_including_deleted(target_key, path) {
                    path.push((right.hash(), false));
                    return Some(fids);
                }
                if let Some(fids) = right.recurse_select_proof_including_deleted(target_key, path) {
                    path.push((left.hash(), true));
                    return Some(fids);
                }
                None
            }
        }
    }

    // ==========================================
    // Mutation operations
    // ==========================================

    /// Insert a document ID to the fids set for target_key. Returns whether hash changed.
    pub fn insert_fid(&mut self, target_key: &str, fid: String) -> bool {
        match self {
            Node::Leaf {
                fids, key, deleted, ..
            } => {
                if key == target_key && !*deleted {
                    let before_len = fids.len();
                    *fids = fids.union(&Set::from_vec(vec![fid]));
                    fids.len() != before_len
                } else {
                    false
                }
            }
            Node::NonLeaf {
                hash, left, right, ..
            } => {
                let changed = if left.has_key(target_key) {
                    left.insert_fid(target_key, fid)
                } else {
                    right.insert_fid(target_key, fid)
                };
                if changed {
                    *hash = nonleaf_hash(left.hash(), right.hash());
                }
                changed
            }
        }
    }

    /// Delete a document ID from the fids set for target_key. Returns whether hash changed.
    /// If fids becomes empty, the leaf is tombstoned (deleted=true).
    pub fn delete_fid(&mut self, target_key: &str, fid: &str) -> bool {
        match self {
            Node::Leaf {
                fids, key, deleted, ..
            } => {
                if key == target_key && !*deleted {
                    let before_len = fids.len();
                    *fids = fids.difference(&Set::from_vec(vec![fid.to_string()]));
                    if fids.is_empty() {
                        *deleted = true;
                    }
                    fids.len() != before_len || *deleted
                } else {
                    false
                }
            }
            Node::NonLeaf {
                hash, left, right, ..
            } => {
                let changed = if left.has_key(target_key) {
                    left.delete_fid(target_key, fid)
                } else {
                    right.delete_fid(target_key, fid)
                };
                if changed {
                    *hash = nonleaf_hash(left.hash(), right.hash());
                }
                changed
            }
        }
    }

    /// Update a document ID: replace old_fid with new_fid in the fids set for target_key.
    /// Returns whether hash changed.
    pub fn update_fid(&mut self, target_key: &str, old_fid: &str, new_fid: String) -> bool {
        match self {
            Node::Leaf {
                fids, key, deleted, ..
            } => {
                if key == target_key && !*deleted {
                    // Check if old_fid exists
                    if !fids.contains(&old_fid.to_string()) {
                        return false;
                    }
                    // Remove old_fid and add new_fid
                    *fids = fids.difference(&Set::from_vec(vec![old_fid.to_string()]));
                    *fids = fids.union(&Set::from_vec(vec![new_fid]));
                    true
                } else {
                    false
                }
            }
            Node::NonLeaf {
                hash, left, right, ..
            } => {
                let changed = if left.has_key(target_key) {
                    left.update_fid(target_key, old_fid, new_fid)
                } else {
                    right.update_fid(target_key, old_fid, new_fid)
                };
                if changed {
                    *hash = nonleaf_hash(left.hash(), right.hash());
                }
                changed
            }
        }
    }

    /// Revive a tombstoned leaf with target_key. Returns new node.
    /// Replaces fids with a new set containing the single fid.
    pub fn revive(self: Box<Self>, target_key: &str, new_fid: &str) -> Box<Node> {
        match *self {
            Node::Leaf {
                key,
                fids,
                level,
                deleted,
            } => {
                if key == target_key && deleted {
                    Box::new(Node::Leaf {
                        key,
                        fids: Set::from_vec(vec![new_fid.to_string()]),
                        level,
                        deleted: false,
                    })
                } else {
                    Box::new(Node::Leaf {
                        key,
                        fids,
                        level,
                        deleted,
                    })
                }
            }
            Node::NonLeaf {
                left, right, level, ..
            } => {
                let l = left.revive(target_key, new_fid);
                let r = right.revive(target_key, new_fid);
                Node::merge(l, r, Some(level))
            }
        }
    }

    /// Merge two nodes into a new NonLeaf node
    /// If level is provided, use it; otherwise compute as right.level() + 1
    pub fn merge(left: Box<Node>, right: Box<Node>, level: Option<usize>) -> Box<Node> {
        let new_keys = Rc::new(left.keys().union(&right.keys()));

        let left_acc = left.acc();

        // Optimize: Only convert the difference (right - left) to Vec<Fr>
        // Using HashSet.difference() is O(n), much faster than converting both full sets
        let diff_elements = right.keys().difference(&left.keys());
        let diff_fr = digest_set_from_set(&diff_elements);
        let new_acc = DynamicAccumulator::incremental_add_with_default_trapdoor(left_acc, &diff_fr);

        Box::new(Node::NonLeaf {
            hash: nonleaf_hash(left.hash(), right.hash()),
            keys: new_keys,
            acc: new_acc,
            level: level.unwrap_or_else(|| right.level() + 1),
            left,
            right,
        })
    }
}

/// Unit tests for Node internal behavior
///
/// These tests verify the basic properties and methods of Node.
/// They focus on individual node operations without complex tree structures.
#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Once;

    static INIT: Once = Once::new();

    fn init_test_params() {
        INIT.call_once(|| {
            use accumulator_ads::acc::setup::{PublicParameters, init_public_parameters_direct};
            use ark_bls12_381::Fr;

            let secret_s = Fr::from(123456789u128);
            let params = PublicParameters::generate_for_testing(secret_s, 10);
            init_public_parameters_direct(params).expect("Failed to initialize test parameters");
        });
    }

    /// Unit test: Verify basic node properties and methods
    #[test]
    fn test_node_basic_properties() {
        init_test_params();
        let leaf = Node::Leaf {
            key: "test".into(),
            fids: Set::from_vec(vec!["fid1".into()]),
            level: 0,
            deleted: false,
        };

        assert_eq!(leaf.level(), 0);
        assert!(leaf.has_key("test"));
        assert!(!leaf.has_key("other"));
        assert_eq!(leaf.keys().len(), 1);
    }

    /// Unit test: Verify tombstone behavior
    #[test]
    fn test_node_deleted_behavior() {
        init_test_params();
        let deleted_leaf = Node::Leaf {
            key: "deleted".into(),
            fids: Set::from_vec(vec!["fid1".into()]),
            level: 0,
            deleted: true,
        };

        assert!(!deleted_leaf.has_key("deleted"));
        assert_eq!(deleted_leaf.keys().len(), 0);
        assert_eq!(deleted_leaf.hash(), empty_hash());
        assert_eq!(deleted_leaf.acc(), empty_acc());
    }

    /// Unit test: Verify collect_leaves functionality
    #[test]
    fn test_collect_leaves() {
        init_test_params();
        let leaf1 = Box::new(Node::Leaf {
            key: "a".into(),
            fids: Set::from_vec(vec!["fa".into()]),
            level: 0,
            deleted: false,
        });
        let leaf2 = Box::new(Node::Leaf {
            key: "b".into(),
            fids: Set::from_vec(vec!["fb".into()]),
            level: 0,
            deleted: false,
        });

        let merged = Node::merge(leaf1, leaf2, None);

        let leaves: Vec<_> = merged.collect_leaves(None).collect();
        assert_eq!(leaves.len(), 2);
        assert!(
            leaves
                .iter()
                .any(|(k, fids)| k == "a" && fids.contains(&"fa".to_string()))
        );
        assert!(
            leaves
                .iter()
                .any(|(k, fids)| k == "b" && fids.contains(&"fb".to_string()))
        );

        // Test exclude functionality
        let excluded: Vec<_> = merged.collect_leaves(Some("a")).collect();
        assert_eq!(excluded.len(), 1);
        assert_eq!(excluded[0].0, "b");
        assert!(excluded[0].1.contains(&"fb".to_string()));
    }
}
