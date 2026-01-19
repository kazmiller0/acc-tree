use accumulator_ads::{DynamicAccumulator, DigestSet, G1Affine, Set};
use std::rc::Rc;

use crate::crypto::{Hash, empty_acc, empty_hash, leaf_hash, nonleaf_hash};

#[derive(Debug, Clone)]
pub enum Node {
    Leaf {
        key: String,
        fid: String,
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
                key, fid, deleted, ..
            } => {
                if *deleted {
                    // tombstoned leaf contributes an empty hash
                    empty_hash()
                } else {
                    leaf_hash(key, fid)
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
                    DynamicAccumulator::calculate_commitment(&DigestSet::new(&Set::from_vec(vec![key.clone()])))
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
    ) -> std::vec::IntoIter<(String, String)> {
        let mut v: Vec<(String, String)> = Vec::new();
        match self {
            Node::Leaf {
                key, fid, deleted, ..
            } => {
                if *deleted {
                    return v.into_iter();
                }
                if let Some(ex) = exclude_key
                    && ex == key.as_str()
                {
                    return v.into_iter();
                }
                v.push((key.clone(), fid.clone()));
            }
            Node::NonLeaf { left, right, .. } => {
                v.extend(left.collect_leaves(exclude_key));
                v.extend(right.collect_leaves(exclude_key));
            }
        }
        v.into_iter()
    }

    /* ---------------- Internal recursive operations ---------------- */

    /// Get value for target_key recursively
    pub(crate) fn get_recursive(&self, target_key: &str) -> Option<String> {
        match self {
            Node::Leaf {
                key, fid, deleted, ..
            } => {
                if key == target_key && !*deleted {
                    Some(fid.clone())
                } else {
                    None
                }
            }
            Node::NonLeaf { left, right, .. } => {
                if left.has_key(target_key) {
                    left.get_recursive(target_key)
                } else {
                    right.get_recursive(target_key)
                }
            }
        }
    }

    /// Build a path-proof for `target_key` within this node.
    /// `path` is populated with sibling hashes on unwind; each entry is (sibling_hash, sibling_is_left).
    pub(crate) fn get_proof_recursive(
        &self,
        target_key: &str,
        path: &mut Vec<(Hash, bool)>,
    ) -> Option<String> {
        match self {
            Node::Leaf {
                key, fid, deleted, ..
            } => {
                if key == target_key && !*deleted {
                    Some(fid.clone())
                } else {
                    None
                }
            }
            Node::NonLeaf { left, right, .. } => {
                if left.has_key(target_key) {
                    if let Some(fid) = left.get_proof_recursive(target_key, path) {
                        // sibling is right child
                        path.push((right.hash(), false));
                        return Some(fid);
                    }
                    None
                } else if right.has_key(target_key) {
                    if let Some(fid) = right.get_proof_recursive(target_key, path) {
                        // sibling is left child
                        path.push((left.hash(), true));
                        return Some(fid);
                    }
                    None
                } else {
                    None
                }
            }
        }
    }

    /// Build a proof for `target_key` including leaves that may be tombstoned.
    /// This searches the tree for a leaf with matching key regardless of tombstone
    /// and records sibling hashes on unwind.
    pub(crate) fn get_proof_including_deleted(
        &self,
        target_key: &str,
        path: &mut Vec<(Hash, bool)>,
    ) -> Option<String> {
        match self {
            Node::Leaf { key, fid, .. } => {
                if key == target_key {
                    Some(fid.clone())
                } else {
                    None
                }
            }
            Node::NonLeaf { left, right, .. } => {
                if let Some(fid) = left.get_proof_including_deleted(target_key, path) {
                    // sibling is right child
                    path.push((right.hash(), false));
                    return Some(fid);
                }
                if let Some(fid) = right.get_proof_including_deleted(target_key, path) {
                    // sibling is left child
                    path.push((left.hash(), true));
                    return Some(fid);
                }
                None
            }
        }
    }

    /// Find predecessor (max key < target) and successor (min key > target) within this node.
    /// Returns (found_exact, pred_opt, succ_opt)
    pub(crate) fn find_pred_succ(
        &self,
        target: &str,
    ) -> (bool, Option<(String, String)>, Option<(String, String)>) {
        match self {
            Node::Leaf {
                key, fid, deleted, ..
            } => {
                if *deleted {
                    return (false, None, None);
                }
                if key == target {
                    return (true, None, None);
                }
                if key.as_str() < target {
                    (false, Some((key.clone(), fid.clone())), None)
                } else {
                    (false, None, Some((key.clone(), fid.clone())))
                }
            }
            Node::NonLeaf { left, right, .. } => {
                // search left and right subtrees and merge results
                let (found_l, pred_l, succ_l) = left.find_pred_succ(target);
                if found_l {
                    return (true, None, None);
                }
                let (found_r, pred_r, succ_r) = right.find_pred_succ(target);
                if found_r {
                    return (true, None, None);
                }

                // merge preds: prefer the larger key
                let pred = match (pred_l, pred_r) {
                    (None, None) => None,
                    (Some(p), None) => Some(p),
                    (None, Some(p)) => Some(p),
                    (Some(p1), Some(p2)) => {
                        if p1.0 > p2.0 {
                            Some(p1)
                        } else {
                            Some(p2)
                        }
                    }
                };

                // merge succs: prefer the smaller key
                let succ = match (succ_l, succ_r) {
                    (None, None) => None,
                    (Some(s), None) => Some(s),
                    (None, Some(s)) => Some(s),
                    (Some(s1), Some(s2)) => {
                        if s1.0 < s2.0 {
                            Some(s1)
                        } else {
                            Some(s2)
                        }
                    }
                };

                (false, pred, succ)
            }
        }
    }

    /// Update fid for target_key recursively. Returns whether hash changed.
    pub(crate) fn update_recursive(&mut self, target_key: &str, new_fid: &str) -> bool {
        match self {
            Node::Leaf {
                fid, key, deleted, ..
            } => {
                if key == target_key && !*deleted {
                    *fid = new_fid.to_string();
                    true // hash changed
                } else {
                    false
                }
            }
            Node::NonLeaf {
                hash,
                left,
                right,
                keys,
                acc,
                ..
            } => {
                // locate branch using `has_key` only (leaf obeys tombstone)
                let changed = if left.has_key(target_key) {
                    left.update_recursive(target_key, new_fid)
                } else {
                    right.update_recursive(target_key, new_fid)
                };
                if changed {
                    // recompute keys/acc/hash from children
                    let new_keys = Rc::new(left.keys().union(&right.keys()));
                    *keys = new_keys.clone();
                    *acc = DynamicAccumulator::calculate_commitment(&DigestSet::new(&new_keys));
                    *hash = nonleaf_hash(left.hash(), right.hash());
                }
                changed
            }
        }
    }

    /// Mark leaf with target_key as deleted (tombstone). Returns new node.
    pub(crate) fn delete_recursive(self: Box<Self>, target_key: &str) -> Box<Node> {
        match *self {
            Node::Leaf {
                key,
                fid,
                level,
                deleted,
            } => {
                if key == target_key && !deleted {
                    // mark tombstone
                    Box::new(Node::Leaf {
                        key,
                        fid,
                        level,
                        deleted: true,
                    })
                } else {
                    // preserve leaf state
                    Box::new(Node::Leaf {
                        key,
                        fid,
                        level,
                        deleted,
                    })
                }
            }
            Node::NonLeaf {
                level, left, right, ..
            } => {
                let l = left.delete_recursive(target_key);
                let r = right.delete_recursive(target_key);
                let new_keys = Rc::new(l.keys().union(&r.keys()));
                let new_acc = DynamicAccumulator::calculate_commitment(&DigestSet::new(&new_keys));
                let new_hash = nonleaf_hash(l.hash(), r.hash());
                Box::new(Node::NonLeaf {
                    hash: new_hash,
                    keys: new_keys,
                    acc: new_acc,
                    level,
                    left: l,
                    right: r,
                })
            }
        }
    }

    /// Revive a tombstoned leaf with target_key. Returns new node.
    pub(crate) fn revive_recursive(self: Box<Self>, target_key: &str, new_fid: &str) -> Box<Node> {
        match *self {
            Node::Leaf {
                key,
                fid,
                level,
                deleted,
            } => {
                if key == target_key && deleted {
                    Box::new(Node::Leaf {
                        key,
                        fid: new_fid.to_string(),
                        level,
                        deleted: false,
                    })
                } else {
                    // preserve as-is
                    Box::new(Node::Leaf {
                        key,
                        fid,
                        level,
                        deleted,
                    })
                }
            }
            Node::NonLeaf {
                level, left, right, ..
            } => {
                let l = left.revive_recursive(target_key, new_fid);
                let r = right.revive_recursive(target_key, new_fid);
                let new_keys = Rc::new(l.keys().union(&r.keys()));
                let new_acc = DynamicAccumulator::calculate_commitment(&DigestSet::new(&new_keys));
                let new_hash = nonleaf_hash(l.hash(), r.hash());
                Box::new(Node::NonLeaf {
                    hash: new_hash,
                    keys: new_keys,
                    acc: new_acc,
                    level,
                    left: l,
                    right: r,
                })
            }
        }
    }

    /// Merge two nodes into a new NonLeaf node
    pub(crate) fn merge(left: Box<Node>, right: Box<Node>) -> Box<Node> {
        let new_keys = Rc::new(left.keys().union(&right.keys()));
        let new_acc = DynamicAccumulator::calculate_commitment(&DigestSet::new(&new_keys));
        Box::new(Node::NonLeaf {
            hash: nonleaf_hash(left.hash(), right.hash()),
            keys: new_keys,
            acc: new_acc,
            level: right.level() + 1,
            left,
            right,
        })
    }
}
