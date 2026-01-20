use accumulator_ads::{digest_set_from_set, DynamicAccumulator, G1Affine, Set};
use std::rc::Rc;

use crate::crypto::{Hash, empty_acc, empty_hash, leaf_hash};

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
}
