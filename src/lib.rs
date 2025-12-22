use acc::{Acc, Accumulator, G1Affine, MultiSet};
use sha2::{Digest, Sha256};
use std::rc::Rc;
use lazy_static::lazy_static;

pub type Hash = [u8; 32];

lazy_static! {
    pub static ref EMPTY_HASH: Hash = leaf_hash("", "");
    pub static ref EMPTY_ACC: G1Affine = Acc::cal_acc_g1(&MultiSet::<String>::new());
}

pub fn empty_hash() -> Hash {
    *EMPTY_HASH
}

pub fn empty_acc() -> G1Affine {
    *EMPTY_ACC
}

pub fn leaf_hash(key: &str, fid: &str) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update((key.len() as u32).to_be_bytes());
    hasher.update(key.as_bytes());
    hasher.update((fid.len() as u32).to_be_bytes());
    hasher.update(fid.as_bytes());
    hasher.finalize().into()
}

pub fn nonleaf_hash(left: Hash, right: Hash) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(&left);
    hasher.update(&right);
    hasher.finalize().into()
}

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
        keys: Rc<MultiSet<String>>,
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
                    // empty multiset accumulator
                    empty_acc()
                } else {
                    Acc::cal_acc_g1(&MultiSet::from_vec(vec![key.clone()]))
                }
            }
            Node::NonLeaf { acc, .. } => *acc,
        }
    }

    pub fn keys(&self) -> MultiSet<String> {
        match self {
            Node::Leaf { key, deleted, .. } => {
                if *deleted {
                    MultiSet::new()
                } else {
                    MultiSet::from_vec(vec![key.clone()])
                }
            }
            Node::NonLeaf { keys, .. } => keys.as_ref().clone(),
        }
    }

    pub fn has_key(&self, target_key: &str) -> bool {
        match self {
            Node::Leaf { key, deleted, .. } => !*deleted && key == target_key,
            Node::NonLeaf { keys, .. } => keys.contains_key(target_key),
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
                if let Some(ex) = exclude_key {
                    if ex == key.as_str() {
                        return v.into_iter();
                    }
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

/* ---------------- recursive ops ---------------- */

pub fn get_recursive(node: &Node, target_key: &str) -> Option<String> {
    match node {
        Node::Leaf { key, fid, deleted, .. } => {
            if key == target_key && !*deleted {
                Some(fid.clone())
            } else {
                None
            }
        }
        Node::NonLeaf { left, right, .. } => {
            if left.has_key(target_key) {
                get_recursive(left, target_key)
            } else {
                get_recursive(right, target_key)
            }
        }
    }
}

/// return: hash_changed
pub fn update_recursive(node: &mut Box<Node>, target_key: &str, new_fid: &str) -> bool {
    match **node {
        Node::Leaf {
            ref mut fid,
            ref key,
            ref deleted,
            ..
        } => {
            if key == target_key && !*deleted {
                *fid = new_fid.to_string();
                true // hash changed
            } else {
                false
            }
        }
        Node::NonLeaf {
            ref mut hash,
            ref mut left,
            ref mut right,
            ref mut keys,
            ref mut acc,
            ..
        } => {
            // locate branch using `has_key` only (leaf obeys tombstone)
            let changed = if left.has_key(target_key) {
                update_recursive(left, target_key, new_fid)
            } else {
                update_recursive(right, target_key, new_fid)
            };
            if changed {
                // recompute keys/acc/hash from children
                let new_keys = Rc::new(&node_keys_from(&*left) + &node_keys_from(&*right));
                *keys = new_keys.clone();
                *acc = Acc::cal_acc_g1(&new_keys);
                *hash = nonleaf_hash(left.hash(), right.hash());
            }
            changed
        }
    }
}

pub fn delete_recursive(node: Box<Node>, target_key: &str) -> Box<Node> {
    match *node {
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
                // preserve leaf state (no accumulator stored on Leaf)
                Box::new(Node::Leaf {
                    key,
                    fid,
                    level,
                    deleted,
                })
            }
        }
        Node::NonLeaf {
            hash: _,
            keys: _,
            acc: _,
            level,
            left,
            right,
        } => {
            let l = delete_recursive(left, target_key);
            let r = delete_recursive(right, target_key);
            let new_keys = Rc::new(&node_keys_from(&l) + &node_keys_from(&r));
            let new_acc = Acc::cal_acc_g1(&new_keys);
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

fn node_keys_from(node: &Node) -> MultiSet<String> {
    node.keys()
}

fn revive_recursive(node: Box<Node>, target_key: &str, new_fid: &str) -> Box<Node> {
    match *node {
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
                // preserve as-is; ensure acc is correct for deleted/non-deleted leaf
                Box::new(Node::Leaf {
                    key,
                    fid,
                    level,
                    deleted,
                })
            }
        }
        Node::NonLeaf {
            hash: _,
            keys: _,
            acc: _,
            level,
            left,
            right,
        } => {
            let l = revive_recursive(left, target_key, new_fid);
            let r = revive_recursive(right, target_key, new_fid);
            let new_keys = Rc::new(&node_keys_from(&l) + &node_keys_from(&r));
            let new_acc = Acc::cal_acc_g1(&new_keys);
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

fn merge_nodes(left: Box<Node>, right: Box<Node>) -> Box<Node> {
    let new_keys = Rc::new(&node_keys_from(&left) + &node_keys_from(&right));
    let new_acc = Acc::cal_acc_g1(&new_keys);
    Box::new(Node::NonLeaf {
        hash: nonleaf_hash(left.hash(), right.hash()),
        keys: new_keys,
        acc: new_acc,
        level: right.level() + 1,
        left,
        right,
    })
}

/* ---------------- forest ---------------- */

pub struct AccumulatorTree {
    pub roots: Vec<Box<Node>>,
}

impl AccumulatorTree {
    pub fn new() -> Self {
        Self { roots: Vec::new() }
    }

    fn normalize(&mut self) {
        self.roots.sort_by_key(|n| n.level());

        let mut stack: Vec<Box<Node>> = Vec::new();

        for node in self.roots.drain(..) {
            let mut cur = node;
            while let Some(top) = stack.last() {
                if top.level() == cur.level() {
                    let left = stack.pop().unwrap();
                    cur = merge_nodes(left, cur);
                } else {
                    break;
                }
            }
            stack.push(cur);
        }

        self.roots = stack;
    }

    pub fn insert(&mut self, key: String, fid: String) {
        // If there's an existing leaf for `key`, try to revive it (use `has_key`).
        if let Some(idx) = self.roots.iter().position(|r| r.has_key(&key)) {
            let root = self.roots.remove(idx);
            let revived = revive_recursive(root, &key, &fid);
            self.roots.push(revived);
            self.normalize();
            return;
        }

        self.roots.push(Box::new(Node::Leaf {
            key,
            fid,
            level: 0,
            deleted: false,
        }));
        self.normalize();
    }

    pub fn get(&self, key: &str) -> Option<String> {
        for r in &self.roots {
            if let Some(v) = get_recursive(r, key) {
                return Some(v);
            }
        }
        None
    }

    pub fn update(&mut self, key: &str, new_fid: String) {
        if let Some(root) = self.roots.iter_mut().find(|r| r.has_key(key)) {
            update_recursive(root, key, &new_fid);
        }
    }

    pub fn delete(&mut self, key: &str) {
        if let Some(idx) = self.roots.iter().position(|r| r.has_key(key)) {
            let root = self.roots.remove(idx);
            let new_root = delete_recursive(root, key);
            self.roots.push(new_root);
            self.normalize();
        }
    }
}

pub mod proof;
pub use proof::*;

pub mod utils;
pub use utils::{print_tree, render_keys};

pub mod demo;
pub use demo::{demo, run_benchmark};

#[cfg(test)]
mod tests;
