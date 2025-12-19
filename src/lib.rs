use acc::{Acc, Accumulator, G1Affine, MultiSet};
use ark_ec::{AffineCurve, ProjectiveCurve};
use sha2::{Digest, Sha256};
use std::rc::Rc;

pub type Hash = [u8; 32];

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
        acc: G1Affine,
        level: usize,
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
            Node::Leaf { key, fid, .. } => leaf_hash(key, fid),
            Node::NonLeaf { hash, .. } => *hash,
        }
    }

    pub fn acc(&self) -> G1Affine {
        match self {
            Node::Leaf { acc, .. } => *acc,
            Node::NonLeaf { acc, .. } => *acc,
        }
    }

    pub fn has_key(&self, target_key: &str) -> bool {
        match self {
            Node::Leaf { key, .. } => key == target_key,
            Node::NonLeaf { keys, .. } => keys.contains_key(target_key),
        }
    }

    pub fn collect_leaves_vec(&self) -> Vec<(String, String)> {
        match self {
            Node::Leaf { key, fid, .. } => vec![(key.clone(), fid.clone())],
            Node::NonLeaf { left, right, .. } => {
                let mut lv = left.collect_leaves_vec();
                lv.extend(right.collect_leaves_vec());
                lv
            }
        }
    }

    pub fn collect_leaves(&self, _level: Option<usize>) -> std::vec::IntoIter<(String, String)> {
        self.collect_leaves_vec().into_iter()
    }
}

pub fn get_recursive(node: &Node, target_key: &str) -> Option<String> {
    match node {
        Node::Leaf { key, fid, .. } => {
            if key == target_key {
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

pub fn update_recursive(node: &mut Box<Node>, target_key: &str, new_fid: &str) -> (bool, bool) {
    match **node {
        Node::Leaf {
            ref mut fid,
            ref key,
            ..
        } => {
            if key == target_key {
                *fid = new_fid.to_string();
                return (true, false);
            }
            (false, false)
        }
        Node::NonLeaf {
            ref mut hash,
            ref mut acc,
            ref mut left,
            ref mut right,
            ref keys,
            ..
        } => {
            if !keys.contains_key(target_key) {
                return (false, false);
            }
            let (l_h, l_a) = update_recursive(left, target_key, new_fid);
            let (r_h, r_a) = update_recursive(right, target_key, new_fid);

            let h_changed = l_h || r_h;
            let a_changed = l_a || r_a;

            if h_changed {
                *hash = nonleaf_hash(left.hash(), right.hash());
            }
            if a_changed {
                let mut acc_proj = left.acc().into_projective();
                acc_proj.add_assign_mixed(&right.acc());
                *acc = acc_proj.into_affine();
            }
            (h_changed, a_changed)
        }
    }
}

pub fn delete_recursive(node: Box<Node>, target_key: &str) -> Option<Box<Node>> {
    if !node.has_key(target_key) {
        return Some(node);
    }

    match *node {
        Node::Leaf {
            key,
            fid,
            acc,
            level,
        } => {
            if key == target_key {
                None
            } else {
                Some(Box::new(Node::Leaf {
                    key,
                    fid,
                    acc,
                    level,
                }))
            }
        }
        Node::NonLeaf {
            level, left, right, ..
        } => {
            let left_res = delete_recursive(left, target_key);
            let right_res = delete_recursive(right, target_key);
            match (left_res, right_res) {
                (Some(l), Some(r)) => {
                    let mut acc_proj = l.acc().into_projective();
                    acc_proj.add_assign_mixed(&r.acc());
                    Some(Box::new(Node::NonLeaf {
                        hash: nonleaf_hash(l.hash(), r.hash()),
                        keys: Rc::new(&node_keys_from(&l) + &node_keys_from(&r)),
                        acc: acc_proj.into_affine(),
                        level,
                        left: l,
                        right: r,
                    }))
                }
                (Some(l), None) => Some(l),
                (None, Some(r)) => Some(r),
                (None, None) => None,
            }
        }
    }
}

fn node_keys_from(node: &Box<Node>) -> MultiSet<String> {
    match &**node {
        Node::Leaf { key, .. } => MultiSet::from_vec(vec![key.clone()]),
        Node::NonLeaf { keys, .. } => keys.as_ref().clone(),
    }
}

fn merge_nodes(r_old: Box<Node>, curr: Box<Node>) -> Box<Node> {
    let mut acc_proj = r_old.acc().into_projective();
    acc_proj.add_assign_mixed(&curr.acc());
    Box::new(Node::NonLeaf {
        hash: nonleaf_hash(r_old.hash(), curr.hash()),
        keys: Rc::new(&node_keys_from(&r_old) + &node_keys_from(&curr)),
        acc: acc_proj.into_affine(),
        level: curr.level() + 1,
        left: r_old,
        right: curr,
    })
}

pub struct AccumulatorTree {
    pub roots: Vec<Box<Node>>,
}

impl AccumulatorTree {
    pub fn new() -> Self {
        Self { roots: Vec::new() }
    }

    pub fn insert(&mut self, key: String, fid: String) {
        let leaf_acc = Acc::cal_acc_g1(&MultiSet::from_vec(vec![key.clone()]));
        let mut node = Box::new(Node::Leaf {
            key,
            fid,
            acc: leaf_acc,
            level: 0,
        });
        loop {
            if let Some(idx) = self.roots.iter().position(|r| r.level() == node.level()) {
                node = merge_nodes(self.roots.remove(idx), node);
            } else {
                self.roots.push(node);
                self.roots.sort_by_key(|n| n.level());
                break;
            }
        }
    }

    pub fn get(&self, key: &str) -> Option<String> {
        self.roots
            .iter()
            .find(|r| r.has_key(key))
            .and_then(|r| get_recursive(r, key))
    }

    pub fn update(&mut self, key: &str, new_fid: String) {
        if let Some(root) = self.roots.iter_mut().find(|r| r.has_key(key)) {
            update_recursive(root, key, &new_fid);
        }
    }

    pub fn delete(&mut self, key: &str) {
        if let Some(idx) = self.roots.iter().position(|r| r.has_key(key)) {
            let root = self.roots.remove(idx);
            if let Some(new_root) = delete_recursive(root, key) {
                self.roots.push(new_root);
                self.roots.sort_by_key(|n| n.level());
            }
        }
    }
}

pub mod utils;
pub use utils::{print_tree, render_keys};

pub mod demo;
pub use demo::{demo, run_benchmark};

#[cfg(test)]
mod tests;
