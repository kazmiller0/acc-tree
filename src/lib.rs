use acc::{Acc, Accumulator, G1Affine, MultiSet};
use lazy_static::lazy_static;
use sha2::{Digest, Sha256};
use std::rc::Rc;

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
                get_recursive(left, target_key)
            } else {
                get_recursive(right, target_key)
            }
        }
    }
}

/// Build a path-proof for `target_key` within `node`.
/// `path` is populated with sibling hashes on unwind; each entry is (sibling_hash, sibling_is_left).
fn get_proof_recursive(
    node: &Node,
    target_key: &str,
    path: &mut Vec<(Hash, bool)>,
) -> Option<String> {
    match node {
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
                if let Some(fid) = get_proof_recursive(left, target_key, path) {
                    // sibling is right child
                    path.push((right.hash(), false));
                    return Some(fid);
                }
                None
            } else if right.has_key(target_key) {
                if let Some(fid) = get_proof_recursive(right, target_key, path) {
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

/// Find predecessor (max key < target) and successor (min key > target) within `node`.
/// Returns (found_exact, pred_opt, succ_opt)
fn find_pred_succ(
    node: &Node,
    target: &str,
) -> (bool, Option<(String, String)>, Option<(String, String)>) {
    match node {
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
            let (found_l, pred_l, succ_l) = find_pred_succ(left, target);
            if found_l {
                return (true, None, None);
            }
            let (found_r, pred_r, succ_r) = find_pred_succ(right, target);
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

    /// Insert with proof: returns pre-insert snapshot and post-insert proofs.
    /// Note: strong non-membership proofs are not implemented; we provide a pre-insert
    /// snapshot (`pre_roots`) that a verifier can use with application-level checks.
    pub fn insert_with_proof(&mut self, key: String, fid: String) -> crate::proof::InsertResponse {
        // capture pre-insert snapshot (root hash + acc) for all roots
        let pre_roots: Vec<(Hash, acc::G1Affine)> =
            self.roots.iter().map(|r| (r.hash(), r.acc())).collect();

        // capture pre-insert non-membership proof (if any)
        let pre_nonmembership = self.get_nonmembership_proof(&key);

        // perform insertion (this will revive if exists)
        self.insert(key.clone(), fid.clone());

        // build post-insert proof for the inserted key
        let qr = self.get_with_proof(&key);
        let post_root_hash = qr.root_hash;
        let post_acc = qr.acc;
        let post_proof = qr.proof;
        let post_acc_witness = qr.acc_witness;

        crate::proof::InsertResponse::new(
            key,
            fid,
            pre_roots,
            post_root_hash,
            post_acc,
            post_proof,
            post_acc_witness,
            pre_nonmembership,
        )
    }

    /// Produce a non-membership proof for `key` by returning the predecessor and successor
    /// leaves (if any) together with their Merkle proofs. Returns `None` if the key exists.
    pub fn get_nonmembership_proof(&self, key: &str) -> Option<crate::proof::NonMembershipProof> {
        // Track best global predecessor (max < key) and successor (min > key)
        let mut best_pred: Option<((String, String), usize)> = None; // ((k,fid), root_idx)
        let mut best_succ: Option<((String, String), usize)> = None; // ((k,fid), root_idx)

        for (i, root) in self.roots.iter().enumerate() {
            let (found, pred, succ) = find_pred_succ(root.as_ref(), key);
            if found {
                return None; // key exists
            }
            if let Some((pk, pf)) = pred {
                let should_replace = match &best_pred {
                    None => true,
                    Some(((bk, _), _)) => pk > *bk,
                };
                if should_replace {
                    best_pred = Some(((pk, pf), i));
                }
            }
            if let Some((sk, sf)) = succ {
                let should_replace = match &best_succ {
                    None => true,
                    Some(((bk, _), _)) => sk < *bk,
                };
                if should_replace {
                    best_succ = Some(((sk, sf), i));
                }
            }
        }

        // build proofs for pred/succ using their respective roots
        let pred_proof = if let Some(((k, f), idx)) = best_pred.clone() {
            let mut path: Vec<(Hash, bool)> = Vec::new();
            let _ = get_proof_recursive(&self.roots[idx], &k, &mut path);
            let root_h = self.roots[idx].hash();
            let leaf_h = leaf_hash(&k, &f);
            Some((k, f, crate::proof::Proof::new(root_h, leaf_h, path)))
        } else {
            None
        };

        let succ_proof = if let Some(((k, f), idx)) = best_succ.clone() {
            let mut path: Vec<(Hash, bool)> = Vec::new();
            let _ = get_proof_recursive(&self.roots[idx], &k, &mut path);
            let root_h = self.roots[idx].hash();
            let leaf_h = leaf_hash(&k, &f);
            Some((k, f, crate::proof::Proof::new(root_h, leaf_h, path)))
        } else {
            None
        };

        Some(crate::proof::NonMembershipProof::new(
            pred_proof, succ_proof,
        ))
    }

    pub fn get(&self, key: &str) -> Option<String> {
        for r in &self.roots {
            if let Some(v) = get_recursive(r, key) {
                return Some(v);
            }
        }
        None
    }

    /// Return the query result together with a proof that the leaf belongs
    /// to the subtree rooted at the returned root hash.
    pub fn get_with_proof(&self, key: &str) -> crate::proof::QueryResponse {
        for r in &self.roots {
            let mut path: Vec<(Hash, bool)> = Vec::new();
            if let Some(fid) = get_proof_recursive(r, key, &mut path) {
                let leaf_h = leaf_hash(key, &fid);
                let root_h = r.hash();
                let proof = crate::proof::Proof::new(root_h, leaf_h, path);
                // create accumulator membership witness for the key
                let acc_val = r.acc();
                let acc_witness = acc::Acc::create_witness(&acc_val, &key.to_string());
                return crate::proof::QueryResponse::new(
                    Some(fid),
                    Some(proof),
                    Some(root_h),
                    Some(acc_val),
                    Some(acc_witness),
                    None,
                );
            }
        }
        // not found: try to construct non-membership proof
        let nm = self.get_nonmembership_proof(key);
        crate::proof::QueryResponse::new(None, None, None, None, None, nm)
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
