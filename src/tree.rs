use crate::crypto::{Hash, empty_hash, leaf_hash, nonleaf_hash};
use crate::node::Node;
use accumulator_ads::{digest_set_from_set, DynamicAccumulator};
use std::rc::Rc;

pub struct AccumulatorTree {
    pub roots: Vec<Box<Node>>,
}

impl Default for AccumulatorTree {
    fn default() -> Self {
        Self::new()
    }
}

impl AccumulatorTree {
    pub fn new() -> Self {
        Self { roots: Vec::new() }
    }

    // ==========================================
    // Internal recursive operations on nodes
    // ==========================================

    /// Get value for target_key recursively
    fn node_select_recursive(node: &Node, target_key: &str) -> Option<String> {
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
                    Self::node_select_recursive(left, target_key)
                } else {
                    Self::node_select_recursive(right, target_key)
                }
            }
        }
    }

    /// Build a path-proof for `target_key` within this node.
    /// `path` is populated with sibling hashes on unwind; each entry is (sibling_hash, sibling_is_left).
    fn node_select_proof_recursive(
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
                    if let Some(fid) = Self::node_select_proof_recursive(left, target_key, path) {
                        path.push((right.hash(), false));
                        return Some(fid);
                    }
                    None
                } else if right.has_key(target_key) {
                    if let Some(fid) = Self::node_select_proof_recursive(right, target_key, path) {
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
    fn node_select_proof_including_deleted(
        node: &Node,
        target_key: &str,
        path: &mut Vec<(Hash, bool)>,
    ) -> Option<String> {
        match node {
            Node::Leaf { key, fid, .. } => {
                if key == target_key {
                    Some(fid.clone())
                } else {
                    None
                }
            }
            Node::NonLeaf { left, right, .. } => {
                if let Some(fid) = Self::node_select_proof_including_deleted(left, target_key, path)
                {
                    path.push((right.hash(), false));
                    return Some(fid);
                }
                if let Some(fid) =
                    Self::node_select_proof_including_deleted(right, target_key, path)
                {
                    path.push((left.hash(), true));
                    return Some(fid);
                }
                None
            }
        }
    }

    /// Update fid for target_key recursively. Returns whether hash changed.
    fn node_update_recursive(node: &mut Node, target_key: &str, new_fid: &str) -> bool {
        match node {
            Node::Leaf {
                fid, key, deleted, ..
            } => {
                if key == target_key && !*deleted {
                    *fid = new_fid.to_string();
                    true
                } else {
                    false
                }
            }
            Node::NonLeaf {
                hash, left, right, ..
            } => {
                let changed = if left.has_key(target_key) {
                    Self::node_update_recursive(left, target_key, new_fid)
                } else {
                    Self::node_update_recursive(right, target_key, new_fid)
                };
                if changed {
                    *hash = nonleaf_hash(left.hash(), right.hash());
                }
                changed
            }
        }
    }

    /// Mark leaf with target_key as deleted (tombstone). Returns new node.
    fn node_delete_recursive(node: Box<Node>, target_key: &str) -> Box<Node> {
        match *node {
            Node::Leaf {
                key,
                fid,
                level,
                deleted,
            } => {
                if key == target_key && !deleted {
                    Box::new(Node::Leaf {
                        key,
                        fid,
                        level,
                        deleted: true,
                    })
                } else {
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
                let l = Self::node_delete_recursive(left, target_key);
                let r = Self::node_delete_recursive(right, target_key);
                let new_keys = Rc::new(l.keys().union(&r.keys()));

                let left_digest = digest_set_from_set(&l.keys());
                let right_digest = digest_set_from_set(&r.keys());
                let new_acc = DynamicAccumulator::incremental_union(
                    l.acc(),
                    r.acc(),
                    &left_digest,
                    &right_digest,
                );

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
    fn node_revive_recursive(node: Box<Node>, target_key: &str, new_fid: &str) -> Box<Node> {
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
                let l = Self::node_revive_recursive(left, target_key, new_fid);
                let r = Self::node_revive_recursive(right, target_key, new_fid);
                let new_keys = Rc::new(l.keys().union(&r.keys()));

                let left_digest = digest_set_from_set(&l.keys());
                let right_digest = digest_set_from_set(&r.keys());
                let new_acc = DynamicAccumulator::incremental_union(
                    l.acc(),
                    r.acc(),
                    &left_digest,
                    &right_digest,
                );

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
    fn node_merge(left: Box<Node>, right: Box<Node>) -> Box<Node> {
        let new_keys = Rc::new(left.keys().union(&right.keys()));

        let left_acc = left.acc();
        let right_acc = right.acc();
        let left_digest = digest_set_from_set(&left.keys());
        let right_digest = digest_set_from_set(&right.keys());

        let new_acc =
            DynamicAccumulator::incremental_union(left_acc, right_acc, &left_digest, &right_digest);

        Box::new(Node::NonLeaf {
            hash: nonleaf_hash(left.hash(), right.hash()),
            keys: new_keys,
            acc: new_acc,
            level: right.level() + 1,
            left,
            right,
        })
    }

    // ==========================================
    // Public API
    // ==========================================

    fn normalize(&mut self) {
        self.roots.sort_by_key(|n| n.level());

        let mut stack: Vec<Box<Node>> = Vec::new();

        for node in self.roots.drain(..) {
            let mut cur = node;
            while let Some(top) = stack.last() {
                if top.level() == cur.level() {
                    let left = stack.pop().unwrap();
                    cur = Self::node_merge(left, cur);
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
            let revived = Self::node_revive_recursive(root, &key, &fid);
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
    pub fn insert_with_proof(
        &mut self,
        key: String,
        fid: String,
    ) -> crate::response::InsertResponse {
        // capture pre-insert snapshot (root hash + acc) for all roots
        let pre_roots: Vec<(Hash, accumulator_ads::G1Affine)> =
            self.roots.iter().map(|r| (r.hash(), r.acc())).collect();

        // capture pre-insert non-membership proof (if any)
        let pre_nonmembership = self.select_nonmembership_proof(&key);

        // perform insertion (this will revive if exists)
        self.insert(key.clone(), fid.clone());

        // build post-insert proof for the inserted key
        let qr = self.select_with_proof(&key);
        let post_root_hash = qr.root_hash;
        let post_acc = qr.accumulator;
        let post_proof = qr.proof;
        let post_acc_witness = qr.membership_witness;

        crate::response::InsertResponse::new(
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
    /// Generate a cryptographically sound non-membership proof
    /// This uses the accumulator's Bézout coefficient approach to prove
    /// that a key is NOT in the accumulated set
    pub fn select_nonmembership_proof(
        &self,
        key: &str,
    ) -> Option<crate::response::NonMembershipProof> {
        // First check if key exists anywhere
        for root in &self.roots {
            if root.has_key(key) {
                return None; // Key exists, cannot create non-membership proof
            }
        }

        // Collect all keys from all roots to build the complete set
        let mut all_keys = accumulator_ads::Set::<String>::new();
        for root in &self.roots {
            all_keys = all_keys.union(&root.keys());
        }

        // Calculate the global accumulator for all keys
        let global_acc = if all_keys.is_empty() {
            // Empty tree: use empty accumulator
            crate::crypto::empty_acc()
        } else {
            // Calculate accumulator commitment for all keys
            let digest_set = accumulator_ads::digest_set_from_set(&all_keys);
            accumulator_ads::DynamicAccumulator::calculate_commitment(&digest_set)
        };

        // Generate non-membership proof using accumulator's Bézout approach
        crate::response::NonMembershipProof::new(key.to_string(), global_acc, &all_keys)
    }

    pub fn select(&self, key: &str) -> Option<String> {
        for r in &self.roots {
            if let Some(v) = Self::node_select_recursive(r, key) {
                return Some(v);
            }
        }
        None
    }

    /// Return the query result together with a proof that the leaf belongs
    /// to the subtree rooted at the returned root hash.
    pub fn select_with_proof(&self, key: &str) -> crate::response::QueryResponse {
        for r in &self.roots {
            let mut path: Vec<(Hash, bool)> = Vec::new();
            if let Some(fid) = Self::node_select_proof_recursive(r, key, &mut path) {
                let leaf_h = leaf_hash(key, &fid);
                let root_h = r.hash();
                let proof = crate::proof::Proof::new(root_h, leaf_h, path);
                // create accumulator membership witness for the key
                let acc_val = r.acc();
                let key_set = accumulator_ads::Set::from_vec(vec![key.to_string()]);
                let key_digest_set = accumulator_ads::digest_set_from_set(&key_set);
                let key_elem = *key_digest_set.iter().next().unwrap();
                let acc_inst = accumulator_ads::DynamicAccumulator { acc_value: acc_val };
                let acc_witness = acc_inst
                    .compute_membership_witness(key_elem)
                    .unwrap_or(acc_val);
                return crate::response::QueryResponse::new(
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
        let nm = self.select_nonmembership_proof(key);
        crate::response::QueryResponse::new(None, None, None, None, None, nm)
    }

    pub fn update(&mut self, key: &str, new_fid: String) {
        if let Some(root) = self.roots.iter_mut().find(|r| r.has_key(key)) {
            Self::node_update_recursive(root, key, &new_fid);
        }
    }

    /// Update with proof: returns an `UpdateResponse` capturing pre/post proofs
    /// and accumulator witnesses so a verifier can confirm that only the
    /// `fid` for `key` changed and the rest of the tree is unchanged.
    pub fn update_with_proof(
        &mut self,
        key: &str,
        new_fid: String,
    ) -> Result<crate::response::UpdateResponse, String> {
        // obtain pre-update proof (must exist)
        let pre_qr = self.select_with_proof(key);
        let old_fid = pre_qr.fid.clone();
        if old_fid.is_none() {
            return Err(format!("key '{}' not found for update", key));
        }
        // capture pre acc/root
        let pre_acc = pre_qr.accumulator;
        let pre_acc_witness = pre_qr.membership_witness;
        let pre_root_hash = pre_qr.root_hash;
        let pre_proof = pre_qr.proof;

        // perform the update
        self.update(key, new_fid.clone());

        // obtain post-update proof
        let post_qr = self.select_with_proof(key);
        if post_qr.fid.is_none() {
            return Err("post-update: key missing after update".to_string());
        }
        let post_proof = post_qr.proof.expect("post proof present");
        let post_acc = post_qr.accumulator.expect("post acc present");
        let post_acc_witness = post_qr
            .membership_witness
            .expect("post acc witness present");
        let post_root_hash = post_qr.root_hash.expect("post root hash present");

        Ok(crate::response::UpdateResponse::new(
            key.to_string(),
            old_fid,
            new_fid,
            pre_proof,
            pre_acc,
            pre_acc_witness,
            post_proof,
            post_acc,
            post_acc_witness,
            pre_root_hash,
            post_root_hash,
        ))
    }

    pub fn delete(&mut self, key: &str) {
        if let Some(idx) = self.roots.iter().position(|r| r.has_key(key)) {
            let root = self.roots.remove(idx);
            let new_root = Self::node_delete_recursive(root, key);
            self.roots.push(new_root);
            self.normalize();
        }
    }

    /// Delete with proof: returns a `DeleteResponse` capturing pre/post proofs
    /// so a verifier can confirm the key was tombstoned and the tree integrity
    /// (path siblings) was preserved.
    pub fn delete_with_proof(
        &mut self,
        key: &str,
    ) -> Result<crate::response::DeleteResponse, String> {
        // capture pre-state proof (must exist)
        let pre_qr = self.select_with_proof(key);
        let old_fid = pre_qr.fid.clone();
        if old_fid.is_none() {
            return Err(format!("key '{}' not found for delete", key));
        }
        let pre_proof = pre_qr.proof;
        let pre_acc = pre_qr.accumulator;
        let pre_acc_witness = pre_qr.membership_witness;
        let pre_root_hash = pre_qr.root_hash;

        // perform deletion
        self.delete(key);

        // find post-state proof including tombstoned leaf
        for r in self.roots.iter() {
            let mut path: Vec<(Hash, bool)> = Vec::new();
            if let Some(_fid) = Self::node_select_proof_including_deleted(r, key, &mut path) {
                let root_h = r.hash();
                // after deletion the leaf's hash should be empty_hash()
                let leaf_h = empty_hash();
                let post_proof = crate::proof::Proof::new(root_h, leaf_h, path);
                let post_acc = r.acc();
                let post_root_hash = root_h;
                return Ok(crate::response::DeleteResponse::new(
                    key.to_string(),
                    old_fid,
                    pre_proof,
                    pre_acc,
                    pre_acc_witness,
                    post_proof,
                    post_acc,
                    pre_root_hash,
                    post_root_hash,
                ));
            }
        }

        // If we reach here, the deleted leaf is not present as a tombstone (unexpected)
        Err("post-delete tombstone not found".to_string())
    }

    // ==========================================
    // Test helpers
    // ==========================================

    #[cfg(test)]
    pub fn test_merge_nodes(left: Box<Node>, right: Box<Node>) -> Box<Node> {
        Self::node_merge(left, right)
    }

    #[cfg(test)]
    pub fn test_delete_recursive(node: Box<Node>, key: &str) -> Box<Node> {
        Self::node_delete_recursive(node, key)
    }

    #[cfg(test)]
    pub fn test_update_recursive(node: &mut Node, key: &str, fid: &str) -> bool {
        Self::node_update_recursive(node, key, fid)
    }

    #[cfg(test)]
    pub fn test_revive_recursive(node: Box<Node>, key: &str, fid: &str) -> Box<Node> {
        Self::node_revive_recursive(node, key, fid)
    }
}
