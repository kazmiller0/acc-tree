use crate::crypto::{Hash, empty_hash, leaf_hash};
use crate::node::Node;

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

    fn normalize(&mut self) {
        self.roots.sort_by_key(|n| n.level());

        let mut stack: Vec<Box<Node>> = Vec::new();

        for node in self.roots.drain(..) {
            let mut cur = node;
            while let Some(top) = stack.last() {
                if top.level() == cur.level() {
                    let left = stack.pop().unwrap();
                    cur = Node::merge(left, cur);
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
            let revived = root.revive_recursive(&key, &fid);
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
        let post_acc = qr.accumulator;
        let post_proof = qr.proof;
        let post_acc_witness = qr.membership_witness;

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
            let (found, pred, succ) = root.find_pred_succ(key);
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
            let _ = self.roots[idx].get_proof_recursive(&k, &mut path);
            let root_h = self.roots[idx].hash();
            let leaf_h = leaf_hash(&k, &f);
            Some((k, f, crate::proof::Proof::new(root_h, leaf_h, path)))
        } else {
            None
        };

        let succ_proof = if let Some(((k, f), idx)) = best_succ.clone() {
            let mut path: Vec<(Hash, bool)> = Vec::new();
            let _ = self.roots[idx].get_proof_recursive(&k, &mut path);
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
            if let Some(v) = r.get_recursive(key) {
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
            if let Some(fid) = r.get_proof_recursive(key, &mut path) {
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
            root.update_recursive(key, &new_fid);
        }
    }

    /// Update with proof: returns an `UpdateResponse` capturing pre/post proofs
    /// and accumulator witnesses so a verifier can confirm that only the
    /// `fid` for `key` changed and the rest of the tree is unchanged.
    pub fn update_with_proof(
        &mut self,
        key: &str,
        new_fid: String,
    ) -> Result<crate::proof::UpdateResponse, String> {
        // obtain pre-update proof (must exist)
        let pre_qr = self.get_with_proof(key);
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
        let post_qr = self.get_with_proof(key);
        if post_qr.fid.is_none() {
            return Err("post-update: key missing after update".to_string());
        }
        let post_proof = post_qr.proof.expect("post proof present");
        let post_acc = post_qr.accumulator.expect("post acc present");
        let post_acc_witness = post_qr
            .membership_witness
            .expect("post acc witness present");
        let post_root_hash = post_qr.root_hash.expect("post root hash present");

        Ok(crate::proof::UpdateResponse::new(
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
            let new_root = root.delete_recursive(key);
            self.roots.push(new_root);
            self.normalize();
        }
    }

    /// Delete with proof: returns a `DeleteResponse` capturing pre/post proofs
    /// so a verifier can confirm the key was tombstoned and the tree integrity
    /// (path siblings) was preserved.
    pub fn delete_with_proof(&mut self, key: &str) -> Result<crate::proof::DeleteResponse, String> {
        // capture pre-state proof (must exist)
        let pre_qr = self.get_with_proof(key);
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
            if let Some(_fid) = r.get_proof_including_deleted(key, &mut path) {
                let root_h = r.hash();
                // after deletion the leaf's hash should be empty_hash()
                let leaf_h = empty_hash();
                let post_proof = crate::proof::Proof::new(root_h, leaf_h, path);
                let post_acc = r.acc();
                let post_root_hash = root_h;
                return Ok(crate::proof::DeleteResponse::new(
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
}
