use crate::utils::Hash;
use crate::node::Node;
use accumulator_ads::Set;

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
    // Public API - Forest Management
    // ==========================================

    fn normalize(&mut self) {
        self.roots.sort_by_key(|n| n.level());

        let mut stack: Vec<Box<Node>> = Vec::new();

        for node in self.roots.drain(..) {
            let mut cur = node;
            while let Some(top) = stack.last() {
                if top.level() == cur.level() {
                    let left = stack.pop().unwrap();
                    cur = Node::merge(left, cur, None);
                } else {
                    break;
                }
            }
            stack.push(cur);
        }

        self.roots = stack;
    }

    pub fn insert(&mut self, key: String, fid: String) {
        // If there's an existing active leaf for `key`, add fid to it
        if let Some(root) = self.roots.iter_mut().find(|r| r.has_key(&key)) {
            root.insert_fid(&key, fid);
            return;
        }

        // If there's a deleted/tombstoned leaf for `key`, revive it
        if let Some(idx) = self.roots.iter().position(|r| {
            // Check if any leaf with this key exists (even if deleted)
            matches!(
                r.recurse_select_proof_including_deleted(&key, &mut Vec::new()),
                Some(_)
            )
        }) {
            let root = self.roots.remove(idx);
            let revived = root.revive(&key, &fid);
            self.roots.push(revived);
            self.normalize();
            return;
        }

        // Create new leaf
        self.roots.push(Box::new(Node::Leaf {
            key,
            fids: Set::from_vec(vec![fid]),
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
        // capture pre-insert non-membership proof (if any)
        let pre_nonmembership = self.select_nonmembership_proof(&key);

        // perform insertion (this will revive if exists)
        self.insert(key.clone(), fid.clone());

        // build post-insert proof for the inserted key
        let qr = self.select_with_proof(&key);
        let post_acc = qr.accumulator;
        let post_proof = qr.merkle_proof;
        let post_acc_witness = match qr.acc_proof {
            Some(crate::acc_proof::AccProof::Membership(mp)) => Some(mp.witness),
            _ => None,
        };
        let post_fids = qr.fids.unwrap_or_else(|| Set::new());

        let post_acc_proof =
            post_acc_witness.map(|w| crate::acc_proof::MembershipProof { witness: w });

        crate::response::InsertResponse::new(
            key,
            post_fids,
            post_acc,
            post_proof,
            post_acc_proof,
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
    ) -> Option<crate::acc_proof::NonMembershipProof> {
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
            crate::utils::empty_acc()
        } else {
            // Calculate accumulator commitment for all keys
            let digest_set = accumulator_ads::digest_set_from_set(&all_keys);
            accumulator_ads::DynamicAccumulator::calculate_commitment(&digest_set)
        };

        // Generate non-membership proof using accumulator's Bézout approach
        crate::acc_proof::NonMembershipProof::new(key.to_string(), global_acc, &all_keys)
    }

    pub fn select(&self, key: &str) -> Option<Set<String>> {
        for r in &self.roots {
            if let Some(v) = r.select(key) {
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
            if let Some(fids) = r.recurse_select_with_proof(key, &mut path) {
                let leaf_h = crate::utils::leaf_hash(key, &fids, 0, false);
                let root_h = r.hash();
                let proof = crate::merkle_proof::Proof::new(root_h, leaf_h, path);
                // create accumulator membership witness for the key
                let acc_val = r.acc();
                let key_set = accumulator_ads::Set::from_vec(vec![key.to_string()]);
                let key_digest_set = accumulator_ads::digest_set_from_set(&key_set);
                let key_elem = *key_digest_set.iter().next().unwrap();
                let acc_inst = accumulator_ads::DynamicAccumulator::from_value(acc_val);
                let acc_witness = acc_inst
                    .compute_membership_witness(key_elem)
                    .unwrap_or(acc_val);
                let acc_proof =
                    crate::acc_proof::AccProof::Membership(crate::acc_proof::MembershipProof {
                        witness: acc_witness,
                    });
                return crate::response::QueryResponse::new(
                    Some(fids),
                    Some(proof),
                    Some(r.acc()),
                    Some(acc_proof),
                );
            }
        }
        // not found: try to construct non-membership proof
        if let Some(nm) = self.select_nonmembership_proof(key) {
            let nm_proof = crate::acc_proof::AccProof::NonMembership(nm);
            crate::response::QueryResponse::new(None, None, None, Some(nm_proof))
        } else {
            crate::response::QueryResponse::new(None, None, None, None)
        }
    }

    /// Update a specific FID: replace old_fid with new_fid in the key's FID set.
    pub fn update(&mut self, key: &str, old_fid: &str, new_fid: String) -> bool {
        if let Some(root) = self.roots.iter_mut().find(|r| r.has_key(key)) {
            root.update_fid(key, old_fid, new_fid)
        } else {
            false
        }
    }

    /// Update with proof: returns an `UpdateResponse` capturing pre/post proofs
    /// and accumulator witnesses so a verifier can confirm that only one FID
    /// was replaced in the `key`'s FID set and the rest of the tree is unchanged.
    pub fn update_with_proof(
        &mut self,
        key: &str,
        old_fid: &str,
        new_fid: String,
    ) -> Result<crate::response::UpdateResponse, String> {
        // obtain pre-update proof (must exist)
        let pre_qr = self.select_with_proof(key);
        let old_fids = pre_qr.fids.clone();
        if old_fids.is_none() {
            return Err(format!("key '{}' not found for update", key));
        }
        // check if the old_fid exists in the set
        if !old_fids.as_ref().unwrap().contains(&old_fid.to_string()) {
            return Err(format!(
                "old_fid '{}' not found in key '{}' for update",
                old_fid, key
            ));
        }
        // capture pre acc/root
        let pre_acc = pre_qr.accumulator;
        let pre_acc_witness = match pre_qr.acc_proof {
            Some(crate::acc_proof::AccProof::Membership(mp)) => Some(mp.witness),
            _ => None,
        };
        let pre_proof = pre_qr.merkle_proof;

        // perform the update
        if !self.update(key, old_fid, new_fid.clone()) {
            return Err("update failed".to_string());
        }

        // obtain post-update proof
        let post_qs = self.select_with_proof(key);
        if post_qs.fids.is_none() {
            return Err("post-update: key missing after update".to_string());
        }
        let new_fids = post_qs.fids.clone().unwrap();
        let post_proof = post_qs.merkle_proof.expect("post proof present");
        let post_acc = post_qs.accumulator.expect("post acc present");
        let post_acc_proof = match post_qs.acc_proof {
            Some(crate::acc_proof::AccProof::Membership(mp)) => mp,
            _ => panic!("post acc witness present"),
        };
        let pre_acc_proof =
            pre_acc_witness.map(|w| crate::acc_proof::MembershipProof { witness: w });

        Ok(crate::response::UpdateResponse::new(
            key.to_string(),
            old_fid.to_string(),
            new_fid,
            old_fids,
            new_fids,
            pre_proof,
            pre_acc,
            pre_acc_proof,
            post_proof,
            post_acc,
            post_acc_proof,
        ))
    }

    /// Delete a specific FID from the FID set of a key.
    /// If the FID set becomes empty, the leaf is tombstoned (marked as deleted).
    pub fn delete(&mut self, key: &str, fid: &str) {
        if let Some(root) = self.roots.iter_mut().find(|r| r.has_key(key)) {
            root.delete_fid(key, fid);
        }
    }

    /// Delete with proof: returns a `DeleteResponse` capturing pre/post proofs.
    /// Deletes a specific FID from the key's FID set. If the set becomes empty,
    /// the leaf is tombstoned and the tree integrity (path siblings) is preserved.
    pub fn delete_with_proof(
        &mut self,
        key: &str,
        fid: &str,
    ) -> Result<crate::response::DeleteResponse, String> {
        // capture pre-state proof (must exist)
        let pre_qr = self.select_with_proof(key);
        let old_fids = pre_qr.fids.clone();
        if old_fids.is_none() {
            return Err(format!("key '{}' not found for delete", key));
        }
        // check if the fid exists in the set
        if !old_fids.as_ref().unwrap().contains(&fid.to_string()) {
            return Err(format!(
                "fid '{}' not found in key '{}' for delete",
                fid, key
            ));
        }
        let pre_proof = pre_qr.merkle_proof;
        let pre_acc = pre_qr.accumulator;
        let pre_acc_proof = match pre_qr.acc_proof {
            Some(crate::acc_proof::AccProof::Membership(mp)) => Some(mp),
            _ => None,
        };

        // perform deletion
        self.delete(key, fid);

        // find post-state proof (may still be active if other FIDs remain, or tombstoned if empty)
        for r in self.roots.iter() {
            let mut path: Vec<(Hash, bool)> = Vec::new();
            if let Some(post_fids) = r.recurse_select_proof_including_deleted(key, &mut path) {
                let root_h = r.hash();
                // Calculate leaf hash based on whether it's now tombstoned
                // Calculate leaf hash based on whether it's now tombstoned
                let leaf_h = if post_fids.is_empty() {
                    // FID set is empty, leaf is tombstoned
                    // Assuming leaves are at level 0
                    crate::utils::leaf_hash(key, &post_fids, 0, true)
                } else {
                    // Still has FIDs remaining
                    crate::utils::leaf_hash(key, &post_fids, 0, false)
                };
                let post_proof = crate::merkle_proof::Proof::new(root_h, leaf_h, path);
                let post_acc = r.acc();
                return Ok(crate::response::DeleteResponse::new(
                    key.to_string(),
                    fid.to_string(), // deleted_fid
                    old_fids,        // old_fids
                    post_fids,       // new_fids
                    pre_proof,
                    pre_acc,
                    pre_acc_proof,
                    post_proof,
                    post_acc,
                ));
            }
        }

        // If we reach here, the leaf was not found (unexpected)
        Err("post-delete: key not found".to_string())
    }

    // ==========================================
    // Test helpers
    // ==========================================

    #[cfg(test)]
    pub fn test_merge_nodes(left: Box<Node>, right: Box<Node>) -> Box<Node> {
        Node::merge(left, right, None)
    }

    #[cfg(test)]
    pub fn test_update_fid_recursive(
        node: &mut Node,
        key: &str,
        old_fid: &str,
        new_fid: String,
    ) -> bool {
        node.update_fid(key, old_fid, new_fid)
    }

    #[cfg(test)]
    pub fn test_revive_recursive(node: Box<Node>, key: &str, fid: &str) -> Box<Node> {
        node.revive(key, fid)
    }
}
