use crate::{Hash, leaf_hash, nonleaf_hash};
use acc::G1Affine;

#[derive(Debug, Clone)]
pub struct Proof {
    /// hash of the root of the subtree used for the proof
    pub root_hash: Hash,
    /// hash of the leaf (key,fid) being proven
    pub leaf_hash: Hash,
    /// path from leaf up to root: each entry is (sibling_hash, sibling_is_left)
    /// sibling_is_left == true means the sibling is the left child.
    pub path: Vec<(Hash, bool)>,
}

impl Proof {
    pub fn new(root_hash: Hash, leaf_hash: Hash, path: Vec<(Hash, bool)>) -> Self {
        Self {
            root_hash,
            leaf_hash,
            path,
        }
    }

    /// Verify the proof by recomputing the root hash from the leaf and path
    pub fn verify(&self) -> bool {
        let mut cur = self.leaf_hash;
        for (sib, sibling_is_left) in &self.path {
            if *sibling_is_left {
                cur = nonleaf_hash(*sib, cur);
            } else {
                cur = nonleaf_hash(cur, *sib);
            }
        }
        cur == self.root_hash
    }

    /// Convenience: recompute the leaf hash from `key`/`fid` and verify this proof.
    /// Returns false if the recomputed leaf hash does not match `self.leaf_hash`.
    pub fn verify_with_kv(&self, key: &str, fid: &str) -> bool {
        let leaf = leaf_hash(key, fid);
        if leaf != self.leaf_hash {
            return false;
        }
        self.verify()
    }
}

#[derive(Debug, Clone)]
pub struct QueryResponse {
    /// found fid if present
    pub fid: Option<String>,
    /// membership proof for the found leaf (if any)
    pub proof: Option<Proof>,
    /// root hash of the subtree used to produce the proof
    pub root_hash: Option<Hash>,
    /// accumulator value (G1Affine) for the subtree's keys
    pub accumulator: Option<G1Affine>,
    /// membership witness (G1Affine) for the element in the subtree's accumulator
    pub membership_witness: Option<G1Affine>,
    /// non-membership proof when the key is not found
    pub nonmembership: Option<NonMembershipProof>,
}

impl QueryResponse {
    pub fn new(
        fid: Option<String>,
        proof: Option<Proof>,
        root_hash: Option<Hash>,
        accumulator: Option<G1Affine>,
        membership_witness: Option<G1Affine>,
        nonmembership: Option<NonMembershipProof>,
    ) -> Self {
        Self {
            fid,
            proof,
            root_hash,
            accumulator,
            membership_witness,
            nonmembership,
        }
    }

    /// Verify both the Merkle path (leaf correctness) and the accumulator membership witness.
    /// Returns true only if both checks pass. Requires the original `key` and `fid` used
    /// to build the leaf hash.
    pub fn verify_full(&self, key: &str, fid: &str) -> bool {
        // verify Merkle path using provided key/fid (prevents leaf tampering)
        let merkle_ok = match (&self.root_hash, &self.proof) {
            (Some(_root), Some(p)) => p.verify_with_kv(key, fid),
            _ => false,
        };
        if !merkle_ok {
            return false;
        }

        // verify accumulator membership: acc + element_commitment == acc (via witness)
        match (&self.accumulator, &self.membership_witness) {
            (Some(acc), Some(witness)) => {
                acc::Acc::verify_membership(acc, witness, &key.to_string())
            }
            _ => false,
        }
    }
}

#[derive(Debug, Clone)]
pub struct InsertResponse {
    /// key inserted
    pub key: String,
    /// fid inserted
    pub fid: String,
    /// snapshot of roots before insertion: vector of (root_hash, acc)
    pub pre_roots: Vec<(Hash, G1Affine)>,
    /// snapshot of root hash after insertion (the root that contains the inserted key)
    pub post_root_hash: Option<Hash>,
    /// accumulator value after insertion for the root containing the key
    pub post_accumulator: Option<G1Affine>,
    /// merkle/path proof for the inserted leaf after insertion
    pub post_proof: Option<Proof>,
    /// membership witness for the inserted element in the post_accumulator
    pub post_membership_witness: Option<G1Affine>,
    /// optional non-membership proof captured before insertion
    pub pre_nonmembership: Option<NonMembershipProof>,
}

impl InsertResponse {
    pub fn new(
        key: String,
        fid: String,
        pre_roots: Vec<(Hash, G1Affine)>,
        post_root_hash: Option<Hash>,
        post_accumulator: Option<G1Affine>,
        post_proof: Option<Proof>,
        post_membership_witness: Option<G1Affine>,
        pre_nonmembership: Option<NonMembershipProof>,
    ) -> Self {
        Self {
            key,
            fid,
            pre_roots,
            post_root_hash,
            post_accumulator,
            post_proof,
            post_membership_witness,
            pre_nonmembership,
        }
    }
}

#[derive(Debug, Clone)]
pub struct NonMembershipProof {
    /// predecessor: (key, fid, proof)
    pub pred: Option<(String, String, Proof)>,
    /// successor: (key, fid, proof)
    pub succ: Option<(String, String, Proof)>,
}

impl NonMembershipProof {
    pub fn new(
        pred: Option<(String, String, Proof)>,
        succ: Option<(String, String, Proof)>,
    ) -> Self {
        Self { pred, succ }
    }

    /// Verify non-membership with respect to provided key.
    /// Returns true if proofs for pred/succ (if present) validate and ordering holds.
    pub fn verify(&self, key: &str) -> bool {
        // verify predecessor proof and ordering
        if let Some((pkey, _pfid, pproof)) = &self.pred {
            if !pproof.verify() {
                return false;
            }
            if !(pkey.as_str() < key) {
                return false;
            }
        }

        // verify successor proof and ordering
        if let Some((skey, _sfid, sproof)) = &self.succ {
            if !sproof.verify() {
                return false;
            }
            if !(key < skey.as_str()) {
                return false;
            }
        }

        // if both absent, tree is empty -> non-membership trivially true
        true
    }
}

#[derive(Debug, Clone)]
pub struct UpdateResponse {
    /// key updated
    pub key: String,
    /// fid before update
    pub old_fid: Option<String>,
    /// fid after update
    pub new_fid: String,
    /// membership proof for the leaf before update
    pub pre_proof: Option<Proof>,
    /// accumulator value before update (for the root containing the key)
    pub pre_accumulator: Option<G1Affine>,
    /// membership witness for the old element
    pub pre_membership_witness: Option<G1Affine>,
    /// membership proof for the leaf after update
    pub post_proof: Proof,
    /// accumulator value after update (for the root containing the key)
    pub post_accumulator: G1Affine,
    /// membership witness for the new element
    pub post_membership_witness: G1Affine,
    /// root hash before update (if available)
    pub pre_root_hash: Option<Hash>,
    /// root hash after update
    pub post_root_hash: Hash,
}

impl UpdateResponse {
    pub fn new(
        key: String,
        old_fid: Option<String>,
        new_fid: String,
        pre_proof: Option<Proof>,
        pre_acc: Option<G1Affine>,
        pre_acc_witness: Option<G1Affine>,
        post_proof: Proof,
        post_acc: G1Affine,
        post_acc_witness: G1Affine,
        pre_root_hash: Option<Hash>,
        post_root_hash: Hash,
    ) -> Self {
        Self {
            key,
            old_fid,
            new_fid,
            pre_proof,
            pre_accumulator: pre_acc,
            pre_membership_witness: pre_acc_witness,
            post_proof,
            post_accumulator: post_acc,
            post_membership_witness: post_acc_witness,
            pre_root_hash,
            post_root_hash,
        }
    }

    /// Verify that the update was well-formed: pre/post proofs are valid and the
    /// Merkle path siblings match (i.e. only the leaf changed), and accumulator
    /// membership holds for old/new values respectively when provided.
    pub fn verify_update(&self) -> bool {
        // verify pre proof if present
        if let Some(pre_p) = &self.pre_proof {
            if !pre_p.verify() {
                return false;
            }
        }

        // verify post proof
        if !self.post_proof.verify() {
            return false;
        }

        // sibling paths (excluding leaf_hash) should match between pre and post
        if let Some(pre_p) = &self.pre_proof {
            if pre_p.path.len() != self.post_proof.path.len() {
                return false;
            }
            for (i, (psib, pleft)) in pre_p.path.iter().enumerate() {
                let (qsib, qleft) = &self.post_proof.path[i];
                if psib != qsib || pleft != qleft {
                    return false;
                }
            }
        }

        // verify accumulator membership: pre (old) and post (new)
        if let (Some(acc), Some(w)) = (&self.pre_accumulator, &self.pre_membership_witness) {
            if let Some(_old) = &self.old_fid {
                if !acc::Acc::verify_membership(acc, w, &self.key) {
                    return false;
                }
            }
        }

        if !acc::Acc::verify_membership(
            &self.post_accumulator,
            &self.post_membership_witness,
            &self.key,
        ) {
            return false;
        }

        true
    }
}

#[derive(Debug, Clone)]
pub struct DeleteResponse {
    /// key deleted
    pub key: String,
    /// fid before deletion
    pub old_fid: Option<String>,
    /// membership proof for the leaf before deletion
    pub pre_proof: Option<Proof>,
    /// accumulator value before deletion (for the root containing the key)
    pub pre_accumulator: Option<G1Affine>,
    /// membership witness for the old element
    pub pre_membership_witness: Option<G1Affine>,
    /// merkle/path proof for the tombstoned leaf after deletion (leaf hash will be empty_hash)
    pub post_proof: Proof,
    /// accumulator value after deletion for the root containing the tombstone
    pub post_accumulator: G1Affine,
    /// root hash before deletion (if available)
    pub pre_root_hash: Option<Hash>,
    /// root hash after deletion
    pub post_root_hash: Hash,
}

impl DeleteResponse {
    pub fn new(
        key: String,
        old_fid: Option<String>,
        pre_proof: Option<Proof>,
        pre_acc: Option<G1Affine>,
        pre_acc_witness: Option<G1Affine>,
        post_proof: Proof,
        post_acc: G1Affine,
        pre_root_hash: Option<Hash>,
        post_root_hash: Hash,
    ) -> Self {
        Self {
            key,
            old_fid,
            pre_proof,
            pre_accumulator: pre_acc,
            pre_membership_witness: pre_acc_witness,
            post_proof,
            post_accumulator: post_acc,
            pre_root_hash,
            post_root_hash,
        }
    }

    /// Verify deletion: pre/post proofs validate and sibling paths match (only leaf changed),
    /// and pre-acc membership holds for the deleted key when provided.
    pub fn verify_delete(&self) -> bool {
        // verify pre proof if present
        if let Some(pre_p) = &self.pre_proof {
            if !pre_p.verify() {
                return false;
            }
        }

        // verify post proof
        if !self.post_proof.verify() {
            return false;
        }

        // sibling paths should match between pre and post
        if let Some(pre_p) = &self.pre_proof {
            if pre_p.path.len() != self.post_proof.path.len() {
                return false;
            }
            for (i, (psib, pleft)) in pre_p.path.iter().enumerate() {
                let (qsib, qleft) = &self.post_proof.path[i];
                if psib != qsib || pleft != qleft {
                    return false;
                }
            }
        }

        // verify accumulator membership for pre-state (old element)
        if let (Some(acc), Some(w)) = (&self.pre_accumulator, &self.pre_membership_witness) {
            if let Some(_old) = &self.old_fid {
                if !acc::Acc::verify_membership(acc, w, &self.key) {
                    return false;
                }
            }
        }

        true
    }
}
