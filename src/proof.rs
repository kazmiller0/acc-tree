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

    /// Convenience: create a leaf hash from key and fid then verify using provided root and path
    pub fn verify_with_kv(root_hash: Hash, key: &str, fid: &str, path: Vec<(Hash, bool)>) -> bool {
        let leaf = leaf_hash(key, fid);
        let p = Proof::new(root_hash, leaf, path);
        p.verify()
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
    pub acc: Option<G1Affine>,
    /// accumulator witness (G1Affine) for the element in the subtree's accumulator
    pub acc_witness: Option<G1Affine>,
    /// non-membership proof when the key is not found
    pub nonmembership: Option<NonMembershipProof>,
}

impl QueryResponse {
    pub fn new(
        fid: Option<String>,
        proof: Option<Proof>,
        root_hash: Option<Hash>,
        acc: Option<G1Affine>,
        acc_witness: Option<G1Affine>,
        nonmembership: Option<NonMembershipProof>,
    ) -> Self {
        Self {
            fid,
            proof,
            root_hash,
            acc,
            acc_witness,
            nonmembership,
        }
    }

    /// Verify both the Merkle path (leaf correctness) and the accumulator membership witness.
    /// Returns true only if both checks pass. Requires the original `key` and `fid` used
    /// to build the leaf hash.
    pub fn verify_full(&self, key: &str, fid: &str) -> bool {
        // verify Merkle path using provided key/fid (prevents leaf tampering)
        let merkle_ok = match (self.root_hash, &self.proof) {
            (Some(root), Some(p)) => Proof::verify_with_kv(root, key, fid, p.path.clone()),
            _ => false,
        };
        if !merkle_ok {
            return false;
        }

        // verify accumulator membership: acc + element_commitment == acc (via witness)
        match (&self.acc, &self.acc_witness) {
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
    pub post_acc: Option<G1Affine>,
    /// merkle/path proof for the inserted leaf after insertion
    pub post_proof: Option<Proof>,
    /// accumulator witness for the inserted element in the post_acc
    pub post_acc_witness: Option<G1Affine>,
    /// optional non-membership proof captured before insertion
    pub pre_nonmembership: Option<NonMembershipProof>,
}

impl InsertResponse {
    pub fn new(
        key: String,
        fid: String,
        pre_roots: Vec<(Hash, G1Affine)>,
        post_root_hash: Option<Hash>,
        post_acc: Option<G1Affine>,
        post_proof: Option<Proof>,
        post_acc_witness: Option<G1Affine>,
        pre_nonmembership: Option<NonMembershipProof>,
    ) -> Self {
        Self {
            key,
            fid,
            pre_roots,
            post_root_hash,
            post_acc,
            post_proof,
            post_acc_witness,
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
// use acc::G1Affine;

// pub struct QueryResponse {
//     pub key: String,
//     pub fid: String,
//     pub merkle_path: Vec<(Hash, bool)>,
//     pub acc_witness: G1Affine,
// }
