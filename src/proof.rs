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
}

impl QueryResponse {
    pub fn new(
        fid: Option<String>,
        proof: Option<Proof>,
        root_hash: Option<Hash>,
        acc: Option<G1Affine>,
        acc_witness: Option<G1Affine>,
    ) -> Self {
        Self {
            fid,
            proof,
            root_hash,
            acc,
            acc_witness,
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
// use acc::G1Affine;

// pub struct QueryResponse {
//     pub key: String,
//     pub fid: String,
//     pub merkle_path: Vec<(Hash, bool)>,
//     pub acc_witness: G1Affine,
// }
