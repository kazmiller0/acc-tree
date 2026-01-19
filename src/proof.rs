use crate::{Hash, leaf_hash, nonleaf_hash};

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

