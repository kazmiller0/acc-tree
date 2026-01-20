use crate::{Hash, leaf_hash_fids, nonleaf_hash};
use accumulator_ads::Set;

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

    /// Convenience: recompute the leaf hash from `key`/`fids` and verify this proof.
    /// Returns false if the recomputed leaf hash does not match `self.leaf_hash`.
    pub fn verify_with_kv(&self, key: &str, fids: &Set<String>) -> bool {
        let leaf = leaf_hash_fids(key, fids);
        if leaf != self.leaf_hash {
            return false;
        }
        self.verify()
    }
}

/// Unit tests for Merkle proof verification
/// 
/// These tests verify the correctness of proof construction and verification logic.
#[cfg(test)]
mod tests {
    use super::*;
    use crate::crypto::{leaf_hash_fids, nonleaf_hash};

    #[test]
    fn test_proof_verify_single_leaf() {
        // Single leaf: proof path is empty
        let key = "test_key";
        let fids = Set::from_vec(vec!["test_fid".to_string()]);
        let leaf = leaf_hash_fids(key, &fids);
        
        let proof = Proof::new(leaf, leaf, vec![]);
        
        assert!(proof.verify());
        assert!(proof.verify_with_kv(key, &fids));
    }

    #[test]
    fn test_proof_verify_two_leaves() {
        // Tree: (A, B)
        let key_a = "A";
        let fids_a = Set::from_vec(vec!["fa".to_string()]);
        let key_b = "B";
        let fids_b = Set::from_vec(vec!["fb".to_string()]);
        
        let leaf_a = leaf_hash_fids(key_a, &fids_a);
        let leaf_b = leaf_hash_fids(key_b, &fids_b);
        let root = nonleaf_hash(leaf_a, leaf_b);
        
        // Proof for A (B is right sibling)
        let proof_a = Proof::new(root, leaf_a, vec![(leaf_b, false)]);
        assert!(proof_a.verify());
        assert!(proof_a.verify_with_kv(key_a, &fids_a));
        
        // Proof for B (A is left sibling)
        let proof_b = Proof::new(root, leaf_b, vec![(leaf_a, true)]);
        assert!(proof_b.verify());
        assert!(proof_b.verify_with_kv(key_b, &fids_b));
    }

    #[test]
    fn test_proof_verify_deep_tree() {
        // Tree: ((A, B), (C, D))
        let leaf_a = leaf_hash_fids("A", &Set::from_vec(vec!["fa".to_string()]));
        let leaf_b = leaf_hash_fids("B", &Set::from_vec(vec!["fb".to_string()]));
        let leaf_c = leaf_hash_fids("C", &Set::from_vec(vec!["fc".to_string()]));
        let leaf_d = leaf_hash_fids("D", &Set::from_vec(vec!["fd".to_string()]));
        
        let left_subtree = nonleaf_hash(leaf_a, leaf_b);
        let right_subtree = nonleaf_hash(leaf_c, leaf_d);
        let root = nonleaf_hash(left_subtree, right_subtree);
        
        // Proof for A: path is [B (right), right_subtree (right)]
        let fids_a = Set::from_vec(vec!["fa".to_string()]);
        let proof_a = Proof::new(
            root,
            leaf_a,
            vec![(leaf_b, false), (right_subtree, false)],
        );
        assert!(proof_a.verify());
        assert!(proof_a.verify_with_kv("A", &fids_a));
        
        // Proof for D: path is [C (left), left_subtree (left)]
        let fids_d = Set::from_vec(vec!["fd".to_string()]);
        let proof_d = Proof::new(
            root,
            leaf_d,
            vec![(leaf_c, true), (left_subtree, true)],
        );
        assert!(proof_d.verify());
        assert!(proof_d.verify_with_kv("D", &fids_d));
    }

    #[test]
    fn test_proof_verify_fails_with_wrong_leaf() {
        let leaf_a = leaf_hash_fids("A", &Set::from_vec(vec!["fa".to_string()]));
        let leaf_b = leaf_hash_fids("B", &Set::from_vec(vec!["fb".to_string()]));
        let root = nonleaf_hash(leaf_a, leaf_b);
        
        // Create proof for A but try to verify with wrong key/fids
        let proof = Proof::new(root, leaf_a, vec![(leaf_b, false)]);
        assert!(!proof.verify_with_kv("Wrong", &Set::from_vec(vec!["Key".to_string()])));
    }

    #[test]
    fn test_proof_verify_fails_with_wrong_path() {
        let leaf_a = leaf_hash_fids("A", &Set::from_vec(vec!["fa".to_string()]));
        let leaf_b = leaf_hash_fids("B", &Set::from_vec(vec!["fb".to_string()]));
        let leaf_c = leaf_hash_fids("C", &Set::from_vec(vec!["fc".to_string()]));
        let root = nonleaf_hash(leaf_a, leaf_b);
        
        // Use wrong sibling in path
        let bad_proof = Proof::new(root, leaf_a, vec![(leaf_c, false)]);
        assert!(!bad_proof.verify());
    }

    #[test]
    fn test_proof_verify_fails_with_wrong_root() {
        let leaf_a = leaf_hash_fids("A", &Set::from_vec(vec!["fa".to_string()]));
        let leaf_b = leaf_hash_fids("B", &Set::from_vec(vec!["fb".to_string()]));
        let wrong_root = leaf_hash_fids("Wrong", &Set::from_vec(vec!["Root".to_string()]));
        
        // Valid path but wrong root
        let proof = Proof::new(wrong_root, leaf_a, vec![(leaf_b, false)]);
        assert!(!proof.verify());
    }
}
