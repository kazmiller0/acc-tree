use accumulator_ads::{DynamicAccumulator, G1Affine, Set};
use lazy_static::lazy_static;
use sha2::{Digest, Sha256};

pub type Hash = [u8; 32];

lazy_static! {
    pub static ref EMPTY_HASH: Hash = leaf_hash_fids("", &Set::new());
    pub static ref EMPTY_ACC: G1Affine = DynamicAccumulator::empty_commitment();
}

pub fn empty_hash() -> Hash {
    *EMPTY_HASH
}

pub fn empty_acc() -> G1Affine {
    *EMPTY_ACC
}

/// Hash a leaf node with key and a set of fids (document IDs)
/// For determinism, fids are sorted before hashing
pub fn leaf_hash_fids(key: &str, fids: &Set<String>) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update((key.len() as u32).to_be_bytes());
    hasher.update(key.as_bytes());

    // Sort fids for deterministic hashing
    let mut fids_vec: Vec<String> = fids.iter().cloned().collect();
    fids_vec.sort();

    hasher.update((fids_vec.len() as u32).to_be_bytes());
    for fid in fids_vec {
        hasher.update((fid.len() as u32).to_be_bytes());
        hasher.update(fid.as_bytes());
    }
    hasher.finalize().into()
}

/// Compatibility wrapper for single fid
#[deprecated(note = "Use leaf_hash_fids instead")]
pub fn leaf_hash(key: &str, fid: &str) -> Hash {
    leaf_hash_fids(key, &Set::from_vec(vec![fid.to_string()]))
}

pub fn nonleaf_hash(left: Hash, right: Hash) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// Unit tests for cryptographic hash functions
///
/// These tests verify hash function properties: determinism, collision resistance, etc.
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_leaf_hash_fids_deterministic() {
        let fids = Set::from_vec(vec!["fid".to_string()]);
        let hash1 = leaf_hash_fids("key", &fids);
        let hash2 = leaf_hash_fids("key", &fids);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_leaf_hash_fids_different_keys() {
        let fids = Set::from_vec(vec!["fid".to_string()]);
        let hash1 = leaf_hash_fids("key1", &fids);
        let hash2 = leaf_hash_fids("key2", &fids);
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_leaf_hash_fids_different_fids() {
        let fids1 = Set::from_vec(vec!["fid1".to_string()]);
        let fids2 = Set::from_vec(vec!["fid2".to_string()]);
        let hash1 = leaf_hash_fids("key", &fids1);
        let hash2 = leaf_hash_fids("key", &fids2);
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_leaf_hash_fids_empty_set() {
        let empty_fids = Set::new();
        let hash = leaf_hash_fids("", &empty_fids);
        assert_eq!(hash, *EMPTY_HASH);
    }

    #[test]
    fn test_leaf_hash_fids_set_order_independence() {
        // Set order should not affect hash due to sorting
        let fids1 = Set::from_vec(vec!["a".to_string(), "b".to_string(), "c".to_string()]);
        let fids2 = Set::from_vec(vec!["c".to_string(), "a".to_string(), "b".to_string()]);
        let hash1 = leaf_hash_fids("key", &fids1);
        let hash2 = leaf_hash_fids("key", &fids2);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_leaf_hash_backward_compat() {
        // Old single-fid hash should match new hash with single-element set
        let fids = Set::from_vec(vec!["fid".to_string()]);
        let new_hash = leaf_hash_fids("key", &fids);
        #[allow(deprecated)]
        let old_hash = leaf_hash("key", "fid");
        assert_eq!(new_hash, old_hash);
    }

    #[test]
    fn test_nonleaf_hash_deterministic() {
        let left = leaf_hash_fids("a", &Set::from_vec(vec!["fa".to_string()]));
        let right = leaf_hash_fids("b", &Set::from_vec(vec!["fb".to_string()]));
        let hash1 = nonleaf_hash(left, right);
        let hash2 = nonleaf_hash(left, right);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_nonleaf_hash_order_matters() {
        let left = leaf_hash_fids("a", &Set::from_vec(vec!["fa".to_string()]));
        let right = leaf_hash_fids("b", &Set::from_vec(vec!["fb".to_string()]));
        let hash1 = nonleaf_hash(left, right);
        let hash2 = nonleaf_hash(right, left);
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_empty_hash_is_cached() {
        let hash1 = empty_hash();
        let hash2 = empty_hash();
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_empty_acc_is_cached() {
        // Need to initialize params for this test
        use accumulator_ads::acc::setup::{PublicParameters, init_public_parameters_direct};
        use ark_bls12_381::Fr;
        use std::sync::Once;

        static INIT: Once = Once::new();
        INIT.call_once(|| {
            let secret_s = Fr::from(123456789u128);
            let params = PublicParameters::generate_for_testing(secret_s, 10);
            init_public_parameters_direct(params).expect("Failed to initialize");
        });

        let acc1 = empty_acc();
        let acc2 = empty_acc();
        assert_eq!(acc1, acc2);
    }

    #[test]
    fn test_hash_output_length() {
        let fids = Set::from_vec(vec!["test".to_string()]);
        let hash = leaf_hash_fids("test", &fids);
        assert_eq!(hash.len(), 32);
    }
}
