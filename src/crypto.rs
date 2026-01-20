use accumulator_ads::{DynamicAccumulator, G1Affine};
use lazy_static::lazy_static;
use sha2::{Digest, Sha256};

pub type Hash = [u8; 32];

lazy_static! {
    pub static ref EMPTY_HASH: Hash = leaf_hash("", "");
    pub static ref EMPTY_ACC: G1Affine = DynamicAccumulator::empty_commitment();
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
    fn test_leaf_hash_deterministic() {
        let hash1 = leaf_hash("key", "fid");
        let hash2 = leaf_hash("key", "fid");
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_leaf_hash_different_keys() {
        let hash1 = leaf_hash("key1", "fid");
        let hash2 = leaf_hash("key2", "fid");
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_leaf_hash_different_fids() {
        let hash1 = leaf_hash("key", "fid1");
        let hash2 = leaf_hash("key", "fid2");
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_leaf_hash_empty_strings() {
        let hash = leaf_hash("", "");
        assert_eq!(hash, *EMPTY_HASH);
    }

    #[test]
    fn test_leaf_hash_length_encoding() {
        // Ensure length encoding prevents collision between ("ab", "c") and ("a", "bc")
        let hash1 = leaf_hash("ab", "c");
        let hash2 = leaf_hash("a", "bc");
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_nonleaf_hash_deterministic() {
        let left = leaf_hash("a", "fa");
        let right = leaf_hash("b", "fb");
        let hash1 = nonleaf_hash(left, right);
        let hash2 = nonleaf_hash(left, right);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_nonleaf_hash_order_matters() {
        let left = leaf_hash("a", "fa");
        let right = leaf_hash("b", "fb");
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
        let hash = leaf_hash("test", "test");
        assert_eq!(hash.len(), 32);
    }
}
