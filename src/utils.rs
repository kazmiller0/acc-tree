use crate::{AccumulatorTree, Node};
use accumulator_ads::{DynamicAccumulator, G1Affine, Set};
use lazy_static::lazy_static;
use sha2::{Digest, Sha256};

pub type Hash = [u8; 32];

lazy_static! {
    // Empty hash now represents a default empty leaf node
    pub static ref EMPTY_HASH: Hash = leaf_hash("", &Set::new(), 0, false);
    pub static ref EMPTY_ACC: G1Affine = DynamicAccumulator::empty_commitment();
}

pub fn empty_hash() -> Hash {
    *EMPTY_HASH
}

pub fn empty_acc() -> G1Affine {
    *EMPTY_ACC
}

/// Hash a leaf node with key, fids, level, and deleted status
/// key: Unique identifier
/// fids: Set of document IDs (sorted for determinism)
/// level: Tree level (usually 0 for leaves)
/// deleted: Tombstone status
pub fn leaf_hash(key: &str, fids: &Set<String>, level: usize, deleted: bool) -> Hash {
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

    // Include metadata
    hasher.update((level as u64).to_le_bytes());
    hasher.update(&[(if deleted { 1 } else { 0 }) as u8]);

    hasher.finalize().into()
}

pub fn nonleaf_hash(left: Hash, right: Hash) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(left);
    hasher.update(right);
    hasher.finalize().into()
}

/// 打印森林的完整状态
pub fn print_tree(tree: &AccumulatorTree) {
    println!("Tree State (Roots: {}):", tree.roots.len());
    for (i, node) in tree.roots.iter().enumerate() {
        let n: &Node = node.as_ref();
        println!(
            "  Root[{}]: Level {}, Hash {}, Keys {}",
            i,
            n.level(),
            hex::encode(n.hash()),
            render_keys(n)
        );
    }
}

/// 将节点的 Key 集合渲染为排序后的字符串
pub fn render_keys(node: &Node) -> String {
    let keys = node.keys();
    let mut entries: Vec<_> = keys.iter().cloned().collect();
    entries.sort();
    format!("{:?}", entries)
}

/// Unit tests for cryptographic hash functions
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_leaf_hash_deterministic() {
        let fids = Set::from_vec(vec!["fid".to_string()]);
        let hash1 = leaf_hash("key", &fids, 0, false);
        let hash2 = leaf_hash("key", &fids, 0, false);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_leaf_hash_different_keys() {
        let fids = Set::from_vec(vec!["fid".to_string()]);
        let hash1 = leaf_hash("key1", &fids, 0, false);
        let hash2 = leaf_hash("key2", &fids, 0, false);
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_leaf_hash_different_fids() {
        let fids1 = Set::from_vec(vec!["fid1".to_string()]);
        let fids2 = Set::from_vec(vec!["fid2".to_string()]);
        let hash1 = leaf_hash("key", &fids1, 0, false);
        let hash2 = leaf_hash("key", &fids2, 0, false);
        assert_ne!(hash1, hash2);
    }

    #[test]
    fn test_leaf_hash_empty_set() {
        let empty_fids = Set::new();
        let hash = leaf_hash("", &empty_fids, 0, false);
        assert_eq!(hash, *EMPTY_HASH);
    }

    #[test]
    fn test_leaf_hash_set_order_independence() {
        // Set order should not affect hash due to sorting
        let fids1 = Set::from_vec(vec!["a".to_string(), "b".to_string(), "c".to_string()]);
        let fids2 = Set::from_vec(vec!["c".to_string(), "a".to_string(), "b".to_string()]);
        let hash1 = leaf_hash("key", &fids1, 0, false);
        let hash2 = leaf_hash("key", &fids2, 0, false);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_nonleaf_hash_deterministic() {
        let left = leaf_hash("a", &Set::from_vec(vec!["fa".to_string()]), 0, false);
        let right = leaf_hash("b", &Set::from_vec(vec!["fb".to_string()]), 0, false);
        let hash1 = nonleaf_hash(left, right);
        let hash2 = nonleaf_hash(left, right);
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn test_nonleaf_hash_order_matters() {
        let left = leaf_hash("a", &Set::from_vec(vec!["fa".to_string()]), 0, false);
        let right = leaf_hash("b", &Set::from_vec(vec!["fb".to_string()]), 0, false);
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
        let hash = leaf_hash("test", &fids, 0, false);
        assert_eq!(hash.len(), 32);
    }
}
