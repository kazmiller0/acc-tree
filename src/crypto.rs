use acc::{Acc, Accumulator, G1Affine, MultiSet};
use lazy_static::lazy_static;
use sha2::{Digest, Sha256};

pub type Hash = [u8; 32];

lazy_static! {
    pub static ref EMPTY_HASH: Hash = leaf_hash("", "");
    pub static ref EMPTY_ACC: G1Affine = Acc::cal_acc_g1(&MultiSet::<String>::new());
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
