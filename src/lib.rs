use acc::{Acc, Accumulator, G1Affine, MultiSet};
use ark_ec::{AffineCurve, ProjectiveCurve};
use sha2::{Digest, Sha256};
use std::rc::Rc;
use std::time::Instant;

// --- 1. 类型定义与基础哈希工具 ---
type Hash = [u8; 32];

fn leaf_hash(key: &str, fid: &str) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update((key.len() as u32).to_be_bytes());
    hasher.update(key.as_bytes());
    hasher.update((fid.len() as u32).to_be_bytes());
    hasher.update(fid.as_bytes());
    hasher.finalize().into()
}

fn nonleaf_hash(left: Hash, right: Hash) -> Hash {
    let mut hasher = Sha256::new();
    hasher.update(&left);
    hasher.update(&right);
    hasher.finalize().into()
}

// --- 2. 核心数据模型 (Node) ---
#[derive(Debug, Clone)]
pub enum Node {
    Leaf {
        key: String,
        fid: String,
        level: usize,
    },
    NonLeaf {
        hash: Hash,
        keys: Rc<MultiSet<String>>,
        acc: G1Affine,
        level: usize,
        left: Box<Node>,
        right: Box<Node>,
    },
}

impl Node {
    pub fn level(&self) -> usize {
        match self {
            Node::Leaf { level, .. } => *level,
            Node::NonLeaf { level, .. } => *level,
        }
    }

    pub fn hash_bytes(&self) -> Hash {
        match self {
            Node::Leaf { key, fid, .. } => leaf_hash(key, fid),
            Node::NonLeaf { hash, .. } => *hash,
        }
    }

    pub fn hash(&self) -> Hash {
        self.hash_bytes()
    }

    pub fn acc(&self) -> G1Affine {
        match self {
            Node::Leaf { key, .. } => {
                let keys = MultiSet::from_vec(vec![key.clone()]);
                Acc::cal_acc_g1(&keys)
            }
            Node::NonLeaf { acc, .. } => acc.clone(),
        }
    }

    pub fn has_key(&self, target_key: &str) -> bool {
        match self {
            Node::Leaf { key, .. } => key == target_key,
            Node::NonLeaf { keys, .. } => keys.contains_key(target_key),
        }
    }

    pub fn collect_leaves(&self, exclude_key: Option<&str>) -> Vec<(String, String)> {
        let mut leaves = Vec::new();
        match self {
            Node::Leaf { key, fid, .. } => {
                if Some(key.as_str()) != exclude_key {
                    leaves.push((key.clone(), fid.clone()));
                }
            }
            Node::NonLeaf { left, right, .. } => {
                leaves.extend(left.collect_leaves(exclude_key));
                leaves.extend(right.collect_leaves(exclude_key));
            }
        }
        leaves
    }
}

// --- 3. 核心节点合并算法 ---
fn merge(r_old: Box<Node>, curr: Box<Node>) -> Box<Node> {
    let new_level = curr.level() + 1;
    let combined_hash = nonleaf_hash(r_old.hash_bytes(), curr.hash_bytes());

    let left_keys_rc: Rc<MultiSet<String>> = match &*r_old {
        Node::Leaf { key, .. } => Rc::new(MultiSet::from_vec(vec![key.clone()])),
        Node::NonLeaf { keys, .. } => keys.clone(),
    };

    let right_keys_rc: Rc<MultiSet<String>> = match &*curr {
        Node::Leaf { key, .. } => Rc::new(MultiSet::from_vec(vec![key.clone()])),
        Node::NonLeaf { keys, .. } => keys.clone(),
    };

    let merged_keys = &*left_keys_rc + &*right_keys_rc;
    let merged_keys_rc = Rc::new(merged_keys);

    let left_acc = r_old.acc();
    let right_acc = curr.acc();
    let mut acc_proj = left_acc.into_projective();
    acc_proj.add_assign_mixed(&right_acc);
    let acc = acc_proj.into_affine();

    Box::new(Node::NonLeaf {
        hash: combined_hash,
        keys: merged_keys_rc,
        acc,
        level: new_level,
        left: r_old,
        right: curr,
    })
}

fn node_keys_from(node: &Box<Node>) -> MultiSet<String> {
    match &**node {
        Node::Leaf { key, .. } => MultiSet::from_vec(vec![key.clone()]),
        Node::NonLeaf { keys, .. } => keys.as_ref().clone(),
    }
}

// --- 4. 递归处理逻辑 (Delete & Update) ---
fn delete_recursive(node: Box<Node>, target_key: &str) -> Option<Box<Node>> {
    match *node {
        Node::Leaf { key, fid, level } => {
            if key == target_key {
                None
            } else {
                Some(Box::new(Node::Leaf { key, fid, level }))
            }
        }
        Node::NonLeaf {
            level, left, right, ..
        } => {
            let subtree_keys = {
                let mut ks = node_keys_from(&left);
                ks = &ks + &node_keys_from(&right);
                ks
            };
            if !subtree_keys.contains_key(target_key) {
                let combined_hash = nonleaf_hash(left.hash_bytes(), right.hash_bytes());
                let mut acc_proj = left.acc().into_projective();
                acc_proj.add_assign_mixed(&right.acc());
                let acc = acc_proj.into_affine();
                return Some(Box::new(Node::NonLeaf {
                    hash: combined_hash,
                    keys: Rc::new(subtree_keys),
                    acc,
                    level,
                    left,
                    right,
                }));
            }

            let left_res = delete_recursive(left, target_key);
            let right_res = delete_recursive(right, target_key);

            match (left_res, right_res) {
                (Some(l), Some(r)) => {
                    let combined_hash = nonleaf_hash(l.hash_bytes(), r.hash_bytes());
                    let mut acc_proj = l.acc().into_projective();
                    acc_proj.add_assign_mixed(&r.acc());
                    let acc = acc_proj.into_affine();
                    let merged = &node_keys_from(&l) + &node_keys_from(&r);
                    Some(Box::new(Node::NonLeaf {
                        hash: combined_hash,
                        keys: Rc::new(merged),
                        acc,
                        level,
                        left: l,
                        right: r,
                    }))
                }
                (Some(l), None) => Some(l),
                (None, Some(r)) => Some(r),
                (None, None) => None,
            }
        }
    }
}

fn update_recursive(node: &mut Box<Node>, target_key: &str, new_fid: &str) -> (bool, bool) {
    match **node {
        Node::Leaf {
            ref mut fid,
            ref key,
            ..
        } => {
            if key == target_key {
                *fid = new_fid.to_string();
                return (true, false);
            }
            (false, false)
        }
        Node::NonLeaf {
            ref mut hash,
            ref keys,
            ref mut acc,
            ref mut left,
            ref mut right,
            ..
        } => {
            if !keys.contains_key(target_key) {
                return (false, false);
            }

            let (l_h, l_a) = update_recursive(left, target_key, new_fid);
            let (r_h, r_a) = update_recursive(right, target_key, new_fid);

            let h_changed = l_h || r_h;
            let a_changed = l_a || r_a;

            if h_changed {
                *hash = nonleaf_hash(left.hash_bytes(), right.hash_bytes());
            }
            if a_changed {
                let mut acc_proj = left.acc().into_projective();
                acc_proj.add_assign_mixed(&right.acc());
                *acc = acc_proj.into_affine();
            }
            (h_changed, a_changed)
        }
    }
}

// --- 5. 对外公开的 AccumulatorTree ---
pub struct AccumulatorTree {
    pub roots: Vec<Box<Node>>,
}

impl AccumulatorTree {
    pub fn new() -> Self {
        AccumulatorTree { roots: Vec::new() }
    }

    pub fn insert(&mut self, key: String, fid: String) {
        let curr = Box::new(Node::Leaf { key, fid, level: 0 });
        self.merge_root(curr);
    }

    pub fn update(&mut self, key: &str, new_fid: String) {
        if let Some(root) = self.roots.iter_mut().find(|r| r.has_key(key)) {
            update_recursive(root, key, &new_fid);
        } else {
            println!("Key {} not found for update", key);
        }
    }

    pub fn delete(&mut self, key: &str) {
        if let Some(idx) = self.roots.iter().position(|r| r.has_key(key)) {
            let root = self.roots.remove(idx);
            if let Some(new_root) = delete_recursive(root, key) {
                self.roots.push(new_root);
                self.roots.sort_by_key(|n| n.level());
            }
        } else {
            println!("Key {} not found for delete", key);
        }
    }

    fn merge_root(&mut self, mut node: Box<Node>) {
        loop {
            if let Some(idx) = self.roots.iter().position(|r| r.level() == node.level()) {
                let other = self.roots.remove(idx);
                node = merge(other, node);
            } else {
                self.roots.push(node);
                self.roots.sort_by_key(|n| n.level());
                break;
            }
        }
    }
}

// --- 6. 辅助工具与基准测试 ---
fn print_tree(tree: &AccumulatorTree) {
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

fn render_keys(node: &Node) -> String {
    let keys = match node {
        Node::Leaf { key, .. } => MultiSet::from_vec(vec![key.clone()]),
        Node::NonLeaf { keys, .. } => keys.as_ref().clone(),
    };
    let mut entries: Vec<_> = keys.iter().map(|(k, v)| (k.clone(), *v)).collect();
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    format!("{:?}", entries)
}

pub fn demo() {
    let mut tree = AccumulatorTree::new();
    println!("--- Insert 1 ---");
    tree.insert("Key1".to_string(), "Fid1".to_string());
    print_tree(&tree);
    println!("\n--- Insert 2 ---");
    tree.insert("Key2".to_string(), "Fid2".to_string());
    print_tree(&tree);
    println!("\n--- Insert 3 ---");
    tree.insert("Key3".to_string(), "Fid3".to_string());
    print_tree(&tree);
    println!("\n--- Update Key3 ---");
    tree.update("Key3", "Fid3_Updated".to_string());
    print_tree(&tree);
    println!("\n--- Delete Key2 ---");
    tree.delete("Key2");
    print_tree(&tree);
}

pub fn run_benchmark(n: usize) {
    println!("Running benchmark with {} keys", n);
    let mut tree = AccumulatorTree::new();
    let t0 = Instant::now();
    for i in 0..n {
        tree.insert(format!("Key{}", i), format!("Fid{}", i));
    }
    let dur_ins = t0.elapsed();
    let t1 = Instant::now();
    for i in (0..n).step_by(10) {
        tree.update(&format!("Key{}", i), format!("Fid{}_u", i));
    }
    let dur_upd = t1.elapsed();
    let t2 = Instant::now();
    for i in (0..n).step_by(5) {
        tree.delete(&format!("Key{}", i));
    }
    let dur_del = t2.elapsed();
    let t3 = Instant::now();
    let mut found = 0usize;
    for i in 0..n {
        let key = format!("Key{}", i);
        if tree.roots.iter().any(|r| r.has_key(&key)) {
            found += 1;
        }
    }
    let dur_q = t3.elapsed();
    let sample = std::cmp::min(1000, n);
    let t4 = Instant::now();
    let mut verify_ok = 0usize;
    for i in 0..sample {
        let key = format!("Key{}", (i * 13) % n);
        if let Some(idx) = tree.roots.iter().position(|r| r.has_key(&key)) {
            let acc = tree.roots[idx].acc();
            let witness = Acc::create_witness(&acc, &key);
            if Acc::verify_membership(&acc, &witness, &key) {
                verify_ok += 1;
            }
        }
    }
    let dur_v = t4.elapsed();
    println!(
        "Insert: total {:?}, per-op {:?}",
        dur_ins,
        dur_ins / (n as u32)
    );
    println!(
        "Update: total {:?}, per-op {:?}",
        dur_upd,
        dur_upd / ((n / 10) as u32)
    );
    println!(
        "Delete: total {:?}, per-op {:?}",
        dur_del,
        dur_del / ((n / 5) as u32)
    );
    println!(
        "Query: total {:?}, per-op {:?}, found {}/{}",
        dur_q,
        dur_q / (n as u32),
        found,
        n
    );
    println!(
        "Verify(sample {}): total {:?}, ok {}/{}",
        sample, dur_v, verify_ok, sample
    );
}

// --- 7. 单元测试 ---
#[cfg(test)]
mod tests {
    use super::*;
    fn verify_node_invariant(node: &Box<Node>) {
        match &**node {
            Node::Leaf { key, fid, .. } => {
                assert_eq!(node.hash_bytes(), leaf_hash(key, fid));
                assert_eq!(
                    node.acc(),
                    Acc::cal_acc_g1(&MultiSet::from_vec(vec![key.clone()]))
                );
            }
            Node::NonLeaf {
                hash,
                keys,
                acc,
                left,
                right,
                ..
            } => {
                let mut collected: Vec<String> = left
                    .collect_leaves(None)
                    .into_iter()
                    .chain(right.collect_leaves(None))
                    .map(|(k, _)| k)
                    .collect();
                collected.sort();
                let mut stored: Vec<String> =
                    keys.as_ref().iter().map(|(k, _)| k.clone()).collect();
                stored.sort();
                assert_eq!(collected, stored);
                assert_eq!(*acc, Acc::cal_acc_g1(keys.as_ref()));
                assert_eq!(*hash, nonleaf_hash(left.hash_bytes(), right.hash_bytes()));
                verify_node_invariant(left);
                verify_node_invariant(right);
            }
        }
    }

    #[test]
    fn test_tree_operations_invariants() {
        let mut tree = AccumulatorTree::new();
        for i in 0..8 {
            tree.insert(format!("K{}", i), format!("F{}", i));
        }
        for root in tree.roots.iter() {
            verify_node_invariant(root);
        }
        tree.update("K3", "F3_u".to_string());
        for root in tree.roots.iter() {
            verify_node_invariant(root);
        }
        tree.delete("K2");
        for root in tree.roots.iter() {
            verify_node_invariant(root);
        }
    }
}
