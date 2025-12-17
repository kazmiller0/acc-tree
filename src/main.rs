use acc::{Acc, Accumulator, G1Affine, MultiSet};
use ark_ec::{AffineCurve, ProjectiveCurve};
use std::collections::HashMap;
use sha2::{Digest, Sha256};
use std::env;
use std::time::Instant;

type Hash = [u8; 32];

#[derive(Debug, Clone)]
enum Node {
    Leaf {
        key: String,
        fid: String,
        level: usize,
    },
    NonLeaf {
        hash: Hash,
        keys: MultiSet<String>,
        acc: G1Affine,
        level: usize,
        left: Box<Node>,
        right: Box<Node>,
    },
}

impl Node {
    fn level(&self) -> usize {
        match self {
            Node::Leaf { level, .. } => *level,
            Node::NonLeaf { level, .. } => *level,
        }
    }

    fn hash_bytes(&self) -> Hash {
        match self {
            Node::Leaf { key, fid, .. } => leaf_hash(key, fid),
            Node::NonLeaf { hash, .. } => *hash,
        }
    }

    fn hash(&self) -> Hash {
        self.hash_bytes()
    }

    fn acc(&self) -> G1Affine {
        match self {
            Node::Leaf { key, .. } => {
                let keys = MultiSet::from_vec(vec![key.clone()]);
                Acc::cal_acc_g1(&keys)
            }
            Node::NonLeaf { acc, .. } => acc.clone(),
        }
    }

    fn has_key(&self, target_key: &str) -> bool {
        match self {
            Node::Leaf { key, .. } => key == target_key,
            Node::NonLeaf { keys, .. } => keys.contains_key(target_key),
        }
    }

    fn collect_leaves(&self, exclude_key: Option<&str>) -> Vec<(String, String)> {
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

struct AccumulatorTree {
    roots: Vec<Box<Node>>,
    index: HashMap<String, usize>, // map key -> root index in `roots`
}

impl AccumulatorTree {
    fn new() -> Self {
        AccumulatorTree { roots: Vec::new(), index: HashMap::new() }
    }

    fn insert(&mut self, key: String, fid: String) {
        // keep a copy of `key` for index maintenance
        let key_copy = key.clone();
        let curr = Box::new(Node::Leaf { key: key, fid: fid, level: 0 });

        self.merge_root(curr);
        // incrementally update index for the single inserted key
        if let Some(idx) = self.roots.iter().position(|r| r.has_key(&key_copy)) {
            self.index.insert(key_copy, idx);
        }
    }

    fn merge_root(&mut self, mut node: Box<Node>) {
        loop {
            if let Some(idx) = self.roots.iter().position(|r| r.level() == node.level()) {
                let other = self.roots.remove(idx);
                node = merge(other, node);
            } else {
                self.roots.push(node);
                break;
            }
        }
        self.roots.sort_by_key(|n| n.level());
    }

    fn rebuild_index(&mut self) {
        self.index.clear();
        for (i, root) in self.roots.iter().enumerate() {
            for (k, _f) in root.collect_leaves(None) {
                self.index.insert(k, i);
            }
        }
    }

    fn update(&mut self, key: &str, new_fid: String) {
        if let Some(&idx) = self.index.get(key) {
            if idx < self.roots.len() {
                update_recursive(&mut self.roots[idx], key, &new_fid);
                // accs updated incrementally; index remains valid
                return;
            }
        }

        // fallback: index may be stale/missing -> locate root by scanning (only for this key)
        if let Some(idx) = self.roots.iter().position(|r| r.has_key(key)) {
            // insert mapping for future fast lookup
            self.index.insert(key.to_string(), idx);
            update_recursive(&mut self.roots[idx], key, &new_fid);
            return;
        }

        println!("Key {} not found for update", key);
    }

    fn delete(&mut self, key: &str) {
        // Prefer index lookup
        if let Some(&idx) = self.index.get(key) {
            if idx < self.roots.len() {
                let root = self.roots.remove(idx);
                if let Some(new_root) = delete_recursive(root, key) {
                    self.roots.push(new_root);
                    self.roots.sort_by_key(|n| n.level());
                }
                // remove only the deleted key from index (incremental)
                self.index.remove(key);
                return;
            }
        }

        // fallback: index may be missing/stale -> find root by scanning (only for this key)
        if let Some(idx) = self.roots.iter().position(|r| r.has_key(key)) {
            let root = self.roots.remove(idx);
            if let Some(new_root) = delete_recursive(root, key) {
                self.roots.push(new_root);
                self.roots.sort_by_key(|n| n.level());
            }
            self.index.remove(key);
            return;
        }

        println!("Key {} not found for delete", key);
    }
}

fn node_keys_from(node: &Box<Node>) -> MultiSet<String> {
    match &**node {
        Node::Leaf { key, .. } => MultiSet::from_vec(vec![key.clone()]),
        Node::NonLeaf { keys, .. } => keys.clone(),
    }
}

fn delete_recursive(node: Box<Node>, target_key: &str) -> Option<Box<Node>> {
    match *node {
        Node::Leaf { key, fid, level } => {
            if key == target_key {
                // remove this leaf
                None
            } else {
                Some(Box::new(Node::Leaf { key, fid, level }))
            }
        }
        Node::NonLeaf {
            hash: _,
            keys: _,
            acc: _,
            level,
            left,
            right,
        } => {
            // quick check: if this subtree doesn't contain the key, keep it
            let subtree_keys = {
                let mut ks = node_keys_from(&left);
                ks = &ks + &node_keys_from(&right);
                ks
            };
            if !subtree_keys.contains_key(target_key) {
                // reconstruct original node
                let mut left_child = left;
                let mut right_child = right;
                let combined_hash = nonleaf_hash(left_child.hash_bytes(), right_child.hash_bytes());
                let mut acc_proj = left_child.acc().into_projective();
                acc_proj.add_assign_mixed(&right_child.acc());
                let acc = acc_proj.into_affine();
                let keys = subtree_keys;
                return Some(Box::new(Node::NonLeaf {
                    hash: combined_hash,
                    keys,
                    acc,
                    level,
                    left: left_child,
                    right: right_child,
                }));
            }

            // otherwise descend
            let left_res = delete_recursive(left, target_key);
            let right_res = delete_recursive(right, target_key);

            match (left_res, right_res) {
                (Some(l), Some(r)) => {
                    // both children remain -> rebuild nonleaf
                    let combined_hash = nonleaf_hash(l.hash_bytes(), r.hash_bytes());
                    let mut acc_proj = l.acc().into_projective();
                    acc_proj.add_assign_mixed(&r.acc());
                    let acc = acc_proj.into_affine();
                    let keys = {
                        let lk = node_keys_from(&l);
                        let rk = node_keys_from(&r);
                        &lk + &rk
                    };
                    Some(Box::new(Node::NonLeaf {
                        hash: combined_hash,
                        keys,
                        acc,
                        level,
                        left: l,
                        right: r,
                    }))
                }
                (Some(l), None) => {
                    // promote left
                    Some(l)
                }
                (None, Some(r)) => {
                    // promote right
                    Some(r)
                }
                (None, None) => None,
            }
        }
    }
}

fn update_recursive(node: &mut Box<Node>, target_key: &str, new_fid: &str) -> bool {
    match **node {
        Node::Leaf {
            ref mut fid,
            ref key,
            ..
        } => {
            if key == target_key {
                *fid = new_fid.to_string();
                return true;
            }
            false
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
                return false;
            }

            let mut changed = false;
            if update_recursive(left, target_key, new_fid) {
                changed = true;
            }
            if update_recursive(right, target_key, new_fid) {
                changed = true;
            }

            if changed {
                // Recompute hash = H(left.hash || right.hash)
                *hash = nonleaf_hash(left.hash_bytes(), right.hash_bytes());
                // Incremental update: recompute accumulator by adding children accumulators
                let mut acc_proj = left.acc().into_projective();
                acc_proj.add_assign_mixed(&right.acc());
                *acc = acc_proj.into_affine();
            }

            changed
        }
    }
}

fn merge(r_old: Box<Node>, curr: Box<Node>) -> Box<Node> {
    let new_level = curr.level() + 1;
    let combined_hash = nonleaf_hash(r_old.hash_bytes(), curr.hash_bytes());

    let left_keys = match &*r_old {
        Node::Leaf { key, .. } => MultiSet::from_vec(vec![key.clone()]),
        Node::NonLeaf { keys, .. } => keys.clone(),
    };

    let right_keys = match &*curr {
        Node::Leaf { key, .. } => MultiSet::from_vec(vec![key.clone()]),
        Node::NonLeaf { keys, .. } => keys.clone(),
    };

    let merged_keys = &left_keys + &right_keys;
    // Compute accumulator incrementally by summing child accumulators
    let left_acc = r_old.acc();
    let right_acc = curr.acc();
    let mut acc_proj = left_acc.into_projective();
    acc_proj.add_assign_mixed(&right_acc);
    let acc = acc_proj.into_affine();

    // keep children boxes directly
    let left_child = r_old;
    let right_child = curr;

    Box::new(Node::NonLeaf {
        hash: combined_hash,
        keys: merged_keys,
        acc,
        level: new_level,
        left: left_child,
        right: right_child,
    })
}

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

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() > 1 && args[1] == "bench" {
        // optional second arg: number of keys
        let n: usize = args.get(2).and_then(|s| s.parse().ok()).unwrap_or(20000);
        run_benchmark(n);
        return;
    }

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

    println!("\n--- Insert 4 ---");
    tree.insert("Key4".to_string(), "Fid4".to_string());
    print_tree(&tree);

    println!("\n--- Insert 5 ---");
    tree.insert("Key5".to_string(), "Fid5".to_string());
    print_tree(&tree);

    println!("\n--- Update Key3 ---");
    tree.update("Key3", "Fid3_Updated".to_string());
    print_tree(&tree);

    println!("\n--- Delete Key2 ---");
    tree.delete("Key2");
    print_tree(&tree);
}

fn run_benchmark(n: usize) {
    println!("Running benchmark with {} keys", n);
    let mut tree = AccumulatorTree::new();

    // Insert
    let t0 = Instant::now();
    for i in 0..n {
        tree.insert(format!("Key{}", i), format!("Fid{}", i));
    }
    let dur_ins = t0.elapsed();

    // Update every 10th key
    let t1 = Instant::now();
    for i in (0..n).step_by(10) {
        tree.update(&format!("Key{}", i), format!("Fid{}_u", i));
    }
    let dur_upd = t1.elapsed();

    // Delete every 5th key
    let t2 = Instant::now();
    for i in (0..n).step_by(5) {
        tree.delete(&format!("Key{}", i));
    }
    let dur_del = t2.elapsed();

    println!("Insert: total {:?}, per-op {:?}", dur_ins, dur_ins / (n as u32));
    println!("Update: total {:?}, per-op {:?}", dur_upd, dur_upd / ((n/10) as u32));
    println!("Delete: total {:?}, per-op {:?}", dur_del, dur_del / ((n/5) as u32));
}

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
        Node::NonLeaf { keys, .. } => keys.clone(),
    };
    let mut entries: Vec<_> = keys.iter().map(|(k, v)| (k.clone(), *v)).collect();
    entries.sort_by(|a, b| a.0.cmp(&b.0));
    format!("{:?}", entries)
}
