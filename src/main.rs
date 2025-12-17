use acc::{Acc, Accumulator, G1Affine, MultiSet};
use ark_ec::{AffineCurve, ProjectiveCurve};
use sha2::{Digest, Sha256};

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
}

impl AccumulatorTree {
    fn new() -> Self {
        AccumulatorTree { roots: Vec::new() }
    }

    fn insert(&mut self, key: String, fid: String) {
        let curr = Box::new(Node::Leaf {
            key: key,
            fid: fid,
            level: 0,
        });

        self.merge_root(curr);
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

    fn update(&mut self, key: &str, new_fid: String) {
        for root in &mut self.roots {
            if root.has_key(key) {
                update_recursive(root, key, &new_fid);
                // Since we only update fid, the level structure doesn't change,
                // so we don't need to re-merge roots.
                return;
            }
        }
        println!("Key {} not found for update", key);
    }

    fn delete(&mut self, key: &str) {
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
