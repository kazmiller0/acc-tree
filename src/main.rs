#[macro_use]
extern crate lazy_static;
#[macro_use]
extern crate log;

pub mod vchain;
use vchain::{Acc1, Accumulator, G1Affine, MultiSet};

#[derive(Debug, Clone)]
enum Node {
    Leaf {
        hash: String,
        key: String,
        fid: String,
        acc: G1Affine,
        level: usize,
    },
    NonLeaf {
        hash: String,
        keys: MultiSet<String>,
        acc: G1Affine,
        level: usize,
        children: Vec<Box<Node>>,
    },
}

impl Node {
    fn level(&self) -> usize {
        match self {
            Node::Leaf { level, .. } => *level,
            Node::NonLeaf { level, .. } => *level,
        }
    }

    fn hash(&self) -> &String {
        match self {
            Node::Leaf { hash, .. } => hash,
            Node::NonLeaf { hash, .. } => hash,
        }
    }

    fn acc(&self) -> &G1Affine {
        match self {
            Node::Leaf { acc, .. } => acc,
            Node::NonLeaf { acc, .. } => acc,
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
            Node::NonLeaf { children, .. } => {
                for child in children {
                    leaves.extend(child.collect_leaves(exclude_key));
                }
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
        let leaf_hash = calculate_hash(&key, &fid);
        let keys = MultiSet::from_vec(vec![key.clone()]);
        let leaf_acc = Acc1::cal_acc_g1(&keys);

        let curr = Box::new(Node::Leaf {
            hash: leaf_hash,
            key: key,
            fid: fid,
            acc: leaf_acc,
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
            let leaves = root.collect_leaves(Some(key));
            for (k, f) in leaves {
                self.insert(k, f);
            }
        } else {
            println!("Key {} not found for delete", key);
        }
    }
}

fn update_recursive(node: &mut Box<Node>, target_key: &str, new_fid: &str) -> bool {
    match **node {
        Node::Leaf {
            ref mut hash,
            ref mut fid,
            ref key,
            ..
        } => {
            if key == target_key {
                *fid = new_fid.to_string();
                *hash = calculate_hash(key, new_fid);
                return true;
            }
            false
        }
        Node::NonLeaf {
            ref mut hash,
            ref keys,
            ref mut children,
            ..
        } => {
            if !keys.contains_key(target_key) {
                return false;
            }

            let mut changed = false;
            for child in children.iter_mut() {
                if update_recursive(child, target_key, new_fid) {
                    changed = true;
                }
            }

            if changed {
                // Recompute hash from children
                // Assuming children are always [left, right] for binary merge
                // But merge function puts them in vec.
                // We need to know the order. merge(r_old, curr) -> children: [r_old, curr]
                // So children[0] is left, children[1] is right.
                if children.len() == 2 {
                    *hash = format!("hash({}||{})", children[0].hash(), children[1].hash());
                }
            }
            changed
        }
    }
}

fn merge(r_old: Box<Node>, curr: Box<Node>) -> Box<Node> {
    let new_level = curr.level() + 1;
    let combined_hash = format!("hash({}||{})", r_old.hash(), curr.hash());

    let left_keys = match &*r_old {
        Node::Leaf { key, .. } => MultiSet::from_vec(vec![key.clone()]),
        Node::NonLeaf { keys, .. } => keys.clone(),
    };

    let right_keys = match &*curr {
        Node::Leaf { key, .. } => MultiSet::from_vec(vec![key.clone()]),
        Node::NonLeaf { keys, .. } => keys.clone(),
    };

    let merged_keys = &left_keys + &right_keys;
    let acc = Acc1::cal_acc_g1(&merged_keys);

    Box::new(Node::NonLeaf {
        hash: combined_hash,
        keys: merged_keys,
        acc,
        level: new_level,
        children: vec![r_old, curr],
    })
}

fn calculate_hash(key: &str, fid: &str) -> String {
    format!("hash({}+{})", key, fid)
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
        println!(
            "  Root[{}]: Level {}, Hash {}, Keys {}",
            i,
            node.level(),
            node.hash(),
            render_keys(node)
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
