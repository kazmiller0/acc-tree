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
            let mut stored: Vec<String> = keys.as_ref().iter().map(|(k, _)| k.clone()).collect();
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
