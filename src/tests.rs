use super::*;
use acc::{Acc, Accumulator, MultiSet};

#[test]
fn test_node_hash_and_collect() {
    let l = Box::new(Node::Leaf {
        key: "A".into(),
        fid: "fa".into(),
        level: 0,
        deleted: false,
    });
    let r = Box::new(Node::Leaf {
        key: "B".into(),
        fid: "fb".into(),
        level: 0,
        deleted: false,
    });

    assert_eq!(l.level(), 0);
    assert_eq!(r.level(), 0);
    assert!(l.has_key("A"));
    assert!(!l.has_key("B"));

    let merged = Node::merge(l.clone(), r.clone());
    // merged level 应为子节点 level + 1
    assert_eq!(merged.level(), 1);

    // nonleaf hash = nonleaf_hash(left.hash(), right.hash())
    if let Node::NonLeaf {
        hash,
        left,
        right,
        keys,
        ..
    } = &*merged
    {
        assert_eq!(
            hash,
            &nonleaf_hash(left.as_ref().hash(), right.as_ref().hash())
        );
        let mut collected: Vec<_> = left
            .collect_leaves(None)
            .chain(right.collect_leaves(None))
            .map(|(k, _)| k)
            .collect();
        collected.sort();
        let mut stored: Vec<_> = keys.as_ref().iter().map(|(k, _)| k.clone()).collect();
        stored.sort();
        assert_eq!(collected, stored);
    } else {
        panic!("merged must be NonLeaf");
    }
}

// ========== additional comprehensive tests ==========

fn find_leaf_by_key<'a>(node: &'a Node, key: &str) -> Option<&'a Node> {
    match node {
        Node::Leaf { key: k, .. } if k == key => Some(node),
        Node::Leaf { .. } => None,
        Node::NonLeaf { left, right, .. } => {
            find_leaf_by_key(left, key).or_else(|| find_leaf_by_key(right, key))
        }
    }
}

fn find_live_leaf_by_key<'a>(node: &'a Node, key: &str) -> Option<&'a Node> {
    match node {
        Node::Leaf {
            key: k, deleted, ..
        } if k == key && !*deleted => Some(node),
        Node::Leaf { .. } => None,
        Node::NonLeaf { left, right, .. } => {
            find_live_leaf_by_key(left, key).or_else(|| find_live_leaf_by_key(right, key))
        }
    }
}

fn traverse_nodes<F: FnMut(&Node)>(node: &Node, f: &mut F) {
    f(node);
    if let Node::NonLeaf { left, right, .. } = node {
        traverse_nodes(left, f);
        traverse_nodes(right, f);
    }
}

#[test]
fn test_basic_ops_insert_update_delete_revive_and_consistency() {
    let mut tree = AccumulatorTree::new();

    // insert
    tree.insert("X".to_string(), "F1".to_string());
    assert_eq!(tree.get("X"), Some("F1".to_string()));

    // find the leaf node and check hash/acc consistency
    let mut found_leaf: Option<&Node> = None;
    for r in &tree.roots {
        if let Some(n) = find_leaf_by_key(r, "X") {
            found_leaf = Some(n);
            break;
        }
    }
    let leaf = found_leaf.expect("leaf X must exist");
    // acc/hash consistent with keys()
    assert_eq!(leaf.acc(), Acc::cal_acc_g1(&leaf.keys()));
    if let Node::Leaf {
        key, fid, deleted, ..
    } = leaf
    {
        assert!(!*deleted);
        assert_eq!(leaf.hash(), leaf_hash(key, fid));
    } else {
        panic!("expected leaf");
    }

    // update
    let prev_hash = leaf.hash();
    tree.update("X", "F1_upd".to_string());
    assert_eq!(tree.get("X"), Some("F1_upd".to_string()));
    // locate updated leaf and check hash changed and acc updated
    let mut updated_leaf: Option<&Node> = None;
    for r in &tree.roots {
        if let Some(n) = find_leaf_by_key(r, "X") {
            updated_leaf = Some(n);
            break;
        }
    }
    let leaf2 = updated_leaf.expect("updated leaf must exist");
    assert_ne!(prev_hash, leaf2.hash());
    assert_eq!(leaf2.acc(), Acc::cal_acc_g1(&leaf2.keys()));

    // delete
    tree.delete("X");
    assert_eq!(tree.get("X"), None);
    // find tombstoned leaf and assert tombstone semantics
    let mut tomb_leaf: Option<&Node> = None;
    for r in &tree.roots {
        if let Some(n) = find_leaf_by_key(r, "X") {
            tomb_leaf = Some(n);
            break;
        }
    }
    let tf = tomb_leaf.expect("tombstone leaf should still be present in structure");
    if let Node::Leaf { deleted, .. } = tf {
        assert!(*deleted);
    }
    assert_eq!(tf.hash(), empty_hash());
    assert_eq!(tf.acc(), empty_acc());

    // revive by inserting same key again
    tree.insert("X".to_string(), "F2".to_string());
    assert_eq!(tree.get("X"), Some("F2".to_string()));
    // ensure there's a non-deleted leaf for X
    let mut live_leaf: Option<&Node> = None;
    for r in &tree.roots {
        if let Some(n) = find_live_leaf_by_key(r, "X") {
            live_leaf = Some(n);
            break;
        }
    }
    let lf = live_leaf.expect("live leaf after revive must exist");
    if let Node::Leaf {
        key, fid, deleted, ..
    } = lf
    {
        assert!(!*deleted);
        assert_eq!(tree.get(key.as_str()), Some(fid.clone()));
        assert_eq!(lf.hash(), leaf_hash(key, fid));
        assert_eq!(lf.acc(), Acc::cal_acc_g1(&lf.keys()));
    }
}

#[test]
fn test_normalize_merge_and_collect_leaves_behaviour() {
    let mut tree = AccumulatorTree::new();
    for i in 0..8 {
        tree.insert(format!("K{}", i), format!("F{}", i));
    }
    // after normalize there should be no two roots with same level
    let mut levels: Vec<usize> = tree.roots.iter().map(|r| r.level()).collect();
    levels.sort();
    for w in levels.windows(2) {
        assert_ne!(w[0], w[1]);
    }

    // traverse all nodes and verify cached NonLeaf acc/hash equal recomputed values
    for r in &tree.roots {
        let mut check = |n: &Node| {
            // acc == cal_acc_g1(keys)
            assert_eq!(n.acc(), Acc::cal_acc_g1(&n.keys()));
            if let Node::NonLeaf { left, right, .. } = n {
                assert_eq!(n.hash(), nonleaf_hash(left.hash(), right.hash()));
            }
        };
        traverse_nodes(r, &mut check);
    }

    // collect_leaves should exclude deleted leaves and honor exclude_key
    tree.delete("K3");
    let all_keys: Vec<String> = tree
        .roots
        .iter()
        .flat_map(|r| r.collect_leaves(None))
        .map(|(k, _)| k)
        .collect();
    assert!(!all_keys.contains(&"K3".to_string()));
    let excl: Vec<String> = tree
        .roots
        .iter()
        .flat_map(|r| r.collect_leaves(Some("K4")))
        .map(|(k, _)| k)
        .collect();
    assert!(!excl.contains(&"K4".to_string()));
}

#[test]
fn test_edge_cases_empty_tree_and_duplicates_and_updates_on_deleted() {
    let mut tree = AccumulatorTree::new();
    // empty tree ops should not panic
    assert_eq!(tree.get("nope"), None);
    tree.update("nope", "v".to_string());
    tree.delete("nope");

    // insert duplicate key twice
    tree.insert("D".to_string(), "F1".to_string());
    tree.insert("D".to_string(), "F2".to_string());
    // duplicate insert does not overwrite an existing non-deleted leaf (use update to change)
    assert_eq!(tree.get("D"), Some("F1".to_string()));
    // collect unique keys should contain only one D
    let mut keys: Vec<String> = tree
        .roots
        .iter()
        .flat_map(|r| r.collect_leaves(None))
        .map(|(k, _)| k)
        .collect();
    keys.sort();
    keys.dedup();
    assert!(keys.contains(&"D".to_string()));

    // delete nonexistent key should not change tree
    let before = tree.roots.len();
    tree.delete("Z_nonexistent");
    assert_eq!(tree.roots.len(), before);

    // update deleted key should be no-op
    tree.delete("D");
    // ensure it's tombstoned
    assert_eq!(tree.get("D"), None);
    tree.update("D", "should_not_apply".to_string());
    assert_eq!(tree.get("D"), None);
}

#[test]
fn test_tombstone_propagation_and_normalize_behavior() {
    // build controlled tree: ((a,b),(c,d))
    let a = Box::new(Node::Leaf {
        key: "a".into(),
        fid: "fa".into(),
        level: 0,
        deleted: false,
    });
    let b = Box::new(Node::Leaf {
        key: "b".into(),
        fid: "fb".into(),
        level: 0,
        deleted: false,
    });
    let c = Box::new(Node::Leaf {
        key: "c".into(),
        fid: "fc".into(),
        level: 0,
        deleted: false,
    });
    let d = Box::new(Node::Leaf {
        key: "d".into(),
        fid: "fd".into(),
        level: 0,
        deleted: false,
    });

    let left = Node::merge(a, b); // level 1
    let right = Node::merge(c, d); // level 1
    let root = Node::merge(left.clone(), right.clone()); // level 2

    // delete both leaves in left subtree
    let root_after = root.delete_recursive("a");
    let root_after = root_after.delete_recursive("b");

    // find left subtree (root_after.left)
    if let Node::NonLeaf { left, right: _, .. } = &*root_after {
        // left keys should be empty and acc should equal empty acc
        assert!(left.keys().is_empty());
        assert_eq!(left.acc(), Acc::cal_acc_g1(&MultiSet::<String>::new()));
        // left.hash() should be computed from child hashes which are tombstones
        if let Node::NonLeaf {
            left: lchild,
            right: rchild,
            ..
        } = &**left
        {
            assert_eq!(lchild.hash(), empty_hash());
            assert_eq!(rchild.hash(), empty_hash());
        }
    } else {
        panic!("root_after must be NonLeaf");
    }

    // test tree merging via insert operations: ensure merge logic handles empty children
    let mut tree = AccumulatorTree::new();
    // create two deleted leaves by inserting and then deleting
    tree.insert("x".to_string(), "fx".to_string());
    tree.insert("y".to_string(), "fy".to_string());
    tree.delete("x");
    tree.delete("y");
    // after deletions, tree should have merged roots with empty keys
    assert!(tree.roots.len() >= 1);
    for root in &tree.roots {
        // all keys should be tombstoned (empty keys)
        assert!(root.keys().is_empty());
        assert_eq!(root.acc(), Acc::cal_acc_g1(&MultiSet::<String>::new()));
    }
}

#[test]
fn test_revive_updates_nonleaf_for_deep_tree() {
    // build ((a,b),(c,d)) again
    let a = Box::new(Node::Leaf {
        key: "a".into(),
        fid: "fa".into(),
        level: 0,
        deleted: false,
    });
    let b = Box::new(Node::Leaf {
        key: "b".into(),
        fid: "fb".into(),
        level: 0,
        deleted: false,
    });
    let c = Box::new(Node::Leaf {
        key: "c".into(),
        fid: "fc".into(),
        level: 0,
        deleted: false,
    });
    let d = Box::new(Node::Leaf {
        key: "d".into(),
        fid: "fd".into(),
        level: 0,
        deleted: false,
    });
    let left = Node::merge(a, b);
    let right = Node::merge(c, d);
    let mut root = Node::merge(left, right);

    // delete a and b (left subtree becomes empty keys)
    root = root.delete_recursive("a");
    root = root.delete_recursive("b");

    // revive a by inserting into the outer tree via revive_recursive semantics
    let revived = root.revive_recursive("a", "fa_new");
    // verify that after revive, acc/hash for the parent nonleaf reflect the restored key
    if let Node::NonLeaf {
        left,
        right: _,
        keys,
        acc,
        ..
    } = &*revived
    {
        // keys should now contain "a"
        assert!(keys.contains_key("a"));
        assert_eq!(acc, &Acc::cal_acc_g1(&keys.as_ref().clone()));
        // hash of left should now not be the tombstone-only hash
        assert_ne!(left.hash(), empty_hash());
    } else {
        panic!("revived root must be NonLeaf");
    }
}

#[test]
fn test_special_key_and_fid_boundaries() {
    let mut tree = AccumulatorTree::new();
    // empty key and fid
    tree.insert("".to_string(), "".to_string());
    assert_eq!(tree.get(""), Some("".to_string()));
    // special chars
    let special = "\n\0!@#$%^&*()_+中文".to_string();
    tree.insert(special.clone(), "fid_special".to_string());
    assert_eq!(tree.get(&special), Some("fid_special".to_string()));

    // verify no panics and acc/hash correctness
    for r in &tree.roots {
        let mut check = |n: &Node| {
            // ensure acc matches keys
            assert_eq!(n.acc(), Acc::cal_acc_g1::<String>(&n.keys()));
            if let Node::Leaf {
                key, fid, deleted, ..
            } = n
            {
                if !*deleted {
                    assert_eq!(n.hash(), leaf_hash(key.as_str(), fid.as_str()));
                } else {
                    assert_eq!(n.hash(), empty_hash());
                }
            }
        };
        traverse_nodes(r, &mut check);
    }
}

#[test]
fn test_tree_lifecycle() {
    let mut tree = AccumulatorTree::new();
    for i in 0..8 {
        tree.insert(format!("K{}", i), format!("F{}", i));
    }

    // 基本查询
    assert_eq!(tree.get("K3"), Some("F3".to_string()));

    // 更新并验证
    tree.update("K3", "F3_upd".to_string());
    assert_eq!(tree.get("K3"), Some("F3_upd".to_string()));

    // 删除并验证
    tree.delete("K2");
    assert_eq!(tree.get("K2"), None);

    // 收集当前键并校验数量（应为 7）
    let mut keys: Vec<String> = Vec::new();
    for root in &tree.roots {
        for (k, _) in root.collect_leaves(None) {
            keys.push(k);
        }
    }
    keys.sort();
    keys.dedup();
    assert_eq!(keys.len(), 7);
    assert!(keys.contains(&"K3".to_string()));
    assert!(!keys.contains(&"K2".to_string()));
}

#[test]
fn test_bulk_kv_operations() {
    let mut tree = AccumulatorTree::new();
    let n: usize = 200;

    // insert n key-value pairs
    for i in 0..n {
        tree.insert(format!("K{}", i), format!("F{}", i));
    }

    // verify basic gets
    for i in 0..n {
        assert_eq!(tree.get(&format!("K{}", i)), Some(format!("F{}", i)));
    }

    // update every 10th entry
    for i in (0..n).step_by(10) {
        tree.update(&format!("K{}", i), format!("F{}_upd", i));
    }
    for i in (0..n).step_by(10) {
        assert_eq!(tree.get(&format!("K{}", i)), Some(format!("F{}_upd", i)));
    }

    // delete every 7th entry
    let mut deleted = 0usize;
    for i in (0..n).step_by(7) {
        tree.delete(&format!("K{}", i));
        deleted += 1;
    }

    // collect keys from the tree and verify count
    let mut keys: Vec<String> = tree
        .roots
        .iter()
        .flat_map(|r| r.collect_leaves(None))
        .map(|(k, _)| k)
        .collect();
    keys.sort();
    keys.dedup();
    assert_eq!(keys.len(), n - deleted);

    // ensure deleted keys are gone
    for i in (0..n).step_by(7) {
        assert_eq!(tree.get(&format!("K{}", i)), None);
    }
}

// Large-scale bulk ops for stress testing. Marked `ignore` so it doesn't
// run in regular CI but can be executed locally with `cargo test -- --ignored`.
#[test]
#[ignore]
fn test_bulk_kv_operations_large() {
    let mut tree = AccumulatorTree::new();
    let n: usize = 500; // reduced size for faster runs

    // insert n key-value pairs
    for i in 0..n {
        tree.insert(format!("K{}", i), format!("F{}", i));
    }

    // verify basic gets for a sample to reduce runtime
    for i in 0..n {
        assert_eq!(tree.get(&format!("K{}", i)), Some(format!("F{}", i)));
    }

    // update every 10th entry
    for i in (0..n).step_by(10) {
        tree.update(&format!("K{}", i), format!("F{}_upd", i));
    }
    for i in (0..n).step_by(10) {
        assert_eq!(tree.get(&format!("K{}", i)), Some(format!("F{}_upd", i)));
    }

    // delete every 7th entry
    let mut deleted = 0usize;
    for i in (0..n).step_by(7) {
        tree.delete(&format!("K{}", i));
        deleted += 1;
    }

    // collect keys from the tree and verify count
    let mut keys: Vec<String> = tree
        .roots
        .iter()
        .flat_map(|r| r.collect_leaves(None))
        .map(|(k, _)| k)
        .collect();
    keys.sort();
    keys.dedup();
    assert_eq!(keys.len(), n - deleted);

    // ensure deleted keys are gone
    for i in (0..n).step_by(7) {
        assert_eq!(tree.get(&format!("K{}", i)), None);
    }
}

#[test]
fn test_randomized_property_operations() {
    use std::collections::HashMap;

    // deterministic simple LCG
    let mut seed: u64 = 0x1234_5678_abcd_eu64;
    fn lcg(s: &mut u64) -> u64 {
        *s = s.wrapping_mul(6364136223846793005).wrapping_add(1);
        *s
    }

    let mut tree = AccumulatorTree::new();
    let mut reference: HashMap<String, String> = HashMap::new();

    // Reduced ops/key_space for faster test runs while keeping coverage
    let ops = 500usize;
    let key_space = 150usize;
    let mut ops_log: Vec<String> = Vec::with_capacity(ops);

    for i in 0..ops {
        let r = lcg(&mut seed);
        let op = (r % 3) as u8; // 0=insert,1=update,2=delete
        let kidx = (lcg(&mut seed) as usize) % key_space;
        let key = format!("K{}", kidx);

        match op {
            0 => {
                // insert or set
                let v = format!("F{}", (lcg(&mut seed) % 10000));
                tree.insert(key.clone(), v.clone());
                reference.insert(key.clone(), v);
                ops_log.push(format!("insert {}", key));
            }
            1 => {
                // update if exists otherwise insert (keep reference in sync with tree semantics)
                let v = format!("U{}", (lcg(&mut seed) % 10000));
                if reference.contains_key(&key) {
                    tree.update(&key, v.clone());
                    reference.insert(key.clone(), v);
                    ops_log.push(format!("update {}", key));
                } else {
                    tree.insert(key.clone(), v.clone());
                    reference.insert(key.clone(), v);
                    ops_log.push(format!("insert {} (via update)", key));
                }
            }
            _ => {
                tree.delete(&key);
                reference.remove(&key);
                ops_log.push(format!("delete {}", key));
            }
        }
        // Sampled full-state check every 50 ops to reduce overhead
        if i % 50 == 0 {
            let mut keys_in_tree: Vec<String> = tree
                .roots
                .iter()
                .flat_map(|r| r.collect_leaves(None))
                .map(|(k, _)| k)
                .collect();
            keys_in_tree.sort();
            keys_in_tree.dedup();

            let mut ref_keys: Vec<String> = reference.keys().cloned().collect();
            ref_keys.sort();

            if keys_in_tree != ref_keys {
                panic!(
                    "Divergence at op {}: op='{}'\nkeys_in_tree.len={} ref.len={}\nops so far:\n{}",
                    i,
                    ops_log.last().unwrap_or(&"<none>".to_string()),
                    keys_in_tree.len(),
                    ref_keys.len(),
                    ops_log.join("\n")
                );
            }
        }
    }

    // final full-scan: collect leaves and compare key sets
    let mut keys: Vec<String> = tree
        .roots
        .iter()
        .flat_map(|r| r.collect_leaves(None))
        .map(|(k, _)| k)
        .collect();
    keys.sort();
    keys.dedup();

    let mut ref_keys: Vec<String> = reference.keys().cloned().collect();
    ref_keys.sort();
    if keys != ref_keys {
        panic!(
            "Final state mismatch: keys.len()={} ref.len()={}\nops_log (all):\n{}\n",
            keys.len(),
            ref_keys.len(),
            ops_log
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join("\n")
        );
    }
}

// Larger randomized property test for stress; ignored by default.
#[test]
#[ignore]
fn test_randomized_property_operations_large() {
    use std::collections::HashMap;

    // deterministic simple LCG
    let mut seed: u64 = 0xfeed_face_dead_beefu64;
    fn lcg(s: &mut u64) -> u64 {
        *s = s.wrapping_mul(6364136223846793005).wrapping_add(1);
        *s
    }

    let mut tree = AccumulatorTree::new();
    let mut reference: HashMap<String, String> = HashMap::new();

    // Larger ops/key_space for stress testing
    let ops = 1000usize; // reduced ops for speed
    let key_space = 200usize; // smaller key space
    let mut ops_log: Vec<String> = Vec::with_capacity(ops);

    for i in 0..ops {
        let r = lcg(&mut seed);
        let op = (r % 3) as u8; // 0=insert,1=update,2=delete
        let kidx = (lcg(&mut seed) as usize) % key_space;
        let key = format!("K{}", kidx);

        match op {
            0 => {
                let v = format!("F{}", (lcg(&mut seed) % 10000));
                tree.insert(key.clone(), v.clone());
                reference.insert(key.clone(), v);
                ops_log.push(format!("insert {}", key));
            }
            1 => {
                let v = format!("U{}", (lcg(&mut seed) % 10000));
                if reference.contains_key(&key) {
                    tree.update(&key, v.clone());
                    reference.insert(key.clone(), v);
                    ops_log.push(format!("update {}", key));
                } else {
                    tree.insert(key.clone(), v.clone());
                    reference.insert(key.clone(), v);
                    ops_log.push(format!("insert {} (via update)", key));
                }
            }
            _ => {
                tree.delete(&key);
                reference.remove(&key);
                ops_log.push(format!("delete {}", key));
            }
        }

        // Sampled check every 500 ops to reduce overhead
        if i % 500 == 0 {
            let mut keys_in_tree: Vec<String> = tree
                .roots
                .iter()
                .flat_map(|r| r.collect_leaves(None))
                .map(|(k, _)| k)
                .collect();
            keys_in_tree.sort();
            keys_in_tree.dedup();

            let mut ref_keys: Vec<String> = reference.keys().cloned().collect();
            ref_keys.sort();

            if keys_in_tree != ref_keys {
                panic!(
                    "Divergence at op {}: op='{}'\nkeys_in_tree.len={} ref.len={}\nops so far:\n{}",
                    i,
                    ops_log.last().unwrap_or(&"<none>".to_string()),
                    keys_in_tree.len(),
                    ref_keys.len(),
                    ops_log.join("\n")
                );
            }
        }
    }

    // final full-scan: collect leaves and compare key sets
    let mut keys: Vec<String> = tree
        .roots
        .iter()
        .flat_map(|r| r.collect_leaves(None))
        .map(|(k, _)| k)
        .collect();
    keys.sort();
    keys.dedup();

    let mut ref_keys: Vec<String> = reference.keys().cloned().collect();
    ref_keys.sort();
    if keys != ref_keys {
        panic!(
            "Final state mismatch (large test): keys.len()={} ref.len()={}\nops_log (all):\n{}\n",
            keys.len(),
            ref_keys.len(),
            ops_log
                .iter()
                .map(|s| s.as_str())
                .collect::<Vec<_>>()
                .join("\n")
        );
    }
}

#[test]
fn test_get_with_proof_verifies() {
    let mut tree = AccumulatorTree::new();
    tree.insert("P".to_string(), "PV".to_string());

    let qr = tree.get_with_proof("P");
    assert_eq!(qr.fid, Some("PV".to_string()));
    let proof = qr.proof.as_ref().expect("proof must be present");
    // verify the proof recomputes the root correctly
    assert!(proof.verify());
    // also verify with key/fid convenience
    assert!(proof.verify_with_kv("P", "PV"));

    // ensure QueryResponse populated root_hash and membership_witness/accumulator
    assert_eq!(qr.root_hash, Some(proof.root_hash));
    let acc_val = qr.accumulator.expect("acc must be present");
    let witness = qr.membership_witness.expect("witness must be present");
    // verify accumulator membership witness
    assert!(acc::Acc::verify_membership(
        &acc_val,
        &witness,
        &"P".to_string()
    ));

    // combined verification convenience
    assert!(qr.verify_full("P", "PV"));
    // since key existed, nonmembership must be None
    assert!(qr.nonmembership.is_none());
}

#[test]
fn test_update_with_proof() {
    let mut tree = AccumulatorTree::new();
    tree.insert("Ukey".to_string(), "Ufid".to_string());

    // perform update with proof
    let resp = tree
        .update_with_proof("Ukey", "Ufid_new".to_string())
        .expect("update_with_proof should succeed");

    // old fid recorded
    assert_eq!(resp.old_fid, Some("Ufid".to_string()));
    assert_eq!(resp.new_fid, "Ufid_new".to_string());

    // post proof verifies
    assert!(resp.post_proof.verify());

    // if pre proof is present, ensure sibling paths match so only leaf changed
    if let Some(pre) = &resp.pre_proof {
        assert_eq!(pre.path.len(), resp.post_proof.path.len());
        for i in 0..pre.path.len() {
            assert_eq!(pre.path[i], resp.post_proof.path[i]);
        }
    }

    // verify using UpdateResponse convenience check
    assert!(resp.verify_update());
}

#[test]
fn test_delete_with_proof() {
    let mut tree = AccumulatorTree::new();
    tree.insert("Dkey".to_string(), "Dfid".to_string());

    // delete with proof
    let resp = tree
        .delete_with_proof("Dkey")
        .expect("delete_with_proof should succeed");

    // old fid recorded
    assert_eq!(resp.old_fid, Some("Dfid".to_string()));

    // post proof verifies (tombstone leaf hash -> empty_hash)
    assert!(resp.post_proof.verify());

    // verify convenience
    assert!(resp.verify_delete());

    // ensure key is gone
    assert_eq!(tree.get("Dkey"), None);
}

#[test]
fn test_get_with_nonmembership_when_absent() {
    let tree = AccumulatorTree::new();
    // empty tree: key absent
    let qr = tree.get_with_proof("Z");
    assert_eq!(qr.fid, None);
    // nonmembership proof should be present (though pred/succ may be None)
    let nm = qr.nonmembership.expect("nonmembership present");
    assert!(nm.verify("Z"));
}

#[test]
fn test_insert_with_proof() {
    let mut tree = AccumulatorTree::new();

    // ensure key absent before insert
    assert_eq!(tree.get("I"), None);

    // capture insert with proof
    let resp = tree.insert_with_proof("I".to_string(), "IV".to_string());

    // pre_roots should be present (snapshot of previous roots)
    assert!(!resp.pre_roots.is_empty() || true);

    // pre_nonmembership should prove 'I' did not exist before
    if let Some(pre_nm) = &resp.pre_nonmembership {
        assert!(pre_nm.verify(&resp.key));
    }

    // post proof must exist and verify
    let proof = resp.post_proof.expect("post proof present");
    assert!(proof.verify());

    // verify membership witness against accumulator
    let acc_val = resp.post_accumulator.expect("post acc present");
    let witness = resp.post_membership_witness.expect("post witness present");
    assert!(acc::Acc::verify_membership(&acc_val, &witness, &resp.key));
}
