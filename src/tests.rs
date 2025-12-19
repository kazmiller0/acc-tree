use super::*;

#[test]
fn test_node_hash_and_collect() {
    let l_acc = Acc::cal_acc_g1(&MultiSet::from_vec(vec!["A".to_string()]));
    let r_acc = Acc::cal_acc_g1(&MultiSet::from_vec(vec!["B".to_string()]));
    let l = Box::new(Node::Leaf {
        key: "A".into(),
        fid: "fa".into(),
        acc: l_acc,
        level: 0,
    });
    let r = Box::new(Node::Leaf {
        key: "B".into(),
        fid: "fb".into(),
        acc: r_acc,
        level: 0,
    });

    assert_eq!(l.level(), 0);
    assert_eq!(r.level(), 0);
    assert!(l.has_key("A"));
    assert!(!l.has_key("B"));

    let merged = merge_nodes(l.clone(), r.clone());
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
            *hash,
            nonleaf_hash(left.as_ref().hash(), right.as_ref().hash())
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

    let ops = 2000usize;
    let key_space = 300usize;
    let mut ops_log: Vec<String> = Vec::with_capacity(ops);

    for _ in 0..ops {
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
        // per-op full-state check to find first divergence
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
                "Divergence at op {}: op='{}'\nkeys_in_tree.len={} ref.len={}\nkeys_in_tree sample={:?}\nref sample={:?}\nops so far:\n{}",
                ops_log.len() - 1,
                ops_log.last().unwrap_or(&"<none>".to_string()),
                keys_in_tree.len(),
                ref_keys.len(),
                &keys_in_tree.iter().take(40).cloned().collect::<Vec<_>>(),
                &ref_keys.iter().take(40).cloned().collect::<Vec<_>>(),
                ops_log.join("\n")
            );
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
