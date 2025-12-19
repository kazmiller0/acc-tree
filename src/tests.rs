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
