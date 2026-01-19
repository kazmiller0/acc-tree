use crate::{AccumulatorTree, Node};

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
