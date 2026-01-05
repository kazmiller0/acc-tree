# 数据结构与 CRUD 实现文档

本文档详细说明了 `AccumulatorTree` 的核心数据结构设计以及增删改查（CRUD）操作的实现逻辑。

## 1. 核心数据结构

### 1.1 `Node` 枚举

树的基本构建块是 `Node` 枚举，分为 `Leaf`（叶节点）和 `NonLeaf`（非叶节点）。

```rust
pub enum Node {
    Leaf {
        key: String,
        fid: String,
        level: usize,
        deleted: bool,
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
```

- **Leaf (叶节点)**:
  - `key`: 数据的唯一标识键。
  - `fid`: 文件标识符或数据内容。
  - `level`: 节点在树中的高度（叶节点通常为 0）。
  - `deleted`: 墓碑标记（Tombstone）。删除操作不会物理移除节点，而是将其标记为 `deleted = true`。
  - **Hash 计算**:
    - 若 `deleted` 为 `true`，Hash 为 `empty_hash()`。
    - 否则，Hash 为 `leaf_hash(key, fid)`。
  - **Accumulator**:
    - 若 `deleted` 为 `true`，贡献空累加器。
    - 否则，贡献包含 `key` 的单元素累加器。

- **NonLeaf (非叶节点)**:
  - `hash`: 左右子节点 Hash 的组合（Merkle Hash）。
  - `keys`: 子树中所有有效（未删除）Key 的多重集合（`MultiSet`）。
  - `acc`: 对应 `keys` 集合的累加器值（`G1Affine`）。
  - `level`: 树的高度，等于 `right.level() + 1`。
  - `left`, `right`: 指向左右子节点的指针。

### 1.2 `AccumulatorTree` 结构体

```rust
pub struct AccumulatorTree {
    pub roots: Vec<Box<Node>>,
}
```

- `AccumulatorTree` 维护一个 `roots` 向量，这是一个**森林**结构。
- 类似于 Merkle Mountain Range (MMR) 或二进制堆积树，它维护多个不同高度的完美二叉树。
- `normalize()` 方法负责在插入后合并相同高度的树，保持森林结构的紧凑性。

---

## 2. CRUD 操作实现

### 2.1 创建 / 插入 (Create / Insert)

**方法**: `insert(&mut self, key: String, fid: String)`

1.  **检查是否存在**: 遍历 `roots`，检查 `key` 是否已存在（通过 `has_key`，该方法会忽略已删除的节点）。
2.  **复活 (Revive)**:
    - 如果 `key` 存在但被标记为 `deleted`（墓碑），则执行 `revive_recursive`。
    - `revive_recursive` 找到对应的叶节点，更新 `fid`，并将 `deleted` 设为 `false`。
    - 递归回溯时，重新计算路径上所有父节点的 `keys`、`acc` 和 `hash`。
3.  **新插入**:
    - 如果 `key` 不存在，创建一个新的 `Node::Leaf`（level=0）。
    - 将新叶节点加入 `roots` 列表。
4.  **规范化 (Normalize)**:
    - 调用 `normalize()`。
    - 对 `roots` 按高度排序。
    - 循环合并相同高度的树（`merge_nodes`），直到所有树的高度唯一。
    - `merge_nodes` 会合并两个子树的 `keys` 集合，重新计算累加器和 Merkle Hash。

### 2.2 读取 / 查询 (Read / Get)

**方法**: `get(&self, key: &str) -> Option<String>`

1.  遍历 `roots` 中的每棵树。
2.  调用 `get_recursive(root, key)`。
3.  **递归查找**:
    - **Leaf**: 匹配 `key` 且 `!deleted`，返回 `Some(fid)`。
    - **NonLeaf**: 根据 `left.has_key(key)` 决定向左或向右递归。
    - `has_key` 利用了 `NonLeaf` 中维护的 `keys` 集合（Bloom Filter 或 Set 包含性检查的逻辑基础），能快速剪枝。

**带证明的查询**: `get_with_proof`
- 类似 `get`，但在递归回溯时收集兄弟节点的 Hash 构建 Merkle Path。
- 同时利用当前 Root 的 `acc` 和 `keys` 计算累加器成员见证（Witness）。

### 2.3 更新 (Update)

**方法**: `update(&mut self, key: &str, new_fid: String)`

1.  找到包含 `key` 的 Root。
2.  调用 `update_recursive(root, key, new_fid)`。
3.  **递归更新**:
    - **Leaf**: 找到匹配 `key` 且 `!deleted` 的叶子，更新 `fid`。
    - **NonLeaf**: 递归查找并更新子节点。
    - **回溯**: 如果子节点发生变化，重新计算当前节点的 `keys`（虽然 Key 集合没变，但为了逻辑统一通常重置引用）、`acc`（通常不变，除非 Key 变了，这里只改 Value/FID，Accumulator 只承诺 Key，所以 Acc 其实不变，但 Hash 会变）和 `hash`（因为叶子 Hash 变了）。
    - *注*: 代码实现中 `update_recursive` 会触发 Hash 更新。

### 2.4 删除 (Delete)

**方法**: `delete(&mut self, key: &str)`

1.  找到包含 `key` 的 Root。
2.  将该 Root 移出 `roots` 列表。
3.  调用 `delete_recursive(root, key)` 生成新的 Root。
4.  **递归删除 (Tombstoning)**:
    - **Leaf**: 找到匹配 `key` 的叶子，创建一个新叶节点，设置 `deleted = true`。
    - **NonLeaf**: 递归处理子节点。
    - **回溯**: 重新计算 `keys`（从集合中移除该 Key）、`acc`（重新计算累加器）和 `hash`（叶子变为空 Hash）。
5.  将新 Root 放回 `roots` 并调用 `normalize()`（虽然删除通常不改变高度，但为了保持一致性）。

---

## 3. 关键算法细节

### 3.1 规范化 (Normalize)
`normalize` 过程确保了树的结构类似于二进制表示。例如，如果有 3 个叶子，会被组织成一棵高度 1 的树（2个叶子）和一棵高度 0 的树（1个叶子）。这保证了树的平衡性和操作的对数复杂度。

### 3.2 墓碑机制 (Tombstones)
删除操作采用墓碑机制，保留了叶节点在树中的位置，只是将其标记为无效。
- **优点**: 简化了树的结构调整，避免了复杂的节点移除和重平衡算法。
- **影响**:
  - `Hash`: 变为 `empty_hash()`。
  - `Accumulator`: 该 Key 不再贡献到累加器中。
  - `Revive`: 再次插入相同 Key 时可以复用该位置。

### 3.3 累加器 (Accumulator) 集成
每个非叶节点维护一个 `acc` 字段，它是其子树中所有有效 Key 的加密累加器值。
- **合并**: `merge_nodes` 时，父节点的累加器是左右子节点 Key 集合并集的累加结果。
- **验证**: 允许生成成员证明（Witness），证明某个 Key 存在于集合中，且与 Merkle Tree 的结构解耦（Accumulator 不依赖路径，只依赖集合内容）。

