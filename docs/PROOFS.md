# 证明生成与验证机制文档（按 CRUD 操作分类）

本文档按照增删改查（CRUD）的操作维度，详细说明了 `AccumulatorTree` 中各类证明（Proof）的生成逻辑与验证流程。

## 1. 插入 (Insert)

### 1.1 证明生成
**核心函数**: `insert_with_proof(key, fid)`

插入操作会改变树的状态，因此证明包含插入前（Pre）和插入后（Post）的信息。

1.  **Pre-State 快照**:
    *   在执行插入前，记录当前所有 Root 的 Hash 和 Accumulator 值 (`pre_roots`)。
    *   尝试生成一个 **Non-Membership Proof** (`pre_nonmembership`)，证明该 Key 在插入前确实不存在。
2.  **执行插入**:
    *   将新 Key-Value 插入树中（可能会触发树的合并/Normalize）。
3.  **Post-State 证明**:
    *   调用 `get_with_proof(key)` 为刚插入的 Key 生成证明。
    *   获取新的 Root Hash (`post_root_hash`)。
    *   获取新的 Accumulator 值 (`post_accumulator`)。
    *   生成新的 Membership Witness (`post_membership_witness`)。

**返回结果**: `InsertResponse`

### 1.2 验证流程
验证者收到 `InsertResponse` 后应执行以下检查：

1.  **Pre-State 验证 (可选)**:
    *   如果提供了 `pre_nonmembership`，调用 `pre_nonmembership.verify(key)` 确认 Key 在插入前不存在。
2.  **Post-State 验证**:
    *   **Merkle Path**: 验证 `post_proof` 是否有效，且 `leaf_hash` 匹配插入的 `key` 和 `fid`。
    *   **Accumulator**: 调用 `acc::Acc::verify_membership(post_accumulator, post_membership_witness, key)` 验证新 Key 已被正确加入累加器。

---

## 2. 查询 (Get / Read)

### 2.1 证明生成
**核心函数**: `get_with_proof(key)`

查询操作分为两种情况：Key 存在或 Key 不存在。

*   **情况 A: Key 存在**
    1.  找到包含 Key 的叶节点。
    2.  **Merkle Path**: 从叶节点向上回溯到根，收集路径上所有兄弟节点的 Hash (`proof.path`)。
    3.  **Accumulator Witness**: 计算该子树的累加器 Witness (`membership_witness`)。
*   **情况 B: Key 不存在**
    1.  调用 `get_nonmembership_proof`。
    2.  在森林中寻找目标 Key 的**前驱** (Predecessor) 和**后继** (Successor)。
    3.  为前驱和后继分别生成 Merkle Path Proof。

**返回结果**: `QueryResponse`

### 2.2 验证流程
验证者收到 `QueryResponse` 后：

*   **若返回了 FID (Key 存在)**:
    1.  **Merkle Path**: 调用 `proof.verify_with_kv(key, fid)`。
        *   计算 `leaf_hash(key, fid)`。
        *   沿 `path` 重建 Root Hash，并与 `root_hash` 比对。
    2.  **Accumulator**: 调用 `acc::Acc::verify_membership(accumulator, membership_witness, key)`。
    *   *快捷方法*: `response.verify_full(key, fid)` 同时执行上述两步。

*   **若未返回 FID (Key 不存在)**:
    1.  检查 `nonmembership` 字段。
    2.  调用 `nonmembership.verify(key)`：
        *   验证前驱证明 (`pred`) 有效，且 `pred.key < target_key`。
        *   验证后继证明 (`succ`) 有效，且 `succ.key > target_key`。
        *   确认前驱和后继在排序上是紧邻的（或基于应用层信任）。

---

## 3. 更新 (Update)

### 3.1 证明生成
**核心函数**: `update_with_proof(key, new_fid)`

更新操作修改现有的 Key 对应的 Value (FID)。

1.  **Pre-State 证明**:
    *   在更新前调用 `get_with_proof(key)`，获取旧状态的 Proof (`pre_proof`)、Accumulator (`pre_accumulator`) 等。
2.  **执行更新**:
    *   找到叶节点，修改其 FID。
    *   重新计算沿途所有父节点的 Hash。
3.  **Post-State 证明**:
    *   再次调用 `get_with_proof(key)`，获取新状态的 Proof (`post_proof`) 等。

**返回结果**: `UpdateResponse`

### 3.2 验证流程
验证者收到 `UpdateResponse` 后：

1.  **独立验证**:
    *   验证 `pre_proof` 对应旧 FID (`verify_with_kv(key, old_fid)`)。
    *   验证 `post_proof` 对应新 FID (`verify_with_kv(key, new_fid)`)。
2.  **路径一致性验证 (Path Consistency)**:
    *   **核心逻辑**: 比较 `pre_proof.path` 和 `post_proof.path`。
    *   **要求**: 两个路径的长度必须相等，且路径上每一个**兄弟节点**的 Hash 和方向必须完全一致。
    *   **意义**: 这证明了除了目标叶节点本身发生变化外，通往根路径上的所有兄弟子树都没有被篡改。这是“仅修改了目标叶子”的强有力证明。
3.  **Accumulator 验证**:
    *   验证 `post_accumulator` 的成员性。

*   *快捷方法*: `response.verify_update()`。

---

## 4. 删除 (Delete)

### 4.1 证明生成
**核心函数**: `delete_with_proof(key)`

删除操作采用 **Tombstone** 机制，即不物理移除节点，而是将其标记为 `deleted`。

1.  **Pre-State 证明**:
    *   删除前调用 `get_with_proof(key)` 获取证明。
2.  **执行删除**:
    *   找到叶节点，设置 `deleted = true`。
    *   重新计算 Hash（Tombstone 叶子的 Hash 通常为特定值，如 `Hash::default()` 或全零）。
3.  **Post-State 证明**:
    *   调用 `get_proof_including_deleted(key)`。这是一个特殊函数，允许为已删除的节点生成 Merkle Path。

**返回结果**: `DeleteResponse`

### 4.2 验证流程
验证者收到 `DeleteResponse` 后：

1.  **Pre-State 验证**:
    *   验证 `pre_proof` 有效，证明删除前 Key 存在。
2.  **Post-State 验证**:
    *   验证 `post_proof` 有效。注意此时 `leaf_hash` 应该是 Tombstone Hash（例如空 Hash）。
3.  **路径一致性验证**:
    *   与更新操作一样，比较 `pre_proof.path` 和 `post_proof.path`，确保兄弟节点 Hash 完全一致。
    *   这证明了仅仅是该叶节点变成了 Tombstone，而没有影响树的其他部分。

*   *快捷方法*: `response.verify_delete()`。

---

## 5. 总结

| 操作                | 涉及证明                          | 关键验证点                                    |
| :------------------ | :-------------------------------- | :-------------------------------------------- |
| **Insert**          | Pre-NonMem, Post-Merkle, Post-Acc | 插入后存在性，插入前不存在性                  |
| **Get (Found)**     | Merkle Path, Acc Witness          | 路径哈希正确，累加器包含 Key                  |
| **Get (Not Found)** | Non-Membership (Pred/Succ)        | 目标 Key 落在前驱和后继的空隙中               |
| **Update**          | Pre-Proof, Post-Proof             | **路径一致性** (兄弟节点不变)，前后状态均有效 |
| **Delete**          | Pre-Proof, Post-Proof (Tombstone) | **路径一致性**，Post-Leaf 为 Tombstone Hash   |

