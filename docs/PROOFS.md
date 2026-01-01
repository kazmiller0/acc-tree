证明实现与验证流程（增删改查）
================================

下面按 CRUD 操作分别说明在本项目中如何生成证明（proof）以及验证（verify）这些证明的流程，包含关键代码点与验证要点。

1) 创建 / 插入（Insert）
- 生成证明：调用 `AccumulatorTree::insert_with_proof(key, fid)`。
  - 步骤：
    1. 在插入前，采集 `pre_roots`（每个 root 的 `(root_hash, acc)` 快照）。
    2. 尝试构造 `pre_nonmembership`（调用 `get_nonmembership_proof`，返回 `NonMembershipProof` 包含前驱/后继的 Merkle 证明，若能构造）。
    3. 插入或 revive 叶节点。
    4. 插入后，调用 `get_with_proof(key)` 构建 `post_proof`（`Proof`，包含 `root_hash`、`leaf_hash`、`path`）以及 `post_accumulator` / `post_membership_witness`（使用 `Acc::create_witness`）。
  - 验证要点：
    - 使用 `Proof::verify()` 或 `proof.verify_with_kv(key, fid)` 验证 Merkle 路径正确（推荐使用实例方法）。
    - 验证累加器成员性：`acc::Acc::verify_membership(&post_accumulator, &post_membership_witness, &key)`。
    - 若提供 `pre_nonmembership`，验证其 `verify(key)`，断言 key 在插入前不存在（基于位置式前驱/后继证明）。

2) 查询 / 读取（Get）
- 生成证明：调用 `AccumulatorTree::get_with_proof(key)`，得到 `QueryResponse`。
  - 情况 A（存在）：返回 `fid`、`proof`（`Proof`）、`root_hash`、`accumulator`、`membership_witness`。
  - 情况 B（不存在）：返回 `nonmembership: Option<NonMembershipProof>`，包含前驱/后继及其 Merkle 证明。
  - 验证要点（存在）：
    - `proof.verify_with_kv(key, fid)` 验证 Merkle 路径。
    - `acc::Acc::verify_membership(&accumulator, &membership_witness, &key)` 验证累加器见证。
    - 或者调用 `QueryResponse::verify_full(key, fid)` 完整验证路径与累加器。
  - 验证要点（不存在）：
    - 对 `NonMembershipProof` 中的前驱/后继分别调用 `Proof::verify()`，并检查键序（`pred.key < key < succ.key`）以断言非存在性。

3) 更新（Update）
- 生成证明：调用 `AccumulatorTree::update_with_proof(key, new_fid)`，得到 `UpdateResponse`。
  - 步骤：
    1. 在更新前调用 `get_with_proof(key)` 获得 `pre_proof`、`pre_accumulator`、`pre_membership_witness`、`pre_root_hash`。
    2. 执行 `update_recursive` 修改叶节点的 `fid`。
    3. 更新后调用 `get_with_proof(key)` 获得 `post_proof`、`post_accumulator`、`post_membership_witness`、`post_root_hash`。
  - 验证要点：
    - 验证 `pre_proof`（若存在）与 `post_proof` 都通过 `Proof::verify()`。
    - 验证路径兄弟项一致性：`pre_proof.path` 与 `post_proof.path` 的长度与每一项（sibling hash + left/right 标记）应一致，确保仅叶发生更改。
    - 验证累加器：若提供 `pre_accumulator`/`pre_membership_witness`，可校验旧元素在 `pre_accumulator` 中的成员性；始终校验 `post_accumulator` 中新元素的成员性：`acc::Acc::verify_membership(&post_accumulator, &post_membership_witness, &key)`。
    - 可调用 `UpdateResponse::verify_update()` 执行上述检查的组合。

4) 删除（Delete）
- 生成证明：调用 `AccumulatorTree::delete_with_proof(key)`，得到 `DeleteResponse`。
  - 步骤：
    1. 在删除前调用 `get_with_proof(key)` 采集 `pre_proof`、`pre_accumulator`、`pre_membership_witness`、`pre_root_hash`。
    2. 执行 `delete_recursive` 标记叶为 tombstone（`deleted = true`）。
    3. 删除后使用 `get_proof_including_deleted` 定位 tombstone 叶并构建 `post_proof`（其 `leaf_hash` 应为 `empty_hash()`），同时返回 `post_accumulator`、`post_root_hash`。
  - 验证要点：
    - 验证 `pre_proof`（若存在）与 `post_proof` 的 Merkle 路径有效性（`Proof::verify()`）。
    - 验证路径兄弟项一致性（`pre_proof.path` 与 `post_proof.path` 相同长度且对应项相同），以确保仅 leaf 被 tombstone 化。
    - 若提供 `pre_accumulator`/`pre_membership_witness`，校验删除前元素在 `pre_accumulator` 中的成员性；删除后可通过 `post_accumulator` 验证剩余集合的正确性（注意：累加器实现为单元素集合的组合，删除会使 leaf 贡献为空）。
    - 可调用 `DeleteResponse::verify_delete()` 执行组合检查。

实现细节 & 注意事项
- Merkle 证明
  - 叶哈希由 `leaf_hash(key, fid)` 计算，内部节点由 `nonleaf_hash(left_hash, right_hash)` 计算。
  - 路径表示为 `Vec<(Hash, bool)>`，其中 bool 表示 sibling 是否为左子树（`true` = sibling 在左侧）。
  - `Proof::verify()` 通过从 `leaf_hash` 开始按路径重建根并与 `root_hash` 比较来验证。

- 累加器证明
  - 子树的累加器值由 `Acc::cal_acc_g1(&keys)` 计算并缓存在 `Node::NonLeaf.acc`。
  - 单元素见证通过 `Acc::create_witness(&acc, &key)` 生成，验证使用 `Acc::verify_membership(&acc, &witness, &key)`。

- 非成员证明（位置式）
  - 通过 `get_nonmembership_proof` 返回前驱/后继（如果存在），每个都包含对应的 `Proof`。
  - 验证者检查前驱/后继的 Merkle 路径有效性并验证键序关系以断言目标 key 不存在。

- 可信根哈希
  - 所有证明依赖根哈希的可信性；在分布式或离线验证场景中，应由服务端签名 `root_hash` 并向验证者提供签名/时间戳以防止回放或分叉攻击。

示例快速参考（伪代码）
```
// 验证一次 get 的完整性
let qr = tree.get_with_proof("key");
if let Some(fid) = qr.fid {
    assert!(qr.verify_full("key", &fid));
} else if let Some(nm) = qr.nonmembership {
    assert!(nm.verify("key"));
}
```

如需我把上述文档拆为单独文件（例如 `DOCS/PROOFS.md`）或生成对应的 Rustdoc 注释，我可以接着把文档结构化并提交改动。
