项目变更与使用文档
=================

概览
----
本仓库增加并完善了用于查询（Get）和插入（Insert）操作的证明生成与验证：

- 成员证明（membership proof）
  - 对于存在的 key，返回从叶到根的路径哈希证明（`Proof`），并返回对应子树的累加器值 `acc` 及单元素见证 `acc_witness`。
  - 提供 `Proof::verify()` 与 `QueryResponse::verify_full(key, fid)` 用来验证哈希路径与累加器成员性闭环。

- 非成员证明（non-membership proof，方案 A：基于树位置）
  - 当查询未命中时，返回 `NonMembershipProof`，包含前驱（predecessor）和/或后继（successor）叶的 `(key, fid, Proof)`。
  - 验证器只需验证前驱/后继各自的 Merkle 路径与键序关系（`pred.key < key < succ.key`）即可断言目标 key 不存在。

- 插入证明（insert with proof）
  - `insert_with_proof` 在插入前截取 `pre_roots`（每个 root 的 `(root_hash, acc)` 快照），并可以返回 `pre_nonmembership`（若能构造），在插入后返回 `post_proof`、`post_acc`、`post_acc_witness`。

被修改 / 新增的文件（重点）
-------------------------
- `src/lib.rs`
  - 新增：`get_with_proof(&self, key)` -> `QueryResponse`（包含 `fid`、`proof`、`root_hash`、`acc`、`acc_witness`、`nonmembership`）。
  - 新增：`insert_with_proof(&mut self, key, fid)` -> `InsertResponse`（包含 `pre_roots`、`pre_nonmembership`、`post_*`）。
  - 新增：`get_nonmembership_proof(&self, key)` 和辅助函数 `find_pred_succ`/`get_proof_recursive`。

- `src/proof.rs`
  - 新增类型：`Proof`、`QueryResponse`（含 `verify_full`）、`InsertResponse`、`NonMembershipProof`（含 `verify`）。

- `src/tests.rs`
  - 增加/更新若干测试：验证 `get_with_proof`、`insert_with_proof`、`NonMembershipProof` 行为。

API 快速使用示例
-----------------
（示例均在项目内已有测试中体现，以下给出小段示意）

- 查询并验证存在项：

```rust
let qr = tree.get_with_proof("key");
if let Some(fid) = qr.fid {
    // 验证路径与累加器
    assert!(qr.verify_full("key", &fid));
}
```

- 查询未命中并验证非存在性：

```rust
let qr = tree.get_with_proof("missing_key");
assert!(qr.fid.is_none());
if let Some(nm) = qr.nonmembership {
    assert!(nm.verify("missing_key"));
}
```

- 插入并获取插入前/后的证明：

```rust
let resp = tree.insert_with_proof("new_key".to_string(), "fid_new".to_string());
// 可验证插入前的非存在性（如果有）
if let Some(pre_nm) = &resp.pre_nonmembership {
    assert!(pre_nm.verify(&resp.key));
}
// 验证插入后的成员证明
let post_proof = resp.post_proof.expect("post proof present");
assert!(post_proof.verify());
let acc = resp.post_acc.unwrap();
let witness = resp.post_acc_witness.unwrap();
assert!(acc::Acc::verify_membership(&acc, &witness, &resp.key));
```

设计说明与限制
----------------
- 非成员证明采用位置式（前驱/后继）方法，依赖键的全序（当前为字符串字典序）。验证者必须信任用于构建 `Proof` 的根哈希（或接受服务器对根哈希的签名）。
- 该非成员证明不是代数上的不可否认非成员证明；若需要数学上强不可否认的非成员证明，应考虑引入或实现累加器级别的非成员证明（工作量大，需谨慎设计）。
- `QueryResponse::verify_full` 同时验证 Merkle 路径与累加器成员性；这已在测试中覆盖。

建议的下一步（可选）
-----------------
- 为 `NonMembershipProof` 和 `InsertResponse` 添加 `serde` 序列化支持，并在服务端对 `root_hash` 签名，便于第三方离线验证。
- 如果需要返回“详细失败原因”，把 `verify()` 返回类型从 `bool` 改为 `Result<(), VerifyError>` 并定义错误枚举。
- 若需代数非成员证明，我可以先草拟设计方案并列出所需库与接口变更。

新增：更新与删除操作的证明
---------------------------
- 更新证明（Update proof）
  - 新增类型 `UpdateResponse`（定义于 `src/proof.rs`）：包含 `key`、`old_fid`、`new_fid`、更新前后的 Merkle 路径证明（`pre_proof` / `post_proof`）、前后累加器快照与对应 witness（`pre_acc`/`pre_acc_witness`、`post_acc`/`post_acc_witness`），以及前后 root hash。
  - 新增方法 `AccumulatorTree::update_with_proof(&mut self, key, new_fid)`（定义于 `src/lib.rs`）：先采集更新前的证明与累加器见证，执行更新，再返回更新后的证明与见证；用于让验证者确认仅该叶的 `fid` 被替换且树的其余部分未被篡改。
  - 新增验证方法 `UpdateResponse::verify_update()`：检查 pre/post Merkle 路径、路径兄弟项一致性（确保仅 leaf 发生变化），并验证累加器成员性（若提供 pre witness，则验证 old 元素在 pre_acc 中的成员性；始终验证 post 成员性）。

- 删除证明（Delete proof）
  - 新增类型 `DeleteResponse`（定义于 `src/proof.rs`）：包含 `key`、`old_fid`、删除前的 Merkle 证明与累加器见证（`pre_*`），以及删除后（tombstone）的 Merkle 证明 `post_proof`（其叶哈希应为 `empty_hash()`）和 `post_acc`、`post_root_hash`。
  - 新增方法 `AccumulatorTree::delete_with_proof(&mut self, key)`（定义于 `src/lib.rs`）：先采集删除前证明与累加器见证，执行删除操作（生成 tombstone），再返回删除后的 tombstone 路径证明与累加器快照，便于离线验证删除合法性与完整性保持。
  - 新增验证方法 `DeleteResponse::verify_delete()`：验证 pre/post 路径、路径兄弟项一致性（仅 leaf 改变），并验证 pre-state 中被删除元素的累加器成员性（若提供）。

测试与压力测试
----------------
- 单元测试：`src/tests.rs` 已新增并更新若干测试以覆盖 `update_with_proof` 与 `delete_with_proof` 行为：
  - `test_update_with_proof`：插入一个键、执行 `update_with_proof`，并验证 `old_fid`/`new_fid`、post proof、路径兄弟项一致性与 `verify_update()`。
  - `test_delete_with_proof`：插入一个键、执行 `delete_with_proof`，并验证 `old_fid`、删除后的 tombstone 路径（`post_proof`）与 `verify_delete()`。

- 压力测试：为更真实地覆盖增删改查场景，`src/tests.rs` 中加入了两项较大的、但默认被忽略的压力测试：
  - `test_bulk_kv_operations_large`（默认 `#[ignore]`，可手动运行）：批量插入/更新/删除并校验状态一致性。当前规模为 n=500（可通过编辑或运行参数调整）。
  - `test_randomized_property_operations_large`（默认 `#[ignore]`）：随机化的 1000 次操作（插入/更新/删除），键空间 200，用于在更大样本上验证引用一致性。
  - 说明：这两项被 `#[ignore]` 标记以避免每次 `cargo test` 都运行压力测试；可用 `cargo test -- --ignored` 手动运行。若需要，我可以把它们改成基于 cargo feature 的可选测试（例如 `--features stress`）。

已完成与验证
---------------
- 代码实现已新增 `UpdateResponse`、`DeleteResponse`、`update_with_proof`、`delete_with_proof`，以及相关辅助函数（例如 `get_proof_including_deleted`）。
- 单元测试：运行 `cargo test`，默认测试通过（示例运行中报告：15 passed, 0 failed, 2 ignored）。

建议的下一步（可选）
------------------
- 为 `UpdateResponse`、`DeleteResponse` 和其它证明类型添加 `serde` 序列化支持并考虑对 `root_hash` 做签名，便于第三方或客户端验证。
- 将 `verify_*` 的返回类型改为 `Result<(), VerifyError>` 提供更精确错误定位。
- 将压力测试移入独立基准（`benches/`）或由 cargo feature 控制，以便 CI/开发流程更灵活地运行。

文档位置
---------
文档已生成：`DOCS/CHANGES_AND_API.md`（项目根目录）。

如需把文档合并入仓库的 `README.md` 或生成更详细的 API 文档（Rustdoc 注释），我可以继续处理。

证明实现与验证流程（增删改查）
---------------------------------
下面按 CRUD 操作分别说明在本项目中如何生成证明（proof）以及验证（verify）这些证明的流程，包含关键代码点与验证要点。

1) 创建 / 插入（Insert）
- 生成证明：调用 `AccumulatorTree::insert_with_proof(key, fid)`。
  - 步骤：
    1. 在插入前，采集 `pre_roots`（每个 root 的 `(root_hash, acc)` 快照）。
    2. 尝试构造 `pre_nonmembership`（调用 `get_nonmembership_proof`，返回 `NonMembershipProof` 包含前驱/后继的 Merkle 证明，若能构造）。
    3. 插入或 revive 叶节点。
    4. 插入后，调用 `get_with_proof(key)` 构建 `post_proof`（`Proof`，包含 `root_hash`、`leaf_hash`、`path`）以及 `post_acc` / `post_acc_witness`（使用 `Acc::create_witness`）。
  - 验证要点：
    - 使用 `Proof::verify()` 或 `Proof::verify_with_kv(root_hash, key, fid, path)` 验证 Merkle 路径正确。
    - 验证累加器成员性：`acc::Acc::verify_membership(&post_acc, &post_acc_witness, &key)`。
    - 若提供 `pre_nonmembership`，验证其 `verify(key)`，断言 key 在插入前不存在（基于位置式前驱/后继证明）。

2) 查询 / 读取（Get）
- 生成证明：调用 `AccumulatorTree::get_with_proof(key)`，得到 `QueryResponse`。
  - 情况 A（存在）：返回 `fid`、`proof`（`Proof`）、`root_hash`、`acc`、`acc_witness`。
  - 情况 B（不存在）：返回 `nonmembership: Option<NonMembershipProof>`，包含前驱/后继及其 Merkle 证明。
  - 验证要点（存在）：
    - `Proof::verify_with_kv(root_hash, key, fid, path)` 验证 Merkle 路径。
    - `acc::Acc::verify_membership(&acc, &acc_witness, &key)` 验证累加器见证。
    - 或者调用 `QueryResponse::verify_full(key, fid)` 完整验证路径与累加器。
  - 验证要点（不存在）：
    - 对 `NonMembershipProof` 中的前驱/后继分别调用 `Proof::verify()`，并检查键序（`pred.key < key < succ.key`）以断言非存在性。

3) 更新（Update）
- 生成证明：调用 `AccumulatorTree::update_with_proof(key, new_fid)`，得到 `UpdateResponse`。
  - 步骤：
    1. 在更新前调用 `get_with_proof(key)` 获得 `pre_proof`、`pre_acc`、`pre_acc_witness`、`pre_root_hash`。
    2. 执行 `update_recursive` 修改叶节点的 `fid`。
    3. 更新后调用 `get_with_proof(key)` 获得 `post_proof`、`post_acc`、`post_acc_witness`、`post_root_hash`。
  - 验证要点：
    - 验证 `pre_proof`（若存在）与 `post_proof` 都通过 `Proof::verify()`。
    - 验证路径兄弟项一致性：`pre_proof.path` 与 `post_proof.path` 的长度与每一项（sibling hash + left/right 标记）应一致，确保仅叶发生更改。
    - 验证累加器：若提供 `pre_acc`/`pre_acc_witness`，可校验旧元素在 `pre_acc` 中的成员性；始终校验 `post_acc` 中新元素的成员性：`acc::Acc::verify_membership(&post_acc, &post_acc_witness, &key)`。
    - 可调用 `UpdateResponse::verify_update()` 执行上述检查的组合。

4) 删除（Delete）
- 生成证明：调用 `AccumulatorTree::delete_with_proof(key)`，得到 `DeleteResponse`。
  - 步骤：
    1. 在删除前调用 `get_with_proof(key)` 采集 `pre_proof`、`pre_acc`、`pre_acc_witness`、`pre_root_hash`。
    2. 执行 `delete_recursive` 标记叶为 tombstone（`deleted = true`）。
    3. 删除后使用 `get_proof_including_deleted` 定位 tombstone 叶并构建 `post_proof`（其 `leaf_hash` 应为 `empty_hash()`），同时返回 `post_acc`、`post_root_hash`。
  - 验证要点：
    - 验证 `pre_proof`（若存在）与 `post_proof` 的 Merkle 路径有效性（`Proof::verify()`）。
    - 验证路径兄弟项一致性（`pre_proof.path` 与 `post_proof.path` 相同长度且对应项相同），以确保仅 leaf 被 tombstone 化。
    - 若提供 `pre_acc`/`pre_acc_witness`，校验删除前元素在 `pre_acc` 中的成员性；删除后可通过 `post_acc` 验证剩余集合的正确性（注意：累加器实现为单元素集合的组合，删除会使 leaf 贡献为空）。
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

详情的增删改查证明实现与验证流程已拆分到独立文档：`DOCS/PROOFS.md`。