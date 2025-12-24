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

文档位置
---------
文档已生成：`DOCS/CHANGES_AND_API.md`（项目根目录）。

如需把文档合并入仓库的 `README.md` 或生成更详细的 API 文档（Rustdoc 注释），我可以继续处理。