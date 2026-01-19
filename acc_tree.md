
基于对你上传代码的深入分析，以下是 **Acc-Tree (Accumulator Tree)** 项目当前的架构设计文档。

---

# Acc-Tree 架构设计文档

## 1. 系统概述

**Acc-Tree** 是一个混合型的**可验证数据结构 (Authenticated Data Structure, ADS)**。它结合了 **Merkle Tree** 的位置绑定能力和 **基于双线性对 (Bilinear Pairing) 的动态累加器** 的集合成员证明能力。

* **核心目标**：提供键值对 (Key-Value) 的安全存储，并支持生成加密证明（Proof），允许第三方在不持有完整数据的情况下验证数据的完整性（Integrity）和成员资格（Membership）。
* **关键特性**：
* **双重验证**：每个节点同时维护 Merkle Hash 和 Accumulator 值。
* **森林结构**：采用类似 MMR (Merkle Mountain Range) 的森林结构优化写入性能。
* **增量更新**：针对 Value 更新进行了特定优化，避免昂贵的密码学重算。



---

## 2. 分层架构

系统在逻辑上分为两层：底层密码学原语层和上层数据结构层。

### 2.1 底层核心：`accumulator_ads` (Cryptographic Core)

该层封装了所有与椭圆曲线和零知识证明相关的数学逻辑，不感知具体的树结构。

* **基础曲线**：基于 `BLS12-381` 椭圆曲线。
* **动态累加器 (`DynamicAccumulator`)**：
* 实现了基于秘密陷门  的动态累加器。
* 支持  复杂度的 `Add` (添加), `Delete` (删除), `Update` (更新) 操作。
* **核心公式**：累加器值 。


* **证明系统 (`Proofs`)**：
* 实现了 `MembershipProof` (成员证明) 和 `NonMembershipProof` (非成员证明)。
* 支持集合操作证明：`IntersectionProof` (交集), `UnionProof` (并集), `DisjointnessProof` (不相交)。



### 2.2 应用层：`accumulator-tree` (Data Structure)

该层利用底层的累加器构建具体的 KV 存储引擎。

* **数据组织**：维护树/森林的拓扑结构 (`Node`, `AccumulatorTree`)。
* **业务逻辑**：处理 KV 的增删改查，并协调底层库生成综合证明 (`QueryResponse`, `UpdateResponse`)。
* **哈希计算**：使用 `SHA256` 计算 Merkle 路径哈希。

---

## 3. 核心数据结构设计

### 3.1 森林结构 (The Forest)

`AccumulatorTree` 并非维护单一的一棵大树，而是维护一个 **子树森林**。

* **定义**：`pub roots: Vec<Box<Node>>`。
* **写入策略 (Normalize)**：
* 新插入的数据总是作为 Level 0 的叶子节点追加到 `roots` 列表末尾。
* **合并规则**：当 `roots` 列表中出现两个相同高度 (`level`) 的根节点时，系统会自动将它们合并为一个更高一层 (`level + 1`) 的父节点。这是一种类似 LSM-Tree 内存组件或 MMR 的设计，极大地优化了追加写入性能。



### 3.2 混合节点 (Hybrid Node)

`Node` 枚举结构同时承载了 Merkle Tree 和 Accumulator 的属性。

| 节点类型               | 包含字段             | 作用                                                             |
| ---------------------- | -------------------- | ---------------------------------------------------------------- |
| **Leaf (叶子)**        | `key`, `fid` (Value) | 存储实际数据。                                                   |
|                        | `deleted` (bool)     | **墓碑机制 (Tombstone)**：软删除标记。                           |
| **NonLeaf (中间节点)** | `hash` (Hash)        | **Merkle 属性**：`SHA256(left.hash, right.hash)`，用于路径证明。 |
|                        | `acc` (G1Affine)     | **累加器属性**：该子树下所有 Key 的累加器值，用于成员证明。      |
|                        | `keys` (Set)         | **全量索引**：维护该子树下所有 Key 的集合（用于计算 `acc`）。    |

---

## 4. 关键工作流 (Key Workflows)

### 4.1 插入 (Insert)

1. 创建新的 `Node::Leaf`。
2. 追加到 `roots` 列表。
3. 触发 `normalize()`：递归合并相同高度的根节点。合并时，父节点的 `acc` 由左右子节点的 `acc` 和 `keys` 集合通过增量算法 (`incremental_union`) 计算得出。

### 4.2 更新 (Update)

针对 Value 更新做了关键性能优化。

* **流程**：找到叶子节点 -> 修改 `fid` -> 递归更新父节点。
* **优化**：因为累加器只与 `Key` 有关，而 Update 操作只修改 `Value`，所以 **只重新计算 Merkle Hash，不重新计算 Accumulator**。这避免了昂贵的椭圆曲线运算。

### 4.3 删除 (Delete)

* **机制**：软删除 (Soft Delete)。
* **流程**：找到叶子节点 -> 将 `deleted` 标记设为 `true`。
* **影响**：
* `hash` 变为 `empty_hash`。
* `acc` 变为 `empty_acc`（空集累加器）。
* **注意**：删除是逻辑上的，节点并未从内存物理移除，且需要更新路径上的 Hash。



### 4.4 证明与验证 (Query & Verify)

查询不仅返回数据，还返回一个强一致性证明 `QueryResponse`。

* **证明组成**：
1. **Merkle Path** (`proof.path`)：证明 `Leaf` 位于树的特定位置。
2. **Accumulator Witness** (`membership_witness`)：证明 `Leaf.Key` 存在于 `Root.Acc` 定义的集合中。


* **验证逻辑**：
* **步骤 1**：重算 Merkle Root，验证位置正确性。
* **步骤 2**：使用双线性对验证 ，验证成员资格。



---

## 5. 安全性模型

* **中心化更新 (Prover)**：
* 系统依赖一个秘密陷门 `PRI_S` (Secret ) 来执行  的 Add/Delete 操作。
* 持有 `PRI_S` 的实体（服务器/Prover）负责维护树的状态。


* **公开可验证 (Verifier)**：
* 验证过程 **不需要** 知道秘密 。
* Verifier 只需要公共参数（Public Parameters，如 ），即可验证证明的有效性。



## 6. 总结

当前的架构是一个 **追加优化 (Append-optimized)、双重验证 (Dual-authenticated)** 的存储系统。它牺牲了一定的内存空间（中间节点存储 Key 集合）和去中心化属性（依赖陷门），换取了极高的验证灵活性（同时支持位置证明和集合证明）以及针对 Value 更新的高性能。