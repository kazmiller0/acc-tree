// 模块声明
pub mod crypto;
pub mod node;
pub mod tree;

pub mod proof;
pub mod utils;
pub mod demo;

// 对外暴露的公共 API
pub use crypto::{empty_acc, empty_hash, leaf_hash, nonleaf_hash, Hash};
pub use node::Node;
pub use tree::AccumulatorTree;

pub use proof::*;
pub use utils::{print_tree, render_keys};
pub use demo::{demo, run_benchmark};

#[cfg(test)]
mod tests;
