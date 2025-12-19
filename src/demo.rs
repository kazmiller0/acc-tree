use acc::Acc;
use std::time::Instant;

pub fn demo() {
    let mut tree = super::AccumulatorTree::new();
    println!("--- Insert 1 ---");
    tree.insert("Key1".to_string(), "Fid1".to_string());
    super::print_tree(&tree);
    println!("\n--- Insert 2 ---");
    tree.insert("Key2".to_string(), "Fid2".to_string());
    super::print_tree(&tree);
    println!("\n--- Insert 3 ---");
    tree.insert("Key3".to_string(), "Fid3".to_string());
    super::print_tree(&tree);
    println!("\n--- Update Key3 ---");
    tree.update("Key3", "Fid3_Updated".to_string());
    super::print_tree(&tree);
    println!("\n--- Delete Key2 ---");
    tree.delete("Key2");
    super::print_tree(&tree);
}

pub fn run_benchmark(n: usize) {
    println!("Running benchmark with {} keys", n);
    let mut tree = super::AccumulatorTree::new();
    let t0 = Instant::now();
    for i in 0..n {
        tree.insert(format!("Key{}", i), format!("Fid{}", i));
    }
    let dur_ins = t0.elapsed();
    let t1 = Instant::now();
    for i in (0..n).step_by(10) {
        tree.update(&format!("Key{}", i), format!("Fid{}_u", i));
    }
    let dur_upd = t1.elapsed();
    let t2 = Instant::now();
    for i in (0..n).step_by(5) {
        tree.delete(&format!("Key{}", i));
    }
    let dur_del = t2.elapsed();
    let t3 = Instant::now();
    let mut found = 0usize;
    for i in 0..n {
        let key = format!("Key{}", i);
        if tree.roots.iter().any(|r| r.has_key(&key)) {
            found += 1;
        }
    }
    let dur_q = t3.elapsed();
    let sample = std::cmp::min(1000, n);
    let t4 = Instant::now();
    let mut verify_ok = 0usize;
    for i in 0..sample {
        let key = format!("Key{}", (i * 13) % n);
        if let Some(idx) = tree.roots.iter().position(|r| r.has_key(&key)) {
            let acc = tree.roots[idx].acc();
            let witness = Acc::create_witness(&acc, &key);
            if Acc::verify_membership(&acc, &witness, &key) {
                verify_ok += 1;
            }
        }
    }
    let dur_v = t4.elapsed();
    println!(
        "Insert: total {:?}, per-op {:?}",
        dur_ins,
        dur_ins / (n as u32)
    );
    println!(
        "Update: total {:?}, per-op {:?}",
        dur_upd,
        dur_upd / ((n / 10) as u32)
    );
    println!(
        "Delete: total {:?}, per-op {:?}",
        dur_del,
        dur_del / ((n / 5) as u32)
    );
    println!(
        "Query: total {:?}, per-op {:?}, found {}/{}",
        dur_q,
        dur_q / (n as u32),
        found,
        n
    );
    println!(
        "Verify(sample {}): total {:?}, ok {}/{}",
        sample, dur_v, verify_ok, sample
    );
}
