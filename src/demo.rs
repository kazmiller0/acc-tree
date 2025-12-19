use acc::Acc;
use std::time::{Duration, Instant};

fn mean(durs: &[Duration]) -> Duration {
    if durs.is_empty() {
        return Duration::ZERO;
    }
    let total = durs.iter().fold(Duration::ZERO, |acc, &d| acc + d);
    total / (durs.len() as u32)
}

fn stddev(durs: &[Duration], mu: Duration) -> Duration {
    if durs.len() <= 1 {
        return Duration::ZERO;
    }
    let ms: Vec<f64> = durs.iter().map(|d| d.as_secs_f64() * 1000.0).collect();
    let mu_ms = mu.as_secs_f64() * 1000.0;
    let var = ms.iter().map(|x| (x - mu_ms).powi(2)).sum::<f64>() / ((ms.len() - 1) as f64);
    Duration::from_secs_f64((var.sqrt() / 1000.0).max(0.0))
}

pub fn demo() {
    let mut tree = super::AccumulatorTree::new();
    println!("simple demo:");
    tree.insert("A".into(), "fa".into());
    tree.insert("B".into(), "fb".into());
    tree.update("B", "fb_u".into());
    tree.delete("A");
    super::print_tree(&tree);
}

pub fn run_benchmark(n: usize) {
    let repeats = 5usize;
    println!("Benchmark: n = {}, repeats = {}", n, repeats);

    let mut ins_times = Vec::with_capacity(repeats);
    let mut upd_times = Vec::with_capacity(repeats);
    let mut del_times = Vec::with_capacity(repeats);
    let mut qry_times = Vec::with_capacity(repeats);
    let mut ver_times = Vec::with_capacity(repeats);

    for r in 0..repeats {
        let mut tree = super::AccumulatorTree::new();

        let t0 = Instant::now();
        for i in 0..n {
            tree.insert(format!("Key{}", i), format!("Fid{}", i));
        }
        ins_times.push(t0.elapsed());

        let t1 = Instant::now();
        for i in (0..n).step_by(10) {
            tree.update(&format!("Key{}", i), format!("Fid{}_u", i));
        }
        upd_times.push(t1.elapsed());

        let t2 = Instant::now();
        for i in (0..n).step_by(5) {
            tree.delete(&format!("Key{}", i));
        }
        del_times.push(t2.elapsed());

        let t3 = Instant::now();
        let mut _found = 0usize;
        for i in 0..n {
            let key = format!("Key{}", i);
            if tree.roots.iter().any(|r| r.has_key(&key)) {
                _found += 1;
            }
        }
        qry_times.push(t3.elapsed());

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
        ver_times.push(t4.elapsed());

        println!(
            "run {}: insert {:?}, update {:?}, delete {:?}, query {:?}, verify(sample {}) {:?} (ok {})",
            r + 1,
            ins_times[r],
            upd_times[r],
            del_times[r],
            qry_times[r],
            sample,
            ver_times[r],
            verify_ok
        );
    }

    let ins_mu = mean(&ins_times);
    let upd_mu = mean(&upd_times);
    let del_mu = mean(&del_times);
    let qry_mu = mean(&qry_times);
    let ver_mu = mean(&ver_times);

    println!("\nSummary (mean ± stddev):");
    println!(
        "Insert: {:?} ± {:?} (per-op {:?})",
        ins_mu,
        stddev(&ins_times, ins_mu),
        ins_mu / (n as u32)
    );
    println!(
        "Update: {:?} ± {:?} (per-op {:?})",
        upd_mu,
        stddev(&upd_times, upd_mu),
        upd_mu / ((n / 10) as u32)
    );
    println!(
        "Delete: {:?} ± {:?} (per-op {:?})",
        del_mu,
        stddev(&del_times, del_mu),
        del_mu / ((n / 5) as u32)
    );
    println!(
        "Query: {:?} ± {:?} (per-op {:?})",
        qry_mu,
        stddev(&qry_times, qry_mu),
        qry_mu / (n as u32)
    );
    println!(
        "Verify(sample 1000): {:?} ± {:?}",
        ver_mu,
        stddev(&ver_times, ver_mu)
    );
}
