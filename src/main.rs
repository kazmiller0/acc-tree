use accumulator_tree::*;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() >= 3 && args[1] == "bench" {
        if let Ok(n) = args[2].parse::<usize>() {
            run_benchmark(n);
            return;
        }
    }
    demo();
}
