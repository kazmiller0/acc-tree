//! Example: Initialize and test public parameters
//!
//! This example shows how to initialize public parameters for testing.
//! Run with: cargo test --example init_params

#[cfg(any(test, debug_assertions))]
use accumulator_ads::acc::setup::{init_public_parameters_direct, PublicParameters};

#[cfg(any(test, debug_assertions))]
fn main() -> anyhow::Result<()> {
    use ark_bls12_381::Fr;

    println!("=== Testing Public Parameter Initialization ===");
    println!();

    // For testing: generate parameters directly
    let secret_s = Fr::from(259535143263514268207918833918737523409u128);
    let params = PublicParameters::generate_for_testing(secret_s, 100);

    println!("Initializing public parameters...");
    init_public_parameters_direct(params)?;

    println!("✓ Public parameters initialized successfully");
    println!();
    println!("The accumulator library is now ready to use.");
    println!("All verification operations will use ONLY public parameters.");
    println!("No secret trapdoor is required for verification!");

    Ok(())
}

#[cfg(not(any(test, debug_assertions)))]
fn main() {
    eprintln!("This example requires test mode. Run with: cargo test --example init_params");
}
