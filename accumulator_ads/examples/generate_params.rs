//! Example: Generate public parameters for trusted setup
//!
//! This tool generates public parameters for the accumulator scheme.
//! Run with: cargo test --features="" --example generate_params
//!
//! **CRITICAL SECURITY WARNING**:
//! In production, the secret trapdoor s MUST be generated in a secure trusted setup ceremony
//! and DESTROYED immediately after generating the public parameters.
//!
//! This example is for TESTING PURPOSES ONLY.

#[cfg(any(test, debug_assertions))]
use accumulator_ads::acc::setup::PublicParameters;

#[cfg(any(test, debug_assertions))]
fn main() -> anyhow::Result<()> {
    use ark_bls12_381::Fr;

    println!("=== Accumulator Public Parameters Generator ===");
    println!();
    println!("⚠️  WARNING: This is for TESTING ONLY!");
    println!("⚠️  In production, use a secure trusted setup ceremony.");
    println!("⚠️  The secret trapdoor MUST be destroyed after generation.");
    println!();

    // For testing: use a fixed secret s
    let secret_s = Fr::from(259535143263514268207918833918737523409u128);

    println!("Generating public parameters...");
    println!("Maximum degree: 5000");
    println!();

    let params = PublicParameters::generate_for_testing(secret_s, 5000);

    // Save to file
    let output_path = "public_params.bin";
    params.save_to_file(output_path)?;

    println!("✓ Public parameters saved to: {}", output_path);
    println!(
        "✓ Parameters contain {} G1 powers and {} G2 powers",
        params.g1_s_vec.len(),
        params.g2_s_vec.len()
    );
    println!();
    println!("🔥 IMPORTANT: In production, the secret s must now be DESTROYED!");
    println!("🔥 Only the public parameters file should be distributed.");

    Ok(())
}

#[cfg(not(any(test, debug_assertions)))]
fn main() {
    eprintln!("This example requires test mode. Run with: cargo test --example generate_params");
}
