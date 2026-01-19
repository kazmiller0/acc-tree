use ark_bls12_381::{Bls12_381 as Curve, Fq12, Fr, G1Affine, G1Projective, G2Affine, G2Projective};
use ark_ec::{AffineCurve, PairingEngine, ProjectiveCurve};
use core::str::FromStr;
use lazy_static::lazy_static;
use log::info;
use rayon::prelude::*;

use super::utils::{FixedBaseCurvePow, FixedBaseScalarPow};

#[cfg(test)]
const GS_VEC_LEN: usize = 20;
#[cfg(not(test))]
const GS_VEC_LEN: usize = 5000;

lazy_static! {
    // Secret trapdoor s (discard in production)
    pub static ref PRI_S: Fr = Fr::from_str("259535143263514268207918833918737523409").unwrap();

    // Generator powers
    pub static ref G1_POWER: FixedBaseCurvePow<G1Projective> =
        FixedBaseCurvePow::build(&G1Projective::prime_subgroup_generator());
    pub static ref G2_POWER: FixedBaseCurvePow<G2Projective> =
        FixedBaseCurvePow::build(&G2Projective::prime_subgroup_generator());

    pub static ref PRI_S_POWER: FixedBaseScalarPow<Fr> = FixedBaseScalarPow::build(&PRI_S);

    // Precomputed G1 powers: g, g^s, ...
    pub static ref G1_S_VEC: Vec<G1Affine> = {
        info!("Initialize G1_S_VEC...");
        let timer = howlong::ProcessCPUTimer::new();
        let mut res: Vec<G1Affine> = Vec::with_capacity(GS_VEC_LEN);
        (0..GS_VEC_LEN)
            .into_par_iter()
            .map(|i| get_g1s(Fr::from(i as u64)))
            .collect_into_vec(&mut res);
        info!("Done in {}.", timer.elapsed());
        res
    };

    // Precomputed G2 powers: g, g^s, ...
    pub static ref G2_S_VEC: Vec<G2Affine> = {
        info!("Initialize G2_S_VEC...");
        let timer = howlong::ProcessCPUTimer::new();
        let mut res: Vec<G2Affine> = Vec::with_capacity(GS_VEC_LEN);
        (0..GS_VEC_LEN)
            .into_par_iter()
            .map(|i| get_g2s(Fr::from(i as u64)))
            .collect_into_vec(&mut res);
        info!("Done in {}.", timer.elapsed());
        res
    };

    // Precomputed Pairing(g1, g2)
    pub static ref E_G_G: Fq12 = Curve::pairing(
        G1Affine::prime_subgroup_generator(),
        G2Affine::prime_subgroup_generator()
    );
}

pub fn get_g1s(coeff: Fr) -> G1Affine {
    let si = PRI_S_POWER.apply(&coeff);
    G1_POWER.apply(&si).into_affine()
}

pub fn get_g2s(coeff: Fr) -> G2Affine {
    let si = PRI_S_POWER.apply(&coeff);
    G2_POWER.apply(&si).into_affine()
}
