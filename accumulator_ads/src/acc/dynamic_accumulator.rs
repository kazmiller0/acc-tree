//! Implements a dynamic cryptographic accumulator that supports additions, deletions,
//! intersection, union, and disjointness proofs.
//!
//! # Trapdoor Note
//! This implementation assumes the entity has access to the secret trapdoor `PRI_S`.
//! Operations like add, delete, and update are performed in O(1) using the trapdoor.

use anyhow::{anyhow, ensure, Context, Result};
use ark_bls12_381::{Fr, G1Affine, G1Projective, G2Affine};
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{Field, One, PrimeField, Zero};
use ark_poly::{
    univariate::{DenseOrSparsePolynomial, DensePolynomial},
    Polynomial, UVPolynomial,
};
use std::ops::{Mul, Neg};

use super::proofs::{MembershipProof, NonMembershipProof};
use crate::acc::digest_set::DigestSet;
use crate::acc::utils::{poly_to_g1, poly_to_g2, xgcd};
// 假设 PRI_S 在生产构建中也是可见的，请确保该模块在正式编译中可用
use super::setup::PRI_S;

/// Represents the result of a query against the accumulator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryResult {
    /// The element is in the set, and here is the proof.
    Membership(MembershipProof),
    /// The element is not in the set, and here is the proof.
    NonMembership(Box<NonMembershipProof>),
}

/// A dynamic cryptographic accumulator based on the Acc scheme.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DynamicAccumulator {
    /// The current accumulator value, g1^P(s).
    pub acc_value: G1Affine,
}

impl Default for DynamicAccumulator {
    fn default() -> Self {
        Self::new()
    }
}

impl DynamicAccumulator {
    /// Creates a new, empty dynamic accumulator.
    pub fn new() -> Self {
        Self {
            acc_value: G1Projective::from(G1Affine::prime_subgroup_generator())
                .mul(Fr::one().into_repr())
                .into_affine(),
        }
    }

    /// Static method: Fast calculation of set commitment using MSM.
    /// Used when initializing from a large set from scratch.
    pub fn calculate_commitment(set: &DigestSet<Fr>) -> G1Affine {
        poly_to_g1(set.expand_to_poly())
    }

    /// Factory method: Initialize accumulator from a DigestSet.
    pub fn from_set(set: &DigestSet<Fr>) -> Self {
        Self {
            acc_value: Self::calculate_commitment(set),
        }
    }

    /// Helper: Compute G2 commitment
    pub fn calculate_commitment_g2(set: &DigestSet<Fr>) -> G2Affine {
        poly_to_g2(set.expand_to_poly())
    }

    // ==========================================
    // 1. Add & Delete & Update (With Trapdoor s)
    // ==========================================

    /// Computes the new accumulator value after adding an element using the trapdoor.
    /// acc' = acc^(s - element)
    pub fn compute_add(&self, element: Fr) -> G1Affine {
        let s_minus_elem: Fr = *PRI_S - element;
        self.acc_value.mul(s_minus_elem).into_affine()
    }

    /// Computes the new accumulator value after deleting an element using the trapdoor.
    /// acc' = acc^(1 / (s - element))
    pub fn compute_delete(&self, element: Fr) -> Result<G1Affine> {
        let s_minus_elem: Fr = *PRI_S - element;
        let inverse = s_minus_elem.inverse().ok_or_else(|| {
            anyhow!("Failed to compute inverse: element might be equal to s (Trapdoor collision)")
        })?;

        Ok(self.acc_value.mul(inverse).into_affine())
    }

    /// Computes the new accumulator value after updating an element using the trapdoor.
    /// acc' = acc^((s - new) / (s - old))
    pub fn compute_update(&self, old_element: Fr, new_element: Fr) -> Result<G1Affine> {
        // Step 1: Delete old (multiply by 1/(s-old))
        let temp_acc = self.compute_delete(old_element)?;

        // Step 2: Add new (multiply by (s-new))
        let s_minus_new: Fr = *PRI_S - new_element;
        Ok(temp_acc.mul(s_minus_new).into_affine())
    }

    // ==========================================
    // 2. Query
    // ==========================================

    /// Computes the membership witness (proof) for an element.
    /// The witness for `x` is simply the accumulator value as if `x` was deleted.
    /// witness = acc^(1/(s-x))
    pub fn compute_membership_witness(&self, element: Fr) -> Result<G1Affine> {
        self.compute_delete(element)
    }

    /// Computes witnesses for non-membership.
    /// Returns (witness=g2^B(s), g2_a=g2^A(s)) where A(x)P(x) + B(x)(x-element) = 1
    pub fn compute_non_membership_witness(
        element: Fr,
        set: &DigestSet<Fr>,
    ) -> Result<(G2Affine, G2Affine)> {
        // 1. Construct P(X)
        let p_poly = set.expand_to_poly();

        // 2. Construct (X - element)
        let elem_poly = DensePolynomial::from_coefficients_vec(vec![element.neg(), Fr::one()]);

        // 3. Solve Bezout identity
        let (a_poly, b_poly) = crate::acc::utils::solve_bezout_identity(p_poly, elem_poly)
            .context("GCD is not constant, element might be in set")?;

        Ok((poly_to_g2(b_poly), poly_to_g2(a_poly)))
    }

    // ==========================================
    // 3. Set Operations Witnesses
    // ==========================================

    /// Computes witnesses for intersection proof.
    pub fn compute_intersection_witnesses(
        set1: &DigestSet<Fr>,
        set2: &DigestSet<Fr>,
        intersection_set: &DigestSet<Fr>,
    ) -> Result<(G2Affine, G2Affine, G1Affine, G1Affine)> {
        let p1_poly = set1.expand_to_poly();
        let p2_poly = set2.expand_to_poly();
        let p_intersect_poly = intersection_set.expand_to_poly();

        // Helper closure for exact division
        let divide_exact = |num: &DensePolynomial<Fr>,
                            den: &DensePolynomial<Fr>,
                            err_msg: &str|
         -> Result<DensePolynomial<Fr>> {
            let (q, r) = DenseOrSparsePolynomial::from(num)
                .divide_with_q_and_r(&DenseOrSparsePolynomial::from(den))
                .ok_or_else(|| anyhow!("Division failed"))?;
            ensure!(r.is_zero(), "{}", err_msg);
            Ok(q)
        };

        let q1_poly = divide_exact(
            &p1_poly,
            &p_intersect_poly,
            "P_intersect does not divide P1",
        )?;
        let q2_poly = divide_exact(
            &p2_poly,
            &p_intersect_poly,
            "P_intersect does not divide P2",
        )?;

        let witness_a = poly_to_g2(q1_poly.clone());
        let witness_b = poly_to_g2(q2_poly.clone());

        let (a_poly, b_poly) = crate::acc::utils::solve_bezout_identity(q1_poly, q2_poly)
            .context("Quotients might not be coprime")?;

        Ok((witness_a, witness_b, poly_to_g1(a_poly), poly_to_g1(b_poly)))
    }

    /// Computes witnesses for disjointness proof.
    pub fn compute_disjointness_witnesses(
        set1: &DigestSet<Fr>,
        set2: &DigestSet<Fr>,
    ) -> Result<(G2Affine, G2Affine)> {
        let poly1 = set1.expand_to_poly();
        let poly2 = set2.expand_to_poly();

        let (x_poly, y_poly) = crate::acc::utils::solve_bezout_identity(poly1, poly2)
            .context("Sets are not disjoint")?;

        Ok((poly_to_g2(x_poly), poly_to_g2(y_poly)))
    }
}
