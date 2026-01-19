//! Implements a dynamic cryptographic accumulator that supports additions, deletions,
//! intersection, union, and disjointness proofs.

use anyhow::{anyhow, ensure, Context, Result};
use ark_bls12_381::{Fr, G1Affine, G1Projective, G2Affine};
use ark_ec::{AffineCurve, ProjectiveCurve};
use ark_ff::{Field, One, PrimeField, Zero};
use ark_poly::{
    univariate::{DenseOrSparsePolynomial, DensePolynomial},
    Polynomial, UVPolynomial,
};
use std::ops::Neg;

use super::proofs::{MembershipProof, NonMembershipProof};
use crate::acc::digest_set::DigestSet;
use crate::acc::utils::{poly_to_g1, poly_to_g2, xgcd};

/// Represents the result of a query against the accumulator.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum QueryResult {
    /// The element is in the set, and here is the proof.
    Membership(MembershipProof),
    /// The element is not in the set, and here is the proof.
    NonMembership(Box<NonMembershipProof>),
}

/// A dynamic cryptographic accumulator based on the Acc scheme.
/// It maintains the accumulator value.
/// Set operations and element storage are handled externally.
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
    /// The initial value is g1^1, representing an empty set.
    pub fn new() -> Self {
        Self {
            acc_value: G1Projective::from(G1Affine::prime_subgroup_generator())
                .mul(Fr::one().into_repr())
                .into_affine(),
        }
    }

    /// Static method: Fast calculation of set commitment using MSM.
    pub fn calculate_commitment(set: &DigestSet<Fr>) -> G1Affine {
        let poly = set.expand_to_poly();
        poly_to_g1(poly)
    }

    /// Factory method: Initialize accumulator from a DigestSet.
    pub fn from_set(set: &DigestSet<Fr>) -> Self {
        let acc_point = Self::calculate_commitment(set);
        Self {
            acc_value: acc_point,
        }
    }

    /// Helper: Compute G2 commitment
    pub fn calculate_commitment_g2(set: &DigestSet<Fr>) -> G2Affine {
        let poly = set.expand_to_poly();
        poly_to_g2(poly)
    }

    // ==========================================
    // 1. Add & Delete & Update
    // ==========================================
    // WARNING: These operations require the secret trapdoor s.
    // In production, only a trusted accumulator manager should have access.
    // These are available in test mode for testing purposes.

    /// Computes the new accumulator value after adding an element.
    /// acc' = acc^(s-element)
    /// 
    /// SECURITY WARNING: This requires the secret trapdoor and should only
    /// be used in testing or by a trusted accumulator manager.
    /// Computes the new accumulator value after adding an element.
    /// acc' = acc^(s-element)
    /// 
    /// SECURITY WARNING: This requires the secret trapdoor and should only
    /// be used in testing or by a trusted accumulator manager.
    #[cfg(any(test, debug_assertions))]
    pub fn compute_add(&self, element: Fr) -> G1Affine {
        use super::setup::PRI_S;
        let s_minus_elem: Fr = *PRI_S - element;
        self.acc_value
            .into_projective()
            .mul(s_minus_elem.into_repr())
            .into_affine()
    }
    
    #[cfg(not(any(test, debug_assertions)))]
    pub fn compute_add(&self, _element: Fr) -> G1Affine {
        panic!("compute_add requires secret trapdoor and is not available in production builds. Use a trusted accumulator manager.");
    }

    /// Computes the new accumulator value after deleting an element.
    /// acc' = acc^(1/(s-element))
    /// 
    /// SECURITY WARNING: This requires the secret trapdoor and should only
    /// be used in testing or by a trusted accumulator manager.
    #[cfg(any(test, debug_assertions))]
    pub fn compute_delete(&self, element: Fr) -> Result<G1Affine> {
        use super::setup::PRI_S;
        let s_minus_elem: Fr = *PRI_S - element;
        let inverse = s_minus_elem
            .inverse()
            .ok_or_else(|| anyhow!("Failed to compute inverse: element might be equal to s"))?;

        Ok(self
            .acc_value
            .into_projective()
            .mul(inverse.into_repr())
            .into_affine())
    }
    
    #[cfg(not(any(test, debug_assertions)))]
    pub fn compute_delete(&self, _element: Fr) -> Result<G1Affine> {
        Err(anyhow!("compute_delete requires secret trapdoor and is not available in production builds. Use a trusted accumulator manager."))
    }

    /// Computes the new accumulator value after updating an element.
    /// This is equivalent to deleting old_element and adding new_element.
    /// acc' = acc^((s-new_element)/(s-old_element))
    /// 
    /// SECURITY WARNING: This requires the secret trapdoor and should only
    /// be used in testing or by a trusted accumulator manager.
    #[cfg(any(test, debug_assertions))]
    pub fn compute_update(&self, old_element: Fr, new_element: Fr) -> Result<G1Affine> {
        use super::setup::PRI_S;
        // First compute the delete operation
        let temp_acc_value = self.compute_delete(old_element)?;

        // Then apply the add operation
        let s_minus_new: Fr = *PRI_S - new_element;
        Ok(G1Projective::from(temp_acc_value)
            .mul(s_minus_new.into_repr())
            .into_affine())
    }
    
    #[cfg(not(any(test, debug_assertions)))]
    pub fn compute_update(&self, _old_element: Fr, _new_element: Fr) -> Result<G1Affine> {
        Err(anyhow!("compute_update requires secret trapdoor and is not available in production builds. Use a trusted accumulator manager."))
    }

    // ==========================================
    // 2. Query
    // ==========================================

    /// Computes witnesses for membership (which is the acc value without the element).
    /// Alias for compute_delete.
    pub fn compute_membership_witness(&self, element: Fr) -> Result<G1Affine> {
        self.compute_delete(element)
    }

    /// Computes witnesses for non-membership.
    /// Returns (witness=g2^B(s), g2_a=g2^A(s))
    /// Requires A(x)P(x) + B(x)(x-element) = 1
    pub fn compute_non_membership_witness(
        element: Fr,
        set: &DigestSet<Fr>,
    ) -> Result<(G2Affine, G2Affine)> {
        // 1. Construct P(X) for current set
        // Optimization: Use divide and conquer for polynomial construction
        let mut p_poly = DensePolynomial::from_coefficients_vec(vec![Fr::one()]);
        for elem in set.iter() {
            let e_poly = DensePolynomial::from_coefficients_vec(vec![elem.neg(), Fr::one()]);
            p_poly = &p_poly * &e_poly;
        }

        // 2. We want to show GCD(P(X), X-element) = 1.
        let elem_poly = DensePolynomial::from_coefficients_vec(vec![element.neg(), Fr::one()]);

        let (g, a_poly, b_poly) = xgcd(p_poly, elem_poly).ok_or_else(|| anyhow!("XGCD failed"))?;

        if g.degree() != 0 {
            return Err(anyhow!("GCD is not constant, element might be in set"));
        }

        // Normalize so GCD is 1
        let g_val = g.coeffs[0];
        let g_inv = g_val
            .inverse()
            .ok_or_else(|| anyhow!("GCD inverse failed"))?;

        let a_norm = DensePolynomial::from_coefficients_vec(
            a_poly.coeffs.iter().map(|c| *c * g_inv).collect(),
        );
        let b_norm = DensePolynomial::from_coefficients_vec(
            b_poly.coeffs.iter().map(|c| *c * g_inv).collect(),
        );

        Ok((poly_to_g2(b_norm), poly_to_g2(a_norm)))
    }

    // ==========================================
    // 3. Set Operations Witnesses
    // ==========================================

    /// Computes witnesses for intersection proof.
    /// Returns (witness_a, witness_b, witness_coprime_a, witness_coprime_b)
    pub fn compute_intersection_witnesses(
        set1: &DigestSet<Fr>,
        set2: &DigestSet<Fr>,
        intersection_set: &DigestSet<Fr>,
    ) -> Result<(G2Affine, G2Affine, G1Affine, G1Affine)> {
        // Construct polynomials
        let mut p1_poly = DensePolynomial::from_coefficients_vec(vec![Fr::one()]);
        for elem in set1.iter() {
            let e_poly = DensePolynomial::from_coefficients_vec(vec![elem.neg(), Fr::one()]);
            p1_poly = &p1_poly * &e_poly;
        }

        let mut p2_poly = DensePolynomial::from_coefficients_vec(vec![Fr::one()]);
        for elem in set2.iter() {
            let e_poly = DensePolynomial::from_coefficients_vec(vec![elem.neg(), Fr::one()]);
            p2_poly = &p2_poly * &e_poly;
        }

        let mut p_intersect_poly = DensePolynomial::from_coefficients_vec(vec![Fr::one()]);
        for elem in intersection_set.iter() {
            let e_poly = DensePolynomial::from_coefficients_vec(vec![elem.neg(), Fr::one()]);
            p_intersect_poly = &p_intersect_poly * &e_poly;
        }

        // Quotients
        let (q1_poly, remainder1) = DenseOrSparsePolynomial::from(&p1_poly)
            .divide_with_q_and_r(&DenseOrSparsePolynomial::from(&p_intersect_poly))
            .ok_or(anyhow!("Failed p1 division"))?;
        if !remainder1.is_zero() {
            return Err(anyhow!("P_intersect does not divide P1"));
        }

        let (q2_poly, remainder2) = DenseOrSparsePolynomial::from(&p2_poly)
            .divide_with_q_and_r(&DenseOrSparsePolynomial::from(&p_intersect_poly))
            .ok_or(anyhow!("Failed p2 division"))?;
        if !remainder2.is_zero() {
            return Err(anyhow!("P_intersect does not divide P2"));
        }

        // Use poly_to_g2 to convert quotient polynomials to G2 points
        // Clone the polynomials before converting since we need them for XGCD
        let witness_a = poly_to_g2(q1_poly.clone());
        let witness_b = poly_to_g2(q2_poly.clone());

        // XGCD for coprime
        if let Some((gcd, a_poly, b_poly)) = xgcd(q1_poly, q2_poly) {
            if !gcd.is_zero() && gcd.degree() == 0 {
                let gcd_val = gcd.coeffs[0];
                let gcd_inv = gcd_val.inverse().ok_or(anyhow!("GCD inverse failed"))?;

                let a_norm = DensePolynomial::from_coefficients_vec(
                    a_poly.coeffs.iter().map(|c| *c * gcd_inv).collect(),
                );
                let b_norm = DensePolynomial::from_coefficients_vec(
                    b_poly.coeffs.iter().map(|c| *c * gcd_inv).collect(),
                );

                let witness_coprime_a = poly_to_g1(a_norm);
                let witness_coprime_b = poly_to_g1(b_norm);

                return Ok((witness_a, witness_b, witness_coprime_a, witness_coprime_b));
            }
        }

        Err(anyhow!(
            "Quotients might not be coprime (Sets Q1, Q2 not coprime)"
        ))
    }

    /// Computes witnesses for disjointness proof.
    /// Returns (f1, f2)
    pub fn compute_disjointness_witnesses(
        set1: &DigestSet<Fr>,
        set2: &DigestSet<Fr>,
    ) -> Result<(G2Affine, G2Affine)> {
        let poly1 = set1.expand_to_poly();
        let poly2 = set2.expand_to_poly();
        let (g, x, y) = xgcd(poly1, poly2).context("failed to compute xgcd")?;
        ensure!(
            g.degree() == 0,
            "cannot generate proof (sets are not disjoint)"
        );
        let g_inv = g.coeffs[0].inverse().ok_or(anyhow!("GCD inverse failed"))?;

        let x_norm =
            DensePolynomial::from_coefficients_vec(x.coeffs.iter().map(|c| *c * g_inv).collect());
        let y_norm =
            DensePolynomial::from_coefficients_vec(y.coeffs.iter().map(|c| *c * g_inv).collect());

        let witness1 = poly_to_g2(x_norm);
        let witness2 = poly_to_g2(y_norm);

        Ok((witness1, witness2))
    }
}
