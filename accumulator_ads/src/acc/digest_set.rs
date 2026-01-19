use crate::acc::utils::digest_to_prime_field;
use crate::set::{Set, SetElement};
use ark_ff::PrimeField;
use ark_poly::{univariate::DensePolynomial, UVPolynomial};
use core::ops::Deref;
use rayon::{self, prelude::*};
use std::borrow::Cow;
#[allow(unused_imports)]
use std::ops::Neg;

#[derive(Debug, Clone, Default)]
pub struct DigestSet<F: PrimeField> {
    pub(crate) inner: Vec<F>,
}

impl<F: PrimeField> DigestSet<F> {
    pub fn new<T: SetElement>(input: &Set<T>) -> Self {
        let mut inner: Vec<F> = Vec::with_capacity(input.len());
        // Collect for parallel iteration
        let elements: Vec<&T> = input.iter().collect();
        (0..elements.len())
            .into_par_iter()
            .map(|i| {
                let k = elements[i];
                let d = k.to_digest();
                digest_to_prime_field(&d)
            })
            .collect_into_vec(&mut inner);
        Self { inner }
    }

    pub fn expand_to_poly(&self) -> DensePolynomial<F> {
        let mut inputs = Vec::new();
        for k in &self.inner {
            inputs.push(DensePolynomial::from_coefficients_vec(vec![
                k.neg(),
                F::one(),
            ]));
        }

        fn expand<'a, F: PrimeField>(
            polys: &'a [DensePolynomial<F>],
        ) -> Cow<'a, DensePolynomial<F>> {
            if polys.is_empty() {
                return Cow::Owned(DensePolynomial::from_coefficients_vec(vec![F::one()]));
            } else if polys.len() == 1 {
                return Cow::Borrowed(&polys[0]);
            }
            let mid = polys.len() / 2;
            let (left, right) = rayon::join(|| expand(&polys[..mid]), || expand(&polys[mid..]));
            Cow::Owned(left.as_ref() * right.as_ref())
        }

        expand(&inputs).into_owned()
    }
}

impl<F: PrimeField> Deref for DigestSet<F> {
    type Target = Vec<F>;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fr;

    #[test]
    fn test_digest_to_poly() {
        let set = DigestSet {
            inner: vec![Fr::from(1u32), Fr::from(2u32), Fr::from(3u32)],
        };
        let _expect = DensePolynomial::from_coefficients_vec(vec![
            Fr::from(6u32).neg(),
            Fr::from(1u32),
            Fr::from(1u32).neg(),
            Fr::from(1u32).neg(),
            Fr::from(1u32),
        ]);
        let poly = set.expand_to_poly();
        // (X-1) * (X-2) * (X-3)
        // (X^2-3X+2) * (X-3)
        // X^3 - 3X^2 - 3X^2 + 9X + 2X - 6
        // X^3 - 6X^2 + 11X - 6
        let expected_poly = DensePolynomial::from_coefficients_vec(vec![
            Fr::from(6u32).neg(),
            Fr::from(11u32),
            Fr::from(6u32).neg(),
            Fr::from(1u32),
        ]);
        assert_eq!(poly, expected_poly);
    }
}
