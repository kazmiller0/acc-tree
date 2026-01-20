use crate::acc::utils::digest_to_prime_field;
use crate::set::{Set, SetElement};
use ark_ff::PrimeField;
use ark_poly::{univariate::DensePolynomial, UVPolynomial};
use rayon::{self, prelude::*};
use std::borrow::Cow;
#[allow(unused_imports)]
use std::ops::Neg;

/// Convert a Set<T> to Vec<F> by hashing each element to prime field.
/// Uses parallel iteration for performance.
pub fn digest_set_from_set<T: SetElement, F: PrimeField>(input: &Set<T>) -> Vec<F> {
    let elements: Vec<&T> = input.iter().collect();
    let mut result: Vec<F> = Vec::with_capacity(elements.len());

    (0..elements.len())
        .into_par_iter()
        .map(|i| {
            let k = elements[i];
            let d = k.to_digest();
            digest_to_prime_field(&d)
        })
        .collect_into_vec(&mut result);

    result
}

/// Expand a slice of field elements to polynomial ∏(X - xᵢ).
/// Uses parallel divide-and-conquer for performance.
pub fn expand_to_poly<F: PrimeField>(elements: &[F]) -> DensePolynomial<F> {
    let mut inputs = Vec::new();
    for k in elements {
        inputs.push(DensePolynomial::from_coefficients_vec(vec![
            k.neg(),
            F::one(),
        ]));
    }

    fn expand<'a, F: PrimeField>(polys: &'a [DensePolynomial<F>]) -> Cow<'a, DensePolynomial<F>> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use ark_bls12_381::Fr;

    #[test]
    fn test_expand_to_poly() {
        let elements = vec![Fr::from(1u32), Fr::from(2u32), Fr::from(3u32)];
        let poly = expand_to_poly(&elements);

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
