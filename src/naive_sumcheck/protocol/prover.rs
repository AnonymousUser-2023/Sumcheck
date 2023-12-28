//! Prover
use ark_ff::Field;
use ark_poly::polynomial::multivariate::{SparseTerm, Term};
use ark_poly::polynomial::{DenseMVPolynomial, Polynomial};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{cfg_into_iter, vec::Vec};

use crate::naive_sumcheck::protocol::{IPForSumcheck, verifier::VerifierMsg};
use crate::{MultiPoly, UniPoly};

#[cfg(feature = "parallel")]
use rayon::prelude::*;


/// Utility functions

/// Converts index `i` into its binary representation, potentially padding
/// some leading zeroes until the bitstring contains `nu` bits in total.
/// Returns a vector containing these bits as field elements.
pub fn to_binary_vec<F: Field + std::convert::From<i32>>(i: usize, nu: usize) -> Vec<F> {
	format!("{:0>width$}", format!("{:b}", i), width = nu)
		.chars()
		.map(|x| if x == '0' { 0.into() } else { 1.into() })
		.collect::<_>()
}

/// Prover Message
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize, Debug)]
pub struct ProverMsg<F: Field> {
    /// univariate polynomial representing a partial sum that gets sent to the verifier
    pub gi: UniPoly<F>,
}

/// Prover State
pub struct ProverState<F: Field + std::convert::From<i32>> {
    /// Polynomial for which we want to prove a relation
    pub g: MultiPoly<F>,
    /// randomness provided by the verifier
    pub randomness: Vec<F>,
    /// The current round number
    pub round: usize,
}

impl<F: Field + std::convert::From<i32>> ProverState<F> {
    /// Given polynomial g, fix X_i, evaluate over x_{i+1}, ...
	pub fn gen_uni_polynomial(&mut self, r: Option<F>) -> UniPoly<F> {
		if r.is_some() {
			self.randomness.push(r.unwrap());
		}

        // remaining number of "non-fixed" variables
		let v = self.g.num_vars() - self.randomness.len();

        // For each possible combination in 0..2^{v - 1}
		(0..(1 << (v as u32 - 1))).fold(   // Note: -1 because 1 variable will get fixed here
			UniPoly::<F>::from_coefficients_vec(vec![(0, 0_u32.into())]),
			|sum, i| sum + self.evaluate_gi(to_binary_vec::<F>(i as usize, v)),
		)
	}

    /// Evaluates gi over a vector permutation of points, folding all evaluated terms together
    /// into one univariate polynomial.
	pub fn evaluate_gi(&self, points: Vec<F>) -> UniPoly<F> {
		let result = cfg_into_iter!(self.g.terms()).fold(
			UniPoly::<F>::from_coefficients_vec(vec![]),   // empty
			|sum, (coeff, term)| {
				let (coeff_eval, fixed_term) = self.evaluate_term(&term, &points);
				let current = match fixed_term {
					None => UniPoly::<F>::from_coefficients_vec(vec![(0, *coeff * coeff_eval)]),
					_ => UniPoly::<F>::from_coefficients_vec(vec![(
						fixed_term.unwrap().degree(),
						*coeff * coeff_eval,
					)]),
				};
                current + sum
			},
		);

        result
	}

	/// Evaluates a term with a fixed univar, returning (new coefficent, fixed term).
	pub fn evaluate_term(
		&self,
		term: &SparseTerm,
		points: &Vec<F>,
	) -> (F, Option<SparseTerm>) {
		let mut fixed_term: Option<SparseTerm> = None;
		let coeff: F =
			cfg_into_iter!(term).fold(1_u32.into(), |product, (var, power)| match *var {
                j if j == self.randomness.len() => {
					fixed_term = Some(SparseTerm::new(vec![(j, *power)]));   // fix term
					product   // retain product
				}
				j if j < self.randomness.len() => self.randomness[j].pow(&[*power as u64]) * product,
				_ => points[*var - self.randomness.len()].pow(&[*power as u64]) * product,   // i.e., j > self.randomness.len()
			});

		(coeff, fixed_term)
	}

    // Sum all evaluations of polynomial `g` over boolean hypercube.
	pub fn slow_sum_g(&self) -> F {
		let v = self.g.num_vars();
		let n = 2_u32.pow(v as u32);
        
		(0..n)
			.map(|i| self.g.evaluate(&to_binary_vec(i as usize, v)))
			.sum()
	}
}

impl<F: Field + std::convert::From<i32>> IPForSumcheck<F> {
    /// Initialize prover to argue for the sum of polynomial `g` over the boolean hypercube of dimension `num_vars`.
    ///
    pub fn prover_init(polynomial: MultiPoly<F>) -> ProverState<F> {
        if polynomial.num_vars == 0 {
            panic!("Proving sumcheck for a constant polynomial is trivial...")
        }

        ProverState {
            g: polynomial.clone(),
            randomness: Vec::with_capacity(polynomial.num_vars),
            round: 0,
        }
    }

    /// Receive message from verifier, generate prover message, and proceed to next round.
    ///
    pub fn prove_round(
        prover_state: &mut ProverState<F>,
        v_msg: &Option<VerifierMsg<F>>,
    ) -> ProverMsg<F> {
        if prover_state.round > prover_state.g.num_vars {
            panic!("Prover is no longer active...");
        }

        let mut r = None;

        if let Some(msg) = v_msg {
            if prover_state.round == 0 {
                panic!("Prover should go first...");
            }

            // Extract randomness from the received verifier message
            r = Some(msg.randomness);
        } else {   // v_msg == None
            if prover_state.round > 0 {
                panic!("Verifier message should not be empty...");
            }
        }

        // Compute partial sum
        let gi = prover_state.gen_uni_polynomial(r);

        // Increment round
        prover_state.round += 1;

        ProverMsg { gi }
    }
}