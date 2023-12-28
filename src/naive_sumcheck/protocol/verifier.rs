//! Verifier
use ark_ff::Field;
use ark_poly::{DenseMVPolynomial, Polynomial};
use ark_serialize::{CanonicalDeserialize, CanonicalSerialize};
use ark_std::{rand::RngCore, vec::Vec};

use crate::naive_sumcheck::protocol::{IPForSumcheck, prover::ProverMsg};
use crate::{MultiPoly, UniPoly};

/// Verifier Message
#[derive(Clone, CanonicalSerialize, CanonicalDeserialize, Debug)]
pub struct VerifierMsg<F: Field> {
    /// randomness sampled by verifier
    pub randomness: F,
}

/// Verifier State
pub struct VerifierState<F: Field> {
    /// Verifier's round counter
    round: usize,
    /// Number of variables in the prover's claimed polynomial `g`
    num_vars: usize,
    /// If verifier is done
    finished: bool,
    /// a list storing the partial sums (univariate polynomials) sent by the prover at each round
    partial_sums: Vec<UniPoly<F>>,   // Optimization: store polynomial evaluations instead
    /// a vector for keeping track of the random field elements sampled by the verifier at each round
    randomness: Vec<F>,
}

/// Verifier's output when it is (almost) convinced.
///
pub struct VerifierOutput<F: Field> {
    /// the random points sampled during execution
    pub r_vec: Vec<F>,
    /// the expected evaluation
    pub expected_evaluation: F,
}

// A degree lookup table for all variables in `g`.
pub fn max_degrees<F: Field>(g: &MultiPoly<F>) -> Vec<usize> {
	let mut degrees: Vec<usize> = vec![0; g.num_vars()];

	cfg_into_iter!(g.terms()).for_each(|(_, term)| {
		cfg_into_iter!(term).for_each(|(var, power)| {
			if *power > degrees[*var] {
				degrees[*var] = *power
			}
		});
	});

	degrees
}

impl<F: Field> IPForSumcheck<F> {
    /// Initializes the verifier
    ///
    pub fn verifier_init(num_variables: usize) -> VerifierState<F> {
        VerifierState {
            round: 1,
            num_vars: num_variables,
            finished: false,
            partial_sums: Vec::with_capacity(num_variables),
            randomness: Vec::with_capacity(num_variables),
        }
    }

    /// Run verifier at current round, given a prover message.
    ///
    /// `verify_round` only samples and stores randomness. Intermediate verifications
    /// are postponed until `partial_verify` is invoked at the last step.
    /// The partial sums received from the prover are also stored for future use.
    pub fn verify_round<R: RngCore>(
        prover_msg: ProverMsg<F>,
        verifier_state: &mut VerifierState<F>,
        rng: &mut R,
    ) -> Option<VerifierMsg<F>> {
        if verifier_state.finished {
            panic!("Incorrect verifier state: Verifier is already finished...");
        }

        // Sample and store randomness for the current round
        let v_msg = Self::sample_r(rng);
        verifier_state.randomness.push(v_msg.randomness);

        verifier_state
            .partial_sums
            .push(prover_msg.gi);

        if verifier_state.round == verifier_state.num_vars {
            // accept and finish up
            verifier_state.finished = true;
        } else {
            verifier_state.round += 1;
        }

        Some(v_msg)
    }

    /// `partial_verify` only performs the intermediate checks of the the sumcheck protocol.
    /// Its output enables the verifier to reach a decision after querying the prover's
    /// polynomial `g`.
    ///
    /// If `asserted_sum` is correct, then polynomial `g` evaluated at the point `r_vec`
    /// should match `expected_evaluation`.
    /// Otherwise, w.h.p. those two will not be equal by the Schwartz-Zippel lemma.
    pub fn partial_verify(
        verifier_state: VerifierState<F>,
        asserted_sum: F,
    ) -> Result<VerifierOutput<F>, crate::Error> {
        if !verifier_state.finished {
            panic!("Verifier has not finished yet...");
        }

        let mut expected_sum = asserted_sum;
        if verifier_state.partial_sums.len() != verifier_state.num_vars {
            panic!("Insufficient number of rounds...");
        } else if verifier_state.randomness.len() != verifier_state.num_vars {
            panic!("Insufficient random field elements...");
        }

        for i in 0..verifier_state.num_vars {
            let gi = &verifier_state.partial_sums[i];
            
            let p0 = gi.evaluate(&0_u32.into());
            let p1 = gi.evaluate(&1_u32.into());

            if p0 + p1 != expected_sum {
                return Err(crate::Error::Reject(Some(
                    "Prover message is inconsistent with the claim.".into(),
                )));
            }

            // Update expected_sum for the next iteration
            expected_sum = gi.evaluate(&verifier_state.randomness[i]);
        }

        Ok(VerifierOutput {
            r_vec: verifier_state.randomness,
            expected_evaluation: expected_sum,
        })
    }

    /// Full verification.
    ///
    pub fn verify(
        g: &MultiPoly<F>,
        verifier_state: VerifierState<F>,
        asserted_sum: F,
    ) -> Result<(), crate::Error> {
        let degrees = max_degrees(&g);

        assert!((0..verifier_state.num_vars)
            .all(|i| verifier_state.partial_sums[i].degree() <= degrees[i]));

        if let Ok(v_out) = Self::partial_verify(verifier_state, asserted_sum) {
            if g.evaluate(&v_out.r_vec) == v_out.expected_evaluation {
                Ok(())
            } else {
                Err(crate::Error::Reject(Some(
                    "Verification failed.".into(),
                )))
            }
        } else {
            Err(crate::Error::Reject(Some(
                "Partial verification failed.".into(),
            )))
        }
    }

    /// Verifier sampling function.
    ///
    #[inline]
    pub fn sample_r<R: RngCore>(rng: &mut R) -> VerifierMsg<F> {
        VerifierMsg {
            randomness: F::rand(rng),
        }
    }
}