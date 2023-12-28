use ark_bls12_381::Fr as Fr;
use ark_std::vec::Vec;
use ark_poly::polynomial::multivariate::{SparsePolynomial, SparseTerm, Term};

use crate::naive_sumcheck::protocol::IPForSumcheck;


pub type MultiPoly<F> = SparsePolynomial<F, SparseTerm>;

// Unit test for the Sumcheck protocol.
// Example taken from Section 4.1 of Justin Thaler's book:
// Proofs, Arguments, and Zero-Knowledge.
#[test]
fn test_protocol() {
    let mut rng = rand::thread_rng();
    let num_vars: usize = 3;

    // CAVEAT: Indexing must start at zero in order to avoid a panic
    // caused from improper indexing withing ark-poly:
    // See:
    // https://docs.rs/ark-poly/latest/src/ark_poly/polynomial/multivariate/mod.rs.html#113
    let terms: Vec<(Fr, SparseTerm)> = vec![
		(2.into(), SparseTerm::new(vec![(0, 3)])),
		(1.into(), SparseTerm::new(vec![(0, 1), (2, 1)])),
		(1.into(), SparseTerm::new(vec![(1, 1), (2, 1)])),
	];

	let g = MultiPoly { num_vars, terms };

    let mut prover_state = IPForSumcheck::<Fr>::prover_init(g.clone());
    let mut verifier_state = IPForSumcheck::<Fr>::verifier_init(g.num_vars);
    let mut verifier_msg = None;

    let asserted_sum = prover_state.slow_sum_g();   // 12.into()

    for _ in 0..g.num_vars {
        let prover_message = IPForSumcheck::<Fr>::prove_round(&mut prover_state, &verifier_msg);

        let verif_msg =
            IPForSumcheck::<Fr>::verify_round(prover_message, &mut verifier_state, &mut rng);
        verifier_msg = verif_msg;
    }
    let result = IPForSumcheck::<Fr>::verify(&g, verifier_state, asserted_sum)
        .expect("Failed to verify...");

	assert_eq!(result, ());
}