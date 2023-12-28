//! Interactive Proof system for the Sumcheck protocol

use ark_ff::Field;
use ark_std::marker::PhantomData;

pub mod prover;
pub mod verifier;

/// Interactive Proof system for the Sumcheck protocol
pub struct IPForSumcheck<F: Field> {
    _marker: PhantomData<F>,   // cache field F
}