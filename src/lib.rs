//! A crate for the Sumcheck protocol

pub use error::Error;

#[macro_use]
extern crate ark_std;

/// error for this crate
mod error;

pub mod naive_sumcheck;

use ark_poly::polynomial::multivariate::{SparsePolynomial, SparseTerm};
use ark_poly::polynomial::univariate::SparsePolynomial as UniSparsePolynomial;

pub type MultiPoly<F> = SparsePolynomial<F, SparseTerm>;
pub type UniPoly<F> = UniSparsePolynomial<F>;