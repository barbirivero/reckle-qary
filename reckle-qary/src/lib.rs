//! `q`-ary Reckle trees: an implementation of circuit `Q_k` (Figure 5) from
//! "Reckle Trees: Updatable Merkle Batch Proofs with Applications" (CCS 2024),
//! which the authors left as future work.
//!
//! * [`tree`] — the out-of-circuit specification: `q`-ary Merkle hashing and
//!   canonical hashing. This is the ground truth the circuits are checked against.
//! * [`circuit`] — the `Q_k` circuit family and the recursive prover/verifier.

pub mod circuit;
pub mod tree;
