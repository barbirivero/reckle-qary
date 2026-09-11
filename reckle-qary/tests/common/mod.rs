//! Shared helpers for the integration tests.
//!
//! Each integration test file is its own crate, so helpers used by only some of
//! them look dead to the others.
#![allow(dead_code)]

use std::panic::{catch_unwind, AssertUnwindSafe};

use anyhow::Result;
use plonky2::field::types::Field;
use reckle_qary::circuit::{BatchProof, LevelCircuits};
use reckle_qary::tree::F;

/// Deterministic leaf values.
pub fn leaves(n: usize) -> Vec<F> {
    (0..n).map(|i| F::from_canonical_u64((i as u64 + 1) * 31 + 7)).collect()
}

/// Outcome of asking the prover to prove something it should not be able to.
///
/// A dishonest witness can fail in three places: witness generation can panic, the
/// prover can return an error, or -- if a constraint is only caught later -- the
/// resulting proof can fail verification. All three count as "rejected"; what must
/// never happen is a proof that verifies.
pub fn is_rejected(lc: &LevelCircuits, attempt: impl FnOnce() -> Result<BatchProof>) -> bool {
    match catch_unwind(AssertUnwindSafe(attempt)) {
        Err(_) => true,          // panicked during witness generation
        Ok(Err(_)) => true,      // prover refused
        Ok(Ok(bp)) => {
            // A proof came out; it must at least fail to verify.
            lc.circuits[bp.k - 1].verify(bp.proof).is_err()
        }
    }
}
