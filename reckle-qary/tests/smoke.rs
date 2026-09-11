//! Fastest possible end-to-end check, used to fail early on setup problems.

use std::collections::BTreeSet;

use plonky2::field::types::Field;
use reckle_qary::circuit::ReckleQary;
use reckle_qary::tree::{QaryTree, F};

fn leaves(n: usize) -> Vec<F> {
    (0..n).map(|i| F::from_canonical_u64((i as u64 + 1) * 31)).collect()
}

#[test]
fn setup_yields_uniform_common_data() {
    // q = 2, height = 2 is the smallest instance that still exercises recursion.
    let s = ReckleQary::setup(2, 2).expect("setup must produce uniform CommonCircuitData");
    for level in 1..=2 {
        let d1 = s.circuit_degree(level, 1);
        let d2 = s.circuit_degree(level, 2);
        assert_eq!(d1, d2, "level {level}: degrees differ");
    }
}

#[test]
fn prove_and_verify_smallest_instance() {
    let q = 2;
    let height = 2;
    let s = ReckleQary::setup(q, height).unwrap();
    let tree = QaryTree::new(q, height, leaves(4));
    let batch = BTreeSet::from([1, 2]);

    let bp = s.prove_batch(&tree, &batch).unwrap();
    s.verify_batch(tree.root(), &tree.claims(&batch), &bp).unwrap();
}
