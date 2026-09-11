//! Completeness: an honest prover always produces a proof the verifier accepts.

mod common;

use std::collections::BTreeSet;

use common::leaves;
use plonky2::field::types::Field;
use reckle_qary::circuit::ReckleQary;
use reckle_qary::tree::{QaryTree, F};

#[test]
fn binary_tree_matches_the_original_construction() {
    // q = 2 is the paper's own setting, so this is the sanity check that the
    // generalisation did not change the base case.
    let (q, height) = (2, 3);
    let s = ReckleQary::setup(q, height).unwrap();
    let tree = QaryTree::new(q, height, leaves(8));

    for batch in [
        BTreeSet::from([0]),
        BTreeSet::from([7]),
        BTreeSet::from([2, 4, 5]),
        BTreeSet::from([0, 1, 2, 3, 4, 5, 6, 7]),
    ] {
        let bp = s.prove_batch(&tree, &batch).unwrap();
        s.verify_batch(tree.root(), &tree.claims(&batch), &bp)
            .unwrap_or_else(|e| panic!("batch {batch:?} rejected: {e}"));
    }
}

#[test]
fn arity_four_covers_every_k() {
    // With q = 4 and these batches, nodes with 1, 2, 3 and 4 active children all
    // occur, so every circuit Q_1..Q_4 is exercised.
    let (q, height) = (4, 2);
    let s = ReckleQary::setup(q, height).unwrap();
    let tree = QaryTree::new(q, height, leaves(16));

    for batch in [
        BTreeSet::from([5]),                     // single path, k = 1 everywhere
        BTreeSet::from([0, 1, 2, 3]),            // one node with k = 4, root k = 1
        BTreeSet::from([0, 4, 8, 12]),           // root k = 4, each child k = 1
        BTreeSet::from([1, 2, 6, 9, 10, 11, 15]), // mixed k
    ] {
        let bp = s.prove_batch(&tree, &batch).unwrap();
        s.verify_batch(tree.root(), &tree.claims(&batch), &bp)
            .unwrap_or_else(|e| panic!("batch {batch:?} rejected: {e}"));
    }
}

#[test]
fn full_batch_is_the_digest_translation_setting() {
    // Section 4.1 uses the whole leaf set as the batch.
    let (q, height) = (3, 2);
    let s = ReckleQary::setup(q, height).unwrap();
    let tree = QaryTree::new(q, height, leaves(9));
    let batch: BTreeSet<usize> = (0..9).collect();

    let bp = s.prove_batch(&tree, &batch).unwrap();
    s.verify_batch(tree.root(), &tree.claims(&batch), &bp).unwrap();
}

#[test]
fn proof_survives_a_leaf_update_outside_the_batch() {
    // Changing a leaf outside the batch changes the Merkle root but not the
    // canonical digest, so a freshly computed proof must still verify against the
    // new root with the same claims.
    let (q, height) = (2, 3);
    let s = ReckleQary::setup(q, height).unwrap();
    let mut tree = QaryTree::new(q, height, leaves(8));
    let batch = BTreeSet::from([1, 6]);

    let bp = s.prove_batch(&tree, &batch).unwrap();
    s.verify_batch(tree.root(), &tree.claims(&batch), &bp).unwrap();

    tree.update_leaf(4, F::from_canonical_u64(4242));
    let bp2 = s.prove_batch(&tree, &batch).unwrap();
    s.verify_batch(tree.root(), &tree.claims(&batch), &bp2).unwrap();

    // ... and the old proof must not verify against the new root.
    assert!(s.verify_batch(tree.root(), &tree.claims(&batch), &bp).is_err());
}

#[test]
fn proof_size_is_independent_of_batch_size() {
    // The headline succinctness property: |pi_I| does not grow with |I|.
    let (q, height) = (2, 3);
    let s = ReckleQary::setup(q, height).unwrap();
    let tree = QaryTree::new(q, height, leaves(8));

    let small = s.prove_batch(&tree, &BTreeSet::from([3])).unwrap();
    let large = s.prove_batch(&tree, &(0..8).collect()).unwrap();
    assert_eq!(small.size_bytes(), large.size_bytes());
}
