//! Updatability: refreshing a batch proof after a leaf change must give a proof
//! indistinguishable from a fresh one, while touching only the affected path.

mod common;

use std::collections::BTreeSet;

use common::leaves;
use plonky2::field::types::Field;
use reckle_qary::circuit::ReckleQary;
use reckle_qary::tree::{QaryTree, F};

#[test]
fn update_of_a_batched_leaf_matches_a_fresh_proof() {
    let (q, height) = (2, 3);
    let s = ReckleQary::setup(q, height).unwrap();
    let mut tree = QaryTree::new(q, height, leaves(8));
    let batch = BTreeSet::from([1, 4, 6]);

    let mut state = s.aggregate(&tree, &batch).unwrap();
    s.verify_batch(tree.root(), &tree.claims(&batch), state.root_proof()).unwrap();

    s.update_leaf(&mut tree, &mut state, 4, F::from_canonical_u64(777)).unwrap();

    // The updated proof verifies against the new root and the new claims ...
    s.verify_batch(tree.root(), &tree.claims(&batch), state.root_proof()).unwrap();
    // ... and only the path from leaf 4 to the root was recomputed.
    assert_eq!(state.last_stats.len(), height);
    // ... and it is a proof of the same statement a fresh aggregation gives.
    let fresh = s.aggregate(&tree, &batch).unwrap();
    assert_eq!(
        state.root_proof().proof.public_inputs,
        fresh.root_proof().proof.public_inputs
    );
}

#[test]
fn update_of_a_leaf_outside_the_batch_still_refreshes_the_proof() {
    // Case 2 of Section 3.4: the canonical digest is unchanged but the Merkle root
    // moved, so the proof must be refreshed even though the batch is untouched.
    let (q, height) = (2, 3);
    let s = ReckleQary::setup(q, height).unwrap();
    let mut tree = QaryTree::new(q, height, leaves(8));
    let batch = BTreeSet::from([1, 6]);

    let mut state = s.aggregate(&tree, &batch).unwrap();
    let digest_before = state.ct.root();
    let stale = state.root_proof().clone();

    s.update_leaf(&mut tree, &mut state, 5, F::from_canonical_u64(31337)).unwrap();

    assert_eq!(state.ct.root(), digest_before, "canonical digest must not change");
    s.verify_batch(tree.root(), &tree.claims(&batch), state.root_proof()).unwrap();
    assert!(
        s.verify_batch(tree.root(), &tree.claims(&batch), &stale).is_err(),
        "the pre-update proof must not verify against the new root"
    );
}

#[test]
fn updates_touch_at_most_one_node_per_level() {
    // The cost bound that makes Reckle trees updatable: O(height) proofs, and in
    // particular independent of |I|.
    let (q, height) = (2, 3);
    let s = ReckleQary::setup(q, height).unwrap();
    let mut tree = QaryTree::new(q, height, leaves(8));

    for batch in [BTreeSet::from([0]), (0..8).collect::<BTreeSet<usize>>()] {
        let mut state = s.aggregate(&tree, &batch).unwrap();
        s.update_leaf(&mut tree, &mut state, 0, F::from_canonical_u64(5)).unwrap();
        assert!(
            state.last_stats.len() <= height,
            "batch of {} recomputed {} proofs, expected at most {height}",
            batch.len(),
            state.last_stats.len()
        );
        s.verify_batch(tree.root(), &tree.claims(&batch), state.root_proof()).unwrap();
    }
}

#[test]
fn repeated_updates_stay_consistent() {
    let (q, height) = (2, 2);
    let s = ReckleQary::setup(q, height).unwrap();
    let mut tree = QaryTree::new(q, height, leaves(4));
    let batch = BTreeSet::from([0, 3]);
    let mut state = s.aggregate(&tree, &batch).unwrap();

    for (i, leaf) in [0usize, 1, 3, 2].iter().enumerate() {
        s.update_leaf(&mut tree, &mut state, *leaf, F::from_canonical_u64(1000 + i as u64))
            .unwrap();
        s.verify_batch(tree.root(), &tree.claims(&batch), state.root_proof())
            .unwrap_or_else(|e| panic!("after updating leaf {leaf}: {e}"));
    }
}
