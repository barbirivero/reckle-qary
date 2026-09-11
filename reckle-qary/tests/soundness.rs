//! Soundness: invalid witnesses and tampered statements must never yield an
//! accepted proof.
//!
//! The tests come in two families:
//!
//! * *Verifier-level* — take an honest proof and lie to the verifier about what it
//!   proves. These check the binding between the proof's public inputs and the
//!   statement `(C, d_I)`.
//! * *Witness-level* — hand the prover a witness an honest party would never
//!   produce, via [`LevelCircuits::prove_node`]. These check the constraints
//!   themselves, including the two that Figure 5 leaves underspecified.

mod common;

use std::collections::BTreeSet;

use common::{is_rejected, leaves};
use plonky2::field::types::Field;
use plonky2::hash::hash_types::HashOut;
use reckle_qary::circuit::{ActiveChild, ReckleQary};
use reckle_qary::tree::{combine_canonical, node_hash, zero_digest, CanonicalTree, QaryTree, F};

// ---------------------------------------------------------------------------
// Verifier-level
// ---------------------------------------------------------------------------

#[test]
fn verifier_rejects_tampered_claims() {
    let (q, height) = (2, 3);
    let s = ReckleQary::setup(q, height).unwrap();
    let tree = QaryTree::new(q, height, leaves(8));
    let batch = BTreeSet::from([1, 4, 6]);
    let bp = s.prove_batch(&tree, &batch).unwrap();
    let claims = tree.claims(&batch);

    // Baseline: the honest statement is accepted.
    s.verify_batch(tree.root(), &claims, &bp).unwrap();

    // A different value at a batched position.
    let mut tampered = claims.clone();
    tampered.insert(4, F::from_canonical_u64(9999));
    assert!(s.verify_batch(tree.root(), &tampered, &bp).is_err());

    // Dropping a claim.
    let mut dropped = claims.clone();
    dropped.remove(&4);
    assert!(s.verify_batch(tree.root(), &dropped, &bp).is_err());

    // Adding a claim that was not in the batch.
    let mut extra = claims.clone();
    extra.insert(7, tree.leaves[7]);
    assert!(s.verify_batch(tree.root(), &extra, &bp).is_err());

    // Moving a claim to a different index, keeping the value.
    let mut moved = claims.clone();
    moved.remove(&1);
    moved.insert(2, tree.leaves[1]);
    assert!(s.verify_batch(tree.root(), &moved, &bp).is_err());
}

#[test]
fn verifier_rejects_a_different_commitment() {
    let (q, height) = (2, 3);
    let s = ReckleQary::setup(q, height).unwrap();
    let tree = QaryTree::new(q, height, leaves(8));
    let batch = BTreeSet::from([0, 5]);
    let bp = s.prove_batch(&tree, &batch).unwrap();

    let other = QaryTree::new(q, height, leaves(8).iter().map(|v| *v + F::ONE).collect());
    assert!(s.verify_batch(other.root(), &tree.claims(&batch), &bp).is_err());
    assert!(s.verify_batch(HashOut::ZERO, &tree.claims(&batch), &bp).is_err());
}

#[test]
fn verifier_rejects_a_proof_for_another_batch() {
    let (q, height) = (2, 3);
    let s = ReckleQary::setup(q, height).unwrap();
    let tree = QaryTree::new(q, height, leaves(8));

    let a = BTreeSet::from([1, 3]);
    let b = BTreeSet::from([2, 6]);
    let proof_a = s.prove_batch(&tree, &a).unwrap();

    assert!(s.verify_batch(tree.root(), &tree.claims(&b), &proof_a).is_err());
}

#[test]
fn verifier_rejects_a_mislabelled_root_arity() {
    // `k` selects which of the q root circuits to check against; claiming the wrong
    // one must not verify.
    let (q, height) = (2, 3);
    let s = ReckleQary::setup(q, height).unwrap();
    let tree = QaryTree::new(q, height, leaves(8));
    let batch = BTreeSet::from([1]); // root has exactly one active child
    let mut bp = s.prove_batch(&tree, &batch).unwrap();
    assert_eq!(bp.k, 1);

    bp.k = 2;
    assert!(s.verify_batch(tree.root(), &tree.claims(&batch), &bp).is_err());
}

#[test]
fn verifier_rejects_out_of_range_claims_without_panicking() {
    // The claims are supplied by whoever presents the proof, so they are untrusted.
    // An index past the end of the tree must come back as an error, not abort the
    // process: a verifier that panics on bad input is a denial of service.
    let (q, height) = (2, 3);
    let s = ReckleQary::setup(q, height).unwrap();
    let tree = QaryTree::new(q, height, leaves(8));
    let batch = BTreeSet::from([1, 4]);
    let bp = s.prove_batch(&tree, &batch).unwrap();

    let mut claims = tree.claims(&batch);
    claims.insert(8, F::ONE); // one past the last leaf

    let outcome = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        s.verify_batch(tree.root(), &claims, &bp).is_err()
    }));
    assert_eq!(outcome.ok(), Some(true), "expected a clean error, not a panic");
}

// ---------------------------------------------------------------------------
// Witness-level, base circuits (level 1, no recursion)
// ---------------------------------------------------------------------------

/// A height-1 tree: the root is a level-1 node whose children are the leaves.
fn base_setup(q: usize) -> (ReckleQary, QaryTree) {
    (ReckleQary::setup(q, 1).unwrap(), QaryTree::new(q, 1, leaves(q)))
}

#[test]
fn prover_cannot_repeat_a_child_position() {
    // Figure 5 step (2) only says the selected children are "a subset" of the
    // children, which does not forbid listing the same child twice. Our circuit
    // enforces strictly increasing positions, so this must be rejected.
    let (s, tree) = base_setup(4);
    let lc = s.level(1);
    let children = tree.children(1, 0).to_vec();

    let d_child = children[1];
    let active = vec![
        ActiveChild { position: 1, d: d_child, proof: None },
        ActiveChild { position: 1, d: d_child, proof: None },
    ];
    let d = combine_canonical(&[d_child, d_child]);

    assert!(is_rejected(lc, || lc.prove_node(tree.root(), d, &children, &active)));
}

#[test]
fn prover_cannot_reorder_child_positions() {
    // Descending order would give a different canonical digest for the same leaf
    // set, breaking canonicity.
    let (s, tree) = base_setup(4);
    let lc = s.level(1);
    let children = tree.children(1, 0).to_vec();

    let active = vec![
        ActiveChild { position: 2, d: children[2], proof: None },
        ActiveChild { position: 1, d: children[1], proof: None },
    ];
    let d = combine_canonical(&[children[2], children[1]]);

    assert!(is_rejected(lc, || lc.prove_node(tree.root(), d, &children, &active)));
}

#[test]
fn prover_cannot_pass_off_an_inactive_child_as_active() {
    // Canonical hash 0 marks "no batch element below"; it must never appear among
    // the active children (Figure 5 step (2)).
    //
    // Isolating this check takes care. Simply witnessing `d_x = 0` against a real
    // child would already be rejected by the level-1 leaf binding `C_x = d_x`,
    // since a real leaf hash is non-zero -- so the test would pass even with
    // `assert_digest_nonzero` deleted. We therefore zero the child's *Merkle* hash
    // too: then `C_x = d_x` holds trivially as `0 = 0`, `C` is recomputed to stay
    // consistent, and the k = 1 collapse makes `d = d_x = 0`. Every other
    // constraint is satisfied, leaving `assert_digest_nonzero` as the only thing
    // that can reject this witness.
    let (s, tree) = base_setup(4);
    let lc = s.level(1);

    let mut children = tree.children(1, 0).to_vec();
    children[0] = zero_digest();
    let c = node_hash(&children);

    let active = vec![ActiveChild { position: 0, d: zero_digest(), proof: None }];
    assert!(is_rejected(lc, || lc.prove_node(c, zero_digest(), &children, &active)));
}

#[test]
fn prover_cannot_claim_a_wrong_canonical_digest() {
    let (s, tree) = base_setup(4);
    let lc = s.level(1);
    let children = tree.children(1, 0).to_vec();

    let active = vec![
        ActiveChild { position: 0, d: children[0], proof: None },
        ActiveChild { position: 1, d: children[1], proof: None },
    ];
    let wrong_d = combine_canonical(&[children[1], children[0]]); // swapped

    assert!(is_rejected(lc, || lc.prove_node(tree.root(), wrong_d, &children, &active)));
}

#[test]
fn prover_cannot_claim_a_wrong_merkle_hash() {
    let (s, tree) = base_setup(4);
    let lc = s.level(1);
    let mut children = tree.children(1, 0).to_vec();
    children[3] = HashOut::ZERO; // no longer hashes to the real root

    let active = vec![ActiveChild { position: 0, d: children[0], proof: None }];
    assert!(is_rejected(lc, || lc.prove_node(tree.root(), children[0], &children, &active)));
}

#[test]
fn prover_cannot_invent_a_leaf_digest() {
    // At level 1 the `C_x = d_x` disjunct pins the child's canonical hash to its
    // Merkle hash, so a made-up leaf digest cannot be smuggled in.
    let (s, tree) = base_setup(4);
    let lc = s.level(1);
    let children = tree.children(1, 0).to_vec();

    let fake = HashOut { elements: [F::from_canonical_u64(123); 4] };
    let active = vec![ActiveChild { position: 0, d: fake, proof: None }];
    assert!(is_rejected(lc, || lc.prove_node(tree.root(), fake, &children, &active)));
}

// ---------------------------------------------------------------------------
// Witness-level, recursive circuits (level >= 2)
// ---------------------------------------------------------------------------

#[test]
fn prover_cannot_attach_a_proof_for_a_different_child() {
    // The parent connects the child's public `C` to the child it selected, so a
    // valid proof about a *sibling* subtree cannot be reused.
    let (q, height) = (2, 2);
    let s = ReckleQary::setup(q, height).unwrap();
    let tree = QaryTree::new(q, height, leaves(4));

    // Honest level-1 proof for node 0 (covering leaves 0,1) with leaf 0 batched.
    let batch = BTreeSet::from([0]);
    let ct = CanonicalTree::new(q, height, &tree.claims(&batch));
    let l1 = s.level(1);
    let child_proof = l1
        .prove_node(
            tree.node(1, 0),
            ct.get(1, 0),
            tree.children(1, 0),
            &[ActiveChild { position: 0, d: ct.get(0, 0), proof: None }],
        )
        .unwrap();

    // Now try to use it at the root while pointing at child position 1 (node 1).
    let l2 = s.level(2);
    let active = vec![ActiveChild {
        position: 1,
        d: ct.get(1, 0),
        proof: Some(&child_proof),
    }];
    assert!(is_rejected(l2, || {
        l2.prove_node(tree.root(), ct.get(1, 0), tree.children(2, 0), &active)
    }));
}

#[test]
fn prover_cannot_use_a_proof_from_another_tree() {
    let (q, height) = (2, 2);
    let s = ReckleQary::setup(q, height).unwrap();
    let tree = QaryTree::new(q, height, leaves(4));
    let other = QaryTree::new(q, height, leaves(4).iter().map(|v| *v + F::ONE).collect());

    let batch = BTreeSet::from([0]);
    let ct_other = CanonicalTree::new(q, height, &other.claims(&batch));
    let l1 = s.level(1);
    let foreign = l1
        .prove_node(
            other.node(1, 0),
            ct_other.get(1, 0),
            other.children(1, 0),
            &[ActiveChild { position: 0, d: ct_other.get(0, 0), proof: None }],
        )
        .unwrap();

    let ct = CanonicalTree::new(q, height, &tree.claims(&batch));
    let l2 = s.level(2);
    let active = vec![ActiveChild { position: 0, d: ct.get(1, 0), proof: Some(&foreign) }];
    assert!(is_rejected(l2, || {
        l2.prove_node(tree.root(), ct.get(1, 0), tree.children(2, 0), &active)
    }));
}

#[test]
fn prover_cannot_skip_a_level_by_treating_an_internal_node_as_a_leaf() {
    // Section 3.3 worries that a prover could stop the recursion early and prove a
    // statement about internal nodes rather than leaves, which is why the paper
    // introduces a `leaf()` predicate. We get the property structurally instead:
    // the level is baked into each circuit, so only level 1 has the `C = d`
    // disjunct and every higher level unconditionally demands a recursive proof.
    //
    // The structural assertion is the real content of this test. The `is_rejected`
    // check below is weaker -- `prove_node` rejects a missing child proof with its
    // own argument check, before any constraint is evaluated -- so on its own it
    // would pass even if the circuit were wrong. Both are asserted deliberately.
    let (q, height) = (2, 2);
    let s = ReckleQary::setup(q, height).unwrap();
    let tree = QaryTree::new(q, height, leaves(4));

    assert!(s.level(1).is_base(), "level 1 must be the leaf base case");
    for level in 2..=height {
        assert!(
            !s.level(level).is_base(),
            "level {level} must require recursive proofs, leaving no leaf disjunct to abuse"
        );
    }

    let l2 = s.level(2);
    let c1 = tree.node(1, 0);
    let active = vec![ActiveChild { position: 0, d: c1, proof: None }];
    assert!(is_rejected(l2, || l2.prove_node(tree.root(), c1, tree.children(2, 0), &active)));
}
