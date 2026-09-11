# Design notes

Detail that did not fit in the README word budget. This file expands Section 5 of
[README.md](README.md).

## Deviations from Figure 5

All of these are on purpose. The paper's Figure 5 is a specification sketch and a few of its steps
do not survive contact with a real circuit.

| Figure 5 says | We do | Why |
| --- | --- | --- |
| d = H(d_x1, ..., d_xk) always | for k=1 pass the digest through | keeps q=2 exactly as Section 3.1, and makes a batch of one leaf have that leaf hash as its digest |
| active children are "a subset" | positions strictly increasing | makes the canonical digest canonical, and forbids repetition |
| Witness 1 has (C_i, d_i) for all q | only C_i | the d_i of inactive children are unconstrained, so checking them does nothing |
| k = 0 to q | k = 1 to q | a node with no active child has d = 0 and is not in T'_I, so it never gets proved |
| step (5) says Verify(vk1, ...) | vk_x1 | looks like a typo in the paper |
| check that vk are in V | one-hot selection over constants | constraining only circuit_digest would leave constants_sigmas_cap free for the prover to choose |
| leaf() predicate from Section 3.3 | not needed | the level is fixed inside each circuit, so the recursion cannot stop early at an internal node |

### On the ordering check

Step (2) of Figure 5 asks only that the selected children be "a subset" of the q children. A subset
does not fix an order and does not forbid repetition. But the prose of Section 3.8 defines the
canonical hash over the sorted list of children that are ancestors of I. So the figure and the
prose do not agree, and the figure is the weaker of the two.

If a prover could reorder the active children, the same set of leaves would produce a different d,
and the canonical digest would stop being canonical. We enforce strictly increasing positions. The
encoding is a one-hot vector per active child, from which we read off a position, plus a range
check on each consecutive difference minus one. A repeated position gives a difference of 0 and a
descending pair gives a negative difference, and both wrap to a large field element that fails the
range check.

Two tests cover this, `prover_cannot_repeat_a_child_position` and
`prover_cannot_reorder_child_positions`. Both fail inside the prover on a real constraint, not in
an argument check.

### On V

Since we specialise per level, the key set of a node's children is already known when the node's
circuit is built, so membership in V is enforced structurally rather than by a witness check. Every
wire of the verifier data, the circuit digest and every element of constants_sigmas_cap, is a
one-hot combination of the real child keys. No other key can be witnessed.

That means the V public input is a redundant binding that we kept in order to stay close to
Figure 5, and the security argument does not rest on it. We did not implement the committed set
with Merkle proofs that the paper describes, because our construction does not need it. A tree of
variable shape, where the child's circuit is not known when the parent is built, would.

### On the uniform shape

This is the obstacle that the paper names when it defers q-ary circuits. In Plonky2 the shape of a
proof depends on the circuit that produced it, and a parent has to verify a child proof without
knowing how many active children that child had. So all q circuits of a level have to agree on
their CommonCircuitData.

Padding to a common size is not enough on its own. Circuits for different k also differ in which
gate types they use. Two cases we hit in practice:

* k=1 performs no ordering comparison, so it emitted no range check gates at all.
* Only some k spill enough constants to allocate a ConstantGate.

So we do two things. We build every k once to observe its gate set and gate count, then rebuild
each one with the union of all the gate sets registered into it, padded with NoopGate to a common
count. The setup asserts that the resulting CommonCircuitData really are equal, and when they are
not it reports which field differs, since this invariant is what the whole construction rests on.

The cost is that every k ends up as large as k=q. That is exactly why the Q_k specialisation buys
nothing here, which is result 2 in the README.

## Test inventory

32 tests, all run in CI.

### Unit, the canonical hashing spec (7)

These test `src/tree.rs`, which is the out of circuit specification that the circuits are checked
against.

* the root is stable and depends on every leaf, and an incremental update matches a full rebuild
* a singleton batch digest equals the leaf hash, at several arities and heights
* an empty batch has digest 0
* the digest binds both the index set and the values
* the digest ignores leaves outside the batch
* the canonical tree has the expected active nodes and collapse behaviour
* q=2 reproduces the binary rules of Section 3.1 verbatim

### Completeness (5)

* the binary case, over several batch shapes including a single leaf and all leaves
* q=4 with batches that exercise every k from 1 to 4
* the full batch case, which is the digest translation setting of Section 4.1
* a proof still verifies after a leaf outside the batch changes, and the stale proof does not
* proof size does not depend on the batch size

### Soundness (14)

Verifier level, where an honest proof is presented against a false statement:

* tampered, dropped, added and moved claims
* a different Merkle root, and the zero root
* a proof computed for another batch
* a mislabelled root arity
* out of range claims, which must come back as an error and not a panic

Witness level, where the prover is fed a witness no honest party would build:

* a repeated child position
* reordered child positions
* a zero canonical digest presented as an active child
* a wrong canonical digest
* a wrong Merkle hash
* an invented leaf digest
* a proof for a sibling subtree
* a proof from another tree
* skipping a level

A test passes only if no verifying proof comes out. A panic during witness generation, an error
from the prover, and a proof that fails verification all count as a rejection, so the assertion
cannot be satisfied by accident.

Two of these needed care to avoid being vacuous, and we say so in the test bodies.
`prover_cannot_pass_off_an_inactive_child_as_active` also zeroes the child's Merkle hash, because
otherwise the level 1 leaf binding C_x = d_x would already reject the witness and the test would
pass even with the non zero check deleted. `prover_cannot_skip_a_level...` asserts the structural
property directly, that only level 1 has a leaf disjunct, because the prove_node rejection on its
own happens in an argument check rather than in the circuit.

### Updatability (4)

* an update of a batched leaf matches a fresh proof, on the same public inputs
* an update of a leaf outside the batch leaves the canonical digest alone but still refreshes the
  proof, and the pre update proof stops verifying
* an update touches at most one node per level, for both a tiny and a full batch
* repeated updates stay consistent
