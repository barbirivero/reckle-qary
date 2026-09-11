//! Circuit `Q_k` for batch proofs in a `q`-ary Reckle tree (Figure 5 of the paper),
//! together with the recursive prover and verifier that drive it.
//!
//! # What the proof means
//!
//! A verifying root proof establishes the statement of Section 3.8:
//!
//! > `d` is the root canonical digest with respect to some set of leaves of some
//! > `q`-ary Merkle tree whose root Merkle digest is `C`.
//!
//! The verifier then recomputes `d` locally from the claimed leaves
//! ([`crate::tree::canonical_digest`]) and compares.
//!
//! # Structure
//!
//! The paper parameterises `Q_k` by the number `k` of *active* children (children
//! that are ancestors of the batch), so that a node with few active children does
//! not pay for `q` recursive verifications. We build one circuit per `(level, k)`
//! pair with `k` in `1..=q`:
//!
//! * `k = 0` is never instantiated. A node with no active children has canonical
//!   hash `0` and is by definition not in `T'_I`, so it is never proved.
//! * Specialising per level as well as per `k` is the `q`-ary analogue of the
//!   Figure 4 optimisation, and is the route the paper itself suggests for trees of
//!   fixed shape ("by hardcoding the respective verification keys, as we did in
//!   Fig. 4"). It also makes the level-1 circuits a genuine base case with no
//!   recursive verification at all.
//!
//! All `q` circuits at a given level are padded to a common gate count so that they
//! share one [`CommonCircuitData`]. Without this a parent could not verify a child
//! proof whose shape depends on the child's own `k` — this is the concrete obstacle
//! that made the authors leave `q`-ary circuits as future work.

use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

use anyhow::{ensure, Result};
use plonky2::field::types::Field;
use plonky2::gates::gate::GateRef;
use plonky2::gates::noop::NoopGate;
use plonky2::hash::hash_types::{HashOut, HashOutTarget, MerkleCapTarget};
use plonky2::iop::target::{BoolTarget, Target};
use plonky2::iop::witness::{PartialWitness, WitnessWrite};
use plonky2::plonk::circuit_builder::CircuitBuilder;
use plonky2::plonk::circuit_data::{
    CircuitConfig, CircuitData, CommonCircuitData, VerifierCircuitTarget, VerifierOnlyCircuitData,
};
use plonky2::plonk::config::PoseidonGoldilocksConfig;
use plonky2::plonk::proof::{ProofWithPublicInputs, ProofWithPublicInputsTarget};

use crate::tree::{canonical_digest, zero_digest, CanonicalTree, QaryTree, D, F, PHash};

/// Plonky2 configuration: Poseidon over Goldilocks, the recursion-friendly default.
pub type Cfg = PoseidonGoldilocksConfig;

/// Public inputs are `C` (4) || `d` (4) || `V` (4).
pub const NUM_PUBLIC_INPUTS: usize = 12;

// ---------------------------------------------------------------------------
// Small in-circuit helpers
// ---------------------------------------------------------------------------

/// Assert that `h` is not the all-zero digest, i.e. that this child really is active.
///
/// Figure 5 step (2) requires the selected children to "have all non-zero `d_i`'s".
/// Without this a prover could present an inactive child as active and change the
/// shape of the canonical hash for a fixed leaf set.
fn assert_digest_nonzero(builder: &mut CircuitBuilder<F, D>, h: HashOutTarget) {
    let zero = builder.zero();
    let mut all_zero = builder.constant_bool(true);
    for e in h.elements {
        let is_zero = builder.is_equal(e, zero);
        all_zero = builder.and(all_zero, is_zero);
    }
    builder.assert_zero(all_zero.target);
}

/// Allocate a one-hot vector of length `n` and return it together with the encoded
/// index `sum_t t * sel[t]`.
fn one_hot(builder: &mut CircuitBuilder<F, D>, n: usize) -> (Vec<BoolTarget>, Target) {
    let sel: Vec<BoolTarget> = (0..n).map(|_| builder.add_virtual_bool_target_safe()).collect();
    let mut sum = builder.zero();
    let mut index = builder.zero();
    for (t, s) in sel.iter().enumerate() {
        sum = builder.add(sum, s.target);
        let weight = builder.constant(F::from_canonical_u64(t as u64));
        index = builder.mul_add(s.target, weight, index);
    }
    builder.assert_one(sum);
    (sel, index)
}

/// `sum_t sel[t] * options[t]`, for a one-hot `sel` over hash targets.
fn select_hash(
    builder: &mut CircuitBuilder<F, D>,
    sel: &[BoolTarget],
    options: &[HashOutTarget],
) -> HashOutTarget {
    let mut out = [builder.zero(); 4];
    for (t, s) in sel.iter().enumerate() {
        for e in 0..4 {
            out[e] = builder.mul_add(s.target, options[t].elements[e], out[e]);
        }
    }
    HashOutTarget { elements: out }
}

/// `sum_t sel[t] * constants[t]`, for a one-hot `sel` over constant hashes.
fn select_constant_hash(
    builder: &mut CircuitBuilder<F, D>,
    sel: &[BoolTarget],
    constants: &[HashOut<F>],
) -> HashOutTarget {
    let options: Vec<HashOutTarget> =
        constants.iter().map(|h| builder.constant_hash(*h)).collect();
    select_hash(builder, sel, &options)
}

/// Build a [`VerifierCircuitTarget`] that is *provably* one of `keys`.
///
/// This is Figure 5 step (1) — "check `vk_x1, ..., vk_xk` are in `V`" — realised by
/// construction: every wire of the verifier data is a one-hot combination of
/// circuit constants, so no other key can be witnessed. Constraining only the
/// circuit digest would leave `constants_sigmas_cap` free for the prover to choose.
fn select_verifier_data(
    builder: &mut CircuitBuilder<F, D>,
    sel: &[BoolTarget],
    keys: &[VerifierOnlyCircuitData<Cfg, D>],
) -> VerifierCircuitTarget {
    let digests: Vec<HashOut<F>> = keys.iter().map(|k| k.circuit_digest).collect();
    let circuit_digest = select_constant_hash(builder, sel, &digests);

    let cap_len = keys[0].constants_sigmas_cap.0.len();
    let mut cap = Vec::with_capacity(cap_len);
    for i in 0..cap_len {
        let column: Vec<HashOut<F>> =
            keys.iter().map(|k| k.constants_sigmas_cap.0[i]).collect();
        cap.push(select_constant_hash(builder, sel, &column));
    }

    VerifierCircuitTarget {
        constants_sigmas_cap: MerkleCapTarget(cap),
        circuit_digest,
    }
}

/// Human-readable report of why two `CommonCircuitData` differ.
///
/// Uniform shape across `k` is the load-bearing invariant of this construction, so
/// when it breaks the error needs to say exactly which field moved.
fn common_data_diff(a: &CommonCircuitData<F, D>, b: &CommonCircuitData<F, D>) -> String {
    let mut out = Vec::new();
    if a.fri_params.degree_bits != b.fri_params.degree_bits {
        out.push(format!(
            "degree_bits {} vs {}",
            a.fri_params.degree_bits, b.fri_params.degree_bits
        ));
    }
    if a.num_public_inputs != b.num_public_inputs {
        out.push(format!("num_public_inputs {} vs {}", a.num_public_inputs, b.num_public_inputs));
    }
    if a.num_constants != b.num_constants {
        out.push(format!("num_constants {} vs {}", a.num_constants, b.num_constants));
    }
    if a.quotient_degree_factor != b.quotient_degree_factor {
        out.push(format!(
            "quotient_degree_factor {} vs {}",
            a.quotient_degree_factor, b.quotient_degree_factor
        ));
    }
    if a.num_gate_constraints != b.num_gate_constraints {
        out.push(format!(
            "num_gate_constraints {} vs {}",
            a.num_gate_constraints, b.num_gate_constraints
        ));
    }
    if a.num_partial_products != b.num_partial_products {
        out.push(format!(
            "num_partial_products {} vs {}",
            a.num_partial_products, b.num_partial_products
        ));
    }
    let ga: Vec<String> = a.gates.iter().map(|g| g.0.id()).collect();
    let gb: Vec<String> = b.gates.iter().map(|g| g.0.id()).collect();
    if ga != gb {
        let only_a: Vec<&String> = ga.iter().filter(|g| !gb.contains(g)).collect();
        let only_b: Vec<&String> = gb.iter().filter(|g| !ga.contains(g)).collect();
        out.push(format!("gate sets differ; only in first: {only_a:?}; only in second: {only_b:?}"));
    }
    if out.is_empty() {
        out.push("differ in a field not covered by this report".to_string());
    }
    out.join("; ")
}

/// Out-of-circuit digest committing to a level's set of verification keys, `d(V)`.
fn key_set_digest(keys: &[VerifierOnlyCircuitData<Cfg, D>]) -> HashOut<F> {
    use plonky2::plonk::config::Hasher;
    let mut flat = Vec::new();
    for k in keys {
        flat.extend_from_slice(&k.circuit_digest.elements);
    }
    PHash::hash_no_pad(&flat)
}

// ---------------------------------------------------------------------------
// Circuit construction
// ---------------------------------------------------------------------------

/// Targets of one `Q_k` instance.
pub struct QTargets {
    pub c: HashOutTarget,
    pub d: HashOutTarget,
    pub v: HashOutTarget,
    /// Witness 1: the `q` children Merkle hashes.
    pub children: Vec<HashOutTarget>,
    /// Witness 2: one-hot position of each active child, in increasing order.
    pub pos_sel: Vec<Vec<BoolTarget>>,
    /// Witness 2: canonical hash of each active child.
    pub active_d: Vec<HashOutTarget>,
    /// Witness 3: the recursive proofs (empty at level 1).
    pub child_proofs: Vec<ProofWithPublicInputsTarget<D>>,
    /// Witness 3: one-hot choice of which child circuit produced each proof.
    pub child_key_sel: Vec<Vec<BoolTarget>>,
}

/// What a parent level needs to know about the level below it.
struct ChildInfo<'a> {
    common: &'a CommonCircuitData<F, D>,
    keys: &'a [VerifierOnlyCircuitData<Cfg, D>],
    /// Value of the `V` public input of the child circuits.
    v_public_input: HashOut<F>,
}

/// Build circuit `Q_k` for a node with exactly `k` active children.
///
/// `extra_gates` are registered into the gate set without being used, and
/// `pad_to_gates` adds `NoopGate` rows. Together they force every `k` at a level to
/// the same [`CommonCircuitData`]; see [`LevelCircuits::build`].
///
/// Returns the circuit, its targets, and the gate count reached before `build()`.
fn build_qk(
    q: usize,
    k: usize,
    v_public_input: HashOut<F>,
    child: Option<&ChildInfo>,
    extra_gates: &[GateRef<F, D>],
    pad_to_gates: Option<usize>,
) -> (CircuitData<F, Cfg, D>, QTargets, usize) {
    assert!((1..=q).contains(&k));
    let config = CircuitConfig::standard_recursion_config();
    let mut builder = CircuitBuilder::<F, D>::new(config);

    // --- public inputs: C, d, V ---
    let c = builder.add_virtual_hash();
    let d = builder.add_virtual_hash();
    let v = builder.add_virtual_hash();
    builder.register_public_inputs(&c.elements);
    builder.register_public_inputs(&d.elements);
    builder.register_public_inputs(&v.elements);

    // `V` is fixed by the setup, so bind it to a constant. The prover cannot swap in
    // a different key set and the verifier can read it straight off the proof.
    let v_const = builder.constant_hash(v_public_input);
    builder.connect_hashes(v, v_const);

    // --- witness 1: the q children ---
    let children: Vec<HashOutTarget> = (0..q).map(|_| builder.add_virtual_hash()).collect();

    // (3) C = H(C_1 || ... || C_q)
    let mut flat = Vec::with_capacity(4 * q);
    for ch in &children {
        flat.extend_from_slice(&ch.elements);
    }
    let c_computed = builder.hash_n_to_hash_no_pad::<PHash>(flat);
    builder.connect_hashes(c, c_computed);

    // --- witness 2: which children are active, and their canonical hashes ---
    let mut pos_sel = Vec::with_capacity(k);
    let mut positions = Vec::with_capacity(k);
    let mut active_c = Vec::with_capacity(k);
    let mut active_d = Vec::with_capacity(k);
    for _ in 0..k {
        let (sel, pos) = one_hot(&mut builder, q);
        active_c.push(select_hash(&mut builder, &sel, &children));
        let dj = builder.add_virtual_hash();
        assert_digest_nonzero(&mut builder, dj);
        active_d.push(dj);
        pos_sel.push(sel);
        positions.push(pos);
    }

    // Positions must be strictly increasing. Figure 5 only asks that the selected
    // pairs be "a subset" of the children, which does not pin down order or rule out
    // repetition; the prose of Section 3.8 says the canonical hash is over the
    // *sorted* list of children. Enforcing strict monotonicity here is what makes
    // the canonical digest canonical, and it also forces the k children to be
    // distinct. See README, "A gap in Figure 5".
    let pos_bits = usize::BITS as usize - (q - 1).leading_zeros() as usize;
    // Range-checking every position is redundant -- the one-hot encoding already
    // forces `pos < q` -- but it keeps the *set* of gate types identical for every
    // k at this level, which is what lets them share one CommonCircuitData. With
    // this omitted, Q_1 performs no range check at all and ends up with a different
    // gate set than Q_2..Q_q.
    for &p in &positions {
        builder.range_check(p, pos_bits);
    }
    for j in 1..k {
        let diff = builder.sub(positions[j], positions[j - 1]);
        let one = builder.one();
        let diff_minus_one = builder.sub(diff, one);
        builder.range_check(diff_minus_one, pos_bits);
    }

    // (4) d = combine(d_x1, ..., d_xk), with the collapsing rule of Section 3.1.
    let d_computed = if k == 1 {
        active_d[0]
    } else {
        let mut flat = Vec::with_capacity(4 * k);
        for dj in &active_d {
            flat.extend_from_slice(&dj.elements);
        }
        builder.hash_n_to_hash_no_pad::<PHash>(flat)
    };
    builder.connect_hashes(d, d_computed);

    // --- witness 3: recursion, or the leaf base case ---
    let mut child_proofs = Vec::new();
    let mut child_key_sel = Vec::new();
    match child {
        // Level 1: children are leaves. This is the `C_x = d_x` disjunct of Figure 5
        // steps (5)-(7). Because the level is baked into the circuit, a prover cannot
        // stop the recursion early at an internal node, which is the concern the
        // paper handles with an explicit `leaf()` predicate in Section 3.3.
        None => {
            for j in 0..k {
                builder.connect_hashes(active_c[j], active_d[j]);
            }
        }
        // Level >= 2: verify one proof per active child.
        Some(info) => {
            let child_v = builder.constant_hash(info.v_public_input);
            for j in 0..k {
                let proof = builder.add_virtual_proof_with_pis(info.common);
                // The child's statement must be about this very child.
                for e in 0..4 {
                    builder.connect(proof.public_inputs[e], active_c[j].elements[e]);
                    builder.connect(proof.public_inputs[4 + e], active_d[j].elements[e]);
                    builder.connect(proof.public_inputs[8 + e], child_v.elements[e]);
                }
                let (sel, _) = one_hot(&mut builder, info.keys.len());
                let vk = select_verifier_data(&mut builder, &sel, info.keys);
                builder.verify_proof::<Cfg>(&proof, &vk, info.common);
                child_proofs.push(proof);
                child_key_sel.push(sel);
            }
        }
    }

    // Register gate types this particular k does not happen to use, so that every k
    // at this level agrees on the gate set (and therefore on the selector layout).
    for g in extra_gates {
        builder.add_gate_to_gate_set(g.clone());
    }

    // Pad so that every k at this level ends up with identical `CommonCircuitData`.
    if let Some(target) = pad_to_gates {
        while builder.num_gates() < target {
            builder.add_gate(NoopGate, vec![]);
        }
    }

    let gates_before_build = builder.num_gates();
    let data = builder.build::<Cfg>();
    let targets = QTargets { c, d, v, children, pos_sel, active_d, child_proofs, child_key_sel };
    (data, targets, gates_before_build)
}

/// The `q` circuits `Q_1..Q_q` for one level of the tree.
pub struct LevelCircuits {
    /// `circuits[k - 1]` handles a node with `k` active children.
    pub circuits: Vec<CircuitData<F, Cfg, D>>,
    pub targets: Vec<QTargets>,
    /// Shared by every `k` at this level.
    pub common: CommonCircuitData<F, D>,
    /// Value of the `V` public input of these circuits: `d(V)` of the level below.
    pub v_public_input: HashOut<F>,
    /// `d(V)` of *this* level, i.e. what the level above uses as its `V`.
    pub key_set_digest: HashOut<F>,
}

impl LevelCircuits {
    fn build(q: usize, v_public_input: HashOut<F>, child: Option<&ChildInfo>) -> Result<Self> {
        // Every k at this level must end up with byte-identical CommonCircuitData,
        // otherwise a parent cannot verify a child proof without knowing the child's
        // k. Two things vary with k and must be neutralised:
        //
        //   * the gate *set* -- e.g. only some k spill constants into a ConstantGate,
        //     and k = 1 needs no comparison for the ordering check;
        //   * the gate *count*, which fixes the degree.
        //
        // So we build once to observe both, then rebuild every k with the union of
        // the gate sets and padded to a common size. The "+ 1" ensures even the
        // largest circuit receives a NoopGate, so that gate type is present in all.
        let mut union: Vec<GateRef<F, D>> = Vec::new();
        let mut max_gates = 0usize;
        for k in 1..=q {
            let (data, _, gates) = build_qk(q, k, v_public_input, child, &[], None);
            max_gates = max_gates.max(gates);
            for g in &data.common.gates {
                if !union.iter().any(|u| u.0.id() == g.0.id()) {
                    union.push(g.clone());
                }
            }
        }
        let target_gates = max_gates + 1;

        let mut circuits = Vec::with_capacity(q);
        let mut targets = Vec::with_capacity(q);
        for k in 1..=q {
            let (data, t, _) = build_qk(q, k, v_public_input, child, &union, Some(target_gates));
            circuits.push(data);
            targets.push(t);
        }

        let common = circuits[0].common.clone();
        for (i, data) in circuits.iter().enumerate() {
            ensure!(
                data.common == common,
                "circuits Q_1 and Q_{} at this level have different CommonCircuitData; \
                 padding to a uniform shape failed: {}",
                i + 1,
                common_data_diff(&common, &data.common)
            );
            ensure!(data.common.num_public_inputs == NUM_PUBLIC_INPUTS);
        }

        let keys: Vec<VerifierOnlyCircuitData<Cfg, D>> =
            circuits.iter().map(|c| c.verifier_only.clone()).collect();
        let key_set_digest = key_set_digest(&keys);

        Ok(Self { circuits, targets, common, v_public_input, key_set_digest })
    }

    fn keys(&self) -> Vec<VerifierOnlyCircuitData<Cfg, D>> {
        self.circuits.iter().map(|c| c.verifier_only.clone()).collect()
    }

    /// Number of active children this level's circuits were built to recurse on.
    pub fn arity(&self) -> usize {
        self.circuits.len()
    }

    /// Whether these are the level-1 (leaf) circuits, which perform no recursion.
    pub fn is_base(&self) -> bool {
        self.targets[0].child_proofs.is_empty()
    }

    /// Fill the witness of `Q_k` for a single node and prove it.
    ///
    /// This is the one place that maps a node's data onto circuit targets, so it is
    /// also the hook the adversarial tests use to feed in witnesses an honest prover
    /// would never produce.
    pub fn prove_node(
        &self,
        c: HashOut<F>,
        d: HashOut<F>,
        children: &[HashOut<F>],
        active: &[ActiveChild<'_>],
    ) -> Result<BatchProof> {
        let q = self.arity();
        let k = active.len();
        ensure!((1..=q).contains(&k), "k = {k} out of range for arity {q}");
        ensure!(children.len() == q, "expected {q} children, got {}", children.len());

        let circuit = &self.circuits[k - 1];
        let t = &self.targets[k - 1];
        let mut pw = PartialWitness::new();

        pw.set_hash_target(t.c, c)?;
        pw.set_hash_target(t.d, d)?;
        pw.set_hash_target(t.v, self.v_public_input)?;
        for (j, ch) in children.iter().enumerate() {
            pw.set_hash_target(t.children[j], *ch)?;
        }

        for (j, a) in active.iter().enumerate() {
            ensure!(a.position < q, "child position {} out of range", a.position);
            for (p, sel) in t.pos_sel[j].iter().enumerate() {
                pw.set_bool_target(*sel, p == a.position)?;
            }
            pw.set_hash_target(t.active_d[j], a.d)?;

            if self.is_base() {
                ensure!(a.proof.is_none(), "level 1 children are leaves and carry no proof");
            } else {
                let child = a.proof.ok_or_else(|| {
                    anyhow::anyhow!("child at position {} needs a recursive proof", a.position)
                })?;
                pw.set_proof_with_pis_target(&t.child_proofs[j], &child.proof)?;
                for (s, sel) in t.child_key_sel[j].iter().enumerate() {
                    pw.set_bool_target(*sel, s == child.k - 1)?;
                }
            }
        }

        let proof = circuit.prove(pw)?;
        Ok(BatchProof { k, proof })
    }
}

/// One active child of a node, as handed to [`LevelCircuits::prove_node`].
pub struct ActiveChild<'a> {
    /// Position in `0..q` among the parent's children.
    pub position: usize,
    /// The child's canonical hash.
    pub d: HashOut<F>,
    /// The child's recursive proof; `None` exactly at level 1, where children are leaves.
    pub proof: Option<&'a BatchProof>,
}

// ---------------------------------------------------------------------------
// The scheme
// ---------------------------------------------------------------------------

/// Time spent proving one node of `T'_I`.
#[derive(Clone, Copy, Debug, serde::Serialize)]
pub struct NodeStat {
    pub level: usize,
    pub k: usize,
    pub millis: f64,
}

/// A batch proof: the root recursive proof plus the arity of the root node, which
/// tells the verifier which of the `q` root circuits to use.
#[derive(Clone)]
pub struct BatchProof {
    pub k: usize,
    pub proof: ProofWithPublicInputs<F, Cfg, D>,
}

impl BatchProof {
    /// Serialised proof size in bytes.
    pub fn size_bytes(&self) -> usize {
        self.proof.to_bytes().len()
    }
}

/// A `q`-ary Reckle tree instance: the circuits for every level.
pub struct ReckleQary {
    pub q: usize,
    pub height: usize,
    /// `levels[i]` holds the circuits for tree level `i + 1`.
    pub levels: Vec<LevelCircuits>,
}

impl ReckleQary {
    /// Run `Gen`: build the `height * q` circuits bottom-up.
    pub fn setup(q: usize, height: usize) -> Result<Self> {
        assert!(q >= 2 && height >= 1);
        let mut levels: Vec<LevelCircuits> = Vec::with_capacity(height);

        // Level 1: children are leaves, so there is no key set below and no recursion.
        levels.push(LevelCircuits::build(q, zero_digest(), None)?);

        for i in 2..=height {
            let below = &levels[i - 2];
            let keys = below.keys();
            let info = ChildInfo {
                common: &below.common,
                keys: &keys,
                v_public_input: below.v_public_input,
            };
            let v = below.key_set_digest;
            let level = LevelCircuits::build(q, v, Some(&info))?;
            levels.push(level);
        }

        // Distinct levels must have distinct verification keys, otherwise a proof
        // from one level could stand in for another and the recursion could be made
        // to skip levels. This holds by construction -- each level up adds real
        // recursion gates -- but it is the kind of invariant that should be checked
        // rather than assumed, so we check it.
        for i in 0..levels.len() {
            for j in (i + 1)..levels.len() {
                ensure!(
                    levels[i].key_set_digest != levels[j].key_set_digest,
                    "levels {} and {} produced the same verification keys; a proof from \
                     one could be substituted for the other",
                    i + 1,
                    j + 1
                );
            }
        }

        Ok(Self { q, height, levels })
    }

    /// Circuits for tree level `level`, counting leaves as level 0.
    pub fn level(&self, level: usize) -> &LevelCircuits {
        &self.levels[level - 1]
    }

    /// Run `Agg`: compute the batch proof for `batch` by applying `Q_k` bottom-up.
    pub fn prove_batch(&self, tree: &QaryTree, batch: &BTreeSet<usize>) -> Result<BatchProof> {
        Ok(self.prove_batch_with_stats(tree, batch)?.0)
    }

    /// As [`Self::prove_batch`], also returning a per-node timing breakdown.
    ///
    /// The breakdown is what the benchmarks use to isolate the cost of `Q_k` as a
    /// function of `k`, which is the quantity the `Q_k` family is meant to reduce.
    pub fn prove_batch_with_stats(
        &self,
        tree: &QaryTree,
        batch: &BTreeSet<usize>,
    ) -> Result<(BatchProof, Vec<NodeStat>)> {
        let state = self.aggregate(tree, batch)?;
        let root = state.root_proof().clone();
        Ok((root, state.last_stats))
    }

    /// Run `Ver`: recompute the canonical digest from the claims and check the proof.
    pub fn verify_batch(
        &self,
        commitment: HashOut<F>,
        claims: &BTreeMap<usize, F>,
        bp: &BatchProof,
    ) -> Result<()> {
        ensure!(!claims.is_empty(), "empty batch");
        ensure!((1..=self.q).contains(&bp.k), "root arity {} out of range", bp.k);

        // The claims come from whoever is presenting the proof, so they are untrusted.
        // `canonical_digest` panics on an out-of-range index; a verifier must reject
        // bad input rather than abort, so the range is checked here first.
        let num_leaves = self.q.pow(self.height as u32);
        if let Some((&bad, _)) = claims.iter().find(|(&i, _)| i >= num_leaves) {
            anyhow::bail!("claimed leaf index {bad} is out of range for {num_leaves} leaves");
        }

        let d = canonical_digest(self.q, self.height, claims);
        let lc = self.level(self.height);

        // The proof only attests to *its own* public inputs, so bind them to the
        // statement the verifier cares about before checking the proof itself.
        let pis = &bp.proof.public_inputs;
        ensure!(pis.len() == NUM_PUBLIC_INPUTS, "unexpected public input count");
        ensure!(pis[0..4] == commitment.elements, "proof is about a different Merkle root");
        ensure!(pis[4..8] == d.elements, "proof is about a different canonical digest");
        ensure!(pis[8..12] == lc.v_public_input.elements, "proof uses a different key set");

        lc.circuits[bp.k - 1].verify(bp.proof.clone())
    }

    /// Number of gates of the circuit for `k` active children at `level`.
    pub fn circuit_degree(&self, level: usize, k: usize) -> usize {
        self.level(level).circuits[k - 1].common.degree()
    }

    /// Run `Agg`, keeping the whole batch data structure `Lambda_I` so that the
    /// proof can later be updated instead of recomputed.
    pub fn aggregate(&self, tree: &QaryTree, batch: &BTreeSet<usize>) -> Result<BatchState> {
        ensure!(!batch.is_empty(), "batch must be non-empty");
        ensure!(tree.q == self.q && tree.height == self.height, "tree/circuit mismatch");

        let ct = CanonicalTree::new(self.q, self.height, &tree.claims(batch));
        let mut state =
            BatchState { batch: batch.clone(), ct, proofs: BTreeMap::new(), last_stats: Vec::new() };
        for level in 1..=self.height {
            let nodes = state.ct.active_nodes(level);
            self.prove_nodes(tree, &mut state, level, &nodes)?;
        }
        Ok(state)
    }

    /// Run `UpdBatchProof`: apply a leaf update and refresh only the affected proofs.
    ///
    /// Changing leaf `index` invalidates exactly the nodes of `T'_I` on the path from
    /// that leaf to the root — at most `height` of them, independently of `|I|`.
    /// This holds whether or not `index` is itself in the batch: if it is, canonical
    /// hashes change too; if it is not, only Merkle hashes do, but the ancestors'
    /// proofs still have to be recomputed because the children hashes are part of
    /// their witness (Section 3.4, cases 1 and 2).
    pub fn update_leaf(
        &self,
        tree: &mut QaryTree,
        state: &mut BatchState,
        index: usize,
        value: F,
    ) -> Result<()> {
        ensure!(index < tree.num_leaves(), "leaf index out of range");
        tree.update_leaf(index, value);

        // Recomputing the canonical structure is O(|I| * height) hashes, negligible
        // next to a single recursive proof, so we simply rebuild it. Only the path
        // to `index` can actually have changed.
        state.ct = CanonicalTree::new(self.q, self.height, &tree.claims(&state.batch));

        state.last_stats.clear();
        for level in 1..=self.height {
            let idx = index / self.q.pow(level as u32);
            // Ancestors that carry no batch element below them hold no proof.
            if state.ct.get(level, idx) == zero_digest() {
                continue;
            }
            self.prove_nodes(tree, state, level, &[idx])?;
        }
        Ok(())
    }

    /// Prove the given nodes at `level`, recording timings in `state.last_stats`.
    fn prove_nodes(
        &self,
        tree: &QaryTree,
        state: &mut BatchState,
        level: usize,
        nodes: &[usize],
    ) -> Result<()> {
        let lc = self.level(level);
        for &idx in nodes {
            let active: Vec<ActiveChild<'_>> = state
                .ct
                .active_children(level, idx)
                .into_iter()
                .map(|pos| {
                    let child_idx = idx * self.q + pos;
                    ActiveChild {
                        position: pos,
                        d: state.ct.get(level - 1, child_idx),
                        proof: if level >= 2 {
                            state.proofs.get(&(level - 1, child_idx))
                        } else {
                            None
                        },
                    }
                })
                .collect();

            let started = Instant::now();
            let bp = lc.prove_node(
                tree.node(level, idx),
                state.ct.get(level, idx),
                tree.children(level, idx),
                &active,
            )?;
            let millis = started.elapsed().as_secs_f64() * 1e3;
            drop(active);
            state.last_stats.push(NodeStat { level, k: bp.k, millis });
            state.proofs.insert((level, idx), bp);
        }
        Ok(())
    }
}

/// The batch data structure `Lambda_I` (Section 3.4): every recursive proof along
/// the paths from the batch to the root, kept so updates cost `O(height)` proofs.
pub struct BatchState {
    pub batch: BTreeSet<usize>,
    pub ct: CanonicalTree,
    /// Keyed by `(level, node index)`.
    pub proofs: BTreeMap<(usize, usize), BatchProof>,
    /// Per-node timings of the most recent aggregate/update.
    pub last_stats: Vec<NodeStat>,
}

impl BatchState {
    /// The current batch proof `pi_I`.
    pub fn root_proof(&self) -> &BatchProof {
        self.proofs.get(&(self.ct.height, 0)).expect("root proof is always present")
    }

    /// Number of recursive proofs stored, i.e. the size of `Lambda_I`.
    pub fn num_proofs(&self) -> usize {
        self.proofs.len()
    }
}
