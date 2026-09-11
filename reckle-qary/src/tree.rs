//! Out-of-circuit `q`-ary Reckle tree: Merkle hashing and canonical hashing.
//!
//! This module is the *specification* that the circuits in [`crate::circuit`] are
//! checked against. Everything here is plain Rust so it can be tested cheaply and
//! read as the ground truth for what a proof is supposed to mean.
//!
//! Reference: Papamanthou et al., "Reckle Trees: Updatable Merkle Batch Proofs with
//! Applications", ACM CCS 2024 — Section 3.1 (canonical hashing) and Section 3.8
//! (`q`-ary Reckle trees).

use std::collections::{BTreeMap, BTreeSet};

use plonky2::field::goldilocks_field::GoldilocksField;
use plonky2::field::types::Field;
use plonky2::hash::hash_types::HashOut;
use plonky2::hash::poseidon::PoseidonHash;
use plonky2::plonk::config::Hasher;

/// Base field. Goldilocks, as used by Plonky2 and by the reference implementation.
pub type F = GoldilocksField;
/// Extension degree used throughout.
pub const D: usize = 2;
/// The hash `H` of the paper. The paper's basic implementation uses Poseidon.
pub type PHash = PoseidonHash;

/// The zero digest, standing for the paper's canonical hash value `0`.
///
/// The paper treats canonical hashes as integers and uses `0` as the "this subtree
/// contains no batch element" sentinel, relying on `d_L * d_R != 0` to detect it.
/// We represent a digest as four field elements, so `0` becomes the all-zero
/// `HashOut`. A Poseidon output colliding with it is a collision-resistance break,
/// so this is sound under the same assumption the paper already makes.
pub fn zero_digest() -> HashOut<F> {
    HashOut::ZERO
}

/// Merkle hash of a leaf: `H(index || value)`.
///
/// The paper stores `index || value` at each leaf (Section 3.1) so that a canonical
/// digest binds positions as well as values.
pub fn leaf_hash(index: usize, value: F) -> HashOut<F> {
    PHash::hash_no_pad(&[F::from_canonical_u64(index as u64), value])
}

/// Merkle hash of an internal node: `H(C_1 || ... || C_q)` (Section 3.8).
pub fn node_hash(children: &[HashOut<F>]) -> HashOut<F> {
    let mut flat = Vec::with_capacity(children.len() * 4);
    for c in children {
        flat.extend_from_slice(&c.elements);
    }
    PHash::hash_no_pad(&flat)
}

/// Canonical hash of an internal node from the canonical hashes of its *active*
/// children, in increasing child position.
///
/// This generalises the binary rule of Section 3.1 to arity `q`:
///
/// * `k == 0` -> `0`                      (matches `d = d_L + d_R` with both zero)
/// * `k == 1` -> the child's digest       (matches `d = d_L + d_R` with one zero)
/// * `k >= 2` -> `H(d_1 || ... || d_k)`   (matches `d = H(d_L || d_R)`)
///
/// Figure 5 of the paper writes step (4) unconditionally as `d = H(d_x1 || ... || d_xk)`,
/// which for `k == 1` would hash a single digest instead of passing it through. We
/// deliberately keep the collapsing rule of the binary construction: it is what makes
/// the canonical digest of a singleton batch equal to that leaf's hash, and it keeps
/// `q = 2` a faithful specialisation of the original scheme. See README, "Deviations".
pub fn combine_canonical(active: &[HashOut<F>]) -> HashOut<F> {
    match active.len() {
        0 => zero_digest(),
        1 => active[0],
        _ => {
            let mut flat = Vec::with_capacity(active.len() * 4);
            for d in active {
                flat.extend_from_slice(&d.elements);
            }
            PHash::hash_no_pad(&flat)
        }
    }
}

/// A full `q`-ary Merkle tree over `q^height` leaves.
#[derive(Clone, Debug)]
pub struct QaryTree {
    pub q: usize,
    pub height: usize,
    pub leaves: Vec<F>,
    /// `levels[0]` are the leaf hashes; `levels[height]` is the single root.
    levels: Vec<Vec<HashOut<F>>>,
}

impl QaryTree {
    pub fn new(q: usize, height: usize, leaves: Vec<F>) -> Self {
        assert!(q >= 2, "arity must be at least 2");
        assert!(height >= 1, "height must be at least 1");
        let n = q.checked_pow(height as u32).expect("tree too large");
        assert_eq!(leaves.len(), n, "expected {n} leaves for q={q}, height={height}");

        let mut levels: Vec<Vec<HashOut<F>>> = Vec::with_capacity(height + 1);
        levels.push(leaves.iter().enumerate().map(|(i, &v)| leaf_hash(i, v)).collect());
        for l in 0..height {
            let prev = &levels[l];
            let next = prev.chunks(q).map(node_hash).collect::<Vec<_>>();
            levels.push(next);
        }
        Self { q, height, leaves, levels }
    }

    pub fn num_leaves(&self) -> usize {
        self.leaves.len()
    }

    pub fn root(&self) -> HashOut<F> {
        self.levels[self.height][0]
    }

    /// Merkle hash of node `idx` at `level` (`level = 0` are leaves).
    pub fn node(&self, level: usize, idx: usize) -> HashOut<F> {
        self.levels[level][idx]
    }

    /// The `q` children hashes of node `idx` at `level` (`level >= 1`).
    pub fn children(&self, level: usize, idx: usize) -> &[HashOut<F>] {
        debug_assert!(level >= 1);
        let below = &self.levels[level - 1];
        &below[idx * self.q..(idx + 1) * self.q]
    }

    /// Update one leaf, recomputing only the affected path. Returns the new root.
    pub fn update_leaf(&mut self, index: usize, value: F) -> HashOut<F> {
        self.leaves[index] = value;
        self.levels[0][index] = leaf_hash(index, value);
        let mut idx = index;
        for l in 0..self.height {
            idx /= self.q;
            let h = node_hash(&self.levels[l][idx * self.q..(idx + 1) * self.q]);
            self.levels[l + 1][idx] = h;
        }
        self.root()
    }

    /// The claims `(index, value)` for a batch, as the verifier would receive them.
    pub fn claims(&self, batch: &BTreeSet<usize>) -> BTreeMap<usize, F> {
        batch.iter().map(|&i| (i, self.leaves[i])).collect()
    }
}

/// The sparse tree of canonical hashes induced by a batch.
///
/// This is `T'_I` of Section 3.3: only nodes that are ancestors of a batch element
/// carry a non-zero canonical hash, and only those are stored.
#[derive(Clone, Debug)]
pub struct CanonicalTree {
    pub q: usize,
    pub height: usize,
    /// `levels[l]` maps a node index at level `l` to its canonical hash.
    /// Only active nodes (canonical hash != 0) are present.
    pub levels: Vec<BTreeMap<usize, HashOut<F>>>,
}

impl CanonicalTree {
    /// Build the canonical-hash structure from the *claimed leaves alone*.
    ///
    /// This is exactly the computation the verifier performs in `Ver` (Figure 3):
    /// it needs no access to the tree, only to `(q, height)` and the claims.
    pub fn new(q: usize, height: usize, claims: &BTreeMap<usize, F>) -> Self {
        let n = q.pow(height as u32);
        let mut levels: Vec<BTreeMap<usize, HashOut<F>>> = Vec::with_capacity(height + 1);

        let mut level0 = BTreeMap::new();
        for (&i, &v) in claims {
            assert!(i < n, "leaf index {i} out of range for {n} leaves");
            level0.insert(i, leaf_hash(i, v));
        }
        levels.push(level0);

        for l in 0..height {
            let mut parents: BTreeMap<usize, Vec<HashOut<F>>> = BTreeMap::new();
            // BTreeMap iterates in increasing key order, so children are gathered
            // in increasing position -- the "sorted list of children" of Section 3.8.
            for (&idx, &d) in &levels[l] {
                parents.entry(idx / q).or_default().push(d);
            }
            let next = parents
                .into_iter()
                .map(|(p, active)| (p, combine_canonical(&active)))
                .collect();
            levels.push(next);
        }

        Self { q, height, levels }
    }

    /// The canonical digest `d_I` of the batch, or `0` for an empty batch.
    pub fn root(&self) -> HashOut<F> {
        self.levels[self.height].get(&0).copied().unwrap_or_else(zero_digest)
    }

    /// Canonical hash of a node, `0` if it is not an ancestor of the batch.
    pub fn get(&self, level: usize, idx: usize) -> HashOut<F> {
        self.levels[level].get(&idx).copied().unwrap_or_else(zero_digest)
    }

    /// Positions in `0..q` of the active children of node `idx` at `level >= 1`,
    /// in increasing order.
    pub fn active_children(&self, level: usize, idx: usize) -> Vec<usize> {
        debug_assert!(level >= 1);
        (0..self.q)
            .filter(|j| self.levels[level - 1].contains_key(&(idx * self.q + j)))
            .collect()
    }

    /// Node indices active at `level`, in increasing order.
    pub fn active_nodes(&self, level: usize) -> Vec<usize> {
        self.levels[level].keys().copied().collect()
    }
}

/// Verifier-side canonical digest: what `Ver` recomputes from the claimed leaves.
pub fn canonical_digest(q: usize, height: usize, claims: &BTreeMap<usize, F>) -> HashOut<F> {
    CanonicalTree::new(q, height, claims).root()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn vals(n: usize) -> Vec<F> {
        (0..n).map(|i| F::from_canonical_u64((i as u64 + 1) * 7)).collect()
    }

    #[test]
    fn root_is_stable_and_depends_on_every_leaf() {
        let mut t = QaryTree::new(4, 2, vals(16));
        let r0 = t.root();
        assert_eq!(r0, QaryTree::new(4, 2, vals(16)).root());
        for i in 0..16 {
            let mut t2 = t.clone();
            t2.update_leaf(i, F::from_canonical_u64(999));
            assert_ne!(r0, t2.root(), "root ignores leaf {i}");
        }
        // Incremental update agrees with a full rebuild.
        let mut expected = vals(16);
        expected[5] = F::from_canonical_u64(999);
        t.update_leaf(5, F::from_canonical_u64(999));
        assert_eq!(t.root(), QaryTree::new(4, 2, expected).root());
    }

    #[test]
    fn singleton_batch_digest_is_the_leaf_hash() {
        // The collapsing rule makes a singleton batch's canonical digest equal to
        // the leaf hash, at any arity and height.
        for (q, height) in [(2usize, 3usize), (4, 2), (3, 2)] {
            let n = q.pow(height as u32);
            let t = QaryTree::new(q, height, vals(n));
            for i in 0..n {
                let claims = t.claims(&BTreeSet::from([i]));
                assert_eq!(canonical_digest(q, height, &claims), leaf_hash(i, t.leaves[i]));
            }
        }
    }

    #[test]
    fn empty_batch_digest_is_zero() {
        assert_eq!(canonical_digest(4, 2, &BTreeMap::new()), zero_digest());
    }

    #[test]
    fn digest_binds_the_index_set_and_the_values() {
        let t = QaryTree::new(4, 2, vals(16));
        let base = t.claims(&BTreeSet::from([1, 6, 9]));
        let d = canonical_digest(4, 2, &base);

        // Different index set.
        for other in [
            BTreeSet::from([1, 6, 10]),
            BTreeSet::from([1, 6]),
            BTreeSet::from([1, 6, 9, 12]),
            BTreeSet::from([0, 6, 9]),
        ] {
            assert_ne!(d, canonical_digest(4, 2, &t.claims(&other)), "collision with {other:?}");
        }

        // Different value at a batched position.
        let mut tampered = base.clone();
        tampered.insert(6, F::from_canonical_u64(12345));
        assert_ne!(d, canonical_digest(4, 2, &tampered));
    }

    #[test]
    fn digest_ignores_leaves_outside_the_batch() {
        let mut t = QaryTree::new(4, 2, vals(16));
        let batch = BTreeSet::from([1, 6, 9]);
        let d = canonical_digest(4, 2, &t.claims(&batch));
        t.update_leaf(11, F::from_canonical_u64(42)); // 11 is not in the batch
        assert_eq!(d, canonical_digest(4, 2, &t.claims(&batch)));
    }

    #[test]
    fn canonical_tree_matches_leaf_hashes_and_structure() {
        let t = QaryTree::new(4, 2, vals(16));
        let batch = BTreeSet::from([1, 6, 9, 10]);
        let ct = CanonicalTree::new(4, 2, &t.claims(&batch));

        assert_eq!(ct.active_nodes(0), vec![1, 6, 9, 10]);
        assert_eq!(ct.active_nodes(1), vec![0, 1, 2]);
        assert_eq!(ct.active_nodes(2), vec![0]);

        // Node 2 at level 1 covers leaves 8..12, of which 9 and 10 are active.
        assert_eq!(ct.active_children(1, 2), vec![1, 2]);
        // Node 0 at level 1 covers leaves 0..4, of which only 1 is active,
        // so the collapsing rule passes the leaf hash straight through.
        assert_eq!(ct.get(1, 0), leaf_hash(1, t.leaves[1]));
    }

    #[test]
    fn q_equals_two_reproduces_the_binary_rules() {
        // With q = 2 the generalised combine must agree with Section 3.1 verbatim:
        // d = H(d_L || d_R) when both are non-zero, else d_L + d_R.
        let t = QaryTree::new(2, 3, vals(8));
        let claims = t.claims(&BTreeSet::from([2, 4, 5]));
        let ct = CanonicalTree::new(2, 3, &claims);

        // Level 1 node 2 covers leaves 4,5 -- both active -> hash of the pair.
        let expect = PHash::hash_no_pad(
            &[leaf_hash(4, t.leaves[4]).elements, leaf_hash(5, t.leaves[5]).elements].concat(),
        );
        assert_eq!(ct.get(1, 2), expect);
        // Level 1 node 1 covers leaves 2,3 -- only 2 active -> passthrough.
        assert_eq!(ct.get(1, 1), leaf_hash(2, t.leaves[2]));
    }
}
