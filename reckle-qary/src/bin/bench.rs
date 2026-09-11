//! Benchmarks for `q`-ary Reckle trees.
//!
//! Everything reported here is measured, never extrapolated. Three comparisons are
//! produced, each with an explicit baseline:
//!
//! 1. **Arity.** The same number of leaves under `q = 2` (the paper's binary
//!    construction, our baseline) and under `q > 2`. A `q`-ary tree is shallower, so
//!    the batch proof needs fewer levels of recursion.
//! 2. **The `Q_k` family.** Proving time for a root node with `k = 1..q` active
//!    children. Without the family, every node would pay the `k = q` cost; the ratio
//!    between `k = q` and `k = 1` is what the family saves per node.
//! 3. **Updates.** Refreshing a batch proof after a single leaf change versus
//!    recomputing it from scratch — the paper's headline claim.
//!
//! Usage:
//!   cargo run --release --bin bench -- [--out results/bench.json] [--quick]

use std::collections::BTreeSet;
use std::time::Instant;

use anyhow::Result;
use plonky2::field::types::Field;
use reckle_qary::circuit::ReckleQary;
use reckle_qary::tree::{QaryTree, F};
use serde::Serialize;

#[derive(Serialize)]
struct Machine {
    cpu: String,
    logical_cores: usize,
    os: String,
    rustc: String,
    plonky2: String,
    profile: String,
}

#[derive(Serialize)]
struct CircuitSize {
    level: usize,
    k: usize,
    degree: usize,
}

#[derive(Serialize)]
struct AggPoint {
    batch_size: usize,
    nodes_proved: usize,
    aggregate_ms: f64,
    verify_ms: f64,
    proof_bytes: usize,
}

#[derive(Serialize)]
struct PerKPoint {
    k: usize,
    root_prove_ms: f64,
}

#[derive(Serialize)]
struct UpdatePoint {
    batch_size: usize,
    updated_leaf: usize,
    leaf_in_batch: bool,
    proofs_recomputed: usize,
    update_ms: f64,
    full_reaggregate_ms: f64,
    speedup: f64,
}

#[derive(Serialize)]
struct ConfigResult {
    q: usize,
    height: usize,
    num_leaves: usize,
    setup_ms: f64,
    lambda_size_proofs: usize,
    circuit_sizes: Vec<CircuitSize>,
    aggregation: Vec<AggPoint>,
    per_k: Vec<PerKPoint>,
    updates: Vec<UpdatePoint>,
}

#[derive(Serialize)]
struct Report {
    machine: Machine,
    configs: Vec<ConfigResult>,
}

fn leaves(n: usize) -> Vec<F> {
    (0..n).map(|i| F::from_canonical_u64((i as u64 + 1) * 2_654_435_761)).collect()
}

fn machine() -> Machine {
    Machine {
        cpu: std::env::var("PROCESSOR_IDENTIFIER").unwrap_or_else(|_| "unknown".into()),
        logical_cores: std::thread::available_parallelism().map(|n| n.get()).unwrap_or(0),
        os: format!("{} {}", std::env::consts::OS, std::env::consts::ARCH),
        rustc: option_env!("RUSTC_VERSION").unwrap_or("nightly").to_string(),
        plonky2: "1.1.0".into(),
        profile: "release (opt-level=3, lto=thin, codegen-units=1)".into(),
    }
}

/// Median of repeated verifications, in milliseconds.
fn time_verify(s: &ReckleQary, tree: &QaryTree, batch: &BTreeSet<usize>, reps: usize) -> Result<f64> {
    let bp = s.prove_batch(tree, batch)?;
    let claims = tree.claims(batch);
    let mut samples = Vec::with_capacity(reps);
    for _ in 0..reps {
        let t = Instant::now();
        s.verify_batch(tree.root(), &claims, &bp)?;
        samples.push(t.elapsed().as_secs_f64() * 1e3);
    }
    samples.sort_by(|a, b| a.partial_cmp(b).unwrap());
    Ok(samples[samples.len() / 2])
}

fn run_config(q: usize, height: usize, quick: bool) -> Result<ConfigResult> {
    let n = q.pow(height as u32);
    eprintln!("=== q={q}, height={height}, n={n} ===");

    let t = Instant::now();
    let s = ReckleQary::setup(q, height)?;
    let setup_ms = t.elapsed().as_secs_f64() * 1e3;
    eprintln!("  setup: {setup_ms:.0} ms");

    let mut circuit_sizes = Vec::new();
    for level in 1..=height {
        for k in 1..=q {
            circuit_sizes.push(CircuitSize { level, k, degree: s.circuit_degree(level, k) });
        }
    }

    let tree = QaryTree::new(q, height, leaves(n));

    // --- aggregation and verification, as a function of batch size ---
    let mut sizes: Vec<usize> = vec![1, 2, 4];
    if !quick {
        sizes.push(n / 2);
        sizes.push(n);
    }
    sizes.retain(|&m| m >= 1 && m <= n);
    sizes.dedup();

    let mut aggregation = Vec::new();
    let mut lambda_size_proofs = 0;
    for &m in &sizes {
        // Spread the batch evenly so it is not an artificially easy shape.
        let batch: BTreeSet<usize> = (0..m).map(|j| j * (n / m)).collect();
        let t = Instant::now();
        let state = s.aggregate(&tree, &batch)?;
        let aggregate_ms = t.elapsed().as_secs_f64() * 1e3;
        let nodes_proved = state.last_stats.len();
        lambda_size_proofs = lambda_size_proofs.max(state.num_proofs());
        let proof_bytes = state.root_proof().size_bytes();
        let verify_ms = time_verify(&s, &tree, &batch, if quick { 5 } else { 25 })?;
        eprintln!(
            "  |I|={m:<4} agg {aggregate_ms:8.0} ms over {nodes_proved:3} nodes, \
             verify {verify_ms:6.2} ms, proof {proof_bytes} B"
        );
        aggregation.push(AggPoint { batch_size: m, nodes_proved, aggregate_ms, verify_ms, proof_bytes });
    }

    // --- cost of Q_k as a function of k, measured at the root ---
    let stride = n / q;
    let mut per_k = Vec::new();
    for k in 1..=q {
        let batch: BTreeSet<usize> = (0..k).map(|j| j * stride).collect();
        let state = s.aggregate(&tree, &batch)?;
        let root_prove_ms = state
            .last_stats
            .iter()
            .find(|st| st.level == height)
            .map(|st| st.millis)
            .unwrap_or(f64::NAN);
        eprintln!("  root with k={k}: {root_prove_ms:.0} ms");
        per_k.push(PerKPoint { k, root_prove_ms });
    }

    // --- updates vs full re-aggregation ---
    let mut updates = Vec::new();
    let m = if quick { 2 } else { n / 2 };
    let batch: BTreeSet<usize> = (0..m).map(|j| j * (n / m)).collect();
    for &leaf in &[0usize, 1usize] {
        let in_batch = batch.contains(&leaf);
        let mut tree_u = tree.clone();
        let mut state = s.aggregate(&tree_u, &batch)?;

        let t = Instant::now();
        s.update_leaf(&mut tree_u, &mut state, leaf, F::from_canonical_u64(123_456))?;
        let update_ms = t.elapsed().as_secs_f64() * 1e3;
        let proofs_recomputed = state.last_stats.len();

        // The update must land on the same proof a fresh aggregation would give.
        s.verify_batch(tree_u.root(), &tree_u.claims(&batch), state.root_proof())?;

        let t = Instant::now();
        let fresh = s.aggregate(&tree_u, &batch)?;
        let full_reaggregate_ms = t.elapsed().as_secs_f64() * 1e3;
        s.verify_batch(tree_u.root(), &tree_u.claims(&batch), fresh.root_proof())?;

        eprintln!(
            "  update leaf {leaf} (in batch: {in_batch}): {update_ms:.0} ms over \
             {proofs_recomputed} proofs vs {full_reaggregate_ms:.0} ms full"
        );
        updates.push(UpdatePoint {
            batch_size: m,
            updated_leaf: leaf,
            leaf_in_batch: in_batch,
            proofs_recomputed,
            update_ms,
            full_reaggregate_ms,
            speedup: full_reaggregate_ms / update_ms,
        });
    }

    Ok(ConfigResult {
        q,
        height,
        num_leaves: n,
        setup_ms,
        lambda_size_proofs,
        circuit_sizes,
        aggregation,
        per_k,
        updates,
    })
}

fn main() -> Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let quick = args.iter().any(|a| a == "--quick");
    let out = args
        .iter()
        .position(|a| a == "--out")
        .and_then(|i| args.get(i + 1))
        .cloned()
        .unwrap_or_else(|| "results/bench.json".to_string());

    // q = 2 and q = 4 over the same 16 leaves: the arity comparison.
    let configs = if quick { vec![(2, 2), (4, 1)] } else { vec![(2, 4), (4, 2)] };

    let mut results = Vec::new();
    for (q, height) in configs {
        results.push(run_config(q, height, quick)?);
    }

    let report = Report { machine: machine(), configs: results };
    if let Some(parent) = std::path::Path::new(&out).parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&out, serde_json::to_string_pretty(&report)?)?;
    eprintln!("\nwrote {out}");
    Ok(())
}
