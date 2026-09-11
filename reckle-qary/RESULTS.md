# Measured results

Generated from `results/bench.json` by `scripts/render_results.py`. Every number below was
measured on the machine described here, nothing is extrapolated.

## Hardware and toolchain

| | |
| --- | --- |
| CPU | Intel64 Family 6 Model 165 Stepping 2, GenuineIntel |
| Logical cores | 12 |
| OS / arch | windows x86_64 |
| Plonky2 | 1.1.0 |
| Build profile | release (opt-level=3, lto=thin, codegen-units=1) |

The prover is sequential, nodes of `T'_I` are proved one after another. Plonky2's own internal parallelism (FFTs, Merkle trees) is enabled.

## `q = 2`, height = 4, 16 leaves

Setup (building 4 x 2 circuits) took 10,639 ms. Batch data structure at its largest: 15 stored proofs.

### Aggregation, verification, proof size

| \|I\| | nodes proved | aggregate (ms) | verify (ms) | proof (bytes) |
| ---: | ---: | ---: | ---: | ---: |
| 1 | 4 | 3,483 | 7.55 | 132,920 |
| 2 | 7 | 5,878 | 7.97 | 132,920 |
| 4 | 11 | 8,664 | 7.13 | 132,920 |
| 8 | 15 | 9,804 | 8.11 | 132,920 |
| 16 | 15 | 9,040 | 8.53 | 132,920 |

### Cost of `Q_k` as a function of `k` (root node)

| k | root prove (ms) |
| ---: | ---: |
| 1 | 1,095 |
| 2 | 1,143 |

Spread across `k` is 1.04x. See "What the numbers say", this flatness is our main negative result.


### Update vs full re-aggregation

| \|I\| | leaf | in batch | proofs recomputed | update (ms) | full (ms) | speedup |
| ---: | ---: | :---: | ---: | ---: | ---: | ---: |
| 8 | 0 | yes | 4 | 3,379 | 8,002 | 2.37x |
| 8 | 1 | no | 4 | 3,584 | 8,410 | 2.35x |

### Circuit sizes (gates, padded to a power of two)

| level | k=1 | k=2 |
| ---: | ---: | ---: |
| 1 | 16 | 16 |
| 2 | 8,192 | 8,192 |
| 3 | 8,192 | 8,192 |
| 4 | 8,192 | 8,192 |

All `k` at a level share one `CommonCircuitData`, so the degrees are equal by construction, which is exactly what lets a parent verify a child proof without knowing the child's `k`.

## `q = 4`, height = 2, 16 leaves

Setup (building 2 x 4 circuits) took 11,325 ms. Batch data structure at its largest: 5 stored proofs.

### Aggregation, verification, proof size

| \|I\| | nodes proved | aggregate (ms) | verify (ms) | proof (bytes) |
| ---: | ---: | ---: | ---: | ---: |
| 1 | 2 | 2,249 | 8.70 | 146,452 |
| 2 | 3 | 2,432 | 8.01 | 146,452 |
| 4 | 5 | 2,485 | 7.91 | 146,452 |
| 8 | 5 | 2,995 | 8.41 | 146,452 |
| 16 | 5 | 2,348 | 9.45 | 146,452 |

### Cost of `Q_k` as a function of `k` (root node)

| k | root prove (ms) |
| ---: | ---: |
| 1 | 2,154 |
| 2 | 2,131 |
| 3 | 2,234 |
| 4 | 2,245 |

Spread across `k` is 1.05x. See "What the numbers say", this flatness is our main negative result.


### Update vs full re-aggregation

| \|I\| | leaf | in batch | proofs recomputed | update (ms) | full (ms) | speedup |
| ---: | ---: | :---: | ---: | ---: | ---: | ---: |
| 8 | 0 | yes | 2 | 2,307 | 2,548 | 1.10x |
| 8 | 1 | no | 2 | 2,229 | 2,431 | 1.09x |

### Circuit sizes (gates, padded to a power of two)

| level | k=1 | k=2 | k=3 | k=4 |
| ---: | ---: | ---: | ---: | ---: |
| 1 | 32 | 32 | 32 | 32 |
| 2 | 16,384 | 16,384 | 16,384 | 16,384 |

All `k` at a level share one `CommonCircuitData`, so the degrees are equal by construction, which is exactly what lets a parent verify a child proof without knowing the child's `k`.

## What the numbers say

Arity, over 16 leaves. The baseline is `q = 2`, the paper's binary construction, at equal leaf count.

| config | levels | nodes proved (full batch) | aggregate (ms) | proof (bytes) |
| --- | ---: | ---: | ---: | ---: |
| `q=2`, h=4 | 4 | 15 | 9,040 | 132,920 |
| `q=4`, h=2 | 2 | 5 | 2,348 | 146,452 |

`q = 4` aggregates a full batch 3.85x faster than `q = 2`: a shallower tree means fewer nodes of `T'_I` to prove (15 -> 5). The proof grows from 132,920 to 146,452 bytes, because each node hashes `q` children instead of 2. This is the case for going `q`-ary, and it is the main positive result.

The `Q_k` family does not pay off in Plonky2, which is our negative result. The point of parameterising by `k` is that a node with few active children should avoid `q` recursive verifications. Measured, the cost is flat in `k`:

* `q = 2`: 1.04x spread across `k = 1..2`, and every top level circuit has degree 8,192.
* `q = 4`: 1.05x spread across `k = 1..4`, and every top level circuit has degree 16,384.

The reason is structural, not an artefact of our code. A parent must verify a child proof without knowing the child's `k`, so every `Q_k` at a level must share one `CommonCircuitData`, and that forces them all to the size of the largest, `k = q`. The specialisation that Figure 5 introduces is therefore cancelled by the uniformity that recursion in Plonky2 requires. The paper does not discuss this tension, and it only becomes visible once the circuit is actually built.

A way out, which we did not implement: give each `Q_k` its natural size and add a small fixed normaliser circuit that wraps any `Q_k` proof into one common shape. A node then costs `k + 1` recursions instead of a padded `q`. For `q = 16, k = 1` that is 2 rather than 16, so the saving should be real at Ethereum's arity even though it is invisible at `q = 4`.

Updates. Refreshing after one leaf change recomputes only the path to the root:

* `q = 2`, |I| = 8: 4 of 15 proofs recomputed, 2.37x faster than re-aggregating (leaf in the batch).
* `q = 2`, |I| = 8: 4 of 15 proofs recomputed, 2.35x faster than re-aggregating (leaf not in the batch).
* `q = 4`, |I| = 8: 2 of 5 proofs recomputed, 1.10x faster than re-aggregating (leaf in the batch).
* `q = 4`, |I| = 8: 2 of 5 proofs recomputed, 1.09x faster than re-aggregating (leaf not in the batch).

The speedup is bounded by `|T'_I| / height`, so at our 16 leaves it is small. The paper reports 10 to 15x at realistic sizes, and our numbers are consistent with that bound rather than a refutation of it. The tree is simply too shallow for the asymptotics to show.

## Threats to validity

* Trees have 16 leaves. This is set by setup cost (building `height x q` circuits, each twice, dominates) and by the sequential prover, not by any limitation of the construction.
* Aggregation and update timings are single runs, and only verification is a median of 25 repetitions. Expect several percent of noise, which is well below the effects reported above but not below the `k` spread, so we claim only that the `k` curve is flat.
* The machine is a laptop running other software, on Windows.
* Proof sizes are exact and deterministic, so they carry no error.

## Comparison with the paper

The paper reports a 112 KiB proof, independent of batch and vector size. We measure 132,920 B (130 KiB) at `q = 2` and 146,452 B (143 KiB) at `q = 4`, likewise constant in `|I|`. The same order, and the difference is expected: our circuits are not shrink-wrapped with a final compression step, and we pad every circuit at a level up to the largest. Prover timings are not comparable, since the paper benchmarks trees of height 21 on server hardware with a distributed prover.
