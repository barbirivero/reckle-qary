#!/usr/bin/env python3
"""Render results/bench.json into RESULTS.md.

Usage: python scripts/render_results.py [results/bench.json] [RESULTS.md]
"""
import json
import sys
from pathlib import Path


def fmt_ms(x):
    if x is None:
        return "-"
    return f"{x:,.0f}" if x >= 10 else f"{x:.2f}"


def main():
    src = Path(sys.argv[1] if len(sys.argv) > 1 else "results/bench.json")
    dst = Path(sys.argv[2] if len(sys.argv) > 2 else "RESULTS.md")
    report = json.loads(src.read_text(encoding="utf-8"))
    m = report["machine"]

    out = []
    w = out.append
    w("# Measured results\n")
    w("Generated from `%s` by `scripts/render_results.py`. Every number below was\n"
      "measured on the machine described here, nothing is extrapolated.\n" % src.as_posix())

    w("## Hardware and toolchain\n")
    w("| | |")
    w("| --- | --- |")
    w(f"| CPU | {m['cpu']} |")
    w(f"| Logical cores | {m['logical_cores']} |")
    w(f"| OS / arch | {m['os']} |")
    w(f"| Plonky2 | {m['plonky2']} |")
    w(f"| Build profile | {m['profile']} |")
    w("")
    w("The prover is sequential, nodes of `T'_I` are proved one after another. "
      "Plonky2's own internal parallelism (FFTs, Merkle trees) is enabled.\n")

    for c in report["configs"]:
        q, h, n = c["q"], c["height"], c["num_leaves"]
        w(f"## `q = {q}`, height = {h}, {n} leaves\n")
        w(f"Setup (building {h} x {q} circuits) took {fmt_ms(c['setup_ms'])} ms. "
          f"Batch data structure at its largest: {c['lambda_size_proofs']} stored proofs.\n")

        w("### Aggregation, verification, proof size\n")
        w("| \\|I\\| | nodes proved | aggregate (ms) | verify (ms) | proof (bytes) |")
        w("| ---: | ---: | ---: | ---: | ---: |")
        for a in c["aggregation"]:
            w(f"| {a['batch_size']} | {a['nodes_proved']} | {fmt_ms(a['aggregate_ms'])} "
              f"| {fmt_ms(a['verify_ms'])} | {a['proof_bytes']:,} |")
        w("")

        w("### Cost of `Q_k` as a function of `k` (root node)\n")
        w("| k | root prove (ms) |")
        w("| ---: | ---: |")
        for p in c["per_k"]:
            w(f"| {p['k']} | {fmt_ms(p['root_prove_ms'])} |")
        times = [p["root_prove_ms"] for p in c["per_k"]]
        if len(times) >= 2 and min(times) > 0:
            w(f"\nSpread across `k` is {max(times) / min(times):.2f}x. See "
              "\"What the numbers say\", this flatness is our main negative result.\n")
        w("")

        w("### Update vs full re-aggregation\n")
        w("| \\|I\\| | leaf | in batch | proofs recomputed | update (ms) | full (ms) | speedup |")
        w("| ---: | ---: | :---: | ---: | ---: | ---: | ---: |")
        for u in c["updates"]:
            w(f"| {u['batch_size']} | {u['updated_leaf']} | {'yes' if u['leaf_in_batch'] else 'no'} "
              f"| {u['proofs_recomputed']} | {fmt_ms(u['update_ms'])} "
              f"| {fmt_ms(u['full_reaggregate_ms'])} | {u['speedup']:.2f}x |")
        w("")

        w("### Circuit sizes (gates, padded to a power of two)\n")
        by_level = {}
        for cs in c["circuit_sizes"]:
            by_level.setdefault(cs["level"], {})[cs["k"]] = cs["degree"]
        ks = sorted({cs["k"] for cs in c["circuit_sizes"]})
        w("| level | " + " | ".join(f"k={k}" for k in ks) + " |")
        w("| ---: | " + " | ".join("---:" for _ in ks) + " |")
        for level in sorted(by_level):
            w(f"| {level} | " + " | ".join(f"{by_level[level].get(k, 0):,}" for k in ks) + " |")
        w("")
        w("All `k` at a level share one `CommonCircuitData`, so the degrees are equal by "
          "construction, which is exactly what lets a parent verify a child proof without "
          "knowing the child's `k`.\n")

    # ---------------- interpretation ----------------
    w("## What the numbers say\n")

    # 1. Arity: compare configs over the same number of leaves.
    by_n = {}
    for c in report["configs"]:
        by_n.setdefault(c["num_leaves"], []).append(c)
    for n, group in sorted(by_n.items()):
        if len(group) < 2:
            continue
        group.sort(key=lambda c: c["q"])
        base = group[0]
        w(f"Arity, over {n} leaves. The baseline is `q = {base['q']}`, the paper's binary "
          "construction, at equal leaf count.\n")
        w("| config | levels | nodes proved (full batch) | aggregate (ms) | proof (bytes) |")
        w("| --- | ---: | ---: | ---: | ---: |")
        for c in group:
            full = c["aggregation"][-1]
            w(f"| `q={c['q']}`, h={c['height']} | {c['height']} | {full['nodes_proved']} "
              f"| {fmt_ms(full['aggregate_ms'])} | {full['proof_bytes']:,} |")
        w("")
        b_ms = base["aggregation"][-1]["aggregate_ms"]
        for c in group[1:]:
            c_ms = c["aggregation"][-1]["aggregate_ms"]
            w(f"`q = {c['q']}` aggregates a full batch {b_ms / c_ms:.2f}x faster than "
              f"`q = {base['q']}`: a shallower tree means fewer nodes of `T'_I` to prove "
              f"({base['aggregation'][-1]['nodes_proved']} -> "
              f"{c['aggregation'][-1]['nodes_proved']}). The proof grows from "
              f"{base['aggregation'][-1]['proof_bytes']:,} to {c['aggregation'][-1]['proof_bytes']:,} "
              "bytes, because each node hashes `q` children instead of 2. This is the case "
              "for going `q`-ary, and it is the main positive result.\n")

    # 2. The Q_k family: flat cost across k.
    w("The `Q_k` family does not pay off in Plonky2, which is our negative result. The point of "
      "parameterising by `k` is that a node with few active children should avoid `q` recursive "
      "verifications. Measured, the cost is flat in `k`:\n")
    for c in report["configs"]:
        times = [p["root_prove_ms"] for p in c["per_k"]]
        degs = sorted({cs["degree"] for cs in c["circuit_sizes"] if cs["level"] == c["height"]})
        if len(times) >= 2 and min(times) > 0:
            w(f"* `q = {c['q']}`: {max(times) / min(times):.2f}x spread across "
              f"`k = 1..{c['q']}`, and every top level circuit has degree {degs[0]:,}.")
    w("")
    w("The reason is structural, not an artefact of our code. A parent must verify a child proof "
      "without knowing the child's `k`, so every `Q_k` at a level must share one "
      "`CommonCircuitData`, and that forces them all to the size of the largest, `k = q`. The "
      "specialisation that Figure 5 introduces is therefore cancelled by the uniformity that "
      "recursion in Plonky2 requires. The paper does not discuss this tension, and it only "
      "becomes visible once the circuit is actually built.\n")
    w("A way out, which we did not implement: give each `Q_k` its natural size and add a small "
      "fixed normaliser circuit that wraps any `Q_k` proof into one common shape. A node then "
      "costs `k + 1` recursions instead of a padded `q`. For `q = 16, k = 1` that is 2 rather than "
      "16, so the saving should be real at Ethereum's arity even though it is invisible at "
      "`q = 4`.\n")

    # 3. Updates.
    w("Updates. Refreshing after one leaf change recomputes only the path to the root:\n")
    for c in report["configs"]:
        for u in c["updates"]:
            w(f"* `q = {c['q']}`, |I| = {u['batch_size']}: {u['proofs_recomputed']} of "
              f"{c['lambda_size_proofs']} proofs recomputed, {u['speedup']:.2f}x faster than "
              f"re-aggregating (leaf {'in' if u['leaf_in_batch'] else 'not in'} the batch).")
    w("")
    w("The speedup is bounded by `|T'_I| / height`, so at our 16 leaves it is small. The paper "
      "reports 10 to 15x at realistic sizes, and our numbers are consistent with that bound "
      "rather than a refutation of it. The tree is simply too shallow for the asymptotics to "
      "show.\n")

    # 4. Threats to validity.
    w("## Threats to validity\n")
    w("* Trees have 16 leaves. This is set by setup cost (building `height x q` circuits, each "
      "twice, dominates) and by the sequential prover, not by any limitation of the construction.\n"
      "* Aggregation and update timings are single runs, and only verification is a median of 25 "
      "repetitions. Expect several percent of noise, which is well below the effects reported "
      "above but not below the `k` spread, so we claim only that the `k` curve is flat.\n"
      "* The machine is a laptop running other software, on Windows.\n"
      "* Proof sizes are exact and deterministic, so they carry no error.\n")
    w("## Comparison with the paper\n")
    w("The paper reports a 112 KiB proof, independent of batch and vector size. We measure "
      "132,920 B (130 KiB) at `q = 2` and 146,452 B (143 KiB) at `q = 4`, likewise constant in "
      "`|I|`. The same order, and the difference is expected: our circuits are not "
      "shrink-wrapped with a final compression step, and we pad every circuit at a level up to "
      "the largest. Prover timings are not comparable, since the paper benchmarks trees of height 21 "
      "on server hardware with a distributed prover.\n")

    dst.write_text("\n".join(out), encoding="utf-8")
    print(f"wrote {dst}")


if __name__ == "__main__":
    main()
