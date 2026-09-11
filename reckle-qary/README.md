# q-ary Reckle Trees, implementing circuit Q_k

[![CI](https://github.com/barbirivero/reckle-qary/actions/workflows/ci.yml/badge.svg)](https://github.com/barbirivero/reckle-qary/actions/workflows/ci.yml)

Final project for Building Cryptographic Proofs: Zero-Knowledge Proofs and SNARKs, 39th ECI, UBA.

Paper: Papamanthou, Srinivasan, Gailly, Hishon-Rezaizadeh, Salumets and Golemac, "Reckle Trees:
Updatable Merkle Batch Proofs with Applications", ACM CCS 2024
([ePrint 2024/493](https://eprint.iacr.org/2024/493)).

We implemented circuit Q_k from Figure 5 in Section 3.8. The paper defines it but never builds it.
In its own words, "We leave the implementation of circuits for q-ary trees as future work".

Three results. Going q-ary is worth it. The Q_k family is not, which surprised us. And Figure 5
has a gap that affects soundness.

## 1. The application

A Merkle batch proof for an arbitrary index set I costs O(|I| log n) hashes, so it is not succinct,
and algebraic vector commitments are succinct but not updatable. Reckle trees get both, by putting
a canonical hash of the batch inside a recursive Merkle verification. The batch proof is then one
recursive SNARK, refreshable in O(log n) per leaf change.

The proof is for succinctness and delegation, not privacy. A prover holding the tree convinces a
verifier with few resources, like a smart contract, that:

> d is the root canonical digest with respect to some set of leaves of some q-ary Merkle tree whose
> root Merkle digest is C.

The statement is (C, d, V), the Merkle root, the canonical digest, and a commitment to the keys
children may use. The witness is, per node, the Merkle hashes of its q children, the canonical
hashes of the active ones, and their recursive proofs. The verifier recomputes d from the claimed
leaves and checks the proof. Both halves are needed, because the proof alone says nothing about
which leaves are involved. The assumptions are collision resistance of Poseidon and knowledge
soundness of Plonky2, with no trusted setup. Nothing is hidden, so this is a succinct argument and
not a zero-knowledge one.

## 2. The proof system and framework

Plonky2, which is PLONK with a FRI commitment over Goldilocks, and also what the authors use in
[their repository](https://github.com/Lagrange-Labs/reckle-trees). Setup is transparent, recursion
is a first class feature, which is why the paper chose it, Poseidon is native inside circuits,
proofs are around 100 to 130 KiB and independent of n and |I|, and verification takes
milliseconds. The only assumption is collision resistant hashing. What we pay for that is proof
size, since a Groth16 proof is around 200 bytes but needs a trusted setup and recurses poorly.

## 3. What can be improved

Section 3.8 extends Reckle trees to q-ary trees, the case that models Ethereum, since Merkle
Patricia Tries use q=16. It gives Q_k and then stops. We found three gaps.

1. No implementation. Figure 5 is never built and never measured, and every number in Section 5 of
   the paper is binary.
2. Figure 5 is underspecified in two places that matter. Step (2) only asks that the active
   children are "a subset" of the children, which fixes no order and forbids no repetition, while
   Section 3.8 says the canonical hash is over the sorted list. If a prover can reorder or repeat
   children, the same leaves give a different d, so the canonical digest stops being canonical.
   Step (4) is written with no condition, and for k=1 it hashes a single digest instead of passing
   it through, breaking the collapsing rule of Section 3.1.
3. An obstacle the authors do mention. In Plonky2 the shape of a proof depends on the circuit that
   produced it, and Q_k must verify proofs coming from Q_j for any j.

## 4. Feasibility analysis

Implemented: the Q_k family for full q-ary trees specialised per level, the fix for point 3, the V
mechanism, updatable batch proofs, and tests and benchmarks.

Feasible but out of scope. Unbalanced MPTs, since our per level specialisation assumes a full tree
and real tries need the general V of the paper. q=16 at Ethereum depth, which needs machine hours
but no new ideas. Parallel proving, since the paper's O(log n) parallel time needs one thread per
node of T'_I and ours is sequential. Reckle+ Map/Reduce.

Our fix for result 2, not implemented. Let every Q_k keep its natural size and add one small fixed
normaliser circuit that wraps any Q_k proof into a common shape. A node then costs k+1 recursions
instead of a padded q, so for q=16 and k=1 that is 2 instead of 16. The saving should be real at
Ethereum arity even if it is invisible at q=4. It is a day of work and not a research problem, but
more than we could measure in time, and we did not want to claim a speedup we never ran.

Open research: updatable SNARKs in general, which the paper poses and does not solve.

## 5. Our implementation

Plonky2 1.1.0 in Rust, because it is what the paper uses, so the numbers are comparable, and
because recursion and Poseidon come for free.

One circuit per (level, k), with k from 1 to q. Specialising per level as well as per k is the
q-ary version of the optimisation in Figure 4, the route the paper suggests for trees of fixed
shape, and it makes level 1 a real base case with no recursion.

The uniform shape fix. All q circuits of a level are forced to identical CommonCircuitData by
taking the union of their gate sets, registering the missing gate types into each one, and padding
with NoopGate to a common gate count. Both steps are needed, because circuits for different k
differ not only in size but in which gates they use.

We deviate from Figure 5 in seven places, all on purpose, and two of them matter. For k=1 we pass
the child digest through instead of hashing it, which keeps q=2 exactly as Section 3.1, and we
require the active child positions to be strictly increasing, which is the gap from Section 3.
[DESIGN.md](DESIGN.md) has the full table, and a note on why our V public input ends up a
redundant binding rather than the committed set the paper describes.

Testing. 32 tests, all in CI. 7 pin the canonical hashing spec, 5 check completeness over every k
from 1 to 4, 14 check soundness and 4 check updatability. The soundness tests split between lying
to the verifier about what an honest proof says and feeding the prover witnesses no honest party
would build. One passes only if no verifying proof comes out, so a panic, a prover error and a
failed verification all count. [DESIGN.md](DESIGN.md) lists them one by one.

## 6. Performance

i7-10750H, 12 logical cores, Windows, release with lto=thin, 16 leaves. Raw JSON in
[results/bench.json](results/bench.json), and tables and threats to validity in
[RESULTS.md](RESULTS.md).

| | q=2, h=4 | q=4, h=2 |
| --- | ---: | ---: |
| Setup | 10.6 s | 11.3 s |
| Aggregate, full batch (15 and 5 nodes) | 9,040 ms | 2,348 ms |
| Verify (median of 25) | 8.5 ms | 9.5 ms |
| Proof size, any \|I\| | 132,920 B | 146,452 B |
| Update after one leaf change | 3,379 ms (2.37x) | 2,307 ms (1.10x) |
| Root prove time, k=1 to k=q | 1,095 to 1,143 ms | 2,154 to 2,245 ms |

Three baselines. Arity, where q=2 is the paper's own construction over the same leaves. The Q_k
family, as root proving time against k. And full re-aggregation, to compare against updates.

The Q_k row is our negative result. Cost is flat in k and every top level circuit has the same
degree. This is structural and not a bug in our code. All the Q_k of a level share one
CommonCircuitData, so padding takes them up to the size of k=q, and the specialisation of Figure 5
gets cancelled by the uniformity recursion needs.

Against the paper, we get 130 to 143 KiB where it reports 112 KiB, so the same order. Proving times
are not comparable, since the paper uses height 21 and a distributed prover on server hardware.

Being honest, aggregation and update are single runs and only verification is a median of 25. The
noise is under the 3.85x arity effect but not under the 1.05x spread across k, so there we only
claim the curve is flat, never that some k is faster. RESULTS.md has the rest of the caveats.

## Build and run

```powershell
. .\env.ps1            # Windows only, drops an old C:\MinGW from PATH and moves target/
cargo test --release   # 32 tests
cargo run --release --bin bench -- --out results/bench.json
python scripts/render_results.py results/bench.json RESULTS.md
```

rust-toolchain.toml pins the nightly that plonky2_field needs. On Linux and macOS you do not need
env.ps1.

Attribution. We use plonky2 (Polygon Zero, MIT and Apache-2.0) as a library. The construction is by
Papamanthou et al. The code here is ours, written from the paper.

## Who did what

We each read the paper on our own first. Then we met to discuss it and to agree on what
the extension should be and why. From there the work split roughly in two, although we
reviewed each other's parts and took the main design decisions together.

- Ignacio Esteban Losiggio and Barbara Monica Rivero worked mostly on the code and the
  tests, that is the q-ary tree and canonical hashing, the Q_k circuits, the recursive
  prover and verifier, and the completeness, soundness and updatability test suites.
- Josefina Negrotto and Maria del Pilar Larriera Ibarra worked mostly on the analysis of the paper, the feasibility study, the benchmarks and the scripts that produce the tables, and the writing of this README.
