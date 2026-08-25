# Staged verification

Contingency design for proofs that do not fit one transaction. It is documented,
and it is deliberately unimplemented: the measured numbers in
[GAS-REPORT.md](GAS-REPORT.md) and the recommendation in
[L2-ARCHITECTURE.md](L2-ARCHITECTURE.md) make recursion the preferred way to
keep every on-chain proof inside a single transaction.

## When it would be needed

Two limits apply to a single `verify` transaction on QRL 2.0:

1. The transaction pool refuses transactions above 131,072 bytes
   (`txMaxSize = 4 * txSlotSize` in the go-qrl legacy pool, without a CLI flag).
   With 7,690 bytes of envelope and ABI overhead, the largest proof that fits
   is 123,382 bytes. In the report, c3 at 2^20 (105,873 bytes) fits; c2 at
   2^20, c1 at 2^16 and every binary preset at 2^16 or larger do not.
2. The consensus block gas cap of 20,000,000 and the project target of 8M for
   one verification. Four of the 44 measured cells exceed 8M; none exceeds the
   cap (worst: c1-binary at 2^20, 17.07M).

Staging removes both limits at the cost of several transactions per proof,
each paying its own base cost and each replaying the transcript prefix.

## Stages

Every stage receives the transcript prefix (`proof[0..pEnd]`, at most a few
kilobytes) plus one block of query data, and derives the challenges by
replaying the prefix through the challenger. The prefix hash `proofId`
binds every stage to the same commitments, opened values and final polynomial.
Layout v1 already makes every block addressable from the header and the
`sib_count` fields, so a stage never scans other blocks.

| Stage                    | Input                                             | Work                                                                                            | Stored fact                                                     |
| ------------------------ | ------------------------------------------------- | ----------------------------------------------------------------------------------------------- | --------------------------------------------------------------- |
| A: `registerMerkleBlock` | prefix, one input batch or one FRI round block    | replay prefix, sample the query indices, verify the pruned Merkle block, hash the opened leaves | `fact(proofId, "MERKLE", block, keccak256(unique idx, leaves))` |
| B: `registerFoldRange`   | prefix, rows and sibling values for a query range | replay prefix, reduced openings and fold chains for the range, final polynomial check per query | `fact(proofId, "FRI", range, keccak256(per-round idx, leaves))` |
| C: `finalize`            | prefix, public values                             | replay prefix, constraint check, require every MERKLE fact and every FRI range fact             | `verified[proofId, keccak256(publicValues)] = true`             |

Stage B facts must match the leaf digests that stage A verified: stage C
recomputes the expected fact keys from the stage B leaves and requires them in
the stage A set, which ties the folded values to the committed rows.

## Cost shape

From the phase table of `fib_c3_n12` (VERIFIER.md section 5): the prefix
replay costs about 30k gas per stage, one input block about 130k, one FRI
round block 20k to 60k, and one query's fold chain about 3k per round. For
c1-binary at 2^20 the split is roughly 2 input blocks, 17 round blocks and
100 queries: about 22 transactions of at most 1M gas each; the unstaged
alternative is one 17M transaction that the pool refuses anyway.

## Why recursion wins

A recursion layer that aggregates k batch proofs into one c3-sized proof pays
the on-chain verifier once per k batches, keeps the transaction under the
pool cap, needs no fact-registry state machine and no multi-transaction
liveness handling, and reuses the verifier as it is. Staging stays available
for the case where a single non-recursive proof must be verified on chain,
for example during a recursion outage.

## Caveat carried over from PROTOCOL.md

With `commit_proof_of_work_bits = 0` the per-round witness bytes are never
observed, so several prefixes with the same transcript exist and `proofId`
is malleable. Staging tolerates this (all stages of one submission share one
prefix), and the fact registry keys facts by public values. `proofId` never
keys a fact.
