# The on-chain verifier (milestones M5 and M6)

How `contracts/hyperion/StarkVerifier.hyp` verifies a Plonky3 uni-stark proof of
the Fibonacci AIR on the 64-byte QRVM, what it costs, and how the numbers were
measured. `docs/PROTOCOL.md` is normative for what is computed; this document
covers how the Hyperion code computes it. Executable specification:
`test/lib/verifier.js` (whole flow), `test/lib/fri.js`, `test/lib/fibonacciAir.js`,
`test/lib/layout.js`; Rust mirror: `prover/stark-prover/src/mirror.rs`.

## 1. Architecture

| Unit                                      | Kind                | Role                                                                                                                                                                                                                                                                  |
| ----------------------------------------- | ------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `lib/ProofLayout.hyp`                     | library             | Header decode, exact-length rule, absolute calldata offsets of every block, the canonical scan of every field element region, `proofId`.                                                                                                                              |
| `air/FibonacciAir.hyp`                    | library             | Trace-domain selectors at `zeta` (one batch inversion), the five constraints in emission order, the `alpha` accumulator, the quotient recomposition, `OodPointInDomain` and `OodMismatch`.                                                                            |
| `lib/FriVerifier.hyp`                     | library             | The PCS side over one memory context: FRI transcript, input batches, reduced openings, fold chains with the final polynomial check, per-round Merkle checks. Reuses `Goldilocks`, `Fp2`, `KeccakChallenger` and `MerkleMultiProof` unchanged.                         |
| `StarkVerifier.hyp` (`StarkVerifierCore`) | abstract contract   | The flow of PROTOCOL.md section 12 parameterised by `ProofLayout.Params` at run time: decode and scan, instance transcript (steps 1 to 10), constraint check, `FriVerifier.verifyFri`.                                                                                |
| `StarkVerifier.hyp` (`StarkVerifier`)     | deployable contract | Binds one preset through six compile-time constants (`LOG_BLOWUP`, `LOG_FINAL_POLY_LEN`, `MAX_LOG_ARITY`, `NUM_QUERIES`, `COMMIT_POW_BITS`, `QUERY_POW_BITS`; committed values = preset c3), exposes `PARAMS()` and `verify(bytes,bytes)`. One deployment per preset. |
| `test/FriHarness.hyp`                     | test contract       | Inherits `StarkVerifierCore`; exposes the layout, `proofId`, the canonical scan, the chain-derived challenges, every reduced opening, `foldRow`, every fold chain step with its leaf digest and gas, `verifyFri` and the whole flow timed per phase.                  |

Presets are selected at compile time because every parameter is a loop bound or
a transcript constant; the test suite (`test/contracts/stark.test.js`) compiles
`StarkVerifier.hyp` once per distinct vector `config` with the six constant
declarations substituted by a regular expression, so the committed file stays
the c3 deployment and no per-preset source files exist. The core and the
libraries read the parameters from a memory struct, which costs a few `mload`
per phase and nothing per query.

The data flow of one `verify(proof, publicValues)` call:

1. `ProofLayout.parse`: version, `degree_bits`, `num_rounds`, `log_arity[]`,
   header rules, prefix offsets, then the `sib_count` fields of the trace
   batch, the quotient batch and every round (each read is bounds-checked
   first), and the exact-length rule. Absolute calldata offsets are stored so
   nothing adds the proof base later.
2. `ProofLayout.checkCanonical`: one pass over the opened values, the
   proof-of-work witnesses, the final polynomial, both row blocks and every
   round's sibling values. The scan works on the little-endian wire form
   without a byte swap (section 3).
3. Public values: `length == 24`, three canonical elements.
4. `FriVerifier.init`: one bump allocation for every array of the context,
   the two-adic generator tables, the fold factor table, the windowed
   product tables and the coset factor table (section 2), then
   `decodePrefix` turns the opened values and the final polynomial into
   numbers.
5. `_absorbInstance`: transcript steps 1 to 10 through `KeccakChallenger`
   (roots, public values and opened values are observed straight from
   calldata with `observeCalldata`; their wire form is the observed form),
   `FibonacciAir.selectors` right after `zeta` (`OodPointInDomain`),
   `zeta_next = zeta * g_n`.
6. `_checkConstraints`: `acc * invVan == quotient` (`OodMismatch`).
7. `FriVerifier.verifyFri`: `friTranscript` (fri_alpha, commits with their
   PoW checks, betas, final polynomial, arities, query PoW, `Q` indices),
   `inputBlocks` (one `sortKeys`, then trace and quotient batch),
   `reducedOpenings` (all query points, all `2Q` denominators, one batch
   inversion, all `ro[q]`), `foldChains` (query by query: every round then
   the final polynomial check), `roundBlocks` (round by round).

Every failure is a custom error; `verify` returns `true` only when every step
passed. The interface's `false` return is never used: a well-formed proof that
fails a check reverts, which is what the fact registry and the gas meter expect
(`StarkVerifierGasMeter` logs the revert data).

## 2. Memory layout

`FriVerifier.Ctx` is one memory struct of 28 words (64 bytes each, declaration
order; the Yul code addresses fields through the `C_*` constants). The first
three fields are pointers to the parsed `ProofLayout.Layout`, the
`ProofLayout.Params` and the `KeccakChallenger.State`; then the challenges
(`alpha`, `zeta`, `zeta_next`, `fri_alpha` as `c0, c1` words); then pointers to
the arrays below, all allocated by `init` in one bump of the free memory
pointer (sizes in 64-byte words; `Q` queries, `R` rounds, `H = n + log_blowup`,
`A = 2^max_log_arity`, `L = 2^log_final_poly_len`):

| Array           | Words                   | Content                                                                                                                             |
| --------------- | ----------------------- | ----------------------------------------------------------------------------------------------------------------------------------- |
| `betas`         | `2R`                    | `beta[r]` as `c0, c1`                                                                                                               |
| `indices`       | `Q`                     | query indices at height `H`                                                                                                         |
| `keys`          | `Q`                     | `MerkleMultiProof.sortKeys` output, sorted once, shared by every block (right shifts keep the order)                                |
| `tab`, `tabInv` | `32` each               | `tab[i] = g_{i+1}`, `tabInv[i] = g_{i+1}^-1` from `Goldilocks.loadTwoAdicTables`                                                    |
| `wTab`          | `A`                     | `INV2 * g_m^-rev(j, m-1)` at `2^(m-1) - 1 + j` for `1 <= m <= max_log_arity`: the per-pair fold factor up to the coset start        |
| `opened`        | `12`                    | `trace_local`, `trace_next`, `quotient_chunk` as numbers (`c0, c1` each)                                                            |
| `finalPoly`     | `2L`                    | coefficients, constant term first                                                                                                   |
| `ro`            | `2Q`                    | reduced openings                                                                                                                    |
| `leaves`        | `RQ`                    | round leaf digests, round-major (`leaves[rQ + q]`)                                                                                  |
| `rowBuf`        | `(16A + 127) / 64`      | one row in wire form (the `mstore` of the query's own value spills up to 48 bytes past the row)                                     |
| `vals`          | `2A + 8`                | one row as numbers; the word-wise decode writes whole words of eight lanes                                                          |
| `scratch`       | `Q`                     | per-query leaf digests of the input batches, later the query points `x_q`                                                           |
| `kp`            | `17`                    | the three lane masks (`0x00FF..`, `0x0000FFFF..`, `0x00000000FFFFFFFF..`) and the opening constants `a, a^4, a^5, a^2, a^3, K0, K1` |
| `qs`            | `8`                     | fold-chain state: index, value (`c0, c1`), height, `k`, `sInv`, the domain point `P` and `P^-1`                                     |
| `pw`, `sw`      | `16 * ceil(H / 4)` each | window tables: `pw[16w + v] = prod tab[4w + b]` over the bits `b` of the nibble `v` (`sw` over `tabInv`)                            |
| `gk`            | `2A`                    | `g_k^rev(pos, k)` at `2^k - 2 + pos` for `1 <= k <= max_log_arity`                                                                  |

The challenger buffer (8 KB plus slack) is allocated by `KeccakChallenger.init`.
`MerkleMultiProof.gather` allocates `2Q` words per block and `verifyPruned`
uses `2(m + 1)` words above the free memory pointer; both blocks and every
round restore the free memory pointer afterwards, so the high-water mark is
flat across blocks. The denominators of `reducedOpenings` (`4Q` words plus the
`4Q` words `Fp2.batchInverse` takes) are released the same way. Peak memory for
`fib_c1-binary_n12` (`Q = 100`, `R = 9`) is about 190 KB, roughly 25k gas of
expansion.

Domain points. Plonky3 evaluates the LDE at `7 * g_H^rev(idx, H)` and folds
over cosets whose start is `g_{h+k}^rev(idx >> k, h)`. Every such point is a
product over the set bits of an index of `g_{i+1}` (bit `i` of the index
contributes `g_{i+1}`), so the bit reversal folds into the table order. The
verifier takes these products four bits at a time from `pw`/`sw` (one `mulmod`
per four-bit window; a bit-by-bit product would cost one per bit). A fold
chain carries its current domain point `P_r = g_{h_r}^rev(idx_r, h_r)` and its
inverse: `x_0 = 7 P_0`, the coset
start of a round is `s = P_r * g_k^-rev(pos, k)` (so `sInv = P_r^-1 * gk[k][pos]`),
`P_{r+1} = P_r^(2^k)` (the `k` squarings the fold performs anyway) and the final
evaluation point `g_H^rev(idx_R, H)` is `P_R` itself. One window product per
query (`P_0^-1`) replaces one product per round plus one per query.

Rows. A round row is assembled in `rowBuf` in wire form: the query's own value
is `bswap64`-encoded into its 16-byte slot, the `arity - 1` sibling values are
copied around it with two `calldatacopy`, the leaf is `keccak256(rowBuf, 16 *
arity)`, and the numeric row is decoded word by word (the three-stage lane byte
swap of `Goldilocks.cdLanes` on memory, eight stores per word). The fold is the
binary decomposition of PROTOCOL.md section 8.3: per step `m`, pair `j` is
`(lo, hi)` at `(y, -y)` with `1 / (2y) = sInv * wTab[m][j]`, folding to
`(lo + hi) / 2 + b (lo - hi) / (2y)`; both result components are sums of three
products below `2^133` reduced with one `mod`; then `sInv` and `b` square.

Reduced openings. With `a = fri_alpha`, the six terms of PROTOCOL.md section 7
regroup by denominator into `ro = inv0 (K0 - B0) + inv1 (K1 - B1)` with the
query-independent `K0 = tl0 + a tl1 + a^4 qc0 + a^5 qc1`, `K1 = a^2 tn0 + a^3 tn1`
(computed once) and the per-query `B0 = r0 + a r1 + a^4 s0 + a^5 s1`,
`B1 = a^2 r0 + a^3 r1` over the base-field rows (lazy base-times-extension
products). The `2Q` denominators `zeta - x_q`, `zeta_next - x_q` go through one
`Fp2.batchInverse`.

## 3. Decoding and the canonical scan

`ProofLayout.parse` follows `layout.js::parseLayout` with the same precedence:
`BadLength` (empty), `BadVersion`, `BadLength` (fewer than `3 + R` bytes),
`BadHeader` (`n == 0`, `n + lb > 32`, `n < lf`, a zero or oversized arity,
`sum(log_arity) != n - lf`), then `BadLength` for every `sib_count` field that
would sit past the end and for a total that differs from `proof.length`.
Because `calldataload` past the end zero-pads, no element is read before the
length rule holds.

`checkCanonical` then rejects any field element `>= p`. It works on the raw
little-endian lanes: a lane is non-canonical exactly when its numeric high 32
bits are all ones (the low half of the lane as loaded) and its numeric low 32
bits are nonzero (the high half). Both tests run on the eight lanes of a word
at once through carries into bit 32 of every lane, and a partial trailing word
keeps only the flags of its valid lanes. About 50 gas per 64 bytes; 34k gas for
`fib_c3_n12`, 71k for `fib_c1_n12`.

## 4. Check order and errors

The order of PROTOCOL.md section 12 is the order of the code:

| Step | Where                                                | Errors, in the order they can fire                                                                         |
| ---- | ---------------------------------------------------- | ---------------------------------------------------------------------------------------------------------- |
| 1    | `ProofLayout.parse`, `checkCanonical`, public values | `BadVersion`, `BadHeader`, `BadLength`, `NonCanonicalElement`                                              |
| 2    | `_absorbInstance`                                    | `OodPointInDomain` (after `zeta`, before the opened values are observed)                                   |
| 3    | `_checkConstraints`                                  | `OodMismatch`                                                                                              |
| 4    | `FriVerifier.friTranscript`                          | `PowFailed` (commit rounds in order, then the query proof of work)                                         |
| 5    | `FriVerifier.inputBlocks`                            | per batch (trace, then quotient): `DuplicateOpeningMismatch`, `SiblingCountMismatch`, `MerkleRootMismatch` |
| 6    | `FriVerifier.reducedOpenings`                        | `ZeroDenominator`                                                                                          |
| 7    | `FriVerifier.foldChains`                             | `FinalPolyMismatch` (first failing query)                                                                  |
| 8    | `FriVerifier.roundBlocks`                            | per round: `DuplicateOpeningMismatch`, `SiblingCountMismatch`, `MerkleRootMismatch`                        |

Selectors are computed from the error name alone, so `ProofLayout.NonCanonicalElement`
and `Goldilocks.NonCanonicalElement` are the same selector, as are the three
Merkle errors raised by `MerkleMultiProof`.

Where the Hyperion order differs from `test/lib/verifier.js` internally (no
accept/reject decision and no raised error changes):

- The JS decodes every element in wire order with a canonical check per
  element and then decodes the public values; the contract scans all element
  regions in one pass after the layout, then the public values. Same error,
  same precedence.
- The JS computes the selectors inside `evaluateConstraints` after the opened
  values are observed and checks `zeta^(2^n) == 1` separately right after
  `zeta`; the contract computes the selectors (including that check) right
  after `zeta`. The transcript is untouched either way.
- The JS calls `checkWitness` for every commit round; the contract skips the
  witness read when the bits are zero (`checkWitness(0, w)` never touches the
  transcript).
- The JS computes, checks and inverts the denominators query by query; the
  contract computes all query points, all denominators (checking each for
  zero) and inverts them in one batch. `ZeroDenominator` carries no query
  number, so the first-failing-query difference is invisible.
- The contract compares duplicate openings as leaf digests
  (`MerkleMultiProof.gather`) and the JS compares row bytes; the two are
  equivalent up to keccak collision resistance.

## 5. Gas

Measured on the gqrl developer node (chain 1337, 20,000,000 gas limit) with
hypc `0.2.0-develop.2026.8.25+commit.cf176678` from the `hyperion-stark`
worktree, `test/contracts/stark.test.js` (whole transactions through
`StarkVerifierGasMeter`) and `test/contracts/fri.test.js` (phases through
`FriHarness.verifyTimed`, `gasleft()` deltas). Regenerate with

```bash
STARK_RPC_URL=http://127.0.0.1:8545 HYPERION_COMPILER=../hyperion-stark/build/hypc/hypc \
  node --test test/contracts/fri.test.js test/contracts/stark.test.js
HYPERION_OPTIMIZE_RUNS=1000000 STARK_SKIP_MUTATIONS=1 ... node --test test/contracts/stark.test.js
HYPERION_VIA_IR=1 STARK_SKIP_MUTATIONS=1 ... node --test test/contracts/stark.test.js
```

The rows land in `build/hyperion/gas-stark-<setting>.json` and in the TAP
diagnostics.

### 5.1 Whole transactions

Columns: proof bytes; the calldata gas of the `verifyAndLog` transaction
(16 per nonzero byte, 4 per zero byte, ABI framing included); then per
optimizer setting `qrl_estimateGas` of a direct `verify` call / receipt
`gasUsed` of the `verifyAndLog` transaction / the inner STATICCALL gas from the
`Verified` event. Presets: c1 `(lb 1, Q 100)`, c2 `(lb 2, Q 50)`, c3 `(lb 3, Q 34)`,
all with query PoW 16 bits; the sweep cells are c3 with `max_log_arity = a` and
`log_final_poly_len = f`.

| Vector            | Proof bytes | Calldata gas | runs 200: estimate / gasUsed / inner | runs 1000000: estimate / gasUsed / inner | via-IR (runs 200): estimate / gasUsed / inner |
| ----------------- | ----------: | -----------: | -----------------------------------: | ---------------------------------------: | --------------------------------------------: |
| fib_c1_n10        |      54,672 |      873,612 |    3,750,528 / 3,884,092 / 2,926,926 |        3,646,469 / 3,779,929 / 2,822,855 |             3,673,981 / 3,746,182 / 2,782,242 |
| fib_c1_n12        |      82,672 |    1,320,236 |    4,795,125 / 4,936,222 / 3,561,025 |        4,660,428 / 4,801,421 / 3,426,316 |             4,696,692 / 4,747,144 / 3,358,335 |
| fib_c2_n10        |      36,432 |      582,336 |    2,173,128 / 2,279,256 / 1,618,446 |        2,108,482 / 2,214,506 / 1,553,788 |             2,132,402 / 2,196,265 / 1,531,934 |
| fib_c2_n12        |      53,936 |      861,432 |    2,782,275 / 2,877,658 / 1,969,892 |        2,698,558 / 2,793,837 / 1,886,163 |             2,731,692 / 2,766,516 / 1,852,132 |
| fib_c3_n10        |      32,848 |      525,256 |    1,742,388 / 1,843,274 / 1,240,505 |        1,689,051 / 1,789,833 / 1,187,156 |             1,714,123 / 1,776,496 / 1,170,734 |
| fib_c3_n12        |      43,440 |      694,372 |    2,104,922 / 2,184,393 / 1,447,427 |        2,041,137 / 2,120,504 / 1,382,845 |             2,070,463 / 2,100,365 / 1,357,961 |
| fib_c1-binary_n12 |      95,634 |    1,526,068 |    6,185,471 / 6,385,270 / 4,763,083 |        5,955,387 / 6,155,082 / 4,532,987 |             6,123,256 / 6,218,807 / 4,579,071 |
| fib_c2-binary_n12 |      75,090 |    1,198,408 |    3,884,157 / 4,049,935 / 2,761,910 |        3,735,761 / 3,901,435 / 2,613,502 |             3,853,139 / 3,936,179 / 2,636,608 |
| fib_c3-binary_n12 |      69,810 |    1,114,196 |    3,167,190 / 3,324,433 / 2,122,236 |        3,041,582 / 3,198,721 / 1,996,616 |             3,146,579 / 3,226,645 / 2,014,259 |
| fib_c3-a1-f0_n12  |      72,227 |    1,152,520 |    3,521,363 / 3,682,500 / 2,441,242 |        3,384,759 / 3,545,792 / 2,304,626 |             3,486,870 / 3,568,284 / 2,316,227 |
| fib_c3-a1-f5_n12  |      61,628 |      983,988 |    2,852,112 / 2,996,404 / 1,926,854 |        2,743,932 / 2,888,120 / 1,818,662 |             2,852,341 / 2,928,033 / 1,850,227 |
| fib_c3-a2-f0_n12  |      49,217 |      786,260 |    2,436,567 / 2,561,815 / 1,693,549 |        2,357,972 / 2,483,116 / 1,614,942 |             2,402,530 / 2,472,111 / 1,598,141 |
| fib_c3-a2-f3_n12  |      47,494 |      758,600 |    2,266,537 / 2,389,168 / 1,549,048 |        2,192,308 / 2,314,835 / 1,474,807 |             2,245,669 / 2,314,442 / 1,468,940 |
| fib_c3-a2-f5_n12  |      43,803 |      700,096 |    2,151,968 / 2,269,014 / 1,488,432 |        2,080,896 / 2,197,838 / 1,417,348 |             2,150,397 / 2,217,471 / 1,432,171 |
| fib_c3-a3-f0_n12  |      48,043 |      767,620 |    2,385,615 / 2,509,020 / 1,659,736 |        2,312,086 / 2,435,387 / 1,586,195 |             2,334,016 / 2,403,027 / 1,548,267 |
| fib_c3-a3-f5_n12  |      41,904 |      669,556 |    2,097,432 / 2,211,610 / 1,462,098 |        2,032,744 / 2,146,818 / 1,397,398 |             2,087,098 / 2,153,315 / 1,399,411 |
| fib_c3-a4-f0_n12  |      53,376 |      852,612 |    2,681,540 / 2,813,039 / 1,877,258 |        2,605,044 / 2,736,439 / 1,800,750 |             2,601,607 / 2,673,150 / 1,730,867 |
| fib_c3-a4-f3_n12  |      45,776 |      731,372 |    2,314,534 / 2,434,558 / 1,622,149 |        2,245,041 / 2,364,961 / 1,552,644 |             2,260,986 / 2,328,962 / 1,511,484 |
| fib_c3-a4-f5_n12  |      43,077 |      688,664 |    2,142,970 / 2,258,963 / 1,490,008 |        2,079,619 / 2,195,508 / 1,426,645 |             2,121,329 / 2,188,087 / 1,414,535 |

Every cell is far below the 20,000,000 block cap and below the 8,000,000
target; the largest, `fib_c1-binary_n12`, uses 6.39M at runs 200. The staged
verification contingency (`docs/STAGED-VERIFICATION.md`) stays unimplemented.
`gasUsed - inner` is the transaction base cost, the calldata and the meter's
own encoding; `inner - phases` (about 57k for `fib_c3_n12`) is the STATICCALL,
its calldata copy and the ABI decoding of the callee. Calldata is 24 to 32
percent of a transaction and is fixed by the proof layout; the plan's `16 * S`
estimate is exact up to the zero bytes (`sib_count` fields, small witnesses).

The optimizer setting moves the total by 2 to 6 percent: runs 1000000 keeps
the wide lane masks and packed tables as `PUSH` where runs 200 fetches them
with `CODECOPY` (`docs/GAS-PRIMITIVES.md`), the IR pipeline schedules the Yul
better. The
default build stays at runs 200 (the settings knob is `HYPERION_OPTIMIZE_RUNS`
/ `HYPERION_VIA_IR` in `scripts/compile-hyperion.js`, `scripts/hypc.js` and
`test/lib/harness.js`); a deployment can pick either of the cheaper settings,
both fit the code-size cap (section 6).

### 5.2 Phases of `fib_c3_n12`

`FriHarness.verifyTimed` (`gasleft()` deltas around each phase of the real flow;
the sum is the verifier's execution without the external-call framing):

| Phase                                               |  runs 200 | runs 1000000 | via-IR (runs 200) | Share (runs 200) |
| --------------------------------------------------- | --------: | -----------: | ----------------: | ---------------: |
| prepare (parse, scan, tables, prefix decode)        |    87,821 |       86,515 |           103,116 |            6.3 % |
| absorbInstance (transcript 1 to 10, selectors)      |     8,235 |        7,951 |             8,035 |            0.6 % |
| checkConstraints                                    |     4,194 |        4,182 |             3,377 |            0.3 % |
| friTranscript (betas, final poly, PoW, 34 indices)  |    18,765 |       18,189 |            17,656 |            1.4 % |
| inputBlocks (sort, 68 leaf hashes, two walks)       |   263,593 |      239,766 |           271,723 |           19.0 % |
| reducedOpenings (34 points, 68 inversions, 34 ro)   |   113,497 |      111,841 |           107,416 |            8.2 % |
| foldChains (102 rounds of arity 8, 34 final checks) |   726,197 |      705,445 |           671,657 |           52.3 % |
| roundBlocks (three walks)                           |   166,809 |      151,377 |           171,739 |           12.0 % |
| Sum                                                 | 1,389,111 |    1,325,266 |         1,354,719 |            100 % |
| Calldata (transaction)                              |   694,372 |      694,372 |           694,372 |                  |

Per (query, round) cost of `foldRound` (row assembly, leaf hash, decode, fold,
state update) and of the final polynomial check, runs 200, averaged over every
vector (`fri.test.js` diagnostics):

| log arity | Pairs folded | Gas per round | Gas per pair (marginal) |
| --------- | -----------: | ------------: | ----------------------: |
| 1         |            1 |         2,766 |                         |
| 2         |            3 |         3,913 |                     574 |
| 3         |            7 |         6,324 |                     603 |
| 4         |           15 |        10,784 |                     558 |

The fixed cost per round (about 2,200 gas) is the row assembly and keccak
(about 700), the word-wise decode (about 550 per 64-byte word), the
`foldRow` call with its per-step squarings and the chain-state update. A final
check costs 368 (`L = 1`) to 4,894 (`L = 32`) gas, 1,867 on average: Horner over
`L` coefficients at about 130 gas each plus the comparison. Per pair, about 25
Yul operations run (three `mulmod`, seven `mul`, two `mod`, the adds, four
loads, two stores); on the QRVM every operation costs its opcode plus the
`DUP`/`PUSH` traffic around it, so 25 operations land near 550 gas.

The phase shares change with the preset: for the binary sweeps (`a1`) the
Merkle walks of nine to twelve rounds are 30 to 40 percent of the execution and
the folds 45 percent; for `c1` (`Q = 100`) the input blocks and the reduced
openings grow linearly with `Q` while `sortKeys` grows a little faster (88k at
`Q = 100`, 28k at `Q = 34`).

### 5.3 Cost decisions

- Coset start inverse: the table product (`P_0^-1` once per query, then
  `sInv = P^-1 * gk[k][pos]` per round) replaced one modexp inversion (about
  440 gas) or one bit-loop product (about 1,300 gas at `H = 15`) per round.
- Query and final points come from the same window tables; the final point is
  the chain's own domain point.
- Input rows are hashed straight from calldata into the scratch word (`calldatacopy` to `0x00`, `keccak256`)
  without a decode, because only their bytes matter to the Merkle tree; the
  numeric values are read once more in `combineOpenings` with a per-element
  byte swap.
- The canonical scan is a separate pass (about 2.5 percent of the execution)
  so that no arithmetic ever sees a non-canonical operand and the error
  precedence of section 11.3 holds for every input.
- The reduced opening regroups the six terms by denominator, which turns six
  extension products per query into two plus five base-times-extension
  products.

## 6. Code size

Runtime bytes of the deployables per optimizer setting (`npm run compile`
tables; the cap is 24,576 bytes):

| Contract              | runs 200 (default) | runs 1000000 | via-IR (runs 200) |
| --------------------- | -----------------: | -----------: | ----------------: |
| StarkVerifier         |             14,646 |       18,298 |            14,111 |
| StarkVerifierGasMeter |              1,342 |        1,959 |             1,220 |
| StarkFactRegistry     |              1,810 |        2,643 |             1,684 |
| StateBridge           |              5,437 |        8,679 |             4,373 |
| FriHarness (test)     |             18,581 |       22,758 |            18,366 |

The verifier fits the cap with 9,930 bytes of headroom at the default setting
and 6,278 bytes at runs 1000000, so the split of a second `FriPcsVerifier` contract at
the `pcs.verify` boundary (challenger state serialised across a STATICCALL)
was unnecessary and was not implemented. Should a second AIR push the size
over the cap, the boundary is ready: `StarkVerifierCore._absorbInstance` ends
with the challenger state and the challenges in `Ctx`, and `FriVerifier.verifyFri`
needs nothing else from the AIR.

## 7. Tests

- `test/contracts/fri.test.js` (needs `STARK_RPC_URL`): layout, `proofId` and
  the canonical scan of every vector plus the 33 layout mutations; the chain-
  derived challenges of every vector; every reduced opening (11 values per
  query); `foldRow` on 620 rows of arity 2, 4, 8 and 16; every fold chain step
  (folded index, value, leaf digest) and every final polynomial check; the
  whole FRI flow and the whole verifier flow timed per phase; the 28
  FRI-related mutation vectors through `verifyFri`.
- `test/contracts/stark.test.js` (needs `STARK_RPC_URL`): 16 preset
  deployments, `PARAMS()`, 32 valid vectors accepted, 73 mutations rejected
  with the expected selector, wrong-length and non-canonical public values,
  and the gas table above. `STARK_SKIP_MUTATIONS=1` limits a run to the gas
  rows (used for the alternative optimizer settings).
- `npm run test:unit`, `npm run lint:prose`, `npm run format:check` and
  `npm run compile` (size gate) stay green.
