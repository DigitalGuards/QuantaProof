# Gas of the field primitives

Measured marginal gas of the Goldilocks and Fp2 library primitives
(`contracts/hyperion/lib/Goldilocks.hyp`, `contracts/hyperion/lib/Fp2.hyp`) on
the QRVM, with the measurement method, the targets from the milestone plan and
the compiler behaviour that moves the numbers. Milestone M2; the full verifier
figures land in `docs/GAS-REPORT.md`.

## Method

Every number comes from the `gasLoop(uint8 op, uint512 n)` function of
`contracts/hyperion/test/GoldilocksHarness.hyp` and `Fp2Harness.hyp`, driven by
the `gas loop` subtests of `test/contracts/goldilocks.test.js` and
`test/contracts/fp2.test.js`:

- `gasLoop` runs `n` iterations of one primitive and returns the `gasleft()`
  delta around the loop; the running value feeds every iteration and comes
  back as a witness, so the optimizer can neither hoist nor drop the body.
- Marginal cost per iteration is `(gasLoop(op, 2n) - gasLoop(op, n)) / n` with
  `n = 1024` (256 for `Goldilocks.pow`, 128 for `Fp2.pow` and
  `Fp2.batchInverse`, whose iterations cost thousands of gas or allocate
  memory). Both calls are `qrl_call` with a 20,000,000 gas limit.
- "Net" subtracts the loop itself, measured as the empty loop (op 0 for the
  Yul form `for { let i := 0 } lt(i, n) { i := add(i, 1) }`, op 16 in the
  Goldilocks harness and op 6 in the Fp2 harness for the high-level form
  `for (uint512 i = 0; i < n; ++i)` in an `unchecked` block). Both loop forms
  cost 43 gas per iteration.
- Yul rows run the primitive's instruction sequence inline in the loop body
  (the exact body of every op is listed in the harness NatSpec). "Library
  call" rows call the Hyperion library function from a high-level loop, so
  they include the internal call, the argument checks and any revert path.
- Table lookups use `i & 31` as the index so every entry is hit uniformly.

Environment: gqrl developer node (chain id 1337, 20,000,000 gas limit,
precompiles `0x05` modexp and `0x06` shake256 live), hypc
`0.2.0-develop.2026.8.25+commit.cf176678` from the `hyperion-stark` worktree,
optimizer enabled. Two optimizer settings are reported because the runs value
changes how the compiler materializes wide literals (see below): `runs = 200`
is the default of `scripts/compile-hyperion.js` and `scripts/hypc.js`
(`HYPERION_OPTIMIZE_RUNS`), `runs = 1000000` is the gas-first setting.

Regenerate with:

```bash
STARK_RPC_URL=http://127.0.0.1:8545 HYPERION_COMPILER=../hyperion-stark/build/hypc/hypc \
  node --test test/contracts/goldilocks.test.js test/contracts/fp2.test.js
HYPERION_OPTIMIZE_RUNS=1000000 STARK_RPC_URL=http://127.0.0.1:8545 HYPERION_COMPILER=../hyperion-stark/build/hypc/hypc \
  node --test test/contracts/goldilocks.test.js test/contracts/fp2.test.js
```

The `gas op` diagnostic lines of the TAP output are the table rows.

## Targets

| Target from the plan | Measured (runs 200 / 1000000)                        | Verdict                           |
| -------------------- | ---------------------------------------------------- | --------------------------------- |
| base mul < 25        | 22 / 22 (inline `mulmod`)                            | met                               |
| EF mul < 90          | 98 / 98 inline, 93 / 93 through `Fp2.mul`            | missed by 3 to 8 gas, see below   |
| inv < 400            | 438 / 420 inline, 488 / 470 through `Goldilocks.inv` | missed by 20 to 88 gas, see below |

Why EF mul misses: the arithmetic is five `MUL`, two `ADD` and two `MOD`
(41 gas). The remaining 50 to 57 gas is stack traffic: four operands read twice
each (eight `DUP`), the literals `p` and 7, and the two result assignments.
Karatsuba trades two `MUL` (10 gas) for two `ADD` and two `SUB` (12 gas) and
the same operand traffic, so it does not help on a VM where `MUL` costs 5. The
lever that works is fusing: sums of extension products fit in the 512-bit word
(each product is below 2^131), so a chain of multiply-accumulate steps can pay
the two `MOD` and the two assignments once at the end instead of per product
(`Goldilocks.mulAdd` is the base field form). The FRI fold and the constraint
evaluation are written that way in later milestones.

Why inv misses: the modexp precompile has a 200 gas floor (EIP-2565 pricing
with 8-byte operands computes 21) and the pre-warmed `STATICCALL` costs 100,
so 300 gas is fixed. Building the 120-byte input (two `MSTORE` of prepared
words), the seven call arguments, the success check, the `returndatasize`
check and the 8-byte read-back add about 100 gas of unavoidable instruction
cost; the check-free inline lower bound measured 404. The library function adds
the zero check and the internal call. Single inversions are rare in the
verifier (the batch paths below cover the denominators), so the miss costs a
few hundred gas per verification.

## Goldilocks base field

Net marginal gas per operation. Yul rows: inline instruction sequence.

| Op  | Primitive (inline Yul)                                   | runs 200 | runs 1000000 |
| --- | -------------------------------------------------------- | -------: | -----------: |
| 1   | add: `addmod(x, y, P)`                                   |       22 |           22 |
| 2   | sub: `addmod(x, sub(P, y), P)`                           |       28 |           28 |
| 3   | neg: `mod(sub(P, x), P)`                                 |       29 |           29 |
| 4   | mul: `mulmod(x, y, P)`                                   |       22 |           22 |
| 5   | mul via `mod(mul(x, y), P)`                              |       31 |           31 |
| 6   | sq: `mulmod(x, x, P)`                                    |       22 |           22 |
| 7   | mulAdd: `mod(add(mul(x, y), z), P)` (lazy reduction)     |       37 |           37 |
| 8   | inv: modexp precompile (input build, call, checks, read) |      438 |          420 |
| 9   | cdLanes: `calldataload` + three-stage lane byte swap     |      360 |          168 |
| 10  | lane: extract one lane of a cdLanes word                 |       64 |           52 |
| 11  | rev(x, 32): five mask stages plus shift                  |      203 |          203 |
| 12  | bswap64: three mask stages                               |      113 |          113 |
| 13  | twoAdicGen: packed constants, five-way switch            |      245 |          177 |
| 14  | twoAdicGen: 33-case switch                               |      441 |          441 |
| 15  | lanesCanonical: SWAR check of eight lanes                |      138 |           42 |

| Op  | Library call from a high-level loop                       | runs 200 | runs 1000000 |
| --- | --------------------------------------------------------- | -------: | -----------: |
| 17  | `Goldilocks.add`                                          |       66 |           66 |
| 26  | `Goldilocks.sub`                                          |       72 |           72 |
| 18  | `Goldilocks.mul`                                          |       66 |           66 |
| 27  | `Goldilocks.sq`                                           |       61 |           61 |
| 19  | `Goldilocks.inv`                                          |      488 |          470 |
| 20  | `Goldilocks.pow(x, 2^64 - 1)` (64 squarings, 64 products) |    7,441 |        7,429 |
| 21  | `Goldilocks.pow2k(x, 32)`                                 |    2,213 |        2,213 |
| 22  | `Goldilocks.twoAdicGen` (range check + packed switch)     |      276 |          208 |
| 28  | `Goldilocks.twoAdicGenAt` (lookup in the memory image)    |       86 |           74 |
| 29  | `Goldilocks.loadTwoAdicTables` (one-time 640-byte image)  |      441 |          156 |
| 23  | `Goldilocks.cdElem` (one element, swap + canonical check) |      202 |          202 |
| 24  | `Goldilocks.rev(x, 32)`                                   |      322 |          322 |
| 25  | `Goldilocks.bswap64`                                      |      150 |          138 |

The internal call costs about 40 gas on top of the inline sequence for the
small functions (add, mul, sq), which is why hot loops in later milestones
inline the Yul rather than call the library.

Two-adic table storage, measured as `qrl_estimateGas` of one external call of
`twoAdicGen(17)` (21,000 base and calldata included, identical for the three):

| Storage                                                   | runs 200 | runs 1000000 |
| --------------------------------------------------------- | -------: | -----------: |
| packed `uint512` constants, five-way switch (the library) |   21,984 |       21,886 |
| 33-case Yul switch                                        |   22,148 |       22,126 |
| `bytes constant` blob copied to memory, `mload` + shift   |   21,898 |       21,864 |

The blob is the cheapest single call by 22 to 86 gas but it allocates 320
bytes of memory on every call (unbounded growth inside loops) and cannot be
read from inline assembly, so the library keeps the packed constants for
`twoAdicGen(i)` (no memory side effects) and adds `loadTwoAdicTables(ptr)` +
`twoAdicGenAt(ptr, i)` / `twoAdicGenInvAt(ptr, i)` for hot paths: 156 gas
once, then 74 per lookup, the cheapest option by a wide margin. The verifier
writes the image into its context struct at entry.

## Fp2 extension field

| Op  | Primitive (inline Yul)                                     | runs 200 | runs 1000000 |
| --- | ---------------------------------------------------------- | -------: | -----------: |
| 1   | EF mul: `(a0 b0 + 7 a1 b1, a0 b1 + a1 b0)`, one `mod` each |       98 |           98 |
| 2   | EF sq                                                      |       87 |           87 |
| 3   | EF mulBase: two `mulmod`                                   |       44 |           44 |
| 4   | EF add: two `addmod`                                       |       44 |           44 |
| 5   | EF inv: norm, base inv (modexp), two `mulmod`              |      537 |          519 |

| Op  | Library call from a high-level loop                     | runs 200 | runs 1000000 |
| --- | ------------------------------------------------------- | -------: | -----------: |
| 7   | `Fp2.mul`                                               |       93 |           93 |
| 11  | `Fp2.sq`                                                |       85 |           85 |
| 8   | `Fp2.inv`                                               |      648 |          630 |
| 9   | `Fp2.batchInverse`, per element (norm-based Montgomery) |      378 |          378 |
| 10  | `Fp2.pow(x, 2^64 - 1)`                                  |   15,331 |       15,319 |

`Fp2.batchInverse` runs Montgomery's trick over the base field norms rather
than over the extension elements: one norm, three base `mulmod` for the prefix
products and the shared inverse, and two `mulmod` to scale the conjugate, plus
two memory words per element. The first version multiplied extension elements
(three EF products per element) and measured 579 gas per element, above the
537 of a direct inversion; on a VM whose modexp costs 300 gas, batching only
pays when the per-element work stays in the base field. The FRI denominators
`zeta - x` with `x` in the base field have `norm = (z0 - x)^2 - 7 z1^2` where
`7 z1^2` is shared, so the verifier can drop below 378 there.

## Compiler behaviour that moves the numbers

- Wide literals and the optimizer runs value. With `runs = 200` the constant
  optimizer decides that a 48 to 64 byte literal is cheaper to fetch with
  `CODECOPY` into memory than to `PUSH`, which costs about 30 gas per use at
  run time. Every lane mask, the packed table words and the prepared modexp
  header words are that wide, so `cdLanes` (360 vs 168), `lanesCanonical`
  (138 vs 42), the table lookups and `inv` all move with the setting. The
  price is code size: the Goldilocks harness grows from 12,680 to 18,365
  runtime bytes, the Fp2 harness from 7,953 to 10,219. The verifier compile
  will pick the highest runs value that keeps every deployable under the
  24,576-byte cap (`HYPERION_OPTIMIZE_RUNS`, see `docs/DECISIONS.md` and
  `scripts/check-code-size.js`).
- Literals of 8 bytes or fewer, and literals the optimizer can rebuild with
  `NOT` or a shift (such as all-ones), cost 3 gas at every runs value.
- Loop bodies are measured with a data dependency on the loop variable or the
  running value; a body that only reads loop-invariant inputs is hoisted by the
  Yul optimizer and measures as free.

## Reading elements from calldata

The proof layout carries 8-byte little-endian elements. Decoding them one at a
time through `cdElem` costs 202 gas (swap, canonical check, call). Decoding a
64-byte word through `cdLanes` costs 168 gas for eight elements, and each lane
extraction 52 gas, so about 73 gas per element with the canonical check of the
whole word at 42 gas (`lanesCanonical`); the query-row readers in the Merkle
and FRI milestones use the word form.

## Hyperion and Yul notes recorded while building this milestone

- Inline assembly can read a constant only when its value is a number literal
  or an identifier that refers to such a constant. A member access such as
  `Goldilocks.P` is rejected ("Only direct number constants and references to
  such constants are supported"), so `Fp2.hyp` and the harnesses carry literal
  copies of the field constants they use in Yul.
- Array indices and `new T[](length)` lengths are `uint256`; a `uint512` loop
  counter cannot index an array without an explicit `uint256(...)` conversion.
- `staticcall` and `gasleft()` require `view`, so `Goldilocks.inv`, `Fp2.inv`
  and `Fp2.batchInverse` are `view` and every caller is too.
- The modexp precompile at `0x05` takes 32-byte length fields:
  `len(base) | len(exp) | len(mod) | base | exp | mod` (120 bytes for 8-byte
  operands) and returns exactly `len(mod)` bytes.
- `uint64[]` arguments and returns use one 64-byte slot per element; a batch
  of 256 elements is 16 KB of calldata per array, which is why the batch
  wrappers stop at 256 operands per call.
- The developer node caps a transaction fee at 1 quanta, so deployments use
  the gas estimate plus 20 percent instead of a blanket limit.
