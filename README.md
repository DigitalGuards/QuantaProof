# QuantaStark: post-quantum STARK verifier for QRL 2.0

QuantaStark is a Hyperion-native verifier for Plonky3-compatible STARK proofs on the 64-byte QRL 2.0 virtual machine, together with the Rust prover that produces the proofs and test vectors, a fact registry and bridge skeleton for the L1 side of a rollup, and the gas measurements that decide the L2 design.

**Research project.** QuantaStark is a DigitalGuards research project: experimental, unaudited, and subject to breaking changes. It exists to measure what post-quantum validity proofs cost on QRL 2.0 and to inform an L2 design. Nothing in this repository is production software, and nothing here should secure funds.

QRL 2.0 has no pairing precompiles, so pairing-based SNARK verifiers cannot run there. Validity proofs on QRL take the hash-and-field-arithmetic shape of a STARK, which is post-quantum by construction. The QRVM word is 512 bits, `address` is 64 bytes and every ABI slot is 64 bytes, so existing Solidity verifiers serve as reference material only.

Status: the verifier, the prover, the vectors, the fact registry and the bridge skeleton are complete and measured on the gqrl developer node (milestones M0 to M8 of [`docs/DECISIONS.md`](docs/DECISIONS.md)); the Kurtosis release gate has been run on chain 3151909 (all presets deployed, `fib_c3_n20` verified end to end, gas report; record in [`docs/TOOLCHAIN.md`](docs/TOOLCHAIN.md)) and the L2 architecture document is derived from the measured numbers. `StarkVerifier.verify` accepts every valid vector of the sixteen parameter presets and rejects every mutated vector with its recorded custom error. Headline numbers (developer node, optimizer runs 200, whole `verifyAndLog` transactions; [`docs/GAS-REPORT.md`](docs/GAS-REPORT.md) has every cell):

| Cell                       | Proof bytes | Transaction gas | Inside the verifier |
| -------------------------- | ----------: | --------------: | ------------------: |
| `fib_c3_n12` (34 queries)  |      43,440 |       2,185,178 |           1,447,427 |
| `fib_c3_n20`               |     105,873 |       4,463,257 |           2,710,754 |
| `fib_c2_n20` (50 queries)  |     134,801 |       5,920,483 |           3,696,128 |
| `fib_c1_n12` (100 queries) |      82,672 |       4,937,007 |           3,561,810 |
| `fib_c1_n20`               |     226,641 |      10,534,049 |           6,807,827 |

40 of the 44 measured cells sit at or below the 8,000,000 target; the largest, `fib_c1-binary_n20` (388 KB proof), takes 17,065,391 gas, 85 percent of the 20,000,000 block cap. The runtime code is 14,458 bytes (cap 24,576). Two facts from the measurements shape the L2 design: calldata is 20 to 43 percent of a verification transaction, and the execution client's transaction pool refuses transactions above 131,072 bytes, so proofs above about 123 KB (c1 from n = 16, c2 at n = 20, every binary-folding preset from n = 16) need a raised pool cap or staged verification before they can be submitted as one transaction.

## Design invariants

- Hyperion is the sole contract source language. No `.sol` files, no Foundry.
- Proof system: Plonky3 uni-stark over Goldilocks (`p = 2^64 - 2^32 + 1`) with the quadratic extension, two-adic FRI with pruned multi-opening Merkle proofs, keccak256 Merkle trees and keccak Fiat-Shamir. The crate version is pinned in `prover/PLONKY3_VERSION` and recorded in every compile manifest; `Cargo.lock` is committed.
- Integers are `uint512` at the Hyperion level, hot loops run in Yul assembly, and proofs travel as packed `bytes calldata` (8-byte little-endian Goldilocks elements exactly as Plonky3 serialises them, 32-byte digests). Field inversion goes through the `0x05` modexp precompile.
- One verifier deployment per parameter preset: the six FRI constants at the top of `contracts/hyperion/StarkVerifier.hyp` are substituted at compile time (`scripts/lib/presets.js`); the committed values are preset c3.
- Gas: the consensus block cap is 20,000,000; the target is 8,000,000 or less per verification transaction. Runtime code is capped at 24,576 bytes per contract and `npm run size` and `npm run deploy` enforce it.
- Target network: the 64-byte QRL 2.0 network (QIP-55) with the ML-DSA-87 verify precompile at `0x03` (64-byte digest) and SHAKE256 at `0x06`. Every compile uses the 64-byte compiler from the `hyperion-stark` worktree.
- Contract tests run against a live QRVM (a `gqrl --dev` node or the Kurtosis composition). Node unit tests check the JS references against the Rust vectors without a chain, and the Rust mirror verifier must reproduce the upstream transcript byte for byte.
- Facts are keyed by public values. A proof hash is never a key: proof bytes contain unobserved witness bytes and are malleable.

## Structure

```text
contracts/hyperion/    StarkVerifier (StarkVerifierCore + preset constants), StarkVerifierGasMeter, StarkFactRegistry, bridge/StateBridge
contracts/hyperion/lib Goldilocks, Fp2, KeccakChallenger, MerkleMultiProof, FriVerifier, ProofLayout
contracts/hyperion/air FibonacciAir (selectors, constraints, quotient recomposition)
contracts/hyperion/test Harnesses exposing the library internals and MockStarkVerifier
prover/                Rust workspace: Plonky3 prover, transcript logging, mirror verifier, vector and mutation generators, size model
scripts/               Hyperion compilation, code-size gate, dev node, Kurtosis composition, per-preset deployment, proof verification, gas report, prose lint
test/unit/             node:test suites that need no chain (toolchain scripts, JS references against the vectors)
test/contracts/        node:test suites that need STARK_RPC_URL (harnesses, verifier, gas, bridge)
test/lib/              JS reference implementations (Goldilocks, Fp2, challenger, Merkle, FRI, layout, verifier, ABI)
test/vectors/          Proof vectors generated by the prover (n = 10 and 12 tracked with mutation sets; large/ holds n = 16 and 20, ignored)
config/                Kurtosis arguments and example deployment records; live records stay local and ignored
docker/                Qrysm image build for the local network
docs/                  Protocol, verifier, decisions, toolchain, gas report, primitives, bridge, compiler notes, L2 architecture
```

## Build and test

Prerequisites: Node 20 or newer, a stable Rust toolchain, the `hyperion-stark` and `go-qrl-stark` worktrees next to this repository (see [`docs/TOOLCHAIN.md`](docs/TOOLCHAIN.md)).

```bash
npm install
HYPERION_COMPILER=../hyperion-stark/build/hypc/hypc npm run compile   # ABI, .bin, .bin-runtime, manifest.json, size gate
npm run prover:build
npm run prover:vectors                                                # writes test/vectors/*.json (n = 10, 12)
npm test                                                              # compile + test:unit + lint:prose
npm run format:check
```

`npm run compile` writes `build/hyperion/manifest.json` with the exact hypc build and the pinned Plonky3 version. `npm run size` prints the runtime and initcode size table and fails above the caps. The Rust gates are `cargo fmt --check`, `cargo clippy -D warnings` and `cargo test --release`, all with `--manifest-path prover/Cargo.toml`. The larger vectors are generated on demand:

```bash
cargo run --release --manifest-path prover/Cargo.toml -- vectors --preset c3,c2,c1,c3-binary,c2-binary,c1-binary --sizes 16,20 --out test/vectors --mutations none
STARK_VECTORS_LARGE=1 npm run test:unit                              # include test/vectors/large/ in the unit suites
```

`npm run test:contracts` needs a node:

```bash
npm run dev-node &                                                    # gqrl --dev, chain 1337, http://127.0.0.1:8545
STARK_RPC_URL=http://127.0.0.1:8545 HYPERION_COMPILER=../hyperion-stark/build/hypc/hypc npm run test:contracts
```

Without `STARK_RPC_URL` the contract suites report themselves as skipped, which is what CI does.

## Local QRL 2.0 network

Two local networks exist. The gqrl developer node is the fast path for iteration and produced every number in the gas report: `npm run dev-node` starts it with chain id 1337, one unlocked pre-funded account and a 20,000,000 gas limit, sealing a block whenever a transaction is pending. Kurtosis is the release gate: a full execution, beacon and validator composition built from pinned sources, validated on 2026-08-25 (see `docs/TOOLCHAIN.md`).

```bash
npm run build:local-network    # qrl2-stark/go-qrl:stark and the pinned Qrysm images
npm run kurtosis:start         # enclave qrl2-stark, chain 3151909, RPC http://127.0.0.1:32102
kurtosis enclave inspect qrl2-stark
```

The composition coexists with the QNS enclave (`qrl2-qns`, chain 3151908, ports 32000+): different enclave name, chain id, published port range and image namespace. The start script verifies image revision labels and running container image IDs before reusing an enclave, refuses a dirty `go-qrl-stark` tree, probes Docker's published-port bind address and refuses anything other than loopback unless `STARK_ALLOW_WILDCARD_BIND=1` acknowledges host-level controls. `STARK_FORCE_REBUILD=1` refreshes every image for a new enclave.

Deploy and measure (developer node shown; on Kurtosis use `STARK_CONFIG=config/local-stark.json` and `STARK_PUBLIC_DEV_ACCOUNT=0` for the deploy):

```bash
export HYPERION_COMPILER=../hyperion-stark/build/hypc/hypc
STARK_CONFIG=config/dev-node.json npm run deploy -- --preset all                      # 16 verifiers + gas meters
STARK_DEPLOY_BRIDGE=1 STARK_CONFIG=config/dev-node.json npm run deploy -- --preset c3  # plus registry and bridge
STARK_CONFIG=config/dev-node.json npm run verify:proof -- --vector test/vectors/fib_c3_n12.json
STARK_CONFIG=config/dev-node.json npm run gas:report                                   # regenerates docs/GAS-REPORT.md
```

`deploy` compiles `StarkVerifier.hyp` once per preset with the constants substituted and records one verifier and gas meter per preset in the deployment record. `verify:proof` picks the verifier of the vector's preset, sends the proof through the gas meter and exits non-zero when the outcome differs from the vector's expectation. `gas:report` measures every valid vector, keeps the measurements per optimizer setting under `build/gas-report/` and renders the tables, the optimizer comparison, the model deviation, the extrapolation to n = 24 and the phase breakdown. The developer node signs with its own account; `STARK_PUBLIC_DEV_ACCOUNT` selects a published fixture account from the sibling `qrl-package` checkout and is accepted only with a loopback RPC URL and chain id 3151909. Use `TESTNET_SEED` in the ignored `.env` for other networks and keep every seed out of tracked files and shell history.

## Documentation

- [`docs/PROTOCOL.md`](docs/PROTOCOL.md): the normative transcript, opening, Merkle and calldata layout contract between the Rust prover, the JS references and the Hyperion verifier.
- [`docs/VERIFIER.md`](docs/VERIFIER.md): how the Hyperion verifier computes the protocol, its memory layout, check order, code size and the phase measurements.
- [`docs/DECISIONS.md`](docs/DECISIONS.md): design decisions with their rationale, verified QRVM facts, parameter sets, milestones and tracked risks.
- [`docs/TOOLCHAIN.md`](docs/TOOLCHAIN.md): worktrees and snapshot commits, hypc and gqrl builds, the dev node, the Kurtosis composition and the deploy, verify and measure flow.
- [`docs/GAS-REPORT.md`](docs/GAS-REPORT.md): generated by `npm run gas:report`; every cell under three optimizer settings, the model deviation and the extrapolation.
- [`docs/GAS-PRIMITIVES.md`](docs/GAS-PRIMITIVES.md): measured gas of the Goldilocks and Fp2 primitives and the compiler behaviour behind the numbers.
- [`docs/BRIDGE.md`](docs/BRIDGE.md): the fact registry and the bridge skeleton with ML-DSA-87 withdrawals.
- [`docs/compiler/HYPC-LEGACY-CODEGEN-DEFECTS.md`](docs/compiler/HYPC-LEGACY-CODEGEN-DEFECTS.md): two confirmed legacy code generator defects with reproductions.
- [`docs/L2-ARCHITECTURE.md`](docs/L2-ARCHITECTURE.md): the L2 design decision grounded in the measured gas.

## License

GPL-3.0. The Fibonacci AIR mirrors the Plonky3 example and keeps its MIT/Apache-2.0 notice; Plonky3 itself is consumed as a pinned crate.
