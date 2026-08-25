# QuantaProof Repository Guide

Rules for coding agents and contributors working in this repository. The
collection-wide workspace rules apply on top of this file; where the two
overlap, the stricter rule wins.

## What this repository is

QuantaProof is a post-quantum STARK verifier for QRL 2.0: Hyperion contracts
that verify Plonky3-compatible proofs on the 64-byte QRVM, the Rust prover and
vector tooling that feed them, a fact registry plus bridge skeleton, and the
gas measurements that decide the L2 design. Read `README.md`, then
`docs/DECISIONS.md` and `docs/PROTOCOL.md` before touching protocol code.

## Layout

- `contracts/hyperion/`: every contract, library, AIR, interface and test
  harness. Hyperion (`.hyp`) is the only contract language. No `.sol` files,
  no Foundry, no Hardhat.
- `prover/`: Rust workspace (Plonky3 pinned in `prover/PLONKY3_VERSION`,
  `Cargo.lock` committed).
- `scripts/`: compile, size gate, dev node, Kurtosis composition, deploy,
  proof verification, gas report, prose lint.
- `test/unit/`: `node:test` suites that need no chain. `test/contracts/`:
  suites that need `STARK_RPC_URL` and skip without it. `test/lib/`: JS
  reference implementations. `test/vectors/`: prover output.
- `config/`: tracked Kurtosis arguments and `*.example.json` deployment
  records. Live records (`config/local-*.json`, `config/dev-node.json`) are
  ignored.
- `docs/`: protocol, decisions, toolchain, generated gas report, bridge and
  L2 architecture.

## Toolchain rules

- Compile only with the 64-byte compiler from the `hyperion-stark` worktree:
  `HYPERION_COMPILER=../hyperion-stark/build/hypc/hypc`. The system `hypc`
  predates the 64-byte word and must never be used.
- The execution client comes from the `go-qrl-stark` worktree
  (`../go-qrl-stark`). Both worktrees carry a snapshot commit of the QNS
  precompile alignment; rebase and drop those commits once the alignment
  lands upstream. Never edit the QNS `go-qrl`, `hyperion` or `myqrlwallet-qns`
  trees from here.
- Local networks: `npm run dev-node` (gqrl developer mode, chain 1337) for
  iteration; `npm run kurtosis:start` (enclave `qrl2-stark`, chain 3151909,
  RPC `http://127.0.0.1:32102`) as the release gate. Details and the port
  and image table live in `docs/TOOLCHAIN.md`.
- `uint512` at the Hyperion level, Yul assembly for hot loops, proofs as
  packed `bytes calldata`. Never `uint256[]` for proof data.
- Runtime code cap 24,576 bytes per contract (`npm run size` enforces it),
  block gas cap 20,000,000, target 8,000,000 or less per verification.

## Gates

Run before every commit and report the results:

```bash
npm run lint:prose
npm run format:check
HYPERION_COMPILER=../hyperion-stark/build/hypc/hypc npm run compile   # includes npm run size
npm run test:unit
cargo fmt --check --manifest-path prover/Cargo.toml
cargo clippy --release --manifest-path prover/Cargo.toml -- -D warnings
cargo test --release --manifest-path prover/Cargo.toml
```

Chain-bound suites run locally against a node:

```bash
STARK_RPC_URL=http://127.0.0.1:8545 HYPERION_COMPILER=../hyperion-stark/build/hypc/hypc npm run test:contracts
```

CI (`.github/workflows/ci.yml`) runs the node unit suite, the prose lint, the
format check and the Rust prover tests. hypc and chain-bound suites are
local-only because hosted runners have neither a 64-byte hypc build nor a
QRL 2.0 node.

## Environment variables

| Variable                                                                                               | Used by                          | Meaning                                                                                                              |
| ------------------------------------------------------------------------------------------------------ | -------------------------------- | -------------------------------------------------------------------------------------------------------------------- |
| `HYPERION_COMPILER`                                                                                    | compile, hypc.js, contract tests | Path to the 64-byte `hypc`. `HYPC_BIN` is accepted as an alias.                                                      |
| `HYPERION_OPTIMIZE_RUNS`, `HYPERION_VIA_IR`                                                            | compile                          | Optimizer runs (default 200) and `--via-ir` toggle (`1`); code-size contingency knobs.                               |
| `STARK_RPC_URL`                                                                                        | contract tests, loadDeployer     | Execution RPC for chain-bound suites. Unset means the suites skip.                                                   |
| `STARK_CONFIG`                                                                                         | deploy, verify:proof, gas:report | Deployment record (default `config/local-stark.json`; `config/dev-node.json` for the dev node).                      |
| `STARK_PUBLIC_DEV_ACCOUNT`                                                                             | loadDeployer                     | Index of a published Kurtosis fixture account. Loopback RPC and chain 3151909 only; command-scoped, never in `.env`. |
| `TESTNET_SEED`                                                                                         | loadDeployer                     | 34-word ML-DSA-87 mnemonic or 102-hex extended seed for other networks. `.env` only, never tracked.                  |
| `QRL_PACKAGE_DIR`                                                                                      | loadDeployer, kurtosis-start     | Sibling `qrl-package` checkout (default `../qrl-package`).                                                           |
| `GO_QRL_DIR`                                                                                           | image builders, kurtosis-start   | Execution client source (default `../go-qrl-stark`).                                                                 |
| `GQRL_BIN`, `STARK_DEV_PORT`, `STARK_DEV_DATADIR`, `STARK_DEV_VERBOSITY`                               | dev-node.sh                      | Binary, HTTP port (8545), data directory (`build/dev-node`), log verbosity (3).                                      |
| `KURTOSIS_ENCLAVE`                                                                                     | kurtosis-start                   | Enclave name (default `qrl2-stark`).                                                                                 |
| `STARK_FORCE_REBUILD`, `STARK_ALLOW_WILDCARD_BIND`                                                     | kurtosis-start                   | Rebuild every image (`1`); acknowledge non-loopback Docker port publication (`1`).                                   |
| `STARK_DOCKER_CGROUP_PARENT`                                                                           | image builders                   | Optional `--cgroup-parent` for `docker build`.                                                                       |
| `QRYSM_COMMIT`, `QRL_GENESIS_GENERATOR_COMMIT`, `QRYSM_REPOSITORY`, `QRL_GENESIS_GENERATOR_REPOSITORY` | image builders                   | Source pins for the beacon, validator and genesis-generator images.                                                  |
| `STARK_RPC_WAIT_ATTEMPTS`                                                                              | wait-for-rpc.js                  | Readiness poll attempts (default 90, two seconds apart).                                                             |

## Writing conventions

- Never write a Unicode em dash (U+2014) anywhere: code, comments, docs,
  commit messages, pull requests. `npm run lint:prose` fails on one.
- No contrastive negation in prose ("X, not Y" / "not X, but Y"). State what
  something is. The prose lint warns on the common patterns.
- Prettier formats JS, JSON, YAML and Markdown (`npm run format`). Rust uses
  `cargo fmt`. Hyperion sources follow the layout of the existing files.
- Comments explain why; file headers state what a file is for and how it is
  used.

## Git and public-repository safety

- Branches: `main` and `dev`. Code changes go through a feature branch and a
  pull request into `dev`, reviewed with the workspace code-review agent.
  Documentation-only changes commit straight to `dev`.
- Conventional Commit prefixes, one behavior per commit. Never rewrite shared
  history without explicit authorization. Never revert changes you did not
  author.
- Every tracked file is treated as world-readable even while the repository is
  private. Never commit private infrastructure detail: host IPs, `user@host`
  targets, webroots, workstation paths, LAN hosts, process layouts or deploy
  runbooks. Loopback URLs and the published Kurtosis fixtures are fine.
  Use relative sibling paths (`../hyperion-stark`, `../go-qrl-stark`).
- `CLAUDE.md` and `docs/OPS.md` are ignored and never force-added.
- Never commit generated build output (`build/`, `prover/target/`), secrets,
  seeds, `.env`, or live deployment records.
- Before every push: `git diff origin/<branch> | grep -nE '([0-9]{1,3}\.){3}[0-9]{1,3}|ops@|root@|/home/|/var/www'`
  and triage every hit.
