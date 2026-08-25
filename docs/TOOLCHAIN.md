# Toolchain

How the compiler, the execution client and the two local networks are built and
used. Everything here is relative to the collection root that holds this
repository and its sibling checkouts (`go-qrl`, `hyperion`, `qrl-package`).

Status (2026-08-25): the compiler and the execution client are built, the
developer node is validated and carries every measurement in
`docs/GAS-REPORT.md`; the Kurtosis composition has been validated (record in the release-gate section).

## Worktrees and snapshot commits

The QNS precompile alignment (ML-DSA-87 verify at `0x03` with a 64-byte digest,
SHAKE256 at `0x06`) is uncommitted in the `go-qrl` and `hyperion` checkouts
while it waits for review and a QIP. QuantaStark never touches those trees. It
builds from linked worktrees that carry one snapshot commit each:

```bash
git -C go-qrl worktree add -b feat/stark-verifier-toolchain ../go-qrl-stark 5bd0860
git -C go-qrl diff | git -C go-qrl-stark apply
cp go-qrl/core/vm/contracts_qrl2_test.go go-qrl-stark/core/vm/
git -C go-qrl-stark add -A
git -C go-qrl-stark commit -m "chore(toolchain): snapshot QNS precompile alignment for the STARK verifier (2026-08-25)"

git -C hyperion worktree add -b feat/stark-verifier-toolchain ../hyperion-stark f55de24d
git -C hyperion diff | git -C hyperion-stark apply
git -C hyperion-stark add -A
git -C hyperion-stark commit -m "chore(toolchain): snapshot PQ builtin alignment (2026-08-25)"
```

Base commits: `go-qrl` `5bd0860` (equal to the aligned upstream main at the
time), `hyperion` `f55de24d`. When the alignment lands upstream, rebase both
branches onto it and drop the snapshot commits, so the two never diverge
silently. The Kurtosis start script refuses a dirty `go-qrl-stark` tree for the
same reason: a commit hash must identify every byte that went into an image.

## Compiler: hypc from hyperion-stark

```bash
cmake -S hyperion-stark -B hyperion-stark/build -DCMAKE_BUILD_TYPE=Release -DUSE_Z3=OFF -DUSE_CVC4=OFF -DPEDANTIC=ON
cmake --build hyperion-stark/build --target hypc -j"$(nproc)"
hyperion-stark/build/hypc/hypc --version
```

The build in use reports `0.2.0-develop.2026.8.25+commit.cf176678`. Every
compile passes the binary explicitly:

```bash
HYPERION_COMPILER=../hyperion-stark/build/hypc/hypc npm run compile
```

`npm run compile` runs `scripts/compile-hyperion.js` (ABI, `.bin`,
`.bin-runtime`, `build/hyperion/manifest.json` with `compilerVersion` and
`plonky3Version`) followed by `scripts/check-code-size.js`. The contract test
suite and `npm run deploy` compile through `scripts/hypc.js` (standard JSON)
with the same binary. The system-wide `hypc` predates the 64-byte word: never
use it, and never rely on `PATH`.

The compiler build fixes the word width and the precompile slots behind the
`shake256` and `mldsa87verify` builtins, which is why the manifest records the
exact version string. Two defects of its legacy code generator are documented
in `docs/compiler/HYPC-LEGACY-CODEGEN-DEFECTS.md`. Bridge deployment and the
bridge contract suite force `--via-ir` through
`scripts/lib/presets.js::compileBridge`; the verifier uses the legacy pipeline
at optimizer runs 200 by default. `HYPERION_OPTIMIZE_RUNS` and
`HYPERION_VIA_IR` change the requested compile setting.

## Execution client: gqrl from go-qrl-stark

```bash
(cd go-qrl-stark && GOTOOLCHAIN=auto make gqrl)
go-qrl-stark/build/bin/gqrl version
```

`go.mod` asks for a newer Go than most hosts carry; `GOTOOLCHAIN=auto` downloads
it on first use. The same source builds the Docker image for Kurtosis.

## Provenance and full protocol gate

`npm run check:provenance` fails unless both source trees are clean and the
embedded revision in each configured binary matches its source `HEAD`. It
writes `build/toolchain-provenance.json` on success or failure. The defaults
use sibling source trees; maintained runners can set all four paths explicitly:

```bash
HYPERION_SOURCE_DIR=../hyperion-stark \
HYPERION_COMPILER=../hyperion-stark/build/hypc/hypc \
GO_QRL_SOURCE_DIR=../go-qrl-stark \
GQRL_BIN=../go-qrl-stark/build/bin/gqrl \
npm run check:provenance

STARK_RPC_URL=http://127.0.0.1:8545 npm run test:protocol
```

`test:protocol` accepts only the developer chain 1337 or Kurtosis chain 3151909. It repeats provenance checking, compiles and checks contract sizes,
runs the Node unit and mutation suites, prose and formatting checks, Rust
formatting, clippy and release tests, then runs every live QRVM contract suite
with full vector selection, the mutation matrix and 10,000 randomized field
operations per arithmetic suite. The result is written to
`build/protocol-gate.json`, including failures.

`.github/workflows/protocol-gate.yml` schedules the same gate on a dedicated
runner labeled `quantastark`. Repository variables provide its four local
toolchain paths. Pull requests do not execute on that runner; reviewed revisions
can use `workflow_dispatch`.

## Fast path: the gqrl developer node

`scripts/dev-node.sh` (also `npm run dev-node`) starts:

```text
gqrl --dev --dev.period 0 --dev.gaslimit 20000000 --nodiscover --ipcdisable \
     --http --http.addr 127.0.0.1 --http.port 8545 --http.api qrl,net,web3,debug \
     --http.vhosts localhost --verbosity 3 --datadir build/dev-node
```

Facts about this mode, verified in the client source and on the running node
(2026-08-25):

- chain id 1337 (`qrl_chainId` returns `0x539`; `--networkid` is left at the
  developer default);
- one developer account created in the keystore of the data directory,
  unlocked with an empty passphrase and pre-funded in the developer genesis;
  `qrl_accounts` returns it and `qrl_sendTransaction` lets the node sign;
- `--dev.period 0` seals a block as soon as a transaction is pending, through a
  simulated beacon, in well under a second; no validator or beacon process is
  involved;
- `--dev.gaslimit 20000000` sets the genesis gas limit and the latest block
  reports `gasLimit 0x1312d00` (20,000,000, the consensus cap). It applies only
  when the data directory is created; an existing chain keeps its own genesis,
  so delete `build/dev-node` to reset;
- the data directory persists between runs: the developer account and every
  deployed contract survive a restart, and the deployment records in
  `config/dev-node.json` stay valid;
- developer mode disables discovery, dialing and listening by itself;
  `--nodiscover` is kept explicit;
- `--ipcdisable` is mandatory: gqrl otherwise fails with
  `listen unix ...gqrl.ipc: bind: invalid argument` when the data directory
  path is long;
- the default HTTP modules are `net,web3`, so `qrl` and `debug` are requested
  explicitly;
- the precompiles are live: `0x03` (ML-DSA-87 verify, 64-byte digest) answers
  the bridge withdrawals, `0x05` (modexp) the field inversions, `0x06`
  (SHAKE256) the withdrawal digests; the stubs `0x01` to `0x06` are
  pre-allocated in the developer genesis;
- the transaction fee is capped at 1 quanta per transaction, so the scripts
  send with the estimate plus 20 percent (a blanket gas limit would push the
  fee over the cap);
- the transaction pool rejects any transaction above 131,072 bytes with
  `oversized data` (`txMaxSize` in `core/txpool/legacypool`, a pool constant
  without a command-line knob). Proofs above about 123 KB therefore cannot be
  sent as one transaction on an unmodified client; `qrl_call` and
  `qrl_estimateGas` still execute them, which is how the gas report measures
  those cells (marked in `docs/GAS-REPORT.md`).

Environment knobs: `GQRL_BIN` (binary, default `../go-qrl-stark/build/bin/gqrl`),
`STARK_DEV_PORT` (8545), `STARK_DEV_DATADIR` (`build/dev-node`),
`STARK_DEV_VERBOSITY` (3). Probes:

```bash
curl -sS -X POST http://127.0.0.1:8545 -H 'content-type: application/json' -d '{"jsonrpc":"2.0","method":"qrl_chainId","params":[],"id":1}'
curl -sS -X POST http://127.0.0.1:8545 -H 'content-type: application/json' -d '{"jsonrpc":"2.0","method":"qrl_accounts","params":[],"id":2}'
node scripts/wait-for-rpc.js http://127.0.0.1:8545 1337
```

Use it through `STARK_RPC_URL=http://127.0.0.1:8545` for `npm run test:contracts`
and through `STARK_CONFIG=config/dev-node.json` for `npm run deploy`,
`npm run verify:proof` and `npm run gas:report`. Kurtosis remains the
authoritative gate; the developer node has no beacon and no second client.

## Release gate: the Kurtosis composition (validated 2026-08-25)

Status: exercised end to end on the workstation on 2026-08-25. Validation record:

- Sources: `go-qrl-stark` b19c839 (clean), `hyperion-stark` cf176678, `qrl-package` 04fd313; `hypc 0.2.0-develop.2026.8.25+commit.cf176678`; Plonky3 0.7.0-rc.1.
- Images: `qrl2-stark/go-qrl:stark` 35f343ac214c (label `revision=b19c839…`, `source-state=clean`), `qrl2-stark/qrysm:beacon-chain-64` 2291f5a9bd5e and `validator-64` 0f80b9cd042b (re-tagged from the QNS builds of `cyyber/qrysm@b53fd7c4`), `qrl2-stark/qrysm:qrl-genesis-generator-64` 14bab0a0877c (same source build of `qrl-genesis-generator@6a11fbce`, relabelled with its revision so the start script accepts it).
- Enclave `qrl2-stark` on chain 3151909 next to the running `qrl2-qns` enclave; `qrl_chainId` 0x301825, blocks advancing every slot, latest block `gasLimit` 0x1312d00 (20,000,000).
- `STARK_ALLOW_WILDCARD_BIND=1` was required: the Kurtosis port publisher binds the execution ports with an explicit `0.0.0.0` host address, which the loopback daemon default cannot override (see "Docker loopback binding" below). The workstation runs WSL2 in NAT mode, so those ports are reachable from the Windows host only.
- `npm run deploy -- --preset all` from fixture account 0: 16 verifiers and 16 gas meters recorded in `config/local-stark.json`. The historical run also deployed a bridge bound to the 24-byte Fibonacci verifier. The current compatibility guard rejects that binding, so the historical bridge addresses are superseded and provide no batch-bridge evidence.
- `npm run verify:proof -- --vector test/vectors/large/fib_c3_n20.json`: transaction `0xc61cfadf…` in block 74, status 1, `verifyAndLog` gasUsed 4,500,257 (the developer-node figure 4,463,257 plus the meter's one-time storage warm-up), inner gas 2,710,754, identical to the developer node.
- Gas report: `npm run gas:report -- --store build/gas-report-kurtosis` re-measured all 44 cells on chain 3151909 at optimizer runs 200; proof bytes, calldata gas, `estimateGas`, `gasUsed` and inner gas are identical to the developer-node cells in `docs/GAS-REPORT.md` for every vector, which keeps the three-setting developer-node render as the published report (the Kurtosis store stays local under `build/gas-report-kurtosis/`).

The execution client in the image is the same source as the developer node,
so QRVM gas is identical and the transaction-pool size cap applies there as
well.

| Item              | Value                                                                                                                             |
| ----------------- | --------------------------------------------------------------------------------------------------------------------------------- |
| Enclave           | `qrl2-stark` (`KURTOSIS_ENCLAVE` overrides)                                                                                       |
| Chain id          | 3151909 (`network_id` in `config/kurtosis-stark.yaml`)                                                                            |
| Execution RPC     | `http://127.0.0.1:32102` (`el.public_port_start: 32100`; discovery, Engine API, WebSocket and metrics fill the rest of the range) |
| Genesis gas limit | 20,000,000 (`genesis_gaslimit`; the package default of 30,000,000 exceeds the consensus cap)                                      |
| Execution image   | `qrl2-stark/go-qrl:stark` from `../go-qrl-stark` (`scripts/build-local-node-image.sh`)                                            |
| Beacon image      | `qrl2-stark/qrysm:beacon-chain-64` from `cyyber/qrysm@b53fd7c488f3f0d1d4163b270afac1749eed954b`                                   |
| Validator image   | `qrl2-stark/qrysm:validator-64`, same source                                                                                      |
| Genesis generator | `qrl2-stark/qrysm:qrl-genesis-generator-64` from `theQRL/qrl-genesis-generator@6a11fbcee762af14d188507f071d08ac5782fa69`          |
| Package           | `../qrl-package/kurtosis.yml` (`QRL_PACKAGE_DIR` overrides)                                                                       |
| Validators        | 64, one execution client, one beacon node, one validator client                                                                   |
| Slots             | 6 seconds per slot, 8 slots per epoch, 30 second genesis delay                                                                    |
| Deployment record | `config/local-stark.json`, seeded from `config/local-stark.example.json`                                                          |

Commands:

```bash
sudo service docker start          # the daemon is normally stopped on the workstation
npm run build:local-network        # both image builders; the start script also rebuilds stale images
npm run kurtosis:start
kurtosis enclave inspect qrl2-stark
kurtosis service logs qrl2-stark el-1-gqrl-qrysm
```

`scripts/kurtosis-start.sh` keeps the QNS safety behaviour: it refuses a dirty
`go-qrl-stark` tree, rebuilds images whose `org.opencontainers.image.revision`
label does not match the source commit, compares the running containers' image
IDs against the local images before reusing an enclave, probes Docker's
published-port bind address with a throwaway container and refuses anything
other than loopback, waits for `qrl_chainId` to return 3151909, and prints the
enclave inspection. `STARK_FORCE_REBUILD=1` refreshes every image (new enclaves
only); `STARK_ALLOW_WILDCARD_BIND=1` acknowledges non-loopback publication on a
host whose access controls have been applied and verified.

Kurtosis 1.20 cannot resume a stopped enclave. A stopped `qrl2-stark` must be
removed (`kurtosis enclave rm -f qrl2-stark`) or a new `KURTOSIS_ENCLAVE` name
chosen before the next start.

### Coexistence with the QNS composition

|                   | QNS                        | QuantaStark                |
| ----------------- | -------------------------- | -------------------------- |
| Enclave           | `qrl2-qns`                 | `qrl2-stark`               |
| Chain id          | 3151908                    | 3151909                    |
| Execution ports   | 32000 to 32004 (RPC 32002) | 32100 to 32104 (RPC 32102) |
| Image namespace   | `qrl2-qns/*`               | `qrl2-stark/*`             |
| Client source     | `../go-qrl`                | `../go-qrl-stark`          |
| Deployment record | `config/local-qip55.json`  | `config/local-stark.json`  |

Both can run at the same time on one Docker daemon. The public fixture guard in
`scripts/lib/loadDeployer.js` accepts `STARK_PUBLIC_DEV_ACCOUNT` only for a
loopback RPC URL on chain 3151909, so a QNS enclave can never be signed for by
mistake from this repository.

### Docker loopback binding

The qrl-package execution client listens on `0.0.0.0` inside its container with
`admin`, `engine`, `debug` and `txpool` enabled, and `nat_exit_ip` only controls
P2P advertisement. Docker publishes ports on every host interface by default.
For a dedicated local daemon, make new bridge networks bind on loopback in
`/etc/docker/daemon.json`, restart Docker and recreate the enclave:

```json
{
  "default-network-opts": {
    "bridge": {
      "com.docker.network.bridge.host_binding_ipv4": "127.0.0.1"
    }
  }
}
```

Confirm with `docker ps --format 'table {{.Names}}\t{{.Ports}}'` and `ss -ltnp`
that every published address is `127.0.0.1`. The start script's probe automates
the check. The URL in the deployment record says nothing about the bind
scope.

Finding from the 2026-08-25 run: the daemon default does reach the enclave
network (`docker network inspect kt-qrl2-stark` shows
`host_binding_ipv4=127.0.0.1`), but the qrl-package port publisher asks Docker
for explicit `0.0.0.0` host bindings on the execution ports (`HostIp` in the
container's `PortBindings`), and an explicit address always wins over the
network default. The start script's pre-start probe therefore passes while its
post-start verification fails, and the enclave is stopped. On a host whose
ingress is already controlled (this workstation: WSL2 in NAT mode, so the
ports are reachable from the Windows host only) start with
`STARK_ALLOW_WILDCARD_BIND=1`; on any other host, front the ports with a
firewall rule before acknowledging.

## Deploy, verify, measure

The same three commands serve both networks; only `STARK_CONFIG` (and the
account selector on Kurtosis) differ.

```bash
export HYPERION_COMPILER=../hyperion-stark/build/hypc/hypc

# developer node (the node signs with its developer account)
STARK_CONFIG=config/dev-node.json npm run deploy -- --preset all
STARK_CONFIG=config/dev-node.json npm run verify:proof -- --vector test/vectors/fib_c3_n12.json
STARK_CONFIG=config/dev-node.json npm run gas:report

# Kurtosis (published fixture account, loopback and chain 3151909 only)
STARK_CONFIG=config/local-stark.json STARK_PUBLIC_DEV_ACCOUNT=0 npm run deploy -- --preset all
STARK_CONFIG=config/local-stark.json npm run verify:proof -- --vector test/vectors/large/fib_c3_n20.json
STARK_CONFIG=config/local-stark.json npm run gas:report
```

`deploy` (`scripts/deploy.js`) asserts the chain id, compiles
`StarkVerifier.hyp` once per requested preset with the six preset constants
substituted (`--preset <name|all|none>`, default `c3`, the committed constants;
`scripts/lib/presets.js` carries the table of sixteen presets and the
substitution), refuses a runtime above 24,576 bytes, estimates gas with a 20
percent margin capped at the block gas limit, deploys the verifier and then
`StarkVerifierGasMeter(verifier)` with the 64-byte address appended raw to the
creation code, checks that code exists at each address and writes
`contracts.verifiers[<preset>] = { verifier, gasMeter, config, compiler: { version, runs, viaIr }, runtimeBytes, ... }`
into the record (presets from earlier runs are kept, the previous record moves
to `previousContracts`). `STARK_DEPLOY_BRIDGE=1` (or `--bridge`) adds
`StarkFactRegistry(verifier, programId)` and
`StateBridge(registry, programId, verifier, 0x00..00)` compiled through the IR
pipeline. It requires `--bridge-verifier` and `--bridge-program-id`, or the
equivalent `STARK_BRIDGE_VERIFIER` and `STARK_BRIDGE_PROGRAM_ID` environment
variables. The verifier must have code and return 128 from
`publicValuesLength()`, and its `programIdentifier()` must equal the requested
program id. The Fibonacci verifiers return 24 and cannot back the bridge.
Bridge-only mode selects `--preset none` automatically; pass an explicit preset
to deploy Fibonacci benchmark verifiers in the same run. The deployment is
recorded under `contracts.bridge`.

All named FRI presets are experimental benchmark profiles. Deployment on chain
1337 and the QuantaStark Kurtosis chain 3151909 is enabled by default. Another
chain requires `--allow-experimental-soundness` or
`STARK_ALLOW_EXPERIMENTAL_SOUNDNESS=1` for benchmark verifiers or the bridge
skeleton; see `docs/SECURITY-STATUS.md`.

`verify:proof` (`scripts/verify-proof.js`) derives the preset from the vector's
`config`, picks that verifier and gas meter from the record, hand-encodes
`verify(bytes,bytes)` and `verifyAndLog(bytes,bytes)` with the 64-byte-word ABI,
and prints the calldata size and calldata gas, `qrl_estimateGas` of a direct
`verify` transaction, the `qrl_call` result, the transaction hash, the receipt
`gasUsed`, the inner gas from the `Verified` event and the `ok` flag. It exits
with status 1 when the outcome differs from the vector's expectation (a valid
vector rejected, a mutated vector accepted). A proof above the transaction-pool
cap is simulated with a `qrl_call` of `verifyAndLog` and reported as such.

`gas:report` (`scripts/gas-report.js`) measures every valid vector under
`test/vectors/` and `test/vectors/large/` through the gas meter of its preset
(one discarded warm-up call per meter, so the receipts are steady-state
numbers), computes the plan's gas model from the vector's exact layout, and
regenerates `docs/GAS-REPORT.md`. Measurements are stored per optimizer setting
in `build/gas-report/<label>.json` (the label comes from the compiler settings
recorded by `deploy`), so the three-setting comparison is produced by
deploying and measuring three times:

```bash
HYPERION_OPTIMIZE_RUNS=1000000 STARK_CONFIG=config/dev-node.json npm run deploy -- --preset all
STARK_CONFIG=config/dev-node.json npm run gas:report
HYPERION_VIA_IR=1 STARK_CONFIG=config/dev-node.json npm run deploy -- --preset all
STARK_CONFIG=config/dev-node.json npm run gas:report
STARK_CONFIG=config/dev-node.json npm run deploy -- --preset all      # runs 200, the primary tables
STARK_CONFIG=config/dev-node.json npm run gas:report
npm run gas:report -- --render-only                                    # re-render without a node
```

## Prerequisites and offline notes

`cargo`, `go`, `node` 20 or newer, `jq`, `kurtosis` 1.20 and Docker. `z3` is
optional (a formal gate would need a separate Z3-enabled hypc build). The first
`cargo build` needs network access for the Plonky3 crates and the first
`make gqrl` for the Go toolchain download; both happen in M0/M1 and
`Cargo.lock` is committed so later builds are reproducible.
