# Toolchain

How the compiler, the execution client and the two local networks are built and
used. Everything here is relative to the collection root that holds this
repository and its sibling checkouts (`go-qrl`, `hyperion`, `qrl-package`).

## Worktrees and snapshot commits

The QNS precompile alignment (ML-DSA-87 verify at `0x03` with a 64-byte digest,
SHAKE256 at `0x06`) is uncommitted in the `go-qrl` and `hyperion` checkouts
while it waits for review and a QIP. QuantaProof never touches those trees. It
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

Every compile passes the binary explicitly:

```bash
HYPERION_COMPILER=../hyperion-stark/build/hypc/hypc npm run compile
```

`npm run compile` runs `scripts/compile-hyperion.js` (ABI, `.bin`,
`.bin-runtime`, `build/hyperion/manifest.json` with `compilerVersion` and
`plonky3Version`) followed by `scripts/check-code-size.js`. The contract test
suite compiles harnesses through `scripts/hypc.js` (standard JSON) with the
same binary. The system-wide `hypc` predates the 64-byte word: never use it, and
never rely on `PATH`.

The compiler build fixes the word width and the precompile slots behind the
`shake256` and `mldsa87verify` builtins, which is why the manifest records the
exact version string.

## Execution client: gqrl from go-qrl-stark

```bash
(cd go-qrl-stark && GOTOOLCHAIN=auto make gqrl)
go-qrl-stark/build/bin/gqrl version
```

`go.mod` asks for a newer Go than most hosts carry; `GOTOOLCHAIN=auto` downloads
it on first use. The same source builds the Docker image for Kurtosis.

## Fast path: the gqrl developer node

`scripts/dev-node.sh` (also `npm run dev-node`) starts:

```text
gqrl --dev --dev.period 0 --dev.gaslimit 20000000 --nodiscover --ipcdisable \
     --http --http.addr 127.0.0.1 --http.port 8545 --http.api qrl,net,web3,debug \
     --http.vhosts localhost --verbosity 3 --datadir build/dev-node
```

Facts about this mode, verified in the client source:

- chain id 1337 (`--networkid` is left at the developer default);
- one developer account created in the keystore of the data directory,
  unlocked with an empty passphrase and pre-funded in the developer genesis;
  `qrl_accounts` returns it and `qrl_sendTransaction` lets the node sign;
- `--dev.period 0` seals a block as soon as a transaction is pending, through a
  simulated beacon; no validator or beacon process is involved;
- `--dev.gaslimit` sets the genesis gas limit. It applies only when the data
  directory is created; an existing chain keeps its own genesis, so delete
  `build/dev-node` to reset;
- developer mode disables discovery, dialing and listening by itself;
  `--nodiscover` is kept explicit;
- `--ipcdisable` is mandatory: gqrl otherwise fails with
  `listen unix ...gqrl.ipc: bind: invalid argument` when the data directory
  path is long;
- the default HTTP modules are `net,web3`, so `qrl` and `debug` are requested
  explicitly;
- the precompile stubs `0x01` to `0x06` are pre-allocated in the developer
  genesis.

Validated on 2026-08-25: `qrl_chainId` returns `0x539`, the developer account
is funded, a transfer seals in well under a second, the latest block reports
`gasLimit 0x1312d00` (20,000,000), and the `0x05` and `0x06` precompiles answer.

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

## Release gate: the Kurtosis composition

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

|                   | QNS                        | QuantaProof                |
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
the check but the URL in the deployment record is never evidence of the bind
scope.

## Deploy, verify, measure

```bash
HYPERION_COMPILER=../hyperion-stark/build/hypc/hypc npm run compile
STARK_CONFIG=config/local-stark.json STARK_PUBLIC_DEV_ACCOUNT=0 npm run deploy
STARK_CONFIG=config/local-stark.json npm run verify:proof -- --vector test/vectors/fib_c3_n20.json
STARK_CONFIG=config/local-stark.json npm run gas:report
```

`deploy` asserts the chain id, estimates gas with a 20 percent margin capped at
the block gas limit, deploys `StarkVerifier` then `StarkVerifierGasMeter(verifier)`
with the 64-byte address appended raw to the creation code, checks that code
exists at each address, and writes the addresses back (the previous set moves
to `previousContracts`). `verify:proof` hand-encodes `verifyAndLog(bytes,bytes)`
with the 64-byte-word ABI, prints the transaction hash, `gasUsed` and the
decoded `Verified` event, and runs a `qrl_call` of `verify(bytes,bytes)`.
`gas:report` repeats that for every vector and regenerates `docs/GAS-REPORT.md`.

## Prerequisites and offline notes

`cargo`, `go`, `node` 20 or newer, `jq`, `kurtosis` 1.20 and Docker. `z3` is
optional (a formal gate would need a separate Z3-enabled hypc build). The first
`cargo build` needs network access for the Plonky3 crates and the first
`make gqrl` for the Go toolchain download; both happen in M0/M1 and
`Cargo.lock` is committed so later builds are reproducible.
