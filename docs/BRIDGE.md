# Fact registry and bridge skeleton

Milestone M8: the L1 side of a validity rollup on QRL 2.0, reduced to the
pieces that depend on the STARK verifier and on the post-quantum precompiles.
`StarkFactRegistry` turns a verified proof into a storage fact keyed by its
public values; `StateBridge` consumes those facts to advance a state root,
accepts deposits into an append-only accumulator, and pays withdrawals that
carry a Merkle inclusion proof and an ML-DSA-87 signature checked through the
`mldsa87verify` builtin (precompile `0x03`) over a `shake256` digest
(precompile `0x06`). Everything is high-level Hyperion without inline assembly.

| File                                            | Role                                                            |
| ----------------------------------------------- | --------------------------------------------------------------- |
| `contracts/hyperion/StarkFactRegistry.hyp`      | Deployable. Implements `IStarkFactRegistry`.                    |
| `contracts/hyperion/bridge/StateBridge.hyp`     | Deployable skeleton. Verifier-agnostic through the registry.    |
| `contracts/hyperion/test/MockStarkVerifier.hyp` | Test double that accepts allow-listed proof hashes.             |
| `test/contracts/bridge.test.js`                 | Chain-bound suite (needs `STARK_RPC_URL`).                      |
| `test/lib/mldsa.js`                             | Keypair, signing, digest and precompile frame helpers.          |
| `test/lib/merkle-simple.js`                     | Plain binary keccak256 Merkle tree and the bridge leaf hashing. |

Status: tested on the gqrl dev node (chain 1337) against `MockStarkVerifier`.
The demo case that wires the real `StarkVerifier` skips itself while the
verifier still reverts `NotImplemented()` (milestone M6) and activates on its
own afterwards.

## StarkFactRegistry

```
constructor(address verifier_, bytes32 programId_)      // both immutable
registerFact(bytes proof, bytes publicValues) returns (bytes32 fact)
isValid(bytes32 fact) returns (bool)
factKey(bytes32 publicValuesHash) returns (bytes32)
verifier() / programId()
event FactRegistered(bytes32 indexed fact, bytes32 indexed publicValuesHash, bytes32 proofId)
```

`registerFact` calls `IStarkVerifier(verifier).verify(proof, publicValues)`
and reverts with `InvalidProof()` when it returns false. A verifier revert
(malformed proof, custom error) propagates unchanged, so callers see the
verifier's own selector. On success it stores

```
fact = keccak256(abi.encodePacked(address(verifier), programId, keccak256(publicValues)))
```

a 128-byte preimage (64-byte address, 32-byte program id, 32-byte hash) and
emits `FactRegistered` with `proofId = keccak256(proof)`. Registering the same
public values twice is allowed and idempotent.

`programId` names the AIR and its parameter set (`keccak256("fibonacci-c3-v1")`
style); together with the verifier address it pins which code checked the
proof, so a fact from one deployment can never satisfy a consumer bound to
another verifier or program.

### Facts are keyed by public values

The proof bytes never enter the key. A serialized proof contains bytes the
verifier never observes: a proof-of-work witness is skipped entirely at zero
PoW bits, and the sibling values of duplicate query openings are free. Many
distinct byte strings therefore verify the same statement, which makes
`keccak256(proof)` malleable. `proofId` is a diagnostic that matches what the
gas meter and the vector files report; it must never be used as an identity.

## StateBridge

```
constructor(address registry_, bytes32 programId_, address verifier_, bytes32 genesisRoot)
stateRoot() batchIndex() depositCount() depositAccumulator() withdrawn(bytes32)
submitBatch(bytes32 prevRoot, bytes32 newRoot, bytes publicValues, bytes proof)
deposit() payable
withdraw(bytes32 pkHash, address recipient, uint512 amount, uint512 nonce,
         bytes32[] merkleProof, uint512 leafIndex, bytes signature, bytes publicKey)
expectedFact(bytes32 publicValuesHash) returns (bytes32)
withdrawDigest(bytes32 leaf, address recipient) returns (bytes64)
verifyWithdrawSignature(bytes32 leaf, address recipient, bytes signature, bytes publicKey) returns (bool)
encodesRoots(bytes publicValues, bytes32 prevRoot, bytes32 newRoot) returns (bool)
verifyInclusion(bytes32 leaf, bytes32[] merkleProof, uint512 leafIndex, bytes32 root) returns (bool)
receive() payable
event BatchSubmitted(uint512 indexed batchIndex, bytes32 prevRoot, bytes32 newRoot, bytes32 fact)
event Deposited(uint512 indexed index, address indexed sender, uint512 amount, bytes32 leaf)
event Withdrawn(bytes32 indexed leaf, address indexed recipient, uint512 amount)
```

`batchIndex` and `depositCount` are counters: the index the next batch or
deposit receives. The events carry the zero-based index of the accepted item.

### submitBatch

1. `prevRoot == stateRoot`, else `StaleRoot()`.
2. `publicValues` must be the canonical encoding of `(prevRoot, newRoot)`,
   else `BadPublicValues()`: exactly 128 bytes, 16 Goldilocks elements of 8
   bytes little-endian. Element `i` is limb `i` of `prevRoot`, element `8 + i`
   is limb `i` of `newRoot`, where limb `i` is bytes `4i .. 4i+3` of the root
   read as a big-endian 32-bit integer. Every element must be below `2^32`,
   which keeps the encoding far inside the Goldilocks field.
3. `fact = keccak256(abi.encodePacked(verifier, programId, keccak256(publicValues)))`,
   the same key the registry derives. If `registry.isValid(fact)` the proof
   bytes are ignored (they may be empty); otherwise
   `registry.registerFact(proof, publicValues)` runs and its revert propagates.
   A registry bound to another verifier or program would return a different
   key, which reverts with `FactMismatch()`.
4. `stateRoot = newRoot`, `batchIndex += 1`, `BatchSubmitted`.

### deposit

`leaf = keccak256(abi.encodePacked(msg.sender, uint512(msg.value), depositCount))`
(64 + 64 + 64 bytes), `depositAccumulator = keccak256(abi.encodePacked(depositAccumulator, leaf))`,
`depositCount += 1`, `Deposited`. The accumulator lets an L2 batch prove it
consumed the deposits in order; wiring it into the public values is part of
the real L2 design and out of scope here.

### withdraw

`leaf = keccak256(abi.encodePacked(pkHash, recipient, amount, nonce))`
(32 + 64 + 64 + 64 bytes). Checks run in this order:

| Check                                                           | Error                |
| --------------------------------------------------------------- | -------------------- |
| `keccak256(publicKey) == pkHash`                                | `WrongKey()`         |
| `leaf` included under `stateRoot` at `leafIndex`                | `NotIncluded()`      |
| leaf not yet paid                                               | `AlreadyWithdrawn()` |
| `mldsa87verify(digest, signature, publicKey, "QP-WITHDRAW-v1")` | `BadSignature()`     |
| `amount` fits a `uint256` and the value call succeeds           | `TransferFailed()`   |

The leaf is marked spent before the transfer (checks, effects, interactions),
so a reentrant `withdraw` from the recipient hits `AlreadyWithdrawn()`.
`receive()` accepts plain transfers so the pool can be funded.

### Withdrawal signature convention

```
message   = "QP-WITHDRAW-v1" || leaf (32 bytes) || recipient (64 bytes)      // 110 bytes
digest    = shake256(message)                                                // 64 bytes, precompile 0x06
signature = ML-DSA-87.Sign(sk, M = digest, ctx = "QP-WITHDRAW-v1")           // FIPS 204, 4627 bytes
```

The digest bytes are the ML-DSA-87 message; nothing hashes them again on
either side. The same string serves as the message prefix and as the FIPS 204
context, so a signature produced for any other purpose (QNS uses
`QNS-SIGN-v1`, transactions have their own domain) can never authorise a
withdrawal. `test/lib/mldsa.js` mirrors the QNS SDK and its
`verify-pq-precompiles.js` script with `@theqrl/mldsa87`:

```js
cryptoSignSignature(signature, digest, secretKey, /* randomized */ false, utf8('QP-WITHDRAW-v1'));
cryptoSignVerify(signature, digest, publicKey, utf8('QP-WITHDRAW-v1'));
```

Precompile `0x03` (and the `mldsa87verify` builtin, which packs the frame for
the contract) consumes

```
digest (64) || publicKey (2592) || signature (4627) || uint8(len(ctx)) || ctx
```

7298 bytes for the 14-byte context, and answers with the 64-byte word
`0x00..01` on success. Failure is empty return data on the current node (a
canonical zero word is the other convention under protocol review); the
builtin maps both to `false`. The suite confirms the convention three ways in
one run: the library's own verifier accepts the signature, the frame sent to
`0x03` by hand returns the success word (and a flipped byte returns empty
data), and the contract's `withdrawDigest` and `verifyWithdrawSignature` views
agree with the JS values before `withdraw` pays out.

### Withdrawal tree

Plain binary keccak256 Merkle tree over 32-byte leaves:
`parent = keccak256(left || right)`, with bit `i` of `leafIndex` selecting the
side of the node at level `i` (0 = left). Trees are padded with zero leaves to
a power of two. An index with set bits above the proof length is rejected, so
a leaf cannot be presented under a second index. `test/lib/merkle-simple.js`
is the JS reference; it is separate from the pruned multi-opening Merkle code
of the STARK verifier.

## Simplifications and scope

- The state root is used directly as the root of the withdrawal tree. A real
  L2 commits a withdrawal subtree inside its state root and the inclusion
  proof walks through that subtree.
- Deposits are recorded (accumulator plus events) and left for the L2 program
  to consume; the bridge does not yet require a batch to account for them.
- No escape hatch, challenge window, forced inclusion, sequencer or operator
  roles, pausing, upgradeability or fee handling. Anyone can submit a batch
  that carries a valid proof.
- The bridge trusts that the registry's verifier and program id match its own
  immutables; `FactMismatch()` catches a misconfiguration at the first batch.
- Call values are `uint256` on this VM (`msg.value` and `call{value:}`), so a
  withdrawal amount above `2^256 - 1` reverts with `TransferFailed()`; the
  check runs on the full 512-bit amount before the call, so nothing is
  truncated.

## Gas (gqrl dev node, chain 1337, receipt `gasUsed`)

| Operation                                                    | Gas     |
| ------------------------------------------------------------ | ------- |
| `registerFact` through `MockStarkVerifier` (96-byte proof)   | 58,555  |
| `submitBatch`, fact registered in the same transaction       | 155,618 |
| `submitBatch`, fact already registered, empty proof          | 103,457 |
| `deposit`                                                    | 68,800  |
| `withdraw` (4-leaf tree, 4627-byte signature, 2592-byte key) | 345,791 |

`withdraw` is dominated by the 125,000-gas ML-DSA-87 precompile and the
7.3 KB of signature and key calldata (16 gas per non-zero byte). With a real
verifier, `registerFact` costs the verifier's own gas on top of the 58k shown
here; `docs/GAS-REPORT.md` carries those numbers once M6 and M7 land.

## Tests

```bash
STARK_RPC_URL=http://127.0.0.1:8545 HYPERION_COMPILER=../hyperion-stark/build/hypc/hypc \
  node --test test/contracts/bridge.test.js
```

One top-level test deploys mock, registry and bridge once and runs twelve
cases: constructor state and zero-address guards; fact registration (accepted
proof, rejected proof, propagated verifier revert, idempotent re-registration
under a second proof); JS and on-chain fact keys; `submitBatch` happy path
with both events; the lookup path with an empty proof; every `submitBatch`
revert (stale root, short and long public values, an element at `2^32`, a
`newRoot` that disagrees with the encoding, a `prevRoot` encoding that
disagrees with the state, a flipped limb, an unproven batch, a reverting
verifier); deposits (leaf, accumulator, events, balance); a withdrawal with a
freshly generated ML-DSA-87 key and a four-leaf tree; replay; wrong signature
(flipped byte, another leaf, another context, another signer, a signature
over the raw message bytes), wrong recipient, amount, nonce, index, sibling
order, proof length and public key, followed by a successful withdrawal of the
untouched leaf; a legacy-code-generator canary; and the real-verifier demo.

## Toolchain notes (hypc `0.2.0-develop.2026.8.25+commit.cf176678`)

Two defects of the legacy code generator (the default pipeline, used unless
`--via-ir` is set) surfaced while testing. The IR pipeline compiles the same
sources correctly, so the bridge suite compiles with `viaIr: true` and a
canary case (`canary: StateBridge built with the legacy code generator`)
skips while the first defect is present and turns into a real check once it
is fixed. Deploy `StateBridge` from a `HYPERION_VIA_IR=1 npm run compile`
build until then.

1. `mldsa87verify` receives its Yul helper arguments in reverse order. The
   legacy path (`libhyperion/codegen/ExpressionCompiler.cpp`, case
   `FunctionType::Kind::MLDSA87Verify`) pushes `digest, signature, publicKey,
context` in declaration order, then the free memory pointer, and calls
   `mldsa87_verify(digest, signature, publicKey, context, pos)` through
   `callYulFunction`, which expects the first Yul parameter on top of the
   stack. The helper therefore sees `digest = pos`, `signature = context`,
   `context = signature` and `pos = digest`; its length check fails and the
   fallback `mstore8(pos, 0)` writes at a 512-bit offset, which the node
   rejects with `gas uint64 overflow` (`debug_traceCall` stops on that
   `MSTORE8`). Every legacy-compiled contract that uses the builtin is
   affected, including the QNS `QRLSignatureVerifier`. Fix: push the
   arguments last to first with the memory pointer first, or reverse the top
   five stack items before the call. The IR generator
   (`IRGeneratorForStatements.cpp`) passes the arguments by name and is
   correct.
2. Auto-generated getters of public mappings with `bytes32` or `address` keys
   read a different storage slot than contract code (`uint512` keys agree).
   `mapping(bytes32 => bool) public flags; flags[k] = true;` leaves
   `flags(k)` returning `false` while an explicit `return flags[k];` returns
   `true`. The IR pipeline agrees in all cases. The bridge contracts keep
   their mappings internal and expose explicit views (`isValid`, `withdrawn`,
   `isAccepted`), which keeps the ABI stable under both pipelines.

Both defects reproduce with the scratch contracts described above on the
dev node; neither affects the `shake256` builtin, custom errors, events, ABI
encoding of 64-byte addresses or `abi.encodePacked`, all of which behaved as
documented in this milestone.
