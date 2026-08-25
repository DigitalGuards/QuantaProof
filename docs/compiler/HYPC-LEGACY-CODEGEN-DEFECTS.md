# Legacy code generator defects in hypc 0.2.0-develop.2026.8.25+commit.cf176678

Independent verification of the two defects reported in `docs/BRIDGE.md`
("Toolchain notes"). Both are confirmed on the gqrl dev node (chain 1337) with
standalone contracts, and both are localized in the compiler source. The IR
pipeline (`--via-ir`) is correct in every case tested here.

| Defect                                                                    | Legacy pipeline                                                                             | `--via-ir` | At `f55de24d`                                                        | Upstream `origin/main` (`f570687a`)             |
| ------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------- | ---------- | -------------------------------------------------------------------- | ----------------------------------------------- |
| 1. `mldsa87verify` hands its arguments to the Yul helper in reverse order | confirmed: every call with a non-zero digest dies with `gas uint64 overflow`                | correct    | different code, the builtin went through the generic precompile path | builtin absent                                  |
| 2. Public mapping getters hash only the low 256 bits of the key           | confirmed for `bytes32`, `address`, `uint512` keys at or above `2^256`, `int256` below zero | correct    | present, same lines                                                  | present, same lines (`VMWordBytes` is 64 there) |

Files next to this document:

| File                     | Role                                                                          |
| ------------------------ | ----------------------------------------------------------------------------- |
| `MldsaVerifyRepro.hyp`   | Defect 1: the builtin next to a hand-built `staticcall` to precompile `0x03`. |
| `MappingGetterRepro.hyp` | Defect 2: four public mappings with explicit setters and views.               |
| `repro.js`               | Compiles both files with both pipelines, deploys and prints every result.     |

## How the reproductions were run

Compiler: `../hyperion-stark/build/hypc/hypc` (the `HYPERION_COMPILER` of
`.env.example`), reporting `0.2.0-develop.2026.8.25+commit.cf176678`. Node:
gqrl `--dev` at `http://127.0.0.1:8545`, chain `1337`, sender `qrl_accounts()[0]`
through `qrl_sendTransaction`. Deployment and calls go through
`test/lib/harness.js` (`deployArtifact`, `encodeArgs`, `decodeReturn`) and
`test/lib/mldsa.js` (keypair, SHAKE256 digest, signing with a context).

```bash
# Each file, both pipelines (the driver runs exactly these flags):
../hyperion-stark/build/hypc/hypc --bin --abi --optimize docs/compiler/MldsaVerifyRepro.hyp
../hyperion-stark/build/hypc/hypc --bin --abi --optimize --via-ir docs/compiler/MldsaVerifyRepro.hyp
../hyperion-stark/build/hypc/hypc --bin --abi --optimize docs/compiler/MappingGetterRepro.hyp
../hyperion-stark/build/hypc/hypc --bin --abi --optimize --via-ir docs/compiler/MappingGetterRepro.hyp

# Deploy and call everything (from the repository root):
STARK_RPC_URL=http://127.0.0.1:8545 HYPERION_COMPILER=../hyperion-stark/build/hypc/hypc \
  node docs/compiler/repro.js               # both defects, both pipelines
node docs/compiler/repro.js mldsa legacy    # one defect, one pipeline
```

All four compilations succeed with only the pre-release warning. The outputs
below are the driver's console lines, condensed into tables.

## Defect 1: `mldsa87verify` argument order (legacy pipeline)

### Reproduction

`MldsaVerifyRepro.hyp` exposes the builtin and a hand-built precompile call:

```solidity
function verifyBuiltin(bytes64 digest, bytes memory signature, bytes memory publicKey, bytes memory context)
    external pure returns (bool)
{
    return mldsa87verify(digest, signature, publicKey, context);
}

function verifyRaw(bytes64 digest, bytes memory signature, bytes memory publicKey, bytes memory context)
    external view returns (bool ok, bytes memory returnData)
{
    bytes memory frame = abi.encodePacked(digest, publicKey, signature, uint8(context.length), context);
    (bool success, bytes memory out) = address(3).staticcall(frame);
    require(success, "precompile call failed");
    ok = out.length == 64 && uint512(bytes64(out)) == 1;
    returnData = out;
}
```

The driver derives a deterministic ML-DSA-87 keypair (32-byte seed of `0x01`),
hashes the message `QuantaStark hypc legacy codegen repro` with SHAKE256 to a
64-byte digest, signs the digest with the FIPS 204 context `QP-REPRO-v1`, and
checks the signature offline first (`verifyDigest` true; a flipped first byte
false). `digestOf(message)` on chain equals the JS digest under both pipelines.

| Call                                        | Legacy build                    | `--via-ir` build   |
| ------------------------------------------- | ------------------------------- | ------------------ |
| `verifyRaw(digest, signature, pk, ctx)`     | `(true, 0x00..01)`              | `(true, 0x00..01)` |
| `verifyRaw(digest, flipped, pk, ctx)`       | `(false, 0x)`                   | `(false, 0x)`      |
| `verifyBuiltin(digest, signature, pk, ctx)` | `qrl_call: gas uint64 overflow` | `true`             |
| `verifyBuiltin(digest, flipped, pk, ctx)`   | `qrl_call: gas uint64 overflow` | `false`            |

The raw frame sent to precompile `Q..03` from the legacy-compiled contract
returns the success word, so the precompile, the ABI encoding of the 64-byte
`bytes64` argument, `abi.encodePacked` and `staticcall` are all fine under
legacy codegen. Only the builtin fails.

Fingerprint of the argument order. The legacy helper uses the digest as its
memory position, so the cost of the call follows the numeric value of the
digest, and a zero digest "succeeds" with `false`:

| `verifyBuiltin` digest argument       | Legacy result / `qrl_estimateGas` | `--via-ir` result / `qrl_estimateGas` |
| ------------------------------------- | --------------------------------- | ------------------------------------- |
| `bytes64(0)`                          | `false` / 267,807                 | `false` / 275,930                     |
| `bytes64(uint512(0x10000))`           | `false` / 272,555                 | `false` / 275,942                     |
| `bytes64(uint512(0x100000))`          | `false` / 840,995                 | `false` / 275,942                     |
| real digest (`0x8c09c856...57bf9ff1`) | `gas uint64 overflow`             | `true` / 276,698                      |

`debug_traceCall` of the legacy call with the real digest stops after 448
steps at `MSTORE8` (pc 1185) with `gas uint64 overflow`; the top of the stack
at that opcode, the `MSTORE8` offset, is the digest word itself:
`0x8c09c8561d817ad0...2f3286457bf9ff1`.

### Root cause

`libhyperion/codegen/ExpressionCompiler.cpp:1076-1084` (paths are relative to
the hyperion checkout, line numbers from `cf176678`):

```cpp
case FunctionType::Kind::MLDSA87Verify:
{
    hypAssert(arguments.size() == function.parameterTypes().size(), "");
    for (size_t i = 0; i < arguments.size(); ++i)
        acceptAndConvert(*arguments[i], *function.parameterTypes()[i]);
    utils().fetchFreeMemoryPointer();
    m_context.callYulFunction(m_context.utilFunctions().mldsa87VerifyFunction(), 5, 1);
    break;
}
```

The stack after those pushes is `digest signature publicKey context pos`
(bottom to top). The helper is declared at
`libhyperion/codegen/YulUtilFunctions.cpp:4118` as
`function mldsa87_verify(digest, signature, publicKey, context, pos) -> result`.

`CompilerContext::callYulFunction` (`libhyperion/codegen/CompilerContext.cpp:139-150`)
only pushes the return tag, moves it below the `_inArgs` items
(`CompilerUtils::moveIntoStack(_inArgs)`) and jumps; it never reorders the
arguments. The Yul-to-QRVM transform defines the calling convention:

- at a call, `libyul/backends/qrvm/QRVMCodeTransform.cpp:253-254` visits the
  arguments in reverse (`_call.arguments | ranges::views::reverse`), so the
  first argument ends up on top of the stack;
- at function entry, `QRVMCodeTransform.cpp:370-374` assigns stack heights to
  `_function.parameters | ranges::views::reverse`, so the last parameter sits
  right above the return label and the first parameter is the topmost item.

The helper therefore expects `pos context publicKey signature digest` (bottom
to top) and receives the exact reverse. Inside the helper `digest := pos`,
`signature := context`, `publicKey := publicKey` (the middle item is the only
one that lands correctly), `context := signature` and `pos := digest`. The
length check `eq(mload(signature), 4627)` sees the context length and fails,
so the helper takes its `case 0` branch and executes `mstore8(pos, 0)` with
`pos` equal to the digest word (`YulUtilFunctions.cpp:4128-4131`). A real
digest is a 512-bit number, the memory expansion overflows and the node
reports `gas uint64 overflow`. A zero digest writes at offset 0, calls the
precompile with a one-byte frame and returns `false`, which is the
fingerprint above.

The neighbouring builtins show the two conventions the legacy pipeline uses:

- `SHA256`, `SHAKE256`, `DepositRoot` (`ExpressionCompiler.cpp:1086-1099`)
  push the precompile address, swap it under the function item and go through
  `appendExternalFunctionCall`, which lays out the stack itself.
- `KECCAK256` (`ExpressionCompiler.cpp:899-925`) uses `packedEncode` and the
  opcode directly.
- The one comparable `callYulFunction` site with several parameters,
  `calldataArrayIndexRangeAccess` (`ExpressionCompiler.cpp:2290-2310`), swaps
  its operands until the first Yul parameter is on top (`stack: sliceEnd
sliceStart length offset` for `(offset, length, startIndex, endIndex)`)
  before calling. The `MLDSA87Verify` case skips that step.

The IR generator (`libhyperion/codegen/ir/IRGeneratorForStatements.cpp:1618-1628`)
emits `mldsa87_verify(<arg0>, <arg1>, <arg2>, <arg3>, allocate_unbounded())`
by name and is correct.

Legacy assembly of `verifyBuiltin` (`hypc --asm --optimize`), showing the
push order and the plain `moveIntoStack` before the jump into the helper:

```
tag_9:
  0x00            // return slot
  dup5            // digest
  dup5            // signature
  dup5            // publicKey
  dup5            // context
  mload(0x80)     // free memory pointer
  tag_24          // return tag
  swap5
  swap4
  swap3
  swap2
  swap1
  tag_25          // mldsa87_verify
  jump  // in
```

### Presence at `f55de24d` and upstream

- `f55de24d` (`git show f55de24d:libhyperion/codegen/ExpressionCompiler.cpp`,
  lines 1076-1095): the `MLDSA87Verify` case does not exist. The kind shares
  the `SHA256`/`SHAKE256` branch with the address map
  `{SHAKE256, 3}, {MLDSA87Verify, 6}` and goes through
  `appendExternalFunctionCall` with a packed argument frame. That is a
  different legacy path (the addresses are the reverse of the node's
  `0x03` = ML-DSA-87 and `0x06` = SHAKE256, and the frame carries no context
  length byte); the specific reversed-stack defect is introduced by
  `cf176678`, which added the dedicated case together with the Yul helper.
  `YulUtilFunctions.cpp` at `f55de24d` has no `mldsa87_verify`.
- Upstream `origin/main` (`f570687a`): `git show origin/main:libhyperion/codegen/ExpressionCompiler.cpp`
  contains neither `MLDSA87Verify` nor `SHAKE256`; the builtins arrive with
  `f55de24d`. Not applicable.

### Would `test/libhyperion/semanticTests/builtinFunctions/mldsa87verify.hyp` catch it?

Yes, in the legacy run, once the suite is built and executed:

- The test (rewritten in `cf176678`; `f55de24d` had a two-case version) has
  no `compileViaYul` setting. `test/libhyperion/SemanticTest.cpp:93-102`
  defaults that setting to `also`, which selects both runs, and
  `SemanticTest::run` (`SemanticTest.cpp:325-329`) executes the legacy run
  first, then the IR run.
- `valid()` builds `bytes64(bytes1(0x42))` and expects `true`. Under legacy
  codegen the helper executes `mstore8(0x42 << 504, 0)`, the test VM runs out
  of gas and the expectation fails. `invalidSignature()`, `noncanonical()`,
  `canonicalFalse()` and `shortTrue()` use non-zero digests and fail the same
  way. `invalid()` and `oversizedContext()` pass by accident: their digest is
  zero, the helper writes at offset 0, sends a one-byte frame and the fixture
  precompile (`test/QRVMHost.cpp:436-479`, dispatch at `:178-188`) returns
  empty data, which decodes to the expected `false`.
- Build state: `hyperion-stark/build` contains no `hyptest`; the `hyptest` in
  the main `hyperion` checkout's `build/test` dates from 2026-08-22 and its
  `hypc` reports `commit.f570687a.mod`, so it predates the `cf176678` sources
  (2026-08-24). No `libevmone` (the `--vm` the semantic tests need) was found
  on this machine. The test has therefore never run against this code.

### Proposed patch (not applied)

Reverse the five items after evaluating the arguments, which keeps the
left-to-right evaluation order the IR pipeline uses:

```diff
--- a/libhyperion/codegen/ExpressionCompiler.cpp
+++ b/libhyperion/codegen/ExpressionCompiler.cpp
@@ -1076,9 +1076,15 @@ bool ExpressionCompiler::visit(FunctionCall const& _functionCall)
 		case FunctionType::Kind::MLDSA87Verify:
 		{
 			hypAssert(arguments.size() == function.parameterTypes().size(), "");
 			for (size_t i = 0; i < arguments.size(); ++i)
 				acceptAndConvert(*arguments[i], *function.parameterTypes()[i]);
 			utils().fetchFreeMemoryPointer();
+			// stack: digest signature publicKey context pos
+			// callYulFunction hands the stack to mldsa87_verify(digest, signature,
+			// publicKey, context, pos) with the first parameter on top, so reverse
+			// the five items before the call.
+			m_context << Instruction::SWAP4 << Instruction::SWAP1 << Instruction::SWAP3 << Instruction::SWAP1;
+			// stack: pos context publicKey signature digest
 			m_context.callYulFunction(m_context.utilFunctions().mldsa87VerifyFunction(), 5, 1);
 			break;
 		}
```

`SWAP4 SWAP1 SWAP3 SWAP1` maps `digest signature publicKey context pos` to
`pos context publicKey signature digest` (bottom to top). The equivalent
one-line alternative, `utils().fetchFreeMemoryPointer()` first and the
`acceptAndConvert` loop running from the last argument to the first, produces
the same layout and evaluates the arguments right to left, which differs from
the IR generator when arguments have side effects.

## Defect 2: public mapping getters with `bytes32` and `address` keys (legacy pipeline)

### Reproduction

`MappingGetterRepro.hyp` declares four public mappings, each with an explicit
setter and an explicit view:

```solidity
mapping(bytes32 => uint512) public byBytes32; // slot 0
mapping(address => uint512) public byAddress; // slot 1
mapping(uint512 => uint512) public byUint512; // slot 2
mapping(int256 => uint512) public byInt256; // slot 3

function setBytes32(bytes32 key, uint512 value) external { byBytes32[key] = value; }
function viewBytes32(bytes32 key) external view returns (uint512) { return byBytes32[key]; }
// same shape for the other three
```

The driver writes through the setters, reads through both the explicit view
and the auto-generated getter, and also reads the two candidate storage slots
with `qrl_getStorageAt`: `keccak256(key || slot)` over the full 64-byte key
word, and the same hash with the key masked to its low 256 bits.

| Step (`k` = `0x1111...11`, 32 bytes)                 | Legacy view | Legacy getter | `--via-ir` view | `--via-ir` getter |
| ---------------------------------------------------- | ----------- | ------------- | --------------- | ----------------- |
| `setBytes32(k, 7)`, then `k`                         | 7           | **0**         | 7               | 7                 |
| `setBytes32(bytes32(0), 99)`, then `k` again         | 7           | **99**        | 7               | 7                 |
| `setAddress(devAccount, 5)` (high 32 bytes non-zero) | 5           | **0**         | 5               | 5                 |
| `setAddress(Q00..00ab..ab, 6)` (high 32 bytes zero)  | 6           | 6             | 6               | 6                 |
| `setUint512(42, 8)`                                  | 8           | 8             | 8               | 8                 |
| `setUint512(2^256 + 42, 9)`, then `2^256 + 42`       | 9           | **8**         | 9               | 9                 |
| `setInt256(-1, 10)`, then `-1`                       | 10          | **0**         | 10              | 10                |

Storage reads under both builds agree with the views: `keccak256(k64 || 0)`
holds 7, `keccak256(low256(k) || 0)` holds 0 until `setBytes32(bytes32(0), 99)`
writes 99 there; `keccak256(devAccount || 1)` holds 5 and the masked slot 0;
`keccak256(0xff..ff || 3)` holds 10 and the masked slot 0. The legacy getter
returns exactly the masked slot in every row: the value stored under
`bytes32(0)`, under the address with its first 32 bytes zeroed, under
`uint512(42)` for the key `2^256 + 42`, and under `2^256 - 1` for `-1`.

So the report's "`uint512` keys fine" holds only for keys below `2^256`. The
getter is wrong for every key whose 64-byte word has a non-zero high half:
`bytesN` (left-aligned), `address` (64 bytes), `uint512` at or above `2^256`,
and negative signed integers (sign-extended to 512 bits).

### Root cause

The getter (`libhyperion/codegen/ExpressionCompiler.cpp:180-193`, in
`appendStateVariableAccessor`) hashes `key || slot` through
`CompilerUtils::storeInMemory`:

```cpp
// move storage offset to memory.
utils().storeInMemory(VMWordBytes);
// move key to memory.
utils().copyToStackTop(static_cast<unsigned>(paramTypes.size() - i), 1);
utils().storeInMemory(0);
m_context << u256(2 * VMWordBytes) << u256(0);
m_context << Instruction::KECCAK256;
```

`CompilerUtils::storeInMemory` (`libhyperion/codegen/CompilerUtils.cpp:196-201`)
is the 32-bit-era "store a 256 bit integer" helper, unchanged by the 64-byte
port:

```cpp
void CompilerUtils::storeInMemory(unsigned _offset)
{
	unsigned numBytes = prepareMemoryStore(*TypeProvider::uint256(), true);
	if (numBytes > 0)
		m_context << u256(_offset) << Instruction::MSTORE;
}
```

`prepareMemoryStore` defaults `_cleanup` to `true`
(`libhyperion/codegen/CompilerUtils.h:317`) and calls
`convertType(uint256, uint256, true)` (`CompilerUtils.cpp:1646`). For an
integer-to-integer conversion with cleanup forced, `convertType` reaches
`cleanHigherOrderBits(targetType)` (`CompilerUtils.cpp:931`), and
`cleanHigherOrderBits` (`CompilerUtils.cpp:1602-1610`) emits
`AND (2^256 - 1)` because 256 differs from `VMWordBits` (512,
`libhyputil/VMConstants.h:32-34`). The key word loses its high 256 bits before
it is hashed. With a 32-byte word the same call was a no-op, which is why the
helper looked harmless.

Key layouts in the 64-byte word (`libhyperion/ast/Types.h`, `VMConstants.h`):
`bytesN` is left-aligned (`FixedBytesType::leftAligned`), `address` fills the
word (`AddressBits = 512`, `VMConstants.h:43-45`), `uint512` fills the word,
signed integers are sign-extended. Only right-aligned values below `2^256`
survive the mask, which is why `uint256`-sized keys, enums, booleans and small
`uint512` keys agree between the two paths.

The write path (`IndexAccess`, `ExpressionCompiler.cpp:2183-2191`) never uses
`storeInMemory`:

```cpp
m_context << u256(0); // memory position
appendExpressionCopyToMemory(*keyType, *_indexAccess.indexExpression());
m_context << Instruction::SWAP1;
utils().storeInMemoryDynamic(*TypeProvider::uint256());
m_context << u256(0);
m_context << Instruction::KECCAK256;
```

`appendExpressionCopyToMemory` (`ExpressionCompiler.cpp:2879-2884`) converts
the key to the mapping's key type and calls `storeInMemoryDynamic(keyType)`,
so `prepareMemoryStore` cleans the value with the key's own type: a `bytes32`
mask keeps the high 32 bytes, an `address` or `uint512` mask is a no-op, and
`MSTORE` writes the full word (`CompilerUtils.cpp:1625-1655`; the shift only
applies for unpadded stores). The slot is stored with
`storeInMemoryDynamic(uint256)`, which is harmless because slots come from
the `KECCAK256` opcode or small constants and stay below `2^256`. Both
paths hash the same 128-byte preimage `key || slot`; they differ only in the
mask applied to the key. The getter reads calldata that the ABI decoder has
already validated, so it needs no cleanup at all.

The IR pipeline uses one function for both the getter
(`libhyperion/codegen/ir/IRGenerator.cpp:520`, `:630`) and index access
(`IRGeneratorForStatements.cpp:2260`):
`YulUtilFunctions::mappingIndexAccessFunction` (`YulUtilFunctions.cpp:2684`),
which stores the key converted with its own type at 0, the slot at 64 and
hashes 128 bytes. That matches the legacy write path and the storage reads
above.

### Presence at `f55de24d` and upstream

- `f55de24d`: identical getter lines (`ExpressionCompiler.cpp:186` and `:190`)
  and identical `storeInMemory` (`CompilerUtils.cpp:198`). Present.
- Upstream `origin/main` (`f570687a`): identical getter lines (`:186`, `:190`),
  identical `storeInMemory` (`:198`), `VMWordBytes = 64` and
  `AddressBits = 512` in `libhyputil/VMConstants.h`, `TypeProvider::uint256()`
  still 256 bits. Present upstream.

### Existing semantic test coverage

No test in `test/libhyperion/semanticTests` exercises a public mapping getter
with a key that has a non-zero high 256 bits:

- `getters/mapping.hyp`, `mapping_with_names.hyp`, `mapping_to_struct.hyp`,
  `mapping_array_struct.hyp`, `array_mapping_struct.hyp` use `uint` keys;
  `getters/mapping_of_string.hyp` uses a `string` key (separate code path).
- `types/mapping_contract_key_getter.hyp` has `mapping(A => uint8) public table`
  with an address-typed key, but its keys are `0`, `0x01` and `0xa7`, which the
  mask leaves intact, so it passes under both pipelines.
- `userDefinedValueType/mapping_key.hyp` has `mapping(MyInt => int) public m`
  with keys `1` and `2`; a negative key would fail under legacy codegen.
- `types/mapping_enum_key_getter_v1.hyp`, `_v2.hyp`,
  `viaYul/mapping_enum_key_getter.hyp` use enum keys (small values).
- The four files with `mapping(bytes32 =>` or `mapping(address =>`
  (`various/sqrctf1.hyp`, `userDefinedValueType/sqrctf1.hyp`,
  `functionTypes/mapping_of_functions.hyp`, `storage/mapping_state.hyp`)
  declare them private or internal and read them from contract code only.

### Proposed patch (not applied)

Store the full word without a 256-bit cleanup. `TypeProvider::uint(VMWordBits)`
is `uint512`; its cleanup is a no-op (`cleanHigherOrderBits` returns early
for `VMWordBits`) and the store stays a plain `MSTORE`. The other caller,
`CompilerUtils::computeHashStatic` (`CompilerUtils.cpp:1494-1498`, array data
location), hashes a slot below `2^256` and is unaffected.

```diff
--- a/libhyperion/codegen/CompilerUtils.h
+++ b/libhyperion/codegen/CompilerUtils.h
@@ -108,7 +108,8 @@ public:
 		bool _keepUpdatedMemoryOffset = true
 	);
-	/// Stores a 256 bit integer from stack in memory.
+	/// Stores one full VM word from the stack in memory, without cleanup: the
+	/// callers pass mapping keys and storage slots that are already canonical.
 	/// @param _offset offset in memory
 	void storeInMemory(unsigned _offset);

--- a/libhyperion/codegen/CompilerUtils.cpp
+++ b/libhyperion/codegen/CompilerUtils.cpp
@@ -196,7 +196,9 @@ void CompilerUtils::storeInMemory(unsigned _offset)
 {
-	unsigned numBytes = prepareMemoryStore(*TypeProvider::uint256(), true);
+	// A uint256 cleanup would drop the high 256 bits of the word: bytesN keys are
+	// left-aligned, address and uint512 keys fill the word, int keys are sign-extended.
+	unsigned numBytes = prepareMemoryStore(*TypeProvider::uint(VMWordBits), true);
 	if (numBytes > 0)
 		m_context << u256(_offset) << Instruction::MSTORE;
 }
```

An equivalent one-line variant keeps `uint256` and passes `false` as the
third `prepareMemoryStore` argument (`_cleanup`). Suggested regression test,
runnable under both pipelines by default:

```diff
--- /dev/null
+++ b/test/libhyperion/semanticTests/getters/mapping_wide_keys.hyp
@@ -0,0 +1,26 @@
+contract C {
+    mapping(bytes32 => uint8) public b;
+    mapping(address => uint8) public a;
+    mapping(uint512 => uint8) public u;
+    mapping(int256 => uint8) public i;
+    function setB(bytes32 k, uint8 v) public { b[k] = v; }
+    function setA(address k, uint8 v) public { a[k] = v; }
+    function setU(uint512 k, uint8 v) public { u[k] = v; }
+    function setI(int256 k, uint8 v) public { i[k] = v; }
+}
+// ----
+// setB(bytes32,uint8): 0x1111111111111111111111111111111111111111111111111111111111111111, 7 ->
+// b(bytes32): 0x1111111111111111111111111111111111111111111111111111111111111111 -> 7
+// b(bytes32): 0 -> 0
+// setA(address,uint8): 0x1111111111111111111111111111111111111111111111111111111111111111000000000000000000000000000000000000000000000000000000000000ab, 5 ->
+// a(address): 0x1111111111111111111111111111111111111111111111111111111111111111000000000000000000000000000000000000000000000000000000000000ab -> 5
+// a(address): 0xab -> 0
+// setU(uint512,uint8): 115792089237316195423570985008687907853269984665640564039457584007913129639978, 9 ->
+// u(uint512): 115792089237316195423570985008687907853269984665640564039457584007913129639978 -> 9
+// u(uint512): 42 -> 0
+// setI(int256,uint8): -1, 10 ->
+// i(int256): -1 -> 10
+// i(int256): 115792089237316195423570985008687907853269984665640564039457584007913129639935 -> 0
```

The `setI` expectation on the last line reads the key `2^256 - 1`, which is
what a masked `-1` becomes, and the `u` block uses `2^256 + 42`; whether the
test framework accepts these literal forms for `int256` and `uint512`
arguments should be checked when the test is added.

## Impact on other workspace contracts

The live QNS, QuantaSwap and QuantaPool deployments were built with the
32-byte-word compiler, where the builtin does not exist and the `uint256`
cleanup equals the word, so neither defect is on chain today. Both defects
bite the moment these repositories are rebuilt with the 64-byte toolchain,
and all three build scripts use the legacy pipeline (no `--via-ir`, no
`viaIR` in the standard JSON):

| Repository        | Contract and pattern                                                                                                                                                                                                                                                            | Defect      | Build script                                                                         |
| ----------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ----------- | ------------------------------------------------------------------------------------ |
| `myqrlwallet-qns` | `contracts/hyperion/crypto/QRLSignatureVerifier.hyp`: `verifyDigest` and `verify` call `mldsa87verify`                                                                                                                                                                          | 1           | `scripts/compile-hyperion.js`: `--abi --bin --optimize --optimize-runs=200` (legacy) |
| `myqrlwallet-qns` | `contracts/hyperion/vendored/resolvers/ResolverBase.hyp`: `mapping(bytes32 => uint64) public recordVersions`, which implements `IVersionableResolver.recordVersions(bytes32)`                                                                                                   | 2           | same                                                                                 |
| `myqrlwallet-qns` | `contracts/hyperion/vendored/root/Root.hyp`: `mapping(bytes32 => bool) public locked`                                                                                                                                                                                           | 2           | same                                                                                 |
| `myqrlwallet-qns` | `contracts/hyperion/vendored/root/Controllable.hyp`: `mapping(address => bool) public controllers`                                                                                                                                                                              | 2           | same                                                                                 |
| `QuantaSwap`      | `contracts/hyperion/HTLC.hyp`: `mapping(bytes32 => Swap) private _swaps` with an explicit getter; no builtin use                                                                                                                                                                | none        | `scripts/hypc.js` standard JSON, optimizer only (legacy)                             |
| `QuantaPool`      | `contracts/hyperion/ValidatorManager.hyp`: `mapping(bytes32 => uint256) public pubkeyToIndex`                                                                                                                                                                                   | 2           | `scripts/compile-hyperion.js`: `--bin` (legacy)                                      |
| `QuantaPool`      | `contracts/hyperion/DepositPool-v2.hyp`: `mapping(address => WithdrawalRequest[]) public withdrawalRequests` (read by `frontend/src/stores/poolStore.ts:1144`), `mapping(address => uint256) public nextWithdrawalIndex` (read by `scripts/integration-test-v2.js:415,460,642`) | 2           | same                                                                                 |
| `QuantaPool`      | `ValidatorManager.validators` (`uint256` key), `stQRL-v2.hyp` private mappings with explicit views                                                                                                                                                                              | none        | same                                                                                 |
| `QuantaStark`     | `StarkFactRegistry`, `StateBridge`: internal mappings with explicit views; `StateBridge.withdraw` uses the builtin and the suite compiles with `viaIr: true` (canary case in `test/contracts/bridge.test.js`)                                                                   | 1 mitigated | `scripts/compile-hyperion.js`, `HYPERION_VIA_IR=1`                                   |

What the defects do to those contracts under a legacy 64-byte build:

- QNS `QRLSignatureVerifier.verify`/`verifyDigest`: every call with a real
  digest fails with `gas uint64 overflow`; `scripts/verify-pq-precompiles.js`
  step 8 (the Hyperion wrapper checks) fails, while its raw precompile steps
  pass. A zero digest returns `false`.
- Contract-internal reads (`recordVersions[node]` inside `QRLPublicResolver`,
  `controllers[msg.sender]` in the `onlyController` modifier, `locked[label]`
  in `Root`, `pubkeyToIndex[pubkeyHash]`, `withdrawalRequests[msg.sender]`)
  keep working: the write path and the explicit reads agree. Only the external
  auto-generated getters lie. `recordVersions(node)` returns the version of
  node `0x00..00` for every node, `locked(label)` returns the entry of the zero
  label for every label, `controllers(addr)` returns `false` for every address
  whose first 32 bytes are non-zero, `pubkeyToIndex(hash)` returns the entry of
  the zero hash (0), `nextWithdrawalIndex(addr)` returns 0, and
  `withdrawalRequests(addr, i)` reads an empty array for every such address
  (the getter's bounds check then reverts).
- Workarounds until the compiler is patched: build with `--via-ir` (QuantaStark
  already does), or keep mappings internal and expose explicit views (the
  pattern the bridge contracts use).

## Related risk

`TypeProvider::uint256()` appears 30 times in `libhyperion/codegen/*.cpp` of
the legacy pipeline. Every use that forces a cleanup on a value that may
occupy the high half of the 64-byte word is a candidate for the same
truncation; the ones reviewed here (`storeInMemory`, the slot stores in
`IndexAccess`, `computeHashStatic`) are covered above, the rest were not
audited for this document.
