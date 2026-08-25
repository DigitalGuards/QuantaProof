// Reproduction driver for docs/compiler/HYPC-LEGACY-CODEGEN-DEFECTS.md.
//
// Compiles the two repro contracts next to this file with the hypc binary from
// HYPERION_COMPILER (`--bin --abi --optimize`, plus `--via-ir` for the IR run),
// deploys every build on the node at STARK_RPC_URL (gqrl --dev, chain 1337)
// through test/lib/harness.js and prints what each function returns under
// each pipeline, together with the storage slots the getters read.
//
//   STARK_RPC_URL=http://127.0.0.1:8545 HYPERION_COMPILER=../hyperion-stark/build/hypc/hypc \
//     node docs/compiler/repro.js               # both defects, both pipelines
//   node docs/compiler/repro.js mldsa legacy    # one defect, one pipeline
//   node docs/compiler/repro.js getter via-ir

'use strict';

const path = require('path');
const { spawnSync } = require('child_process');
const { keccak_256 } = require('@noble/hashes/sha3');

const abi = require('../../scripts/lib/abi64');
const { HYPC_BIN } = require('../../scripts/hypc');
const harness = require('../../test/lib/harness');
const mldsa = require('../../test/lib/mldsa');

const { connect, deployArtifact, encodeArgs, decodeReturn, revertData, DEFAULT_CALL_GAS } = harness;

const utf8 = (text) => new TextEncoder().encode(text);
const ZERO_WORD = new Uint8Array(64);

// ---------------------------------------------------------------------------
// Compile with the command line interface (same flags as the document)
// ---------------------------------------------------------------------------

function compile(file, viaIr) {
  const args = ['--bin', '--abi', '--optimize'];
  if (viaIr) args.push('--via-ir');
  args.push(file);
  const r = spawnSync(HYPC_BIN, args, { encoding: 'utf8', maxBuffer: 64 * 1024 * 1024 });
  if (r.error) throw new Error(`spawn ${HYPC_BIN} failed: ${r.error.message}`);
  if (r.status !== 0) throw new Error(`hypc exited ${r.status}: ${r.stderr || r.stdout}`);
  const lines = r.stdout.split('\n');
  let bytecode = null;
  let contractAbi = null;
  for (let i = 0; i < lines.length - 1; i += 1) {
    if (lines[i] === 'Binary:') bytecode = lines[i + 1].trim();
    if (lines[i] === 'Contract JSON ABI') contractAbi = JSON.parse(lines[i + 1]);
  }
  if (!bytecode || !contractAbi) throw new Error(`could not parse hypc output for ${file}`);
  return { bytecode: `0x${bytecode}`, abi: contractAbi, deployedBytecode: '' };
}

// ---------------------------------------------------------------------------
// Call helpers (explicit ABI types, so int256 keys can be sent as raw words)
// ---------------------------------------------------------------------------

function calldata(signature, types, values) {
  return abi.bytesToHex(
    abi.concatBytes([abi.hexToBytes(abi.selector(signature)), encodeArgs(types, values)])
  );
}

async function call(ctx, h, signature, types, values, returnTypes) {
  const data = calldata(signature, types, values);
  const out = await ctx.rpc.qrlCall({ to: h.address, data, gas: DEFAULT_CALL_GAS });
  return decodeReturn(returnTypes, out);
}

async function send(ctx, h, signature, types, values) {
  const data = calldata(signature, types, values);
  const estimate = await ctx.rpc.estimateGas({ from: ctx.sender.address, to: h.address, data });
  const receipt = await ctx.sender.send({ to: h.address, data, gas: (estimate * 12n) / 10n });
  if (Number(receipt.status) !== 1) throw new Error(`${signature} reverted`);
  return receipt;
}

function format(value) {
  if (typeof value === 'bigint') return value.toString();
  if (Array.isArray(value)) return `[${value.map(format).join(', ')}]`;
  return String(value);
}

async function attempt(label, fn) {
  try {
    const value = await fn();
    console.log(`  ${label} -> ${format(value)}`);
    return { ok: true, value };
  } catch (error) {
    const payload = revertData(error);
    console.log(`  ${label} -> ERROR ${error.message}${payload ? ` data=${payload}` : ''}`);
    return { ok: false, error };
  }
}

// keccak256(keyWord || slotWord): the slot a mapping entry lives in.
function mappingSlot(keyWord, slot) {
  return abi.bytesToHex(keccak_256(abi.concatBytes([keyWord, abi.encodeUint(slot)])));
}

// The key word with its high 256 bits cleared (what a uint256 cleanup leaves).
function low256(keyWord) {
  const out = new Uint8Array(64);
  out.set(keyWord.subarray(32), 32);
  return out;
}

async function storageAt(ctx, address, slotHex) {
  const raw = await ctx.rpc.call('qrl_getStorageAt', [address, slotHex, 'latest']);
  return abi.decodeUint(raw);
}

// ---------------------------------------------------------------------------
// Defect 1: mldsa87verify under the legacy pipeline
// ---------------------------------------------------------------------------

async function runMldsa(ctx, viaIr) {
  const label = viaIr ? 'via-ir' : 'legacy';
  const artifact = compile(path.join(__dirname, 'MldsaVerifyRepro.hyp'), viaIr);
  const h = await deployArtifact(ctx, artifact);
  console.log(`\n[mldsa ${label}] MldsaVerifyRepro at ${h.address}`);

  const seed = new Uint8Array(32).fill(1);
  const { publicKey, secretKey } = mldsa.generateKeypair(seed);
  const message = utf8('QuantaProof hypc legacy codegen repro');
  const context = 'QP-REPRO-v1';
  const digest = mldsa.shake256Digest(message);
  const signature = mldsa.signDigest(digest, secretKey, context);
  const flipped = Uint8Array.from(signature);
  flipped[0] ^= 0x01;
  const contextBytes = utf8(context);
  console.log(
    `  offline: verifyDigest(signature) = ${mldsa.verifyDigest(signature, digest, publicKey, context)}`
  );
  console.log(
    `  offline: verifyDigest(flipped)   = ${mldsa.verifyDigest(flipped, digest, publicKey, context)}`
  );
  console.log(`  digest = ${abi.bytesToHex(digest)}`);

  const sigVerify = 'verifyBuiltin(bytes64,bytes,bytes,bytes)';
  const sigRaw = 'verifyRaw(bytes64,bytes,bytes,bytes)';
  const types = ['bytes64', 'bytes', 'bytes', 'bytes'];

  await attempt('digestOf(message) == shake256(message)', async () => {
    const [onChain] = await call(ctx, h, 'digestOf(bytes)', ['bytes'], [message], ['bytes64']);
    return onChain === abi.bytesToHex(digest);
  });
  await attempt('verifyRaw(digest, signature, publicKey, context)', () =>
    call(ctx, h, sigRaw, types, [digest, signature, publicKey, contextBytes], ['bool', 'bytes'])
  );
  await attempt('verifyRaw(digest, flipped, publicKey, context)', () =>
    call(ctx, h, sigRaw, types, [digest, flipped, publicKey, contextBytes], ['bool', 'bytes'])
  );
  await attempt('verifyBuiltin(digest, signature, publicKey, context)', () =>
    call(ctx, h, sigVerify, types, [digest, signature, publicKey, contextBytes], ['bool'])
  );
  await attempt('verifyBuiltin(digest, flipped, publicKey, context)', () =>
    call(ctx, h, sigVerify, types, [digest, flipped, publicKey, contextBytes], ['bool'])
  );

  // Fingerprint of the argument order: under the legacy build the helper uses
  // the digest as its memory position, so the cost of the call follows the
  // numeric value of the digest and a zero digest "succeeds" with false.
  console.log('  fingerprint: qrl_estimateGas as a function of the digest value');
  for (const [name, value] of [
    ['bytes64(0)', 0n],
    ['bytes64(uint512(0x10000))', 0x10000n],
    ['bytes64(uint512(0x100000))', 0x100000n],
  ]) {
    const word = abi.encodeUint(value);
    await attempt(`  verifyBuiltin(${name}, ...) result`, () =>
      call(ctx, h, sigVerify, types, [word, signature, publicKey, contextBytes], ['bool'])
    );
    await attempt(`  verifyBuiltin(${name}, ...) gas`, () =>
      ctx.rpc.estimateGas({
        from: ctx.sender.address,
        to: h.address,
        data: calldata(sigVerify, types, [word, signature, publicKey, contextBytes]),
      })
    );
  }
  await attempt('  verifyBuiltin(real digest, ...) gas', () =>
    ctx.rpc.estimateGas({
      from: ctx.sender.address,
      to: h.address,
      data: calldata(sigVerify, types, [digest, signature, publicKey, contextBytes]),
    })
  );

  // Last opcode of the failing call, when the node exposes debug_traceCall.
  await attempt('  debug_traceCall(real digest): last opcode', async () => {
    const trace = await ctx.rpc.call('debug_traceCall', [
      {
        from: ctx.sender.address,
        to: h.address,
        gas: `0x${DEFAULT_CALL_GAS.toString(16)}`,
        data: calldata(sigVerify, types, [digest, signature, publicKey, contextBytes]),
      },
      'latest',
      { disableStorage: true, disableStack: false, enableMemory: false },
    ]);
    const last = trace.structLogs[trace.structLogs.length - 1] || {};
    const stack = last.stack || [];
    return `failed=${trace.failed} steps=${trace.structLogs.length} op=${last.op} pc=${last.pc} error=${last.error || ''} top-of-stack=${stack[stack.length - 1] || ''}`;
  });
}

// ---------------------------------------------------------------------------
// Defect 2: public mapping getters under the legacy pipeline
// ---------------------------------------------------------------------------

async function runGetter(ctx, viaIr) {
  const label = viaIr ? 'via-ir' : 'legacy';
  const artifact = compile(path.join(__dirname, 'MappingGetterRepro.hyp'), viaIr);
  const h = await deployArtifact(ctx, artifact);
  console.log(`\n[getter ${label}] MappingGetterRepro at ${h.address}`);

  // bytes32 key: slot 0
  const keyB = `0x${'11'.repeat(32)}`;
  const keyBWord = abi.encodeBytes32(keyB);
  await send(ctx, h, 'setBytes32(bytes32,uint512)', ['bytes32', 'uint512'], [keyB, 7n]);
  await attempt('viewBytes32(k) after setBytes32(k, 7)', () =>
    call(ctx, h, 'viewBytes32(bytes32)', ['bytes32'], [keyB], ['uint512'])
  );
  await attempt('byBytes32(k)   auto getter', () =>
    call(ctx, h, 'byBytes32(bytes32)', ['bytes32'], [keyB], ['uint512'])
  );
  await attempt('storage keccak256(k || 0)          full 64-byte key word', () =>
    storageAt(ctx, h.address, mappingSlot(keyBWord, 0n))
  );
  await attempt('storage keccak256(low256(k) || 0)  key masked to 256 bits', () =>
    storageAt(ctx, h.address, mappingSlot(low256(keyBWord), 0n))
  );
  await send(
    ctx,
    h,
    'setBytes32(bytes32,uint512)',
    ['bytes32', 'uint512'],
    [`0x${'00'.repeat(32)}`, 99n]
  );
  await attempt('byBytes32(k)   auto getter after setBytes32(bytes32(0), 99)', () =>
    call(ctx, h, 'byBytes32(bytes32)', ['bytes32'], [keyB], ['uint512'])
  );
  await attempt('viewBytes32(k) after setBytes32(bytes32(0), 99)', () =>
    call(ctx, h, 'viewBytes32(bytes32)', ['bytes32'], [keyB], ['uint512'])
  );

  // address key: slot 1. The dev account has non-zero high bytes; the second
  // key has 32 zero bytes in front and fits in 256 bits.
  const keyAddrHigh = ctx.sender.address;
  const keyAddrLow = `Q${'00'.repeat(32)}${'ab'.repeat(32)}`;
  await send(ctx, h, 'setAddress(address,uint512)', ['address', 'uint512'], [keyAddrHigh, 5n]);
  await send(ctx, h, 'setAddress(address,uint512)', ['address', 'uint512'], [keyAddrLow, 6n]);
  await attempt('viewAddress(devAccount) after setAddress(devAccount, 5)', () =>
    call(ctx, h, 'viewAddress(address)', ['address'], [keyAddrHigh], ['uint512'])
  );
  await attempt('byAddress(devAccount)   auto getter', () =>
    call(ctx, h, 'byAddress(address)', ['address'], [keyAddrHigh], ['uint512'])
  );
  await attempt('storage keccak256(devAccount || 1)         full key word', () =>
    storageAt(ctx, h.address, mappingSlot(abi.encodeAddress(keyAddrHigh), 1n))
  );
  await attempt('storage keccak256(low256(devAccount) || 1) key masked to 256 bits', () =>
    storageAt(ctx, h.address, mappingSlot(low256(abi.encodeAddress(keyAddrHigh)), 1n))
  );
  await attempt('viewAddress(Q00..ab) after setAddress(Q00..ab, 6)', () =>
    call(ctx, h, 'viewAddress(address)', ['address'], [keyAddrLow], ['uint512'])
  );
  await attempt('byAddress(Q00..ab)   auto getter', () =>
    call(ctx, h, 'byAddress(address)', ['address'], [keyAddrLow], ['uint512'])
  );

  // uint512 key: slot 2
  const keySmall = 42n;
  const keyBig = (1n << 256n) + 42n;
  await send(ctx, h, 'setUint512(uint512,uint512)', ['uint512', 'uint512'], [keySmall, 8n]);
  await send(ctx, h, 'setUint512(uint512,uint512)', ['uint512', 'uint512'], [keyBig, 9n]);
  await attempt('viewUint512(42) after setUint512(42, 8)', () =>
    call(ctx, h, 'viewUint512(uint512)', ['uint512'], [keySmall], ['uint512'])
  );
  await attempt('byUint512(42)   auto getter', () =>
    call(ctx, h, 'byUint512(uint512)', ['uint512'], [keySmall], ['uint512'])
  );
  await attempt('viewUint512(2^256 + 42) after setUint512(2^256 + 42, 9)', () =>
    call(ctx, h, 'viewUint512(uint512)', ['uint512'], [keyBig], ['uint512'])
  );
  await attempt('byUint512(2^256 + 42)   auto getter', () =>
    call(ctx, h, 'byUint512(uint512)', ['uint512'], [keyBig], ['uint512'])
  );

  // int256 key: slot 3. -1 is the sign-extended 64-byte word 0xff..ff, sent
  // as a raw uint512 word under the int256 selector.
  const minusOne = (1n << 512n) - 1n;
  await send(ctx, h, 'setInt256(int256,uint512)', ['uint512', 'uint512'], [minusOne, 10n]);
  await attempt('viewInt256(-1) after setInt256(-1, 10)', () =>
    call(ctx, h, 'viewInt256(int256)', ['uint512'], [minusOne], ['uint512'])
  );
  await attempt('byInt256(-1)   auto getter', () =>
    call(ctx, h, 'byInt256(int256)', ['uint512'], [minusOne], ['uint512'])
  );
  await attempt('storage keccak256(low256(0xff..ff) || 3)  key masked to 256 bits', () =>
    storageAt(ctx, h.address, mappingSlot(low256(abi.encodeUint(minusOne)), 3n))
  );
  await attempt('storage keccak256(0xff..ff || 3)          full key word', () =>
    storageAt(ctx, h.address, mappingSlot(abi.encodeUint(minusOne), 3n))
  );
  void ZERO_WORD;
}

// ---------------------------------------------------------------------------

async function main() {
  const [which = 'all', pipeline = 'both'] = process.argv.slice(2);
  const ctx = await connect();
  if (!ctx) {
    console.error('STARK_RPC_URL is unset; point it at the gqrl dev node');
    process.exit(2);
  }
  console.log(`hypc: ${HYPC_BIN}`);
  console.log(`node: ${ctx.rpc.url} chain ${ctx.chainId} sender ${ctx.sender.address}`);
  const pipelines = pipeline === 'both' ? [false, true] : [pipeline === 'via-ir'];
  for (const viaIr of pipelines) {
    if (which === 'all' || which === 'mldsa') await runMldsa(ctx, viaIr);
    if (which === 'all' || which === 'getter') await runGetter(ctx, viaIr);
  }
}

main().catch((error) => {
  console.error(error);
  process.exit(1);
});
