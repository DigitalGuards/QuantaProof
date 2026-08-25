// Shared helper for the chain-bound contract suites (test/contracts/*.test.js).
//
// Compiles a harness from contracts/hyperion/test/ through scripts/hypc.js,
// deploys it with the sender from scripts/lib/devAccount.js (unlocked gqrl
// --dev account or a locally signed Kurtosis fixture), and calls its functions
// with a 64-byte-word ABI encoder/decoder that covers what harnesses use:
// uint<N>, bool, bytes<N>, bytes and dynamic uint<N>[] / bool[] arrays.
// scripts/lib/abi64.js only knows the toolchain's `bytes` arguments, so the
// array and static-argument encoding lives here rather than in scripts/.
//
// Usage:
//   const { connect, deployHarness, expectRevert } = require('../lib/harness');
//   const ctx = await connect();                       // null when STARK_RPC_URL is unset
//   const h = await deployHarness(ctx, 'test/GoldilocksHarness.hyp', 'GoldilocksHarness');
//   const [sum] = await h.call('add(uint512,uint512)', [1n, 2n], ['uint512']);
//   await expectRevert(h, 'inv(uint512)', [0n], 'ZeroInverse()');

const abi = require('../../scripts/lib/abi64');
const { RpcClient, JsonRpcError } = require('../../scripts/lib/rpc');
const { getSender } = require('../../scripts/lib/devAccount');
const { compileFiles } = require('../../scripts/hypc');

const WORD = abi.WORD_BYTES;
const DEFAULT_CALL_GAS = 20_000_000;
const DEFAULT_DEPLOY_GAS = 15_000_000;

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

function parseType(type) {
  const t = type.trim();
  if (t.endsWith('[]')) {
    return { kind: 'array', element: parseType(t.slice(0, -2)), dynamic: true };
  }
  if (t === 'bytes') return { kind: 'bytes', dynamic: true };
  if (t === 'bool') return { kind: 'bool', dynamic: false };
  if (t === 'address') return { kind: 'address', dynamic: false };
  let m = /^uint(\d*)$/.exec(t);
  if (m) {
    const bits = m[1] === '' ? 256 : Number(m[1]);
    return { kind: 'uint', bits, dynamic: false };
  }
  m = /^bytes(\d+)$/.exec(t);
  if (m) {
    return { kind: 'fixedBytes', size: Number(m[1]), dynamic: false };
  }
  throw new TypeError(`unsupported ABI type: ${type}`);
}

// "name(type,type,...)" -> ["type", "type", ...]; nested tuples are not needed.
function signatureTypes(signature) {
  const open = signature.indexOf('(');
  const close = signature.lastIndexOf(')');
  if (open < 0 || close < open) {
    throw new TypeError(`malformed signature: ${signature}`);
  }
  const inner = signature.slice(open + 1, close).trim();
  return inner === '' ? [] : inner.split(',').map((s) => s.trim());
}

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

function encodeStatic(type, value) {
  switch (type.kind) {
    case 'uint': {
      const v = BigInt(value);
      if (v < 0n || v >= 1n << BigInt(type.bits)) {
        throw new RangeError(`uint${type.bits} out of range: ${v}`);
      }
      return abi.encodeUint(v);
    }
    case 'bool':
      return abi.encodeUint(value ? 1n : 0n);
    case 'address':
      return abi.encodeAddress(value);
    case 'fixedBytes': {
      const bytes = value instanceof Uint8Array ? value : abi.hexToBytes(value);
      if (bytes.length !== type.size) {
        throw new TypeError(`bytes${type.size} needs ${type.size} bytes, got ${bytes.length}`);
      }
      const out = new Uint8Array(WORD);
      out.set(bytes);
      return out;
    }
    default:
      throw new TypeError(`not a static type: ${type.kind}`);
  }
}

function encodeDynamic(type, value) {
  if (type.kind === 'bytes') {
    const bytes = value instanceof Uint8Array ? value : abi.hexToBytes(value);
    return abi.concatBytes([abi.encodeUint(bytes.length), abi.padRightToWord(bytes)]);
  }
  if (type.kind === 'array') {
    if (type.element.dynamic) {
      throw new TypeError('arrays of dynamic types are not supported');
    }
    const items = Array.from(value, (v) => encodeStatic(type.element, v));
    return abi.concatBytes([abi.encodeUint(items.length), ...items]);
  }
  throw new TypeError(`not a dynamic type: ${type.kind}`);
}

// Head (one 64-byte slot per argument) followed by the dynamic tails.
function encodeArgs(types, values) {
  if (types.length !== values.length) {
    throw new TypeError(`expected ${types.length} values, got ${values.length}`);
  }
  const parsed = types.map(parseType);
  const heads = [];
  const tails = [];
  let tailOffset = parsed.length * WORD;
  parsed.forEach((type, i) => {
    if (type.dynamic) {
      const tail = encodeDynamic(type, values[i]);
      heads.push(abi.encodeUint(tailOffset));
      tails.push(tail);
      tailOffset += tail.length;
    } else {
      heads.push(encodeStatic(type, values[i]));
    }
  });
  return abi.concatBytes([...heads, ...tails]);
}

function encodeCall(signature, values) {
  const types = signatureTypes(signature);
  return abi.bytesToHex(
    abi.concatBytes([abi.hexToBytes(abi.selector(signature)), encodeArgs(types, values)])
  );
}

// ---------------------------------------------------------------------------
// Decoding
// ---------------------------------------------------------------------------

function readWord(bytes, offset) {
  if (offset + WORD > bytes.length) {
    throw new RangeError(`return data too short: need ${offset + WORD}, have ${bytes.length}`);
  }
  return bytes.subarray(offset, offset + WORD);
}

function wordToBigInt(word) {
  let v = 0n;
  for (const b of word) v = (v << 8n) | BigInt(b);
  return v;
}

function decodeStatic(type, word) {
  switch (type.kind) {
    case 'uint':
      return wordToBigInt(word);
    case 'bool': {
      const v = wordToBigInt(word);
      if (v !== 0n && v !== 1n) throw new TypeError(`bool word is neither 0 nor 1: ${v}`);
      return v === 1n;
    }
    case 'address':
      return abi.bytesToHex(word);
    case 'fixedBytes':
      return abi.bytesToHex(word.subarray(0, type.size));
    default:
      throw new TypeError(`not a static type: ${type.kind}`);
  }
}

function decodeDynamic(type, bytes, offset) {
  const length = Number(wordToBigInt(readWord(bytes, offset)));
  if (type.kind === 'bytes') {
    const start = offset + WORD;
    if (start + length > bytes.length) throw new RangeError('bytes tail runs past the data');
    return abi.bytesToHex(bytes.subarray(start, start + length));
  }
  if (type.kind === 'array') {
    const items = [];
    for (let i = 0; i < length; i += 1) {
      items.push(decodeStatic(type.element, readWord(bytes, offset + WORD * (i + 1))));
    }
    return items;
  }
  throw new TypeError(`not a dynamic type: ${type.kind}`);
}

// Decode return data (hex) against a list of types, in order.
function decodeReturn(types, dataHex) {
  const bytes = abi.hexToBytes(dataHex);
  const parsed = types.map(parseType);
  const out = [];
  parsed.forEach((type, i) => {
    const head = readWord(bytes, i * WORD);
    if (type.dynamic) {
      out.push(decodeDynamic(type, bytes, Number(wordToBigInt(head))));
    } else {
      out.push(decodeStatic(type, head));
    }
  });
  return out;
}

// ---------------------------------------------------------------------------
// Revert data
// ---------------------------------------------------------------------------

function errorSelector(errorSignature) {
  return abi.selector(errorSignature);
}

// Revert payload of a failed qrl_call as a hex string, or null when the node
// reported no data (plain revert(0, 0) or an out-of-gas).
function revertData(error) {
  if (!(error instanceof JsonRpcError)) return null;
  const data = error.data;
  if (typeof data === 'string') return data;
  if (data && typeof data.data === 'string') return data.data;
  return null;
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

class Harness {
  constructor(ctx, address, artifact) {
    this.ctx = ctx;
    this.rpc = ctx.rpc;
    this.address = address;
    this.artifact = artifact;
  }

  // Raw qrl_call; returns the hex return data or throws JsonRpcError.
  async callRaw(signature, values, options = {}) {
    return this.rpc.qrlCall({
      to: this.address,
      data: encodeCall(signature, values),
      gas: options.gas ?? DEFAULT_CALL_GAS,
    });
  }

  // qrl_call and decode the return values against `returnTypes`.
  async call(signature, values, returnTypes, options = {}) {
    const data = await this.callRaw(signature, values, options);
    return decodeReturn(returnTypes, data);
  }

  // Single-value convenience: the first decoded return value.
  async callOne(signature, values, returnType, options = {}) {
    const [value] = await this.call(signature, values, [returnType], options);
    return value;
  }

  // qrl_estimateGas for a call (includes the 21,000 base and calldata cost).
  async estimateGas(signature, values) {
    return this.rpc.estimateGas({
      from: this.ctx.sender.address,
      to: this.address,
      data: encodeCall(signature, values),
    });
  }
}

// Reads STARK_RPC_URL; returns null when it is unset so suites can skip.
async function connect(options = {}) {
  const rpcUrl = options.rpcUrl ?? process.env.STARK_RPC_URL;
  if (!rpcUrl) return null;
  const rpc = new RpcClient(rpcUrl, { timeoutMs: options.timeoutMs ?? 120000 });
  const sender = await getSender(rpc);
  return { rpc, sender, chainId: sender.chainId };
}

// Optimizer settings shared with scripts/compile-hyperion.js: HYPERION_OPTIMIZE_RUNS
// (default 200) and HYPERION_VIA_IR=1. The runs value matters for gas: below a
// few thousand runs the optimizer materializes wide literals (lane masks,
// packed tables) through CODECOPY instead of a PUSH, which costs about 30 gas
// per use; docs/GAS-PRIMITIVES.md reports both settings.
function optimizerOptions(env = process.env) {
  return {
    optimizerRuns: Number(env.HYPERION_OPTIMIZE_RUNS || 200),
    viaIr: env.HYPERION_VIA_IR === '1',
  };
}

// Compile `entryFile` (relative to contracts/hyperion/) and return the artifact
// for `contractName` (defaults to the entry file's base name).
function compileHarness(entryFile, contractName, options = {}) {
  const artifacts = compileFiles([entryFile], { ...optimizerOptions(), ...options });
  const name =
    contractName ||
    entryFile
      .split('/')
      .pop()
      .replace(/\.hyp$/, '');
  const artifact = artifacts[name];
  if (!artifact) {
    throw new Error(`${name} is not among the compiled contracts: ${Object.keys(artifacts)}`);
  }
  return artifact;
}

// Deploys with the estimate plus 20 percent (capped at DEFAULT_DEPLOY_GAS)
// unless a gas limit is given: the dev node's transaction fee cap (1 quanta by
// default) rejects a blanket 15M limit at its gas price.
async function deployArtifact(ctx, artifact, options = {}) {
  let gas = options.gas;
  if (gas === undefined) {
    const estimate = await ctx.sender.estimateGas({ data: artifact.bytecode });
    gas = (estimate * 12n) / 10n;
    if (gas > BigInt(DEFAULT_DEPLOY_GAS)) gas = BigInt(DEFAULT_DEPLOY_GAS);
  }
  const receipt = await ctx.sender.send({ data: artifact.bytecode, gas });
  if (Number(receipt.status) !== 1) {
    throw new Error(`deployment reverted (tx ${receipt.transactionHash})`);
  }
  const code = await ctx.rpc.getCode(receipt.contractAddress);
  if (!code || code === '0x') {
    throw new Error(`no code at ${receipt.contractAddress} after deployment`);
  }
  return new Harness(ctx, receipt.contractAddress, artifact);
}

async function deployHarness(ctx, entryFile, contractName, options = {}) {
  return deployArtifact(ctx, compileHarness(entryFile, contractName, options.compile), options);
}

// Assert that a call reverts with the given custom error (by selector).
async function expectRevert(harness, signature, values, errorSignature, options = {}) {
  let data;
  try {
    data = await harness.callRaw(signature, values, options);
  } catch (error) {
    const payload = revertData(error);
    if (payload === null) {
      throw new Error(`${signature} failed without revert data: ${error.message}`);
    }
    const expected = errorSelector(errorSignature);
    if (!payload.toLowerCase().startsWith(expected.toLowerCase())) {
      throw new Error(
        `${signature} reverted with ${payload.slice(0, 10)}, expected ${errorSignature} (${expected})`
      );
    }
    return payload;
  }
  throw new Error(`${signature} did not revert (returned ${data})`);
}

// Marginal gas per iteration of harness.gasLoop(op, n): (gas(2n) - gas(n)) / n.
async function marginalGas(harness, op, n = 1024n, options = {}) {
  const returnTypes = options.returnTypes || ['uint512', 'uint512'];
  const [gasN] = await harness.call('gasLoop(uint8,uint512)', [op, n], returnTypes, options);
  const [gas2N] = await harness.call('gasLoop(uint8,uint512)', [op, 2n * n], returnTypes, options);
  return {
    op,
    n,
    gasN,
    gas2N,
    marginal: Number(gas2N - gasN) / Number(n),
  };
}

// Split values into chunks of `size` for batched calls.
function chunk(values, size) {
  const out = [];
  for (let i = 0; i < values.length; i += size) {
    out.push(values.slice(i, i + size));
  }
  return out;
}

module.exports = {
  DEFAULT_CALL_GAS,
  DEFAULT_DEPLOY_GAS,
  Harness,
  chunk,
  compileHarness,
  connect,
  decodeReturn,
  deployArtifact,
  deployHarness,
  encodeArgs,
  encodeCall,
  errorSelector,
  expectRevert,
  marginalGas,
  optimizerOptions,
  parseType,
  revertData,
  signatureTypes,
};
