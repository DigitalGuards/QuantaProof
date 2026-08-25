// JS reference for calldata layout v1 (docs/PROTOCOL.md section 11,
// prover/stark-prover/src/layout.rs): byte offsets of every field, header
// validation, the exact-length rule, canonical-element decoding of a proof
// into its parts, and the inverse encoding.
//
// parseLayout mirrors layout.rs::parse_layout including its error precedence
// (BadVersion, BadHeader, BadLength) and returns the same object shape the
// vector files carry under `layout`, so the suites compare them with a deep
// equality. decodeProof mirrors layout.rs::decode_raw (adds
// NonCanonicalElement) and encodeProof is serialize.rs::serialize_proof for
// the decoded structure, so decode-then-encode must reproduce the bytes.

const { keccak_256 } = require('@noble/hashes/sha3');

const { bytesToHex, hexToBytes } = require('./vectors');

const VERSION = 1;
const F_BYTES = 8;
const EF_BYTES = 16;
const DIGEST_BYTES = 32;
const TRACE_WIDTH = 2;
const SIB_COUNT_BYTES = 2;
const P = 0xffffffff00000001n;
const TWO_ADICITY = 32;

class LayoutError extends Error {
  constructor(name, detail) {
    super(detail ? `${name}: ${detail}` : name);
    this.name = name;
    this.errorName = name;
  }
}

function fail(name, detail) {
  throw new LayoutError(name, detail);
}

// Header rules of layout.rs::validate_header; returns null or 'BadHeader'.
function headerError(degreeBits, logArities, cfg) {
  if (degreeBits === 0 || degreeBits + cfg.logBlowup > TWO_ADICITY) return 'BadHeader';
  if (degreeBits < cfg.logFinalPolyLen) return 'BadHeader';
  if (cfg.maxLogArity === 0 || cfg.numQueries === 0) return 'BadHeader';
  let sum = 0;
  for (const k of logArities) {
    if (k === 0 || k > cfg.maxLogArity) return 'BadHeader';
    sum += k;
  }
  if (sum !== degreeBits - cfg.logFinalPolyLen) return 'BadHeader';
  return null;
}

function finalPolyLen(cfg) {
  return 2 ** cfg.logFinalPolyLen;
}

// Offsets of the transcript prefix (layout.rs::prefix_layout).
function prefixLayout(numRounds, finalPolyLength) {
  const logArity = 3;
  const traceRoot = logArity + numRounds;
  const quotientRoot = traceRoot + DIGEST_BYTES;
  const traceLocal = quotientRoot + DIGEST_BYTES;
  const traceNext = traceLocal + TRACE_WIDTH * EF_BYTES;
  const quotientChunk = traceNext + TRACE_WIDTH * EF_BYTES;
  let cursor = quotientChunk + TRACE_WIDTH * EF_BYTES;
  const roundCommits = [];
  const roundPowWitnesses = [];
  for (let r = 0; r < numRounds; r += 1) {
    roundCommits.push(cursor);
    cursor += DIGEST_BYTES;
    roundPowWitnesses.push(cursor);
    cursor += F_BYTES;
  }
  const finalPoly = cursor;
  cursor += finalPolyLength * EF_BYTES;
  const queryPowWitness = cursor;
  cursor += F_BYTES;
  return {
    version: 0,
    degreeBits: 1,
    numRounds: 2,
    logArity,
    traceRoot,
    quotientRoot,
    traceLocal,
    traceNext,
    quotientChunk,
    roundCommits,
    roundPowWitnesses,
    finalPoly,
    queryPowWitness,
    pEnd: cursor,
  };
}

// Closed form of the prefix end, PROTOCOL.md section 11.1.
function prefixEnd(numRounds, logFinalPolyLen) {
  return 171 + 41 * numRounds + 16 * 2 ** logFinalPolyLen;
}

function readU16BE(bytes, off) {
  if (off + SIB_COUNT_BYTES > bytes.length) fail('BadLength', `sib_count at ${off} past the end`);
  return (bytes[off] << 8) | bytes[off + 1];
}

// Parse the header and the sib_count fields, validate the header and enforce
// the exact-length rule. No field element is decoded here. Throws LayoutError.
function parseLayout(bytes, cfg) {
  if (bytes.length === 0) fail('BadLength', 'empty proof');
  if (bytes[0] !== VERSION) fail('BadVersion', `version byte ${bytes[0]}`);
  if (bytes.length < 3) fail('BadLength', 'header truncated');
  const degreeBits = bytes[1];
  const numRounds = bytes[2];
  if (bytes.length < 3 + numRounds) fail('BadLength', 'arity list truncated');
  const logArities = Array.from(bytes.subarray(3, 3 + numRounds));
  const headerProblem = headerError(degreeBits, logArities, cfg);
  if (headerProblem) fail(headerProblem, `degree_bits ${degreeBits}, log_arity ${logArities}`);

  const prefix = prefixLayout(numRounds, finalPolyLen(cfg));
  const q = cfg.numQueries;
  let cursor = prefix.pEnd;

  const blocks = [];
  for (const name of ['trace', 'quotient']) {
    const rowsOffset = cursor;
    const rowsLen = q * TRACE_WIDTH * F_BYTES;
    const sibCountOffset = rowsOffset + rowsLen;
    const sibCount = readU16BE(bytes, sibCountOffset);
    const siblingsOffset = sibCountOffset + SIB_COUNT_BYTES;
    const end = siblingsOffset + sibCount * DIGEST_BYTES;
    blocks.push({ name, rowsOffset, rowsLen, sibCountOffset, siblingsOffset, sibCount, end });
    cursor = end;
  }

  const rounds = [];
  for (const k of logArities) {
    const siblingValuesOffset = cursor;
    const siblingValuesLen = q * (2 ** k - 1) * EF_BYTES;
    const sibCountOffset = siblingValuesOffset + siblingValuesLen;
    const sibCount = readU16BE(bytes, sibCountOffset);
    const siblingsOffset = sibCountOffset + SIB_COUNT_BYTES;
    const end = siblingsOffset + sibCount * DIGEST_BYTES;
    rounds.push({
      logArity: k,
      siblingValuesOffset,
      siblingValuesLen,
      sibCountOffset,
      siblingsOffset,
      sibCount,
      end,
    });
    cursor = end;
  }

  if (cursor !== bytes.length) {
    fail('BadLength', `computed ${cursor} bytes, proof has ${bytes.length}`);
  }

  return {
    degreeBits,
    logArities,
    numQueries: q,
    pEnd: prefix.pEnd,
    prefix,
    blocks,
    rounds,
    totalLen: cursor,
  };
}

// Element readers (canonical little-endian u64; >= p is NonCanonicalElement).

function readF(bytes, off) {
  if (off + F_BYTES > bytes.length) fail('BadLength', `element at ${off} past the end`);
  let v = 0n;
  for (let i = F_BYTES - 1; i >= 0; i -= 1) v = (v << 8n) | BigInt(bytes[off + i]);
  if (v >= P) fail('NonCanonicalElement', `offset ${off}`);
  return v;
}

function readEf(bytes, off) {
  return [readF(bytes, off), readF(bytes, off + F_BYTES)];
}

function readDigest(bytes, off) {
  if (off + DIGEST_BYTES > bytes.length) fail('BadLength', `digest at ${off} past the end`);
  return bytes.slice(off, off + DIGEST_BYTES);
}

function readDigests(bytes, off, count) {
  const out = [];
  for (let i = 0; i < count; i += 1) out.push(readDigest(bytes, off + i * DIGEST_BYTES));
  return out;
}

function readRows(bytes, off, q) {
  const out = [];
  for (let i = 0; i < q; i += 1) {
    const base = off + i * TRACE_WIDTH * F_BYTES;
    out.push([readF(bytes, base), readF(bytes, base + F_BYTES)]);
  }
  return out;
}

function proofId(bytes, pEnd) {
  return bytesToHex(keccak_256(bytes.subarray(0, pEnd)));
}

// Decode a proof: layout first (version, header, exact length), then every
// element with the canonical check, in wire order. Throws LayoutError.
function decodeProof(bytes, cfg) {
  const layout = parseLayout(bytes, cfg);
  const p = layout.prefix;
  const q = cfg.numQueries;

  const traceRoot = readDigest(bytes, p.traceRoot);
  const quotientRoot = readDigest(bytes, p.quotientRoot);
  const traceLocal = [readEf(bytes, p.traceLocal), readEf(bytes, p.traceLocal + EF_BYTES)];
  const traceNext = [readEf(bytes, p.traceNext), readEf(bytes, p.traceNext + EF_BYTES)];
  const quotientChunk = [readEf(bytes, p.quotientChunk), readEf(bytes, p.quotientChunk + EF_BYTES)];
  const commits = [];
  const witnesses = [];
  for (let r = 0; r < layout.rounds.length; r += 1) {
    commits.push(readDigest(bytes, p.roundCommits[r]));
    witnesses.push(readF(bytes, p.roundPowWitnesses[r]));
  }
  const finalPoly = [];
  for (let i = 0; i < finalPolyLen(cfg); i += 1) {
    finalPoly.push(readEf(bytes, p.finalPoly + i * EF_BYTES));
  }
  const queryPowWitness = readF(bytes, p.queryPowWitness);

  const [traceBlock, quotientBlock] = layout.blocks;
  const traceRows = readRows(bytes, traceBlock.rowsOffset, q);
  const traceSiblings = readDigests(bytes, traceBlock.siblingsOffset, traceBlock.sibCount);
  const quotientRows = readRows(bytes, quotientBlock.rowsOffset, q);
  const quotientSiblings = readDigests(bytes, quotientBlock.siblingsOffset, quotientBlock.sibCount);

  const rounds = layout.rounds.map((rl, r) => {
    const perQuery = 2 ** rl.logArity - 1;
    const siblingValues = [];
    for (let qi = 0; qi < q; qi += 1) {
      const base = rl.siblingValuesOffset + qi * perQuery * EF_BYTES;
      const vals = [];
      for (let j = 0; j < perQuery; j += 1) vals.push(readEf(bytes, base + j * EF_BYTES));
      siblingValues.push(vals);
    }
    return {
      logArity: rl.logArity,
      commit: commits[r],
      powWitness: witnesses[r],
      siblingValues,
      siblings: readDigests(bytes, rl.siblingsOffset, rl.sibCount),
    };
  });

  return {
    layout,
    degreeBits: layout.degreeBits,
    traceRoot,
    quotientRoot,
    traceLocal,
    traceNext,
    quotientChunk,
    rounds,
    finalPoly,
    queryPowWitness,
    traceRows,
    traceSiblings,
    quotientRows,
    quotientSiblings,
    proofId: proofId(bytes, layout.pEnd),
  };
}

// decodeProof that reports the error name instead of throwing.
function tryDecodeProof(bytes, cfg) {
  try {
    return { ok: true, proof: decodeProof(bytes, cfg) };
  } catch (e) {
    if (e instanceof LayoutError) return { ok: false, error: e.errorName, message: e.message };
    throw e;
  }
}

// Encoders (serialize.rs::serialize_proof for a decoded proof).

function fBytes(v) {
  if (typeof v !== 'bigint' || v < 0n || v >= P) {
    throw new RangeError(`cannot encode non-canonical element ${String(v)}`);
  }
  const out = new Uint8Array(F_BYTES);
  let x = v;
  for (let i = 0; i < F_BYTES; i += 1) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return out;
}

function efBytes(e) {
  const out = new Uint8Array(EF_BYTES);
  out.set(fBytes(e[0]), 0);
  out.set(fBytes(e[1]), F_BYTES);
  return out;
}

function u16BE(count) {
  if (!Number.isInteger(count) || count < 0 || count > 0xffff) {
    throw new RangeError(`sib_count ${count} does not fit in a u16`);
  }
  return Uint8Array.from([count >> 8, count & 0xff]);
}

function encodeProof(proof) {
  const parts = [];
  const numRounds = proof.rounds.length;
  parts.push(Uint8Array.from([VERSION, proof.degreeBits, numRounds]));
  parts.push(Uint8Array.from(proof.rounds.map((r) => r.logArity)));
  parts.push(proof.traceRoot, proof.quotientRoot);
  for (const e of proof.traceLocal) parts.push(efBytes(e));
  for (const e of proof.traceNext) parts.push(efBytes(e));
  for (const e of proof.quotientChunk) parts.push(efBytes(e));
  for (const r of proof.rounds) parts.push(r.commit, fBytes(r.powWitness));
  for (const e of proof.finalPoly) parts.push(efBytes(e));
  parts.push(fBytes(proof.queryPowWitness));
  for (const [rows, siblings] of [
    [proof.traceRows, proof.traceSiblings],
    [proof.quotientRows, proof.quotientSiblings],
  ]) {
    for (const row of rows) for (const v of row) parts.push(fBytes(v));
    parts.push(u16BE(siblings.length));
    for (const d of siblings) parts.push(d);
  }
  for (const r of proof.rounds) {
    for (const sv of r.siblingValues) for (const e of sv) parts.push(efBytes(e));
    parts.push(u16BE(r.siblings.length));
    for (const d of r.siblings) parts.push(d);
  }
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

// The three public values from their 24-byte wire form.
function decodePublicValues(bytes) {
  const b = bytes instanceof Uint8Array ? bytes : hexToBytes(bytes);
  if (b.length !== 3 * F_BYTES)
    fail('BadLength', `public values must be 24 bytes, got ${b.length}`);
  return [readF(b, 0), readF(b, F_BYTES), readF(b, 2 * F_BYTES)];
}

function encodePublicValues(values) {
  const out = new Uint8Array(3 * F_BYTES);
  values.forEach((v, i) => out.set(fBytes(v), i * F_BYTES));
  return out;
}

module.exports = {
  DIGEST_BYTES,
  EF_BYTES,
  F_BYTES,
  LayoutError,
  P,
  SIB_COUNT_BYTES,
  TRACE_WIDTH,
  TWO_ADICITY,
  VERSION,
  decodePublicValues,
  decodeProof,
  efBytes,
  encodeProof,
  encodePublicValues,
  fBytes,
  finalPolyLen,
  headerError,
  parseLayout,
  prefixEnd,
  prefixLayout,
  proofId,
  readF,
  tryDecodeProof,
};
