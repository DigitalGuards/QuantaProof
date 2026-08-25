// Chain-bound parity suite for contracts/hyperion/lib/KeccakChallenger.hyp.
//
// Every valid vector's `transcript` (the byte log of the unmodified upstream
// Plonky3 verifier, see docs/PROTOCOL.md section 4 and 5) is converted into
// the ChallengerHarness op stream and replayed on chain in three encodings:
//   raw     every observe through observeCalldata, every group through nextU64
//   typed   observeU64LE / observeExt / observeDigest, sampleField / sampleExt /
//           sampleBits / checkWitness, exactly as the verifier will call them
//   memory  like raw with observeMemory (word copy) instead of calldatacopy
// Each replay must return every sampled u64, field element, bit sample and
// proof-of-work outcome the vector recorded, plus every flush digest. Targeted
// scripts then cover the 4-groups-per-flush boundary, discard-on-observe, the
// rehash of an exhausted digest, an empty transcript, the buffer overflow
// guard and a forced rejection (a prefix whose digest holds a group >= p).
//
// The expectations of the hand-built scripts come from a byte-level mirror of
// p3-challenger 0.7.0-rc.1 kept private to this file (RefChallenger); vector
// replays use the values the Rust side recorded. Skips without STARK_RPC_URL.

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const path = require('path');

const { keccak_256 } = require('@noble/hashes/sha3');

const { connect, deployHarness, expectRevert, marginalGas } = require('../lib/harness');
const { P } = require('../lib/goldilocks');

const rpcUrl = process.env.STARK_RPC_URL;
const skip = rpcUrl ? false : 'set STARK_RPC_URL to run against a node';

const VECTOR_DIR = path.join(__dirname, '..', 'vectors');
const MASK64 = 0xffffffffffffffffn;
const BUF_CAPACITY = 8192;

// Forced-rejection preimage (found by the JS-reference search, asserted in
// test/unit/challenger.test.js): keccak256(LE(2907198534)) has group 2 equal
// to 0xffffffffbedfa74c >= p, so a challenger that observes those 8 bytes and
// samples field elements skips its third group. Re-derived in JS below, both
// with the private mirror and with test/lib/challenger.js, before the replay.
const REJECTION_PREFIX = {
  u64: 2907198534n,
  group: 2,
  digest: '0x61d7b9ef16cc5c31ffffffffbedfa74c60640175999fdd46dd2b959e6b707b0c',
};

// ---------------------------------------------------------------------------
// Op stream (mirrors the table in ChallengerHarness.hyp)
// ---------------------------------------------------------------------------

const OP = {
  OBSERVE_BYTES: 0x01,
  OBSERVE_U64: 0x02,
  OBSERVE_DIGEST: 0x03,
  OBSERVE_EXT: 0x04,
  OBSERVE_MEMORY: 0x05,
  SAMPLE_U64: 0x10,
  SAMPLE_FIELD: 0x11,
  SAMPLE_EXT: 0x12,
  SAMPLE_BITS: 0x13,
  CHECK_WITNESS: 0x14,
  PUSH_DIGEST: 0x20,
  PUSH_AVAIL: 0x21,
  PUSH_LEN: 0x22,
};

function hexToBytes(hex) {
  return Uint8Array.from(Buffer.from(hex.startsWith('0x') ? hex.slice(2) : hex, 'hex'));
}

function bytesToHex(bytes) {
  return `0x${Buffer.from(bytes).toString('hex')}`;
}

function beBytes(value, size) {
  const out = new Uint8Array(size);
  let v = BigInt(value);
  for (let i = size - 1; i >= 0; i -= 1) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  if (v !== 0n) throw new RangeError(`${value} does not fit in ${size} bytes`);
  return out;
}

function beToBigInt(bytes) {
  let v = 0n;
  for (const b of bytes) v = (v << 8n) | BigInt(b);
  return v;
}

function u64le(value) {
  const out = new Uint8Array(8);
  let v = BigInt(value) & MASK64;
  for (let i = 0; i < 8; i += 1) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

function leToBigInt(bytes) {
  let v = 0n;
  for (let i = bytes.length - 1; i >= 0; i -= 1) v = (v << 8n) | BigInt(bytes[i]);
  return v;
}

function concat(chunks) {
  const total = chunks.reduce((n, c) => n + c.length, 0);
  const out = new Uint8Array(total);
  let o = 0;
  for (const c of chunks) {
    out.set(c, o);
    o += c.length;
  }
  return out;
}

// Builds a script and, in parallel, the list of values the replay must push.
class Script {
  constructor() {
    this.chunks = [];
    this.expected = []; // [{ label, value: BigInt }]
  }

  op(code, ...payload) {
    this.chunks.push(Uint8Array.of(code), ...payload);
    return this;
  }

  observeBytes(bytes, viaMemory = false) {
    if (bytes.length > 0xffff) throw new RangeError('observe payload too long for u16');
    return this.op(
      viaMemory ? OP.OBSERVE_MEMORY : OP.OBSERVE_BYTES,
      beBytes(bytes.length, 2),
      bytes
    );
  }

  observeU64(value) {
    return this.op(OP.OBSERVE_U64, beBytes(value, 8));
  }

  observeDigest(hex) {
    const bytes = hexToBytes(hex);
    if (bytes.length !== 32) throw new RangeError('digest must be 32 bytes');
    return this.op(OP.OBSERVE_DIGEST, bytes);
  }

  observeExt(c0, c1) {
    return this.op(OP.OBSERVE_EXT, beBytes(c0, 8), beBytes(c1, 8));
  }

  expect(label, value) {
    this.expected.push({ label, value: BigInt(value) });
  }

  sampleU64(label, value) {
    this.expect(label, value);
    return this.op(OP.SAMPLE_U64);
  }

  sampleField(label, value) {
    this.expect(label, value);
    return this.op(OP.SAMPLE_FIELD);
  }

  sampleExt(label, c0, c1) {
    this.expect(`${label}.c0`, c0);
    this.expect(`${label}.c1`, c1);
    return this.op(OP.SAMPLE_EXT);
  }

  sampleBits(label, bits, value) {
    this.expect(label, value);
    return this.op(OP.SAMPLE_BITS, Uint8Array.of(bits));
  }

  checkWitness(label, bits, witness, ok) {
    this.expect(label, ok ? 1n : 0n);
    return this.op(OP.CHECK_WITNESS, Uint8Array.of(bits), beBytes(witness, 8));
  }

  pushDigest(label, hex) {
    this.expect(label, beToBigInt(hexToBytes(hex)));
    return this.op(OP.PUSH_DIGEST);
  }

  pushAvail(label, value) {
    this.expect(label, value);
    return this.op(OP.PUSH_AVAIL);
  }

  pushLen(label, value) {
    this.expect(label, value);
    return this.op(OP.PUSH_LEN);
  }

  bytes() {
    return concat(this.chunks);
  }
}

// ---------------------------------------------------------------------------
// Byte-level mirror of p3-challenger 0.7.0-rc.1 (HashChallenger<u8, Keccak256Hash, 32>
// inside SerializingChallenger64<Goldilocks, _>), used for the hand-built cases
// ---------------------------------------------------------------------------

class RefChallenger {
  constructor() {
    this.input = []; // input_buffer
    this.output = []; // output_buffer, popped from the end
    this.digest = 0n; // last flush output as a 256-bit integer
  }

  // hash_challenger.rs:51-56: clear the output buffer, append to the input.
  observe(bytes) {
    this.output.length = 0;
    for (const b of bytes) this.input.push(b);
  }

  // hash_challenger.rs:36-43: hash the input, then input = output = digest.
  flush() {
    const d = keccak_256(Uint8Array.from(this.input));
    this.input = Array.from(d);
    this.output = Array.from(d);
    this.digest = beToBigInt(d);
  }

  // hash_challenger.rs:130-137
  sampleByte() {
    if (this.output.length === 0) this.flush();
    return this.output.pop();
  }

  // lib.rs:51-53 (sample_array) + serializing_challenger.rs:344 (u64::from_le_bytes)
  sampleU64() {
    const bytes = new Uint8Array(8);
    for (let i = 0; i < 8; i += 1) bytes[i] = this.sampleByte();
    return leToBigInt(bytes);
  }

  // serializing_challenger.rs:330-354
  sampleField() {
    for (;;) {
      const v = this.sampleU64();
      if (v < P) return v;
    }
  }

  // serializing_challenger.rs:362-367
  sampleBits(bits) {
    return this.sampleU64() & ((1n << BigInt(bits)) - 1n);
  }

  // grinding_challenger.rs:42-48
  checkWitness(bits, witness) {
    if (bits === 0) return true;
    this.observe(u64le(witness));
    return this.sampleBits(bits) === 0n;
  }

  avail() {
    return BigInt(this.output.length / 8);
  }

  len() {
    return BigInt(this.input.length);
  }
}

// Runs a script through the mirror; returns the pushed values and the digest.
function interpret(script) {
  const c = new RefChallenger();
  const out = [];
  let p = 0;
  const take = (n) => {
    if (p + n > script.length) throw new RangeError(`script truncated at ${p}`);
    const s = script.subarray(p, p + n);
    p += n;
    return s;
  };
  while (p < script.length) {
    const op = script[p];
    p += 1;
    switch (op) {
      case OP.OBSERVE_BYTES:
      case OP.OBSERVE_MEMORY: {
        const n = Number(beToBigInt(take(2)));
        c.observe(take(n));
        break;
      }
      case OP.OBSERVE_U64:
        c.observe(u64le(beToBigInt(take(8))));
        break;
      case OP.OBSERVE_DIGEST:
        c.observe(take(32));
        break;
      case OP.OBSERVE_EXT: {
        const c0 = beToBigInt(take(8));
        const c1 = beToBigInt(take(8));
        c.observe(concat([u64le(c0), u64le(c1)]));
        break;
      }
      case OP.SAMPLE_U64:
        out.push(c.sampleU64());
        break;
      case OP.SAMPLE_FIELD:
        out.push(c.sampleField());
        break;
      case OP.SAMPLE_EXT:
        out.push(c.sampleField());
        out.push(c.sampleField());
        break;
      case OP.SAMPLE_BITS:
        out.push(c.sampleBits(take(1)[0]));
        break;
      case OP.CHECK_WITNESS: {
        const bits = take(1)[0];
        const witness = beToBigInt(take(8));
        out.push(c.checkWitness(bits, witness) ? 1n : 0n);
        break;
      }
      case OP.PUSH_DIGEST:
        out.push(c.digest);
        break;
      case OP.PUSH_AVAIL:
        out.push(c.avail());
        break;
      case OP.PUSH_LEN:
        out.push(c.len());
        break;
      default:
        throw new Error(`unknown op 0x${op.toString(16)} at ${p - 1}`);
    }
  }
  return { samples: out, digest: c.digest };
}

function digestHex(value) {
  return `0x${value.toString(16).padStart(64, '0')}`;
}

function keccakHex(bytes) {
  return bytesToHex(keccak_256(bytes));
}

function group(digestHexValue, k) {
  return (beToBigInt(hexToBytes(digestHexValue)) >> BigInt(64 * k)) & MASK64;
}

// ---------------------------------------------------------------------------
// Vector transcript -> script
// ---------------------------------------------------------------------------

function listVectors() {
  return fs
    .readdirSync(VECTOR_DIR)
    .filter((f) => f.endsWith('.json'))
    .sort()
    .map((f) => ({ name: f.replace(/\.json$/, ''), file: path.join(VECTOR_DIR, f) }));
}

function loadVector(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

// Events of `kind` at or after index i, skipping annotations that do not
// consume transcript bytes, until an event of another consuming kind.
function nextEvent(events, i) {
  for (let j = i; j < events.length; j += 1) {
    if (events[j].op !== 'flush') return j;
  }
  return -1;
}

// raw: OBSERVE_BYTES + SAMPLE_U64; typed: the verifier's calls; memory: raw
// through observeMemory. Returns { script, expected, indices, openedDigest,
// openedPrefixLength } where openedPrefixLength is the byte length of the
// script prefix that ends with the first sample after the opened values.
function buildScript(vector, mode) {
  const events = vector.transcript;
  const s = new Script();
  const indices = [];
  let pendingFlush = null;
  let openedFlush = null;
  let openedPrefixLength = null;
  let lastObserveLabel = null;

  const afterSample = () => {
    if (pendingFlush) {
      s.pushDigest(`digest after ${pendingFlush.label}`, pendingFlush.bytes);
      if (openedFlush === pendingFlush && openedPrefixLength === null) {
        openedPrefixLength = s.bytes().length;
      }
      pendingFlush = null;
    }
  };

  for (let i = 0; i < events.length; i += 1) {
    const ev = events[i];
    switch (ev.op) {
      case 'flush':
        pendingFlush = ev;
        if (lastObserveLabel === 'quotient_chunk[1]') openedFlush = ev;
        break;
      case 'observe': {
        lastObserveLabel = ev.label;
        const bytes = hexToBytes(ev.bytes);
        if (mode === 'typed') {
          // A witness observation followed by its proof-of-work sample becomes
          // one checkWitness call (bits > 0 only; bits == 0 observes nothing).
          const j = nextEvent(events, i + 1);
          const k = j >= 0 ? nextEvent(events, j + 1) : -1;
          const l = k >= 0 ? nextEvent(events, k + 1) : -1;
          if (
            j >= 0 &&
            k >= 0 &&
            l >= 0 &&
            events[j].op === 'sample_u64' &&
            events[k].op === 'sample_bits' &&
            events[l].op === 'check_pow' &&
            events[l].bits > 0 &&
            bytes.length === 8 &&
            leToBigInt(bytes) === BigInt(events[l].witness)
          ) {
            for (let m = i + 1; m < l; m += 1) {
              if (events[m].op === 'flush') pendingFlush = events[m];
            }
            s.checkWitness(ev.label, events[l].bits, BigInt(events[l].witness), events[l].ok);
            afterSample();
            i = l;
            break;
          }
          if (bytes.length === 8) s.observeU64(leToBigInt(bytes));
          else if (bytes.length === 16) {
            s.observeExt(leToBigInt(bytes.subarray(0, 8)), leToBigInt(bytes.subarray(8, 16)));
          } else if (bytes.length === 32) s.observeDigest(ev.bytes);
          else s.observeBytes(bytes);
        } else {
          s.observeBytes(bytes, mode === 'memory');
        }
        break;
      }
      case 'sample_u64':
        if (mode !== 'typed') {
          s.sampleU64(ev.label, BigInt(ev.value));
          afterSample();
        }
        break;
      case 'sample_field': {
        assert.equal(ev.rejected.length, 0, `${vector.name} ${ev.label}: unexpected rejection`);
        if (mode !== 'typed') break;
        // Pair X.c0 with the directly following X.c1 into one sampleExt.
        const j = nextEvent(events, i + 1);
        const k = j >= 0 ? nextEvent(events, j + 1) : -1;
        const base = ev.label.endsWith('.c0') ? ev.label.slice(0, -3) : null;
        const paired =
          base !== null &&
          j >= 0 &&
          k >= 0 &&
          events[j].op === 'sample_u64' &&
          events[k].op === 'sample_field' &&
          events[k].label === `${base}.c1` &&
          !events.slice(i + 1, k).some((e) => e.op === 'flush');
        if (paired) {
          s.sampleExt(base, BigInt(ev.value), BigInt(events[k].value));
          i = k;
        } else {
          s.sampleField(ev.label, BigInt(ev.value));
        }
        afterSample();
        break;
      }
      case 'sample_bits': {
        const mask = (1n << BigInt(ev.bits)) - 1n;
        assert.equal(BigInt(ev.raw) & mask, BigInt(ev.value), `${vector.name} ${ev.label}: mask`);
        if (/^index\[\d+\]$/.test(ev.label)) indices.push(BigInt(ev.value));
        if (mode !== 'typed') break;
        s.sampleBits(ev.label, ev.bits, BigInt(ev.value));
        afterSample();
        break;
      }
      case 'check_pow':
        assert.equal(ev.ok, true, `${vector.name} ${ev.label}: vector records a failed PoW`);
        if (mode === 'typed' && ev.bits === 0) {
          s.checkWitness(ev.label, 0, BigInt(ev.witness), true);
        }
        break;
      default:
        throw new Error(`${vector.name}: unknown transcript op ${ev.op}`);
    }
  }
  assert.ok(openedFlush, `${vector.name}: no flush after the opened values`);
  assert.ok(openedPrefixLength !== null, `${vector.name}: opened-values prefix not found`);
  return {
    script: s.bytes(),
    expected: s.expected,
    indices,
    openedDigest: openedFlush.bytes,
    openedPrefixLength,
    lastDigest: events.filter((e) => e.op === 'flush').at(-1).bytes,
  };
}

function assertSamples(actual, expected, context) {
  assert.equal(actual.length, expected.length, `${context}: sample count`);
  for (let i = 0; i < expected.length; i += 1) {
    assert.equal(actual[i], expected[i].value, `${context}: sample ${i} (${expected[i].label})`);
  }
}

// ---------------------------------------------------------------------------
// Suite
// ---------------------------------------------------------------------------

test('KeccakChallenger harness', { skip, timeout: 900000 }, async (t) => {
  const ctx = await connect();
  const h = await deployHarness(ctx, 'test/ChallengerHarness.hyp', 'ChallengerHarness');

  const replay = async (script) =>
    h.callOne('replay(bytes)', [script], 'uint512[]', { gas: 20_000_000 });
  const digestAfter = async (script) =>
    h.callOne('digestAfter(bytes)', [script], 'bytes32', { gas: 20_000_000 });
  const gasReplay = async (script) =>
    h.callOne('gasReplay(bytes)', [script], 'uint512', { gas: 20_000_000 });

  // Replays a hand-built script: the mirror's interpretation is the expectation,
  // and the builder's own expectations (when given) must agree with the mirror.
  const check = async (s, context) => {
    const script = s.bytes();
    const ref = interpret(script);
    if (s.expected.length > 0) assertSamples(ref.samples, s.expected, `${context} (mirror)`);
    const samples = await replay(script);
    assert.deepEqual(samples, ref.samples, `${context}: chain vs mirror`);
    assert.equal(await digestAfter(script), digestHex(ref.digest), `${context}: digestAfter`);
    return samples;
  };

  const gasRows = [];

  await t.test('replays every valid vector transcript (raw, typed, memory)', async () => {
    const vectors = listVectors();
    assert.ok(vectors.length > 0, 'no vectors under test/vectors');
    for (const { name, file } of vectors) {
      const vector = loadVector(file);
      assert.equal(vector.expected.valid, true, `${name} is not a valid vector`);
      const row = { name, n: vector.degreeBits, Q: vector.config.numQueries };
      for (const mode of ['raw', 'typed', 'memory']) {
        const built = buildScript(vector, mode);
        const context = `${name} ${mode}`;
        // The mirror must reproduce the Rust log before the chain is asked to.
        assertSamples(interpret(built.script).samples, built.expected, `${context} (mirror)`);
        const samples = await replay(built.script);
        assertSamples(samples, built.expected, context);
        assert.equal(await digestAfter(built.script), built.lastDigest, `${context}: final digest`);
        assert.equal(
          await digestAfter(built.script.subarray(0, built.openedPrefixLength)),
          built.openedDigest,
          `${context}: digest after the opened values`
        );
        assert.deepEqual(
          built.indices,
          vector.challenges.indices.map((x) => BigInt(x)),
          `${context}: query indices`
        );
        assert.equal(built.indices.length, vector.config.numQueries, `${context}: index count`);
        row[`${mode}Bytes`] = built.script.length;
        row[`${mode}Gas`] = Number(await gasReplay(built.script));
      }
      row.estimate = Number(
        await h.estimateGas('replay(bytes)', [buildScript(vector, 'raw').script])
      );
      row.flushes = vector.transcript.filter((e) => e.op === 'flush').length;
      gasRows.push(row);
    }
    console.log(
      'challenger replay gas (gasleft delta inside the harness; estimate = qrl_estimateGas of replay(raw))'
    );
    console.log(
      'vector, n, Q, flushes, rawBytes, rawGas, typedBytes, typedGas, memoryGas, estimate'
    );
    for (const r of gasRows) {
      console.log(
        [
          r.name,
          r.n,
          r.Q,
          r.flushes,
          r.rawBytes,
          r.rawGas,
          r.typedBytes,
          r.typedGas,
          r.memoryGas,
          r.estimate,
        ].join(', ')
      );
    }
  });

  await t.test('empty transcript: the first flush hashes zero bytes', async () => {
    const s = new Script();
    s.pushLen('len', 0n)
      .pushAvail('avail', 0n)
      .sampleU64('g0', group(keccakHex(new Uint8Array(0)), 0));
    s.pushDigest('digest', keccakHex(new Uint8Array(0)))
      .pushLen('len', 32n)
      .pushAvail('avail', 3n);
    await check(s, 'empty');
  });

  await t.test('four groups per flush, then a rehash of the exhausted digest', async () => {
    const bytes = Uint8Array.from({ length: 80 }, (_, i) => (i * 7 + 3) & 0xff);
    const d1 = keccakHex(bytes);
    const d2 = keccakHex(hexToBytes(d1));
    const d3 = keccakHex(hexToBytes(d2));
    const s = new Script();
    s.observeBytes(bytes).pushLen('len', 80n).pushAvail('avail', 0n);
    for (let k = 0; k < 4; k += 1) {
      s.sampleU64(`d1 group ${k}`, group(d1, k));
      s.pushDigest(`digest after group ${k}`, d1).pushAvail(
        `avail after group ${k}`,
        BigInt(3 - k)
      );
      s.pushLen(`len after group ${k}`, 32n);
    }
    // Group 5 forces D2 = keccak256(D1); nothing was observed in between.
    for (let k = 0; k < 4; k += 1) s.sampleU64(`d2 group ${k}`, group(d2, k));
    s.pushDigest('digest after d2', d2).pushAvail('avail after d2', 0n);
    s.sampleU64('d3 group 0', group(d3, 0)).pushDigest('digest after d3', d3);
    await check(s, 'four groups');
  });

  await t.test('observe discards unread groups and appends to the digest', async () => {
    const a = Uint8Array.from([1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
    const b = Uint8Array.from([0xde, 0xad, 0xbe, 0xef, 0x00, 0x01]);
    const d1 = keccakHex(a);
    const d2 = keccakHex(concat([hexToBytes(d1), b]));
    const s = new Script();
    s.observeBytes(a).sampleU64('d1 group 0', group(d1, 0)).pushAvail('unread', 3n);
    s.observeBytes(b).pushAvail('after observe', 0n).pushLen('len', 38n);
    s.sampleU64('d2 group 0', group(d2, 0)).pushDigest('d2', d2);
    // The three unread groups of d1 never surface.
    s.sampleU64('d2 group 1', group(d2, 1)).sampleU64('d2 group 2', group(d2, 2));
    await check(s, 'discard');
    // Observing zero bytes still discards the unread output.
    const z = new Script();
    z.observeBytes(a).sampleU64('d1 group 0', group(d1, 0)).observeBytes(new Uint8Array(0));
    z.pushAvail('after empty observe', 0n).pushLen('len', 32n);
    z.sampleU64('keccak(d1) group 0', group(keccakHex(hexToBytes(d1)), 0));
    await check(z, 'discard on empty observe');
  });

  await t.test('typed observes produce the same bytes as raw observes', async () => {
    const u = 0x0123456789abcdefn;
    const c0 = 0xfedcba9876543210n;
    const c1 = 0x1122334455667788n;
    const digest = keccakHex(Uint8Array.from([42]));
    const raw = new Script();
    raw.observeBytes(concat([u64le(u), u64le(c0), u64le(c1), hexToBytes(digest)]));
    raw.sampleU64('g0', 0n);
    const typed = new Script();
    typed.observeU64(u).observeExt(c0, c1).observeDigest(digest).sampleU64('g0', 0n);
    raw.expected.length = 0;
    typed.expected.length = 0;
    const [r, ty] = await Promise.all([check(raw, 'raw'), check(typed, 'typed')]);
    assert.deepEqual(ty, r);
    assert.equal(await digestAfter(typed.bytes()), await digestAfter(raw.bytes()));
    assert.equal(
      await digestAfter(typed.bytes()),
      keccakHex(concat([u64le(u), u64le(c0), u64le(c1), hexToBytes(digest)]))
    );
  });

  await t.test('observeMemory matches observeCalldata for odd sizes', async () => {
    for (const size of [1, 7, 8, 63, 64, 65, 100, 127, 128, 129, 300]) {
      const bytes = Uint8Array.from({ length: size }, (_, i) => (i * 31 + size) & 0xff);
      const viaCalldata = new Script().observeBytes(bytes, false).sampleU64('g0', 0n);
      const viaMemory = new Script().observeBytes(bytes, true).sampleU64('g0', 0n);
      viaCalldata.expected.length = 0;
      viaMemory.expected.length = 0;
      const [a, b] = await Promise.all([
        check(viaCalldata, `cd ${size}`),
        check(viaMemory, `mem ${size}`),
      ]);
      assert.deepEqual(b, a, `size ${size}`);
      assert.equal(await digestAfter(viaMemory.bytes()), keccakHex(bytes), `size ${size}`);
    }
    // Two memory observes back to back: the second one starts at len, inside a word.
    const first = Uint8Array.from({ length: 33 }, (_, i) => i);
    const second = Uint8Array.from({ length: 50 }, (_, i) => 200 - i);
    const s = new Script().observeBytes(first, true).observeBytes(second, true).sampleU64('g0', 0n);
    s.expected.length = 0;
    await check(s, 'two memory observes');
    assert.equal(await digestAfter(s.bytes()), keccakHex(concat([first, second])));
  });

  await t.test(
    'sampleBits masks one full group and sampleField accepts canonical groups',
    async () => {
      const bytes = Uint8Array.from({ length: 24 }, (_, i) => 255 - i);
      const d1 = keccakHex(bytes);
      const s = new Script();
      s.observeBytes(bytes);
      s.sampleBits('13 bits', 13, group(d1, 0) & 0x1fffn);
      s.sampleBits('1 bit', 1, group(d1, 1) & 1n);
      s.sampleBits('63 bits', 63, group(d1, 2) & ((1n << 63n) - 1n));
      s.sampleBits('0 bits', 0, 0n);
      s.pushAvail('avail', 0n);
      // Every group of this digest chain is < p (probability 1 - 2^-32 each).
      const d2 = keccakHex(hexToBytes(d1));
      for (let k = 0; k < 4; k += 1) assert.ok(group(d2, k) < P);
      s.sampleExt('ext', group(d2, 0), group(d2, 1));
      s.sampleField('field', group(d2, 2));
      await check(s, 'bits');
      // Plonky3 asserts 2^bits < p; the library rejects bits >= 64.
      const wide = new Script().observeBytes(bytes).sampleBits('64 bits', 64, 0n);
      await expectRevert(h, 'replay(bytes)', [wide.bytes()], 'SampleBitsOutOfRange()');
    }
  );

  await t.test('checkWitness: no-op at 0 bits, observe + sampleBits otherwise', async () => {
    const prefix = Uint8Array.from({ length: 40 }, (_, i) => (i * 13) & 0xff);
    // Grind a 16-bit witness (about 2^16 keccak calls): the PoW group is group 0
    // of keccak256(prefix || LE(witness)). Confirmed through the mirror below.
    let witness = 0n;
    while ((group(keccakHex(concat([prefix, u64le(witness)])), 0) & 0xffffn) !== 0n) {
      witness += 1n;
    }
    const grind = new RefChallenger();
    grind.observe(prefix);
    assert.equal(grind.checkWitness(16, witness), true);
    const d1 = keccakHex(prefix);
    const s = new Script();
    s.observeBytes(prefix).sampleU64('g0', group(d1, 0)).pushAvail('unread', 3n);
    s.checkWitness('pow 0 bits', 0, 12345n, true).pushAvail('still unread', 3n).pushLen('len', 32n);
    s.sampleU64('g1', group(d1, 1));
    const good = new Script();
    good.observeBytes(prefix).checkWitness('pow ok', 16, witness, true).pushLen('len', 32n);
    good.pushDigest('digest', keccakHex(concat([prefix, u64le(witness)])));
    const bad = new Script();
    bad.observeBytes(prefix).checkWitness('pow fails', 16, witness + 1n, false);
    await check(s, 'pow no-op');
    await check(good, 'pow ok');
    const badRef = interpret(bad.bytes());
    assert.deepEqual(badRef.samples, [0n]);
    await check(bad, 'pow fails');
  });

  await t.test('forced rejection: a group >= p is skipped by sampleField', async () => {
    const prefix = u64le(REJECTION_PREFIX.u64);
    const d1 = keccakHex(prefix);
    assert.equal(d1, REJECTION_PREFIX.digest, 'search result does not reproduce');
    const k = REJECTION_PREFIX.group;
    assert.ok(group(d1, k) >= P, `group ${k} of ${d1} is canonical`);
    const rejectedGroups = [0, 1, 2, 3].filter((i) => group(d1, i) >= P);
    assert.deepEqual(rejectedGroups, [k], 'exactly one rejected group expected');
    const d2 = keccakHex(hexToBytes(d1));
    const accepted = [0, 1, 2, 3].filter((i) => i !== k).map((i) => group(d1, i));
    accepted.push(group(d2, 0));
    // The shared JS reference (test/lib/challenger.js) must skip the same group.
    const { Challenger } = require('../lib/challenger');
    const shared = new Challenger();
    shared.observeU64LE(REJECTION_PREFIX.u64, 'preimage');
    const sharedFields = [0, 1, 2, 3].map((i) => shared.sampleField(`field ${i}`));
    assert.deepEqual(sharedFields, accepted, 'shared reference disagrees with the search result');
    const sharedEvents = shared.events.filter((e) => e.op === 'sample_field');
    assert.deepEqual(
      sharedEvents.map((e) => e.rejected.length),
      [0, 0, 1, 0],
      'shared reference rejection pattern'
    );
    // Raw groups show the non-canonical value; field samples skip it.
    const raw = new Script().observeU64(REJECTION_PREFIX.u64);
    for (let i = 0; i < 4; i += 1) raw.sampleU64(`group ${i}`, group(d1, i));
    const fields = new Script().observeU64(REJECTION_PREFIX.u64);
    fields.sampleField('field 0', accepted[0]).sampleField('field 1', accepted[1]);
    fields.sampleExt('ext', accepted[2], accepted[3]).pushDigest('rehashed', d2);
    await check(raw, 'rejection raw');
    const samples = await check(fields, 'rejection fields');
    assert.ok(samples.slice(0, 4).every((v) => v < P));
  });

  await t.test('primitive gas: marginal cost per library call (gasLoop)', async () => {
    // (gasLoop(op, 2n) - gasLoop(op, n)) / n: the loop overhead is op 0.
    // n = 100 keeps 2n observes of 32 bytes inside the 8 KB buffer.
    const ops = [
      [0, 'empty loop'],
      [1, 'observeU64LE'],
      [2, 'observeExt'],
      [3, 'observeDigest'],
      [4, 'observeCalldata 8 bytes'],
      [5, 'observeMemory 16 bytes'],
      [6, 'nextU64 on the digest chain (one 32-byte flush per 4)'],
      [7, 'sampleField on the digest chain'],
      [8, 'sampleBits(13) on the digest chain'],
      [9, 'observeU64LE + nextU64 (one 40-byte flush each)'],
      [10, 'checkWitness(16): observe + 40-byte flush + sampleBits'],
    ];
    console.log('challenger primitive gas (marginal per call, loop overhead = op 0)');
    for (const [op, label] of ops) {
      const { marginal } = await marginalGas(h, op, 100n, { gas: 20_000_000 });
      console.log(`${Math.round(marginal * 10) / 10}, ${label}`);
      assert.ok(marginal >= 0, `${label}: negative marginal gas`);
    }
    await expectRevert(h, 'gasLoop(uint8,uint512)', [11n, 1n], 'BadScript(uint512)');
  });

  await t.test('buffer overflow guard and script validation', async () => {
    const full = Uint8Array.from({ length: BUF_CAPACITY }, (_, i) => (i * 3) & 0xff);
    const fits = new Script().observeBytes(full).sampleU64('g0', 0n);
    fits.expected.length = 0;
    await check(fits, 'capacity');
    assert.equal(await digestAfter(fits.bytes()), keccakHex(full));
    // One byte more than the capacity in one observe, and one byte after a full buffer.
    const over = new Script().observeBytes(concat([full, Uint8Array.of(1)]));
    await expectRevert(h, 'replay(bytes)', [over.bytes()], 'ChallengerOverflow()');
    const overSplit = new Script().observeBytes(full).observeU64(1n);
    await expectRevert(h, 'replay(bytes)', [overSplit.bytes()], 'ChallengerOverflow()');
    // After a flush the pending input is 32 bytes, so capacity - 32 more fit.
    const afterFlush = new Script().observeBytes(full).sampleU64('g0', 0n);
    afterFlush.observeBytes(full.subarray(0, BUF_CAPACITY - 32)).sampleU64('g1', 0n);
    afterFlush.expected.length = 0;
    await check(afterFlush, 'refill after flush');
    const afterFlushOver = new Script().observeBytes(full).sampleU64('g0', 0n);
    afterFlushOver.observeBytes(full.subarray(0, BUF_CAPACITY - 31));
    await expectRevert(h, 'replay(bytes)', [afterFlushOver.bytes()], 'ChallengerOverflow()');
    // Unknown op and a truncated payload.
    await expectRevert(h, 'replay(bytes)', [Uint8Array.of(0x10, 0x99)], 'BadScript(uint512)');
    await expectRevert(
      h,
      'replay(bytes)',
      [Uint8Array.of(0x01, 0x00, 0x10, 0xaa)],
      'BadScript(uint512)'
    );
    await expectRevert(h, 'gasReplay(bytes)', [Uint8Array.of(0x02, 0x01)], 'BadScript(uint512)');
  });
});
