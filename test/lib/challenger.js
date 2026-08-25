// Byte-exact JS model of the Plonky3 Fiat-Shamir transcript used by
// QuantaStark: SerializingChallenger64<Goldilocks, HashChallenger<u8,
// Keccak256Hash, 32>> (crates p3-challenger 0.7.0-rc.1).
//
// Semantics, with the rc.1 source locations they are taken from:
//
// - HashChallenger keeps an input buffer and an output buffer of bytes.
//   observe(byte) clears the output buffer and appends the byte to the input
//   buffer (hash_challenger.rs:51-56; observe_slice is the trait default that
//   observes one byte at a time, lib.rs:32-39). Any unread sampled bytes are
//   therefore discarded by the next observe.
// - sample() with an empty output buffer flushes: D = keccak256(input), the
//   input buffer is drained and refilled with D (the chaining value) and the
//   output buffer becomes D (hash_challenger.rs:36-43); then one byte is
//   popped from the END of the output buffer (hash_challenger.rs:130-137).
// - SerializingChallenger64 observes a field element as its canonical value
//   in 8 little-endian bytes (serializing_challenger.rs:263-267) and a Merkle
//   cap as the raw bytes of each root (serializing_challenger.rs:290-299).
// - sample_u64 = u64::from_le_bytes(sample_array::<8>()): eight popped bytes
//   read little-endian, so with D viewed as a big-endian 256-bit integer the
//   k-th sample of a flush is group k = (D >> 64k) & (2^64 - 1) for
//   k = 0, 1, 2, 3 (serializing_challenger.rs:336-354).
// - sample() of a base element masks the u64 to log2_ceil(p) = 64 bits (no
//   effect) and rejects values >= p, drawing the next group
//   (serializing_challenger.rs:343-352). An extension element is sampled
//   coefficient by coefficient (lib.rs:124-126; observed likewise, lib.rs:106-108).
// - sample_bits(b) draws one full u64 group and masks its low b bits
//   (serializing_challenger.rs:362-367).
// - check_witness(bits, w) returns true immediately for bits == 0; otherwise
//   it observes w as a field element and requires sample_bits(bits) == 0
//   (grinding_challenger.rs:42-48).
//
// Every method records an event in the exact shape prover/stark-prover/src/
// mirror.rs writes into the vector files (`transcript[]`), so replay() can
// compare a vector's transcript event by event, including the flush inputs.

const { keccak_256 } = require('@noble/hashes/sha3');

const { bytesToHex, hexToBytes } = require('./vectors');

const P = 0xffffffff00000001n;
const MASK64 = 0xffffffffffffffffn;
const DIGEST_BYTES = 32;
const GROUPS_PER_FLUSH = DIGEST_BYTES / 8;

function u64ToLeBytes(value) {
  let v = BigInt(value);
  if (v < 0n || v > MASK64) throw new RangeError(`u64 out of range: ${v}`);
  const out = new Uint8Array(8);
  for (let i = 0; i < 8; i += 1) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

function assertCanonical(value, what) {
  if (typeof value !== 'bigint' || value < 0n || value >= P) {
    throw new RangeError(`${what} is not a canonical Goldilocks element: ${String(value)}`);
  }
}

function toBytes(bytes) {
  if (bytes instanceof Uint8Array) return bytes;
  if (typeof bytes === 'string') return hexToBytes(bytes);
  if (Array.isArray(bytes)) return Uint8Array.from(bytes);
  throw new TypeError('bytes expected (Uint8Array, hex string or number array)');
}

class Challenger {
  // options.hash: the byte hash (default keccak256); tests inject a stub to
  // force a rejection-sampling case. options.record: keep the event log.
  constructor(options = {}) {
    this.hash = options.hash || keccak_256;
    this.record = options.record !== false;
    this.input = [];
    this.output = [];
    this.events = [];
    this.flushes = 0;
  }

  clone() {
    const c = new Challenger({ hash: this.hash, record: this.record });
    c.input = this.input.slice();
    c.output = this.output.slice();
    c.events = this.events.slice();
    c.flushes = this.flushes;
    return c;
  }

  push(event) {
    if (this.record) this.events.push(event);
  }

  // Observe raw bytes (a digest, or the serialized form of anything else).
  observeBytes(bytes, label = 'bytes') {
    const b = toBytes(bytes);
    // Any buffered output is now invalid (hash_challenger.rs:52-53).
    this.output.length = 0;
    for (const byte of b) this.input.push(byte);
    this.push({ op: 'observe', label, bytes: bytesToHex(b) });
  }

  // Observe a u64 as eight little-endian bytes (no field range check).
  observeU64LE(value, label = 'u64') {
    this.observeBytes(u64ToLeBytes(value), label);
  }

  // Observe a canonical base field element (F on the wire).
  observeField(value, label = 'field') {
    assertCanonical(value, label);
    this.observeU64LE(value, label);
  }

  // Observe a 32-byte Merkle root (MerkleCap of height 0).
  observeDigest(bytes, label = 'digest') {
    const b = toBytes(bytes);
    if (b.length !== DIGEST_BYTES) {
      throw new RangeError(`digest must be ${DIGEST_BYTES} bytes, got ${b.length}`);
    }
    this.observeBytes(b, label);
  }

  // Observe an extension element as c0 || c1.
  observeExt(pair, label = 'ext') {
    assertCanonical(pair[0], `${label}.c0`);
    assertCanonical(pair[1], `${label}.c1`);
    const bytes = new Uint8Array(16);
    bytes.set(u64ToLeBytes(pair[0]), 0);
    bytes.set(u64ToLeBytes(pair[1]), 8);
    this.observeBytes(bytes, label);
  }

  flush() {
    const inputBytes = Uint8Array.from(this.input);
    const digest = this.hash(inputBytes);
    if (!(digest instanceof Uint8Array) || digest.length !== DIGEST_BYTES) {
      throw new Error('hash must return 32 bytes');
    }
    this.push({
      op: 'flush',
      label: `flush[${this.flushes}]`,
      input: bytesToHex(inputBytes),
      bytes: bytesToHex(digest),
    });
    this.flushes += 1;
    // Chaining value: the input buffer becomes exactly the digest.
    this.input = Array.from(digest);
    this.output = Array.from(digest);
  }

  sampleByte() {
    if (this.output.length === 0) this.flush();
    return this.output.pop();
  }

  // One 64-bit group: eight popped bytes read little-endian.
  sampleU64(label = 'u64') {
    const bytes = new Uint8Array(8);
    for (let i = 0; i < 8; i += 1) bytes[i] = this.sampleByte();
    let value = 0n;
    for (let i = 7; i >= 0; i -= 1) value = (value << 8n) | BigInt(bytes[i]);
    this.push({ op: 'sample_u64', label, bytes: bytesToHex(bytes), value: value.toString() });
    return value;
  }

  // Rejection-sampled base field element: groups >= p are discarded.
  sampleField(label = 'field') {
    const rejected = [];
    for (;;) {
      const v = this.sampleU64(label);
      if (v < P) {
        this.push({ op: 'sample_field', label, value: v.toString(), rejected });
        return v;
      }
      rejected.push(v.toString());
    }
  }

  // Extension element: c0 then c1.
  sampleExt(label = 'ext') {
    const c0 = this.sampleField(`${label}.c0`);
    const c1 = this.sampleField(`${label}.c1`);
    return [c0, c1];
  }

  // One full u64 group masked to its low `bits` bits; no rejection sampling.
  sampleBits(bits, label = 'bits') {
    if (!Number.isInteger(bits) || bits < 0 || bits >= 64 || 1n << BigInt(bits) >= P) {
      throw new RangeError(`sample_bits: unsupported bit count ${bits}`);
    }
    const raw = this.sampleU64(label);
    const value = raw & ((1n << BigInt(bits)) - 1n);
    this.push({
      op: 'sample_bits',
      label,
      bits,
      raw: raw.toString(),
      value: value.toString(),
    });
    return Number(value);
  }

  // GrindingChallenger::check_witness.
  checkWitness(bits, witness, label = 'pow') {
    assertCanonical(witness, `${label}.witness`);
    if (bits === 0) {
      this.push({ op: 'check_pow', label, bits, witness: witness.toString(), ok: true });
      return true;
    }
    this.observeField(witness, `${label}.witness`);
    const value = this.sampleBits(bits, label);
    const ok = value === 0;
    this.push({
      op: 'check_pow',
      label,
      bits,
      witness: witness.toString(),
      value: String(value),
      ok,
    });
    return ok;
  }
}

// Group k of a digest, as defined in the header comment (k = 0 is served first).
function digestGroup(digest, k) {
  if (!Number.isInteger(k) || k < 0 || k >= GROUPS_PER_FLUSH) {
    throw new RangeError(`group index out of range: ${k}`);
  }
  let d = 0n;
  for (const b of digest) d = (d << 8n) | BigInt(b);
  return (d >> BigInt(64 * k)) & MASK64;
}

function canonicalJson(value) {
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(',')}]`;
  if (value && typeof value === 'object') {
    return `{${Object.keys(value)
      .sort()
      .map((k) => `${JSON.stringify(k)}:${canonicalJson(value[k])}`)
      .join(',')}}`;
  }
  return JSON.stringify(value);
}

// Throw on the first event that differs (index, op and both renderings).
function compareEvents(actual, expected) {
  const n = Math.min(actual.length, expected.length);
  for (let i = 0; i < n; i += 1) {
    const a = canonicalJson(actual[i]);
    const e = canonicalJson(expected[i]);
    if (a !== e) {
      throw new Error(`transcript event ${i} differs:\n  js:     ${a}\n  vector: ${e}`);
    }
  }
  if (actual.length !== expected.length) {
    throw new Error(
      `transcript length differs: js ${actual.length} events, vector ${expected.length} events`
    );
  }
}

// Find the check_pow event that a `<label>.witness` observe belongs to: the
// next check_pow event, provided no other observe intervenes and its label
// matches. Returns its index or -1.
function findWitnessCheck(events, observeIndex) {
  const label = events[observeIndex].label;
  if (typeof label !== 'string' || !label.endsWith('.witness')) return -1;
  for (let j = observeIndex + 1; j < events.length; j += 1) {
    const op = events[j].op;
    if (op === 'check_pow') {
      return `${events[j].label}.witness` === label && events[j].bits > 0 ? j : -1;
    }
    if (op === 'observe') return -1;
  }
  return -1;
}

// Drive a fresh challenger through a vector's transcript (the recorded
// observes, field / bit samples and PoW checks) and assert that the JS
// challenger produces the identical event list: every flush input and digest,
// every popped byte group, every accepted or rejected value and every PoW
// outcome. Returns the challenger (its `events` are the JS-side log).
function replay(events, options = {}) {
  const ch = new Challenger(options);
  let i = 0;
  while (i < events.length) {
    const e = events[i];
    switch (e.op) {
      case 'observe': {
        const pow = findWitnessCheck(events, i);
        if (pow >= 0) {
          ch.checkWitness(events[pow].bits, BigInt(events[pow].witness), events[pow].label);
          i = pow + 1;
        } else {
          ch.observeBytes(hexToBytes(e.bytes), e.label);
          i += 1;
        }
        break;
      }
      case 'flush':
        // Flushes happen implicitly on sampling; they are verified by compareEvents.
        i += 1;
        break;
      case 'sample_u64': {
        let j = i + 1;
        while (j < events.length && (events[j].op === 'sample_u64' || events[j].op === 'flush')) {
          j += 1;
        }
        const annotation = events[j];
        if (!annotation) throw new Error(`sample_u64 at ${i} has no annotation`);
        if (annotation.op === 'sample_field') {
          ch.sampleField(annotation.label);
        } else if (annotation.op === 'sample_bits') {
          ch.sampleBits(annotation.bits, annotation.label);
        } else {
          throw new Error(`unexpected annotation ${annotation.op} at ${j}`);
        }
        i = j + 1;
        break;
      }
      case 'check_pow': {
        if (e.bits !== 0) {
          throw new Error(`check_pow with bits ${e.bits} at ${i} lacks its witness observe`);
        }
        ch.checkWitness(0, BigInt(e.witness), e.label);
        i += 1;
        break;
      }
      case 'sample_field':
      case 'sample_bits':
        throw new Error(`${e.op} at ${i} without a preceding sample_u64`);
      default:
        throw new Error(`unknown transcript op ${String(e.op)} at ${i}`);
    }
  }
  compareEvents(ch.events, events);
  return ch;
}

// label -> value for every sample_field, sample_bits and check_pow event.
function samplesByLabel(events) {
  const out = new Map();
  for (const e of events) {
    if (e.op === 'sample_field') out.set(e.label, BigInt(e.value));
    else if (e.op === 'sample_bits') out.set(e.label, Number(e.value));
    else if (e.op === 'check_pow') out.set(e.label, e.ok);
  }
  return out;
}

module.exports = {
  Challenger,
  DIGEST_BYTES,
  GROUPS_PER_FLUSH,
  MASK64,
  P,
  canonicalJson,
  compareEvents,
  digestGroup,
  replay,
  samplesByLabel,
  u64ToLeBytes,
};
