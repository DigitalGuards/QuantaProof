// BigInt reference implementation of the Goldilocks base field
// (p = 2^64 - 2^32 + 1) used by the unit and contract suites.
//
// Mirrors contracts/hyperion/lib/Goldilocks.hyp function by function so a
// contract test can compare thousands of random operations against these
// results. Elements are BigInt values in [0, p); inputs are assumed canonical
// unless a function says otherwise. Also provides the two-adic generator table
// (Plonky3 TWO_ADIC_GENERATORS), its inverses, the packed table words the
// contract stores as constants, the calldata lane helpers and a seeded PRNG
// (splitmix64) so every random test is reproducible.

const P = 0xffffffff00000001n;
const GENERATOR = 7n;
const TWO_ADICITY = 32;
const INV2 = 0x7fffffff80000001n;
const MASK64 = 0xffffffffffffffffn;
const WORD_BITS = 512n;

function assertCanonical(x, name = 'element') {
  if (typeof x !== 'bigint' || x < 0n || x >= P) {
    throw new RangeError(`${name} is not a canonical Goldilocks element: ${String(x)}`);
  }
}

function isCanonical(x) {
  return typeof x === 'bigint' && x >= 0n && x < P;
}

function reduce(x) {
  return ((x % P) + P) % P;
}

function add(a, b) {
  const s = a + b;
  return s >= P ? s - P : s;
}

function sub(a, b) {
  const d = a - b;
  return d < 0n ? d + P : d;
}

function neg(a) {
  return a === 0n ? 0n : P - a;
}

function mul(a, b) {
  return (a * b) % P;
}

function sq(a) {
  return (a * a) % P;
}

// (a * b + c) mod p for canonical a, b and any c < 2^384 (lazy reduction).
function mulAdd(a, b, c) {
  return (a * b + c) % P;
}

// Square-and-multiply; e is any non-negative BigInt.
function pow(x, e) {
  let base = x % P;
  let exp = BigInt(e);
  let result = 1n;
  while (exp > 0n) {
    if (exp & 1n) result = (result * base) % P;
    base = (base * base) % P;
    exp >>= 1n;
  }
  return result;
}

// k successive squarings: x^(2^k).
function pow2k(x, k) {
  let r = x % P;
  for (let i = 0; i < k; i += 1) r = (r * r) % P;
  return r;
}

// Fermat inversion, the same map the contract asks the modexp precompile for.
function inv(x) {
  if (x % P === 0n) throw new RangeError('inverse of zero');
  return pow(x, P - 2n);
}

// g_32 = GENERATOR^((p - 1) / 2^32); g_i = g_32^(2^(32 - i)).
function computeTwoAdicGenerators() {
  const g32 = pow(GENERATOR, (P - 1n) >> BigInt(TWO_ADICITY));
  const table = new Array(TWO_ADICITY + 1);
  for (let i = 0; i <= TWO_ADICITY; i += 1) {
    table[i] = pow2k(g32, TWO_ADICITY - i);
  }
  return table;
}

const TWO_ADIC_GENERATORS = Object.freeze(computeTwoAdicGenerators());
const TWO_ADIC_GENERATOR_INVERSES = Object.freeze(TWO_ADIC_GENERATORS.map((g) => inv(g)));

function twoAdicGen(i) {
  if (!Number.isInteger(i) || i < 0 || i > TWO_ADICITY) {
    throw new RangeError(`two-adic index out of range: ${i}`);
  }
  return TWO_ADIC_GENERATORS[i];
}

function twoAdicGenInv(i) {
  if (!Number.isInteger(i) || i < 0 || i > TWO_ADICITY) {
    throw new RangeError(`two-adic index out of range: ${i}`);
  }
  return TWO_ADIC_GENERATOR_INVERSES[i];
}

// The contract packs eight 64-bit table entries per 512-bit word: entry i
// lives in word i >> 3 at bit offset 64 * (i & 7), counted from the low end.
function packTableWords(table) {
  const words = [];
  for (let i = 0; i < table.length; i += 1) {
    const w = i >> 3;
    if (words[w] === undefined) words[w] = 0n;
    words[w] |= (table[i] & MASK64) << BigInt(64 * (i & 7));
  }
  return words;
}

// Reverse the low `bits` bits of x (1 <= bits <= 32), Plonky3 reverse_bits_len.
function rev(x, bits) {
  if (!Number.isInteger(bits) || bits < 1 || bits > 32) {
    throw new RangeError(`bit count out of range: ${bits}`);
  }
  let v = BigInt(x) & ((1n << BigInt(bits)) - 1n);
  let r = 0n;
  for (let i = 0; i < bits; i += 1) {
    r = (r << 1n) | (v & 1n);
    v >>= 1n;
  }
  return r;
}

// Byte swap of one 64-bit value.
function bswap64(x) {
  let v = BigInt(x) & MASK64;
  let r = 0n;
  for (let i = 0; i < 8; i += 1) {
    r = (r << 8n) | (v & 0xffn);
    v >>= 8n;
  }
  return r;
}

function u64ToLeBytes(x) {
  const out = new Uint8Array(8);
  let v = BigInt(x) & MASK64;
  for (let i = 0; i < 8; i += 1) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

function leBytesToU64(bytes, offset = 0) {
  let v = 0n;
  for (let i = 7; i >= 0; i -= 1) {
    v = (v << 8n) | BigInt(bytes[offset + i] ?? 0);
  }
  return v;
}

// Encode canonical elements as consecutive 8-byte little-endian slices.
function elementsToBytes(elements) {
  const out = new Uint8Array(elements.length * 8);
  elements.forEach((e, i) => out.set(u64ToLeBytes(e), i * 8));
  return out;
}

// The eight little-endian u64 lanes of the 64 bytes at `offset`; bytes past
// the end read as zero, matching calldataload.
function laneDecode(bytes, offset = 0) {
  const lanes = [];
  for (let k = 0; k < 8; k += 1) {
    lanes.push(leBytesToU64(bytes, offset + 8 * k));
  }
  return lanes;
}

// The packed 512-bit word Goldilocks.cdLanes returns: lane 0 (lowest calldata
// offset) in the top 64 bits.
function packLanes(lanes) {
  let w = 0n;
  for (let k = 0; k < 8; k += 1) {
    w = (w << 64n) | (BigInt(lanes[k] ?? 0n) & MASK64);
  }
  return w;
}

function lane(word, k) {
  if (!Number.isInteger(k) || k < 0 || k > 7) {
    throw new RangeError(`lane index out of range: ${k}`);
  }
  return (BigInt(word) >> BigInt(448 - 64 * k)) & MASK64;
}

function lanesCanonical(lanes) {
  return lanes.every((x) => x < P);
}

// One canonical element from the 8 little-endian bytes at `offset`; throws on
// a value >= p exactly where the contract reverts with NonCanonicalElement().
function cdElem(bytes, offset = 0) {
  const v = leBytesToU64(bytes, offset);
  if (v >= P) throw new RangeError(`non-canonical element at offset ${offset}`);
  return v;
}

// splitmix64: deterministic 64-bit stream from a seed.
function splitmix64(seed) {
  let state = BigInt(seed) & MASK64;
  return () => {
    state = (state + 0x9e3779b97f4a7c15n) & MASK64;
    let z = state;
    z = ((z ^ (z >> 30n)) * 0xbf58476d1ce4e5b9n) & MASK64;
    z = ((z ^ (z >> 27n)) * 0x94d049bb133111ebn) & MASK64;
    return z ^ (z >> 31n);
  };
}

// Seeded generator of canonical elements (rejection sampling, like Plonky3),
// raw u64 values and bounded integers.
function prng(seed) {
  const next = splitmix64(seed);
  return {
    u64: () => next(),
    element: () => {
      for (;;) {
        const v = next();
        if (v < P) return v;
      }
    },
    nonZeroElement() {
      for (;;) {
        const v = this.element();
        if (v !== 0n) return v;
      }
    },
    // Uniform integer in [0, bound) for bound <= 2^53.
    int: (bound) => Number(next() % BigInt(bound)),
    bits: (bits) => next() & ((1n << BigInt(bits)) - 1n),
  };
}

module.exports = {
  GENERATOR,
  INV2,
  MASK64,
  P,
  TWO_ADICITY,
  TWO_ADIC_GENERATORS,
  TWO_ADIC_GENERATOR_INVERSES,
  WORD_BITS,
  add,
  assertCanonical,
  bswap64,
  cdElem,
  elementsToBytes,
  inv,
  isCanonical,
  lane,
  laneDecode,
  lanesCanonical,
  leBytesToU64,
  mul,
  mulAdd,
  neg,
  packLanes,
  packTableWords,
  pow,
  pow2k,
  prng,
  reduce,
  rev,
  splitmix64,
  sq,
  sub,
  twoAdicGen,
  twoAdicGenInv,
  u64ToLeBytes,
};
