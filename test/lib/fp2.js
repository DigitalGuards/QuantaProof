// BigInt reference implementation of the quadratic extension
// Fp[X] / (X^2 - 7) of the Goldilocks field (Plonky3
// BinomialExtensionField<Goldilocks, 2>), mirroring contracts/hyperion/lib/Fp2.hyp.
//
// Elements are two-entry arrays [c0, c1] of canonical base field BigInts.
// batchInverse is the norm-based Montgomery trick the contract runs over a
// memory array, written the same way (norms, forward prefix products, one
// inversion, backward pass) so an implementation mistake shows up as a
// mismatch rather than agreement.

const G = require('./goldilocks');

const W = 7n;
const P = G.P;

function assertElement(a, name = 'element') {
  if (!Array.isArray(a) || a.length !== 2) {
    throw new TypeError(`${name} is not an [c0, c1] pair`);
  }
  G.assertCanonical(a[0], `${name}.c0`);
  G.assertCanonical(a[1], `${name}.c1`);
}

function fromBase(x) {
  return [x % P, 0n];
}

const ZERO = Object.freeze([0n, 0n]);
const ONE = Object.freeze([1n, 0n]);

function equal(a, b) {
  return a[0] === b[0] && a[1] === b[1];
}

function add(a, b) {
  return [G.add(a[0], b[0]), G.add(a[1], b[1])];
}

function sub(a, b) {
  return [G.sub(a[0], b[0]), G.sub(a[1], b[1])];
}

function neg(a) {
  return [G.neg(a[0]), G.neg(a[1])];
}

function mul(a, b) {
  return [(a[0] * b[0] + W * a[1] * b[1]) % P, (a[0] * b[1] + a[1] * b[0]) % P];
}

function sq(a) {
  return [(a[0] * a[0] + W * a[1] * a[1]) % P, (2n * a[0] * a[1]) % P];
}

function mulBase(a, s) {
  return [(a[0] * s) % P, (a[1] * s) % P];
}

// a0^2 - 7 a1^2, a base field element that vanishes only at zero.
function norm(a) {
  return (((a[0] * a[0] - W * a[1] * a[1]) % P) + P) % P;
}

function inv(a) {
  const n = norm(a);
  if (n === 0n) throw new RangeError('inverse of zero');
  const nInv = G.inv(n);
  return [(a[0] * nInv) % P, (G.neg(a[1]) * nInv) % P];
}

function pow(a, e) {
  let base = [a[0], a[1]];
  let exp = BigInt(e);
  let result = [1n, 0n];
  while (exp > 0n) {
    if (exp & 1n) result = mul(result, base);
    base = sq(base);
    exp >>= 1n;
  }
  return result;
}

// Batch inversion the way the contract does it: Montgomery's trick over the
// base field norms (prefix products of norms, one inversion, backward pass),
// then each element becomes conj(a) / norm(a). Returns a new array. Throws on
// a zero element, where the contract reverts with ZeroInverse().
function batchInverse(elements) {
  const count = elements.length;
  if (count === 0) return [];
  const norms = elements.map((a) => norm(a));
  const prefix = new Array(count);
  let acc = 1n;
  for (let j = 0; j < count; j += 1) {
    prefix[j] = acc;
    acc = G.mul(acc, norms[j]);
  }
  if (acc === 0n) throw new RangeError('inverse of zero');
  acc = G.inv(acc);
  const out = new Array(count);
  for (let j = count - 1; j >= 0; j -= 1) {
    const nInv = G.mul(acc, prefix[j]);
    acc = G.mul(acc, norms[j]);
    out[j] = [G.mul(elements[j][0], nInv), G.mul(G.neg(elements[j][1]), nInv)];
  }
  return out;
}

// Interleave [c0, c1] pairs into a flat array (the harness batch layout).
function flatten(elements) {
  const out = [];
  for (const [c0, c1] of elements) out.push(c0, c1);
  return out;
}

function unflatten(values) {
  if (values.length % 2 !== 0) throw new TypeError('odd number of components');
  const out = [];
  for (let i = 0; i < values.length; i += 2) out.push([values[i], values[i + 1]]);
  return out;
}

function randomElement(rng) {
  return [rng.element(), rng.element()];
}

function randomNonZeroElement(rng) {
  for (;;) {
    const a = randomElement(rng);
    if (a[0] !== 0n || a[1] !== 0n) return a;
  }
}

module.exports = {
  ONE,
  P,
  W,
  ZERO,
  add,
  assertElement,
  batchInverse,
  equal,
  flatten,
  fromBase,
  inv,
  mul,
  mulBase,
  neg,
  norm,
  pow,
  randomElement,
  randomNonZeroElement,
  sq,
  sub,
  unflatten,
};
