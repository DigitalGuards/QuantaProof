// Self-checks of the Fp2 JS reference (test/lib/fp2.js): the extension is
// well defined (7 is a quadratic non-residue), known values, field axioms on
// seeded random elements, inversion, powers and the Montgomery batch inverse.
// No chain involved; the contract suite compares Fp2.hyp against this file.

const assert = require('node:assert/strict');
const test = require('node:test');

const G = require('../lib/goldilocks');
const F2 = require('../lib/fp2');

test('7 is a quadratic non-residue, so X^2 - 7 is irreducible', () => {
  assert.equal(G.pow(F2.W, (G.P - 1n) >> 1n), G.P - 1n);
});

test('known values', () => {
  const x = [0n, 1n];
  assert.deepEqual(F2.sq(x), [7n, 0n]);
  assert.deepEqual(F2.mul(x, x), [7n, 0n]);
  assert.deepEqual(F2.fromBase(5n), [5n, 0n]);
  assert.deepEqual(F2.mul(F2.fromBase(3n), F2.fromBase(5n)), [15n, 0n]);
  assert.deepEqual(F2.mulBase([2n, 3n], 4n), [8n, 12n]);
  assert.deepEqual(F2.neg([0n, 0n]), [0n, 0n]);
  assert.deepEqual(F2.neg([1n, 2n]), [G.P - 1n, G.P - 2n]);
  assert.equal(F2.norm([3n, 0n]), 9n);
  assert.equal(F2.norm([0n, 1n]), G.P - 7n);
  assert.deepEqual(F2.inv([1n, 0n]), [1n, 0n]);
  // 1 / X = X / 7.
  assert.deepEqual(F2.inv([0n, 1n]), [0n, G.inv(7n)]);
  assert.deepEqual(F2.pow([0n, 1n], 2n), [7n, 0n]);
  assert.deepEqual(F2.pow([0n, 1n], 3n), [0n, 7n]);
  assert.deepEqual(F2.pow([5n, 6n], 0n), F2.ONE);
  assert.equal(F2.equal([1n, 2n], [1n, 2n]), true);
  assert.equal(F2.equal([1n, 2n], [2n, 1n]), false);
  assert.throws(() => F2.inv([0n, 0n]), /zero/);
});

test('field axioms on seeded random elements', () => {
  const rng = G.prng(0xf2000001n);
  for (let round = 0; round < 200; round += 1) {
    const a = F2.randomElement(rng);
    const b = F2.randomElement(rng);
    const c = F2.randomElement(rng);
    assert.deepEqual(F2.add(a, b), F2.add(b, a));
    assert.deepEqual(F2.mul(a, b), F2.mul(b, a));
    assert.deepEqual(F2.mul(F2.mul(a, b), c), F2.mul(a, F2.mul(b, c)));
    assert.deepEqual(F2.mul(a, F2.add(b, c)), F2.add(F2.mul(a, b), F2.mul(a, c)));
    assert.deepEqual(F2.sub(F2.add(a, b), b), a);
    assert.deepEqual(F2.add(a, F2.neg(a)), F2.ZERO);
    assert.deepEqual(F2.sq(a), F2.mul(a, a));
    assert.deepEqual(F2.mulBase(a, b[0]), F2.mul(a, F2.fromBase(b[0])));
    // The norm is multiplicative.
    assert.equal(F2.norm(F2.mul(a, b)), G.mul(F2.norm(a), F2.norm(b)));
    for (const [c0, c1] of [a, b, c]) {
      assert.ok(G.isCanonical(c0) && G.isCanonical(c1));
    }
  }
});

test('inversion and powers', () => {
  const rng = G.prng(0xf2000002n);
  for (let round = 0; round < 200; round += 1) {
    const a = F2.randomNonZeroElement(rng);
    const ai = F2.inv(a);
    assert.deepEqual(F2.mul(a, ai), F2.ONE);
    assert.deepEqual(F2.inv(ai), a);
    const e = rng.int(64);
    let expected = [1n, 0n];
    for (let i = 0; i < e; i += 1) expected = F2.mul(expected, a);
    assert.deepEqual(F2.pow(a, BigInt(e)), expected);
    // a^(p^2 - 1) == 1 for every non-zero element of the extension field.
    assert.deepEqual(F2.pow(a, G.P * G.P - 1n), F2.ONE);
    // Frobenius: a^p is the conjugate (a0, -a1).
    assert.deepEqual(F2.pow(a, G.P), [a[0], G.neg(a[1])]);
  }
});

test('batchInverse matches element-wise inversion and rejects zero', () => {
  const rng = G.prng(0xf2000003n);
  for (const count of [0, 1, 2, 3, 64]) {
    const elements = Array.from({ length: count }, () => F2.randomNonZeroElement(rng));
    const expected = elements.map((a) => F2.inv(a));
    assert.deepEqual(F2.batchInverse(elements), expected);
  }
  const withZero = [F2.randomNonZeroElement(rng), F2.ZERO, F2.randomNonZeroElement(rng)];
  assert.throws(() => F2.batchInverse(withZero), /zero/);
});

test('flatten and unflatten round-trip the harness layout', () => {
  const elements = [
    [1n, 2n],
    [3n, 4n],
  ];
  assert.deepEqual(F2.flatten(elements), [1n, 2n, 3n, 4n]);
  assert.deepEqual(F2.unflatten([1n, 2n, 3n, 4n]), elements);
  assert.throws(() => F2.unflatten([1n]), /odd/);
  assert.throws(() => F2.assertElement([1n]), /pair/);
  assert.throws(() => F2.assertElement([G.P, 0n]), /canonical/);
});
