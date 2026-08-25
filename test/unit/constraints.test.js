// Constraint parity (docs/PROTOCOL.md section 10): the trace-domain
// selectors at zeta, the five Fibonacci constraints, the alpha accumulator
// and the quotient recomposition reproduce the constraints section of every
// valid vector, and the OodMismatch mutations are rejected before any FRI
// work. Executable specification of contracts/hyperion/air/FibonacciAir.hyp.

const assert = require('node:assert/strict');
const { describe, test } = require('node:test');

const V = require('../lib/vectors');
const L = require('../lib/layout');
const G = require('../lib/goldilocks');
const F2 = require('../lib/fp2');
const air = require('../lib/fibonacciAir');
const { verifyProof } = require('../lib/verifier');

const valid = V.loadValidVectors();
const mutated = V.loadMutationVectors();

// Constraint inputs of a vector: openings from its proof bytes, alpha and
// zeta from `challenges` (a mutated vector borrows its source's).
function inputsOf(vector, challenges = vector.challenges) {
  const proof = L.decodeProof(V.proofBytes(vector), vector.config);
  return {
    degreeBits: vector.degreeBits,
    zeta: V.ef(challenges.zeta),
    alpha: V.ef(challenges.alpha),
    traceLocal: proof.traceLocal,
    traceNext: proof.traceNext,
    quotientChunk: proof.quotientChunk,
    publicValues: V.publicValues(vector),
  };
}

describe('selectors, constraints and quotient reproduce every valid vector', () => {
  for (const { baseName, vector } of valid) {
    test(baseName, () => {
      const inputs = inputsOf(vector);
      const c = air.evaluateConstraints(inputs);
      assert.equal(c.ok, true, 'acc * invVan == quotient');
      const actual = {
        zH: V.efStr(c.zH),
        isFirst: V.efStr(c.isFirst),
        isLast: V.efStr(c.isLast),
        isTrans: V.efStr(c.isTrans),
        invVan: V.efStr(c.invVan),
        values: c.values.map(V.efStr),
        acc: V.efStr(c.acc),
        quotient: V.efStr(c.quotient),
      };
      const d = V.firstDifference(actual, vector.constraints);
      assert.equal(d, null, d);

      // Selector identities on the trace domain (shift 1, order 2^n).
      const { zeta, degreeBits } = inputs;
      const gInv = F2.fromBase(G.twoAdicGenInv(degreeBits));
      assert.deepEqual(F2.mul(c.isFirst, F2.sub(zeta, F2.ONE)), c.zH);
      assert.deepEqual(F2.mul(c.isLast, F2.sub(zeta, gInv)), c.zH);
      assert.deepEqual(c.isTrans, F2.sub(zeta, gInv));
      assert.deepEqual(F2.mul(c.invVan, c.zH), F2.ONE);
      assert.deepEqual(F2.sub(F2.pow(zeta, 1n << BigInt(degreeBits)), F2.ONE), c.zH);

      // acc = c1 alpha^4 + c2 alpha^3 + c3 alpha^2 + c4 alpha + c5.
      let horner = F2.ZERO;
      c.values.forEach((v, i) => {
        horner = F2.add(horner, F2.mul(v, F2.pow(inputs.alpha, BigInt(4 - i))));
      });
      assert.deepEqual(horner, c.acc);
    });
  }
});

test('the five constraints in emission order', () => {
  const rng = G.prng(99);
  const ef = () => [rng.element(), rng.element()];
  const inputs = {
    degreeBits: 4,
    zeta: ef(),
    alpha: ef(),
    traceLocal: [ef(), ef()],
    traceNext: [ef(), ef()],
    quotientChunk: [ef(), ef()],
    publicValues: [rng.element(), rng.element(), rng.element()],
  };
  const c = air.evaluateConstraints(inputs);
  const [a, b, x] = inputs.publicValues.map(F2.fromBase);
  const [l0, l1] = inputs.traceLocal;
  const [n0, n1] = inputs.traceNext;
  assert.deepEqual(c.values[0], F2.mul(c.isFirst, F2.sub(l0, a)));
  assert.deepEqual(c.values[1], F2.mul(c.isFirst, F2.sub(l1, b)));
  assert.deepEqual(c.values[2], F2.mul(c.isTrans, F2.sub(l1, n0)));
  assert.deepEqual(c.values[3], F2.mul(c.isTrans, F2.sub(F2.add(l0, l1), n1)));
  assert.deepEqual(c.values[4], F2.mul(c.isLast, F2.sub(l1, x)));
  assert.equal(c.ok, false, 'random openings do not satisfy the identity');
});

test('quotient recomposition is q0 + X q1 with X^2 = 7', () => {
  const q0 = [3n, 5n];
  const q1 = [11n, 13n];
  const X = [0n, 1n];
  assert.deepEqual(air.recomposeQuotient([q0, q1]), F2.add(q0, F2.mul(X, q1)));
  assert.deepEqual(air.recomposeQuotient([q0, q1]), [3n + 7n * 13n, 5n + 11n]);
  assert.deepEqual(F2.mul(X, X), [7n, 0n]);
});

test('selectors reject a point on the trace domain', () => {
  assert.throws(() => air.selectors(3, F2.ONE), /trace domain/);
  assert.throws(() => air.selectors(3, F2.fromBase(G.twoAdicGen(3))), /trace domain/);
});

describe('OodMismatch mutations are rejected before any FRI work', () => {
  for (const { baseName, vector } of mutated) {
    if (vector.expected.error !== 'OodMismatch') continue;
    test(baseName, () => {
      const result = verifyProof(vector.config, V.proofBytes(vector), V.publicValuesBytes(vector));
      assert.equal(result.ok, false);
      assert.equal(result.error, 'OodMismatch', result.detail);
      // With the source's alpha and zeta the identity fails for every mutation
      // of the openings or public values; a flipped trace root leaves them
      // intact and only changes alpha through the transcript.
      const source = V.loadSourceVector(vector);
      const c = air.evaluateConstraints(inputsOf(vector, source.challenges));
      assert.equal(c.ok, vector.expected.mutation === 'flip_trace_root');
    });
  }
});
