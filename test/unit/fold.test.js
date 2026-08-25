// FRI parity (docs/PROTOCOL.md sections 6 to 8): the reduced openings, the
// binary fold chain (with the literal barycentric fold_row alongside) and the
// final polynomial evaluation reproduce the openInputs, fold and
// finalPolyChecks sections of every valid vector. These BigInt functions are
// the executable specification of contracts/hyperion/lib/FriVerifier.hyp.

const assert = require('node:assert/strict');
const { describe, test } = require('node:test');

const V = require('../lib/vectors');
const L = require('../lib/layout');
const M = require('../lib/merkle');
const G = require('../lib/goldilocks');
const F2 = require('../lib/fp2');
const fri = require('../lib/fri');
const { verifyProof } = require('../lib/verifier');

const valid = V.loadValidVectors();
const mutated = V.loadMutationVectors();

describe('reduced openings reproduce openInputs', () => {
  for (const { baseName, vector } of valid) {
    test(baseName, () => {
      const proof = L.decodeProof(V.proofBytes(vector), vector.config);
      const h = vector.degreeBits + vector.config.logBlowup;
      const c = vector.challenges;
      const [zeta, zetaNext, friAlpha] = [c.zeta, c.zetaNext, c.friAlpha].map(V.ef);
      assert.deepEqual(
        zetaNext,
        F2.mulBase(zeta, G.twoAdicGen(vector.degreeBits)),
        'zeta_next = zeta * g_n'
      );
      c.indices.forEach((idx, qi) => {
        const expected = vector.openInputs[qi];
        assert.equal(expected.query, qi);
        assert.equal(expected.index, idx);
        const x = fri.queryPoint(idx, h);
        assert.equal(x, V.f(expected.x), `x of query ${qi}`);
        assert.equal(x, G.mul(7n, G.pow(G.twoAdicGen(h), BigInt(fri.revBits(idx, h)))));
        const ro = fri.reducedOpening({
          friAlpha,
          zeta,
          zetaNext,
          x,
          traceLocal: proof.traceLocal,
          traceNext: proof.traceNext,
          quotientChunk: proof.quotientChunk,
          traceRow: proof.traceRows[qi],
          quotientRow: proof.quotientRows[qi],
        });
        const actual = {
          query: qi,
          index: idx,
          x: V.fStr(x),
          denomZeta: V.efStr(ro.denomZeta),
          denomZetaNext: V.efStr(ro.denomZetaNext),
          invDenomZeta: V.efStr(ro.invDenomZeta),
          invDenomZetaNext: V.efStr(ro.invDenomZetaNext),
          traceRow: proof.traceRows[qi].map(V.fStr),
          quotientRow: proof.quotientRows[qi].map(V.fStr),
          reducedOpening: V.efStr(ro.reducedOpening),
        };
        const d = V.firstDifference(actual, expected);
        assert.equal(d, null, `query ${qi}: ${d}`);
      });
    });
  }
});

describe('fold chains and final polynomial reproduce fold and finalPolyChecks', () => {
  for (const { baseName, vector } of valid) {
    test(baseName, () => {
      const proof = L.decodeProof(V.proofBytes(vector), vector.config);
      const h = vector.degreeBits + vector.config.logBlowup;
      const numRounds = proof.rounds.length;
      const betas = vector.challenges.betas.map(V.ef);
      assert.equal(betas.length, numRounds);
      vector.challenges.indices.forEach((idx, qi) => {
        const chain = fri.foldChain({
          index: idx,
          reduced: V.ef(vector.openInputs[qi].reducedOpening),
          logHeight: h,
          rounds: proof.rounds.map((r) => ({
            logArity: r.logArity,
            siblingValues: r.siblingValues[qi],
          })),
          betas,
          finalPoly: proof.finalPoly,
          efBytes: L.efBytes,
        });
        assert.equal(chain.steps.length, numRounds);
        chain.steps.forEach((step, r) => {
          const expected = vector.fold[qi * numRounds + r];
          const actual = {
            query: qi,
            round: r,
            logArity: step.logArity,
            index: step.index,
            position: step.position,
            row: step.row.map(V.efStr),
            foldedIndex: step.foldedIndex,
            subgroupStart: V.fStr(step.subgroupStart),
            folded: V.efStr(step.folded),
            foldedBarycentric: V.efStr(step.foldedBarycentric),
            leafDigest: V.bytesToHex(M.leafDigest(step.rowBytes)),
          };
          const d = V.firstDifference(actual, expected);
          assert.equal(d, null, `query ${qi} round ${r}: ${d}`);
          assert.equal(step.position, step.index % 2 ** step.logArity);
          assert.equal(step.foldedIndex, Math.floor(step.index / 2 ** step.logArity));
        });
        const check = vector.finalPolyChecks[qi];
        assert.equal(chain.finalIndex, check.index);
        assert.equal(chain.finalHeight, vector.config.logBlowup + vector.config.logFinalPolyLen);
        assert.ok(chain.finalIndex < 2 ** chain.finalHeight);
        assert.equal(V.fStr(chain.finalX), check.x, 'g_H^rev(index, H), no coset shift');
        assert.deepEqual(V.efStr(chain.finalValue), check.value);
        assert.ok(chain.ok, `final polynomial check of query ${qi}`);
        assert.deepEqual(chain.folded, chain.finalValue);
      });
    });
  }
});

describe('fold_row algebra', () => {
  const rng = G.prng(7);
  const randomEf = () => [rng.element(), rng.element()];

  test('binary and barycentric forms agree on random rows (mirror.rs fold_forms_agree_on_random_rows)', () => {
    for (let logArity = 1; logArity <= 4; logArity += 1) {
      for (const logHeight of [3, 5, 9]) {
        const beta = randomEf();
        const row = Array.from({ length: 2 ** logArity }, randomEf);
        for (const index of [0, 1, 5, 2 ** logHeight - 1]) {
          const a = fri.foldRowBarycentric(index, logHeight, logArity, beta, row);
          const b = fri.foldRowBinary(index, logHeight, logArity, beta, row);
          assert.deepEqual(a, b, `log_arity ${logArity} log_height ${logHeight} index ${index}`);
        }
      }
    }
  });

  test('folding interpolates the row: a constant row folds to itself', () => {
    for (let logArity = 1; logArity <= 4; logArity += 1) {
      const c = randomEf();
      const row = new Array(2 ** logArity).fill(c);
      assert.deepEqual(fri.foldRowBinary(3, 6, logArity, randomEf(), row), c);
    }
  });

  test('a row sampled from a low-degree polynomial folds to its value at beta', () => {
    // row[i] = f(xs[i]) over the bit-reversed coset points xs of fold_row with
    // f of degree < arity, so the fold is f(beta) (Lagrange interpolation).
    for (let logArity = 1; logArity <= 4; logArity += 1) {
      const arity = 2 ** logArity;
      const index = 11;
      const logHeight = 7;
      const s = fri.subgroupStart(index, logHeight, logArity);
      const g = G.twoAdicGen(logArity);
      const coeffs = Array.from({ length: arity }, randomEf);
      const evalAt = (x) => fri.horner(coeffs, x);
      const row = [];
      for (let i = 0; i < arity; i += 1) {
        const x = G.mul(s, G.pow(g, BigInt(fri.revBits(i, logArity))));
        row.push(evalAt(x));
      }
      const beta = randomEf();
      let expected = F2.ZERO;
      for (let i = coeffs.length - 1; i >= 0; i -= 1)
        expected = F2.add(F2.mul(expected, beta), coeffs[i]);
      assert.deepEqual(fri.foldRowBinary(index, logHeight, logArity, beta, row), expected);
      assert.deepEqual(fri.foldRowBarycentric(index, logHeight, logArity, beta, row), expected);
    }
  });

  test('binary fold step: (lo + hi) / 2 + beta (lo - hi) / (2y) at y = s', () => {
    const lo = randomEf();
    const hi = randomEf();
    const beta = randomEf();
    const index = 5;
    const logHeight = 4;
    const s = fri.subgroupStart(index, logHeight, 1);
    const manual = F2.add(
      F2.mulBase(F2.add(lo, hi), G.INV2),
      F2.mulBase(F2.mul(F2.sub(lo, hi), beta), G.inv(G.mul(2n, s)))
    );
    assert.deepEqual(fri.foldRowBinary(index, logHeight, 1, beta, [lo, hi]), manual);
    // s = g_{h+1}^rev(index, h) and the pair sits at (s, -s): g_1 = -1.
    assert.equal(s, G.pow(G.twoAdicGen(logHeight + 1), BigInt(fri.revBits(index, logHeight))));
    assert.equal(G.twoAdicGen(1), G.P - 1n);
  });

  test('horner evaluates with the constant term first', () => {
    const c = [
      [3n, 0n],
      [5n, 0n],
      [7n, 0n],
    ];
    assert.deepEqual(fri.horner(c, 2n), [41n, 0n]);
    assert.deepEqual(fri.horner([], 2n), F2.ZERO);
  });

  test('revBits matches Plonky3 reverse_bits_len (and goldilocks.rev for bits >= 1)', () => {
    assert.equal(fri.revBits(0, 0), 0);
    assert.equal(fri.revBits(1, 3), 4);
    assert.equal(fri.revBits(6, 3), 3);
    for (let bits = 1; bits <= 12; bits += 1) {
      for (const x of [0, 1, 2, 5, 2 ** bits - 1]) {
        assert.equal(BigInt(fri.revBits(x, bits)), G.rev(x, bits));
      }
    }
  });

  test('reconstructRow places the query value at its position', () => {
    assert.deepEqual(fri.reconstructRow(2, 'q', ['a', 'b', 'c'], 4), ['a', 'b', 'q', 'c']);
    assert.deepEqual(fri.reconstructRow(0, 'q', ['a'], 2), ['q', 'a']);
    assert.throws(() => fri.reconstructRow(0, 'q', ['a', 'b'], 2), /sibling values/);
  });

  test('reducedOpening reports a zero denominator', () => {
    const zeta = [7n, 0n];
    assert.throws(
      () =>
        fri.reducedOpening({
          friAlpha: randomEf(),
          zeta,
          zetaNext: randomEf(),
          x: 7n,
          traceLocal: [randomEf(), randomEf()],
          traceNext: [randomEf(), randomEf()],
          quotientChunk: [randomEf(), randomEf()],
          traceRow: [1n, 2n],
          quotientRow: [3n, 4n],
        }),
      (e) => e instanceof fri.FriError && e.errorName === 'ZeroDenominator'
    );
  });
});

describe('FinalPolyMismatch mutations', () => {
  for (const { baseName, vector } of mutated) {
    if (vector.expected.error !== 'FinalPolyMismatch') continue;
    test(baseName, () => {
      const result = verifyProof(vector.config, V.proofBytes(vector), V.publicValuesBytes(vector));
      assert.equal(result.ok, false);
      assert.equal(result.error, 'FinalPolyMismatch', result.detail);
      assert.match(result.detail, /query 0/, 'round[0] query 0 sibling value changed');
    });
  }
});
