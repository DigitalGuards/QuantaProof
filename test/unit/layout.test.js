// Calldata layout v1 (docs/PROTOCOL.md section 11): the JS offset calculator
// reproduces the offsets the Rust prover recorded for every valid vector,
// decoding then re-encoding a proof yields the identical bytes, and the
// header, exact-length and canonical-element rules raise the documented
// errors on the layout mutations.

const assert = require('node:assert/strict');
const { describe, test } = require('node:test');

const V = require('../lib/vectors');
const L = require('../lib/layout');

const valid = V.loadValidVectors();
const mutated = V.loadMutationVectors();
const C3 = {
  logBlowup: 3,
  logFinalPolyLen: 3,
  maxLogArity: 3,
  numQueries: 34,
  commitPowBits: 0,
  queryPowBits: 16,
};

function errorOf(fn) {
  try {
    fn();
  } catch (e) {
    if (e instanceof L.LayoutError) return e.errorName;
    throw e;
  }
  return null;
}

describe('offsets match the Rust layout of every valid vector', () => {
  for (const { baseName, vector } of valid) {
    test(baseName, () => {
      const bytes = V.proofBytes(vector);
      const layout = L.parseLayout(bytes, vector.config);
      const d = V.firstDifference(layout, vector.layout);
      assert.equal(d, null, d);

      const numRounds = layout.rounds.length;
      assert.equal(layout.pEnd, L.prefixEnd(numRounds, vector.config.logFinalPolyLen));
      assert.deepEqual(layout.prefix, L.prefixLayout(numRounds, L.finalPolyLen(vector.config)));
      assert.equal(layout.totalLen, bytes.length);
      assert.deepEqual(layout.logArities, Array.from(bytes.subarray(3, 3 + numRounds)));
      assert.equal(bytes[1], vector.degreeBits);
      assert.equal(bytes[2], numRounds);

      // sib_count is a big-endian u16 and every block starts where the previous ended.
      let cursor = layout.pEnd;
      for (const block of [...layout.blocks, ...layout.rounds]) {
        const start = block.rowsOffset ?? block.siblingValuesOffset;
        assert.equal(start, cursor);
        const be = (bytes[block.sibCountOffset] << 8) | bytes[block.sibCountOffset + 1];
        assert.equal(be, block.sibCount);
        assert.equal(block.siblingsOffset, block.sibCountOffset + 2);
        assert.equal(block.end, block.siblingsOffset + 32 * block.sibCount);
        cursor = block.end;
      }
      assert.equal(cursor, bytes.length, 'exact-length rule');
    });
  }
});

describe('decode then encode reproduces the bytes', () => {
  for (const { baseName, vector } of valid) {
    test(baseName, () => {
      const bytes = V.proofBytes(vector);
      const proof = L.decodeProof(bytes, vector.config);
      assert.equal(proof.proofId, vector.proofId);
      assert.equal(proof.degreeBits, vector.degreeBits);
      assert.equal(proof.rounds.length, vector.layout.rounds.length);
      assert.equal(proof.finalPoly.length, L.finalPolyLen(vector.config));
      assert.equal(proof.traceRows.length, vector.config.numQueries);
      assert.equal(V.bytesToHex(proof.traceRoot), vector.merkle[0].root);
      assert.equal(V.bytesToHex(proof.quotientRoot), vector.merkle[1].root);
      proof.rounds.forEach((r, i) => {
        assert.equal(V.bytesToHex(r.commit), vector.merkle[2 + i].root);
        assert.equal(r.siblings.length, vector.layout.rounds[i].sibCount);
        assert.ok(r.siblingValues.every((sv) => sv.length === 2 ** r.logArity - 1));
      });
      const encoded = L.encodeProof(proof);
      assert.equal(encoded.length, bytes.length);
      assert.ok(V.bytesEqual(encoded, bytes), 'encode(decode(bytes)) == bytes');
    });
  }
});

test('worked example of PROTOCOL.md section 11.2 (fib_c3_n10)', () => {
  const entry = valid.find((v) => v.baseName === 'fib_c3_n10');
  if (!entry) return;
  const layout = L.parseLayout(V.proofBytes(entry.vector), entry.vector.config);
  assert.equal(layout.pEnd, 422);
  assert.deepEqual(layout.logArities, [3, 3, 1]);
  const [trace, quotient] = layout.blocks;
  assert.deepEqual([trace.rowsOffset, trace.sibCountOffset, trace.siblingsOffset], [422, 966, 968]);
  assert.equal(trace.sibCount, 250);
  assert.equal(trace.end, 8968);
  assert.deepEqual([quotient.rowsOffset, quotient.sibCountOffset], [8968, 9512]);
  assert.equal(quotient.end, 17514);
  const [r0, r1, r2] = layout.rounds;
  assert.deepEqual(
    [r0.siblingValuesOffset, r0.sibCountOffset, r0.sibCount, r0.end],
    [17514, 21322, 148, 26060]
  );
  assert.deepEqual([r1.siblingValuesOffset, r1.sibCount, r1.end], [26060, 52, 31534]);
  assert.deepEqual([r2.siblingValuesOffset, r2.sibCount, r2.end], [31534, 24, 32848]);
  assert.equal(layout.totalLen, 32848);
});

test('prefix offsets are contiguous (layout.rs prefix_offsets_are_contiguous)', () => {
  const p = L.prefixLayout(3, 8);
  assert.equal(p.traceRoot, 6);
  assert.equal(p.quotientRoot, 38);
  assert.equal(p.traceLocal, 70);
  assert.equal(p.traceNext, 102);
  assert.equal(p.quotientChunk, 134);
  assert.deepEqual(p.roundCommits, [166, 206, 246]);
  assert.deepEqual(p.roundPowWitnesses, [198, 238, 278]);
  assert.equal(p.finalPoly, 286);
  assert.equal(p.queryPowWitness, 286 + 128);
  assert.equal(p.pEnd, 286 + 128 + 8);
  assert.equal(L.prefixEnd(3, 3), p.pEnd);
  assert.equal(L.prefixEnd(0, 0), 171 + 16);
});

test('header rules (layout.rs header_rules)', () => {
  assert.equal(L.headerError(10, [3, 3, 1], C3), null);
  assert.equal(L.headerError(10, [3, 3], C3), 'BadHeader');
  assert.equal(L.headerError(10, [0, 3, 4], C3), 'BadHeader');
  assert.equal(L.headerError(10, [4, 3], C3), 'BadHeader');
  assert.equal(L.headerError(30, new Array(9).fill(3), C3), 'BadHeader');
  assert.equal(L.headerError(0, [], C3), 'BadHeader');
  assert.equal(L.headerError(3, [], C3), null, 'R = 0 is legal when n == lf');
  assert.equal(L.headerError(2, [], C3), 'BadHeader', 'n < lf');
  // n + lb = 32 is the largest supported height; the schedule must sum to n - lf = 26.
  assert.equal(L.headerError(29, new Array(8).fill(3).concat([2]), C3), null);
});

test('short inputs are length errors, a wrong version byte wins over them', () => {
  assert.equal(
    errorOf(() => L.parseLayout(new Uint8Array(0), C3)),
    'BadLength'
  );
  assert.equal(
    errorOf(() => L.parseLayout(Uint8Array.from([2]), C3)),
    'BadVersion'
  );
  assert.equal(
    errorOf(() => L.parseLayout(Uint8Array.from([1, 10]), C3)),
    'BadLength'
  );
  assert.equal(
    errorOf(() => L.parseLayout(Uint8Array.from([1, 10, 3, 3, 3, 1]), C3)),
    'BadLength'
  );
  assert.equal(
    errorOf(() => L.parseLayout(Uint8Array.from([1, 10, 3, 3, 3]), C3)),
    'BadLength'
  );
  assert.equal(
    errorOf(() => L.parseLayout(Uint8Array.from([1, 10, 2, 3, 3]), C3)),
    'BadHeader'
  );
});

test('exact-length rule on a valid proof', () => {
  const { vector } = valid[0];
  const bytes = V.proofBytes(vector);
  const cfg = vector.config;
  assert.equal(
    errorOf(() => L.parseLayout(bytes, cfg)),
    null
  );
  const longer = new Uint8Array(bytes.length + 1);
  longer.set(bytes);
  assert.equal(
    errorOf(() => L.parseLayout(longer, cfg)),
    'BadLength'
  );
  assert.equal(
    errorOf(() => L.parseLayout(bytes.subarray(0, bytes.length - 1), cfg)),
    'BadLength'
  );
  assert.equal(
    errorOf(() => L.parseLayout(bytes.subarray(0, bytes.length - 32), cfg)),
    'BadLength'
  );
  // Cut inside the last sib_count field: the field itself is past the end.
  const lastCount = vector.layout.rounds[vector.layout.rounds.length - 1].sibCountOffset;
  assert.equal(
    errorOf(() => L.parseLayout(bytes.subarray(0, lastCount + 1), cfg)),
    'BadLength'
  );
  // The prefix alone: the trace sib_count is past the end.
  assert.equal(
    errorOf(() => L.parseLayout(bytes.subarray(0, vector.layout.pEnd), cfg)),
    'BadLength'
  );
  // The layout does not look at field element values.
  const noncanonical = bytes.slice();
  noncanonical.set(new Uint8Array(8).fill(0xff), vector.layout.prefix.traceLocal);
  assert.equal(
    errorOf(() => L.parseLayout(noncanonical, cfg)),
    null
  );
  assert.equal(
    errorOf(() => L.decodeProof(noncanonical, cfg)),
    'NonCanonicalElement'
  );
});

test('canonical element decoding', () => {
  const p = L.fBytes(L.P - 1n);
  assert.equal(L.readF(p, 0), L.P - 1n);
  const bad = new Uint8Array(8);
  let v = L.P;
  for (let i = 0; i < 8; i += 1) {
    bad[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  assert.equal(
    errorOf(() => L.readF(bad, 0)),
    'NonCanonicalElement'
  );
  assert.equal(
    errorOf(() => L.readF(new Uint8Array(7), 0)),
    'BadLength'
  );
  assert.throws(() => L.fBytes(L.P), /non-canonical/);
  assert.deepEqual(Array.from(L.fBytes(10n)), [10, 0, 0, 0, 0, 0, 0, 0]);
  assert.deepEqual(L.decodePublicValues(L.encodePublicValues([0n, 1n, 2n])), [0n, 1n, 2n]);
  assert.equal(
    errorOf(() => L.decodePublicValues(new Uint8Array(23))),
    'BadLength'
  );
});

describe('layout mutations raise the documented error', () => {
  const layoutErrors = new Set(['BadVersion', 'BadHeader', 'BadLength', 'NonCanonicalElement']);
  for (const { baseName, vector } of mutated) {
    if (!layoutErrors.has(vector.expected.error)) continue;
    test(`${baseName}: ${vector.expected.error}`, () => {
      const result = L.tryDecodeProof(V.proofBytes(vector), vector.config);
      assert.equal(result.ok, false);
      assert.equal(result.error, vector.expected.error, result.message);
    });
  }
  for (const { baseName, vector } of mutated) {
    if (layoutErrors.has(vector.expected.error)) continue;
    test(`${baseName}: decodes (fails later)`, () => {
      const result = L.tryDecodeProof(V.proofBytes(vector), vector.config);
      assert.equal(result.ok, true, result.message);
    });
  }
});
