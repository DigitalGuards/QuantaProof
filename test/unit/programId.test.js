// The program identifier (docs/PROTOCOL.md section 1.3) across its three
// implementations: the JS reference (test/lib/programId.js), the deployment
// tooling (scripts/lib/presets.js::programIdFor) and the Rust prover through
// the `programIdentifier` field of every vector. Pins the c1, c2 and c3
// values so that a change of the label, the public-value length or the packed
// layout is caught on every side at once (the same constants sit in
// prover/stark-prover/src/config.rs).

const assert = require('node:assert/strict');
const { describe, test } = require('node:test');

const { keccak_256 } = require('@noble/hashes/sha3');

const P = require('../../scripts/lib/presets');
const ID = require('../lib/programId');
const V = require('../lib/vectors');

const PINNED = {
  c1: '0xf229ff0379f9c9b18f0e864063233cf5ad918a7fa28e46fd3d2f5d437c4711cb',
  c2: '0x382d87b1e36d10731f13016f85a2d21570a3e02d21c62a847ed46647d8cf1f3d',
  c3: '0x2d01b82c3e39759e2d2772e2d0b28277832bddd37668756c2fee577d48169634',
};

test('the preimage is the label, 24 and the six parameters as 64-byte big-endian words', () => {
  const config = P.presetConfig('c3');
  const preimage = ID.programIdPreimage(config);
  assert.equal(preimage.length, 19 + 7 * 64);
  assert.equal(Buffer.from(preimage.subarray(0, 19)).toString('ascii'), 'QSTARK-FIBONACCI-v1');
  const word = (i) => {
    const start = 19 + 64 * i;
    assert.ok(
      preimage.subarray(start, start + 56).every((b) => b === 0),
      `word ${i} high bytes`
    );
    return Number(
      BigInt(`0x${Buffer.from(preimage.subarray(start + 56, start + 64)).toString('hex')}`)
    );
  };
  assert.deepEqual([0, 1, 2, 3, 4, 5, 6].map(word), [
    24,
    config.logBlowup,
    config.logFinalPolyLen,
    config.maxLogArity,
    config.numQueries,
    config.commitPowBits,
    config.queryPowBits,
  ]);
  assert.deepEqual(ID.programIdentifier(config), keccak_256(preimage));
  assert.equal(ID.programIdentifierHex(config), V.bytesToHex(keccak_256(preimage)));
  assert.equal(ID.PUBLIC_VALUES_BYTES, 24);
  assert.deepEqual(ID.PARAMETER_ORDER, P.PRESET_KEYS);
  assert.throws(() => ID.packedWord(-1), /non-negative integer/);
  assert.throws(() => ID.programIdPreimage({ ...config, numQueries: undefined }), /integer/);
});

test('the pinned c1, c2 and c3 identifiers', () => {
  for (const [name, expected] of Object.entries(PINNED)) {
    assert.equal(ID.programIdentifierHex(P.presetConfig(name)), expected, name);
  }
});

test('the deployment tooling computes the same identifier for every preset', () => {
  const seen = new Set();
  for (const { name, config } of P.PRESETS) {
    const id = ID.programIdentifierHex(config);
    assert.equal(P.programIdFor(name), id, name);
    seen.add(id);
  }
  assert.equal(seen.size, P.PRESETS.length, 'every parameter set has its own identifier');
});

describe('every vector carries the identifier of its parameter set', () => {
  for (const { baseName, vector } of V.loadValidVectors().concat(V.loadMutationVectors())) {
    test(baseName, () => {
      const preset = P.presetFromVector(vector);
      assert.equal(vector.programIdentifier, P.programIdFor(preset));
      assert.equal(vector.programIdentifier, ID.programIdentifierHex(vector.config));
      if (PINNED[preset]) assert.equal(vector.programIdentifier, PINNED[preset]);
    });
  }
});
