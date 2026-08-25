// Schema of every prover-generated vector (docs/PROTOCOL.md section 13) and
// the end-to-end agreement of the JS reference verifier with the Rust mirror:
// every valid vector is accepted with every recorded section reproduced, and
// every mutated vector is rejected with the recorded error.

const assert = require('node:assert/strict');
const { describe, test } = require('node:test');

const { keccak_256 } = require('@noble/hashes/sha3');

const V = require('../lib/vectors');
const L = require('../lib/layout');
const { verifyProof } = require('../lib/verifier');

const valid = V.loadValidVectors();
const mutated = V.loadMutationVectors();
const PLONKY3_VERSION = V.plonky3Version();

const CONFIG_KEYS = [
  'logBlowup',
  'logFinalPolyLen',
  'maxLogArity',
  'numQueries',
  'commitPowBits',
  'queryPowBits',
];
const VALID_KEYS = [
  'air',
  'challenges',
  'config',
  'constraints',
  'degreeBits',
  'expected',
  'finalPolyChecks',
  'fold',
  'layout',
  'merkle',
  'name',
  'openInputs',
  'plonky3Version',
  'proofHex',
  'proofId',
  'proofLength',
  'publicValues',
  'publicValuesHex',
  'schema',
  'transcript',
];
const MUTATION_KEYS = [
  'air',
  'config',
  'degreeBits',
  'expected',
  'name',
  'plonky3Version',
  'proofHex',
  'proofLength',
  'publicValues',
  'publicValuesHex',
  'schema',
  'source',
];
// PROTOCOL.md section 12.1.
const MUTATION_ERRORS = {
  bad_version: 'BadVersion',
  degree_bits_plus_one: 'BadHeader',
  log_arity_zero: 'BadHeader',
  log_arity_too_large: 'BadHeader',
  drop_last_round: 'BadHeader',
  append_byte: 'BadLength',
  truncate_1: 'BadLength',
  truncate_32: 'BadLength',
  truncate_half: 'BadLength',
  sib_count_field_plus_one: 'BadLength',
  non_canonical_element: 'NonCanonicalElement',
  flip_trace_local: 'OodMismatch',
  flip_quotient_chunk: 'OodMismatch',
  flip_trace_root: 'OodMismatch',
  wrong_public_value: 'OodMismatch',
  flip_final_poly0: 'PowFailed',
  flip_fri_commit0: 'PowFailed',
  zero_query_pow_witness: 'PowFailed',
  zero_commit_pow_witness: 'PowFailed',
  duplicate_opening_mismatch: 'DuplicateOpeningMismatch',
  sib_count_plus_one: 'SiblingCountMismatch',
  sib_count_minus_one: 'SiblingCountMismatch',
  flip_input_sibling: 'MerkleRootMismatch',
  flip_round_sibling: 'MerkleRootMismatch',
  swap_query_rows: 'MerkleRootMismatch',
  flip_sibling_value: 'FinalPolyMismatch',
};

const SECTIONS = [
  'layout',
  'proofId',
  'transcript',
  'challenges',
  'constraints',
  'openInputs',
  'fold',
  'finalPolyChecks',
  'merkle',
];

function isDecimal(s) {
  return typeof s === 'string' && /^\d+$/.test(s);
}

function isEf(e) {
  return Array.isArray(e) && e.length === 2 && e.every(isDecimal);
}

function checkConfig(config) {
  assert.deepEqual(Object.keys(config).sort(), [...CONFIG_KEYS].sort());
  for (const k of CONFIG_KEYS) assert.ok(Number.isInteger(config[k]), `config.${k} is an integer`);
  assert.ok(config.logBlowup >= 1);
  assert.ok(config.maxLogArity >= 1);
  assert.ok(config.numQueries >= 1);
}

function checkCommon(vector, baseName) {
  assert.equal(vector.schema, V.SCHEMA);
  assert.equal(vector.plonky3Version, PLONKY3_VERSION);
  assert.equal(vector.name, baseName);
  assert.equal(vector.air, 'fibonacci');
  checkConfig(vector.config);
  assert.ok(Number.isInteger(vector.degreeBits) && vector.degreeBits >= 1);
  assert.equal(vector.publicValues.length, 3);
  assert.ok(vector.publicValues.every(isDecimal));
  const pv = V.publicValues(vector);
  assert.equal(V.bytesToHex(L.encodePublicValues(pv)), vector.publicValuesHex);
  const bytes = V.proofBytes(vector);
  assert.equal(vector.proofLength, bytes.length, 'proofLength == bytes(proofHex)');
  return bytes;
}

test('the vector directories are populated', () => {
  assert.ok(valid.length > 0, 'test/vectors/*.json');
  assert.ok(mutated.length > 0, 'test/vectors/mutations/*.json');
  assert.match(PLONKY3_VERSION, /^\d+\.\d+\.\d+/);
});

describe('valid vectors', () => {
  for (const { baseName, vector } of valid) {
    test(`${baseName}: schema`, () => {
      assert.deepEqual(Object.keys(vector).sort(), VALID_KEYS);
      const bytes = checkCommon(vector, baseName);
      assert.deepEqual(vector.expected, { valid: true });
      assert.match(baseName, /^fib_[a-z0-9-]+_n\d+$/);
      assert.equal(Number(baseName.slice(baseName.lastIndexOf('_n') + 2)), vector.degreeBits);

      const { config: cfg, layout } = vector;
      const numRounds = layout.rounds.length;
      const q = cfg.numQueries;
      assert.equal(layout.degreeBits, vector.degreeBits);
      assert.equal(layout.numQueries, q);
      assert.equal(layout.totalLen, vector.proofLength);
      assert.equal(layout.pEnd, layout.prefix.pEnd);
      assert.equal(
        vector.proofId,
        V.bytesToHex(keccak_256(bytes.subarray(0, layout.pEnd))),
        'proofId == keccak256(prefix)'
      );

      assert.ok(vector.transcript.length > 0);
      for (const e of vector.transcript) {
        assert.ok(
          ['observe', 'flush', 'sample_u64', 'sample_field', 'sample_bits', 'check_pow'].includes(
            e.op
          ),
          `transcript op ${e.op}`
        );
        assert.equal(typeof e.label, 'string');
      }

      const ch = vector.challenges;
      assert.ok(isEf(ch.alpha) && isEf(ch.zeta) && isEf(ch.zetaNext) && isEf(ch.friAlpha));
      assert.equal(ch.betas.length, numRounds);
      assert.ok(ch.betas.every(isEf));
      assert.equal(ch.indices.length, q);
      const height = 2 ** (vector.degreeBits + cfg.logBlowup);
      assert.ok(ch.indices.every((i) => Number.isInteger(i) && i >= 0 && i < height));

      assert.equal(vector.openInputs.length, q);
      assert.equal(vector.fold.length, q * numRounds);
      assert.equal(vector.finalPolyChecks.length, q);
      assert.equal(vector.merkle.length, 2 + numRounds);
      assert.deepEqual(
        vector.merkle.map((b) => b.name),
        ['trace', 'quotient', ...layout.rounds.map((_, r) => `round[${r}]`)]
      );
      assert.equal(vector.constraints.values.length, 5);
      for (const k of ['zH', 'isFirst', 'isLast', 'isTrans', 'invVan', 'acc', 'quotient']) {
        assert.ok(isEf(vector.constraints[k]), `constraints.${k}`);
      }
    });
  }
});

describe('mutated vectors', () => {
  const validNames = new Set(valid.map((v) => v.baseName));
  for (const { baseName, vector } of mutated) {
    test(`${baseName}: schema`, () => {
      assert.deepEqual(Object.keys(vector).sort(), MUTATION_KEYS);
      checkCommon(vector, baseName);
      assert.ok(validNames.has(vector.source), `source ${vector.source} is a valid vector`);
      const source = V.loadSourceVector(vector);
      assert.equal(vector.name, `${vector.source}__${vector.expected.mutation}`);
      assert.deepEqual(vector.config, source.config);
      assert.equal(vector.degreeBits, source.degreeBits);
      assert.equal(vector.expected.valid, false);
      assert.ok(V.ERROR_NAMES.includes(vector.expected.error), vector.expected.error);
      assert.equal(
        MUTATION_ERRORS[vector.expected.mutation],
        vector.expected.error,
        'mutation table of PROTOCOL.md section 12.1'
      );
      if (vector.expected.mutation === 'wrong_public_value') {
        assert.notDeepEqual(vector.publicValues, source.publicValues);
        assert.equal(vector.proofHex, source.proofHex);
      } else {
        assert.deepEqual(vector.publicValues, source.publicValues);
        assert.notEqual(vector.proofHex, source.proofHex);
      }
    });
  }
});

describe('expected outcomes of the JS verifier', () => {
  for (const { baseName, vector } of valid) {
    test(`${baseName}: accepted, every section reproduced`, () => {
      const result = verifyProof(vector.config, V.proofBytes(vector), V.publicValuesBytes(vector));
      assert.equal(result.ok, true, result.detail);
      for (const section of SECTIONS) {
        const d = V.firstDifference(result.output[section], vector[section]);
        assert.equal(d, null, `${section}: ${d}`);
      }
    });
  }
  for (const { baseName, vector } of mutated) {
    test(`${baseName}: rejected with ${vector.expected.error}`, () => {
      const result = verifyProof(vector.config, V.proofBytes(vector), V.publicValuesBytes(vector));
      assert.equal(result.ok, false);
      assert.equal(result.error, vector.expected.error, result.detail);
    });
  }
});
