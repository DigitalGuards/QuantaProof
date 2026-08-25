// Byte-exact challenger parity (docs/PROTOCOL.md sections 4 and 5): the JS
// challenger replays every valid vector's transcript event by event (flush
// inputs, digests, popped byte groups, accepted and rejected values, PoW
// outcomes and the query indices), plus targeted tests of the HashChallenger
// semantics: four groups per flush served from the end of the digest, the
// keccak256(D) rehash once a digest is exhausted, discard-on-observe,
// rejection sampling and the PoW check.

const assert = require('node:assert/strict');
const { describe, test } = require('node:test');

const { keccak_256 } = require('@noble/hashes/sha3');

const V = require('../lib/vectors');
const {
  Challenger,
  P,
  compareEvents,
  digestGroup,
  replay,
  samplesByLabel,
  u64ToLeBytes,
} = require('../lib/challenger');
const { verifyProof } = require('../lib/verifier');

const valid = V.loadValidVectors();
const mutated = V.loadMutationVectors();

// Digests of the two flushes a fresh challenger performs after observing `bytes`.
function chainOf(bytes) {
  const d0 = keccak_256(Uint8Array.from(bytes));
  return [d0, keccak_256(d0)];
}

describe('transcript replay of every valid vector', () => {
  for (const { baseName, vector } of valid) {
    test(baseName, () => {
      const ch = replay(vector.transcript);
      const samples = samplesByLabel(ch.events);
      const c = vector.challenges;
      const ef = (label) => [samples.get(`${label}.c0`), samples.get(`${label}.c1`)];
      assert.deepEqual(ef('alpha'), V.ef(c.alpha));
      assert.deepEqual(ef('zeta'), V.ef(c.zeta));
      assert.deepEqual(ef('fri_alpha'), V.ef(c.friAlpha));
      c.betas.forEach((beta, r) => assert.deepEqual(ef(`beta[${r}]`), V.ef(beta)));
      c.indices.forEach((idx, i) => assert.equal(samples.get(`index[${i}]`), idx));
      assert.equal(c.indices.length, vector.config.numQueries);

      const pows = ch.events.filter((e) => e.op === 'check_pow');
      assert.equal(pows.length, vector.layout.rounds.length + 1);
      assert.ok(pows.every((e) => e.ok === true));
      const queryPow = pows[pows.length - 1];
      assert.equal(queryPow.label, 'query_pow');
      assert.equal(queryPow.bits, vector.config.queryPowBits);
      assert.equal(queryPow.value, '0');
      for (const commitPow of pows.slice(0, -1)) {
        assert.equal(commitPow.bits, vector.config.commitPowBits);
        if (commitPow.bits === 0) assert.ok(!('value' in commitPow), 'no sample for 0 bits');
      }

      // Every index is one full u64 group masked to H bits.
      const h = vector.degreeBits + vector.config.logBlowup;
      const bitSamples = ch.events.filter(
        (e) => e.op === 'sample_bits' && /^index\[/.test(e.label)
      );
      assert.equal(bitSamples.length, vector.config.numQueries);
      for (const e of bitSamples) {
        assert.equal(e.bits, h);
        assert.equal(BigInt(e.raw) & ((1n << BigInt(h)) - 1n), BigInt(e.value));
      }
      assert.equal(ch.flushes, vector.transcript.filter((e) => e.op === 'flush').length);
    });
  }
});

test('worked example of PROTOCOL.md section 5 (fib_c3_n10)', () => {
  const entry = valid.find((v) => v.baseName === 'fib_c3_n10');
  if (!entry) return;
  const ch = replay(entry.vector.transcript);
  const flushInputs = ch.events
    .filter((e) => e.op === 'flush')
    .map((e) => V.hexToBytes(e.input).length);
  assert.deepEqual(flushInputs, [80, 64, 128, 64, 64, 64, 192, 32, 32, 32, 32, 32, 32, 32, 32]);
  let observed = 0;
  let sampled = 0;
  const runs = [];
  for (const e of ch.events) {
    if (e.op === 'observe') {
      observed += V.hexToBytes(e.bytes).length;
      if (runs[runs.length - 1] !== 'observe') runs.push('observe');
    } else if (e.op === 'sample_u64') {
      sampled += 8;
      if (runs[runs.length - 1] !== 'sample') runs.push('sample');
    }
  }
  assert.equal(observed, 464);
  assert.equal(sampled, 376);
  assert.equal(runs.length, 14);
});

describe('HashChallenger semantics', () => {
  test('a fresh challenger hashes exactly the observed bytes on the first sample', () => {
    const ch = new Challenger();
    ch.observeBytes([1, 2, 3], 'x');
    assert.equal(ch.flushes, 0);
    const [d0] = chainOf([1, 2, 3]);
    assert.equal(ch.sampleU64('g0'), digestGroup(d0, 0));
    assert.equal(ch.flushes, 1);
    const flush = ch.events.find((e) => e.op === 'flush');
    assert.equal(flush.input, '0x010203');
    assert.equal(flush.bytes, V.bytesToHex(d0));
  });

  test('four groups per flush are served from the end of the digest', () => {
    const ch = new Challenger();
    ch.observeBytes([1, 2, 3], 'x');
    const [d0, d1] = chainOf([1, 2, 3]);
    for (let k = 0; k < 4; k += 1) {
      assert.equal(ch.sampleU64(`g${k}`), digestGroup(d0, k), `group ${k}`);
    }
    // Group 0 is D[24..32] read big-endian (popped from the end, little-endian bytes).
    let g0 = 0n;
    for (let i = 24; i < 32; i += 1) g0 = (g0 << 8n) | BigInt(d0[i]);
    assert.equal(digestGroup(d0, 0), g0);
    const popped = ch.events.filter((e) => e.op === 'sample_u64')[0].bytes;
    assert.equal(popped, V.bytesToHex(Uint8Array.from(d0.subarray(24, 32)).reverse()));
    assert.equal(ch.flushes, 1);

    // The fifth sample rehashes the digest itself: input buffer == D.
    assert.equal(ch.sampleU64('g4'), digestGroup(d1, 0));
    assert.equal(ch.flushes, 2);
    const rehash = ch.events.filter((e) => e.op === 'flush')[1];
    assert.equal(rehash.input, V.bytesToHex(d0));
    assert.equal(rehash.bytes, V.bytesToHex(d1));
    for (let k = 1; k < 4; k += 1) assert.equal(ch.sampleU64(`g${4 + k}`), digestGroup(d1, k));
    assert.equal(ch.sampleU64('g8'), digestGroup(keccak_256(d1), 0));
  });

  test('observe discards unread output and chains D || new bytes', () => {
    const ch = new Challenger();
    ch.observeBytes([1, 2, 3], 'x');
    const [d0] = chainOf([1, 2, 3]);
    assert.equal(ch.sampleU64('g0'), digestGroup(d0, 0));
    ch.observeBytes([9], 'y');
    assert.equal(ch.output.length, 0, 'unread groups dropped');
    const d = keccak_256(V.concatBytes(d0, Uint8Array.from([9])));
    assert.equal(ch.sampleU64('g1'), digestGroup(d, 0), 'continues from keccak256(D || 09)');
    const flush = ch.events.filter((e) => e.op === 'flush')[1];
    assert.equal(flush.input, V.bytesToHex(V.concatBytes(d0, Uint8Array.from([9]))));
  });

  test('observe encodings: F as 8 LE bytes, EF as c0 || c1, digests raw', () => {
    const ch = new Challenger();
    ch.observeU64LE(10n, 'ten');
    ch.observeField(P - 1n, 'max');
    ch.observeExt([1n, 2n], 'ext');
    const digest = new Uint8Array(32).fill(0xab);
    ch.observeDigest(digest, 'd');
    const bytes = ch.events.map((e) => e.bytes);
    assert.deepEqual(bytes, [
      '0x0a00000000000000',
      '0x00000000ffffffff',
      '0x01000000000000000200000000000000',
      V.bytesToHex(digest),
    ]);
    assert.deepEqual(Array.from(u64ToLeBytes(0x0102030405060708n)), [8, 7, 6, 5, 4, 3, 2, 1]);
    assert.throws(() => ch.observeField(P, 'p'), /canonical/);
    assert.throws(() => ch.observeExt([0n, P], 'e'), /canonical/);
    assert.throws(() => ch.observeDigest(new Uint8Array(31), 'short'), /32 bytes/);
  });

  test('sampleBits consumes a whole group and masks its low bits', () => {
    const ch = new Challenger();
    ch.observeBytes([7], 'x');
    const [d0] = chainOf([7]);
    const raw = digestGroup(d0, 0);
    assert.equal(ch.sampleBits(13, 'b'), Number(raw & 0x1fffn));
    assert.equal(ch.sampleU64('next'), digestGroup(d0, 1), 'the rest of group 0 is gone');
    const e = ch.events.find((ev) => ev.op === 'sample_bits');
    assert.deepEqual(e, {
      op: 'sample_bits',
      label: 'b',
      bits: 13,
      raw: raw.toString(),
      value: e.value,
    });
    assert.equal(ch.sampleBits(0, 'zero'), 0);
    assert.throws(() => ch.sampleBits(64, 'x'), /unsupported/);
  });

  test('sampleField rejects a group >= p and takes the next one (stub hash)', () => {
    // Digest with group 0 = p (rejected) and group 1 = 5 (accepted).
    const digest = new Uint8Array(32);
    const setGroup = (d, k, value) => {
      let v = value;
      for (let i = 0; i < 8; i += 1) {
        d[31 - 8 * k - i] = Number(v & 0xffn);
        v >>= 8n;
      }
    };
    setGroup(digest, 0, P);
    setGroup(digest, 1, 5n);
    setGroup(digest, 2, 0xffffffffffffffffn);
    setGroup(digest, 3, P - 1n);
    const ch = new Challenger({ hash: () => digest.slice() });
    ch.observeBytes([1], 'x');
    assert.equal(ch.sampleField('f'), 5n);
    assert.deepEqual(
      ch.events.filter((e) => e.op !== 'observe' && e.op !== 'flush'),
      [
        {
          op: 'sample_u64',
          label: 'f',
          bytes: '0x01000000ffffffff',
          value: P.toString(),
        },
        { op: 'sample_u64', label: 'f', bytes: '0x0500000000000000', value: '5' },
        { op: 'sample_field', label: 'f', value: '5', rejected: [P.toString()] },
      ]
    );
    // Group 2 (2^64 - 1) is rejected, group 3 (p - 1) accepted: the mask is 64 bits wide.
    assert.equal(ch.sampleField('g'), P - 1n);
    // Every group of the next digest is >= p: all four are rejected and the
    // rehash serves the value.
    const all = new Uint8Array(32);
    for (let k = 0; k < 4; k += 1) setGroup(all, k, P + BigInt(k));
    let calls = 0;
    const ch2 = new Challenger({
      hash: () => {
        calls += 1;
        return calls === 1 ? all.slice() : digest.slice();
      },
    });
    ch2.observeBytes([2], 'y');
    assert.equal(ch2.sampleField('h'), 5n);
    assert.equal(calls, 2);
    const fieldEvent = ch2.events.find((e) => e.op === 'sample_field');
    assert.deepEqual(fieldEvent.rejected, [P, P + 1n, P + 2n, P + 3n, P].map(String));
  });

  test('sampleField rejects a real keccak256 group >= p (preimage found by search)', () => {
    // keccak256(LE(2907198534)) = 61d7b9ef16cc5c31 ffffffffbedfa74c 60640175999fdd46 dd2b959e6b707b0c:
    // group 2 (bytes 8..16) is 0xffffffffbedfa74c >= p. Found by an offline
    // search over u64 preimages (about 2^30 hashes); the assertions below
    // re-derive the property, so the constant is self-validating.
    const preimage = 2907198534n;
    const digest = keccak_256(u64ToLeBytes(preimage));
    assert.equal(
      V.bytesToHex(digest),
      '0x61d7b9ef16cc5c31ffffffffbedfa74c60640175999fdd46dd2b959e6b707b0c'
    );
    assert.ok(digestGroup(digest, 0) < P && digestGroup(digest, 1) < P);
    assert.ok(digestGroup(digest, 2) >= P, 'group 2 is out of the field');
    assert.equal(digestGroup(digest, 2), 0xffffffffbedfa74cn);

    const ch = new Challenger();
    ch.observeU64LE(preimage, 'preimage');
    assert.equal(ch.sampleField('a'), digestGroup(digest, 0));
    assert.equal(ch.sampleField('b'), digestGroup(digest, 1));
    assert.equal(ch.sampleField('c'), digestGroup(digest, 3), 'group 2 rejected, group 3 served');
    const fieldEvents = ch.events.filter((e) => e.op === 'sample_field');
    assert.deepEqual(
      fieldEvents.map((e) => e.rejected),
      [[], [], [digestGroup(digest, 2).toString()]]
    );
    assert.equal(ch.events.filter((e) => e.op === 'sample_u64').length, 4);
    assert.equal(ch.flushes, 1);
    // The next field sample needs a rehash: keccak256(D).
    assert.equal(ch.sampleField('d'), digestGroup(keccak_256(digest), 0));
    assert.equal(ch.flushes, 2);
  });

  test('checkWitness(0, w) is a no-op on the transcript', () => {
    const a = new Challenger();
    const b = new Challenger();
    for (const ch of [a, b]) ch.observeBytes([1, 2], 'x');
    assert.equal(a.checkWitness(0, 7n, 'commit_pow[0]'), true);
    assert.deepEqual(a.events[a.events.length - 1], {
      op: 'check_pow',
      label: 'commit_pow[0]',
      bits: 0,
      witness: '7',
      ok: true,
    });
    assert.equal(a.sampleU64('g'), b.sampleU64('g'));
    assert.deepEqual(a.input, b.input);
  });

  test('checkWitness(bits, w) observes w then requires sampleBits(bits) == 0', () => {
    const base = new Challenger();
    base.observeBytes([3, 1, 4], 'x');
    const bits = 8;
    let witness = -1n;
    for (let w = 0n; w < 4096n && witness < 0n; w += 1n) {
      if (base.clone().checkWitness(bits, w, 'pow')) witness = w;
    }
    assert.ok(witness >= 0n, 'a witness exists within 4096 tries for 8 bits');
    const ch = base.clone();
    assert.equal(ch.checkWitness(bits, witness, 'pow'), true);
    const expected = base.clone();
    expected.observeField(witness, 'pow.witness');
    assert.equal(expected.sampleBits(bits, 'pow'), 0);
    assert.deepEqual(ch.events.slice(0, -1), expected.events);
    assert.deepEqual(ch.events[ch.events.length - 1], {
      op: 'check_pow',
      label: 'pow',
      bits,
      witness: witness.toString(),
      value: '0',
      ok: true,
    });
    const wrong = base.clone();
    assert.equal(wrong.checkWitness(bits, witness + 1n, 'pow'), false);
    assert.equal(wrong.events[wrong.events.length - 1].ok, false);
  });

  test('replay reports a tampered transcript', () => {
    const { vector } = valid[0];
    const events = vector.transcript.map((e) => ({ ...e }));
    const i = events.findIndex((e) => e.op === 'sample_field');
    events[i] = { ...events[i], value: '0' };
    assert.throws(() => replay(events), /transcript event/);
    const shorter = vector.transcript.slice(0, -2);
    assert.throws(() => compareEvents(replay(shorter).events, vector.transcript), /length/);
  });
});

describe('PowFailed mutations', () => {
  for (const { baseName, vector } of mutated) {
    if (vector.expected.error !== 'PowFailed') continue;
    test(baseName, () => {
      const result = verifyProof(vector.config, V.proofBytes(vector), V.publicValuesBytes(vector));
      assert.equal(result.ok, false);
      assert.equal(result.error, 'PowFailed', result.detail);
      assert.match(result.detail, /query_pow|commit_pow/);
    });
  }
});
