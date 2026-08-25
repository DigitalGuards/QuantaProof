// Self-checks of the Goldilocks JS reference (test/lib/goldilocks.js): field
// constants, the two-adic generator tables against the Plonky3 values, the
// packed table words the contract stores, bit and byte helpers, and random
// identities. No chain involved; the contract suite compares the Hyperion
// library against this reference.

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const G = require('../lib/goldilocks');

// Plonky3 TWO_ADIC_GENERATORS[0..=32] for Goldilocks.
const PLONKY3_TWO_ADIC_GENERATORS = [
  0x1n,
  0xffffffff00000000n,
  0x0001000000000000n,
  0xfffffffeff000001n,
  0xefffffff00000001n,
  0x00003fffffffc000n,
  0x0000008000000000n,
  0xf80007ff08000001n,
  0xbf79143ce60ca966n,
  0x1905d02a5c411f4en,
  0x9d8f2ad78bfed972n,
  0x0653b4801da1c8cfn,
  0xf2c35199959dfcb6n,
  0x1544ef2335d17997n,
  0xe0ee099310bba1e2n,
  0xf6b2cffe2306baacn,
  0x54df9630bf79450en,
  0xabd0a6e8aa3d8a0en,
  0x81281a7b05f9beacn,
  0xfbd41c6b8caa3302n,
  0x30ba2ecd5e93e76dn,
  0xf502aef532322654n,
  0x4b2a18ade67246b5n,
  0xea9d5a1336fbc98bn,
  0x86cdcc31c307e171n,
  0x4bbaf5976ecfefd8n,
  0xed41d05b78d6e286n,
  0x10d78dd8915a171dn,
  0x59049500004a4485n,
  0xdfa8c93ba46d2666n,
  0x7e9bd009b86a0845n,
  0x400a7f755588e659n,
  0x185629dcda58878cn,
];

const libraryPath = path.join(
  __dirname,
  '..',
  '..',
  'contracts',
  'hyperion',
  'lib',
  'Goldilocks.hyp'
);

function libraryConstants() {
  const source = fs.readFileSync(libraryPath, 'utf8');
  const out = {};
  for (const m of source.matchAll(/uint512 internal constant (\w+) =\s*(0x[0-9A-Fa-f]+|\d+);/g)) {
    out[m[1]] = BigInt(m[2]);
  }
  return out;
}

// Deterministic Miller-Rabin with fixed bases; enough for one 64-bit prime.
function isProbablePrime(n) {
  if (n < 2n) return false;
  let d = n - 1n;
  let r = 0;
  while ((d & 1n) === 0n) {
    d >>= 1n;
    r += 1;
  }
  for (const a of [2n, 3n, 5n, 7n, 11n, 13n, 17n, 19n, 23n, 29n, 31n, 37n]) {
    if (a % n === 0n) continue;
    let x = G.pow(a, d);
    if (x === 1n || x === n - 1n) continue;
    let composite = true;
    for (let i = 1; i < r; i += 1) {
      x = (x * x) % n;
      if (x === n - 1n) {
        composite = false;
        break;
      }
    }
    if (composite) return false;
  }
  return true;
}

test('field constants', () => {
  assert.equal(G.P, (1n << 64n) - (1n << 32n) + 1n);
  assert.equal(isProbablePrime(G.P), true);
  assert.equal(G.INV2, 0x7fffffff80000001n);
  assert.equal(G.inv(2n), G.INV2);
  assert.equal(G.mul(G.INV2, 2n), 1n);
  // p - 1 = 2^32 * (2^32 - 1): the two-adicity is exactly 32.
  assert.equal((G.P - 1n) % (1n << 32n), 0n);
  assert.notEqual((G.P - 1n) % (1n << 33n), 0n);
  // 7 generates the multiplicative group: its order is p - 1, so 7^((p-1)/q) != 1
  // for every prime factor q of p - 1 = 2^32 * 3 * 5 * 17 * 257 * 65537.
  for (const q of [2n, 3n, 5n, 17n, 257n, 65537n]) {
    assert.notEqual(G.pow(G.GENERATOR, (G.P - 1n) / q), 1n, `7^((p-1)/${q}) == 1`);
  }
});

test('two-adic generator table matches Plonky3 and satisfies the order identities', () => {
  assert.equal(G.TWO_ADIC_GENERATORS.length, 33);
  assert.equal(G.pow(G.GENERATOR, (G.P - 1n) >> 32n), PLONKY3_TWO_ADIC_GENERATORS[32]);
  for (let i = 0; i <= 32; i += 1) {
    const g = G.twoAdicGen(i);
    assert.equal(g, PLONKY3_TWO_ADIC_GENERATORS[i], `g_${i}`);
    assert.equal(G.pow2k(g, i), 1n, `g_${i}^(2^${i}) != 1`);
    if (i > 0) {
      assert.notEqual(G.pow2k(g, i - 1), 1n, `g_${i}^(2^${i - 1}) == 1`);
      assert.equal(G.sq(g), G.twoAdicGen(i - 1), `g_${i}^2 != g_${i - 1}`);
    }
    assert.equal(G.mul(g, G.twoAdicGenInv(i)), 1n, `g_${i} * ginv_${i} != 1`);
    assert.equal(G.twoAdicGenInv(i), G.inv(g));
  }
  assert.throws(() => G.twoAdicGen(33), /out of range/);
  assert.throws(() => G.twoAdicGenInv(-1), /out of range/);
});

test('packed table words equal the constants in Goldilocks.hyp', () => {
  const consts = libraryConstants();
  assert.equal(consts.P, G.P);
  assert.equal(consts.P_MINUS_2, G.P - 2n);
  assert.equal(consts.GENERATOR, G.GENERATOR);
  assert.equal(consts.TWO_ADICITY, BigInt(G.TWO_ADICITY));
  assert.equal(consts.INV2, G.INV2);
  assert.equal(consts.MASK64, G.MASK64);

  const gen = G.packTableWords(G.TWO_ADIC_GENERATORS);
  const inv = G.packTableWords(G.TWO_ADIC_GENERATOR_INVERSES);
  assert.equal(gen.length, 5);
  assert.equal(inv.length, 5);
  for (let w = 0; w < 5; w += 1) {
    assert.equal(consts[`TAG_${w}`], gen[w], `TAG_${w}`);
    assert.equal(consts[`TAGI_${w}`], inv[w], `TAGI_${w}`);
  }
  // Unpack the way the contract does: word i >> 3, lane i & 7 from the low end.
  for (let i = 0; i <= 32; i += 1) {
    const g = (gen[i >> 3] >> BigInt(64 * (i & 7))) & G.MASK64;
    assert.equal(g, G.twoAdicGen(i));
  }

  const repeat = (pattern, times) => BigInt(`0x${pattern.repeat(times)}`);
  assert.equal(consts.LANE_MASK_8, repeat('00FF', 32));
  assert.equal(consts.LANE_MASK_16, repeat('0000FFFF', 16));
  assert.equal(consts.LANE_MASK_32, repeat('00000000FFFFFFFF', 8));
  assert.equal(consts.LANE_TOP_BIT, repeat('8000000000000000', 8));
  assert.equal(consts.LANE_LOW_63, repeat('7FFFFFFFFFFFFFFF', 8));
});

test('ring operations and inversion on edge values', () => {
  const edges = [0n, 1n, 2n, G.P - 1n, 1n << 32n, (1n << 32n) - 1n, G.INV2, G.GENERATOR];
  for (const a of edges) {
    for (const b of edges) {
      const s = G.add(a, b);
      assert.equal(G.sub(s, b), a);
      assert.equal(G.add(G.neg(a), a), 0n);
      assert.equal(G.mul(a, b), G.mul(b, a));
      assert.equal(G.mulAdd(a, b, 0n), G.mul(a, b));
      assert.equal(G.mulAdd(a, b, G.mul(a, b)), G.add(G.mul(a, b), G.mul(a, b)));
      if (a !== 0n) {
        assert.equal(G.mul(a, G.inv(a)), 1n, `inv(${a})`);
      }
    }
    assert.equal(G.sq(a), G.mul(a, a));
    assert.equal(G.isCanonical(a), true);
  }
  assert.equal(G.isCanonical(G.P), false);
  assert.equal(G.isCanonical(G.MASK64), false);
  assert.throws(() => G.inv(0n), /zero/);
  assert.equal(G.mul(G.P - 1n, G.P - 1n), 1n);
  assert.equal(G.add(G.P - 1n, 1n), 0n);
  assert.equal(G.sub(0n, 1n), G.P - 1n);
  assert.equal(G.neg(0n), 0n);
  assert.equal(G.reduce(G.P + 5n), 5n);
  assert.equal(G.reduce(-1n), G.P - 1n);
});

test('pow and pow2k agree with repeated multiplication', () => {
  const rng = G.prng(0x5eed0001n);
  for (let round = 0; round < 50; round += 1) {
    const x = rng.element();
    const e = rng.int(200);
    let expected = 1n;
    for (let i = 0; i < e; i += 1) expected = G.mul(expected, x);
    assert.equal(G.pow(x, BigInt(e)), expected);
    const k = rng.int(12);
    assert.equal(G.pow2k(x, k), G.pow(x, 1n << BigInt(k)));
  }
  assert.equal(G.pow(0n, 0n), 1n);
  assert.equal(G.pow(5n, 1n), 5n);
  assert.equal(G.pow(G.GENERATOR, G.P - 1n), 1n);
  assert.equal(G.pow(G.GENERATOR, G.P - 2n), G.inv(G.GENERATOR));
});

test('rev reverses the low bits and is an involution', () => {
  assert.equal(G.rev(1n, 3), 4n);
  assert.equal(G.rev(0b110n, 3), 0b011n);
  assert.equal(G.rev(1n, 1), 1n);
  assert.equal(G.rev(0n, 32), 0n);
  assert.equal(G.rev(1n, 32), 1n << 31n);
  assert.equal(G.rev(0x80000000n, 32), 1n);
  assert.equal(G.rev(0x12345678n, 32), 0x1e6a2c48n);
  // Bits above the width are ignored.
  assert.equal(G.rev(0b1101n, 2), 0b10n);
  const rng = G.prng(0x5eed0002n);
  for (let bits = 1; bits <= 32; bits += 1) {
    for (let round = 0; round < 8; round += 1) {
      const x = rng.bits(bits);
      assert.equal(G.rev(G.rev(x, bits), bits), x);
      assert.ok(G.rev(x, bits) < 1n << BigInt(bits));
    }
  }
  assert.throws(() => G.rev(1n, 0), /out of range/);
  assert.throws(() => G.rev(1n, 33), /out of range/);
});

test('bswap64 and the little-endian byte helpers', () => {
  assert.equal(G.bswap64(0x0102030405060708n), 0x0807060504030201n);
  assert.equal(G.bswap64(0n), 0n);
  assert.equal(G.bswap64(G.MASK64), G.MASK64);
  assert.equal(G.bswap64(1n), 1n << 56n);
  const rng = G.prng(0x5eed0003n);
  for (let round = 0; round < 100; round += 1) {
    const x = rng.u64();
    assert.equal(G.bswap64(G.bswap64(x)), x);
    const bytes = G.u64ToLeBytes(x);
    assert.equal(G.leBytesToU64(bytes), x);
    // Reading the little-endian bytes as big-endian gives the byte swap.
    let be = 0n;
    for (const b of bytes) be = (be << 8n) | BigInt(b);
    assert.equal(be, G.bswap64(x));
  }
});

test('calldata lanes: decode, pack, extract and the canonical check', () => {
  const rng = G.prng(0x5eed0004n);
  const elements = Array.from({ length: 8 }, () => rng.element());
  const bytes = G.elementsToBytes(elements);
  assert.equal(bytes.length, 64);
  assert.deepEqual(G.laneDecode(bytes), elements);
  const word = G.packLanes(elements);
  for (let k = 0; k < 8; k += 1) {
    assert.equal(G.lane(word, k), elements[k]);
    assert.equal(G.cdElem(bytes, 8 * k), elements[k]);
  }
  assert.equal(G.lanesCanonical(elements), true);
  assert.equal(G.lanesCanonical([...elements.slice(0, 7), G.P]), false);
  assert.equal(G.lanesCanonical([G.MASK64, ...elements.slice(1)]), false);

  // Non-canonical wire values are rejected by cdElem and reported by laneDecode.
  const bad = G.elementsToBytes([G.P]);
  assert.throws(() => G.cdElem(bad, 0), /non-canonical/);
  assert.equal(G.laneDecode(bad)[0], G.P);
  // Bytes past the end read as zero, like calldataload.
  assert.deepEqual(G.laneDecode(new Uint8Array(8).fill(1)), [
    0x0101010101010101n,
    0n,
    0n,
    0n,
    0n,
    0n,
    0n,
    0n,
  ]);
  assert.throws(() => G.lane(word, 8), /out of range/);
});

test('seeded PRNG is deterministic and produces canonical elements', () => {
  const a = G.prng(42n);
  const b = G.prng(42n);
  for (let i = 0; i < 20; i += 1) {
    const x = a.element();
    assert.equal(x, b.element());
    assert.ok(G.isCanonical(x));
  }
  assert.notEqual(G.prng(1n).u64(), G.prng(2n).u64());
  assert.notEqual(a.nonZeroElement(), 0n);
  assert.ok(a.bits(5) < 32n);
  assert.ok(a.int(10) < 10);
});
