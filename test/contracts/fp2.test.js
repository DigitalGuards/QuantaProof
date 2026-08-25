// Fp2.hyp against the JS reference on a live QRVM.
//
// Deploys contracts/hyperion/test/Fp2Harness.hyp once and checks every
// extension field function: known values, edge pairs, 10,000 seeded random
// mul/add/sub/sq/neg/mulBase/norm operations in batches of 256 elements,
// 1,000 inversions, 2,500 powers, batchInverse (Montgomery trick) for 64
// elements, and the gas loop that feeds docs/GAS-PRIMITIVES.md. Skips without
// STARK_RPC_URL. STARK_RANDOM_OPS overrides the random operation count.

const assert = require('node:assert/strict');
const test = require('node:test');

const G = require('../lib/goldilocks');
const F2 = require('../lib/fp2');
const H = require('../lib/harness');

const rpcUrl = process.env.STARK_RPC_URL;
const skip = rpcUrl ? false : 'set STARK_RPC_URL to run against a node';
const RANDOM_OPS = Number(process.env.STARK_RANDOM_OPS || 10000);
const INV_OPS = Math.min(RANDOM_OPS, 1000);
const POW_OPS = Math.min(RANDOM_OPS, 2500);
const BATCH = 256; // elements per call (512 uint64 components)
const LOOP_N = 1024n;

const TARGET_EF_MUL = 90;

const EDGES = [0n, 1n, G.P - 1n, 1n << 32n, (1n << 32n) - 1n];

const GAS_OPS = [
  [0, 'yul empty loop (baseline)'],
  [1, 'EF mul: 5 mul + 2 add + 2 mod'],
  [2, 'EF sq'],
  [3, 'EF mulBase: 2 mulmod'],
  [4, 'EF add: 2 addmod'],
  [5, 'EF inv: norm + modexp + 2 mulmod'],
  [6, 'high-level empty loop (baseline)'],
  [7, 'Fp2.mul (library call)'],
  [8, 'Fp2.inv (library call)'],
  [9, 'Fp2.batchInverse per element (norm-based Montgomery)'],
  [10, 'Fp2.pow(x, 2^64 - 1) (library call)'],
  [11, 'Fp2.sq (library call)'],
];

// Batch `signature` over element arrays (interleaved components) and compare
// each output element with `expected(i)`; `scalars` optionally maps an element
// array to a per-element side input (uint64[] with one entry per element).
async function checkBatch(h, signature, elements, expected, extra = null) {
  for (let start = 0; start < elements.length; start += BATCH) {
    const slice = elements.slice(start, start + BATCH);
    const args = [F2.flatten(slice)];
    if (extra) args.push(extra.slice(start, start + BATCH));
    const [out] = await h.call(signature, args, ['uint64[]']);
    const got = F2.unflatten(out);
    assert.equal(got.length, slice.length, `${signature}: batch length`);
    for (let i = 0; i < slice.length; i += 1) {
      assert.deepEqual(got[i], expected(start + i), `${signature}: element ${start + i}`);
    }
  }
}

async function checkBinaryBatch(h, signature, a, b, expected) {
  for (let start = 0; start < a.length; start += BATCH) {
    const [out] = await h.call(
      signature,
      [F2.flatten(a.slice(start, start + BATCH)), F2.flatten(b.slice(start, start + BATCH))],
      ['uint64[]']
    );
    const got = F2.unflatten(out);
    for (let i = 0; i < got.length; i += 1) {
      assert.deepEqual(got[i], expected(start + i), `${signature}: element ${start + i}`);
    }
  }
}

test('Fp2 harness', { skip, timeout: 1200000 }, async (t) => {
  const ctx = await H.connect();
  const h = await H.deployHarness(ctx, 'test/Fp2Harness.hyp');
  t.diagnostic(`Fp2Harness at ${h.address} (chain ${ctx.chainId})`);
  const rng = G.prng(0xf2c0ffeen);

  const pair = (sig, args) => h.call(sig, args, ['uint512', 'uint512']);

  await t.test('known values and single-element wrappers', async () => {
    assert.deepEqual(await pair('sq(uint512,uint512)', [0n, 1n]), [7n, 0n]);
    assert.deepEqual(await pair('mul(uint512,uint512,uint512,uint512)', [0n, 1n, 0n, 1n]), [
      7n,
      0n,
    ]);
    assert.deepEqual(await pair('fromBase(uint512)', [5n]), [5n, 0n]);
    assert.deepEqual(await pair('mulBase(uint512,uint512,uint512)', [2n, 3n, 4n]), [8n, 12n]);
    assert.deepEqual(await pair('neg(uint512,uint512)', [0n, 0n]), [0n, 0n]);
    assert.deepEqual(await pair('neg(uint512,uint512)', [1n, 2n]), [G.P - 1n, G.P - 2n]);
    assert.deepEqual(
      await pair('add(uint512,uint512,uint512,uint512)', [G.P - 1n, G.P - 1n, 1n, 2n]),
      [0n, 1n]
    );
    assert.deepEqual(await pair('sub(uint512,uint512,uint512,uint512)', [0n, 0n, 1n, G.P - 1n]), [
      G.P - 1n,
      1n,
    ]);
    assert.equal(await h.callOne('norm(uint512,uint512)', [3n, 0n], 'uint512'), 9n);
    assert.equal(await h.callOne('norm(uint512,uint512)', [0n, 1n], 'uint512'), G.P - 7n);
    assert.deepEqual(await pair('inv(uint512,uint512)', [1n, 0n]), [1n, 0n]);
    assert.deepEqual(await pair('inv(uint512,uint512)', [0n, 1n]), [0n, G.inv(7n)]);
    await H.expectRevert(h, 'inv(uint512,uint512)', [0n, 0n], 'ZeroInverse()');
    assert.deepEqual(await pair('pow(uint512,uint512,uint512)', [0n, 1n, 3n]), [0n, 7n]);
    assert.deepEqual(await pair('pow(uint512,uint512,uint512)', [5n, 6n, 0n]), [1n, 0n]);
    assert.deepEqual(await pair('pow(uint512,uint512,uint512)', [5n, 6n, 1n]), [5n, 6n]);
    assert.equal(
      await h.callOne('equal(uint512,uint512,uint512,uint512)', [1n, 2n, 1n, 2n], 'bool'),
      true
    );
    assert.equal(
      await h.callOne('equal(uint512,uint512,uint512,uint512)', [1n, 2n, 2n, 1n], 'bool'),
      false
    );
    // Frobenius through pow: a^p is the conjugate.
    const a = F2.randomNonZeroElement(rng);
    assert.deepEqual(await pair('pow(uint512,uint512,uint512)', [a[0], a[1], G.P]), [
      a[0],
      G.neg(a[1]),
    ]);
  });

  await t.test('edge pairs through the batch wrappers', async () => {
    const elements = [];
    for (const c0 of EDGES) for (const c1 of EDGES) elements.push([c0, c1]);
    const a = [];
    const b = [];
    for (const x of elements) {
      for (const y of elements) {
        a.push(x);
        b.push(y);
      }
    }
    await checkBinaryBatch(h, 'batchAdd(uint64[],uint64[])', a, b, (i) => F2.add(a[i], b[i]));
    await checkBinaryBatch(h, 'batchSub(uint64[],uint64[])', a, b, (i) => F2.sub(a[i], b[i]));
    await checkBinaryBatch(h, 'batchMul(uint64[],uint64[])', a, b, (i) => F2.mul(a[i], b[i]));
    await checkBatch(h, 'batchSq(uint64[])', elements, (i) => F2.sq(elements[i]));
    await checkBatch(h, 'batchNeg(uint64[])', elements, (i) => F2.neg(elements[i]));
    const nonZero = elements.filter((e) => e[0] !== 0n || e[1] !== 0n);
    await checkBatch(h, 'batchInv(uint64[])', nonZero, (i) => F2.inv(nonZero[i]));
    const scalars = elements.map((e) => e[0]);
    await checkBatch(
      h,
      'batchMulBase(uint64[],uint64[])',
      elements,
      (i) => F2.mulBase(elements[i], scalars[i]),
      scalars
    );
  });

  await t.test(`${RANDOM_OPS} random mul/add/sub/sq/neg/mulBase/norm operations`, async () => {
    const a = Array.from({ length: RANDOM_OPS }, () => F2.randomElement(rng));
    const b = Array.from({ length: RANDOM_OPS }, () => F2.randomElement(rng));
    const s = Array.from({ length: RANDOM_OPS }, () => rng.element());
    await checkBinaryBatch(h, 'batchMul(uint64[],uint64[])', a, b, (i) => F2.mul(a[i], b[i]));
    await checkBinaryBatch(h, 'batchAdd(uint64[],uint64[])', a, b, (i) => F2.add(a[i], b[i]));
    await checkBinaryBatch(h, 'batchSub(uint64[],uint64[])', a, b, (i) => F2.sub(a[i], b[i]));
    await checkBatch(h, 'batchSq(uint64[])', a, (i) => F2.sq(a[i]));
    await checkBatch(h, 'batchNeg(uint64[])', a, (i) => F2.neg(a[i]));
    await checkBatch(h, 'batchMulBase(uint64[],uint64[])', a, (i) => F2.mulBase(a[i], s[i]), s);
    for (let start = 0; start < RANDOM_OPS; start += BATCH) {
      const slice = a.slice(start, start + BATCH);
      const [norms] = await h.call('batchNorm(uint64[])', [F2.flatten(slice)], ['uint64[]']);
      assert.deepEqual(
        norms,
        slice.map((e) => F2.norm(e))
      );
    }
  });

  await t.test(`${INV_OPS} random inversions`, async () => {
    const a = Array.from({ length: INV_OPS }, () => F2.randomNonZeroElement(rng));
    await checkBatch(h, 'batchInv(uint64[])', a, (i) => F2.inv(a[i]));
  });

  await t.test(`${POW_OPS} random powers`, async () => {
    const a = Array.from({ length: POW_OPS }, () => F2.randomElement(rng));
    const e = Array.from({ length: POW_OPS }, () => rng.u64());
    await checkBatch(h, 'batchPow(uint64[],uint64[])', a, (i) => F2.pow(a[i], e[i]), e);
  });

  await t.test('batchInverse (Montgomery trick) for 64 elements', async () => {
    for (const count of [1, 2, 3, 64]) {
      const a = Array.from({ length: count }, () => F2.randomNonZeroElement(rng));
      const [out] = await h.call('batchInverse(uint64[])', [F2.flatten(a)], ['uint64[]']);
      assert.deepEqual(F2.unflatten(out), F2.batchInverse(a), `count ${count}`);
      assert.deepEqual(
        F2.unflatten(out),
        a.map((x) => F2.inv(x))
      );
    }
    const [empty] = await h.call('batchInverse(uint64[])', [[]], ['uint64[]']);
    assert.deepEqual(empty, []);
    const withZero = F2.flatten([
      F2.randomNonZeroElement(rng),
      F2.ZERO,
      F2.randomNonZeroElement(rng),
    ]);
    await H.expectRevert(h, 'batchInverse(uint64[])', [withZero], 'ZeroInverse()');
  });

  await t.test('gas loop', async () => {
    const rows = [];
    for (const [op, label] of GAS_OPS) {
      // Fp2.pow costs about 15k gas per iteration: fewer iterations keep 2n
      // under the 20M call gas limit. batchInverse allocates 128 bytes per
      // element on top of the input array, so a smaller n keeps quadratic
      // memory expansion out of its per-element figure.
      const iterations = op === 10 || op === 9 ? 128n : LOOP_N;
      const r = await H.marginalGas(h, op, iterations, {
        returnTypes: ['uint512', 'uint512', 'uint512'],
      });
      rows.push({ op, label, marginal: r.marginal, gasN: r.gasN, gas2N: r.gas2N });
    }
    const yulBase = rows.find((r) => r.op === 0).marginal;
    const hlBase = rows.find((r) => r.op === 6).marginal;
    for (const r of rows) {
      // batchInverse (op 9) is one call over n elements, so its marginal cost
      // is already per element without a loop to subtract.
      r.net = r.op === 9 ? r.marginal : r.op < 6 ? r.marginal - yulBase : r.marginal - hlBase;
      t.diagnostic(
        `gas op ${String(r.op).padStart(2)} ${r.label.padEnd(40)} marginal ${r.marginal.toFixed(2).padStart(9)} net ${r.net.toFixed(2).padStart(9)}`
      );
    }
    const efMul = rows.find((r) => r.op === 1).net;
    t.diagnostic(
      `targets: EF mul < ${TARGET_EF_MUL} (${efMul}, ${efMul < TARGET_EF_MUL ? 'met' : 'MISSED'}); ` +
        `optimizer runs ${H.optimizerOptions().optimizerRuns}`
    );
    // Five MUL, two ADD and two MOD are 41 gas; the rest is stack traffic for
    // four operands used twice each plus the literals, so the target is
    // documented as missed in docs/GAS-PRIMITIVES.md when the measurement
    // lands above it; the regression bound is 120.
    assert.ok(efMul < 120, `EF mul marginal ${efMul} >= 120`);
    assert.ok(rows.every((r) => r.gas2N > r.gasN));
  });
});
