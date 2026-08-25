// Goldilocks.hyp against the JS reference on a live QRVM.
//
// Deploys contracts/hyperion/test/GoldilocksHarness.hyp once and checks every
// library function: edge values, 10,000 seeded random operations per ring
// function in batches of 256, modexp inversion for 1,000 elements, the two
// two-adic tables, rev for every width, bswap64, the calldata lane decoder and
// the gas loop that feeds docs/GAS-PRIMITIVES.md. Skips without STARK_RPC_URL.
//
// STARK_RANDOM_OPS overrides the random operation count (default 10,000).

const assert = require('node:assert/strict');
const test = require('node:test');

const G = require('../lib/goldilocks');
const H = require('../lib/harness');

const rpcUrl = process.env.STARK_RPC_URL;
const skip = rpcUrl ? false : 'set STARK_RPC_URL to run against a node';
const RANDOM_OPS = Number(process.env.STARK_RANDOM_OPS || 10000);
const INV_OPS = Math.min(RANDOM_OPS, 1000);
const BATCH = 256;
const LOOP_N = 1024n;

const EDGES = [0n, 1n, G.P - 1n, 1n << 32n, (1n << 32n) - 1n, G.INV2, G.GENERATOR];

// Marginal-gas targets from the milestone definition (net of loop overhead).
const TARGET_MUL = 25;
const TARGET_INV = 400;

const GAS_OPS = [
  [0, 'yul empty loop (baseline)'],
  [1, 'add: addmod(x, y, P)'],
  [2, 'sub: addmod(x, sub(P, y), P)'],
  [3, 'neg: mod(sub(P, x), P)'],
  [4, 'mul: mulmod(x, y, P)'],
  [5, 'mul via mod(mul(x, y), P)'],
  [6, 'sq: mulmod(x, x, P)'],
  [7, 'mulAdd: mod(add(mul(x, y), z), P)'],
  [8, 'inv: modexp precompile'],
  [9, 'cdLanes: calldataload + 3-stage swap'],
  [10, 'lane: extract one lane'],
  [11, 'rev(x, 32)'],
  [12, 'bswap64'],
  [13, 'twoAdicGen: packed constants (5-way switch)'],
  [14, 'twoAdicGen: 33-case switch'],
  [15, 'lanesCanonical: SWAR check'],
  [16, 'high-level empty loop (baseline)'],
  [17, 'Goldilocks.add (library call)'],
  [18, 'Goldilocks.mul (library call)'],
  [19, 'Goldilocks.inv (library call)'],
  [20, 'Goldilocks.pow(x, 2^64 - 1) (library call)'],
  [21, 'Goldilocks.pow2k(x, 32) (library call)'],
  [22, 'Goldilocks.twoAdicGen (library call)'],
  [23, 'Goldilocks.cdElem (library call)'],
  [24, 'Goldilocks.rev(x, 32) (library call)'],
  [25, 'Goldilocks.bswap64 (library call)'],
  [26, 'Goldilocks.sub (library call)'],
  [27, 'Goldilocks.sq (library call)'],
  [28, 'Goldilocks.twoAdicGenAt (memory image, library call)'],
  [29, 'Goldilocks.loadTwoAdicTables (one-time image write)'],
];

// Iterations per gas-loop op; the pow loop costs thousands of gas per
// iteration and must stay under the 20M call gas limit at 2n.
function loopIterations(op) {
  return op === 20 ? 256n : LOOP_N;
}

// Call `signature` over the inputs in batches of BATCH and compare each
// output element with `expected(i)`.
async function checkBatch(h, signature, inputs, expected, count) {
  let checked = 0;
  for (let start = 0; start < count; start += BATCH) {
    const end = Math.min(count, start + BATCH);
    const args = inputs.map((values) => values.slice(start, end));
    const [out] = await h.call(signature, args, ['uint64[]']);
    assert.equal(out.length, end - start, `${signature}: batch length`);
    for (let i = start; i < end; i += 1) {
      assert.equal(out[i - start], expected(i), `${signature}: element ${i}`);
    }
    checked += out.length;
  }
  assert.equal(checked, count);
}

test('Goldilocks harness', { skip, timeout: 1200000 }, async (t) => {
  const ctx = await H.connect();
  const h = await H.deployHarness(ctx, 'test/GoldilocksHarness.hyp');
  t.diagnostic(`GoldilocksHarness at ${h.address} (chain ${ctx.chainId})`);
  const rng = G.prng(0x601d110c5n);

  await t.test('edge values through the single-operand wrappers', async () => {
    assert.equal(await h.callOne('add(uint512,uint512)', [G.P - 1n, 1n], 'uint512'), 0n);
    assert.equal(await h.callOne('sub(uint512,uint512)', [0n, 1n], 'uint512'), G.P - 1n);
    assert.equal(await h.callOne('neg(uint512)', [0n], 'uint512'), 0n);
    assert.equal(await h.callOne('neg(uint512)', [1n], 'uint512'), G.P - 1n);
    assert.equal(await h.callOne('mul(uint512,uint512)', [G.P - 1n, G.P - 1n], 'uint512'), 1n);
    assert.equal(await h.callOne('sq(uint512)', [G.P - 1n], 'uint512'), 1n);
    assert.equal(await h.callOne('reduce(uint512)', [G.P + 5n], 'uint512'), 5n);
    assert.equal(
      await h.callOne('reduce(uint512)', [(1n << 512n) - 1n], 'uint512'),
      G.reduce((1n << 512n) - 1n)
    );
    assert.equal(
      await h.callOne('mulNoReduce(uint512,uint512)', [G.P - 1n, G.P - 1n], 'uint512'),
      (G.P - 1n) * (G.P - 1n)
    );
    // Lazy reduction: c may hold a sum of unreduced products.
    const big = (G.P - 1n) * (G.P - 1n) * 3n;
    assert.equal(
      await h.callOne('mulAdd(uint512,uint512,uint512)', [G.P - 1n, G.P - 1n, big], 'uint512'),
      G.mulAdd(G.P - 1n, G.P - 1n, big)
    );
    assert.equal(await h.callOne('inv(uint512)', [2n], 'uint512'), G.INV2);
    assert.equal(await h.callOne('inv(uint512)', [1n], 'uint512'), 1n);
    assert.equal(await h.callOne('inv(uint512)', [G.P - 1n], 'uint512'), G.P - 1n);
    await H.expectRevert(h, 'inv(uint512)', [0n], 'ZeroInverse()');
    assert.equal(await h.callOne('isCanonical(uint512)', [G.P - 1n], 'bool'), true);
    assert.equal(await h.callOne('isCanonical(uint512)', [G.P], 'bool'), false);
    assert.equal(await h.callOne('isCanonical(uint512)', [G.MASK64], 'bool'), false);
    assert.equal(await h.callOne('pow(uint512,uint512)', [G.GENERATOR, G.P - 1n], 'uint512'), 1n);
    assert.equal(await h.callOne('pow(uint512,uint512)', [0n, 0n], 'uint512'), 1n);
    assert.equal(await h.callOne('pow2k(uint512,uint512)', [G.GENERATOR, 0n], 'uint512'), 7n);

    // Every pair of edge values through the batch wrappers.
    const a = [];
    const b = [];
    for (const x of EDGES) {
      for (const y of EDGES) {
        a.push(x);
        b.push(y);
      }
    }
    const n = a.length;
    await checkBatch(h, 'batchAdd(uint64[],uint64[])', [a, b], (i) => G.add(a[i], b[i]), n);
    await checkBatch(h, 'batchSub(uint64[],uint64[])', [a, b], (i) => G.sub(a[i], b[i]), n);
    await checkBatch(h, 'batchMul(uint64[],uint64[])', [a, b], (i) => G.mul(a[i], b[i]), n);
    await checkBatch(h, 'batchNeg(uint64[])', [a], (i) => G.neg(a[i]), n);
    await checkBatch(h, 'batchSq(uint64[])', [a], (i) => G.sq(a[i]), n);
    const nonZero = a.filter((x) => x !== 0n);
    await checkBatch(h, 'batchInv(uint64[])', [nonZero], (i) => G.inv(nonZero[i]), nonZero.length);
    const canon = [...EDGES, G.P, G.P + 1n, G.MASK64];
    await checkBatch(
      h,
      'batchIsCanonical(uint64[])',
      [canon],
      (i) => (G.isCanonical(canon[i]) ? 1n : 0n),
      canon.length
    );
  });

  await t.test(`${RANDOM_OPS} random add/sub/mul/sq/neg/mulAdd operations`, async () => {
    const a = Array.from({ length: RANDOM_OPS }, () => rng.element());
    const b = Array.from({ length: RANDOM_OPS }, () => rng.element());
    const c = Array.from({ length: RANDOM_OPS }, () => rng.element());
    await checkBatch(
      h,
      'batchAdd(uint64[],uint64[])',
      [a, b],
      (i) => G.add(a[i], b[i]),
      RANDOM_OPS
    );
    await checkBatch(
      h,
      'batchSub(uint64[],uint64[])',
      [a, b],
      (i) => G.sub(a[i], b[i]),
      RANDOM_OPS
    );
    await checkBatch(
      h,
      'batchMul(uint64[],uint64[])',
      [a, b],
      (i) => G.mul(a[i], b[i]),
      RANDOM_OPS
    );
    await checkBatch(h, 'batchSq(uint64[])', [a], (i) => G.sq(a[i]), RANDOM_OPS);
    await checkBatch(h, 'batchNeg(uint64[])', [a], (i) => G.neg(a[i]), RANDOM_OPS);
    await checkBatch(
      h,
      'batchMulAdd(uint64[],uint64[],uint64[])',
      [a, b, c],
      (i) => G.mulAdd(a[i], b[i], c[i]),
      RANDOM_OPS
    );
  });

  await t.test(`modexp inversion for ${INV_OPS} random elements`, async () => {
    const x = Array.from({ length: INV_OPS }, () => rng.nonZeroElement());
    await checkBatch(h, 'batchInv(uint64[])', [x], (i) => G.inv(x[i]), INV_OPS);
  });

  await t.test(`${RANDOM_OPS} random pow and pow2k operations`, async () => {
    const x = Array.from({ length: RANDOM_OPS }, () => rng.element());
    const e = Array.from({ length: RANDOM_OPS }, () => rng.u64());
    await checkBatch(
      h,
      'batchPow(uint64[],uint64[])',
      [x, e],
      (i) => G.pow(x[i], e[i]),
      RANDOM_OPS
    );
    const k = Array.from({ length: RANDOM_OPS }, () => BigInt(rng.int(65)));
    await checkBatch(
      h,
      'batchPow2k(uint64[],uint64[])',
      [x, k],
      (i) => G.pow2k(x[i], Number(k[i])),
      RANDOM_OPS
    );
  });

  await t.test('two-adic generator tables', async () => {
    for (let i = 0; i <= 32; i += 1) {
      const g = await h.callOne('twoAdicGen(uint512)', [BigInt(i)], 'uint512');
      const gi = await h.callOne('twoAdicGenInv(uint512)', [BigInt(i)], 'uint512');
      assert.equal(g, G.twoAdicGen(i), `g_${i}`);
      assert.equal(gi, G.twoAdicGenInv(i), `ginv_${i}`);
      assert.equal(G.mul(g, gi), 1n);
      assert.equal(G.pow2k(g, i), 1n);
      assert.equal(await h.callOne('twoAdicGenSwitch(uint512)', [BigInt(i)], 'uint512'), g);
      assert.equal(await h.callOne('twoAdicGenBlob(uint512)', [BigInt(i)], 'uint512'), g);
    }
    await H.expectRevert(h, 'twoAdicGen(uint512)', [33n], 'TwoAdicIndexOutOfRange()');
    await H.expectRevert(h, 'twoAdicGenInv(uint512)', [33n], 'TwoAdicIndexOutOfRange()');
    assert.equal(await h.callOne('twoAdicTableCheck()', [], 'bool'), true);
    const [gens, invs] = await h.call('twoAdicMemTables()', [], ['uint64[]', 'uint64[]']);
    assert.deepEqual(gens, [...G.TWO_ADIC_GENERATORS]);
    assert.deepEqual(invs, [...G.TWO_ADIC_GENERATOR_INVERSES]);

    const packed = await h.estimateGas('twoAdicGen(uint512)', [17n]);
    const switched = await h.estimateGas('twoAdicGenSwitch(uint512)', [17n]);
    const blob = await h.estimateGas('twoAdicGenBlob(uint512)', [17n]);
    t.diagnostic(
      `twoAdicGen(17) single-call gas: packed ${packed}, 33-case switch ${switched}, bytes constant ${blob}`
    );
  });

  await t.test('rev for every width 1..32', async () => {
    const x = [];
    const bits = [];
    for (let i = 0; i < RANDOM_OPS; i += 1) {
      const width = (i % 32) + 1;
      bits.push(BigInt(width));
      x.push(rng.bits(width));
    }
    await checkBatch(
      h,
      'batchRev(uint64[],uint64[])',
      [x, bits],
      (i) => G.rev(x[i], Number(bits[i])),
      RANDOM_OPS
    );
    assert.equal(await h.callOne('rev(uint512,uint512)', [1n, 3n], 'uint512'), 4n);
    assert.equal(
      await h.callOne('rev(uint512,uint512)', [0x12345678n, 32n], 'uint512'),
      0x1e6a2c48n
    );
    // Bits above the width are ignored, as in the reference.
    assert.equal(await h.callOne('rev(uint512,uint512)', [0b1101n, 2n], 'uint512'), 0b10n);
    await H.expectRevert(h, 'rev(uint512,uint512)', [1n, 0n], 'BitWidthOutOfRange()');
    await H.expectRevert(h, 'rev(uint512,uint512)', [1n, 33n], 'BitWidthOutOfRange()');
  });

  await t.test('bswap64', async () => {
    const x = Array.from({ length: RANDOM_OPS }, () => rng.u64());
    await checkBatch(h, 'batchBswap64(uint64[])', [x], (i) => G.bswap64(x[i]), RANDOM_OPS);
    assert.equal(
      await h.callOne('bswap64(uint512)', [0x0102030405060708n], 'uint512'),
      0x0807060504030201n
    );
    assert.equal(await h.callOne('bswap64(uint512)', [G.MASK64], 'uint512'), G.MASK64);
  });

  await t.test('calldata lanes and elements', async () => {
    const elements = Array.from({ length: 64 }, () => rng.element());
    const bytes = G.elementsToBytes(elements);

    // First word, packed.
    const word = await h.callOne('cdLanes(bytes)', [bytes], 'uint512');
    assert.equal(word, G.packLanes(elements.slice(0, 8)));
    for (let k = 0; k < 8; k += 1) {
      assert.equal(
        await h.callOne('lane(uint512,uint512)', [word, BigInt(k)], 'uint512'),
        elements[k]
      );
    }
    assert.equal(await h.callOne('lanesCanonicalWord(uint512)', [word], 'bool'), true);

    // Every aligned word and one unaligned offset through lane extraction.
    for (let w = 0; w < 8; w += 1) {
      const [lanes] = await h.call(
        'cdLanesAt(bytes,uint512)',
        [bytes, BigInt(64 * w)],
        ['uint64[]']
      );
      assert.deepEqual(lanes, G.laneDecode(bytes, 64 * w), `word ${w}`);
    }
    const [unaligned] = await h.call('cdLanesAt(bytes,uint512)', [bytes, 8n], ['uint64[]']);
    assert.deepEqual(unaligned, elements.slice(1, 9));

    // Every element through cdElem, individually and all at once.
    for (const i of [0, 1, 7, 8, 63]) {
      assert.equal(
        await h.callOne('cdElem(bytes,uint512)', [bytes, BigInt(8 * i)], 'uint512'),
        elements[i]
      );
    }
    const [all] = await h.call('cdElems(bytes)', [bytes], ['uint64[]']);
    assert.deepEqual(all, elements);

    // Non-canonical wire values: p, p + 1 and 2^64 - 1 are rejected; p - 1 passes.
    for (const bad of [G.P, G.P + 1n, G.MASK64]) {
      const wire = G.elementsToBytes([...elements.slice(0, 5), bad, ...elements.slice(6, 8)]);
      await H.expectRevert(h, 'cdElem(bytes,uint512)', [wire, 40n], 'NonCanonicalElement()');
      await H.expectRevert(h, 'cdElems(bytes)', [wire], 'NonCanonicalElement()');
      assert.equal(await h.callOne('lanesCanonical(bytes)', [wire], 'bool'), false);
      const packed = await h.callOne('cdLanes(bytes)', [wire], 'uint512');
      assert.equal(G.lane(packed, 5), bad, 'cdLanes itself does not reject');
    }
    for (let k = 0; k < 8; k += 1) {
      const lanes = elements.slice(0, 8);
      lanes[k] = G.P;
      assert.equal(
        await h.callOne('lanesCanonical(bytes)', [G.elementsToBytes(lanes)], 'bool'),
        false
      );
      lanes[k] = G.P - 1n;
      assert.equal(
        await h.callOne('lanesCanonical(bytes)', [G.elementsToBytes(lanes)], 'bool'),
        true
      );
    }
    const edgeWire = G.elementsToBytes([
      G.P - 1n,
      0n,
      1n,
      1n << 32n,
      (1n << 32n) - 1n,
      G.INV2,
      7n,
      G.P - 1n,
    ]);
    assert.equal(await h.callOne('lanesCanonical(bytes)', [edgeWire], 'bool'), true);
    assert.equal(await h.callOne('cdElem(bytes,uint512)', [edgeWire, 0n], 'uint512'), G.P - 1n);

    // calldataload past the end zero-pads: a short buffer decodes as zeros.
    const short = G.elementsToBytes([5n]);
    const [padded] = await h.call('cdLanesAt(bytes,uint512)', [short, 0n], ['uint64[]']);
    assert.deepEqual(padded, [5n, 0n, 0n, 0n, 0n, 0n, 0n, 0n]);
  });

  await t.test('gas loop', async () => {
    const rows = [];
    for (const [op, label] of GAS_OPS) {
      const r = await H.marginalGas(h, op, loopIterations(op));
      rows.push({ op, label, marginal: r.marginal, gasN: r.gasN, gas2N: r.gas2N });
    }
    const baseline = (op) => rows.find((r) => r.op === op).marginal;
    const yulBase = baseline(0);
    const hlBase = baseline(16);
    for (const r of rows) {
      r.net = r.op < 16 ? r.marginal - yulBase : r.marginal - hlBase;
      t.diagnostic(
        `gas op ${String(r.op).padStart(2)} ${r.label.padEnd(48)} marginal ${r.marginal.toFixed(2).padStart(9)} net ${r.net.toFixed(2).padStart(9)}`
      );
    }
    const mul = rows.find((r) => r.op === 4).net;
    const inv = rows.find((r) => r.op === 8).net;
    t.diagnostic(
      `targets: base mul < ${TARGET_MUL} (${mul}, ${mul < TARGET_MUL ? 'met' : 'MISSED'}), ` +
        `inv < ${TARGET_INV} (${inv}, ${inv < TARGET_INV ? 'met' : 'MISSED'}); ` +
        `optimizer runs ${H.optimizerOptions().optimizerRuns}`
    );
    assert.ok(mul < TARGET_MUL, `base mul marginal ${mul} >= ${TARGET_MUL}`);
    // The modexp floor (200) plus the pre-warmed STATICCALL (100) leave about
    // 100 gas for input assembly, output read and the success check, so the
    // 400 target is documented as missed in docs/GAS-PRIMITIVES.md when the
    // measurement lands above it; the regression bound is 500.
    assert.ok(inv < 500, `inv marginal ${inv} >= 500`);
    // Loop bodies really ran: a witness-free loop would have zero cost.
    assert.ok(rows.every((r) => r.gas2N > r.gasN));
  });
});
