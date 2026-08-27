// FriVerifier.hyp, ProofLayout.hyp and the StarkVerifierCore transcript
// against every vector on a live QRVM (milestone M5).
//
// Deploys contracts/hyperion/test/FriHarness.hyp once and, for every valid
// vector under test/vectors/, compares with the vector file (the byte-exact
// record of the upstream Plonky3 verifier, see docs/PROTOCOL.md):
//   - the decoded layout, proofId and the canonical scan;
//   - every transcript challenge (alpha, zeta, zeta_next, fri_alpha, betas,
//     query indices);
//   - every reduced opening with its intermediates (x, both denominators,
//     both inverses, ro);
//   - fold_row on rows of every arity the vectors exercise (2, 4, 8, 16);
//   - every fold chain step (folded index, folded value, round leaf digest)
//     and every final polynomial check;
//   - the whole FRI flow (verifyFri) and the whole verifier flow, timed per
//     phase.
// The layout and FRI mutation vectors must revert with the expected custom
// error through the same production functions. Gas per (query, round) is
// grouped by arity and reported as diagnostics. Skips without STARK_RPC_URL.
//
// STARK_FRI_VECTORS=fib_c3_n10,fib_c1_n12 restricts the valid vectors for a
// quick run; the mutation vectors always run.

const assert = require('node:assert/strict');
const test = require('node:test');

const H = require('../lib/harness');
const V = require('../lib/vectors');

const rpcUrl = process.env.STARK_RPC_URL;
const skip = rpcUrl ? false : 'set STARK_RPC_URL to run against a node';

const SIG = {
  layout: 'layout(bytes,uint512[])',
  proofId: 'proofId(bytes,uint512[])',
  programIdentifier: 'programIdentifier(uint512[])',
  checkCanonical: 'checkCanonical(bytes,uint512[])',
  challenges: 'challenges(bytes,bytes,uint512[])',
  openInputs: 'openInputs(bytes,uint512[])',
  foldRow: 'foldRow(uint512[])',
  foldChains: 'foldChains(bytes,uint512[])',
  verifyFri: 'verifyFri(bytes,bytes,uint512[])',
  verifyTimed: 'verifyTimed(bytes,bytes,uint512[])',
};

const LAYOUT_ERRORS = ['BadVersion', 'BadHeader', 'BadLength'];
const FRI_ERRORS = [
  'PowFailed',
  'DuplicateOpeningMismatch',
  'SiblingCountMismatch',
  'MerkleRootMismatch',
  'FinalPolyMismatch',
];
const PHASES_FRI = [
  'prepare',
  'absorbInstance',
  'friTranscript',
  'inputBlocks',
  'reducedOpenings',
  'foldChains',
  'roundBlocks',
];
const PHASES_FULL = [
  'prepare',
  'absorbInstance',
  'checkConstraints',
  'friTranscript',
  'inputBlocks',
  'reducedOpenings',
  'foldChains',
  'roundBlocks',
];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function paramsArgs(cfg) {
  return [
    cfg.logBlowup,
    cfg.logFinalPolyLen,
    cfg.maxLogArity,
    cfg.numQueries,
    cfg.commitPowBits,
    cfg.queryPowBits,
  ].map(BigInt);
}

function big(values) {
  return values.map((x) => BigInt(x));
}

function efBig(pair) {
  return [BigInt(pair[0]), BigInt(pair[1])];
}

function digestBig(hex) {
  return BigInt(hex);
}

function loadValid() {
  const only = process.env.STARK_FRI_VECTORS
    ? new Set(process.env.STARK_FRI_VECTORS.split(',').map((s) => s.trim()))
    : null;
  return V.loadValidVectors().filter((e) => !only || only.has(e.baseName));
}

// Layout array returned by the harness, in the vector's `layout` shape.
function layoutFromWords(words, cfg) {
  const n = Number(words[0]);
  const numRounds = Number(words[2]);
  const q = cfg.numQueries;
  const rounds = [];
  for (let r = 0; r < numRounds; r += 1) {
    const logArity = Number(words[10 + 4 * r]);
    const siblingValuesOffset = Number(words[11 + 4 * r]);
    const sibCount = Number(words[12 + 4 * r]);
    const siblingsOffset = Number(words[13 + 4 * r]);
    const siblingValuesLen = q * (2 ** logArity - 1) * 16;
    rounds.push({
      logArity,
      siblingValuesOffset,
      siblingValuesLen,
      sibCountOffset: siblingValuesOffset + siblingValuesLen,
      siblingsOffset,
      sibCount,
      end: siblingsOffset + 32 * sibCount,
    });
  }
  const block = (name, rowsOffset, sibCount, siblingsOffset) => ({
    name,
    rowsOffset,
    rowsLen: q * 16,
    sibCountOffset: rowsOffset + q * 16,
    siblingsOffset,
    sibCount,
    end: siblingsOffset + 32 * sibCount,
  });
  return {
    degreeBits: n,
    logHeight: Number(words[1]),
    logArities: rounds.map((r) => r.logArity),
    numQueries: q,
    pEnd: Number(words[3]),
    blocks: [
      block('trace', Number(words[4]), Number(words[5]), Number(words[6])),
      block('quotient', Number(words[7]), Number(words[8]), Number(words[9])),
    ],
    rounds,
  };
}

function revertName(error, names) {
  const payload = H.revertData(error);
  if (payload === null) throw error;
  for (const name of names) {
    if (payload.toLowerCase().startsWith(H.errorSelector(`${name}()`).toLowerCase())) return name;
  }
  throw new Error(`unexpected revert data ${payload.slice(0, 10)}: ${error.message}`);
}

async function revertOf(h, signature, values, names) {
  try {
    await h.callRaw(signature, values);
  } catch (error) {
    return revertName(error, names);
  }
  return null;
}

function mean(values) {
  return values.reduce((a, b) => a + b, 0) / values.length;
}

// ---------------------------------------------------------------------------
// Suite
// ---------------------------------------------------------------------------

test('FRI harness', { skip, timeout: 3600000 }, async (t) => {
  const ctx = await H.connect();
  const h = await H.deployHarness(ctx, 'test/FriHarness.hyp');
  t.diagnostic(`FriHarness at ${h.address} (chain ${ctx.chainId})`);

  const vectors = loadValid();
  assert.ok(vectors.length > 0, 'no valid vectors under test/vectors/');
  const mutations = V.loadMutationVectors();
  const gasByArity = new Map();
  const gasFinal = [];
  const proofGas = [];

  await t.test('layout, proofId and canonical scan match every vector', async () => {
    for (const { baseName, vector } of vectors) {
      const args = paramsArgs(vector.config);
      const [words] = await h.call(SIG.layout, [vector.proofHex, args], ['uint512[]']);
      const got = layoutFromWords(words, vector.config);
      const expected = {
        degreeBits: vector.layout.degreeBits,
        logHeight: vector.degreeBits + vector.config.logBlowup,
        logArities: vector.layout.logArities,
        numQueries: vector.layout.numQueries,
        pEnd: vector.layout.pEnd,
        blocks: vector.layout.blocks,
        rounds: vector.layout.rounds,
      };
      const d = V.firstDifference(got, expected);
      assert.equal(d, null, `${baseName}: layout ${d}`);
      assert.equal(got.rounds[got.rounds.length - 1]?.end ?? got.blocks[1].end, vector.proofLength);
      assert.equal(
        await h.callOne(SIG.proofId, [vector.proofHex, args], 'bytes32'),
        vector.proofId,
        `${baseName}: proofId`
      );
      assert.equal(await h.callOne(SIG.checkCanonical, [vector.proofHex, args], 'bool'), true);
    }
    // Layout mutations through the parser, the non-canonical one through the scan.
    let checked = 0;
    for (const { baseName, vector } of mutations) {
      const args = paramsArgs(vector.config);
      const error = vector.expected.error;
      if (LAYOUT_ERRORS.includes(error)) {
        assert.equal(
          await revertOf(h, SIG.layout, [vector.proofHex, args], LAYOUT_ERRORS),
          error,
          `${baseName}: layout error`
        );
        checked += 1;
      } else if (error === 'NonCanonicalElement') {
        // The layout itself parses; the scan rejects.
        await h.call(SIG.layout, [vector.proofHex, args], ['uint512[]']);
        await H.expectRevert(
          h,
          SIG.checkCanonical,
          [vector.proofHex, args],
          'NonCanonicalElement()'
        );
        checked += 1;
      }
    }
    assert.ok(checked >= 4, 'layout mutation vectors are missing');
    t.diagnostic(`layout: ${vectors.length} valid vectors, ${checked} layout mutations`);
  });

  await t.test('transcript challenges match every vector', async () => {
    for (const { baseName, vector } of vectors) {
      // Transcript step 0: the identifier the core observes for these parameters.
      assert.equal(
        await h.callOne(SIG.programIdentifier, [paramsArgs(vector.config)], 'bytes32'),
        vector.programIdentifier,
        `${baseName}: programIdentifier`
      );
      const [out] = await h.call(
        SIG.challenges,
        [vector.proofHex, vector.publicValuesHex, paramsArgs(vector.config)],
        ['uint512[]']
      );
      const c = vector.challenges;
      const numRounds = c.betas.length;
      const got = {
        alpha: [out[0], out[1]],
        zeta: [out[2], out[3]],
        zetaNext: [out[4], out[5]],
        friAlpha: [out[6], out[7]],
        betas: c.betas.map((_, r) => [out[8 + 2 * r], out[9 + 2 * r]]),
        indices: c.indices.map((_, i) => out[8 + 2 * numRounds + i]),
      };
      const expected = {
        alpha: efBig(c.alpha),
        zeta: efBig(c.zeta),
        zetaNext: efBig(c.zetaNext),
        friAlpha: efBig(c.friAlpha),
        betas: c.betas.map(efBig),
        indices: big(c.indices),
      };
      const d = V.firstDifference(got, expected);
      assert.equal(d, null, `${baseName}: challenges ${d}`);
    }
  });

  await t.test('reduced openings match openInputs', async () => {
    for (const { baseName, vector } of vectors) {
      const c = vector.challenges;
      const args = [
        ...paramsArgs(vector.config),
        ...efBig(c.zeta),
        ...efBig(c.zetaNext),
        ...efBig(c.friAlpha),
        ...big(c.indices),
      ];
      const [out] = await h.call(SIG.openInputs, [vector.proofHex, args], ['uint512[]']);
      assert.equal(out.length, 11 * c.indices.length);
      vector.openInputs.forEach((o, qi) => {
        const w = out.slice(11 * qi, 11 * qi + 11);
        const got = {
          x: w[0],
          denomZeta: [w[1], w[2]],
          denomZetaNext: [w[3], w[4]],
          invDenomZeta: [w[5], w[6]],
          invDenomZetaNext: [w[7], w[8]],
          reducedOpening: [w[9], w[10]],
        };
        const expected = {
          x: BigInt(o.x),
          denomZeta: efBig(o.denomZeta),
          denomZetaNext: efBig(o.denomZetaNext),
          invDenomZeta: efBig(o.invDenomZeta),
          invDenomZetaNext: efBig(o.invDenomZetaNext),
          reducedOpening: efBig(o.reducedOpening),
        };
        const d = V.firstDifference(got, expected);
        assert.equal(d, null, `${baseName}: query ${qi} ${d}`);
      });
    }
  });

  await t.test('foldRow reproduces fold_row for every arity', async () => {
    const arities = new Map();
    for (const { baseName, vector } of vectors) {
      const numRounds = vector.challenges.betas.length;
      const heights = [vector.degreeBits + vector.config.logBlowup];
      for (const k of vector.layout.logArities) heights.push(heights[heights.length - 1] - k);
      // Every round of the first three queries plus the last query.
      const queries = [0, 1, 2, vector.challenges.indices.length - 1];
      for (const qi of queries) {
        for (let r = 0; r < numRounds; r += 1) {
          const f = vector.fold[qi * numRounds + r];
          assert.equal(f.query, qi);
          assert.equal(f.round, r);
          const beta = efBig(vector.challenges.betas[r]);
          const args = [
            BigInt(f.foldedIndex),
            BigInt(heights[r + 1]),
            BigInt(f.logArity),
            ...beta,
            ...f.row.flatMap(efBig),
          ];
          const [c0, c1] = await h.call(SIG.foldRow, [args], ['uint512', 'uint512']);
          assert.deepEqual([c0, c1], efBig(f.folded), `${baseName}: query ${qi} round ${r}`);
          assert.deepEqual([c0, c1], efBig(f.foldedBarycentric));
          arities.set(f.logArity, (arities.get(f.logArity) || 0) + 1);
        }
      }
    }
    const seen = [...arities.keys()].sort((a, b) => a - b);
    t.diagnostic(
      `foldRow checked log arities ${seen.join(', ')} (${[...arities.values()].reduce((a, b) => a + b, 0)} rows)`
    );
    for (const k of [1, 2, 3, 4]) {
      assert.ok(arities.has(k), `no vector exercises log arity ${k}; run the a${k} sweep vectors`);
    }
  });

  await t.test('fold chains, round leaves and final polynomial match', async () => {
    for (const { baseName, vector } of vectors) {
      const c = vector.challenges;
      const numRounds = c.betas.length;
      const q = c.indices.length;
      const args = [
        ...paramsArgs(vector.config),
        ...c.betas.flatMap(efBig),
        ...big(c.indices),
        ...vector.openInputs.flatMap((o) => efBig(o.reducedOpening)),
      ];
      const [out] = await h.call(SIG.foldChains, [vector.proofHex, args], ['uint512[]']);
      assert.equal(out.length, q * (5 * numRounds + 5));
      for (let qi = 0; qi < q; qi += 1) {
        let o = qi * (5 * numRounds + 5);
        for (let r = 0; r < numRounds; r += 1) {
          const f = vector.fold[qi * numRounds + r];
          const got = {
            foldedIndex: out[o],
            folded: [out[o + 1], out[o + 2]],
            leafDigest: out[o + 3],
          };
          const expected = {
            foldedIndex: BigInt(f.foldedIndex),
            folded: efBig(f.folded),
            leafDigest: digestBig(f.leafDigest),
          };
          const d = V.firstDifference(got, expected);
          assert.equal(d, null, `${baseName}: query ${qi} round ${r} ${d}`);
          const key = f.logArity;
          if (!gasByArity.has(key)) gasByArity.set(key, []);
          gasByArity.get(key).push(Number(out[o + 4]));
          o += 5;
        }
        const check = vector.finalPolyChecks[qi];
        const got = { index: out[o], value: [out[o + 1], out[o + 2]], ok: out[o + 3] };
        const expected = { index: BigInt(check.index), value: efBig(check.value), ok: 1n };
        const d = V.firstDifference(got, expected);
        assert.equal(d, null, `${baseName}: query ${qi} final ${d}`);
        gasFinal.push(Number(out[o + 4]));
      }
    }
    const rows = [...gasByArity.entries()].sort((a, b) => a[0] - b[0]);
    for (const [k, samples] of rows) {
      t.diagnostic(
        `foldRound gas at log arity ${k}: mean ${mean(samples).toFixed(0)}, ` +
          `min ${Math.min(...samples)}, max ${Math.max(...samples)} (${samples.length} rounds)`
      );
    }
    t.diagnostic(
      `finalCheck gas: mean ${mean(gasFinal).toFixed(0)}, min ${Math.min(...gasFinal)}, max ${Math.max(...gasFinal)}`
    );
  });

  await t.test('verifyFri accepts every valid vector and reports phase gas', async () => {
    for (const { baseName, vector } of vectors) {
      const args = paramsArgs(vector.config);
      const [friGas] = await h.call(
        SIG.verifyFri,
        [vector.proofHex, vector.publicValuesHex, args],
        ['uint512[]']
      );
      const [fullGas] = await h.call(
        SIG.verifyTimed,
        [vector.proofHex, vector.publicValuesHex, args],
        ['uint512[]']
      );
      assert.equal(friGas.length, 8);
      assert.equal(fullGas.length, 8);
      const full = Object.fromEntries(PHASES_FULL.map((p, i) => [p, Number(fullGas[i])]));
      const fri = Object.fromEntries(PHASES_FRI.map((p, i) => [p, Number(friGas[i])]));
      // The FRI-only flow and the full flow agree on the shared phases within
      // the noise of memory expansion (the full flow allocates 192 more bytes).
      for (const p of PHASES_FRI) {
        assert.ok(
          Math.abs(full[p] - fri[p]) < 2000,
          `${baseName}: phase ${p} differs (${full[p]} vs ${fri[p]})`
        );
      }
      const total = PHASES_FULL.reduce((s, p) => s + full[p], 0);
      proofGas.push({ vector: baseName, total, phases: full });
    }
    for (const row of proofGas) {
      const parts = PHASES_FULL.map((p) => `${p} ${row.phases[p]}`).join(', ');
      t.diagnostic(`${row.vector}: ${row.total} gas in phases (${parts})`);
    }
  });

  await t.test('FRI mutation vectors revert with the expected error', async () => {
    let checked = 0;
    const seen = new Set();
    for (const { baseName, vector } of mutations) {
      const error = vector.expected.error;
      if (!FRI_ERRORS.includes(error)) continue;
      const got = await revertOf(
        h,
        SIG.verifyFri,
        [vector.proofHex, vector.publicValuesHex, paramsArgs(vector.config)],
        FRI_ERRORS
      );
      assert.equal(got, error, `${baseName}: verifyFri error`);
      seen.add(vector.expected.mutation);
      checked += 1;
    }
    assert.ok(checked > 0, 'no FRI mutation vectors under test/vectors/mutations/');
    for (const required of [
      'flip_final_poly0',
      'flip_fri_commit0',
      'zero_query_pow_witness',
      'flip_sibling_value',
      'flip_input_sibling',
      'flip_round_sibling',
      'sib_count_plus_one',
      'sib_count_minus_one',
      'swap_query_rows',
    ]) {
      assert.ok(seen.has(required), `mutation ${required} is missing`);
    }
    t.diagnostic(`${checked} FRI mutation vectors: ${[...seen].sort().join(', ')}`);
  });
});
