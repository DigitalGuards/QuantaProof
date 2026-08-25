// StarkVerifier.hyp on a live QRVM (milestone M6): every preset the vectors
// exercise, every valid and mutated vector, and the gas of the deployable
// path through StarkVerifierGasMeter.
//
// The deployable verifier binds its preset through six compile-time
// constants at the top of contracts/hyperion/StarkVerifier.hyp. This suite
// groups the vectors by their `config`, compiles the file once per distinct
// preset with the constants substituted (the committed file stays the c3
// deployment) and deploys one verifier per preset. `verify` must return true
// for every valid vector and revert with the expected custom error for every
// mutation; PARAMS() must echo the preset.
//
// Gas: for the cells listed in GAS_VECTORS a StarkVerifierGasMeter is
// deployed in front of the preset's verifier and one `verifyAndLog`
// transaction is sent per vector, recording the node estimate, the receipt
// gasUsed, the inner STATICCALL gas from the Verified event and the calldata
// size. The rows are reported as diagnostics and written to
// build/hyperion/gas-stark-<runs|viaIr>.json (ignored; `npm run compile`
// clears that directory) so docs/VERIFIER.md can be assembled from several
// optimizer settings (HYPERION_OPTIMIZE_RUNS, HYPERION_VIA_IR, read by
// test/lib/harness.js). Skips without STARK_RPC_URL.
//
// STARK_SKIP_MUTATIONS=1 skips the accept/reject matrix (gas rows only);
// STARK_STARK_VECTORS=fib_c3_n10,... restricts the valid vectors.

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const { collectSources, compileSources } = require('../../scripts/hypc');
const { loadVector, runVerifyProof } = require('../../scripts/verify-proof');
const abi = require('../../scripts/lib/abi64');
const H = require('../lib/harness');
const V = require('../lib/vectors');

const rpcUrl = process.env.STARK_RPC_URL;
const skip = rpcUrl ? false : 'set STARK_RPC_URL to run against a node';

const VERIFIER_FILE = 'StarkVerifier.hyp';
const GAS_METER_FILE = 'StarkVerifierGasMeter.hyp';
const SIG_VERIFY = 'verify(bytes,bytes)';
const SIG_PARAMS = 'PARAMS()';

const PRESET_KEYS = [
  'logBlowup',
  'logFinalPolyLen',
  'maxLogArity',
  'numQueries',
  'commitPowBits',
  'queryPowBits',
];
const PRESET_CONSTANTS = {
  logBlowup: 'LOG_BLOWUP',
  logFinalPolyLen: 'LOG_FINAL_POLY_LEN',
  maxLogArity: 'MAX_LOG_ARITY',
  numQueries: 'NUM_QUERIES',
  commitPowBits: 'COMMIT_POW_BITS',
  queryPowBits: 'QUERY_POW_BITS',
};

// Cells of the gas table: the three presets at both tracked sizes and the
// arity / final-polynomial sweep at n = 12.
const GAS_VECTORS = [
  'fib_c1_n10',
  'fib_c1_n12',
  'fib_c2_n10',
  'fib_c2_n12',
  'fib_c3_n10',
  'fib_c3_n12',
  'fib_c1-binary_n12',
  'fib_c2-binary_n12',
  'fib_c3-binary_n12',
  'fib_c3-a1-f0_n12',
  'fib_c3-a1-f5_n12',
  'fib_c3-a2-f0_n12',
  'fib_c3-a2-f3_n12',
  'fib_c3-a2-f5_n12',
  'fib_c3-a3-f0_n12',
  'fib_c3-a3-f5_n12',
  'fib_c3-a4-f0_n12',
  'fib_c3-a4-f3_n12',
  'fib_c3-a4-f5_n12',
];

// ---------------------------------------------------------------------------
// Preset substitution
// ---------------------------------------------------------------------------

function presetKey(cfg) {
  return PRESET_KEYS.map((k) => cfg[k]).join('/');
}

// StarkVerifier.hyp with its six preset constants replaced by `cfg`.
function presetSource(source, cfg) {
  let out = source;
  for (const key of PRESET_KEYS) {
    const name = PRESET_CONSTANTS[key];
    const re = new RegExp(`(uint512 internal constant ${name} = )\\d+;`);
    if (!re.test(out)) throw new Error(`constant ${name} not found in ${VERIFIER_FILE}`);
    out = out.replace(re, `$1${cfg[key]};`);
  }
  return out;
}

function compilePreset(sources, cfg) {
  const patched = {
    ...sources,
    [VERIFIER_FILE]: { content: presetSource(sources[VERIFIER_FILE].content, cfg) },
  };
  const artifacts = compileSources(patched, { ...H.optimizerOptions(), entries: [VERIFIER_FILE] });
  return artifacts.StarkVerifier;
}

function errorNameOf(error) {
  const payload = H.revertData(error);
  if (payload === null) throw error;
  for (const name of V.ERROR_NAMES) {
    if (payload.toLowerCase().startsWith(H.errorSelector(`${name}()`).toLowerCase())) return name;
  }
  throw new Error(`unexpected revert data ${payload.slice(0, 10)}: ${error.message}`);
}

async function outcomeOf(verifier, vector) {
  try {
    const [ok] = await verifier.call(
      SIG_VERIFY,
      [vector.proofHex, vector.publicValuesHex],
      ['bool']
    );
    return ok ? 'true' : 'false';
  } catch (error) {
    return errorNameOf(error);
  }
}

function settingsLabel() {
  const o = H.optimizerOptions();
  return o.viaIr ? `viaIr-runs${o.optimizerRuns}` : `runs${o.optimizerRuns}`;
}

// ---------------------------------------------------------------------------
// Suite
// ---------------------------------------------------------------------------

test('StarkVerifier', { skip, timeout: 3600000 }, async (t) => {
  const ctx = await H.connect();
  const sources = collectSources();
  const only = process.env.STARK_STARK_VECTORS
    ? new Set(process.env.STARK_STARK_VECTORS.split(',').map((s) => s.trim()))
    : null;
  const valid = V.loadValidVectors().filter((e) => !only || only.has(e.baseName));
  const mutations = V.loadMutationVectors();
  assert.ok(valid.length > 0, 'no valid vectors under test/vectors/');

  // Group every vector by preset; one deployment per preset.
  const presets = new Map();
  for (const entry of valid.concat(mutations)) {
    const key = presetKey(entry.vector.config);
    if (!presets.has(key)) presets.set(key, { cfg: entry.vector.config, entries: [] });
    presets.get(key).entries.push(entry);
  }
  const deployed = new Map();
  async function verifierFor(cfg) {
    const key = presetKey(cfg);
    if (!deployed.has(key)) {
      const artifact = compilePreset(sources, cfg);
      const verifier = await H.deployArtifact(ctx, artifact);
      verifier.runtimeBytes = (artifact.deployedBytecode.length - 2) / 2;
      deployed.set(key, verifier);
    }
    return deployed.get(key);
  }

  t.diagnostic(
    `${valid.length} valid + ${mutations.length} mutated vectors over ${presets.size} presets, ` +
      `optimizer ${settingsLabel()}`
  );

  if (process.env.STARK_SKIP_MUTATIONS !== '1') {
    await t.test('PARAMS() echoes every preset', async () => {
      for (const { cfg } of presets.values()) {
        const verifier = await verifierFor(cfg);
        const params = await verifier.call(SIG_PARAMS, [], Array(6).fill('uint512'));
        assert.deepEqual(
          params,
          [
            cfg.logBlowup,
            cfg.numQueries,
            cfg.queryPowBits,
            cfg.commitPowBits,
            cfg.maxLogArity,
            cfg.logFinalPolyLen,
          ].map(BigInt),
          `PARAMS of preset ${presetKey(cfg)}`
        );
      }
      const sizes = [...deployed.values()].map((v) => v.runtimeBytes);
      t.diagnostic(
        `${deployed.size} verifiers deployed, runtime ${Math.min(...sizes)}..${Math.max(...sizes)} bytes`
      );
    });

    await t.test('verify returns true for every valid vector', async () => {
      for (const { baseName, vector } of valid) {
        const verifier = await verifierFor(vector.config);
        assert.equal(await outcomeOf(verifier, vector), 'true', `${baseName}: verify`);
      }
      t.diagnostic(`${valid.length} valid vectors accepted`);
    });

    await t.test('verify reverts with the expected error for every mutation', async () => {
      const seen = new Map();
      for (const { baseName, vector } of mutations) {
        const verifier = await verifierFor(vector.config);
        const expected = vector.expected.error;
        assert.ok(V.ERROR_NAMES.includes(expected), `${baseName}: unknown error ${expected}`);
        assert.equal(await outcomeOf(verifier, vector), expected, `${baseName}: error`);
        seen.set(expected, (seen.get(expected) || 0) + 1);
      }
      const summary = [...seen.entries()]
        .sort((a, b) => a[0].localeCompare(b[0]))
        .map(([name, count]) => `${name} x${count}`)
        .join(', ');
      t.diagnostic(`${mutations.length} mutations rejected: ${summary}`);
      // Public values are validated after the proof: wrong length and a
      // non-canonical value on an otherwise valid proof.
      const { vector } = valid[0];
      const verifier = await verifierFor(vector.config);
      await H.expectRevert(
        verifier,
        SIG_VERIFY,
        [vector.proofHex, vector.publicValuesHex.slice(0, -2)],
        'BadLength()'
      );
      const nonCanonical = `${vector.publicValuesHex.slice(0, -16)}ffffffffffffffff`;
      await H.expectRevert(
        verifier,
        SIG_VERIFY,
        [vector.proofHex, nonCanonical],
        'NonCanonicalElement()'
      );
    });
  }

  await t.test('gas of the deployable path through StarkVerifierGasMeter', async () => {
    const meterArtifact = compileSources(sources, {
      ...H.optimizerOptions(),
      entries: [GAS_METER_FILE],
    }).StarkVerifierGasMeter;
    const meters = new Map();
    const rows = [];
    for (const name of GAS_VECTORS) {
      const file = path.join(V.VECTORS_DIR, `${name}.json`);
      if (!fs.existsSync(file)) {
        t.diagnostic(`${name}: vector missing, skipped`);
        continue;
      }
      const vector = V.loadVector(file);
      if (only && !only.has(name)) continue;
      const verifier = await verifierFor(vector.config);
      const key = presetKey(vector.config);
      if (!meters.has(key)) {
        const constructorArgs = abi.addressHex(verifier.address);
        const meter = await H.deployArtifact(ctx, {
          ...meterArtifact,
          bytecode: meterArtifact.bytecode + constructorArgs,
        });
        meters.set(key, meter);
      }
      const meter = meters.get(key);
      const result = await runVerifyProof({
        rpc: ctx.rpc,
        sender: ctx.sender,
        config: {
          contracts: { StarkVerifier: verifier.address, StarkVerifierGasMeter: meter.address },
        },
        vector: loadVector(file),
      });
      assert.equal(result.call.ok, true, `${name}: verify call`);
      assert.equal(result.tx.status, 1, `${name}: verifyAndLog status`);
      assert.ok(result.tx.verified, `${name}: Verified event`);
      assert.equal(result.tx.verified.ok, true, `${name}: Verified.ok`);
      const directEstimate = await verifier.estimateGas(SIG_VERIFY, [
        vector.proofHex,
        vector.publicValuesHex,
      ]);
      rows.push({
        vector: name,
        preset: key,
        degreeBits: vector.degreeBits,
        proofBytes: result.proofBytes,
        runtimeBytes: verifier.runtimeBytes,
        verifyEstimate: Number(directEstimate),
        meterEstimate: Number(result.tx.estimateGas),
        meterGasUsed: Number(result.tx.gasUsed),
        innerGas: Number(result.tx.verified.gasUsed),
      });
    }
    assert.ok(rows.length > 0, 'no gas rows');
    for (const r of rows) {
      t.diagnostic(
        `${r.vector}: ${r.proofBytes} proof bytes, verify estimate ${r.verifyEstimate}, ` +
          `meter estimate ${r.meterEstimate}, meter gasUsed ${r.meterGasUsed}, inner ${r.innerGas}`
      );
    }
    const outDir = path.join(__dirname, '..', '..', 'build', 'hyperion');
    fs.mkdirSync(outDir, { recursive: true });
    const outFile = path.join(outDir, `gas-stark-${settingsLabel()}.json`);
    fs.writeFileSync(
      outFile,
      JSON.stringify({ settings: H.optimizerOptions(), chainId: ctx.chainId, rows }, null, 2) + '\n'
    );
    t.diagnostic(`gas rows written to ${path.relative(process.cwd(), outFile)}`);
    // Every cell must fit the block cap with room; the 8M target is reported.
    for (const r of rows) {
      assert.ok(
        r.meterGasUsed < 20_000_000,
        `${r.vector}: ${r.meterGasUsed} gas exceeds the block cap`
      );
    }
    const worst = rows.reduce((a, b) => (a.meterGasUsed > b.meterGasUsed ? a : b));
    t.diagnostic(
      `largest cell ${worst.vector} at ${worst.meterGasUsed} gas ` +
        `(${worst.meterGasUsed <= 8_000_000 ? 'within' : 'above'} the 8,000,000 target)`
    );
  });
});
