// Generate docs/GAS-REPORT.md: measure every valid vector through the gas
// meter of its preset, compare each cell with the plan's gas model and render
// the tables, the optimizer comparison and the summary.
//
// Usage:
//   STARK_CONFIG=config/dev-node.json npm run gas:report
//   STARK_CONFIG=config/dev-node.json npm run gas:report -- --skip-large
//   STARK_CONFIG=config/dev-node.json npm run gas:report -- --only fib_c3_n12,fib_c1_n20
//   npm run gas:report -- --render-only            # re-render from the store, no node needed
//
// Options:
//   --vectors <dir>    vector directory (default test/vectors; large/ below it is included)
//   --skip-large       ignore test/vectors/large/
//   --only <a,b,...>   restrict to the named vectors
//   --out <file>       report path (default docs/GAS-REPORT.md)
//   --config <path>    deployment record (default STARK_CONFIG or config/local-stark.json)
//   --store <dir>      measurement store (default build/gas-report)
//   --render-only      skip the measurements, render what the store holds
//
// Every vector goes through scripts/verify-proof.js (qrl_call and estimate of
// `verify`, then the `verifyAndLog` transaction of the preset's gas meter).
// Proofs whose transaction exceeds the node's transaction-pool size cap
// (128 KiB, txMaxSize in core/txpool/legacypool) are simulated with a
// qrl_call of `verifyAndLog` instead: the inner gas is exact, the receipt
// number is replaced by the meter's qrl_estimateGas and the cell is marked.
//
// Measurements are kept per optimizer setting in <store>/<label>.json, where
// the label (runs200, runs1000000, viaIr-runs200, ...) comes from the compiler
// settings deploy.js recorded for the verifier that served the cell. A report
// therefore accumulates several settings: deploy with one setting, run the
// report, deploy with the next, run it again. The primary tables use runs200
// (the committed default) when that store exists, otherwise the label of the
// current run; the comparison section lists every label side by side.
//
// The model column is the plan's formula (prover/stark-prover/src/sizes.rs,
// `stark-prover sizes --vector <file>`): calldata 16 * bytes, compute
// 130 * hashes + 2500 * Q * R + 3000 * Q + 15 * Q^2 + 60000, plus the 21000
// base cost, evaluated on the vector's exact layout and Merkle traces.
// Deviation is the direct `verify` estimate against that total.

const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

require('dotenv').config({ path: path.join(__dirname, '..', '.env'), quiet: true });

const { RpcClient } = require('./lib/rpc');
const { getSender } = require('./lib/devAccount');
const { loadConfig, resolveConfigPath } = require('./deploy');
const { loadVector, runVerifyProof } = require('./verify-proof');
const P = require('./lib/presets');
const { readPlonky3Version } = require('./compile-hyperion');

const repoRoot = path.join(__dirname, '..');
const defaultVectorsDir = path.join(repoRoot, 'test', 'vectors');
const defaultOutFile = path.join(repoRoot, 'docs', 'GAS-REPORT.md');
const defaultStoreDir = path.join(repoRoot, 'build', 'gas-report');
const manifestPath = path.join(repoRoot, 'build', 'hyperion', 'manifest.json');

const BLOCK_GAS_CAP = 20_000_000;
const GAS_TARGET = 8_000_000;
const TX_POOL_MAX_BYTES = 128 * 1024;
const EXTRAPOLATION_N = 24;
const DEFAULT_LABEL = 'runs200';

const FAMILIES = [
  { id: 'core', title: 'Core presets (c1, c2, c3)' },
  { id: 'binary', title: 'Binary folding (c1-binary, c2-binary, c3-binary)' },
  { id: 'sweep', title: 'c3 arity and final-polynomial sweep' },
];

// Phase breakdown of fib_c3_n12 measured by test/contracts/fri.test.js
// (FriHarness.verifyTimed, gasleft() deltas per phase); copied from
// docs/VERIFIER.md section 5.2, which is where it is regenerated.
const PHASES_FIB_C3_N12 = {
  source:
    'docs/VERIFIER.md section 5.2 (FriHarness.verifyTimed, test/contracts/fri.test.js), measured before the arity-schedule fix of commit 144f74f, which adds under 1k gas to the prepare phase',
  columns: ['runs 200', 'runs 1000000', 'via-IR (runs 200)', 'Share (runs 200)'],
  rows: [
    ['prepare (parse, scan, tables, prefix decode)', '87,821', '86,515', '103,116', '6.3 %'],
    ['absorbInstance (transcript 1 to 10, selectors)', '8,235', '7,951', '8,035', '0.6 %'],
    ['checkConstraints', '4,194', '4,182', '3,377', '0.3 %'],
    ['friTranscript (betas, final poly, PoW, 34 indices)', '18,765', '18,189', '17,656', '1.4 %'],
    ['inputBlocks (sort, 68 leaf hashes, two walks)', '263,593', '239,766', '271,723', '19.0 %'],
    ['reducedOpenings (34 points, 68 inversions, 34 ro)', '113,497', '111,841', '107,416', '8.2 %'],
    [
      'foldChains (102 rounds of arity 8, 34 final checks)',
      '726,197',
      '705,445',
      '671,657',
      '52.3 %',
    ],
    ['roundBlocks (three walks)', '166,809', '151,377', '171,739', '12.0 %'],
    ['Sum', '1,389,111', '1,325,266', '1,354,719', '100 %'],
    ['Calldata (transaction)', '694,372', '694,372', '694,372', ''],
  ],
};

// ---------------------------------------------------------------------------
// Arguments and vector discovery
// ---------------------------------------------------------------------------

function parseArgs(argv) {
  const options = {
    vectorsDir: defaultVectorsDir,
    outFile: defaultOutFile,
    storeDir: defaultStoreDir,
    skipLarge: false,
    only: null,
    renderOnly: false,
    config: null,
  };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    const next = () => {
      if (i + 1 >= argv.length) throw new Error(`${arg} needs a value`);
      i += 1;
      return argv[i];
    };
    if (arg === '--vectors') options.vectorsDir = path.resolve(repoRoot, next());
    else if (arg === '--out') options.outFile = path.resolve(repoRoot, next());
    else if (arg === '--config') options.config = path.resolve(repoRoot, next());
    else if (arg === '--store') options.storeDir = path.resolve(repoRoot, next());
    else if (arg === '--skip-large') options.skipLarge = true;
    else if (arg === '--render-only') options.renderOnly = true;
    else if (arg === '--only') {
      options.only = new Set(
        next()
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean)
      );
    } else throw new Error(`unknown option ${arg}`);
  }
  return options;
}

function listJson(dir) {
  if (!fs.existsSync(dir)) return [];
  return fs
    .readdirSync(dir)
    .filter((name) => name.endsWith('.json'))
    .sort()
    .map((name) => path.join(dir, name));
}

// Valid vectors: the tracked files plus large/ (mutations/ is never listed).
function listVectorFiles(dir, { skipLarge = false } = {}) {
  const files = listJson(dir);
  return skipLarge ? files : files.concat(listJson(path.join(dir, 'large')));
}

// ---------------------------------------------------------------------------
// The gas model (port of prover/stark-prover/src/sizes.rs)
// ---------------------------------------------------------------------------

const F_BYTES = 8;
const EF_BYTES = 16;
const DIGEST_BYTES = 32;
const SIB_COUNT_BYTES = 2;
const TRACE_WIDTH = 2;

// docs/PROTOCOL.md section 11.1: pEnd = 171 + 41 R + 16 * 2^lf.
function prefixEnd(rounds, logFinalPolyLen) {
  return 171 + 41 * rounds + 16 * 2 ** logFinalPolyLen;
}

// p3_fri::compute_log_arity_for_round with a single input height.
function aritySchedule(cfg, degreeBits) {
  let remaining = Math.max(degreeBits - cfg.logFinalPolyLen, 0);
  const schedule = [];
  while (remaining > 0) {
    const k = Math.min(remaining, cfg.maxLogArity);
    schedule.push(k);
    remaining -= k;
  }
  return schedule;
}

// Pruned sibling count for q queries into 2^h leaves:
// q * max(h - ceil(log2 q), 0) + min(q, 2^h).
function estimatedSiblingCount(q, h) {
  const logQ = q <= 1 ? 0 : (q - 1).toString(2).length;
  return q * Math.max(h - logQ, 0) + Math.min(q, 2 ** h);
}

// keccak calls of one block: unique leaves plus frontier compressions.
function estimatedHashes(q, h) {
  let sum = 0;
  for (let l = 0; l <= h; l += 1) sum += Math.min(q, 2 ** (h - l));
  return sum;
}

function modelGas(cfg, totalBytes, hashes, rounds) {
  const q = cfg.numQueries;
  const calldataGas = 16 * totalBytes;
  const computeGas = 130 * hashes + 2500 * q * rounds + 3000 * q + 15 * q * q + 60_000;
  return { calldataGas, computeGas, totalGas: 21_000 + calldataGas + computeGas };
}

// Model-based size and gas for a preset at degreeBits (sizes::estimate).
function modelEstimate(cfg, degreeBits) {
  const q = cfg.numQueries;
  const h = degreeBits + cfg.logBlowup;
  const schedule = aritySchedule(cfg, degreeBits);
  let bytes = prefixEnd(schedule.length, cfg.logFinalPolyLen);
  let hashes = 0;
  for (let i = 0; i < 2; i += 1) {
    const sib = estimatedSiblingCount(q, h);
    bytes += q * TRACE_WIDTH * F_BYTES + SIB_COUNT_BYTES + sib * DIGEST_BYTES;
    hashes += estimatedHashes(q, h);
  }
  let height = h;
  for (const k of schedule) {
    height -= k;
    const sib = estimatedSiblingCount(q, height);
    bytes += q * (2 ** k - 1) * EF_BYTES + SIB_COUNT_BYTES + sib * DIGEST_BYTES;
    hashes += estimatedHashes(q, height);
  }
  return {
    kind: 'estimate',
    degreeBits,
    aritySchedule: schedule,
    rounds: schedule.length,
    totalBytes: bytes,
    hashes,
    ...modelGas(cfg, bytes, hashes, schedule.length),
  };
}

// Exact size and gas from a vector's layout and Merkle traces (sizes::exact);
// falls back to the estimate when the vector carries no traces.
function modelForVector(vector) {
  const cfg = vector.config;
  const raw = vector.raw;
  if (!raw?.layout || !Array.isArray(raw.merkle)) {
    return modelEstimate(cfg, vector.degreeBits);
  }
  const hashes = raw.merkle.reduce(
    (sum, block) =>
      sum + block.leaves.length + block.levels.reduce((s, level) => s + level.length, 0),
    0
  );
  const rounds = raw.layout.rounds.length;
  const totalBytes = raw.layout.totalLen;
  return {
    kind: 'exact',
    degreeBits: vector.degreeBits,
    aritySchedule: raw.layout.logArities,
    rounds,
    totalBytes,
    hashes,
    ...modelGas(cfg, totalBytes, hashes, rounds),
  };
}

// ---------------------------------------------------------------------------
// Measurement store
// ---------------------------------------------------------------------------

function labelOf(settings) {
  if (!settings) return 'unknown';
  return P.settingsLabel({ optimizerRuns: settings.runs, viaIr: settings.viaIr });
}

function loadStores(dir) {
  const stores = new Map();
  for (const file of listJson(dir)) {
    const store = JSON.parse(fs.readFileSync(file, 'utf8'));
    if (store?.label && store.rows) stores.set(store.label, store);
  }
  return stores;
}

function saveStore(dir, store) {
  fs.mkdirSync(dir, { recursive: true });
  fs.writeFileSync(path.join(dir, `${store.label}.json`), JSON.stringify(store, null, 2) + '\n');
}

function gitCommit() {
  try {
    return execFileSync('git', ['rev-parse', '--short', 'HEAD'], {
      cwd: repoRoot,
      encoding: 'utf8',
    }).trim();
  } catch {
    return 'unknown';
  }
}

function loadManifest() {
  return fs.existsSync(manifestPath) ? JSON.parse(fs.readFileSync(manifestPath, 'utf8')) : null;
}

// ---------------------------------------------------------------------------
// Measurement
// ---------------------------------------------------------------------------

function presetOrder(name) {
  return P.PRESETS.findIndex((p) => p.name === name);
}

function familyOrder(family) {
  return FAMILIES.findIndex((f) => f.id === family);
}

function sortRows(rows) {
  return [...rows].sort(
    (a, b) =>
      familyOrder(a.family) - familyOrder(b.family) ||
      presetOrder(a.preset) - presetOrder(b.preset) ||
      a.degreeBits - b.degreeBits
  );
}

async function measureVector({ rpc, sender, config, vector }) {
  const result = await runVerifyProof({ rpc, sender, config, vector });
  if (!result.tx) throw new Error('no verifyAndLog result');
  if (!result.tx.simulated && result.tx.status !== 1) {
    throw new Error(`verifyAndLog transaction failed (${result.tx.hash})`);
  }
  if (!result.tx.verified) throw new Error('no Verified event in the receipt');
  if (!result.pass) {
    throw new Error(
      `verifier ${result.ok ? 'accepted' : 'rejected'} the proof, vector expects ` +
        `${result.expectedValid ? 'accepted' : 'rejected'}` +
        (result.tx.verifyReverted
          ? ` (revert data ${result.tx.verifyReverted.data.slice(0, 10)})`
          : '')
    );
  }
  const model = modelForVector(vector);
  const verifyEstimate = result.verifyEstimate === null ? null : Number(result.verifyEstimate);
  const meterEstimate = Number(result.tx.estimateGas);
  const gasUsed = result.tx.simulated ? null : Number(result.tx.gasUsed);
  return {
    vector: vector.name,
    preset: result.preset,
    family: P.presetFamily(result.preset),
    degreeBits: vector.degreeBits,
    proofBytes: result.proofBytes,
    calldataBytes: result.calldataBytes,
    calldataGas: result.calldataGas,
    verifyEstimate,
    meterEstimate,
    gasUsed,
    // The transaction cost used for the cap and target comparisons: the
    // receipt, or the meter estimate when the transaction could not be sent.
    txGas: gasUsed ?? meterEstimate,
    simulated: Boolean(result.tx.simulated),
    txError: result.tx.error ?? null,
    innerGas: Number(result.tx.verified.gasUsed),
    ok: result.ok,
    model,
    deviation: verifyEstimate === null ? null : (verifyEstimate - model.totalGas) / model.totalGas,
    settings: result.settings,
    label: labelOf(result.settings),
    runtimeBytes: result.runtimeBytes,
    verifier: result.verifier,
    gasMeter: result.gasMeter,
    txHash: result.tx.hash,
    measuredAt: new Date().toISOString(),
  };
}

// ---------------------------------------------------------------------------
// Rendering
// ---------------------------------------------------------------------------

function fmt(value) {
  if (value === null || value === undefined) return '?';
  return Number(value).toLocaleString('en-US');
}

function pct(value, digits = 1) {
  if (value === null || value === undefined || Number.isNaN(value)) return '?';
  const v = value * 100;
  return `${v > 0 ? '+' : ''}${v.toFixed(digits)} %`;
}

// Receipt gasUsed, or the meter estimate marked with `*` for simulated cells.
function gasCell(row) {
  return row.simulated ? `${fmt(row.meterEstimate)}\\*` : fmt(row.gasUsed);
}

function table(header, rows) {
  const lines = [`| ${header.join(' | ')} |`, `| ${header.map(() => '---').join(' | ')} |`];
  for (const row of rows) lines.push(`| ${row.join(' | ')} |`);
  return lines.join('\n');
}

function cellRow(r) {
  return [
    r.vector,
    String(r.degreeBits),
    fmt(r.proofBytes),
    fmt(r.calldataGas),
    fmt(r.verifyEstimate),
    gasCell(r),
    fmt(r.innerGas),
    fmt(r.model.totalGas),
    pct(r.deviation),
  ];
}

const CELL_HEADER = [
  'Vector',
  'n',
  'Proof bytes',
  'Calldata gas',
  'estimateGas',
  'gasUsed',
  'Inner gas',
  'Model',
  'Deviation',
];

function mean(values) {
  return values.length === 0 ? null : values.reduce((a, b) => a + b, 0) / values.length;
}

function extrapolationRows(rows) {
  const out = [];
  for (const preset of ['c1', 'c2', 'c3']) {
    const cells = rows.filter((r) => r.preset === preset && r.verifyEstimate !== null);
    if (cells.length === 0) continue;
    const largest = cells.reduce((a, b) => (b.degreeBits > a.degreeBits ? b : a));
    const ratio = largest.verifyEstimate / largest.model.totalGas;
    const model24 = modelEstimate(P.presetConfig(preset), EXTRAPOLATION_N);
    out.push({
      preset,
      largest,
      ratio,
      model24,
      calibrated: Math.round(model24.totalGas * ratio),
    });
  }
  return out;
}

function simulatedNote(rows) {
  const simulated = rows.filter((r) => r.simulated);
  if (simulated.length === 0) return [];
  return [
    `\\* Transaction above the node's ${fmt(TX_POOL_MAX_BYTES)}-byte transaction-pool cap ` +
      '(`txMaxSize` in `core/txpool/legacypool`, a pool constant, no consensus rule); the cell ' +
      'shows `qrl_estimateGas` of `verifyAndLog` and the inner gas of a `qrl_call` of the same ' +
      `function. Cells: ${simulated.map((r) => `\`${r.vector}\``).join(', ')}.`,
    '',
  ];
}

function renderReport({ stores, primaryLabel, environment, skipped, failures, vectorCounts }) {
  const primary = stores.get(primaryLabel);
  const rows = sortRows(Object.values(primary?.rows ?? {}));
  const labels = [...stores.keys()].sort((a, b) =>
    a === primaryLabel ? -1 : b === primaryLabel ? 1 : a.localeCompare(b)
  );
  const L = [];
  const push = (...lines) => L.push(...lines);

  push('# Gas report', '');
  push(
    'Generated by `npm run gas:report`; do not edit by hand. Whole `verifyAndLog` transactions',
    'through `StarkVerifierGasMeter` on a live QRVM, one verifier deployment per preset',
    '(`npm run deploy -- --preset all`, `scripts/lib/presets.js`), compared with the gas model',
    'of the plan (`stark-prover sizes`). `docs/VERIFIER.md` explains the verifier and the',
    'phase measurements; `docs/GAS-PRIMITIVES.md` the field primitives.',
    ''
  );

  push('## Environment', '');
  push(`- Generated at: ${environment.generatedAt}`);
  push(`- Commit: \`${environment.commit}\``);
  push(
    `- Network: ${environment.network} (chain ${environment.chainId}), block gas limit ${fmt(environment.blockGasLimit)}`
  );
  push(
    `- Compiler: ${environment.compilerVersion}; \`npm run compile\` manifest: runs ${environment.manifest?.optimizerRuns ?? '?'}, ` +
      `via-IR ${environment.manifest?.viaIr ? 'on' : 'off'}`
  );
  push(`- Plonky3: ${environment.plonky3Version}`);
  push(
    `- Block gas cap: ${fmt(BLOCK_GAS_CAP)} (consensus); target per verification: ${fmt(GAS_TARGET)} or less; ` +
      `transaction-pool size cap ${fmt(TX_POOL_MAX_BYTES)} bytes`
  );
  push(
    `- Vectors: ${vectorCounts.tracked} tracked (n = 10, 12) and ${vectorCounts.large} large (n = 16, 20) ` +
      `under \`test/vectors/\`; ${rows.length} cells in the primary tables`
  );
  push(
    `- Optimizer settings measured: ${labels.map((l) => (l === primaryLabel ? `${l} (primary)` : l)).join(', ')}`
  );
  push('');
  push(
    'Verifier runtime bytes per setting (range over the deployed presets; the cap is 24,576):',
    ''
  );
  push(
    table(
      ['Setting', 'Compiler', 'StarkVerifier[c3]', 'Smallest preset', 'Largest preset', 'Cells'],
      labels.map((label) => {
        const s = stores.get(label);
        const all = Object.values(s.rows);
        const sizes = new Map();
        for (const r of all) if (r.runtimeBytes) sizes.set(r.preset, r.runtimeBytes);
        const entries = [...sizes.entries()].sort((a, b) => a[1] - b[1]);
        const c3 = sizes.get('c3');
        const last = entries[entries.length - 1];
        return [
          label,
          s.environment?.compilerVersion ?? '?',
          fmt(c3),
          entries.length ? `${entries[0][0]} (${fmt(entries[0][1])})` : '?',
          entries.length ? `${last[0]} (${fmt(last[1])})` : '?',
          String(all.length),
        ];
      })
    ),
    ''
  );

  push('## Columns', '');
  push(
    '- `n`: log2 of the trace length; the LDE height is `n + log_blowup`.',
    '- Proof bytes: the packed `bytes calldata proof` (docs/PROTOCOL.md section 11).',
    '- Calldata gas: 16 gas per non-zero byte and 4 per zero byte of the `verify(bytes,bytes)` calldata, ABI framing included.',
    '- estimateGas: `qrl_estimateGas` of a direct `verify` transaction (base cost, calldata and execution; the number one verification transaction pays).',
    '- gasUsed: receipt `gasUsed` of the `verifyAndLog` transaction (adds the meter framing: the STATICCALL, its calldata copy, two storage writes and the event). Every meter is warmed by one discarded call before its first measured cell, so the receipts are steady-state numbers. A `\\*` marks a cell whose transaction exceeds the pool size cap (see the note under the table).',
    '- Inner gas: the `gasleft()` delta around the STATICCALL from the `Verified` event.',
    '- Model: the plan formula on the exact layout, `21000 + 16 * bytes + 130 * hashes + 2500 * Q * R + 3000 * Q + 15 * Q^2 + 60000`.',
    '- Deviation: `(estimateGas - model) / model`.',
    ''
  );

  for (const family of FAMILIES) {
    const familyRows = rows.filter((r) => r.family === family.id);
    push(`## ${family.title} (${primaryLabel})`, '');
    if (familyRows.length === 0) {
      push('No cells measured.', '');
      continue;
    }
    push(table(CELL_HEADER, familyRows.map(cellRow)), '');
    push(...simulatedNote(familyRows));
  }

  push('## Optimizer settings', '');
  if (labels.length < 2) {
    push(
      `Only ${primaryLabel} has been measured. Deploy with \`HYPERION_OPTIMIZE_RUNS=1000000\` or`,
      '`HYPERION_VIA_IR=1` (`npm run deploy -- --preset all`) and run the report again to add a column.',
      ''
    );
  } else {
    push(
      'Per setting: `estimateGas` of `verify` / `gasUsed` of `verifyAndLog` / inner gas, for the',
      'cells measured under every setting. The runs value decides whether the compiler',
      'materialises the wide lane masks and packed tables with `PUSH` or `CODECOPY`',
      '(`docs/GAS-PRIMITIVES.md`); the IR pipeline schedules the Yul differently.',
      ''
    );
    const names = new Set(Object.keys(primary.rows));
    const shared = sortRows(
      [...names]
        .filter((v) => labels.every((l) => stores.get(l).rows[v]))
        .map((v) => primary.rows[v])
    );
    push(
      table(
        ['Vector', ...labels.map((l) => `${l}: estimate / gasUsed / inner`)],
        shared.map((r) => [
          r.vector,
          ...labels.map((l) => {
            const c = stores.get(l).rows[r.vector];
            return `${fmt(c.verifyEstimate)} / ${gasCell(c)} / ${fmt(c.innerGas)}`;
          }),
        ])
      ),
      ''
    );
    push(...simulatedNote(shared));
    const c3 = shared.filter((r) => r.preset === 'c3');
    if (c3.length > 0) {
      push(`Change of \`gasUsed\` relative to ${primaryLabel} for the c3 cells:`, '');
      push(
        table(
          ['Vector', ...labels.filter((l) => l !== primaryLabel)],
          c3.map((r) => [
            r.vector,
            ...labels
              .filter((l) => l !== primaryLabel)
              .map((l) => pct((stores.get(l).rows[r.vector].txGas - r.txGas) / r.txGas)),
          ])
        ),
        ''
      );
    }
  }

  push('## Summary', '');
  if (rows.length > 0) {
    const byGas = [...rows].sort((a, b) => a.txGas - b.txGas);
    const best = byGas[0];
    const worst = byGas[byGas.length - 1];
    const within = rows.filter((r) => r.txGas <= GAS_TARGET).length;
    const over = rows.filter((r) => r.txGas > GAS_TARGET);
    const deviations = rows.map((r) => r.deviation).filter((d) => d !== null);
    const calldataShares = rows
      .map((r) => r.calldataGas / r.verifyEstimate)
      .filter((s) => Number.isFinite(s));
    const simulated = rows.filter((r) => r.simulated);
    push(
      `- Cheapest cell: \`${best.vector}\` at ${fmt(best.txGas)} gas (${fmt(best.innerGas)} inner). ` +
        `Most expensive: \`${worst.vector}\` at ${fmt(worst.txGas)} gas (${fmt(worst.innerGas)} inner), ` +
        `${((100 * worst.txGas) / BLOCK_GAS_CAP).toFixed(1)} % of the ${fmt(BLOCK_GAS_CAP)} block cap.`
    );
    push(
      `- ${within} of ${rows.length} cells are at or below the ${fmt(GAS_TARGET)} target` +
        (over.length === 0
          ? '; the staged verification contingency (`docs/STAGED-VERIFICATION.md`) stays unimplemented.'
          : `; above it: ${over.map((r) => `\`${r.vector}\` (${fmt(r.txGas)})`).join(', ')}.`)
    );
    if (simulated.length > 0) {
      push(
        `- ${simulated.length} cells could not be sent as a transaction: their calldata exceeds the ` +
          `${fmt(TX_POOL_MAX_BYTES)}-byte transaction-pool cap of the execution client (a pool constant, ` +
          'no consensus rule). Their gas is measured through `qrl_estimateGas` and `qrl_call` and marked ' +
          '`\\*`; a rollup that needs such proofs must raise the pool cap on its sequencer nodes or split ' +
          'the proof across transactions (`docs/STAGED-VERIFICATION.md`).'
      );
    }
    if (deviations.length > 0) {
      push(
        `- Model deviation (estimateGas against the formula): ${pct(Math.min(...deviations))} to ` +
          `${pct(Math.max(...deviations))}, mean ${pct(mean(deviations))}. The formula counts every calldata byte ` +
          'at 16 gas (zero bytes cost 4) and its compute term is a coarse per-query, per-round budget; the phase ' +
          'table below is what the verifier spends.'
      );
    }
    if (calldataShares.length > 0) {
      push(
        `- Calldata is ${(100 * Math.min(...calldataShares)).toFixed(0)} to ${(100 * Math.max(...calldataShares)).toFixed(0)} % ` +
          'of a verification transaction and is fixed by the proof layout; the rest is execution.'
      );
    }
    push('');

    const extra = extrapolationRows(rows);
    if (extra.length > 0) {
      push(`### Extrapolation to n = ${EXTRAPOLATION_N}`, '');
      push(
        'The formula evaluated on the modelled layout at n = 24 (`stark-prover sizes --preset <p> --log-n 24`),',
        'and the same number scaled by the measured-to-model ratio of the largest measured cell of the preset.',
        'Both are calldata-dominated: the sibling count grows with `Q * (h - log2 Q)` per block and the round',
        'count with `n / max_log_arity`, so cost is close to linear in n.',
        ''
      );
      push(
        table(
          [
            'Preset',
            'Largest measured n',
            'estimateGas',
            'Model at that n',
            'Ratio',
            `Model bytes at n = ${EXTRAPOLATION_N}`,
            `Model gas at n = ${EXTRAPOLATION_N}`,
            `Calibrated gas at n = ${EXTRAPOLATION_N}`,
          ],
          extra.map((e) => [
            e.preset,
            String(e.largest.degreeBits),
            fmt(e.largest.verifyEstimate),
            fmt(e.largest.model.totalGas),
            e.ratio.toFixed(3),
            fmt(e.model24.totalBytes),
            fmt(e.model24.totalGas),
            fmt(e.calibrated),
          ])
        ),
        ''
      );
      const overTarget = extra.filter((e) => e.calibrated > GAS_TARGET);
      const overPool = extra.filter((e) => e.model24.totalBytes > TX_POOL_MAX_BYTES);
      push(
        overTarget.length === 0
          ? `- Every core preset stays below the ${fmt(GAS_TARGET)} target at n = ${EXTRAPOLATION_N} by this extrapolation.`
          : `- Above the ${fmt(GAS_TARGET)} target at n = ${EXTRAPOLATION_N}: ${overTarget
              .map((e) => `${e.preset} (${fmt(e.calibrated)})`)
              .join(', ')}; ${
              extra.every((e) => e.calibrated < BLOCK_GAS_CAP) ? 'all' : 'some'
            } below the ${fmt(BLOCK_GAS_CAP)} cap.`
      );
      if (overPool.length > 0) {
        push(
          `- Above the ${fmt(TX_POOL_MAX_BYTES)}-byte pool cap at n = ${EXTRAPOLATION_N}: ${overPool
            .map((e) => `${e.preset} (${fmt(e.model24.totalBytes)} bytes)`)
            .join(', ')}.`
        );
      }
      push('');
    }
  } else {
    push('No cells measured.', '');
  }

  push('### Phases of `fib_c3_n12`', '');
  push(
    `Copied from ${PHASES_FIB_C3_N12.source}; \`gasleft()\` deltas around each phase of the real flow.`,
    ''
  );
  push(table(['Phase', ...PHASES_FIB_C3_N12.columns], PHASES_FIB_C3_N12.rows), '');

  if (skipped.length > 0 || failures.length > 0) {
    push('## Not measured in this run', '');
    for (const s of skipped) push(`- ${s}`);
    for (const f of failures) push(`- ${f}`);
    push('');
  }

  return L.join('\n');
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const configPath = options.config || resolveConfigPath(process.env);
  // --render-only needs no record; do not seed one from the example.
  const config = options.renderOnly && !fs.existsSync(configPath) ? {} : loadConfig(configPath);
  const manifest = loadManifest();
  const stores = loadStores(options.storeDir);
  const skipped = [];
  const failures = [];

  const allFiles = listVectorFiles(options.vectorsDir, { skipLarge: options.skipLarge });
  const vectorCounts = {
    tracked: listJson(options.vectorsDir).length,
    large: options.skipLarge ? 0 : listJson(path.join(options.vectorsDir, 'large')).length,
  };

  let environment = {
    generatedAt: new Date().toISOString(),
    commit: gitCommit(),
    network: config.network ?? 'unknown',
    chainId: config.chainId,
    blockGasLimit: null,
    compilerVersion: config.compilerVersion ?? manifest?.compilerVersion ?? 'unknown',
    plonky3Version: readPlonky3Version(),
    manifest: manifest ? { optimizerRuns: manifest.optimizerRuns, viaIr: manifest.viaIr } : null,
  };
  let currentLabel = null;

  if (!options.renderOnly) {
    const rpc = new RpcClient(config.rpcUrl, { timeoutMs: 120000 });
    const chainId = await rpc.chainId();
    if (chainId !== Number(config.chainId)) {
      throw new Error(`chainId mismatch: expected ${config.chainId}, got ${chainId}`);
    }
    const sender = await getSender(rpc, { repoRoot, chainId });
    const latest = await rpc.getBlockByNumber('latest');
    environment.chainId = chainId;
    environment.blockGasLimit = latest?.gasLimit ? Number(BigInt(latest.gasLimit)) : null;

    const touched = new Set();
    const warmed = new Set();
    for (const file of allFiles) {
      const vector = loadVector(file);
      if (options.only && !options.only.has(vector.name)) continue;
      if (vector.expected && vector.expected.valid === false) {
        skipped.push(`${vector.name}: mutated vector`);
        continue;
      }
      if (!vector.preset) {
        skipped.push(`${vector.name}: custom parameters, no preset`);
        continue;
      }
      const entry = config.contracts?.verifiers?.[vector.preset];
      if (!entry) {
        skipped.push(
          `${vector.name}: no verifier deployed for preset ${vector.preset} (npm run deploy -- --preset ${vector.preset})`
        );
        continue;
      }
      process.stdout.write(
        `${vector.name} (${vector.preset}, ${fmt(vector.proof.length)} bytes)... `
      );
      let row;
      try {
        // The first call of a meter pays the zero-to-nonzero storage writes of
        // lastGas and lastOk (about 37k gas); one discarded call per meter keeps
        // every measured receipt at its steady-state cost.
        if (!warmed.has(entry.gasMeter)) {
          await runVerifyProof({ rpc, sender, config, vector });
          warmed.add(entry.gasMeter);
        }
        row = await measureVector({ rpc, sender, config, vector });
      } catch (error) {
        console.log('FAILED');
        console.error(`  ${error.message}`);
        failures.push(`${vector.name}: ${error.message}`);
        continue;
      }
      console.log(
        `estimate ${fmt(row.verifyEstimate)}, gasUsed ${row.simulated ? `${fmt(row.meterEstimate)} (simulated)` : fmt(row.gasUsed)}, ` +
          `inner ${fmt(row.innerGas)}, model ${fmt(row.model.totalGas)} (${pct(row.deviation)}) [${row.label}]`
      );
      let store = stores.get(row.label);
      if (!store) {
        store = { label: row.label, settings: row.settings, environment: null, rows: {} };
        stores.set(row.label, store);
      }
      store.rows[row.vector] = row;
      store.environment = { ...environment };
      touched.add(row.label);
      currentLabel = currentLabel ?? row.label;
    }
    for (const label of touched) saveStore(options.storeDir, stores.get(label));
    if (touched.size > 0) {
      console.log(
        `\nMeasurements stored under ${path.relative(repoRoot, options.storeDir)}/ (${[...touched].join(', ')})`
      );
    }
  }

  if (stores.size === 0) {
    throw new Error('nothing to render: no measurements were taken and the store is empty');
  }
  const primaryLabel = stores.has(DEFAULT_LABEL)
    ? DEFAULT_LABEL
    : (currentLabel ?? [...stores.keys()].sort()[0]);
  if (options.renderOnly) {
    const env = stores.get(primaryLabel).environment;
    if (env)
      environment = { ...env, generatedAt: environment.generatedAt, commit: environment.commit };
  }

  const report = renderReport({
    stores,
    primaryLabel,
    environment,
    skipped,
    failures,
    vectorCounts,
  });
  fs.mkdirSync(path.dirname(options.outFile), { recursive: true });
  fs.writeFileSync(options.outFile, report);
  const cells = Object.keys(stores.get(primaryLabel).rows).length;
  console.log(
    `Wrote ${path.relative(repoRoot, options.outFile)} (${cells} cells in the ${primaryLabel} tables, ${stores.size} setting(s))`
  );
  if (skipped.length > 0) {
    console.log(`Skipped ${skipped.length} vector(s); listed at the end of the report.`);
  }
  if (failures.length > 0) {
    console.error(`${failures.length} vector(s) failed; listed at the end of the report.`);
    process.exit(1);
  }
}

if (require.main === module) {
  main().catch((err) => {
    console.error('\ngas:report failed:', err.message);
    if (err.data) console.error('Data:', err.data);
    process.exit(1);
  });
}

module.exports = {
  BLOCK_GAS_CAP,
  GAS_TARGET,
  TX_POOL_MAX_BYTES,
  aritySchedule,
  estimatedHashes,
  estimatedSiblingCount,
  listVectorFiles,
  modelEstimate,
  modelForVector,
  modelGas,
  parseArgs,
  prefixEnd,
  renderReport,
};
