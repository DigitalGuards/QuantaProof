// FRI parameter presets, preset detection for vectors, and the per-preset
// compile of StarkVerifier.hyp.
//
// The deployable verifier binds its preset through six compile-time constants
// (LOG_BLOWUP, LOG_FINAL_POLY_LEN, MAX_LOG_ARITY, NUM_QUERIES, COMMIT_POW_BITS,
// QUERY_POW_BITS) declared on single lines at the top of
// contracts/hyperion/StarkVerifier.hyp; the committed values are preset c3.
// `compileVerifierForPreset` substitutes them with a regular expression and
// compiles the file through scripts/hypc.js (standard JSON), so one source
// file serves every preset and no per-preset copies exist.
//
// The table mirrors prover/stark-prover/src/config.rs (`all_presets`): c1, c2,
// c3, the -binary variants (max_log_arity 1) and the c3 arity / final-poly
// sweep c3-a<k>-f<l> for k in {1, 2, 3, 4} and l in {0, 3, 5} minus the two
// cells that coincide with c3 (a3-f3) and c3-binary (a1-f3): sixteen presets,
// in the order the prover emits them. test/contracts/stark.test.js keeps its
// own copy of the substitution (it groups vectors by config rather than by
// name), so the contract suite stays independent of the deployment tooling.

const { spawnSync } = require('child_process');

const { HYPC_BIN, collectSources, compileSources } = require('../hypc');
const { keccak256Hex } = require('./abi64');

const VERIFIER_FILE = 'StarkVerifier.hyp';
const GAS_METER_FILE = 'StarkVerifierGasMeter.hyp';
const REGISTRY_FILE = 'StarkFactRegistry.hyp';
const BRIDGE_FILE = 'bridge/StateBridge.hyp';

const PRESET_KEYS = Object.freeze([
  'logBlowup',
  'logFinalPolyLen',
  'maxLogArity',
  'numQueries',
  'commitPowBits',
  'queryPowBits',
]);

const PRESET_CONSTANTS = Object.freeze({
  logBlowup: 'LOG_BLOWUP',
  logFinalPolyLen: 'LOG_FINAL_POLY_LEN',
  maxLogArity: 'MAX_LOG_ARITY',
  numQueries: 'NUM_QUERIES',
  commitPowBits: 'COMMIT_POW_BITS',
  queryPowBits: 'QUERY_POW_BITS',
});

const CORE = Object.freeze({
  c1: {
    logBlowup: 1,
    logFinalPolyLen: 3,
    maxLogArity: 3,
    numQueries: 100,
    commitPowBits: 0,
    queryPowBits: 16,
  },
  c2: {
    logBlowup: 2,
    logFinalPolyLen: 3,
    maxLogArity: 3,
    numQueries: 50,
    commitPowBits: 0,
    queryPowBits: 16,
  },
  c3: {
    logBlowup: 3,
    logFinalPolyLen: 3,
    maxLogArity: 3,
    numQueries: 34,
    commitPowBits: 0,
    queryPowBits: 16,
  },
});

const SWEEP_ARITIES = Object.freeze([1, 2, 3, 4]);
const SWEEP_FINAL_POLY = Object.freeze([0, 3, 5]);

// "lb/lf/arity/Q/commitPow/queryPow": one string per distinct parameter set.
function presetKey(config) {
  for (const key of PRESET_KEYS) {
    if (config?.[key] === undefined || config[key] === null) {
      throw new TypeError(`preset config lacks ${key}`);
    }
  }
  return PRESET_KEYS.map((key) => Number(config[key])).join('/');
}

function sameConfig(a, b) {
  return presetKey(a) === presetKey(b);
}

function buildPresets() {
  const out = [];
  const push = (name, config) => out.push(Object.freeze({ name, config: Object.freeze(config) }));
  push('c1', { ...CORE.c1 });
  push('c2', { ...CORE.c2 });
  push('c3', { ...CORE.c3 });
  push('c1-binary', { ...CORE.c1, maxLogArity: 1 });
  push('c2-binary', { ...CORE.c2, maxLogArity: 1 });
  push('c3-binary', { ...CORE.c3, maxLogArity: 1 });
  for (const k of SWEEP_ARITIES) {
    for (const l of SWEEP_FINAL_POLY) {
      const config = { ...CORE.c3, maxLogArity: k, logFinalPolyLen: l };
      if (out.some((p) => sameConfig(p.config, config))) continue;
      push(`c3-a${k}-f${l}`, config);
    }
  }
  return Object.freeze(out);
}

// [{ name, config }] in prover order.
const PRESETS = buildPresets();

function presetNames() {
  return PRESETS.map((p) => p.name);
}

function presetConfig(name) {
  const entry = PRESETS.find((p) => p.name === name);
  if (!entry) {
    throw new Error(`unknown preset ${name}; known: ${presetNames().join(', ')}`);
  }
  return { ...entry.config };
}

// Preset name for a parameter set, or null for custom parameters.
function presetFromConfig(config) {
  const entry = PRESETS.find((p) => sameConfig(p.config, config));
  return entry ? entry.name : null;
}

// Preset name of a vector from its `config` (authoritative). Vectors without a
// config (none of the prover's outputs) fall back to the fib_<preset>_n<N>
// name pattern. Throws for custom parameters.
function presetFromVector(vector) {
  const label = vector?.name ?? '(unnamed vector)';
  if (vector?.config) {
    const name = presetFromConfig(vector.config);
    if (!name) {
      throw new Error(`${label}: config ${presetKey(vector.config)} matches no preset`);
    }
    return name;
  }
  const match = /^fib_(.+)_n\d+$/.exec(label);
  if (match && PRESETS.some((p) => p.name === match[1])) return match[1];
  throw new Error(`${label}: no config and no recognisable preset in the name`);
}

// The families the gas report groups by: the three core presets, their binary
// variants and the c3 sweep.
function presetFamily(name) {
  if (/^c[123]$/.test(name)) return 'core';
  if (/^c[123]-binary$/.test(name)) return 'binary';
  if (/^c3-a\d-f\d$/.test(name)) return 'sweep';
  throw new Error(`unknown preset ${name}`);
}

// keccak256("fibonacci-<preset>-v1"): the fact-registry program id of a
// verifier deployment (docs/BRIDGE.md).
function programIdFor(preset) {
  presetConfig(preset);
  return keccak256Hex(new TextEncoder().encode(`fibonacci-${preset}-v1`));
}

// ---------------------------------------------------------------------------
// Compiler settings and provenance
// ---------------------------------------------------------------------------

// Shared with scripts/compile-hyperion.js and test/lib/harness.js:
// HYPERION_OPTIMIZE_RUNS (default 200) and HYPERION_VIA_IR=1.
function optimizerSettings(env = process.env) {
  const runs = Number(env.HYPERION_OPTIMIZE_RUNS || 200);
  if (!Number.isInteger(runs) || runs < 1) {
    throw new Error(
      `HYPERION_OPTIMIZE_RUNS must be a positive integer, got ${env.HYPERION_OPTIMIZE_RUNS}`
    );
  }
  return { optimizerRuns: runs, viaIr: env.HYPERION_VIA_IR === '1' };
}

// "runs200" / "viaIr-runs200": the label the gas tables and the measurement
// store use for one optimizer setting (same form as stark.test.js).
function settingsLabel(settings) {
  const runs = settings.optimizerRuns ?? settings.runs;
  return settings.viaIr ? `viaIr-runs${runs}` : `runs${runs}`;
}

// The `Version:` line of `hypc --version` for the configured binary.
function compilerVersion(binary = HYPC_BIN) {
  const result = spawnSync(binary, ['--version'], { encoding: 'utf8' });
  if (result.error) {
    throw new Error(
      `Hyperion compiler not found: ${binary} (${result.error.message}). ` +
        'Set HYPERION_COMPILER=../hyperion-stark/build/hypc/hypc.'
    );
  }
  if (result.status !== 0) {
    throw new Error((result.stderr || result.stdout || 'hypc --version failed').trim());
  }
  const line = (result.stdout || '')
    .split('\n')
    .map((l) => l.trim())
    .find((l) => l.startsWith('Version:'));
  return line ? line.replace(/^Version:\s*/, '') : 'unknown';
}

// ---------------------------------------------------------------------------
// Compilation
// ---------------------------------------------------------------------------

// StarkVerifier.hyp with its six preset constants replaced by `config`.
function presetSource(source, config) {
  let out = source;
  for (const key of PRESET_KEYS) {
    const name = PRESET_CONSTANTS[key];
    const value = Number(config[key]);
    if (!Number.isInteger(value) || value < 0) {
      throw new TypeError(
        `preset constant ${name} must be a non-negative integer, got ${config[key]}`
      );
    }
    const re = new RegExp(`(uint512 internal constant ${name} = )\\d+;`);
    if (!re.test(out)) throw new Error(`constant ${name} not found in ${VERIFIER_FILE}`);
    out = out.replace(re, `$1${value};`);
  }
  return out;
}

function runtimeBytesOf(artifact) {
  return (artifact.deployedBytecode.length - 2) / 2;
}

// Compile StarkVerifier for one preset. Options: `sources` (a collectSources()
// map, collected once by callers that compile several presets), and the
// optimizer settings `optimizerRuns` / `viaIr` (default: the environment).
function compileVerifierForPreset(name, options = {}) {
  const config = presetConfig(name);
  const settings = { ...optimizerSettings(), ...pickSettings(options) };
  const sources = options.sources || collectSources();
  if (!sources[VERIFIER_FILE]) throw new Error(`${VERIFIER_FILE} is absent from the source map`);
  const patched = {
    ...sources,
    [VERIFIER_FILE]: { content: presetSource(sources[VERIFIER_FILE].content, config) },
  };
  const artifacts = compileSources(patched, { ...settings, entries: [VERIFIER_FILE] });
  const artifact = artifacts.StarkVerifier;
  if (!artifact) throw new Error(`StarkVerifier is missing from the compile of ${VERIFIER_FILE}`);
  return { preset: name, config, artifact, runtimeBytes: runtimeBytesOf(artifact), settings };
}

// StarkVerifierGasMeter is preset-independent: compile it once.
function compileGasMeter(options = {}) {
  const settings = { ...optimizerSettings(), ...pickSettings(options) };
  const sources = options.sources || collectSources();
  const artifacts = compileSources(sources, { ...settings, entries: [GAS_METER_FILE] });
  const artifact = artifacts.StarkVerifierGasMeter;
  if (!artifact)
    throw new Error(`StarkVerifierGasMeter is missing from the compile of ${GAS_METER_FILE}`);
  return { artifact, runtimeBytes: runtimeBytesOf(artifact), settings };
}

// StarkFactRegistry and StateBridge, always through the IR pipeline: the
// legacy code generator passes the mldsa87verify arguments to its Yul helper
// in reverse order (docs/compiler/HYPC-LEGACY-CODEGEN-DEFECTS.md).
function compileBridge(options = {}) {
  const settings = { ...optimizerSettings(), ...pickSettings(options), viaIr: true };
  const sources = options.sources || collectSources();
  const artifacts = compileSources(sources, { ...settings, entries: [REGISTRY_FILE, BRIDGE_FILE] });
  const registry = artifacts.StarkFactRegistry;
  const bridge = artifacts.StateBridge;
  if (!registry || !bridge)
    throw new Error('StarkFactRegistry or StateBridge is missing from the bridge compile');
  return {
    registry: { artifact: registry, runtimeBytes: runtimeBytesOf(registry) },
    bridge: { artifact: bridge, runtimeBytes: runtimeBytesOf(bridge) },
    settings,
  };
}

function pickSettings(options) {
  const out = {};
  if (options.optimizerRuns !== undefined) out.optimizerRuns = Number(options.optimizerRuns);
  if (options.viaIr !== undefined) out.viaIr = Boolean(options.viaIr);
  return out;
}

module.exports = {
  BRIDGE_FILE,
  GAS_METER_FILE,
  PRESETS,
  PRESET_CONSTANTS,
  PRESET_KEYS,
  REGISTRY_FILE,
  SWEEP_ARITIES,
  SWEEP_FINAL_POLY,
  VERIFIER_FILE,
  compileBridge,
  compileGasMeter,
  compileVerifierForPreset,
  compilerVersion,
  optimizerSettings,
  presetConfig,
  presetFamily,
  presetFromConfig,
  presetFromVector,
  presetKey,
  presetNames,
  presetSource,
  programIdFor,
  sameConfig,
  settingsLabel,
};
