// Standard-JSON compile helper around the native hypc binary.
//
// The contract test suite uses this to compile contracts/hyperion/test/*Harness.hyp
// on the fly. Adapted from the QuantaSwap hypc helper (GPL-3.0): keeps
// language "Hyperion" and reads abi plus qrvm.bytecode.object from the output.
//
// The whole contracts/hyperion/ tree is handed to the compiler as sources keyed
// by their path relative to that directory, so harness imports such as
// `import "../lib/Goldilocks.hyp";` resolve without a base-path flag. Output is
// limited to the requested entry files.

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const repoRoot = path.join(__dirname, '..');
const hyperionRoot = path.join(repoRoot, 'contracts', 'hyperion');
const HYPC_BIN = process.env.HYPERION_COMPILER || process.env.HYPC_BIN || 'hypc';
const OUTPUT_SELECTION = ['abi', 'qrvm.bytecode.object', 'qrvm.deployedBytecode.object'];

function toPosix(p) {
  return p.split(path.sep).join('/');
}

// Read every .hyp file under root into a standard-json sources map keyed by
// the posix path relative to root.
function collectSources(root = hyperionRoot, filter = null) {
  const sources = {};
  const walk = (dir) => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, entry.name);
      if (entry.isDirectory()) {
        walk(full);
      } else if (entry.name.endsWith('.hyp')) {
        const rel = toPosix(path.relative(root, full));
        if (!filter || filter(rel)) {
          sources[rel] = { content: fs.readFileSync(full, 'utf8') };
        }
      }
    }
  };
  walk(root);
  return sources;
}

// Compile a standard-json sources map. Returns
// { [contractName]: { abi, bytecode, deployedBytecode, sourceFile } },
// skipping interfaces and abstract contracts (no bytecode).
function compileSources(sources, options = {}) {
  const { entries = null, optimizerRuns = 200, viaIr = false } = options;
  if (Object.keys(sources).length === 0) {
    throw new Error('no .hyp sources to compile');
  }
  for (const entry of entries || []) {
    if (!sources[entry]) {
      throw new Error(`entry ${entry} is absent from the source map`);
    }
  }

  const outputSelection = {};
  if (entries && entries.length > 0) {
    for (const entry of entries) {
      outputSelection[entry] = { '*': OUTPUT_SELECTION };
    }
  } else {
    outputSelection['*'] = { '*': OUTPUT_SELECTION };
  }

  const settings = {
    optimizer: { enabled: true, runs: optimizerRuns },
    outputSelection,
  };
  if (viaIr) {
    settings.viaIR = true;
  }
  const input = { language: 'Hyperion', sources, settings };

  const r = spawnSync(HYPC_BIN, ['--standard-json'], {
    input: JSON.stringify(input),
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
  });
  if (r.error) {
    throw new Error(
      `spawn hypc failed: ${r.error.message} (set HYPERION_COMPILER=../hyperion-stark/build/hypc/hypc)`
    );
  }
  if (r.status !== 0) {
    throw new Error(`hypc exited ${r.status}: ${r.stderr || r.stdout}`);
  }

  const out = JSON.parse(r.stdout);
  if (out.errors) {
    const fatal = out.errors.filter((e) => e.severity === 'error');
    for (const e of out.errors) {
      (e.severity === 'error' ? console.error : console.warn)(e.formattedMessage || e.message);
    }
    if (fatal.length > 0) {
      throw new Error('compilation failed');
    }
  }

  const artifacts = {};
  for (const [sourceFile, byName] of Object.entries(out.contracts || {})) {
    for (const [name, artifact] of Object.entries(byName)) {
      const bytecode = artifact?.qrvm?.bytecode?.object;
      if (!bytecode) continue; // interface or abstract contract
      const deployed = artifact?.qrvm?.deployedBytecode?.object || '';
      artifacts[name] = {
        abi: artifact.abi,
        bytecode: `0x${bytecode}`,
        deployedBytecode: `0x${deployed}`,
        sourceFile,
      };
    }
  }
  return artifacts;
}

// Compile the given entry files (paths relative to contracts/hyperion/, for
// example "test/GoldilocksHarness.hyp") with the whole tree available for imports.
function compileFiles(entries, options = {}) {
  const root = options.root || hyperionRoot;
  return compileSources(collectSources(root), { ...options, entries });
}

// Compile every .hyp file directly inside the given directories (absolute
// paths or paths relative to the repository root).
function compileDirs(dirs, options = {}) {
  const root = options.root || hyperionRoot;
  const entries = [];
  for (const dir of dirs) {
    const absolute = path.isAbsolute(dir) ? dir : path.join(repoRoot, dir);
    for (const file of fs.readdirSync(absolute)) {
      if (file.endsWith('.hyp')) {
        entries.push(toPosix(path.relative(root, path.join(absolute, file))));
      }
    }
  }
  if (entries.length === 0) {
    throw new Error(`no .hyp sources in ${dirs.join(', ')}`);
  }
  return compileFiles(entries, options);
}

module.exports = {
  HYPC_BIN,
  hyperionRoot,
  collectSources,
  compileSources,
  compileFiles,
  compileDirs,
};
