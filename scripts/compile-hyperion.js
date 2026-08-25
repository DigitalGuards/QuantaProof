// Compile the deployable Hyperion sources with hypc.
//
// Walks contracts/hyperion/ for each DEPLOYABLE entry, emits the ABI, the
// creation bytecode (.bin) and the runtime bytecode (.bin-runtime) to
// build/hyperion/, and writes a manifest.json that records the exact compiler
// build, the pinned Plonky3 version and the byte sizes of every artifact.
//
// Adapted from the QNS Hyperion compile script (GPL-3.0). Every compile must
// run with the 64-byte compiler:
//   HYPERION_COMPILER=../hyperion-stark/build/hypc/hypc npm run compile

const fs = require('fs');
const path = require('path');
const { execFileSync, spawnSync } = require('child_process');

const repoRoot = path.join(__dirname, '..');
const hyperionRoot = path.join(repoRoot, 'contracts', 'hyperion');
const artifactsDir = path.join(repoRoot, 'build', 'hyperion');
const plonky3VersionFile = path.join(repoRoot, 'prover', 'PLONKY3_VERSION');
const compilerBinary = process.env.HYPERION_COMPILER || process.env.HYPC_BIN || 'hypc';
const optimizerRuns = process.env.HYPERION_OPTIMIZE_RUNS || '200';
const viaIr = process.env.HYPERION_VIA_IR === '1';

// Top-level deployable contracts (relative paths under contracts/hyperion/).
// Interfaces, libraries and harnesses compile as transitive dependencies or
// through scripts/hypc.js; they are never listed here. StarkFactRegistry.hyp
// and bridge/StateBridge.hyp join this list when they land (milestone M8).
const DEPLOYABLE = ['StarkVerifier.hyp', 'StarkVerifierGasMeter.hyp'];

function ensureCompilerAvailable() {
  const result = spawnSync(compilerBinary, ['--version'], { encoding: 'utf8' });
  if (result.error && result.error.code === 'ENOENT') {
    throw new Error(
      `Hyperion compiler not found: ${compilerBinary}. ` +
        'Build ../hyperion-stark and set HYPERION_COMPILER=../hyperion-stark/build/hypc/hypc.'
    );
  }
  if (result.status !== 0) {
    throw new Error((result.stderr || result.stdout || 'hypc execution failed').trim());
  }
  // The compiler build determines the word width and the precompile slots
  // baked into the builtins, so artifact provenance must record exactly which
  // hypc ran.
  const versionLine = (result.stdout || '')
    .split('\n')
    .map((line) => line.trim())
    .find((line) => line.startsWith('Version:'));
  const compilerVersion = versionLine ? versionLine.replace(/^Version:\s*/, '') : 'unknown';
  console.log(`hypc: ${compilerBinary} (${compilerVersion})`);
  return compilerVersion;
}

function readPlonky3Version() {
  if (!fs.existsSync(plonky3VersionFile)) {
    return 'unknown';
  }
  const value = fs.readFileSync(plonky3VersionFile, 'utf8').trim();
  return value || 'unknown';
}

function clearArtifactsDir() {
  fs.mkdirSync(artifactsDir, { recursive: true });
  for (const f of fs.readdirSync(artifactsDir)) {
    fs.rmSync(path.join(artifactsDir, f), { force: true, recursive: true });
  }
}

function discoverPrimaryContractName(source) {
  const matches = [
    ...source.matchAll(/^\s*(?:abstract\s+)?contract\s+([A-Za-z_][A-Za-z0-9_]*)\b/gm),
  ];
  if (matches.length === 0) {
    throw new Error('No contract definition found in Hyperion source.');
  }
  // Last contract declared in the file wins; this matches the QNS behaviour.
  return matches[matches.length - 1][1];
}

function hexFileByteLength(file) {
  if (!fs.existsSync(file)) {
    return 0;
  }
  return fs.readFileSync(file, 'utf8').trim().length / 2;
}

function compileOne(relHypPath) {
  const sourcePath = path.join(hyperionRoot, relHypPath);
  if (!fs.existsSync(sourcePath)) {
    throw new Error(`Missing canonical Hyperion source: ${relHypPath}`);
  }
  const source = fs.readFileSync(sourcePath, 'utf8');
  const contractName = discoverPrimaryContractName(source);

  console.log(`compile ${relHypPath} -> ${contractName}`);
  const args = [
    '--abi',
    '--bin',
    '--bin-runtime',
    `--base-path=${hyperionRoot}`,
    `--allow-paths=${repoRoot},${hyperionRoot}`,
    '--optimize',
    `--optimize-runs=${optimizerRuns}`,
  ];
  if (viaIr) {
    args.push('--via-ir');
  }
  args.push(`--output-dir=${artifactsDir}`, '--overwrite', sourcePath);
  execFileSync(compilerBinary, args, { stdio: ['ignore', 'inherit', 'inherit'] });

  const abiFile = `${contractName}.abi`;
  const binFile = `${contractName}.bin`;
  const runtimeFile = `${contractName}.bin-runtime`;
  const initcodeBytes = hexFileByteLength(path.join(artifactsDir, binFile));
  const runtimeBytes = hexFileByteLength(path.join(artifactsDir, runtimeFile));
  console.log(`  initcode ${initcodeBytes} bytes, runtime ${runtimeBytes} bytes`);

  return {
    sourceFile: relHypPath,
    contractName,
    abiFile,
    binFile,
    runtimeFile,
    initcodeBytes,
    runtimeBytes,
  };
}

function compileAll() {
  const compilerVersion = ensureCompilerAvailable();
  const plonky3Version = readPlonky3Version();
  clearArtifactsDir();

  const entries = DEPLOYABLE.map(compileOne);

  const manifest = {
    compiler: compilerBinary,
    compilerVersion,
    plonky3Version,
    optimizerRuns: Number(optimizerRuns),
    viaIr,
    generatedAt: new Date().toISOString(),
    contracts: entries,
  };
  const manifestPath = path.join(artifactsDir, 'manifest.json');
  fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + '\n');
  console.log(`\nWrote ${manifestPath}`);
  console.log(`Compiled ${entries.length} contract(s) (plonky3 ${plonky3Version}).`);
  return manifest;
}

if (require.main === module) {
  try {
    compileAll();
  } catch (err) {
    console.error(err.message);
    process.exit(1);
  }
}

module.exports = { DEPLOYABLE, artifactsDir, compileAll, readPlonky3Version };
