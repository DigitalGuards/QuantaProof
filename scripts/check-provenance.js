// Fail-closed provenance checks for the two source-built QRL tools used by
// QuantaStark. A binary is accepted only when its embedded revision identifies
// the clean sibling source tree at HEAD.

const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const repoRoot = path.join(__dirname, '..');

function run(command, args, options = {}) {
  const displayCommand = path.basename(command);
  const result = spawnSync(command, args, {
    cwd: options.cwd || repoRoot,
    encoding: 'utf8',
  });
  if (result.error) {
    throw new Error(`${displayCommand}: ${result.error.message}`);
  }
  if (result.status !== 0) {
    throw new Error(
      `${displayCommand} ${args.join(' ')} failed: ${(result.stderr || result.stdout).trim()}`
    );
  }
  return (result.stdout || '').trim();
}

function gitHead(sourceDir, runner = run) {
  return runner('git', ['-C', sourceDir, 'rev-parse', 'HEAD']);
}

function assertClean(sourceDir, label, runner = run) {
  const status = runner('git', ['-C', sourceDir, 'status', '--porcelain']);
  if (status) {
    throw new Error(`${label} source tree is dirty`);
  }
}

function parseHyperionCommit(version) {
  const match = /(?:^|[.+-])commit\.([0-9a-f]{7,40})(?:[.+-]|$)/i.exec(version);
  if (!match) throw new Error(`hypc version has no embedded commit: ${version}`);
  return match[1].toLowerCase();
}

function parseGqrlCommit(version) {
  const match = /^Git Commit:\s*([0-9a-f]{7,40})\s*$/im.exec(version);
  if (!match) throw new Error(`gqrl version has no embedded Git Commit line: ${version}`);
  return match[1].toLowerCase();
}

function assertCommitMatch(label, sourceCommit, binaryCommit) {
  const source = sourceCommit.toLowerCase();
  const binary = binaryCommit.toLowerCase();
  if (!source.startsWith(binary) && !binary.startsWith(source)) {
    throw new Error(
      `${label} binary revision ${binaryCommit} does not match source HEAD ${sourceCommit}`
    );
  }
}

function checkToolchainProvenance(env = process.env, runner = run) {
  const hyperionSource = path.resolve(repoRoot, env.HYPERION_SOURCE_DIR || '../hyperion-stark');
  const compiler = path.resolve(
    repoRoot,
    env.HYPERION_COMPILER || env.HYPC_BIN || '../hyperion-stark/build/hypc/hypc'
  );
  const goQrlSource = path.resolve(repoRoot, env.GO_QRL_SOURCE_DIR || '../go-qrl-stark');
  const gqrl = path.resolve(repoRoot, env.GQRL_BIN || '../go-qrl-stark/build/bin/gqrl');

  assertClean(hyperionSource, 'Hyperion', runner);
  assertClean(goQrlSource, 'go-qrl', runner);

  const hyperionSourceCommit = gitHead(hyperionSource, runner);
  const hyperionVersion = runner(compiler, ['--version']);
  const hyperionBinaryCommit = parseHyperionCommit(hyperionVersion);
  assertCommitMatch('hypc', hyperionSourceCommit, hyperionBinaryCommit);

  const goQrlSourceCommit = gitHead(goQrlSource, runner);
  const gqrlVersion = runner(gqrl, ['version']);
  const gqrlBinaryCommit = parseGqrlCommit(gqrlVersion);
  assertCommitMatch('gqrl', goQrlSourceCommit, gqrlBinaryCommit);

  return {
    hyperion: {
      sourceCommit: hyperionSourceCommit,
      binaryCommit: hyperionBinaryCommit,
      version: hyperionVersion.split('\n').find((line) => line.startsWith('Version:')) || '',
    },
    goQrl: {
      sourceCommit: goQrlSourceCommit,
      binaryCommit: gqrlBinaryCommit,
      version: gqrlVersion.split('\n').find((line) => line.startsWith('Version:')) || '',
    },
  };
}

function main() {
  const report = {
    schema: 1,
    checkedAt: new Date().toISOString(),
    status: 'running',
  };
  const outDir = path.join(repoRoot, 'build');
  const outFile = path.join(outDir, 'toolchain-provenance.json');
  try {
    report.toolchain = checkToolchainProvenance();
    report.status = 'passed';
  } catch (error) {
    report.status = 'failed';
    report.error = error.message;
    throw error;
  } finally {
    fs.mkdirSync(outDir, { recursive: true });
    fs.writeFileSync(outFile, `${JSON.stringify(report, null, 2)}\n`);
    console.log(JSON.stringify(report, null, 2));
  }
}

if (require.main === module) {
  try {
    main();
  } catch (error) {
    console.error(`Toolchain provenance failed: ${error.message}`);
    process.exit(1);
  }
}

module.exports = {
  assertCommitMatch,
  checkToolchainProvenance,
  parseGqrlCommit,
  parseHyperionCommit,
};
