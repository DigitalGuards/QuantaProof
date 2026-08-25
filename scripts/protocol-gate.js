// Required end-to-end validation on a clean, source-matched compiler and QRL
// node binary. The gate uses an already running local node and never deploys to
// a public chain.

const fs = require('node:fs');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const { checkToolchainProvenance } = require('./check-provenance');
const { DEV_CHAIN_ID } = require('./lib/devAccount');
const { LOCAL_KURTOSIS_CHAIN_ID, isLoopbackRpcUrl } = require('./lib/loadDeployer');
const { RpcClient } = require('./lib/rpc');

const repoRoot = path.join(__dirname, '..');

function writeRecord(record) {
  const outDir = path.join(repoRoot, 'build');
  fs.mkdirSync(outDir, { recursive: true });
  fs.writeFileSync(path.join(outDir, 'protocol-gate.json'), `${JSON.stringify(record, null, 2)}\n`);
}

function assertProtocolRpcUrl(rpcUrl) {
  if (!rpcUrl) {
    throw new Error('STARK_RPC_URL is required; the full protocol gate cannot use skip paths');
  }
  if (!isLoopbackRpcUrl(rpcUrl)) {
    throw new Error('STARK_RPC_URL must use a loopback host for the full protocol gate');
  }
}

function assertProtocolChainId(chainId) {
  if (chainId !== DEV_CHAIN_ID && chainId !== LOCAL_KURTOSIS_CHAIN_ID) {
    throw new Error(
      `chain ${chainId} is outside the protocol gate; use ${DEV_CHAIN_ID} or ${LOCAL_KURTOSIS_CHAIN_ID}`
    );
  }
}

function gateEnvironment(env = process.env) {
  const out = {
    ...env,
    HYPERION_OPTIMIZE_RUNS: '200',
    HYPERION_VIA_IR: '0',
    STARK_RANDOM_OPS: '10000',
  };
  for (const name of [
    'STARK_FRI_VECTORS',
    'STARK_MERKLE_VECTORS',
    'STARK_SKIP_MUTATIONS',
    'STARK_STARK_VECTORS',
    'STARK_VECTORS_LARGE',
  ]) {
    delete out[name];
  }
  return out;
}

function run(label, command, args, env) {
  console.log(`\n[protocol gate] ${label}`);
  const result = spawnSync(command, args, {
    cwd: repoRoot,
    env,
    stdio: 'inherit',
  });
  if (result.error) throw new Error(`${label}: ${result.error.message}`);
  if (result.status !== 0) throw new Error(`${label} exited ${result.status}`);
}

async function main() {
  const record = {
    schema: 1,
    startedAt: new Date().toISOString(),
    status: 'running',
  };
  try {
    const env = gateEnvironment();
    const rpcUrl = env.STARK_RPC_URL?.trim();
    assertProtocolRpcUrl(rpcUrl);

    record.profile = {
      optimizerRuns: Number(env.HYPERION_OPTIMIZE_RUNS),
      viaIr: env.HYPERION_VIA_IR === '1',
      randomFieldOperations: Number(env.STARK_RANDOM_OPS),
      vectorFilters: false,
    };
    console.log('[protocol gate] source and binary provenance');
    record.provenance = checkToolchainProvenance(env);
    const rpc = new RpcClient(rpcUrl);
    record.chainId = await rpc.chainId();
    assertProtocolChainId(record.chainId);

    run('Hyperion compile and size', 'npm', ['run', 'compile'], env);
    run('Node unit tests', 'npm', ['run', 'test:unit'], env);
    run('Prose lint', 'npm', ['run', 'lint:prose'], env);
    run('Format check', 'npm', ['run', 'format:check'], env);
    run('Rust format', 'cargo', ['fmt', '--check', '--manifest-path', 'prover/Cargo.toml'], env);
    run(
      'Rust clippy',
      'cargo',
      [
        'clippy',
        '--release',
        '--manifest-path',
        'prover/Cargo.toml',
        '--all-targets',
        '--',
        '-D',
        'warnings',
      ],
      env
    );
    run('Rust tests', 'cargo', ['test', '--release', '--manifest-path', 'prover/Cargo.toml'], env);
    run('Live QRVM contract tests', 'npm', ['run', 'test:contracts'], env);

    record.status = 'passed';
    record.passedAt = new Date().toISOString();
    record.plonky3Version = fs
      .readFileSync(path.join(repoRoot, 'prover', 'PLONKY3_VERSION'), 'utf8')
      .trim();
  } catch (error) {
    record.status = 'failed';
    record.failedAt = new Date().toISOString();
    record.error = error.message;
    throw error;
  } finally {
    writeRecord(record);
  }
  console.log('\n[protocol gate] passed; wrote build/protocol-gate.json');
}

if (require.main === module) {
  main().catch((error) => {
    console.error(`\nProtocol gate failed: ${error.message}`);
    process.exit(1);
  });
}

module.exports = { assertProtocolChainId, assertProtocolRpcUrl, gateEnvironment };
