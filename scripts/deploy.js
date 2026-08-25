// Deploy StarkVerifier and StarkVerifierGasMeter to a QRL 2.0 network.
//
// Usage:
//   HYPERION_COMPILER=../hyperion-stark/build/hypc/hypc npm run compile
//   STARK_CONFIG=config/dev-node.json npm run deploy
//   STARK_CONFIG=config/local-stark.json STARK_PUBLIC_DEV_ACCOUNT=0 npm run deploy
//
// The dev node (chain 1337) signs with its unlocked developer account. Any
// other chain needs STARK_PUBLIC_DEV_ACCOUNT (Kurtosis) or TESTNET_SEED.
// Addresses are written back into the config file; the previous set moves to
// previousContracts. A missing config file is seeded from its .example.json.

const fs = require('fs');
const path = require('path');

require('dotenv').config({ path: path.join(__dirname, '..', '.env'), quiet: true });

const { RpcClient, toQuantity } = require('./lib/rpc');
const { getSender } = require('./lib/devAccount');
const { addressHex } = require('./lib/abi64');

const repoRoot = path.join(__dirname, '..');
const artifactsDir = path.join(repoRoot, 'build', 'hyperion');
const PLANCK_PER_QUANTA = 10n ** 18n;

function resolveConfigPath(env = process.env) {
  return env.STARK_CONFIG
    ? path.resolve(repoRoot, env.STARK_CONFIG)
    : path.join(repoRoot, 'config', 'local-stark.json');
}

function loadJson(p) {
  return JSON.parse(fs.readFileSync(p, 'utf8'));
}

function loadConfig(configPath) {
  if (!fs.existsSync(configPath)) {
    const example = configPath.replace(/\.json$/, '.example.json');
    if (!fs.existsSync(example)) {
      throw new Error(`Config not found: ${configPath} (and no ${example} to seed it from)`);
    }
    fs.copyFileSync(example, configPath);
    console.log(`Seeded ${configPath} from ${example}`);
  }
  return loadJson(configPath);
}

function loadManifest() {
  const manifestPath = path.join(artifactsDir, 'manifest.json');
  return fs.existsSync(manifestPath) ? loadJson(manifestPath) : null;
}

function loadArtifact(contractName) {
  const abiPath = path.join(artifactsDir, `${contractName}.abi`);
  const binPath = path.join(artifactsDir, `${contractName}.bin`);
  if (!fs.existsSync(abiPath) || !fs.existsSync(binPath)) {
    throw new Error(
      `Hyperion artifact missing for ${contractName} (expected ${abiPath} + ${binPath}). ` +
        'Run `npm run compile` first.'
    );
  }
  const bytecode = fs.readFileSync(binPath, 'utf8').trim();
  if (bytecode.length === 0) {
    throw new Error(`${contractName} has empty creation bytecode`);
  }
  return { abi: loadJson(abiPath), bytecode: `0x${bytecode}` };
}

function withGasMargin(estimate, cap) {
  const padded = (BigInt(estimate) * 12n) / 10n;
  return cap && padded > cap ? cap : padded;
}

function formatQuanta(planck) {
  const whole = planck / PLANCK_PER_QUANTA;
  const frac = (planck % PLANCK_PER_QUANTA).toString().padStart(18, '0').slice(0, 6);
  return `${whole}.${frac}`;
}

async function deployContract(rpc, sender, contractName, constructorArgsHex = '', gasCap = null) {
  const artifact = loadArtifact(contractName);
  const data = artifact.bytecode + constructorArgsHex;
  console.log(
    `\nDeploying ${contractName}${constructorArgsHex ? ' (with constructor args)' : ''}...`
  );

  const estimate = await sender.estimateGas({ data });
  const gas = withGasMargin(estimate, gasCap);
  console.log(`  gas estimate: ${estimate} (sending with ${gas})`);

  const receipt = await sender.send({ data, gas: toQuantity(gas) });
  if (Number(receipt.status) !== 1) {
    throw new Error(`${contractName} deployment reverted in tx ${receipt.transactionHash}`);
  }
  const address = receipt.contractAddress;
  if (!address) {
    throw new Error(`${contractName} receipt has no contractAddress`);
  }
  const code = await rpc.getCode(address);
  if (!code || code === '0x') {
    throw new Error(`no code at ${address} after deploying ${contractName}`);
  }
  console.log(`  address: ${address}`);
  console.log(`  tx: ${receipt.transactionHash}, gas used: ${Number(receipt.gasUsed)}`);
  console.log(`  runtime code on chain: ${(code.length - 2) / 2} bytes`);
  return { address, receipt };
}

async function main() {
  const configPath = resolveConfigPath();
  const config = loadConfig(configPath);
  const manifest = loadManifest();

  console.log('='.repeat(60));
  console.log('QuantaProof deployment');
  console.log('='.repeat(60));
  console.log(`Provider:         ${config.rpcUrl}`);
  console.log(`Expected chainId: ${config.chainId}`);
  console.log(`Compiler:         ${manifest?.compilerVersion || 'unknown'}`);
  console.log(`Plonky3:          ${manifest?.plonky3Version || 'unknown'}`);

  const rpc = new RpcClient(config.rpcUrl);
  const chainId = await rpc.chainId();
  console.log(`Connected chainId: ${chainId}`);
  if (chainId !== Number(config.chainId)) {
    throw new Error(`chainId mismatch: expected ${config.chainId}, got ${chainId}`);
  }

  const sender = await getSender(rpc, { repoRoot, chainId });
  const balance = await rpc.getBalance(sender.address);
  console.log(`Deployer (${sender.kind}): ${sender.address}`);
  console.log(`Balance: ${formatQuanta(balance)} Quanta`);

  const latest = await rpc.getBlockByNumber('latest');
  const gasCap = latest?.gasLimit ? BigInt(latest.gasLimit) : null;
  console.log(`Block gas limit: ${gasCap ?? 'unknown'}`);

  const verifier = await deployContract(rpc, sender, 'StarkVerifier', '', gasCap);
  const gasMeter = await deployContract(
    rpc,
    sender,
    'StarkVerifierGasMeter',
    addressHex(verifier.address),
    gasCap
  );

  if (config.contracts && Object.values(config.contracts).some(Boolean)) {
    config.previousContracts = config.contracts;
  }
  config.contracts = {
    ...(config.contracts || {}),
    StarkVerifier: verifier.address,
    StarkVerifierGasMeter: gasMeter.address,
  };
  config.deployedAt = new Date().toISOString();
  config.deployer = sender.address;
  config.buildTarget = 'hyperion';
  config.compilerVersion = manifest?.compilerVersion || 'unknown';
  config.plonky3Version = manifest?.plonky3Version || 'unknown';

  fs.writeFileSync(configPath, JSON.stringify(config, null, 2) + '\n');

  console.log('\n' + '='.repeat(60));
  console.log('Deployment complete. Addresses written to:');
  console.log(`  ${configPath}`);
  console.log('='.repeat(60));
  for (const [name, addr] of Object.entries(config.contracts)) {
    console.log(`  ${name.padEnd(24)} ${addr ?? '(not deployed)'}`);
  }
}

if (require.main === module) {
  main().catch((err) => {
    console.error('\nDeployment failed:', err.message);
    if (err.data) console.error('Data:', err.data);
    process.exit(1);
  });
}

module.exports = { deployContract, loadArtifact, loadConfig, resolveConfigPath, withGasMargin };
