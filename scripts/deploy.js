// Deploy StarkVerifier per preset (plus one StarkVerifierGasMeter per
// verifier) and, on request, the StarkFactRegistry and StateBridge skeleton
// to a QRL 2.0 network.
//
// Usage:
//   STARK_CONFIG=config/dev-node.json npm run deploy -- --preset all
//   STARK_CONFIG=config/dev-node.json npm run deploy -- --preset c1
//   STARK_CONFIG=config/local-stark.json STARK_PUBLIC_DEV_ACCOUNT=0 npm run deploy -- --preset c3
//   STARK_DEPLOY_BRIDGE=1 STARK_CONFIG=config/dev-node.json npm run deploy
//
// Options:
//   --preset <name|all>   preset(s) to deploy (default c3, the committed constants)
//   --bridge              deploy StarkFactRegistry + StateBridge (same as STARK_DEPLOY_BRIDGE=1)
//   --config <path>       deployment record (default STARK_CONFIG or config/local-stark.json)
//
// Every verifier is compiled from contracts/hyperion/StarkVerifier.hyp with
// the preset's six constants substituted (scripts/lib/presets.js) under the
// optimizer settings of HYPERION_OPTIMIZE_RUNS / HYPERION_VIA_IR, so the
// artifacts of `npm run compile` are never deployed directly. The bridge
// contracts always compile through the IR pipeline (legacy codegen defect,
// docs/compiler/HYPC-LEGACY-CODEGEN-DEFECTS.md); the registry's programId is
// keccak256("fibonacci-<preset>-v1") and the bridge starts from a zero root.
//
// The dev node (chain 1337) signs with its unlocked developer account. Any
// other chain needs STARK_PUBLIC_DEV_ACCOUNT (Kurtosis) or TESTNET_SEED.
// Addresses are written back into the config file as
//   contracts.verifiers[preset] = { verifier, gasMeter, compiler, runtimeBytes, ... }
//   contracts.bridge = { registry, bridge, preset, programId, ... }
// and the previous record moves to previousContracts. A missing config file
// is seeded from its .example.json.

const fs = require('fs');
const path = require('path');

require('dotenv').config({ path: path.join(__dirname, '..', '.env'), quiet: true });

const { RpcClient, toQuantity } = require('./lib/rpc');
const { getSender } = require('./lib/devAccount');
const abi = require('./lib/abi64');
const P = require('./lib/presets');
const { collectSources } = require('./hypc');
const { MAX_RUNTIME_BYTES } = require('./check-code-size');
const { readPlonky3Version } = require('./compile-hyperion');

const repoRoot = path.join(__dirname, '..');
const PLANCK_PER_QUANTA = 10n ** 18n;
const ZERO_ROOT = `0x${'00'.repeat(32)}`;

function parseArgs(argv, env = process.env) {
  const options = { preset: 'c3', bridge: env.STARK_DEPLOY_BRIDGE === '1', config: null };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    const next = () => {
      if (i + 1 >= argv.length) throw new Error(`${arg} needs a value`);
      i += 1;
      return argv[i];
    };
    if (arg === '--preset') options.preset = next();
    else if (arg === '--bridge') options.bridge = true;
    else if (arg === '--config') options.config = next();
    else throw new Error(`unknown option ${arg}`);
  }
  return options;
}

// "all" or a comma-separated list of preset names, validated against the table.
function selectPresets(spec) {
  if (spec === 'all') return P.presetNames();
  const names = spec
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
  if (names.length === 0) throw new Error('--preset needs at least one name');
  for (const name of names) P.presetConfig(name);
  return [...new Set(names)];
}

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

function withGasMargin(estimate, cap) {
  const padded = (BigInt(estimate) * 12n) / 10n;
  return cap && padded > cap ? cap : padded;
}

function formatQuanta(planck) {
  const whole = planck / PLANCK_PER_QUANTA;
  const frac = (planck % PLANCK_PER_QUANTA).toString().padStart(18, '0').slice(0, 6);
  return `${whole}.${frac}`;
}

// Deploy one compiled artifact ({ bytecode }) with optional raw constructor
// arguments (hex without 0x, 64-byte ABI words), estimate plus 20 percent
// capped at the block gas limit; verifies that code exists afterwards.
async function deployContract(
  rpc,
  sender,
  label,
  artifact,
  constructorArgsHex = '',
  gasCap = null
) {
  const data = artifact.bytecode + constructorArgsHex;
  console.log(`\nDeploying ${label}${constructorArgsHex ? ' (with constructor args)' : ''}...`);

  const estimate = await sender.estimateGas({ data });
  const gas = withGasMargin(estimate, gasCap);
  console.log(`  gas estimate: ${estimate} (sending with ${gas})`);

  const receipt = await sender.send({ data, gas: toQuantity(gas) });
  if (Number(receipt.status) !== 1) {
    throw new Error(`${label} deployment reverted in tx ${receipt.transactionHash}`);
  }
  const address = receipt.contractAddress;
  if (!address) {
    throw new Error(`${label} receipt has no contractAddress`);
  }
  const code = await rpc.getCode(address);
  if (!code || code === '0x') {
    throw new Error(`no code at ${address} after deploying ${label}`);
  }
  const runtimeBytes = (code.length - 2) / 2;
  console.log(`  address: ${address}`);
  console.log(`  tx: ${receipt.transactionHash}, gas used: ${Number(receipt.gasUsed)}`);
  console.log(`  runtime code on chain: ${runtimeBytes} bytes`);
  return { address, receipt, runtimeBytes, gasUsed: Number(receipt.gasUsed) };
}

function assertRuntimeSize(label, runtimeBytes) {
  if (runtimeBytes > MAX_RUNTIME_BYTES) {
    throw new Error(
      `${label}: runtime ${runtimeBytes} bytes exceeds the ${MAX_RUNTIME_BYTES}-byte cap; ` +
        'lower HYPERION_OPTIMIZE_RUNS or set HYPERION_VIA_IR=1 (docs/DECISIONS.md)'
    );
  }
}

// Whether a contracts record holds any address worth rotating.
function hasAddresses(contracts) {
  if (!contracts || typeof contracts !== 'object') return false;
  const verifiers =
    contracts.verifiers && typeof contracts.verifiers === 'object' ? contracts.verifiers : {};
  if (Object.keys(verifiers).length > 0) return true;
  if (contracts.bridge && typeof contracts.bridge === 'object') return true;
  // Records written before the per-preset layout kept flat addresses.
  return Object.values(contracts).some((v) => typeof v === 'string' && v.length > 0);
}

// Deploy one preset's verifier and its gas meter; returns the config entry.
async function deployPreset(ctx, name, sources, meter) {
  const { rpc, sender, gasCap, compilerVersion } = ctx;
  console.log(`\n${'-'.repeat(60)}\nPreset ${name}: ${JSON.stringify(P.presetConfig(name))}`);
  const compiled = P.compileVerifierForPreset(name, { sources });
  console.log(
    `  compiled StarkVerifier[${name}]: ${compiled.runtimeBytes} runtime bytes ` +
      `(${P.settingsLabel(compiled.settings)})`
  );
  assertRuntimeSize(`StarkVerifier[${name}]`, compiled.runtimeBytes);

  const verifier = await deployContract(
    rpc,
    sender,
    `StarkVerifier[${name}]`,
    compiled.artifact,
    '',
    gasCap
  );
  const gasMeter = await deployContract(
    rpc,
    sender,
    `StarkVerifierGasMeter[${name}]`,
    meter.artifact,
    abi.addressHex(verifier.address),
    gasCap
  );
  return {
    verifier: verifier.address,
    gasMeter: gasMeter.address,
    config: compiled.config,
    compiler: {
      version: compilerVersion,
      runs: compiled.settings.optimizerRuns,
      viaIr: compiled.settings.viaIr,
    },
    runtimeBytes: compiled.runtimeBytes,
    gasMeterRuntimeBytes: meter.runtimeBytes,
    deployGas: { verifier: verifier.gasUsed, gasMeter: gasMeter.gasUsed },
    deployTx: {
      verifier: verifier.receipt.transactionHash,
      gasMeter: gasMeter.receipt.transactionHash,
    },
    deployedAt: new Date().toISOString(),
  };
}

// Registry bound to `preset`'s verifier, then the bridge on top of it.
async function deployBridge(ctx, preset, verifierAddress, sources) {
  const { rpc, sender, gasCap, compilerVersion } = ctx;
  console.log(
    `\n${'-'.repeat(60)}\nBridge skeleton bound to StarkVerifier[${preset}] (IR pipeline)`
  );
  const compiled = P.compileBridge({ sources });
  console.log(
    `  compiled StarkFactRegistry: ${compiled.registry.runtimeBytes} runtime bytes, ` +
      `StateBridge: ${compiled.bridge.runtimeBytes} runtime bytes (${P.settingsLabel(compiled.settings)})`
  );
  assertRuntimeSize('StarkFactRegistry', compiled.registry.runtimeBytes);
  assertRuntimeSize('StateBridge', compiled.bridge.runtimeBytes);

  const programId = P.programIdFor(preset);
  const registryArgs =
    abi.addressHex(verifierAddress) + Buffer.from(abi.encodeBytes32(programId)).toString('hex');
  const registry = await deployContract(
    rpc,
    sender,
    'StarkFactRegistry',
    compiled.registry.artifact,
    registryArgs,
    gasCap
  );
  const bridgeArgs =
    abi.addressHex(registry.address) +
    Buffer.from(abi.encodeBytes32(programId)).toString('hex') +
    abi.addressHex(verifierAddress) +
    Buffer.from(abi.encodeBytes32(ZERO_ROOT)).toString('hex');
  const bridge = await deployContract(
    rpc,
    sender,
    'StateBridge',
    compiled.bridge.artifact,
    bridgeArgs,
    gasCap
  );
  return {
    registry: registry.address,
    bridge: bridge.address,
    verifier: verifierAddress,
    preset,
    programId,
    genesisRoot: ZERO_ROOT,
    compiler: {
      version: compilerVersion,
      runs: compiled.settings.optimizerRuns,
      viaIr: true,
    },
    runtimeBytes: {
      registry: compiled.registry.runtimeBytes,
      bridge: compiled.bridge.runtimeBytes,
    },
    deployGas: { registry: registry.gasUsed, bridge: bridge.gasUsed },
    deployTx: {
      registry: registry.receipt.transactionHash,
      bridge: bridge.receipt.transactionHash,
    },
    deployedAt: new Date().toISOString(),
  };
}

// The verifier the bridge binds to: c3 when it is among the deployed presets
// (the committed default), otherwise the first deployed preset.
function bridgePreset(deployedPresets) {
  return deployedPresets.includes('c3') ? 'c3' : deployedPresets[0];
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  const presets = selectPresets(options.preset);
  const configPath = options.config ? path.resolve(repoRoot, options.config) : resolveConfigPath();
  const config = loadConfig(configPath);
  const compilerVersion = P.compilerVersion();
  const plonky3Version = readPlonky3Version();
  const settings = P.optimizerSettings();

  console.log('='.repeat(60));
  console.log('QuantaStark deployment');
  console.log('='.repeat(60));
  console.log(`Provider:         ${config.rpcUrl}`);
  console.log(`Expected chainId: ${config.chainId}`);
  console.log(`Compiler:         ${compilerVersion} (${P.settingsLabel(settings)})`);
  console.log(`Plonky3:          ${plonky3Version}`);
  console.log(`Presets:          ${presets.join(', ')}`);
  console.log(`Bridge:           ${options.bridge ? 'yes' : 'no'}`);

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

  const ctx = { rpc, sender, gasCap, compilerVersion };
  const sources = collectSources();
  const meter = P.compileGasMeter({ sources });
  console.log(`\nCompiled StarkVerifierGasMeter: ${meter.runtimeBytes} runtime bytes`);

  const verifiers = {};
  for (const name of presets) {
    verifiers[name] = await deployPreset(ctx, name, sources, meter);
  }
  const bridge = options.bridge
    ? await deployBridge(
        ctx,
        bridgePreset(presets),
        verifiers[bridgePreset(presets)].verifier,
        sources
      )
    : null;

  if (hasAddresses(config.contracts)) {
    config.previousContracts = config.contracts;
  }
  const previousVerifiers =
    config.contracts?.verifiers && typeof config.contracts.verifiers === 'object'
      ? config.contracts.verifiers
      : {};
  config.contracts = {
    verifiers: { ...previousVerifiers, ...verifiers },
    bridge: bridge ?? config.contracts?.bridge ?? null,
  };
  config.deployedAt = new Date().toISOString();
  config.deployer = sender.address;
  config.buildTarget = 'hyperion';
  config.compilerVersion = compilerVersion;
  config.optimizer = { runs: settings.optimizerRuns, viaIr: settings.viaIr };
  config.plonky3Version = plonky3Version;

  fs.writeFileSync(configPath, JSON.stringify(config, null, 2) + '\n');

  console.log('\n' + '='.repeat(60));
  console.log('Deployment complete. Addresses written to:');
  console.log(`  ${configPath}`);
  console.log('='.repeat(60));
  for (const [name, entry] of Object.entries(config.contracts.verifiers)) {
    const fresh = verifiers[name] ? '' : ' (kept from an earlier run)';
    console.log(`  ${`StarkVerifier[${name}]`.padEnd(32)} ${entry.verifier}${fresh}`);
    console.log(`  ${`StarkVerifierGasMeter[${name}]`.padEnd(32)} ${entry.gasMeter}${fresh}`);
  }
  if (config.contracts.bridge) {
    const b = config.contracts.bridge;
    const fresh = bridge ? '' : ' (kept from an earlier run)';
    console.log(`  ${'StarkFactRegistry'.padEnd(32)} ${b.registry}${fresh}`);
    console.log(`  ${'StateBridge'.padEnd(32)} ${b.bridge}${fresh}`);
  }
}

if (require.main === module) {
  main().catch((err) => {
    console.error('\nDeployment failed:', err.message);
    if (err.data) console.error('Data:', err.data);
    process.exit(1);
  });
}

module.exports = {
  ZERO_ROOT,
  bridgePreset,
  deployContract,
  hasAddresses,
  loadConfig,
  parseArgs,
  resolveConfigPath,
  selectPresets,
  withGasMargin,
};
