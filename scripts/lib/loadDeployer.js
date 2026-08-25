// Deployer account loader for networks that need locally signed transactions
// (Kurtosis or a public testnet). Adapted from the QNS loader (GPL-3.0).
// QRL 2.0 uses 34-word ML-DSA-87 mnemonics and 51-byte extended seeds.
//
// The gqrl dev node (chain 1337) signs with its own unlocked account and
// never goes through this loader; see scripts/lib/devAccount.js.

const fs = require('fs');
const path = require('path');

const { MLDSA87 } = require('@theqrl/wallet.js');

const MNEMONIC_WORDS = 34;
const EXTENDED_SEED_HEX_LENGTH = 102;
const LOCAL_KURTOSIS_CHAIN_ID = 3151909;

function loadDeployer(web3, secret) {
  const value = secret?.trim() || '';
  const rawHex = value.replace(/^0x/i, '');
  let seedHex;

  if (rawHex.length === EXTENDED_SEED_HEX_LENGTH && /^[0-9a-fA-F]+$/.test(rawHex)) {
    seedHex = `0x${rawHex}`;
  } else if (value.split(/\s+/).length === MNEMONIC_WORDS) {
    const wallet = MLDSA87.newWalletFromMnemonic(value);
    seedHex = wallet.getHexExtendedSeed();
  } else {
    throw new Error(
      `Deployer seed must be a ${MNEMONIC_WORDS}-word ML-DSA-87 mnemonic ` +
        `or a ${EXTENDED_SEED_HEX_LENGTH}-character extended-seed hex value.`
    );
  }

  const account = web3.qrl.accounts.seedToAccount(seedHex);
  web3.qrl.accounts.wallet.add(account);
  if (
    web3.qrl.wallet &&
    web3.qrl.wallet !== web3.qrl.accounts.wallet &&
    typeof web3.qrl.wallet.add === 'function'
  ) {
    web3.qrl.wallet.add(seedHex);
  }
  return account;
}

function parsePublicDevSeeds(source) {
  const seeds = [];
  const pattern = /new_prefunded_account\(\s*"Q[0-9a-fA-F]{128}",\s*"([0-9a-fA-F]{102})",?\s*\)/g;
  let match;
  while ((match = pattern.exec(source)) !== null) {
    seeds.push(match[1]);
  }
  return seeds;
}

function isLoopbackRpcUrl(rpcUrl) {
  let parsed;
  try {
    parsed = new URL(rpcUrl);
  } catch {
    return false;
  }
  return ['127.0.0.1', 'localhost', '[::1]'].includes(parsed.hostname);
}

function loadPublicDevSeed(repoRoot, accountIndex, env = process.env) {
  if (!/^(0|[1-9][0-9]*)$/.test(accountIndex)) {
    throw new Error('STARK_PUBLIC_DEV_ACCOUNT must be a non-negative integer');
  }

  const packageDir = env.QRL_PACKAGE_DIR
    ? path.resolve(env.QRL_PACKAGE_DIR)
    : path.resolve(repoRoot, '..', 'qrl-package');
  const constantsPath = path.join(
    packageDir,
    'src',
    'prelaunch_data_generator',
    'genesis_constants',
    'genesis_constants.star'
  );
  const seeds = parsePublicDevSeeds(fs.readFileSync(constantsPath, 'utf8'));
  const index = Number(accountIndex);
  if (!seeds[index]) {
    throw new Error(`Public development account #${index} is absent from ${constantsPath}`);
  }
  return seeds[index];
}

// Resolution order: an explicit STARK_PUBLIC_DEV_ACCOUNT (loopback RPC URL
// and chain 3151909 only) beats an ambient TESTNET_SEED, so an ignored .env
// seed can never sign a local deployment by accident.
function loadDeployerFromEnvironment(web3, options) {
  const { repoRoot, chainId, env = process.env } = options;
  const rpcUrl = options.rpcUrl ?? env.STARK_RPC_URL;
  const publicDevAccount = env.STARK_PUBLIC_DEV_ACCOUNT?.trim();
  if (publicDevAccount) {
    if (!isLoopbackRpcUrl(rpcUrl) || Number(chainId) !== LOCAL_KURTOSIS_CHAIN_ID) {
      throw new Error(
        'STARK_PUBLIC_DEV_ACCOUNT is restricted to the local Kurtosis network ' +
          `(loopback RPC URL, chain ${LOCAL_KURTOSIS_CHAIN_ID})`
      );
    }
    const seed = loadPublicDevSeed(repoRoot, publicDevAccount, env);
    return loadDeployer(web3, seed);
  }

  if (env.TESTNET_SEED?.trim()) {
    return loadDeployer(web3, env.TESTNET_SEED);
  }

  throw new Error(
    'Set TESTNET_SEED, or select a published local Kurtosis account with STARK_PUBLIC_DEV_ACCOUNT'
  );
}

module.exports = {
  LOCAL_KURTOSIS_CHAIN_ID,
  isLoopbackRpcUrl,
  loadDeployer,
  loadDeployerFromEnvironment,
  loadPublicDevSeed,
  parsePublicDevSeeds,
};
