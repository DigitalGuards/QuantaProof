// Sender selection for the two local signing paths.
//
// gqrl --dev (chain 1337): the node holds one unlocked, pre-funded developer
// account; qrl_accounts()[0] is the sender and qrl_sendTransaction lets the
// node sign. Any other chain (Kurtosis 3151909, public testnets): the
// transaction is signed locally by @theqrl/web3 with an account from
// scripts/lib/loadDeployer.js (STARK_PUBLIC_DEV_ACCOUNT or TESTNET_SEED).
//
// Both paths return the same sender shape:
//   { kind, address, chainId, estimateGas(tx) -> BigInt, send(tx) -> receipt }
// where receipt is the raw JSON-RPC receipt from qrl_getTransactionReceipt.

const path = require('path');

const { loadDeployerFromEnvironment } = require('./loadDeployer');

const DEV_CHAIN_ID = 1337;
const defaultRepoRoot = path.join(__dirname, '..', '..');

async function getDevAccount(rpc) {
  const accounts = await rpc.accounts();
  if (!accounts || accounts.length === 0) {
    throw new Error(`no unlocked accounts at ${rpc.url}; is this a gqrl --dev node?`);
  }
  return accounts[0];
}

function devSender(rpc, address, chainId) {
  return {
    kind: 'dev',
    address,
    chainId,
    estimateGas: (tx) => rpc.estimateGas({ from: address, ...tx }),
    async send(tx, options = {}) {
      const hash = await rpc.sendTransaction({ from: address, ...tx });
      return rpc.waitForReceipt(hash, options);
    },
  };
}

function seedSender(rpc, web3, account, chainId) {
  return {
    kind: 'seed',
    address: account.address,
    chainId,
    estimateGas: (tx) => rpc.estimateGas({ from: account.address, ...tx }),
    async send(tx, options = {}) {
      const sent = await web3.qrl.sendTransaction({ from: account.address, ...tx });
      // Re-read through JSON-RPC so both signing paths return one receipt shape.
      return rpc.waitForReceipt(sent.transactionHash, options);
    },
  };
}

async function getSender(rpc, options = {}) {
  const { repoRoot = defaultRepoRoot, env = process.env } = options;
  const chainId = options.chainId ?? (await rpc.chainId());
  if (chainId === DEV_CHAIN_ID) {
    return devSender(rpc, await getDevAccount(rpc), chainId);
  }
  const { Web3 } = require('@theqrl/web3');
  const web3 = new Web3(rpc.url);
  const account = loadDeployerFromEnvironment(web3, {
    repoRoot,
    rpcUrl: rpc.url,
    chainId,
    env,
  });
  return seedSender(rpc, web3, account, chainId);
}

module.exports = { DEV_CHAIN_ID, getDevAccount, getSender };
