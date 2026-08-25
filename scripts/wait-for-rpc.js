// Poll a QRL 2.0 execution RPC until it answers qrl_chainId with the expected
// chain id. Used by kurtosis-start.sh; also handy for the dev node:
//   node scripts/wait-for-rpc.js http://127.0.0.1:8545 1337

const rpcUrl = process.argv[2];
const expectedChainId = Number(process.argv[3]);
const maxAttempts = Number(process.env.STARK_RPC_WAIT_ATTEMPTS || 90);

if (!rpcUrl || !Number.isSafeInteger(expectedChainId)) {
  throw new Error('usage: node wait-for-rpc.js <rpc-url> <chain-id>');
}

function delay(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

async function readChainId() {
  const response = await fetch(rpcUrl, {
    method: 'POST',
    headers: { 'content-type': 'application/json' },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: 1,
      method: 'qrl_chainId',
      params: [],
    }),
  });
  if (!response.ok) {
    throw new Error(`HTTP ${response.status}`);
  }
  const payload = await response.json();
  if (payload.error) {
    throw new Error(payload.error.message || JSON.stringify(payload.error));
  }
  return Number(payload.result);
}

async function main() {
  for (let attempt = 1; attempt <= maxAttempts; attempt += 1) {
    try {
      const chainId = await readChainId();
      if (chainId !== expectedChainId) {
        throw new Error(
          `chainId mismatch at ${rpcUrl}: expected ${expectedChainId}, got ${chainId}`
        );
      }
      console.log(`Execution RPC ready on chainId ${chainId}`);
      return;
    } catch (error) {
      if (String(error.message).startsWith('chainId mismatch')) {
        throw error;
      }
      if (attempt % 10 === 0) {
        console.log(`Waiting for execution RPC (${attempt}/${maxAttempts})`);
      }
      await delay(2000);
    }
  }
  throw new Error(`Execution RPC did not become ready at ${rpcUrl}`);
}

main().catch((error) => {
  console.error(error.message);
  process.exit(1);
});
