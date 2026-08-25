# Contract suites

`node --test test/contracts/*.test.js` runs every suite in this directory
against a live QRVM. Each file must skip itself when `STARK_RPC_URL` is unset,
so `npm run test:contracts` is safe on CI and on a workstation without a node:

```js
const test = require('node:test');
const assert = require('node:assert/strict');

const rpcUrl = process.env.STARK_RPC_URL;
const skip = rpcUrl ? false : 'set STARK_RPC_URL to run against a node';

test('Goldilocks harness', { skip, timeout: 600000 }, async (t) => {
  const { RpcClient } = require('../../scripts/lib/rpc');
  const { getSender } = require('../../scripts/lib/devAccount');
  const { compileFiles } = require('../../scripts/hypc');

  const rpc = new RpcClient(rpcUrl);
  const sender = await getSender(rpc);
  const { GoldilocksHarness } = compileFiles(['test/GoldilocksHarness.hyp']);
  const receipt = await sender.send({ data: GoldilocksHarness.bytecode, gas: 8000000 });
  assert.equal(Number(receipt.status), 1);
  // ... qrl_call the harness through rpc.qrlCall({ to: receipt.contractAddress, data })
});
```

Conventions:

- Harnesses live in `contracts/hyperion/test/*Harness.hyp` and are compiled on
  the fly through `scripts/hypc.js` (`compileFiles` hands the whole
  `contracts/hyperion/` tree to hypc, so `import "../lib/Goldilocks.hyp";`
  resolves). `HYPERION_COMPILER` must point at the 64-byte compiler.
- `scripts/lib/devAccount.js` picks the sender: the unlocked developer
  account on the gqrl dev node (chain 1337, node-signed `qrl_sendTransaction`)
  or a locally signed fixture account on Kurtosis (chain 3151909,
  `STARK_PUBLIC_DEV_ACCOUNT=0`). Both return the raw JSON-RPC receipt.
- Calldata and return data use the 64-byte-word ABI. `test/lib/abi.js` is the
  reference encoder; `scripts/lib/abi64.js` covers the toolchain's needs.
- Vectors come from `test/vectors/*.json`. Suites that need a vector size the
  prover does not track (`test/vectors/large/`, ignored) skip with a message
  naming the `npm run prover:vectors` invocation that produces it.
- Deploy once per file inside the test and reuse the address across subtests;
  the dev node keeps its chain between runs, so never depend on a fresh state.
- Report gas from receipts (`gasUsed`) and from `qrl_estimateGas`; the
  `StarkVerifierGasMeter` event carries the inner STATICCALL cost.

Environment:

```bash
npm run dev-node &
STARK_RPC_URL=http://127.0.0.1:8545 HYPERION_COMPILER=../hyperion-stark/build/hypc/hypc npm run test:contracts
```
