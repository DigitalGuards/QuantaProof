const assert = require('node:assert/strict');
const test = require('node:test');

const {
  assertProtocolChainId,
  assertProtocolRpcUrl,
  gateEnvironment,
} = require('../../scripts/protocol-gate');

test('full protocol gate accepts only loopback RPC endpoints', () => {
  assert.doesNotThrow(() => assertProtocolRpcUrl('http://127.0.0.1:8545'));
  assert.doesNotThrow(() => assertProtocolRpcUrl('http://localhost:32102'));
  assert.doesNotThrow(() => assertProtocolRpcUrl('http://[::1]:8545'));
  assert.throws(() => assertProtocolRpcUrl('https://testnet.example'), /loopback host/);
  assert.throws(() => assertProtocolRpcUrl(''), /STARK_RPC_URL is required/);
});

test('full protocol gate accepts only its two local chain ids', () => {
  assert.doesNotThrow(() => assertProtocolChainId(1337));
  assert.doesNotThrow(() => assertProtocolChainId(3151909));
  assert.throws(() => assertProtocolChainId(1), /outside the protocol gate/);
});

test('full protocol gate pins its profile and removes test filters', () => {
  const env = gateEnvironment({
    KEEP_ME: 'yes',
    HYPERION_OPTIMIZE_RUNS: '1',
    HYPERION_VIA_IR: '1',
    STARK_RANDOM_OPS: '2',
    STARK_FRI_VECTORS: 'fib_c3_n10',
    STARK_MERKLE_VECTORS: 'fib_c3_n10',
    STARK_SKIP_MUTATIONS: '1',
    STARK_STARK_VECTORS: 'fib_c3_n10',
    STARK_VECTORS_LARGE: '1',
  });
  assert.equal(env.KEEP_ME, 'yes');
  assert.equal(env.HYPERION_OPTIMIZE_RUNS, '200');
  assert.equal(env.HYPERION_VIA_IR, '0');
  assert.equal(env.STARK_RANDOM_OPS, '10000');
  for (const name of [
    'STARK_FRI_VECTORS',
    'STARK_MERKLE_VECTORS',
    'STARK_SKIP_MUTATIONS',
    'STARK_STARK_VECTORS',
    'STARK_VECTORS_LARGE',
  ]) {
    assert.equal(env[name], undefined);
  }
});
