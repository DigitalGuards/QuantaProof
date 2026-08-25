// Guards of the deployer loader (ported from the QNS suite): fixture parsing,
// the loopback + chain-id restriction on STARK_PUBLIC_DEV_ACCOUNT, and the
// precedence of an explicit public fixture over an ambient TESTNET_SEED.

const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const test = require('node:test');

const {
  LOCAL_KURTOSIS_CHAIN_ID,
  isLoopbackRpcUrl,
  loadDeployerFromEnvironment,
  parsePublicDevSeeds,
} = require('../../scripts/lib/loadDeployer');

function writeFixturePackage(t, seedHex) {
  const packageDir = fs.mkdtempSync(path.join(os.tmpdir(), 'stark-public-fixture-'));
  t.after(() => fs.rmSync(packageDir, { recursive: true, force: true }));
  const constantsDir = path.join(
    packageDir,
    'src',
    'prelaunch_data_generator',
    'genesis_constants'
  );
  fs.mkdirSync(constantsDir, { recursive: true });
  fs.writeFileSync(
    path.join(constantsDir, 'genesis_constants.star'),
    `new_prefunded_account("Q${'12'.repeat(64)}", "${seedHex}")\n`
  );
  return packageDir;
}

test('the local Kurtosis chain id is 3151909', () => {
  assert.equal(LOCAL_KURTOSIS_CHAIN_ID, 3151909);
});

test('parses public development seeds from the Kurtosis fixture', () => {
  const firstSeed = '01'.repeat(51);
  const secondSeed = 'ab'.repeat(51);
  const source = `
        new_prefunded_account(
            "Q${'12'.repeat(64)}",
            "${firstSeed}",
        ),
        new_prefunded_account("Q${'34'.repeat(64)}", "${secondSeed}"),
    `;

  assert.deepEqual(parsePublicDevSeeds(source), [firstSeed, secondSeed]);
});

test('recognizes only loopback RPC URLs', () => {
  assert.equal(isLoopbackRpcUrl('http://127.0.0.1:32102'), true);
  assert.equal(isLoopbackRpcUrl('http://localhost:32102'), true);
  assert.equal(isLoopbackRpcUrl('http://[::1]:32102'), true);
  assert.equal(isLoopbackRpcUrl('https://testnet.example:32102'), false);
  assert.equal(isLoopbackRpcUrl('not a URL'), false);
});

test('explicit local public account overrides a configured private seed', (t) => {
  const publicSeed = '01'.repeat(51);
  const packageDir = writeFixturePackage(t, publicSeed);

  const selectedSeeds = [];
  const wallet = { add() {} };
  const web3 = {
    qrl: {
      accounts: {
        seedToAccount(seed) {
          selectedSeeds.push(seed);
          return { address: `Q${'34'.repeat(64)}` };
        },
        wallet,
      },
      wallet,
    },
  };

  loadDeployerFromEnvironment(web3, {
    repoRoot: packageDir,
    rpcUrl: 'http://127.0.0.1:32102',
    chainId: 3151909,
    env: {
      STARK_PUBLIC_DEV_ACCOUNT: '0',
      QRL_PACKAGE_DIR: packageDir,
      TESTNET_SEED: `0x${'ab'.repeat(51)}`,
    },
  });

  assert.deepEqual(selectedSeeds, [`0x${publicSeed}`]);
});

test('the RPC URL falls back to STARK_RPC_URL from the environment', (t) => {
  const publicSeed = '02'.repeat(51);
  const packageDir = writeFixturePackage(t, publicSeed);
  const selectedSeeds = [];
  const wallet = { add() {} };
  const web3 = {
    qrl: {
      accounts: {
        seedToAccount(seed) {
          selectedSeeds.push(seed);
          return { address: `Q${'34'.repeat(64)}` };
        },
        wallet,
      },
      wallet,
    },
  };

  loadDeployerFromEnvironment(web3, {
    repoRoot: packageDir,
    chainId: 3151909,
    env: {
      STARK_RPC_URL: 'http://127.0.0.1:32102',
      STARK_PUBLIC_DEV_ACCOUNT: '0',
      QRL_PACKAGE_DIR: packageDir,
    },
  });

  assert.deepEqual(selectedSeeds, [`0x${publicSeed}`]);
});

test('public account selector refuses a non-loopback RPC URL', () => {
  assert.throws(
    () =>
      loadDeployerFromEnvironment(
        {},
        {
          repoRoot: os.tmpdir(),
          rpcUrl: 'https://testnet.example:32102',
          chainId: 3151909,
          env: { STARK_PUBLIC_DEV_ACCOUNT: '0' },
        }
      ),
    /restricted to the local Kurtosis network/
  );
});

test('public account selector refuses the QNS chain and the dev node chain', () => {
  for (const chainId of [3151908, 1337]) {
    assert.throws(
      () =>
        loadDeployerFromEnvironment(
          {},
          {
            repoRoot: os.tmpdir(),
            rpcUrl: 'http://127.0.0.1:32102',
            chainId,
            env: { STARK_PUBLIC_DEV_ACCOUNT: '0' },
          }
        ),
      /restricted to the local Kurtosis network/
    );
  }
});

test('public account selector validates the index format', () => {
  for (const badIndex of ['abc', '-1', '01', '1.5']) {
    assert.throws(
      () =>
        loadDeployerFromEnvironment(
          {},
          {
            repoRoot: os.tmpdir(),
            rpcUrl: 'http://127.0.0.1:32102',
            chainId: 3151909,
            env: { STARK_PUBLIC_DEV_ACCOUNT: badIndex },
          }
        ),
      /non-negative integer/
    );
  }
});

test('public account selector rejects an out-of-range index', (t) => {
  const packageDir = writeFixturePackage(t, '01'.repeat(51));

  assert.throws(
    () =>
      loadDeployerFromEnvironment(
        {},
        {
          repoRoot: packageDir,
          rpcUrl: 'http://127.0.0.1:32102',
          chainId: 3151909,
          env: { STARK_PUBLIC_DEV_ACCOUNT: '5', QRL_PACKAGE_DIR: packageDir },
        }
      ),
    /absent from/
  );
});

test('a seed that is neither hex nor a 34-word mnemonic is rejected', () => {
  assert.throws(
    () =>
      loadDeployerFromEnvironment(
        {},
        {
          repoRoot: os.tmpdir(),
          rpcUrl: 'http://127.0.0.1:32102',
          chainId: 3151909,
          env: { TESTNET_SEED: 'definitely not a seed' },
        }
      ),
    /34-word ML-DSA-87 mnemonic/
  );
});

test('throws when no deployer secret is configured at all', () => {
  assert.throws(
    () =>
      loadDeployerFromEnvironment(
        {},
        {
          repoRoot: os.tmpdir(),
          rpcUrl: 'http://127.0.0.1:32102',
          chainId: 3151909,
          env: {},
        }
      ),
    /Set TESTNET_SEED/
  );
});
