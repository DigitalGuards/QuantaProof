const assert = require('node:assert/strict');
const test = require('node:test');

const abi = require('../../scripts/lib/abi64');
const P = require('../../scripts/lib/presets');
const {
  BRIDGE_PUBLIC_VALUES_LENGTH,
  assertBridgeVerifierCompatible,
  assertSoundnessDeploymentPolicy,
  parseArgs,
  resolveBridgeBinding,
  selectPresets,
  verifierProgramIdentifier,
  verifierPublicValuesLength,
} = require('../../scripts/deploy');

const VERIFIER = `Q${'12'.repeat(64)}`;
const PROGRAM_ID = `0x${'34'.repeat(32)}`;

test('bridge deployment needs an explicit verifier and program id', () => {
  assert.equal(resolveBridgeBinding(parseArgs([], {})), null);
  assert.throws(
    () => resolveBridgeBinding(parseArgs(['--bridge'], {})),
    /needs --bridge-verifier and --bridge-program-id/
  );

  const options = parseArgs(['--bridge-verifier', VERIFIER, '--bridge-program-id', PROGRAM_ID], {});
  assert.equal(options.bridge, true);
  assert.equal(options.preset, 'none');
  assert.deepEqual(resolveBridgeBinding(options), {
    verifier: VERIFIER,
    programId: PROGRAM_ID,
  });
});

test('bridge deployment reads its binding from the environment', () => {
  const options = parseArgs([], {
    STARK_DEPLOY_BRIDGE: '1',
    STARK_BRIDGE_VERIFIER: VERIFIER,
    STARK_BRIDGE_PROGRAM_ID: PROGRAM_ID,
  });
  assert.deepEqual(resolveBridgeBinding(options), {
    verifier: VERIFIER,
    programId: PROGRAM_ID,
  });
});

test('bridge binding validates the address and bytes32 shapes', () => {
  assert.throws(
    () =>
      resolveBridgeBinding({
        bridge: true,
        bridgeVerifier: 'Q1234',
        bridgeProgramId: PROGRAM_ID,
      }),
    /expected a 64-byte QRL address/
  );
  assert.throws(
    () =>
      resolveBridgeBinding({
        bridge: true,
        bridgeVerifier: VERIFIER,
        bridgeProgramId: '0x1234',
      }),
    /bytes32 needs 32 bytes/
  );
});

test('current presets are benchmark profiles', () => {
  assert.deepEqual(P.presetSecurity('c3'), {
    profile: 'benchmark',
    status: 'experimental',
    conjecturedBits: 118,
    productionReady: false,
  });
  const c3 = P.presetConfig('c3');
  const expectedProgramId = abi.keccak256Hex(
    abi.concatBytes([
      new TextEncoder().encode('QSTARK-FIBONACCI-v1'),
      abi.encodeUint(24),
      ...P.PRESET_KEYS.map((key) => abi.encodeUint(c3[key])),
    ])
  );
  assert.equal(P.programIdFor('c3'), expectedProgramId);
  assert.notEqual(P.programIdFor('c2'), expectedProgramId);
});

test('bridge-only deployment skips Fibonacci presets unless requested', () => {
  assert.deepEqual(selectPresets(parseArgs(['--bridge'], {}).preset), []);
  assert.deepEqual(selectPresets(parseArgs(['--preset', 'c3', '--bridge'], {}).preset), ['c3']);
});

test('experimental soundness is automatic only on the two local chains', () => {
  assert.doesNotThrow(() => assertSoundnessDeploymentPolicy(1337, ['c3'], false));
  assert.doesNotThrow(() => assertSoundnessDeploymentPolicy(3151909, ['c3'], false));
  assert.throws(() => assertSoundnessDeploymentPolicy(42, ['c3'], false), /experimental security/);
  assert.throws(
    () => assertSoundnessDeploymentPolicy(42, [], false, true),
    /experimental security/
  );
  assert.doesNotThrow(() => assertSoundnessDeploymentPolicy(42, ['c3'], true));
});

test('bridge verifier preflight requires code and 128 public-value bytes', async () => {
  const compatible = {
    async getCode(address) {
      assert.equal(address, VERIFIER);
      return '0x01';
    },
    async qrlCall(tx) {
      assert.equal(tx.to, VERIFIER);
      if (tx.data === abi.selector('publicValuesLength()')) {
        return abi.bytesToHex(abi.encodeUint(BRIDGE_PUBLIC_VALUES_LENGTH));
      }
      assert.equal(tx.data, abi.selector('programIdentifier()'));
      return abi.bytesToHex(abi.encodeBytes32(PROGRAM_ID));
    },
  };
  assert.equal(await verifierPublicValuesLength(compatible, VERIFIER), 128n);
  assert.equal(await verifierProgramIdentifier(compatible, VERIFIER), PROGRAM_ID);
  await assertBridgeVerifierCompatible(compatible, {
    verifier: VERIFIER,
    programId: PROGRAM_ID,
  });

  const incompatible = {
    ...compatible,
    async qrlCall() {
      return abi.bytesToHex(abi.encodeUint(24));
    },
  };
  await assert.rejects(
    assertBridgeVerifierCompatible(incompatible, {
      verifier: VERIFIER,
      programId: PROGRAM_ID,
    }),
    /accepts 24 public-value bytes/
  );

  const wrongProgram = {
    ...compatible,
    async qrlCall(tx) {
      if (tx.data === abi.selector('publicValuesLength()')) {
        return abi.bytesToHex(abi.encodeUint(BRIDGE_PUBLIC_VALUES_LENGTH));
      }
      return abi.bytesToHex(abi.encodeBytes32(`0x${'56'.repeat(32)}`));
    },
  };
  await assert.rejects(
    assertBridgeVerifierCompatible(wrongProgram, {
      verifier: VERIFIER,
      programId: PROGRAM_ID,
    }),
    /reports program/
  );

  await assert.rejects(
    verifierPublicValuesLength(
      {
        async getCode() {
          return '0x';
        },
      },
      VERIFIER
    ),
    /has no code/
  );
});
