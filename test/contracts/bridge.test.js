// StarkFactRegistry and StateBridge on a live QRVM (docs/BRIDGE.md).
//
// Deploys MockStarkVerifier, StarkFactRegistry and StateBridge once from the
// dev account and walks the whole bridge flow: fact registration keyed by
// public values, batch submission with the (prevRoot, newRoot) public-value
// encoding, deposits into the rolling accumulator, and a withdrawal authorised
// by a real ML-DSA-87 signature (@theqrl/mldsa87) over the 64-byte SHAKE256
// digest the contract computes with the shake256 builtin and checks with
// mldsa87verify (precompile 0x03). The same frame is sent to precompile 0x03
// directly so the JS signing convention is pinned against the chain as well
// as against the library's own verifier. A final demo case wires the real
// StarkVerifier through the registry and skips itself while the verifier
// still reverts NotImplemented(). Skips without STARK_RPC_URL.
//
// The contracts are compiled through the IR pipeline (viaIr). The legacy code
// generator of the current 64-byte hypc passes the mldsa87verify arguments to
// its Yul helper in reverse order, so a legacy build of StateBridge fails
// every withdrawal with "gas uint64 overflow" (docs/BRIDGE.md, toolchain
// notes). A canary case compiles StateBridge with the legacy pipeline and
// stops skipping once that defect is fixed.

const assert = require('node:assert/strict');
const crypto = require('node:crypto');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const abi = require('../../scripts/lib/abi64');
const { compileFiles } = require('../../scripts/hypc');
const H = require('../lib/harness');
const M = require('../lib/mldsa');
const T = require('../lib/merkle-simple');

const rpcUrl = process.env.STARK_RPC_URL;
const skip = rpcUrl ? false : 'set STARK_RPC_URL to run against a node';

const utf8 = (text) => new TextEncoder().encode(text);

const PROGRAM_ID = abi.keccak256Hex(utf8('bridge-mock-v1'));
const GENESIS_ROOT = abi.keccak256Hex(utf8('quantaproof-genesis'));
const DEPOSIT_AMOUNT = 10n ** 15n; // planck
const WITHDRAW_AMOUNT = 3n * 10n ** 14n;
const VECTOR = path.join(__dirname, '..', 'vectors', 'fib_c3_n10.json');
const MUTATION = path.join(
  __dirname,
  '..',
  'vectors',
  'mutations',
  'fib_c3_n10__flip_trace_root.json'
);

const SIG_REGISTER = 'registerFact(bytes,bytes)';
const SIG_SUBMIT = 'submitBatch(bytes32,bytes32,bytes,bytes)';
const SIG_WITHDRAW = 'withdraw(bytes32,address,uint512,uint512,bytes32[],uint512,bytes,bytes)';
const EV_FACT = 'FactRegistered(bytes32,bytes32,bytes32)';
const EV_BATCH = 'BatchSubmitted(uint512,bytes32,bytes32,bytes32)';
const EV_DEPOSIT = 'Deposited(uint512,address,uint512,bytes32)';
const EV_WITHDRAW = 'Withdrawn(bytes32,address,uint512)';

// ---------------------------------------------------------------------------
// Encoding helpers mirroring the contracts
// ---------------------------------------------------------------------------

function randomBytes(length) {
  return Uint8Array.from(crypto.randomBytes(length));
}

function randomDigest() {
  return abi.bytesToHex(randomBytes(32));
}

// A fresh externally owned address (lowercase hex so no checksum applies).
function randomAddress() {
  return `Q${crypto.randomBytes(64).toString('hex')}`;
}

function lower(hex) {
  return hex.toLowerCase();
}

// StarkFactRegistry.factKey: keccak256(verifier(64) || programId(32) || publicValuesHash(32)).
function factKey(verifier, programId, publicValuesHash) {
  return abi.keccak256Hex(
    abi.concatBytes([
      abi.encodeAddress(verifier),
      abi.hexToBytes(programId),
      abi.hexToBytes(publicValuesHash),
    ])
  );
}

// (prevRoot, newRoot) as 16 Goldilocks elements: element i is limb i of prevRoot,
// element 8 + i is limb i of newRoot, limbs are 32-bit big-endian slices of the
// root and every element is written as 8 bytes little-endian.
function encodeRoots(prevRoot, newRoot) {
  const out = new Uint8Array(128);
  [prevRoot, newRoot].forEach((root, r) => {
    const bytes = abi.hexToBytes(root);
    for (let i = 0; i < 8; i += 1) {
      const limb = bytes.subarray(4 * i, 4 * i + 4);
      const value = ((limb[0] << 24) | (limb[1] << 16) | (limb[2] << 8) | limb[3]) >>> 0;
      const offset = 8 * (8 * r + i);
      for (let k = 0; k < 8; k += 1) {
        out[offset + k] = Number((BigInt(value) >> BigInt(8 * k)) & 0xffn);
      }
    }
  });
  return out;
}

// ---------------------------------------------------------------------------
// Chain helpers
// ---------------------------------------------------------------------------

async function deploy(ctx, artifact, types, values) {
  const args = types.length > 0 ? abi.bytesToHex(H.encodeArgs(types, values)).slice(2) : '';
  return H.deployArtifact(ctx, { ...artifact, bytecode: `${artifact.bytecode}${args}` });
}

// Send a transaction with the estimate plus 20 percent; the dev node caps the
// fee per transaction, so a blanket high limit is rejected at its gas price.
async function send(ctx, tx) {
  const estimate = await ctx.sender.estimateGas(tx);
  const receipt = await ctx.sender.send({ ...tx, gas: (estimate * 12n) / 10n });
  assert.equal(Number(receipt.status), 1, `transaction ${receipt.transactionHash} reverted`);
  return { receipt, estimate, gasUsed: BigInt(receipt.gasUsed) };
}

async function sendCall(ctx, contract, signature, values, extra = {}) {
  return send(ctx, { to: contract.address, data: H.encodeCall(signature, values), ...extra });
}

function findLogs(receipt, contract, signature) {
  const topic = lower(abi.eventTopic(signature));
  return receipt.logs.filter(
    (log) => abi.sameAddress(log.address, contract.address) && lower(log.topics[0]) === topic
  );
}

function onlyLog(receipt, contract, signature) {
  const logs = findLogs(receipt, contract, signature);
  assert.equal(logs.length, 1, `expected one ${signature} log, got ${logs.length}`);
  return { topics: logs[0].topics, words: abi.decodeWords(logs[0].data) };
}

function assertHex(actual, expected, message) {
  assert.equal(lower(actual), lower(expected), message);
}

function gasLine(name, entry) {
  return `${name}: receipt gasUsed ${entry.gasUsed}, qrl_estimateGas ${entry.estimate}`;
}

// ---------------------------------------------------------------------------
// Suite
// ---------------------------------------------------------------------------

test('StarkFactRegistry and StateBridge', { skip, timeout: 900000 }, async (t) => {
  const ctx = await H.connect();
  const entries = [
    'test/MockStarkVerifier.hyp',
    'StarkFactRegistry.hyp',
    'bridge/StateBridge.hyp',
    'StarkVerifier.hyp',
  ];
  const artifacts = compileFiles(entries, { viaIr: true });
  const mock = await deploy(ctx, artifacts.MockStarkVerifier, [], []);
  const registry = await deploy(
    ctx,
    artifacts.StarkFactRegistry,
    ['address', 'bytes32'],
    [mock.address, PROGRAM_ID]
  );
  const bridge = await deploy(
    ctx,
    artifacts.StateBridge,
    ['address', 'bytes32', 'address', 'bytes32'],
    [registry.address, PROGRAM_ID, mock.address, GENESIS_ROOT]
  );
  t.diagnostic(
    `mock ${mock.address}, registry ${registry.address}, bridge ${bridge.address} (chain ${ctx.chainId})`
  );

  const gas = {};
  const state = { root: GENESIS_ROOT, batches: 0n };

  async function acceptProof(proof) {
    await sendCall(ctx, mock, 'setAccepted(bytes32,bool)', [abi.keccak256Hex(proof), true]);
  }

  async function submit(newRoot, proof, options = {}) {
    const publicValues = options.publicValues || encodeRoots(state.root, newRoot);
    const result = await sendCall(ctx, bridge, SIG_SUBMIT, [
      state.root,
      newRoot,
      publicValues,
      proof,
    ]);
    const fact = factKey(mock.address, PROGRAM_ID, abi.keccak256Hex(publicValues));
    const { topics, words } = onlyLog(result.receipt, bridge, EV_BATCH);
    assert.equal(abi.decodeUint(topics[1]), state.batches, 'BatchSubmitted.batchIndex');
    assertHex(abi.decodeBytes32(words[0]), state.root, 'BatchSubmitted.prevRoot');
    assertHex(abi.decodeBytes32(words[1]), newRoot, 'BatchSubmitted.newRoot');
    assertHex(abi.decodeBytes32(words[2]), fact, 'BatchSubmitted.fact');
    state.root = newRoot;
    state.batches += 1n;
    assertHex(await bridge.callOne('stateRoot()', [], 'bytes32'), newRoot, 'stateRoot');
    assert.equal(await bridge.callOne('batchIndex()', [], 'uint512'), state.batches, 'batchIndex');
    assert.equal(await registry.callOne('isValid(bytes32)', [fact], 'bool'), true, 'fact valid');
    return { ...result, fact };
  }

  await t.test('constructor state and getters', async () => {
    assert.ok(abi.sameAddress(await registry.callOne('verifier()', [], 'address'), mock.address));
    assertHex(await registry.callOne('programId()', [], 'bytes32'), PROGRAM_ID);
    assert.ok(abi.sameAddress(await bridge.callOne('registry()', [], 'address'), registry.address));
    assert.ok(abi.sameAddress(await bridge.callOne('verifier()', [], 'address'), mock.address));
    assertHex(await bridge.callOne('programId()', [], 'bytes32'), PROGRAM_ID);
    assertHex(await bridge.callOne('stateRoot()', [], 'bytes32'), GENESIS_ROOT);
    assert.equal(await bridge.callOne('batchIndex()', [], 'uint512'), 0n);
    assert.equal(await bridge.callOne('depositCount()', [], 'uint512'), 0n);
    assertHex(await bridge.callOne('depositAccumulator()', [], 'bytes32'), T.ZERO_DIGEST);

    // Zero addresses are refused at construction (the estimate reverts).
    const zero = `Q${'0'.repeat(128)}`;
    const registryArgs = abi.bytesToHex(H.encodeArgs(['address', 'bytes32'], [zero, PROGRAM_ID]));
    await assert.rejects(
      ctx.sender.estimateGas({
        data: `${artifacts.StarkFactRegistry.bytecode}${registryArgs.slice(2)}`,
      })
    );
    const bridgeArgs = abi.bytesToHex(
      H.encodeArgs(
        ['address', 'bytes32', 'address', 'bytes32'],
        [zero, PROGRAM_ID, mock.address, GENESIS_ROOT]
      )
    );
    await assert.rejects(
      ctx.sender.estimateGas({ data: `${artifacts.StateBridge.bytecode}${bridgeArgs.slice(2)}` })
    );
  });

  await t.test('registry accepts a mock-accepted proof and rejects others', async () => {
    const proof = randomBytes(96);
    const publicValues = randomBytes(24);
    const publicValuesHash = abi.keccak256Hex(publicValues);
    const expected = factKey(mock.address, PROGRAM_ID, publicValuesHash);
    await acceptProof(proof);

    assert.equal(await registry.callOne('isValid(bytes32)', [expected], 'bool'), false);
    assert.equal(await mock.callOne('verify(bytes,bytes)', [proof, publicValues], 'bool'), true);
    assertHex(await registry.callOne(SIG_REGISTER, [proof, publicValues], 'bytes32'), expected);

    const result = await sendCall(ctx, registry, SIG_REGISTER, [proof, publicValues]);
    gas.registerFact = result;
    const { topics, words } = onlyLog(result.receipt, registry, EV_FACT);
    assertHex(abi.decodeBytes32(topics[1]), expected, 'FactRegistered.fact');
    assertHex(abi.decodeBytes32(topics[2]), publicValuesHash, 'FactRegistered.publicValuesHash');
    assertHex(abi.decodeBytes32(words[0]), abi.keccak256Hex(proof), 'FactRegistered.proofId');
    assert.equal(await registry.callOne('isValid(bytes32)', [expected], 'bool'), true);
    assert.equal(
      await mock.callOne('isAccepted(bytes32)', [abi.keccak256Hex(proof)], 'bool'),
      true
    );

    // A proof the verifier does not accept.
    await H.expectRevert(registry, SIG_REGISTER, [randomBytes(96), publicValues], 'InvalidProof()');
    // A reverting verifier propagates its own error.
    await sendCall(ctx, mock, 'setRevert(bool)', [true]);
    await H.expectRevert(registry, SIG_REGISTER, [proof, publicValues], 'MockRevert()');
    await sendCall(ctx, mock, 'setRevert(bool)', [false]);
    // Facts are keyed by public values: a second accepted proof of the same
    // statement lands on the same key.
    const otherProof = randomBytes(96);
    await acceptProof(otherProof);
    assertHex(
      await registry.callOne(SIG_REGISTER, [otherProof, publicValues], 'bytes32'),
      expected
    );
    // Unregistered public values stay invalid even with an accepted proof
    // hash, until registerFact runs for them.
    const otherKey = factKey(mock.address, PROGRAM_ID, abi.keccak256Hex(randomBytes(24)));
    assert.equal(await registry.callOne('isValid(bytes32)', [otherKey], 'bool'), false);
  });

  await t.test('fact key equals the JS-computed key', async () => {
    for (let i = 0; i < 4; i += 1) {
      const publicValuesHash = randomDigest();
      const expected = factKey(mock.address, PROGRAM_ID, publicValuesHash);
      assertHex(
        await registry.callOne('factKey(bytes32)', [publicValuesHash], 'bytes32'),
        expected
      );
      assertHex(
        await bridge.callOne('expectedFact(bytes32)', [publicValuesHash], 'bytes32'),
        expected
      );
    }
  });

  await t.test('submitBatch happy path advances the root and emits', async () => {
    const newRoot = randomDigest();
    const proof = randomBytes(128);
    const publicValues = encodeRoots(state.root, newRoot);
    await acceptProof(proof);
    assert.equal(
      await bridge.callOne(
        'encodesRoots(bytes,bytes32,bytes32)',
        [publicValues, state.root, newRoot],
        'bool'
      ),
      true
    );
    const fact = factKey(mock.address, PROGRAM_ID, abi.keccak256Hex(publicValues));
    assert.equal(await registry.callOne('isValid(bytes32)', [fact], 'bool'), false);

    const result = await submit(newRoot, proof);
    gas.submitBatch = result;
    assertHex(result.fact, fact);
    // The registry registered the fact inside the same transaction.
    const { topics } = onlyLog(result.receipt, registry, EV_FACT);
    assertHex(abi.decodeBytes32(topics[1]), fact);
  });

  await t.test('submitBatch reuses a registered fact and ignores the proof bytes', async () => {
    const newRoot = randomDigest();
    const proof = randomBytes(64);
    const publicValues = encodeRoots(state.root, newRoot);
    await acceptProof(proof);
    await sendCall(ctx, registry, SIG_REGISTER, [proof, publicValues]);

    // An empty proof is never allow-listed on the mock, so success proves the
    // lookup path was taken.
    await H.expectRevert(
      registry,
      SIG_REGISTER,
      [new Uint8Array(0), publicValues],
      'InvalidProof()'
    );
    const result = await submit(newRoot, new Uint8Array(0));
    gas.submitBatchRegistered = result;
    assert.equal(findLogs(result.receipt, registry, EV_FACT).length, 0);
  });

  await t.test(
    'submitBatch rejects stale roots, malformed public values and unproven batches',
    async () => {
      const previousRoot = state.root;
      const newRoot = randomDigest();
      const proof = randomBytes(64);
      const publicValues = encodeRoots(previousRoot, newRoot);
      await acceptProof(proof);

      const stale = randomDigest();
      await H.expectRevert(
        bridge,
        SIG_SUBMIT,
        [stale, newRoot, encodeRoots(stale, newRoot), proof],
        'StaleRoot()'
      );

      const short = publicValues.slice(0, 120);
      await H.expectRevert(
        bridge,
        SIG_SUBMIT,
        [previousRoot, newRoot, short, proof],
        'BadPublicValues()'
      );
      const long = abi.concatBytes([publicValues, new Uint8Array(8)]);
      await H.expectRevert(
        bridge,
        SIG_SUBMIT,
        [previousRoot, newRoot, long, proof],
        'BadPublicValues()'
      );

      // Element 0 gains 2^32: it no longer fits a 32-bit limb.
      const big = publicValues.slice();
      big[4] = 1;
      await H.expectRevert(
        bridge,
        SIG_SUBMIT,
        [previousRoot, newRoot, big, proof],
        'BadPublicValues()'
      );
      // Element 15 gains 2^32 (the newRoot half is checked too).
      const bigTail = publicValues.slice();
      bigTail[15 * 8 + 4] = 1;
      await H.expectRevert(
        bridge,
        SIG_SUBMIT,
        [previousRoot, newRoot, bigTail, proof],
        'BadPublicValues()'
      );

      // newRoot argument disagrees with the encoded newRoot.
      await H.expectRevert(
        bridge,
        SIG_SUBMIT,
        [previousRoot, randomDigest(), publicValues, proof],
        'BadPublicValues()'
      );
      // prevRoot matches the state but the encoding names another prevRoot.
      await H.expectRevert(
        bridge,
        SIG_SUBMIT,
        [previousRoot, newRoot, encodeRoots(randomDigest(), newRoot), proof],
        'BadPublicValues()'
      );
      // One limb of the encoded prevRoot flipped.
      const flipped = publicValues.slice();
      flipped[3 * 8] ^= 0x01;
      await H.expectRevert(
        bridge,
        SIG_SUBMIT,
        [previousRoot, newRoot, flipped, proof],
        'BadPublicValues()'
      );

      // Well-formed but unproven: the registry's InvalidProof propagates.
      await H.expectRevert(
        bridge,
        SIG_SUBMIT,
        [previousRoot, newRoot, publicValues, randomBytes(64)],
        'InvalidProof()'
      );
      // A reverting verifier propagates through registry and bridge.
      await sendCall(ctx, mock, 'setRevert(bool)', [true]);
      await H.expectRevert(
        bridge,
        SIG_SUBMIT,
        [previousRoot, newRoot, publicValues, proof],
        'MockRevert()'
      );
      await sendCall(ctx, mock, 'setRevert(bool)', [false]);

      assertHex(
        await bridge.callOne('stateRoot()', [], 'bytes32'),
        previousRoot,
        'state unchanged'
      );
      assert.equal(await bridge.callOne('batchIndex()', [], 'uint512'), state.batches);
    }
  );

  await t.test('deposit updates the count and accumulator and emits', async () => {
    const sender = ctx.sender.address;
    const balanceBefore = await ctx.rpc.getBalance(bridge.address);

    const first = await sendCall(ctx, bridge, 'deposit()', [], { value: DEPOSIT_AMOUNT });
    gas.deposit = first;
    const leaf0 = T.depositLeaf(sender, DEPOSIT_AMOUNT, 0n);
    const acc0 = T.accumulate(T.ZERO_DIGEST, leaf0);
    const log0 = onlyLog(first.receipt, bridge, EV_DEPOSIT);
    assert.equal(abi.decodeUint(log0.topics[1]), 0n, 'Deposited.index');
    assert.ok(abi.sameAddress(log0.topics[2], sender), 'Deposited.sender');
    assert.equal(abi.decodeUint(log0.words[0]), DEPOSIT_AMOUNT, 'Deposited.amount');
    assertHex(abi.decodeBytes32(log0.words[1]), leaf0, 'Deposited.leaf');
    assert.equal(await bridge.callOne('depositCount()', [], 'uint512'), 1n);
    assertHex(await bridge.callOne('depositAccumulator()', [], 'bytes32'), acc0);

    const secondAmount = DEPOSIT_AMOUNT / 2n;
    const second = await sendCall(ctx, bridge, 'deposit()', [], { value: secondAmount });
    const leaf1 = T.depositLeaf(sender, secondAmount, 1n);
    const acc1 = T.accumulate(acc0, leaf1);
    const log1 = onlyLog(second.receipt, bridge, EV_DEPOSIT);
    assert.equal(abi.decodeUint(log1.topics[1]), 1n);
    assertHex(abi.decodeBytes32(log1.words[1]), leaf1);
    assert.equal(await bridge.callOne('depositCount()', [], 'uint512'), 2n);
    assertHex(await bridge.callOne('depositAccumulator()', [], 'bytes32'), acc1);
    assert.equal(
      await ctx.rpc.getBalance(bridge.address),
      balanceBefore + DEPOSIT_AMOUNT + secondAmount,
      'bridge balance'
    );
  });

  // Withdrawal fixtures shared by the remaining cases: one key, two leaves in
  // a four-leaf tree (index 2 is withdrawn, index 0 serves the negative cases).
  const key = M.generateKeypair();
  const otherKey = M.generateKeypair();
  const pkHash = M.publicKeyHash(key.publicKey);
  const recipient = randomAddress();
  const leaves = [
    { nonce: 8n, index: 0 },
    { nonce: 7n, index: 2 },
  ].map((entry) => ({
    ...entry,
    leaf: T.withdrawalLeaf(pkHash, recipient, WITHDRAW_AMOUNT, entry.nonce),
  }));
  const tree = T.buildTree([leaves[0].leaf, randomDigest(), leaves[1].leaf, randomDigest()]);
  for (const entry of leaves) {
    entry.proof = T.getProof(tree, entry.index);
    entry.digest = M.withdrawDigest(entry.leaf, recipient);
    entry.signature = M.signDigest(entry.digest, key.secretKey);
    assert.ok(T.verifyProof(entry.leaf, entry.proof, entry.index, tree.root));
    assert.ok(M.verifyDigest(entry.signature, entry.digest, key.publicKey));
  }
  const withdrawArgs = (entry, overrides = {}) => {
    const args = {
      pkHash,
      recipient,
      amount: WITHDRAW_AMOUNT,
      nonce: entry.nonce,
      proof: entry.proof,
      index: BigInt(entry.index),
      signature: entry.signature,
      publicKey: key.publicKey,
      ...overrides,
    };
    return [
      args.pkHash,
      args.recipient,
      args.amount,
      args.nonce,
      args.proof,
      args.index,
      args.signature,
      args.publicKey,
    ];
  };

  await t.test(
    'withdraw pays out a leaf under the state root with a real ML-DSA-87 signature',
    async () => {
      const entry = leaves[1];

      // The digest the contract computes: shake256 builtin == precompile 0x06 == noble.
      const message = abi.bytesToHex(M.withdrawMessage(entry.leaf, recipient));
      const onChainDigest = await ctx.rpc.qrlCall({ to: M.SHAKE256_PRECOMPILE, data: message });
      assertHex(onChainDigest, abi.bytesToHex(entry.digest), 'shake256 precompile digest');

      // The frame mldsa87verify packs, sent to precompile 0x03 by hand.
      const frame = M.encodePrecompileInput(entry.digest, entry.signature, key.publicKey);
      assert.equal(
        frame.length,
        64 + M.PUBLIC_KEY_BYTES + M.SIGNATURE_BYTES + 1 + M.WITHDRAW_CONTEXT.length
      );
      const verdict = await ctx.rpc.qrlCall({
        to: M.MLDSA87_VERIFY_PRECOMPILE,
        data: abi.bytesToHex(frame),
      });
      assertHex(verdict, M.PRECOMPILE_TRUE, 'precompile 0x03 accepts the frame');
      const tampered = frame.slice();
      tampered[64 + M.PUBLIC_KEY_BYTES] ^= 0x01;
      const rejected = await ctx.rpc.qrlCall({
        to: M.MLDSA87_VERIFY_PRECOMPILE,
        data: abi.bytesToHex(tampered),
      });
      assert.ok(
        rejected === '0x' || lower(rejected) === `0x${'00'.repeat(64)}`,
        'precompile 0x03 rejects'
      );

      // The contract's own digest and signature views agree with the JS side.
      assertHex(
        await bridge.callOne('withdrawDigest(bytes32,address)', [entry.leaf, recipient], 'bytes64'),
        abi.bytesToHex(entry.digest),
        'withdrawDigest view'
      );
      assert.equal(
        await bridge.callOne(
          'verifyWithdrawSignature(bytes32,address,bytes,bytes)',
          [entry.leaf, recipient, entry.signature, key.publicKey],
          'bool'
        ),
        true,
        'verifyWithdrawSignature accepts'
      );
      assert.equal(
        await bridge.callOne(
          'verifyWithdrawSignature(bytes32,address,bytes,bytes)',
          [
            entry.leaf,
            recipient,
            tampered.slice(64 + M.PUBLIC_KEY_BYTES, 64 + M.PUBLIC_KEY_BYTES + M.SIGNATURE_BYTES),
            key.publicKey,
          ],
          'bool'
        ),
        false,
        'verifyWithdrawSignature rejects a flipped byte'
      );

      // Inclusion as the contract sees it.
      assert.equal(
        await bridge.callOne(
          'verifyInclusion(bytes32,bytes32[],uint512,bytes32)',
          [entry.leaf, entry.proof, 2n, tree.root],
          'bool'
        ),
        true
      );
      assert.equal(
        await bridge.callOne(
          'verifyInclusion(bytes32,bytes32[],uint512,bytes32)',
          [entry.leaf, entry.proof, 3n, tree.root],
          'bool'
        ),
        false
      );

      // Before the batch lands the leaf is not under the state root.
      await H.expectRevert(bridge, SIG_WITHDRAW, withdrawArgs(entry), 'NotIncluded()');

      const batchProof = randomBytes(64);
      await acceptProof(batchProof);
      await submit(tree.root, batchProof);

      // Fund the pool through receive().
      await send(ctx, { to: bridge.address, value: 2n * WITHDRAW_AMOUNT });
      const poolBefore = await ctx.rpc.getBalance(bridge.address);
      const recipientBefore = await ctx.rpc.getBalance(recipient);

      const result = await sendCall(ctx, bridge, SIG_WITHDRAW, withdrawArgs(entry));
      gas.withdraw = result;
      const { topics, words } = onlyLog(result.receipt, bridge, EV_WITHDRAW);
      assertHex(abi.decodeBytes32(topics[1]), entry.leaf, 'Withdrawn.leaf');
      assert.ok(abi.sameAddress(topics[2], recipient), 'Withdrawn.recipient');
      assert.equal(abi.decodeUint(words[0]), WITHDRAW_AMOUNT, 'Withdrawn.amount');
      assert.equal(
        await ctx.rpc.getBalance(recipient),
        recipientBefore + WITHDRAW_AMOUNT,
        'recipient paid'
      );
      assert.equal(
        await ctx.rpc.getBalance(bridge.address),
        poolBefore - WITHDRAW_AMOUNT,
        'pool debited'
      );
      assert.equal(await bridge.callOne('withdrawn(bytes32)', [entry.leaf], 'bool'), true);
    }
  );

  await t.test('replay reverts AlreadyWithdrawn', async () => {
    await H.expectRevert(bridge, SIG_WITHDRAW, withdrawArgs(leaves[1]), 'AlreadyWithdrawn()');
    // A fresh signature over the same leaf changes nothing: the leaf is spent.
    const again = M.signDigest(leaves[1].digest, key.secretKey, M.WITHDRAW_CONTEXT, {
      randomized: true,
    });
    await H.expectRevert(
      bridge,
      SIG_WITHDRAW,
      withdrawArgs(leaves[1], { signature: again }),
      'AlreadyWithdrawn()'
    );
  });

  await t.test('wrong signature, recipient, key, proof and index revert', async () => {
    const entry = leaves[0];

    const flipped = entry.signature.slice();
    flipped[100] ^= 0x01;
    await H.expectRevert(
      bridge,
      SIG_WITHDRAW,
      withdrawArgs(entry, { signature: flipped }),
      'BadSignature()'
    );
    // A valid signature for the other leaf.
    await H.expectRevert(
      bridge,
      SIG_WITHDRAW,
      withdrawArgs(entry, { signature: leaves[1].signature }),
      'BadSignature()'
    );
    // Right digest, wrong context string.
    const qnsContext = M.signDigest(entry.digest, key.secretKey, 'QNS-SIGN-v1');
    assert.ok(M.verifyDigest(qnsContext, entry.digest, key.publicKey, 'QNS-SIGN-v1'));
    await H.expectRevert(
      bridge,
      SIG_WITHDRAW,
      withdrawArgs(entry, { signature: qnsContext }),
      'BadSignature()'
    );
    // Right digest and context, wrong signer.
    const otherSigner = M.signDigest(entry.digest, otherKey.secretKey);
    await H.expectRevert(
      bridge,
      SIG_WITHDRAW,
      withdrawArgs(entry, { signature: otherSigner }),
      'BadSignature()'
    );
    // Signature over the message bytes instead of the digest.
    const overMessage = M.signDigest(M.shake256Digest(abi.hexToBytes(entry.leaf)), key.secretKey);
    await H.expectRevert(
      bridge,
      SIG_WITHDRAW,
      withdrawArgs(entry, { signature: overMessage }),
      'BadSignature()'
    );

    // The leaf commits to the recipient and the amount: changing either
    // changes the leaf, which is then not in the tree.
    await H.expectRevert(
      bridge,
      SIG_WITHDRAW,
      withdrawArgs(entry, { recipient: randomAddress() }),
      'NotIncluded()'
    );
    await H.expectRevert(
      bridge,
      SIG_WITHDRAW,
      withdrawArgs(entry, { amount: WITHDRAW_AMOUNT + 1n }),
      'NotIncluded()'
    );
    await H.expectRevert(bridge, SIG_WITHDRAW, withdrawArgs(entry, { nonce: 9n }), 'NotIncluded()');
    // Wrong position, wrong sibling, out-of-range index, truncated proof.
    await H.expectRevert(bridge, SIG_WITHDRAW, withdrawArgs(entry, { index: 1n }), 'NotIncluded()');
    await H.expectRevert(bridge, SIG_WITHDRAW, withdrawArgs(entry, { index: 4n }), 'NotIncluded()');
    await H.expectRevert(
      bridge,
      SIG_WITHDRAW,
      withdrawArgs(entry, { proof: [entry.proof[1], entry.proof[0]] }),
      'NotIncluded()'
    );
    await H.expectRevert(
      bridge,
      SIG_WITHDRAW,
      withdrawArgs(entry, { proof: entry.proof.slice(0, 1) }),
      'NotIncluded()'
    );
    await H.expectRevert(bridge, SIG_WITHDRAW, withdrawArgs(entry, { proof: [] }), 'NotIncluded()');

    // The public key must hash to the committed pkHash.
    await H.expectRevert(
      bridge,
      SIG_WITHDRAW,
      withdrawArgs(entry, { publicKey: otherKey.publicKey }),
      'WrongKey()'
    );
    await H.expectRevert(
      bridge,
      SIG_WITHDRAW,
      withdrawArgs(entry, { publicKey: key.publicKey.slice(0, 2591) }),
      'WrongKey()'
    );
    // A leaf built for the other key is not in the tree either.
    const otherHash = M.publicKeyHash(otherKey.publicKey);
    await H.expectRevert(
      bridge,
      SIG_WITHDRAW,
      withdrawArgs(entry, {
        pkHash: otherHash,
        publicKey: otherKey.publicKey,
        signature: otherSigner,
      }),
      'NotIncluded()'
    );

    // None of the failed attempts spent the leaf.
    assert.equal(await bridge.callOne('withdrawn(bytes32)', [entry.leaf], 'bool'), false);
    const recipientBefore = await ctx.rpc.getBalance(recipient);
    await sendCall(ctx, bridge, SIG_WITHDRAW, withdrawArgs(entry));
    assert.equal(await ctx.rpc.getBalance(recipient), recipientBefore + WITHDRAW_AMOUNT);
    assert.equal(await bridge.callOne('withdrawn(bytes32)', [entry.leaf], 'bool'), true);
  });

  await t.test('canary: StateBridge built with the legacy code generator', async (tt) => {
    // Same source, legacy pipeline. Skips while the known hypc defect (Yul
    // helper arguments of mldsa87verify pushed in reverse order) is present.
    const legacy = compileFiles(['bridge/StateBridge.hyp']);
    const bridgeLegacy = await deploy(
      ctx,
      legacy.StateBridge,
      ['address', 'bytes32', 'address', 'bytes32'],
      [registry.address, PROGRAM_ID, mock.address, GENESIS_ROOT]
    );
    const entry = leaves[1];
    const args = [entry.leaf, recipient, entry.signature, key.publicKey];
    try {
      const ok = await bridgeLegacy.callOne(
        'verifyWithdrawSignature(bytes32,address,bytes,bytes)',
        args,
        'bool'
      );
      assert.equal(ok, true, 'legacy build verifies the withdrawal signature');
    } catch (error) {
      if (/gas uint64 overflow/.test(error.message)) {
        tt.skip('legacy hypc codegen defect still present: mldsa87verify argument order');
        return;
      }
      throw error;
    }
  });

  await t.test('demo: real StarkVerifier through the registry', async (tt) => {
    const vector = JSON.parse(fs.readFileSync(VECTOR, 'utf8'));
    const mutation = JSON.parse(fs.readFileSync(MUTATION, 'utf8'));
    const verifier = await deploy(ctx, artifacts.StarkVerifier, [], []);
    try {
      await verifier.callRaw('verify(bytes,bytes)', [vector.proofHex, vector.publicValuesHex]);
    } catch (error) {
      const payload = H.revertData(error);
      if (payload && lower(payload).startsWith(lower(H.errorSelector('NotImplemented()')))) {
        tt.skip(
          'StarkVerifier.verify still reverts NotImplemented(); demo wiring waits for milestone M6'
        );
        return;
      }
      throw error;
    }

    // Public values are the Fibonacci triple here, so only the registry side
    // of the flow is exercised: the bridge needs the (prevRoot, newRoot) encoding.
    const programId = abi.keccak256Hex(utf8(`fibonacci-${vector.name}-v1`));
    const real = await deploy(
      ctx,
      artifacts.StarkFactRegistry,
      ['address', 'bytes32'],
      [verifier.address, programId]
    );
    const fact = factKey(
      verifier.address,
      programId,
      abi.keccak256Hex(abi.hexToBytes(vector.publicValuesHex))
    );
    const result = await sendCall(ctx, real, SIG_REGISTER, [
      vector.proofHex,
      vector.publicValuesHex,
    ]);
    gas.registerFactReal = result;
    const { topics } = onlyLog(result.receipt, real, EV_FACT);
    assertHex(abi.decodeBytes32(topics[1]), fact);
    assert.equal(await real.callOne('isValid(bytes32)', [fact], 'bool'), true);
    // A mutated proof is rejected by the verifier (its own error or a false).
    await assert.rejects(real.callRaw(SIG_REGISTER, [mutation.proofHex, mutation.publicValuesHex]));
    tt.diagnostic(
      `registerFact with the real verifier (${vector.name}): ${gasLine('gas', result)}`
    );
  });

  for (const [name, entry] of Object.entries(gas)) {
    t.diagnostic(gasLine(name, entry));
  }
});
