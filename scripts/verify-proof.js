// Send one proof vector through the StarkVerifierGasMeter of its preset and
// report every gas number of the deployable path.
//
// Usage:
//   STARK_CONFIG=config/dev-node.json npm run verify:proof -- --vector test/vectors/fib_c3_n12.json
//   STARK_CONFIG=config/local-stark.json npm run verify:proof -- --vector test/vectors/large/fib_c3_n20.json
//
// Options:
//   --vector <path>      vector JSON with proofHex and publicValuesHex (required)
//   --config <path>      deployment record (default: STARK_CONFIG or config/local-stark.json)
//   --verifier <addr>    override the verifier address chosen from the config
//   --gas-meter <addr>   override the gas meter address chosen from the config
//   --call-only          skip the transaction, only run the qrl_call and the estimate
//
// The verifier is picked from config.contracts.verifiers[<preset>], where the
// preset is derived from the vector's `config` (scripts/lib/presets.js). The
// script prints the calldata size and calldata gas, qrl_estimateGas of a
// direct `verify` transaction, the `verifyAndLog` receipt gasUsed, the inner
// STATICCALL gas from the Verified event and the ok flag. The exit status is
// 0 when the outcome matches the vector's expectation (accepted for a valid
// vector, rejected for a mutated one) and 1 otherwise. Calldata is
// hand-encoded with the 64-byte-word ABI (scripts/lib/abi64.js).

const fs = require('fs');
const path = require('path');

require('dotenv').config({ path: path.join(__dirname, '..', '.env'), quiet: true });

const { JsonRpcError, RpcClient, toQuantity } = require('./lib/rpc');
const { getSender } = require('./lib/devAccount');
const { loadConfig, resolveConfigPath, withGasMargin } = require('./deploy');
const abi = require('./lib/abi64');
const { presetFromConfig } = require('./lib/presets');

const repoRoot = path.join(__dirname, '..');

const VERIFY_SIGNATURE = 'verify(bytes,bytes)';
const VERIFY_AND_LOG_SIGNATURE = 'verifyAndLog(bytes,bytes)';
const VERIFIED_TOPIC = abi.eventTopic('Verified(bytes32,bool,uint512)');
const VERIFY_REVERTED_TOPIC = abi.eventTopic('VerifyReverted(bytes32,bytes)');

// Transaction data pricing: 16 gas per non-zero byte, 4 per zero byte.
const CALLDATA_NONZERO_GAS = 16;
const CALLDATA_ZERO_GAS = 4;

function parseArgs(argv) {
  const options = { callOnly: false };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    const next = () => {
      if (i + 1 >= argv.length) throw new Error(`${arg} needs a value`);
      i += 1;
      return argv[i];
    };
    if (arg === '--vector') options.vector = next();
    else if (arg === '--config') options.config = next();
    else if (arg === '--verifier') options.verifier = next();
    else if (arg === '--gas-meter') options.gasMeter = next();
    else if (arg === '--call-only') options.callOnly = true;
    else throw new Error(`unknown option ${arg}`);
  }
  return options;
}

function loadVector(file) {
  const raw = JSON.parse(fs.readFileSync(file, 'utf8'));
  const proofHex = raw.proofHex ?? raw.proof;
  const publicValuesHex = raw.publicValuesHex ?? raw.publicValues;
  if (typeof proofHex !== 'string' || typeof publicValuesHex !== 'string') {
    throw new Error(`${file}: expected proofHex and publicValuesHex strings`);
  }
  return {
    name: raw.name ?? path.basename(file, '.json'),
    file,
    config: raw.config ?? null,
    preset: raw.config ? presetFromConfig(raw.config) : null,
    degreeBits: raw.degreeBits ?? null,
    expected: raw.expected ?? null,
    proof: abi.hexToBytes(proofHex),
    publicValues: abi.hexToBytes(publicValuesHex),
    raw,
  };
}

function calldataGas(bytes) {
  let gas = 0;
  for (const b of bytes) gas += b === 0 ? CALLDATA_ZERO_GAS : CALLDATA_NONZERO_GAS;
  return gas;
}

// The verifier and gas meter for a vector: explicit overrides, then the
// preset entry of a per-preset record (deploy.js), then the flat
// StarkVerifier / StarkVerifierGasMeter keys of a single-verifier record
// (the contract suite passes that shape).
function resolveContracts(config, vector, options = {}) {
  const contracts = config?.contracts ?? {};
  const entry = vector.preset ? (contracts.verifiers?.[vector.preset] ?? null) : null;
  return {
    preset: vector.preset,
    entry,
    verifier: options.verifier || entry?.verifier || contracts.StarkVerifier || null,
    gasMeter: options.gasMeter || entry?.gasMeter || contracts.StarkVerifierGasMeter || null,
  };
}

function decodeVerifiedLog(log) {
  const words = abi.decodeWords(log.data);
  if (words.length !== 2) {
    throw new Error(`Verified log data has ${words.length} words, expected 2`);
  }
  return {
    proofId: abi.decodeBytes32(log.topics[1]),
    ok: abi.decodeBool(words[0]),
    gasUsed: abi.decodeUint(words[1]),
  };
}

function decodeVerifyRevertedLog(log) {
  const words = abi.decodeWords(log.data);
  // head: offset word; tail: length word + data padded to 64 bytes
  const length = Number(abi.decodeUint(words[1]));
  const data = abi
    .strip0x(log.data)
    .slice(2 * 2 * abi.WORD_BYTES, 2 * 2 * abi.WORD_BYTES + length * 2);
  return { proofId: abi.decodeBytes32(log.topics[1]), data: `0x${data}` };
}

function logsFrom(receipt, address, topic) {
  return (receipt.logs || []).filter(
    (log) =>
      abi.sameAddress(log.address, address) &&
      (log.topics?.[0] || '').toLowerCase() === topic.toLowerCase()
  );
}

async function callVerify(rpc, verifier, data) {
  try {
    const ret = await rpc.qrlCall({ to: verifier, data });
    const words = abi.decodeWords(ret);
    if (words.length !== 1) {
      return { ok: false, reverted: false, error: `unexpected return size ${words.length * 64}` };
    }
    return { ok: abi.decodeBool(words[0]), reverted: false };
  } catch (error) {
    if (error instanceof JsonRpcError) {
      return { ok: false, reverted: true, error: error.message, data: error.data ?? null };
    }
    throw error;
  }
}

// qrl_estimateGas of a direct `verify` transaction; null when the call
// reverts (mutated vectors), with the node's message.
async function estimateVerify(rpc, sender, verifier, data) {
  try {
    const tx = { to: verifier, data };
    if (sender?.address) tx.from = sender.address;
    return { gas: await rpc.estimateGas(tx), error: null };
  } catch (error) {
    if (error instanceof JsonRpcError) return { gas: null, error: error.message };
    throw error;
  }
}

// Runs the qrl_call and the estimate of `verify` and (unless callOnly) the
// gas-meter transaction. `sender` may be null in call-only mode.
async function runVerifyProof({ rpc, sender, config, vector, options = {} }) {
  const { preset, entry, verifier, gasMeter } = resolveContracts(config, vector, options);
  if (!verifier) {
    throw new Error(
      `no StarkVerifier for ${vector.name}${preset ? ` (preset ${preset})` : ''}; ` +
        `run \`npm run deploy -- --preset ${preset ?? 'c3'}\``
    );
  }

  const verifyData = abi.encodeBytesArgs(VERIFY_SIGNATURE, [vector.proof, vector.publicValues]);
  const verifyDataHex = abi.bytesToHex(verifyData);
  const estimate = await estimateVerify(rpc, sender, verifier, verifyDataHex);
  const result = {
    vector: vector.name,
    preset,
    config: vector.config,
    degreeBits: vector.degreeBits,
    proofBytes: vector.proof.length,
    publicValuesBytes: vector.publicValues.length,
    proofId: abi.keccak256Hex(vector.proof),
    expected: vector.expected,
    expectedValid: vector.expected?.valid !== false,
    verifier,
    gasMeter,
    settings: entry?.compiler ?? null,
    runtimeBytes: entry?.runtimeBytes ?? null,
    calldataBytes: verifyData.length,
    calldataGas: calldataGas(verifyData),
    verifyEstimate: estimate.gas,
    verifyEstimateError: estimate.error,
    call: await callVerify(rpc, verifier, verifyDataHex),
    tx: null,
    ok: null,
    pass: null,
  };

  if (options.callOnly) {
    result.ok = result.call.ok;
    result.pass = result.ok === result.expectedValid;
    return result;
  }
  if (!gasMeter) {
    throw new Error(
      `no StarkVerifierGasMeter for ${vector.name}${preset ? ` (preset ${preset})` : ''}; ` +
        `run \`npm run deploy -- --preset ${preset ?? 'c3'}\``
    );
  }
  if (!sender) throw new Error('a sender is required to send the verifyAndLog transaction');

  const meterData = abi.encodeBytesArgs(VERIFY_AND_LOG_SIGNATURE, [
    vector.proof,
    vector.publicValues,
  ]);
  const data = abi.bytesToHex(meterData);
  const latest = await rpc.getBlockByNumber('latest');
  const gasCap = latest?.gasLimit ? BigInt(latest.gasLimit) : null;
  const meterEstimate = await sender.estimateGas({ to: gasMeter, data });
  const gas = withGasMargin(meterEstimate, gasCap);
  let receipt = null;
  let txError = null;
  try {
    receipt = await sender.send({ to: gasMeter, data, gas: toQuantity(gas) });
  } catch (error) {
    // The transaction pool caps a transaction at 128 KiB (txMaxSize in
    // core/txpool/legacypool); larger proofs are simulated below instead.
    if (!/oversized data/i.test(error.message)) throw error;
    txError = error.message;
  }

  if (receipt) {
    const verified = logsFrom(receipt, gasMeter, VERIFIED_TOPIC).map(decodeVerifiedLog);
    const reverted = logsFrom(receipt, gasMeter, VERIFY_REVERTED_TOPIC).map(
      decodeVerifyRevertedLog
    );
    result.tx = {
      hash: receipt.transactionHash,
      status: Number(receipt.status),
      simulated: false,
      error: null,
      calldataBytes: meterData.length,
      calldataGas: calldataGas(meterData),
      estimateGas: meterEstimate,
      gasSent: gas,
      gasUsed: BigInt(receipt.gasUsed),
      blockNumber: Number(receipt.blockNumber),
      verified: verified[0] ?? null,
      verifyReverted: reverted[0] ?? null,
    };
    result.ok = result.tx.status === 1 && result.tx.verified ? result.tx.verified.ok : false;
  } else {
    // qrl_call executes verifyAndLog against the latest state and returns
    // (ok, gasUsed): the same inner STATICCALL measurement without a receipt.
    const ret = await rpc.qrlCall({ from: sender.address, to: gasMeter, data });
    const words = abi.decodeWords(ret);
    if (words.length !== 2) {
      throw new Error(`verifyAndLog call returned ${words.length} words, expected 2`);
    }
    result.tx = {
      hash: null,
      status: null,
      simulated: true,
      error: txError,
      calldataBytes: meterData.length,
      calldataGas: calldataGas(meterData),
      estimateGas: meterEstimate,
      gasSent: null,
      gasUsed: null,
      blockNumber: null,
      verified: {
        proofId: result.proofId,
        ok: abi.decodeBool(words[0]),
        gasUsed: abi.decodeUint(words[1]),
      },
      verifyReverted: null,
    };
    result.ok = result.tx.verified.ok;
  }
  result.pass = result.ok === result.expectedValid;
  return result;
}

function fmt(value) {
  return value === null || value === undefined ? '?' : Number(value).toLocaleString('en-US');
}

function printResult(result) {
  console.log(
    `\nVector:          ${result.vector} (preset ${result.preset ?? 'custom'}, degreeBits ${result.degreeBits ?? '?'})`
  );
  console.log(
    `Proof bytes:     ${fmt(result.proofBytes)} (public values ${result.publicValuesBytes} bytes)`
  );
  console.log(`proofId:         ${result.proofId}`);
  console.log(`Verifier:        ${result.verifier}`);
  if (result.settings) {
    console.log(
      `Compiler:        ${result.settings.version ?? '?'} runs ${result.settings.runs}` +
        `${result.settings.viaIr ? ' via-IR' : ''}, runtime ${fmt(result.runtimeBytes)} bytes`
    );
  }
  console.log(
    `Expected:        ${result.expectedValid ? 'accepted' : `rejected (${result.expected?.error ?? '?'})`}`
  );
  console.log(
    `Calldata:        ${fmt(result.calldataBytes)} bytes, ${fmt(result.calldataGas)} gas (verify(bytes,bytes))`
  );
  console.log(
    `verify estimate: ${result.verifyEstimate === null ? `reverted (${result.verifyEstimateError})` : fmt(result.verifyEstimate)}`
  );
  if (result.call.reverted) {
    console.log(
      `verify() call:   reverted (${result.call.error})${result.call.data ? ` data ${result.call.data}` : ''}`
    );
  } else if (result.call.error) {
    console.log(`verify() call:   ${result.call.error}`);
  } else {
    console.log(`verify() call:   ${result.call.ok}`);
  }
  if (result.tx) {
    console.log(`Gas meter:       ${result.gasMeter}`);
    if (result.tx.simulated) {
      console.log(
        `tx:              not sent (${result.tx.error}); verifyAndLog simulated with qrl_call`
      );
    }
    if (!result.tx.simulated) {
      console.log(
        `tx hash:         ${result.tx.hash} (block ${result.tx.blockNumber}, status ${result.tx.status})`
      );
    }
    console.log(`estimateGas:     ${fmt(result.tx.estimateGas)} (verifyAndLog)`);
    if (!result.tx.simulated) {
      console.log(`gasUsed:         ${fmt(result.tx.gasUsed)} (receipt)`);
    }
    if (result.tx.verified) {
      const ev = result.tx.verified;
      const match =
        ev.proofId.toLowerCase() === result.proofId.toLowerCase() ? 'matches' : 'MISMATCH';
      console.log(`inner gas:       ${fmt(ev.gasUsed)} (Verified event, proofId ${match})`);
      console.log(`ok:              ${ev.ok}`);
    } else {
      console.log('Verified:        no event in receipt');
    }
    if (result.tx.verifyReverted) {
      console.log(`VerifyReverted:  data ${result.tx.verifyReverted.data}`);
    }
  }
  console.log(
    `Result:          ${result.pass ? 'PASS' : 'FAIL'} (verifier ${result.ok ? 'accepted' : 'rejected'}, ` +
      `vector expects ${result.expectedValid ? 'accepted' : 'rejected'})`
  );
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  if (!options.vector) {
    throw new Error(
      'usage: npm run verify:proof -- --vector <path> [--config <path>] [--verifier <addr>] [--gas-meter <addr>] [--call-only]'
    );
  }
  const configPath = options.config
    ? path.resolve(repoRoot, options.config)
    : resolveConfigPath(process.env);
  const config = loadConfig(configPath);
  const vector = loadVector(path.resolve(repoRoot, options.vector));

  const rpc = new RpcClient(config.rpcUrl);
  const chainId = await rpc.chainId();
  if (chainId !== Number(config.chainId)) {
    throw new Error(`chainId mismatch: expected ${config.chainId}, got ${chainId}`);
  }
  const sender = options.callOnly ? null : await getSender(rpc, { repoRoot, chainId });

  console.log(`RPC ${config.rpcUrl} (chain ${chainId})`);
  const result = await runVerifyProof({ rpc, sender, config, vector, options });
  printResult(result);
  if (!result.pass) {
    console.error(`\nverify:proof: ${result.vector} did not behave as the vector expects`);
    process.exit(1);
  }
}

if (require.main === module) {
  main().catch((err) => {
    console.error('\nverify:proof failed:', err.message);
    if (err.data) console.error('Data:', err.data);
    process.exit(1);
  });
}

module.exports = {
  VERIFIED_TOPIC,
  VERIFY_AND_LOG_SIGNATURE,
  VERIFY_REVERTED_TOPIC,
  VERIFY_SIGNATURE,
  calldataGas,
  callVerify,
  decodeVerifiedLog,
  decodeVerifyRevertedLog,
  loadVector,
  parseArgs,
  printResult,
  resolveContracts,
  runVerifyProof,
};
