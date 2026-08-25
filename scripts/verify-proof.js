// Send one proof vector through StarkVerifierGasMeter.verifyAndLog, print the
// transaction hash, the receipt gasUsed and the decoded Verified event, and
// qrl_call StarkVerifier.verify for the plain boolean.
//
// Usage:
//   STARK_CONFIG=config/local-stark.json npm run verify:proof -- --vector test/vectors/fib_c3_n20.json
//
// Options:
//   --vector <path>      vector JSON with proofHex and publicValuesHex (required)
//   --config <path>      deployment record (default: STARK_CONFIG or config/local-stark.json)
//   --verifier <addr>    override config.contracts.StarkVerifier
//   --gas-meter <addr>   override config.contracts.StarkVerifierGasMeter
//   --call-only          skip the transaction, only run the qrl_call
//
// Calldata is hand-encoded with the 64-byte-word ABI (scripts/lib/abi64.js).

const fs = require('fs');
const path = require('path');

require('dotenv').config({ path: path.join(__dirname, '..', '.env'), quiet: true });

const { JsonRpcError, RpcClient, toQuantity } = require('./lib/rpc');
const { getSender } = require('./lib/devAccount');
const { loadConfig, resolveConfigPath, withGasMargin } = require('./deploy');
const abi = require('./lib/abi64');

const repoRoot = path.join(__dirname, '..');

const VERIFY_SIGNATURE = 'verify(bytes,bytes)';
const VERIFY_AND_LOG_SIGNATURE = 'verifyAndLog(bytes,bytes)';
const VERIFIED_TOPIC = abi.eventTopic('Verified(bytes32,bool,uint512)');
const VERIFY_REVERTED_TOPIC = abi.eventTopic('VerifyReverted(bytes32,bytes)');

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
    name: path.basename(file, '.json'),
    file,
    config: raw.config ?? null,
    degreeBits: raw.degreeBits ?? null,
    expected: raw.expected ?? null,
    proof: abi.hexToBytes(proofHex),
    publicValues: abi.hexToBytes(publicValuesHex),
    raw,
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

async function callVerify(rpc, verifier, vector) {
  const data = abi.bytesToHex(
    abi.encodeBytesArgs(VERIFY_SIGNATURE, [vector.proof, vector.publicValues])
  );
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

// Runs the qrl_call and (unless callOnly) the gas-meter transaction.
async function runVerifyProof({ rpc, sender, config, vector, options = {} }) {
  const verifier = options.verifier || config.contracts?.StarkVerifier;
  const gasMeter = options.gasMeter || config.contracts?.StarkVerifierGasMeter;
  if (!verifier) throw new Error('StarkVerifier address is unknown; run `npm run deploy`');

  const result = {
    vector: vector.name,
    config: vector.config,
    degreeBits: vector.degreeBits,
    proofBytes: vector.proof.length,
    publicValuesBytes: vector.publicValues.length,
    proofId: abi.keccak256Hex(vector.proof),
    expected: vector.expected,
    call: await callVerify(rpc, verifier, vector),
    tx: null,
  };

  if (options.callOnly) {
    return result;
  }
  if (!gasMeter) throw new Error('StarkVerifierGasMeter address is unknown; run `npm run deploy`');

  const data = abi.bytesToHex(
    abi.encodeBytesArgs(VERIFY_AND_LOG_SIGNATURE, [vector.proof, vector.publicValues])
  );
  const latest = await rpc.getBlockByNumber('latest');
  const gasCap = latest?.gasLimit ? BigInt(latest.gasLimit) : null;
  const estimate = await sender.estimateGas({ to: gasMeter, data });
  const gas = withGasMargin(estimate, gasCap);
  const receipt = await sender.send({ to: gasMeter, data, gas: toQuantity(gas) });

  const verified = logsFrom(receipt, gasMeter, VERIFIED_TOPIC).map(decodeVerifiedLog);
  const reverted = logsFrom(receipt, gasMeter, VERIFY_REVERTED_TOPIC).map(decodeVerifyRevertedLog);
  result.tx = {
    hash: receipt.transactionHash,
    status: Number(receipt.status),
    estimateGas: estimate,
    gasSent: gas,
    gasUsed: BigInt(receipt.gasUsed),
    blockNumber: Number(receipt.blockNumber),
    verified: verified[0] ?? null,
    verifyReverted: reverted[0] ?? null,
  };
  return result;
}

function printResult(result) {
  console.log(
    `\nVector:        ${result.vector} (config ${result.config ?? '?'}, degreeBits ${result.degreeBits ?? '?'})`
  );
  console.log(
    `Proof bytes:   ${result.proofBytes} (public values ${result.publicValuesBytes} bytes)`
  );
  console.log(`proofId:       ${result.proofId}`);
  if (result.expected) {
    console.log(`Expected:      ${JSON.stringify(result.expected)}`);
  }
  if (result.call.reverted) {
    console.log(
      `verify() call: reverted (${result.call.error})${result.call.data ? ` data ${result.call.data}` : ''}`
    );
  } else if (result.call.error) {
    console.log(`verify() call: ${result.call.error}`);
  } else {
    console.log(`verify() call: ${result.call.ok}`);
  }
  if (!result.tx) return;
  console.log(
    `tx hash:       ${result.tx.hash} (block ${result.tx.blockNumber}, status ${result.tx.status})`
  );
  console.log(`estimateGas:   ${result.tx.estimateGas}`);
  console.log(`gasUsed:       ${result.tx.gasUsed}`);
  if (result.tx.verified) {
    const ev = result.tx.verified;
    const match =
      ev.proofId.toLowerCase() === result.proofId.toLowerCase() ? 'matches' : 'MISMATCH';
    console.log(
      `Verified:      ok=${ev.ok} gasUsed=${ev.gasUsed} proofId=${ev.proofId} (${match})`
    );
  } else {
    console.log('Verified:      no event in receipt');
  }
  if (result.tx.verifyReverted) {
    console.log(`VerifyReverted: data ${result.tx.verifyReverted.data}`);
  }
}

async function main() {
  const options = parseArgs(process.argv.slice(2));
  if (!options.vector) {
    throw new Error(
      'usage: npm run verify:proof -- --vector <path> [--config <path>] [--call-only]'
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
  console.log(`StarkVerifier ${options.verifier || config.contracts?.StarkVerifier}`);
  console.log(
    `StarkVerifierGasMeter ${options.gasMeter || config.contracts?.StarkVerifierGasMeter}`
  );

  const result = await runVerifyProof({ rpc, sender, config, vector, options });
  printResult(result);
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
  VERIFY_REVERTED_TOPIC,
  callVerify,
  decodeVerifiedLog,
  decodeVerifyRevertedLog,
  loadVector,
  parseArgs,
  printResult,
  runVerifyProof,
};
