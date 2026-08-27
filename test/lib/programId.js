// The canonical program identifier of the Fibonacci verifier (docs/PROTOCOL.md
// section 1.3) and its transcript role (section 5, step 0): every verifier
// observes these 32 bytes before anything else, so a proof made for one AIR,
// layout or parameter set never replays under another.
//
//   keccak256("QSTARK-FIBONACCI-v1" || uint512(24) || uint512(log_blowup)
//     || uint512(log_final_poly_len) || uint512(max_log_arity)
//     || uint512(num_queries) || uint512(commit_pow_bits)
//     || uint512(query_pow_bits))
//
// with every uint512 packed as 64 big-endian bytes (467 preimage bytes). This
// is a self-contained mirror of StarkVerifier.programIdentifier() and of
// prover/stark-prover/src/config.rs::program_identifier, kept independent of
// the deployment tooling (scripts/lib/presets.js::programIdFor computes the
// same value; test/unit/programId.test.js pins the three implementations to
// each other and to the vectors).

const { keccak_256 } = require('@noble/hashes/sha3');

const { bytesToHex } = require('./vectors');

const PROGRAM_ID_LABEL = 'QSTARK-FIBONACCI-v1';
const PUBLIC_VALUES_BYTES = 24;
const WORD_BYTES = 64;
// The parameter order of the packed preimage (section 1.3).
const PARAMETER_ORDER = Object.freeze([
  'logBlowup',
  'logFinalPolyLen',
  'maxLogArity',
  'numQueries',
  'commitPowBits',
  'queryPowBits',
]);

// One packed uint512: 64 big-endian bytes.
function packedWord(value) {
  const n = Number(value);
  if (!Number.isInteger(n) || n < 0) {
    throw new TypeError(`packed uint512 needs a non-negative integer, got ${String(value)}`);
  }
  const out = new Uint8Array(WORD_BYTES);
  let v = BigInt(n);
  for (let i = WORD_BYTES - 1; i >= 0 && v > 0n; i -= 1) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

// The abi.encodePacked preimage: label, public-value length, six parameters.
function programIdPreimage(config) {
  const label = new TextEncoder().encode(PROGRAM_ID_LABEL);
  const words = [PUBLIC_VALUES_BYTES, ...PARAMETER_ORDER.map((key) => config[key])];
  const out = new Uint8Array(label.length + words.length * WORD_BYTES);
  out.set(label, 0);
  words.forEach((w, i) => out.set(packedWord(w), label.length + i * WORD_BYTES));
  return out;
}

// The 32 identifier bytes.
function programIdentifier(config) {
  return keccak_256(programIdPreimage(config));
}

// The identifier as 0x-hex (the `programIdentifier` field of the vectors).
function programIdentifierHex(config) {
  return bytesToHex(programIdentifier(config));
}

module.exports = {
  PARAMETER_ORDER,
  PROGRAM_ID_LABEL,
  PUBLIC_VALUES_BYTES,
  WORD_BYTES,
  packedWord,
  programIdPreimage,
  programIdentifier,
  programIdentifierHex,
};
