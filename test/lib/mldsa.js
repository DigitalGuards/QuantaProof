// ML-DSA-87 helpers for the bridge suite (test/contracts/bridge.test.js).
//
// Wraps @theqrl/mldsa87 (the library behind @theqrl/wallet.js) so a test can
// generate a keypair, sign the 64-byte SHAKE256 withdrawal digest with the
// bridge's context string and check the signature offline before it goes on
// chain. The signing convention mirrors the QNS SDK and its precompile
// verification script: the message handed to ML-DSA-87 is the 64-byte digest
// itself (no further hashing on either side), the context string is passed as
// the FIPS 204 ctx, and precompile 0x03 consumes
//   digest(64) || publicKey(2592) || signature(4627) || uint8(ctx.length) || ctx
// which the Hyperion builtin mldsa87verify(digest, signature, publicKey, context)
// packs for the contract. encodePrecompileInput reproduces that frame so a
// test can call 0x03 directly and compare with the builtin's verdict.

const { shake256, keccak_256 } = require('@noble/hashes/sha3');
const mldsa = require('@theqrl/mldsa87');

const abi = require('../../scripts/lib/abi64');

const PUBLIC_KEY_BYTES = mldsa.CryptoPublicKeyBytes; // 2592
const SECRET_KEY_BYTES = mldsa.CryptoSecretKeyBytes; // 4896
const SIGNATURE_BYTES = mldsa.CryptoBytes; // 4627
const DIGEST_BYTES = 64;
const MAX_CONTEXT_BYTES = 255;
const SEED_BYTES = 32;

// Domain separator of StateBridge.withdraw: message prefix and ML-DSA-87 context.
const WITHDRAW_CONTEXT = 'QP-WITHDRAW-v1';

// Precompile slots (64-byte addresses, Q-prefixed as the node expects them).
const MLDSA87_VERIFY_PRECOMPILE = `Q${'0'.repeat(127)}3`;
const SHAKE256_PRECOMPILE = `Q${'0'.repeat(127)}6`;

// Return words of precompile 0x03: exactly one 64-byte word with a trailing 1
// on success; empty return data (or a zero word) on failure.
const PRECOMPILE_TRUE = `0x${'00'.repeat(63)}01`;

const utf8 = (text) => new TextEncoder().encode(text);

function toBytes(value) {
  return value instanceof Uint8Array ? value : abi.hexToBytes(value);
}

function checkContext(context) {
  if (context.length > MAX_CONTEXT_BYTES) {
    throw new RangeError(`ML-DSA-87 context is limited to ${MAX_CONTEXT_BYTES} bytes`);
  }
}

// Deterministic keypair from a 32-byte seed (a random seed when omitted).
// The returned seed is secret-key material; tests keep it in memory only.
function generateKeypair(seed) {
  const seedBytes = seed === undefined ? null : toBytes(seed);
  if (seedBytes !== null && seedBytes.length !== SEED_BYTES) {
    throw new RangeError(`seed must be ${SEED_BYTES} bytes`);
  }
  const publicKey = new Uint8Array(PUBLIC_KEY_BYTES);
  const secretKey = new Uint8Array(SECRET_KEY_BYTES);
  const usedSeed = mldsa.cryptoSignKeypair(seedBytes, publicKey, secretKey);
  return { publicKey, secretKey, seed: usedSeed };
}

// keccak256 of the public key: what a withdrawal leaf commits to (pkHash).
function publicKeyHash(publicKey) {
  return abi.bytesToHex(keccak_256(toBytes(publicKey)));
}

// Sign a 64-byte digest with the context string. Deterministic signing keeps
// vectors reproducible; the precompile accepts hedged signatures just the same.
function signDigest(digest, secretKey, context = WITHDRAW_CONTEXT, options = {}) {
  const digestBytes = toBytes(digest);
  if (digestBytes.length !== DIGEST_BYTES) {
    throw new RangeError(`digest must be ${DIGEST_BYTES} bytes`);
  }
  const contextBytes = typeof context === 'string' ? utf8(context) : toBytes(context);
  checkContext(contextBytes);
  const signature = new Uint8Array(SIGNATURE_BYTES);
  const randomized = options.randomized === true;
  const status = mldsa.cryptoSignSignature(
    signature,
    digestBytes,
    toBytes(secretKey),
    randomized,
    contextBytes
  );
  if (status !== 0) {
    throw new Error(`cryptoSignSignature returned ${status}`);
  }
  return signature;
}

// Offline check with the library's own verifier.
function verifyDigest(signature, digest, publicKey, context = WITHDRAW_CONTEXT) {
  const contextBytes = typeof context === 'string' ? utf8(context) : toBytes(context);
  checkContext(contextBytes);
  return mldsa.cryptoSignVerify(
    toBytes(signature),
    toBytes(digest),
    toBytes(publicKey),
    contextBytes
  );
}

// 64-byte SHAKE256 digest, equal to what precompile 0x06 and the Hyperion
// shake256 builtin return for the same message.
function shake256Digest(message) {
  return shake256(toBytes(message), { dkLen: DIGEST_BYTES });
}

// Message the bridge hashes: "QP-WITHDRAW-v1" || leaf (32 bytes) || recipient (64 bytes).
function withdrawMessage(leaf, recipient) {
  return abi.concatBytes([
    utf8(WITHDRAW_CONTEXT),
    abi.hexToBytes(leaf),
    abi.encodeAddress(recipient),
  ]);
}

function withdrawDigest(leaf, recipient) {
  return shake256Digest(withdrawMessage(leaf, recipient));
}

// The exact input frame of precompile 0x03 (and of the mldsa87verify builtin).
function encodePrecompileInput(digest, signature, publicKey, context = WITHDRAW_CONTEXT) {
  const digestBytes = toBytes(digest);
  const signatureBytes = toBytes(signature);
  const publicKeyBytes = toBytes(publicKey);
  const contextBytes = typeof context === 'string' ? utf8(context) : toBytes(context);
  if (digestBytes.length !== DIGEST_BYTES) {
    throw new RangeError(`digest must be ${DIGEST_BYTES} bytes`);
  }
  if (signatureBytes.length !== SIGNATURE_BYTES) {
    throw new RangeError(`signature must be ${SIGNATURE_BYTES} bytes`);
  }
  if (publicKeyBytes.length !== PUBLIC_KEY_BYTES) {
    throw new RangeError(`public key must be ${PUBLIC_KEY_BYTES} bytes`);
  }
  checkContext(contextBytes);
  return abi.concatBytes([
    digestBytes,
    publicKeyBytes,
    signatureBytes,
    Uint8Array.of(contextBytes.length),
    contextBytes,
  ]);
}

function zeroize(buffer) {
  mldsa.zeroize(buffer);
}

module.exports = {
  DIGEST_BYTES,
  MAX_CONTEXT_BYTES,
  MLDSA87_VERIFY_PRECOMPILE,
  PRECOMPILE_TRUE,
  PUBLIC_KEY_BYTES,
  SECRET_KEY_BYTES,
  SEED_BYTES,
  SHAKE256_PRECOMPILE,
  SIGNATURE_BYTES,
  WITHDRAW_CONTEXT,
  encodePrecompileInput,
  generateKeypair,
  publicKeyHash,
  shake256Digest,
  signDigest,
  verifyDigest,
  withdrawDigest,
  withdrawMessage,
  zeroize,
};
