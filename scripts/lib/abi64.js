// Minimal 64-byte-word ABI helpers for the QRVM (QIP-55).
//
// Rules mirrored from go-qrl accounts/abi and the Hyperion code generator:
// - the function selector stays the first 4 bytes of keccak256(signature);
// - every static head slot is 64 bytes, numbers right-aligned, bytesN and
//   address left-aligned (address is exactly 64 bytes);
// - a dynamic `bytes` argument is a 64-byte offset in the head and a tail of
//   one 64-byte length word followed by the data right-padded to a multiple
//   of 64 bytes;
// - event topic0 is keccak256(signature) left-aligned in a 64-byte topic, and
//   an indexed bytes32 is left-aligned in its 64-byte topic as well.
//
// test/lib/abi.js (the JS reference suite) is the exhaustively tested mirror;
// this module only covers what the toolchain scripts need.

const { keccak_256 } = require('@noble/hashes/sha3');

const WORD_BYTES = 64;
const ADDRESS_BYTES = 64;

function strip0x(hex) {
  return hex.startsWith('0x') || hex.startsWith('0X') ? hex.slice(2) : hex;
}

function hexToBytes(hex) {
  if (typeof hex !== 'string') {
    throw new TypeError('expected a hex string');
  }
  const clean = strip0x(hex);
  if (clean.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(clean)) {
    throw new TypeError(`invalid hex string (${clean.length} chars)`);
  }
  return Uint8Array.from(Buffer.from(clean, 'hex'));
}

function bytesToHex(bytes) {
  return `0x${Buffer.from(bytes).toString('hex')}`;
}

function utf8(text) {
  return new TextEncoder().encode(text);
}

function keccak256Hex(bytes) {
  return bytesToHex(keccak_256(bytes));
}

function selector(signature) {
  return bytesToHex(keccak_256(utf8(signature)).slice(0, 4));
}

// 64-byte topic0: the 32-byte digest followed by 32 zero bytes.
function eventTopic(signature) {
  return `${keccak256Hex(utf8(signature))}${'00'.repeat(32)}`;
}

function padRightToWord(bytes) {
  const padded = Math.ceil(bytes.length / WORD_BYTES) * WORD_BYTES;
  const out = new Uint8Array(padded);
  out.set(bytes);
  return out;
}

function encodeUint(value) {
  let v = BigInt(value);
  if (v < 0n || v >= 1n << 512n) {
    throw new RangeError('uint512 out of range');
  }
  const out = new Uint8Array(WORD_BYTES);
  for (let i = WORD_BYTES - 1; i >= 0 && v > 0n; i -= 1) {
    out[i] = Number(v & 0xffn);
    v >>= 8n;
  }
  return out;
}

// bytes32 (and any bytesN) sits in the high bytes of its 64-byte word.
function encodeBytes32(hex) {
  const bytes = hexToBytes(hex);
  if (bytes.length !== 32) {
    throw new TypeError(`bytes32 needs 32 bytes, got ${bytes.length}`);
  }
  const out = new Uint8Array(WORD_BYTES);
  out.set(bytes);
  return out;
}

// Accepts "Q" + 128 hex, "0x" + 128 hex or bare 128 hex. Returns the 64 raw bytes,
// which is also the complete ABI word for an address argument.
function encodeAddress(address) {
  if (typeof address !== 'string') {
    throw new TypeError('expected an address string');
  }
  const body =
    address.startsWith('Q') || address.startsWith('q') ? address.slice(1) : strip0x(address);
  if (!/^[0-9a-fA-F]+$/.test(body) || body.length !== ADDRESS_BYTES * 2) {
    throw new TypeError(`expected a 64-byte QRL address, got ${address.length} chars`);
  }
  return hexToBytes(body);
}

function addressHex(address) {
  return Buffer.from(encodeAddress(address)).toString('hex');
}

function sameAddress(a, b) {
  return addressHex(a).toLowerCase() === addressHex(b).toLowerCase();
}

function concatBytes(chunks) {
  const total = chunks.reduce((sum, chunk) => sum + chunk.length, 0);
  const out = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    out.set(chunk, offset);
    offset += chunk.length;
  }
  return out;
}

// Calldata for a function whose arguments are all dynamic `bytes`:
// selector | head (one 64-byte offset per argument) | tails.
function encodeBytesArgs(signature, args) {
  const heads = [];
  const tails = [];
  let tailOffset = args.length * WORD_BYTES;
  for (const arg of args) {
    const bytes = arg instanceof Uint8Array ? arg : hexToBytes(arg);
    heads.push(encodeUint(tailOffset));
    const tail = concatBytes([encodeUint(bytes.length), padRightToWord(bytes)]);
    tails.push(tail);
    tailOffset += tail.length;
  }
  return concatBytes([hexToBytes(selector(signature)), ...heads, ...tails]);
}

// Split return data or log data into 64-byte words (hex strings without 0x).
function decodeWords(dataHex) {
  const clean = strip0x(dataHex);
  if (clean.length % (WORD_BYTES * 2) !== 0) {
    throw new TypeError(`data is not a whole number of 64-byte words (${clean.length / 2} bytes)`);
  }
  const words = [];
  for (let i = 0; i < clean.length; i += WORD_BYTES * 2) {
    words.push(clean.slice(i, i + WORD_BYTES * 2));
  }
  return words;
}

function decodeUint(wordHex) {
  const clean = strip0x(wordHex);
  return clean.length === 0 ? 0n : BigInt(`0x${clean}`);
}

function decodeBool(wordHex) {
  const value = decodeUint(wordHex);
  if (value !== 0n && value !== 1n) {
    throw new TypeError(`bool word is neither 0 nor 1: 0x${strip0x(wordHex)}`);
  }
  return value === 1n;
}

// bytes32 from a 64-byte word or topic: the first 32 bytes.
function decodeBytes32(wordHex) {
  const clean = strip0x(wordHex);
  if (clean.length < 64) {
    throw new TypeError('word is shorter than 32 bytes');
  }
  return `0x${clean.slice(0, 64)}`;
}

module.exports = {
  ADDRESS_BYTES,
  WORD_BYTES,
  addressHex,
  bytesToHex,
  concatBytes,
  decodeBool,
  decodeBytes32,
  decodeUint,
  decodeWords,
  encodeAddress,
  encodeBytes32,
  encodeBytesArgs,
  encodeUint,
  eventTopic,
  hexToBytes,
  keccak256Hex,
  padRightToWord,
  sameAddress,
  selector,
  strip0x,
};
