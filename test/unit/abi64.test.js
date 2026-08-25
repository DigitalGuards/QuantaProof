// 64-byte-word ABI helpers used by the toolchain scripts (scripts/lib/abi64.js).
// The exhaustive reference lives in test/lib/abi.js; these tests pin the
// layout rules the deploy and verify scripts depend on.

const assert = require('node:assert/strict');
const test = require('node:test');

const { keccak_256 } = require('@noble/hashes/sha3');

const abi = require('../../scripts/lib/abi64');

test('selector is the first 4 bytes of keccak256(signature)', () => {
  // Well-known Ethereum selector; the 4-byte rule is unchanged on the QRVM.
  assert.equal(abi.selector('transfer(address,uint256)'), '0xa9059cbb');
  const expected = Buffer.from(keccak_256(new TextEncoder().encode('verify(bytes,bytes)')))
    .subarray(0, 4)
    .toString('hex');
  assert.equal(abi.selector('verify(bytes,bytes)'), `0x${expected}`);
});

test('event topic0 is the 32-byte digest left-aligned in a 64-byte topic', () => {
  const topic = abi.eventTopic('Verified(bytes32,bool,uint512)');
  assert.equal(topic.length, 2 + 128);
  const digest = Buffer.from(
    keccak_256(new TextEncoder().encode('Verified(bytes32,bool,uint512)'))
  ).toString('hex');
  assert.equal(topic.slice(2, 66), digest);
  assert.equal(topic.slice(66), '00'.repeat(32));
});

test('encodeBytesArgs lays out head offsets and 64-byte padded tails', () => {
  const a = Uint8Array.from([1, 2, 3]); // pads to 64
  const b = new Uint8Array(65); // pads to 128
  b[64] = 9;
  const calldata = abi.encodeBytesArgs('verifyAndLog(bytes,bytes)', [a, b]);

  const headBytes = 2 * abi.WORD_BYTES;
  const tailA = abi.WORD_BYTES + 64;
  const tailB = abi.WORD_BYTES + 128;
  assert.equal(calldata.length, 4 + headBytes + tailA + tailB);

  const hex = Buffer.from(calldata).toString('hex');
  assert.equal(`0x${hex.slice(0, 8)}`, abi.selector('verifyAndLog(bytes,bytes)'));
  const words = abi.decodeWords(hex.slice(8));
  assert.equal(abi.decodeUint(words[0]), BigInt(headBytes));
  assert.equal(abi.decodeUint(words[1]), BigInt(headBytes + tailA));
  assert.equal(abi.decodeUint(words[2]), 3n);
  assert.equal(words[3], `010203${'00'.repeat(61)}`);
  assert.equal(abi.decodeUint(words[4]), 65n);
  assert.equal(words[5], '00'.repeat(64));
  assert.equal(words[6], `09${'00'.repeat(63)}`);
});

test('encodeBytesArgs accepts hex strings and empty arguments', () => {
  const calldata = abi.encodeBytesArgs('verify(bytes,bytes)', ['0x', '0xff']);
  const words = abi.decodeWords(Buffer.from(calldata).toString('hex').slice(8));
  assert.equal(abi.decodeUint(words[0]), 128n);
  assert.equal(abi.decodeUint(words[1]), 128n + 64n); // empty tail is one length word
  assert.equal(abi.decodeUint(words[2]), 0n);
  assert.equal(abi.decodeUint(words[3]), 1n);
  assert.equal(words[4], `ff${'00'.repeat(63)}`);
});

test('encodeAddress accepts Q, 0x and bare 128-hex forms and rejects other widths', () => {
  const body = 'ab'.repeat(64);
  for (const form of [`Q${body}`, `0x${body}`, body]) {
    const encoded = abi.encodeAddress(form);
    assert.equal(encoded.length, 64);
    assert.equal(Buffer.from(encoded).toString('hex'), body);
  }
  assert.equal(abi.addressHex(`Q${body.toUpperCase()}`).toLowerCase(), body);
  assert.equal(abi.sameAddress(`Q${body.toUpperCase()}`, `0x${body}`), true);
  assert.throws(() => abi.encodeAddress(`Q${'ab'.repeat(20)}`), /64-byte QRL address/);
  assert.throws(() => abi.encodeAddress(`Q${'zz'.repeat(64)}`), /64-byte QRL address/);
});

test('uint and bool words are right-aligned, bytes32 is left-aligned', () => {
  const one = abi.encodeUint(1);
  assert.equal(one.length, 64);
  assert.equal(one[63], 1);
  assert.equal(abi.decodeUint(Buffer.from(one).toString('hex')), 1n);
  assert.equal(abi.decodeBool(`${'00'.repeat(63)}01`), true);
  assert.equal(abi.decodeBool(`0x${'00'.repeat(64)}`), false);
  assert.throws(() => abi.decodeBool(`${'00'.repeat(63)}02`), /neither 0 nor 1/);
  assert.throws(() => abi.encodeUint(1n << 512n), /out of range/);

  const digest = `0x${'cd'.repeat(32)}`;
  const word = abi.encodeBytes32(digest);
  assert.equal(Buffer.from(word.subarray(0, 32)).toString('hex'), 'cd'.repeat(32));
  assert.equal(Buffer.from(word.subarray(32)).toString('hex'), '00'.repeat(32));
  assert.equal(abi.decodeBytes32(Buffer.from(word).toString('hex')), digest);
});

test('decodeWords rejects data that is not whole 64-byte words', () => {
  assert.throws(() => abi.decodeWords('0x' + '00'.repeat(32)), /64-byte words/);
  assert.deepEqual(abi.decodeWords('0x'), []);
});
