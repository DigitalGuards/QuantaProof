// Plain binary keccak256 Merkle tree and the StateBridge leaf encodings.
//
// This is the withdrawal-tree reference for test/contracts/bridge.test.js and
// mirrors StateBridge.verifyInclusion: parent = keccak256(left || right) over
// two 32-byte digests, the side of a node at level i given by bit i of the
// leaf index, no sorting, no domain separation. It is unrelated to the pruned
// multi-opening Merkle code of the STARK verifier (test/lib/merkle.js), which
// has its own leaf hashing and frontier walk.
//
// Leaves and digests are 32-byte values given as 0x-hex or Uint8Array; every
// function returns 0x-hex for digests. Trees are padded with zero leaves up to
// the next power of two so that every proof has the same length (the depth).

const { keccak_256 } = require('@noble/hashes/sha3');

const abi = require('../../scripts/lib/abi64');

const ZERO_DIGEST = `0x${'00'.repeat(32)}`;

function toDigest(value) {
  const bytes = value instanceof Uint8Array ? value : abi.hexToBytes(value);
  if (bytes.length !== 32) {
    throw new TypeError(`digest needs 32 bytes, got ${bytes.length}`);
  }
  return bytes;
}

function hashPair(left, right) {
  return abi.bytesToHex(keccak_256(abi.concatBytes([toDigest(left), toDigest(right)])));
}

// Build a tree over `leaves` (already hashed). Returns { root, depth, layers,
// leafCount } where layers[0] holds the padded leaves and layers[depth] the root.
function buildTree(leaves) {
  if (leaves.length === 0) {
    throw new RangeError('a tree needs at least one leaf');
  }
  let depth = 0;
  while (1 << depth < leaves.length) depth += 1;
  const width = 1 << depth;
  const level0 = leaves.map((leaf) => abi.bytesToHex(toDigest(leaf)));
  while (level0.length < width) level0.push(ZERO_DIGEST);

  const layers = [level0];
  for (let d = 0; d < depth; d += 1) {
    const below = layers[d];
    const above = [];
    for (let i = 0; i < below.length; i += 2) {
      above.push(hashPair(below[i], below[i + 1]));
    }
    layers.push(above);
  }
  return { root: layers[depth][0], depth, layers, leafCount: leaves.length };
}

// Sibling digests from the leaf level up; proof[i] is the sibling at level i.
function getProof(tree, index) {
  if (!Number.isInteger(index) || index < 0 || index >= 1 << tree.depth) {
    throw new RangeError(`leaf index ${index} is outside the tree`);
  }
  const proof = [];
  let position = index;
  for (let d = 0; d < tree.depth; d += 1) {
    proof.push(tree.layers[d][position ^ 1]);
    position >>= 1;
  }
  return proof;
}

// Same walk as StateBridge.verifyInclusion, including the index-range check.
function verifyProof(leaf, proof, index, root) {
  const indexBig = BigInt(index);
  if (indexBig >> BigInt(proof.length) !== 0n) return false;
  let node = abi.bytesToHex(toDigest(leaf));
  let position = indexBig;
  for (const sibling of proof) {
    node = (position & 1n) === 0n ? hashPair(node, sibling) : hashPair(sibling, node);
    position >>= 1n;
  }
  return node.toLowerCase() === abi.bytesToHex(toDigest(root)).toLowerCase();
}

// StateBridge.withdraw leaf: keccak256(pkHash(32) || recipient(64) || amount(64) || nonce(64)).
function withdrawalLeaf(pkHash, recipient, amount, nonce) {
  return abi.bytesToHex(
    keccak_256(
      abi.concatBytes([
        toDigest(pkHash),
        abi.encodeAddress(recipient),
        abi.encodeUint(amount),
        abi.encodeUint(nonce),
      ])
    )
  );
}

// StateBridge.deposit leaf: keccak256(sender(64) || amount(64) || index(64)).
function depositLeaf(sender, amount, index) {
  return abi.bytesToHex(
    keccak_256(
      abi.concatBytes([abi.encodeAddress(sender), abi.encodeUint(amount), abi.encodeUint(index)])
    )
  );
}

// StateBridge.depositAccumulator update: keccak256(prev(32) || leaf(32)).
function accumulate(previous, leaf) {
  return hashPair(previous, leaf);
}

module.exports = {
  ZERO_DIGEST,
  accumulate,
  buildTree,
  depositLeaf,
  getProof,
  hashPair,
  verifyProof,
  withdrawalLeaf,
};
