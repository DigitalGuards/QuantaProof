// Pruned multi-opening parity (docs/PROTOCOL.md section 9): every Merkle
// block of every valid vector verifies against its root from the vector's
// rows and sibling hashes with the recorded frontier digests, the consumed
// sibling counts equal the sib_count fields, the wire order is pinned on a
// hand-built tree, and every Merkle mutation fails at the expected block with
// the expected error.

const assert = require('node:assert/strict');
const { describe, test } = require('node:test');

const V = require('../lib/vectors');
const L = require('../lib/layout');
const M = require('../lib/merkle');
const G = require('../lib/goldilocks');

const valid = V.loadValidVectors();
const mutated = V.loadMutationVectors();

// Leaf preimages per query for a block: input rows in wire form from the
// decoded proof, round rows (query value plus sibling values) from `fold`.
function blockRows(vector, proof, blockIndex) {
  const q = vector.config.numQueries;
  const numRounds = vector.layout.rounds.length;
  if (blockIndex < 2) {
    const rows = blockIndex === 0 ? proof.traceRows : proof.quotientRows;
    return rows.map((row) => V.concatBytes(...row.map(L.fBytes)));
  }
  const r = blockIndex - 2;
  const out = [];
  for (let qi = 0; qi < q; qi += 1) {
    const step = vector.fold[qi * numRounds + r];
    assert.equal(step.query, qi);
    assert.equal(step.round, r);
    out.push(V.concatBytes(...step.row.map((e) => L.efBytes(V.ef(e)))));
  }
  return out;
}

function blockSiblings(proof, blockIndex) {
  if (blockIndex === 0) return proof.traceSiblings;
  if (blockIndex === 1) return proof.quotientSiblings;
  return proof.rounds[blockIndex - 2].siblings;
}

function blockIndices(vector, blockIndex) {
  if (blockIndex < 2) return vector.challenges.indices;
  const numRounds = vector.layout.rounds.length;
  const r = blockIndex - 2;
  return vector.challenges.indices.map((_, qi) => vector.fold[qi * numRounds + r].foldedIndex);
}

describe('every block of every valid vector verifies against its root', () => {
  for (const { baseName, vector } of valid) {
    test(baseName, () => {
      const proof = L.decodeProof(V.proofBytes(vector), vector.config);
      const h = vector.degreeBits + vector.config.logBlowup;
      let height = h;
      vector.merkle.forEach((block, b) => {
        const expectedHeight = b < 2 ? h : height - vector.layout.rounds[b - 2].logArity;
        if (b >= 2) height = expectedHeight;
        assert.equal(block.logHeight, expectedHeight, `${block.name} height`);

        const indices = blockIndices(vector, b);
        assert.deepEqual(block.indices, indices, `${block.name} indices`);
        const rows = blockRows(vector, proof, b);
        const siblings = blockSiblings(proof, b);
        const layoutCount =
          b < 2 ? vector.layout.blocks[b].sibCount : vector.layout.rounds[b - 2].sibCount;
        assert.equal(siblings.length, layoutCount);
        assert.equal(block.sibCount, layoutCount);

        const result = M.verifyPrunedRows(
          V.hexToBytes(block.root),
          block.logHeight,
          indices,
          rows,
          siblings
        );
        assert.equal(result.ok, true, `${block.name}: ${result.error}`);
        assert.equal(result.consumed, block.sibCount, `${block.name} consumed == sib_count`);
        assert.equal(result.expected, block.sibCount);
        assert.equal(M.expectedSiblingCount(block.sortedUnique, block.logHeight), block.sibCount);
        assert.deepEqual(result.sortedUnique, block.sortedUnique);
        let d = V.firstDifference(result.leaves, block.leaves);
        assert.equal(d, null, `${block.name} leaves: ${d}`);
        d = V.firstDifference(result.levels, block.levels);
        assert.equal(d, null, `${block.name} levels: ${d}`);
        assert.equal(result.levels.length, block.logHeight);
        const top = result.levels[result.levels.length - 1];
        assert.deepEqual(top, [{ index: 0, digest: block.root }]);

        // Round leaves are keccak256 of the row bytes recorded per fold step.
        if (b >= 2) {
          const numRounds = vector.layout.rounds.length;
          rows.forEach((row, qi) => {
            const step = vector.fold[qi * numRounds + (b - 2)];
            assert.equal(V.bytesToHex(M.leafDigest(row)), step.leafDigest);
          });
        }
      });
      assert.equal(height, vector.config.logBlowup + vector.config.logFinalPolyLen);
    });
  }
});

describe('frontier walk wire order (pruning.rs walk_frontier)', () => {
  const rng = G.prng(2024);
  const randomDigest = () => {
    const d = new Uint8Array(32);
    for (let i = 0; i < 32; i += 1) d[i] = rng.int(256);
    return d;
  };
  const leaves8 = Array.from({ length: 8 }, randomDigest);
  const tree = M.buildTree(leaves8);

  test('height-3 tree, leaves {1, 2, 5}: siblings 0, 3, 4 at level 0, F at level 1', () => {
    // The example of the pruning.rs module documentation.
    const indices = [5, 1, 2, 1];
    const pruned = M.pruneTree(tree, indices);
    const f = tree.levels[1][3];
    assert.deepEqual(
      pruned.map(V.bytesToHex),
      [leaves8[0], leaves8[3], leaves8[4], f].map(V.bytesToHex)
    );
    assert.equal(M.expectedSiblingCount([1, 2, 5], 3), 4);
    assert.equal(M.expectedSiblingCount([0, 1, 2, 3, 4, 5, 6, 7], 3), 0);
    assert.equal(M.expectedSiblingCount([5], 3), 3);
    assert.equal(M.expectedSiblingCount([0], 0), 0);

    const digests = indices.map((i) => leaves8[i]);
    const result = M.verifyPruned(tree.root, 3, indices, digests, pruned);
    assert.equal(result.ok, true, result.error);
    assert.equal(result.consumed, 4);
    assert.deepEqual(result.sortedUnique, [1, 2, 5]);
    assert.deepEqual(result.reps, [1, 2, 0], 'representative = first query opening the leaf');
    assert.deepEqual(
      result.levels.map((level) => level.map((n) => n.index)),
      [[0, 1, 2], [0, 1], [0]]
    );
    assert.equal(result.levels[2][0].digest, V.bytesToHex(tree.root));
  });

  test('swapping two siblings breaks the root (order is part of the wire format)', () => {
    const indices = [1, 2, 5];
    const pruned = M.pruneTree(tree, indices);
    const swapped = [pruned[1], pruned[0], pruned[2], pruned[3]];
    const result = M.verifyPruned(
      tree.root,
      3,
      indices,
      indices.map((i) => leaves8[i]),
      swapped
    );
    assert.equal(result.ok, false);
    assert.equal(result.error, 'MerkleRootMismatch');
    assert.equal(result.consumed, 4);
  });

  test('error precedence: duplicates, then sibling count, then root', () => {
    const indices = [1, 5, 1];
    const pruned = M.pruneTree(tree, indices);
    const good = indices.map((i) => leaves8[i]);
    const bad = [leaves8[1], leaves8[5], randomDigest()];
    const wrongRoot = randomDigest();
    let r = M.verifyPruned(wrongRoot, 3, indices, bad, pruned.slice(0, -1));
    assert.equal(r.error, 'DuplicateOpeningMismatch');
    assert.equal(r.duplicateIndex, 1);
    r = M.verifyPruned(wrongRoot, 3, indices, good, pruned.slice(0, -1));
    assert.equal(r.error, 'SiblingCountMismatch');
    assert.equal(r.expected, pruned.length);
    r = M.verifyPruned(wrongRoot, 3, indices, good, pruned.concat([randomDigest()]));
    assert.equal(r.error, 'SiblingCountMismatch');
    r = M.verifyPruned(wrongRoot, 3, indices, good, pruned);
    assert.equal(r.error, 'MerkleRootMismatch');
    r = M.verifyPruned(tree.root, 3, indices, good, pruned);
    assert.equal(r.ok, true);
  });

  test('verifyPrunedRows hashes representatives only and compares duplicate rows bytewise', () => {
    const rows = [Uint8Array.from([1, 2]), Uint8Array.from([3]), Uint8Array.from([1, 2])];
    const digests = rows.map(M.leafDigest);
    const t = M.buildTree([digests[0], digests[1], randomDigest(), randomDigest()]);
    const indices = [0, 1, 0];
    const pruned = M.pruneTree(t, indices);
    assert.equal(M.verifyPrunedRows(t.root, 2, indices, rows, pruned).ok, true);
    const mismatch = [rows[0], rows[1], Uint8Array.from([1, 3])];
    const r = M.verifyPrunedRows(t.root, 2, indices, mismatch, pruned);
    assert.equal(r.error, 'DuplicateOpeningMismatch');
    assert.equal(M.verifyPrunedRows(t.root, 2, [0, 1], rows.slice(0, 2), pruned).ok, true);
  });

  test('all leaves opened needs no siblings; a height-0 tree is its leaf', () => {
    const all = [0, 1, 2, 3, 4, 5, 6, 7];
    const r = M.verifyPruned(tree.root, 3, all, leaves8, []);
    assert.equal(r.ok, true);
    assert.equal(r.consumed, 0);
    const leaf = randomDigest();
    assert.equal(M.verifyPruned(leaf, 0, [0], [leaf], []).ok, true);
    assert.equal(M.verifyPruned(leaf, 0, [0], [randomDigest()], []).error, 'MerkleRootMismatch');
    assert.throws(() => M.verifyPruned(tree.root, 3, [8], [leaf], []), /outside/);
  });

  test('compression is keccak256(left || right) and leaves are keccak256(row bytes)', () => {
    const { keccak_256 } = require('@noble/hashes/sha3');
    const a = randomDigest();
    const b = randomDigest();
    assert.deepEqual(M.compress(a, b), keccak_256(V.concatBytes(a, b)));
    assert.notDeepEqual(M.compress(a, b), M.compress(b, a));
    const row = L.efBytes([1n, 2n]);
    assert.deepEqual(M.leafDigest(row), keccak_256(row));
  });
});

describe('Merkle mutations fail at the expected block', () => {
  const merkleErrors = new Set([
    'MerkleRootMismatch',
    'SiblingCountMismatch',
    'DuplicateOpeningMismatch',
  ]);
  for (const { baseName, vector } of mutated) {
    if (!merkleErrors.has(vector.expected.error)) continue;
    test(`${baseName}: ${vector.expected.error}`, () => {
      const source = V.loadSourceVector(vector);
      const proof = L.decodeProof(V.proofBytes(vector), vector.config);
      // None of these mutations touches the prefix, so the transcript (and the
      // query indices) of the source vector still apply.
      assert.equal(proof.proofId, source.proofId);
      const numBlocks = 2 + source.layout.rounds.length;
      const results = [];
      for (let b = 0; b < numBlocks; b += 1) {
        const block = source.merkle[b];
        const indices = blockIndices(source, b);
        const rows = blockRows(source, proof, b);
        const r = M.verifyPrunedRows(
          V.hexToBytes(block.root),
          block.logHeight,
          indices,
          rows,
          blockSiblings(proof, b)
        );
        results.push({ name: block.name, ok: r.ok, error: r.error });
      }
      const failing = results.filter((r) => !r.ok);
      assert.equal(failing.length, 1, JSON.stringify(results));
      assert.equal(failing[0].error, vector.expected.error);
      const expectedBlock =
        vector.expected.mutation === 'flip_round_sibling'
          ? `round[${source.layout.rounds.findIndex((r) => r.sibCount > 0)}]`
          : 'trace';
      assert.equal(failing[0].name, expectedBlock);
    });
  }
});
