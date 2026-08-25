// JS reference for the keccak256 Merkle commitments and the pruned
// multi-opening verification of p3-merkle-tree 0.7.0-rc.1 as QuantaStark
// uses them: binary trees (N = 2), 32-byte digests, cap height 0 (the
// commitment is the single root), one matrix per commitment.
//
// - Leaf digest: keccak256 of the row in wire form (each field element as a
//   canonical 8-byte little-endian word). SerializingHasher streams the
//   elements as bytes (p3-symmetric/src/serializing_hasher.rs:22-33) and the
//   pruned verifier hashes one leaf per unique index from its representative
//   query's rows (p3-merkle-tree/src/mmcs/mod.rs:591-600).
// - Compression: parent = keccak256(left || right), children in position
//   order (p3-symmetric/src/compression.rs:61-70, hash_iter over the flattened
//   inputs).
// - Wire order of the pruned proof: the frontier walk `walk_frontier` in
//   p3-merkle-tree/src/pruning.rs:130-176 (shared by prune_paths, :194-232,
//   and restore_paths, :252-314) visits the levels from the leaves upward;
//   within a level the frontier nodes are grouped by parent in ascending
//   order, and within a group the child positions are visited ascending, a
//   position no frontier node occupies consuming the next digest of the flat
//   `sibling_hashes` list (documented on the struct, pruning.rs:83-89).
//   `verify_batch_pruned` (mmcs/mod.rs:450-720) replays the same walk with
//   hashing: phase 3 sorts and dedups the indices (:510-513), phase 4 picks
//   the first query per unique leaf as representative and rejects duplicate
//   queries whose opened rows differ (:528-541,
//   InconsistentDuplicateOpenings), phase 5 rejects a digest count that
//   differs from what the frontier consumes (restore_paths, pruning.rs:304-311,
//   SiblingCountMismatch) before any hash, and phase 8 (:631-703) walks the
//   groups, filling unoccupied positions from the siblings and compressing.
//
// The vector files record every intermediate of this walk (`merkle[]`), and
// `verifyPruned` returns the same shapes so the suites can compare them.

const { keccak_256 } = require('@noble/hashes/sha3');

const { bytesEqual, bytesToHex, concatBytes } = require('./vectors');

const DIGEST_BYTES = 32;

function leafDigest(rowBytes) {
  return keccak_256(rowBytes);
}

function compress(left, right) {
  if (left.length !== DIGEST_BYTES || right.length !== DIGEST_BYTES) {
    throw new RangeError('compress expects two 32-byte digests');
  }
  return keccak_256(concatBytes(left, right));
}

// Ascending distinct indices plus, per unique leaf, the first query (in query
// order) that opens it.
function representatives(indices) {
  const order = indices.map((_, q) => q).sort((a, b) => indices[a] - indices[b] || a - b);
  const sortedUnique = [];
  const reps = [];
  for (const q of order) {
    const leaf = indices[q];
    if (sortedUnique.length === 0 || sortedUnique[sortedUnique.length - 1] !== leaf) {
      sortedUnique.push(leaf);
      reps.push(q);
    }
  }
  return { sortedUnique, reps };
}

// Digests the frontier walk consumes for `sortedUnique` leaves of a tree of
// height `logHeight`; determined by the indices alone.
function expectedSiblingCount(sortedUnique, logHeight) {
  let nodes = sortedUnique.slice();
  let count = 0;
  for (let level = 0; level < logHeight; level += 1) {
    const next = [];
    let i = 0;
    while (i < nodes.length) {
      const idx = nodes[i];
      if ((idx & 1) === 0 && i + 1 < nodes.length && nodes[i + 1] === idx + 1) {
        i += 2;
      } else {
        count += 1;
        i += 1;
      }
      next.push(idx >> 1);
    }
    nodes = next;
  }
  return count;
}

function checkIndices(indices, logHeight) {
  if (!Number.isInteger(logHeight) || logHeight < 0 || logHeight > 31) {
    throw new RangeError(`unsupported tree height ${logHeight}`);
  }
  const size = 2 ** logHeight;
  for (const i of indices) {
    if (!Number.isInteger(i) || i < 0 || i >= size) {
      throw new RangeError(`leaf index ${i} outside a tree of height ${logHeight}`);
    }
  }
}

// Verify one pruned multi-opening. `leafDigests[q]` is the leaf digest query
// `q` claims for `indices[q]`; duplicate queries on one leaf must agree
// (DuplicateOpeningMismatch). Returns { ok, error, consumed, expected,
// sortedUnique, reps, leaves, levels, root } where `leaves` and `levels` use
// the vector file shapes ({ index, digest } with 0x-hex digests, levels from
// the parents of the leaves up to the root).
function verifyPruned(root, logHeight, indices, leafDigests, siblingHashes) {
  checkIndices(indices, logHeight);
  if (leafDigests.length !== indices.length) {
    throw new RangeError('one leaf digest per query index expected');
  }
  const { sortedUnique, reps } = representatives(indices);
  const result = {
    ok: false,
    error: null,
    consumed: 0,
    expected: expectedSiblingCount(sortedUnique, logHeight),
    sortedUnique,
    reps,
    leaves: [],
    levels: [],
    root: bytesToHex(root),
  };

  // Duplicate consistency, before any hashing.
  const slotOf = new Map(sortedUnique.map((leaf, slot) => [leaf, slot]));
  for (let q = 0; q < indices.length; q += 1) {
    const rep = reps[slotOf.get(indices[q])];
    if (rep !== q && !bytesEqual(leafDigests[rep], leafDigests[q])) {
      result.error = 'DuplicateOpeningMismatch';
      result.duplicateIndex = indices[q];
      return result;
    }
  }

  if (siblingHashes.length !== result.expected) {
    result.error = 'SiblingCountMismatch';
    return result;
  }

  let nodes = sortedUnique.map((leaf, slot) => ({ index: leaf, digest: leafDigests[reps[slot]] }));
  result.leaves = nodes.map((n) => ({ index: n.index, digest: bytesToHex(n.digest) }));

  let cursor = 0;
  for (let level = 0; level < logHeight; level += 1) {
    const next = [];
    let i = 0;
    while (i < nodes.length) {
      const { index, digest } = nodes[i];
      let left;
      let right;
      if ((index & 1) === 0) {
        left = digest;
        if (i + 1 < nodes.length && nodes[i + 1].index === index + 1) {
          right = nodes[i + 1].digest;
          i += 2;
        } else {
          right = siblingHashes[cursor];
          cursor += 1;
          i += 1;
        }
      } else {
        left = siblingHashes[cursor];
        cursor += 1;
        right = digest;
        i += 1;
      }
      next.push({ index: index >> 1, digest: compress(left, right) });
    }
    result.levels.push(next.map((n) => ({ index: n.index, digest: bytesToHex(n.digest) })));
    nodes = next;
  }
  result.consumed = cursor;
  if (cursor !== siblingHashes.length || nodes.length !== 1 || nodes[0].index !== 0) {
    throw new Error('frontier walk did not converge (internal error)');
  }
  if (!bytesEqual(nodes[0].digest, root)) {
    result.error = 'MerkleRootMismatch';
    return result;
  }
  result.ok = true;
  return result;
}

// Same as verifyPruned, from the leaf preimages (row bytes) per query. Rows
// of duplicate queries are compared byte for byte before hashing, as the
// upstream verifier does; only representatives are hashed.
function verifyPrunedRows(root, logHeight, indices, rows, siblingHashes) {
  checkIndices(indices, logHeight);
  if (rows.length !== indices.length) throw new RangeError('one row per query index expected');
  const { sortedUnique, reps } = representatives(indices);
  const slotOf = new Map(sortedUnique.map((leaf, slot) => [leaf, slot]));
  for (let q = 0; q < indices.length; q += 1) {
    const rep = reps[slotOf.get(indices[q])];
    if (rep !== q && !bytesEqual(rows[rep], rows[q])) {
      return {
        ok: false,
        error: 'DuplicateOpeningMismatch',
        duplicateIndex: indices[q],
        consumed: 0,
        expected: expectedSiblingCount(sortedUnique, logHeight),
        sortedUnique,
        reps,
        leaves: [],
        levels: [],
        root: bytesToHex(root),
      };
    }
  }
  const digests = new Array(rows.length);
  reps.forEach((rep) => {
    digests[rep] = leafDigest(rows[rep]);
  });
  // Non-representative duplicates share their representative's digest.
  for (let q = 0; q < rows.length; q += 1) {
    if (digests[q] === undefined) digests[q] = digests[reps[slotOf.get(indices[q])]];
  }
  return verifyPruned(root, logHeight, indices, digests, siblingHashes);
}

// Build a full binary tree over `leaves` (digests); returns { root, levels }
// with levels[0] the leaves and the last level the single root. Used by the
// suites to fabricate trees for wire-order tests.
function buildTree(leaves) {
  if (leaves.length === 0 || (leaves.length & (leaves.length - 1)) !== 0) {
    throw new RangeError('leaf count must be a power of two');
  }
  const levels = [leaves.slice()];
  while (levels[levels.length - 1].length > 1) {
    const prev = levels[levels.length - 1];
    const next = [];
    for (let i = 0; i < prev.length; i += 2) next.push(compress(prev[i], prev[i + 1]));
    levels.push(next);
  }
  return { root: levels[levels.length - 1][0], levels };
}

// The pruned sibling list for `indices` of a tree built by buildTree, in
// frontier wire order (the prover side, prune_paths).
function pruneTree(tree, indices) {
  const { sortedUnique } = representatives(indices);
  const logHeight = tree.levels.length - 1;
  let nodes = sortedUnique.slice();
  const siblings = [];
  for (let level = 0; level < logHeight; level += 1) {
    const next = [];
    let i = 0;
    while (i < nodes.length) {
      const idx = nodes[i];
      if ((idx & 1) === 0) {
        if (i + 1 < nodes.length && nodes[i + 1] === idx + 1) {
          i += 2;
        } else {
          siblings.push(tree.levels[level][idx + 1]);
          i += 1;
        }
      } else {
        siblings.push(tree.levels[level][idx - 1]);
        i += 1;
      }
      next.push(idx >> 1);
    }
    nodes = next;
  }
  return siblings;
}

module.exports = {
  DIGEST_BYTES,
  buildTree,
  compress,
  expectedSiblingCount,
  leafDigest,
  pruneTree,
  representatives,
  verifyPruned,
  verifyPrunedRows,
};
