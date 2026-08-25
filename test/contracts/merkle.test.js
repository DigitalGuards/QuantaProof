// MerkleMultiProof.hyp against every Merkle block of every vector on a live QRVM.
//
// Deploys contracts/hyperion/test/MerkleHarness.hyp once and, for every valid
// vector under test/vectors/, verifies the trace block, the quotient block and
// every FRI round block twice: first with the leaf digests recorded in the
// vector, then with digests recomputed on chain from the proof calldata (input
// rows) or from the fold rows (round rows). The number of siblings the walk
// consumes must equal the vector's sibCount, the layout's sibCount and a JS
// frontier count. Every Merkle-related mutation vector must fail at the
// expected block with the expected custom error while the blocks before it
// pass. Gas per block, per pipeline stage and per compression is measured
// through the harness gas wrappers and reported as diagnostics.
// Skips without STARK_RPC_URL.
//
// STARK_MERKLE_VECTORS=fib_c3_n10,fib_c1_n12 restricts the valid vectors for a
// quick run; the mutation vectors always run.

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');

const { keccak_256 } = require('@noble/hashes/sha3');

const H = require('../lib/harness');

const rpcUrl = process.env.STARK_RPC_URL;
const skip = rpcUrl ? false : 'set STARK_RPC_URL to run against a node';

const VECTOR_DIR = path.join(__dirname, '..', 'vectors');
const MUTATION_DIR = path.join(VECTOR_DIR, 'mutations');

const F_BYTES = 8;
const EF_BYTES = 16;
const DIGEST_BYTES = 32;
const SIB_COUNT_BYTES = 2;
const TRACE_WIDTH = 2;
const TWO_ADICITY = 32;
const INPUT_ROW_BYTES = TRACE_WIDTH * F_BYTES;

// Milestone target for the frontier walk, bookkeeping included.
const GAS_TARGET_PER_COMPRESSION = 150;
// Regression guard: the measured cost is about twice the target (see the
// diagnostics); anything beyond this bound means the walk changed shape.
const GAS_CEILING_PER_COMPRESSION = 450;

const SIG = {
  leaf: 'leaf(bytes)',
  leafMemory: 'leafMemory(bytes)',
  leaves: 'leaves(bytes,uint512)',
  compress: 'compress(bytes32,bytes32)',
  sortOrder: 'sortOrder(uint64[])',
  sortUnique: 'sortUnique(uint64[])',
  gather: 'gather(uint64[],bytes32[],uint512)',
  collapseByShift: 'collapseByShift(uint64[],bytes32[],uint512)',
  expectedSiblingCount: 'expectedSiblingCount(uint8,uint64[])',
  verifyPruned: 'verifyPruned(bytes32,uint8,uint64[],bytes32[],bytes)',
  gasVerifyPruned: 'gasVerifyPruned(bytes32,uint8,uint64[],bytes32[],bytes)',
  verifyBlockFromCalldata:
    'verifyBlockFromCalldata(bytes,uint512,uint512,uint64[],bytes32,uint8,uint512,uint512)',
  gasVerifyBlock: 'gasVerifyBlock(bytes,uint512,uint512,uint64[],bytes32,uint8,uint512)',
  gasStages: 'gasStages(bytes,uint512,uint512,uint64[])',
};

const MERKLE_ERRORS = ['SiblingCountMismatch', 'MerkleRootMismatch', 'DuplicateOpeningMismatch'];
const SELECTOR_TO_ERROR = new Map(
  MERKLE_ERRORS.map((name) => [H.errorSelector(`${name}()`).toLowerCase(), name])
);

// ---------------------------------------------------------------------------
// Byte helpers and JS references
// ---------------------------------------------------------------------------

function hex(bytes) {
  return `0x${Buffer.from(bytes).toString('hex')}`;
}

function unhex(h) {
  return Buffer.from(h.slice(2), 'hex');
}

function keccakHex(bytes) {
  return hex(keccak_256(bytes));
}

function le8(decimal) {
  const out = Buffer.alloc(F_BYTES);
  out.writeBigUInt64LE(BigInt(decimal));
  return out;
}

// Wire bytes of a base-field row (`F(row[0]) || F(row[1]) ...`).
function rowBytesF(row) {
  return Buffer.concat(row.map(le8));
}

// Wire bytes of an extension-field row (`c0 || c1` per element).
function rowBytesEF(row) {
  return Buffer.concat(row.flatMap(([c0, c1]) => [le8(c0), le8(c1)]));
}

// Stable (index, query) order, sorted unique indices and the first query per leaf.
function sortUniqueJs(indices) {
  const order = indices.map((v, q) => [v, q]).sort((a, b) => a[0] - b[0] || a[1] - b[1]);
  const unique = [];
  const rep = [];
  for (const [v, q] of order) {
    if (unique.length === 0 || unique[unique.length - 1] !== v) {
      unique.push(v);
      rep.push(q);
    }
  }
  return { order: order.map(([, q]) => q), unique, rep };
}

// Siblings the frontier walk consumes, indices only (mirror.rs expected_sibling_count).
function frontierCount(sortedUnique, height) {
  let nodes = sortedUnique.slice();
  let count = 0;
  for (let level = 0; level < height; level += 1) {
    const next = [];
    for (let i = 0; i < nodes.length;) {
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

// The walk itself (mirror.rs verify_pruned_binary): returns the root it reaches
// and how many siblings it consumed, or null when the walk does not converge.
function frontierRoot(sortedUnique, leafDigests, siblings, height) {
  let nodes = sortedUnique.map((idx, i) => [idx, unhex(leafDigests[i])]);
  let cursor = 0;
  const sibling = () => {
    const s = siblings.subarray(cursor * DIGEST_BYTES, (cursor + 1) * DIGEST_BYTES);
    cursor += 1;
    return s.length === DIGEST_BYTES ? s : Buffer.alloc(DIGEST_BYTES);
  };
  for (let level = 0; level < height; level += 1) {
    const next = [];
    for (let i = 0; i < nodes.length;) {
      const [idx, digest] = nodes[i];
      let left;
      let right;
      if ((idx & 1) === 0) {
        if (i + 1 < nodes.length && nodes[i + 1][0] === idx + 1) {
          [left, right] = [digest, nodes[i + 1][1]];
          i += 2;
        } else {
          [left, right] = [digest, sibling()];
          i += 1;
        }
      } else {
        [left, right] = [sibling(), digest];
        i += 1;
      }
      next.push([idx >> 1, Buffer.from(keccak_256(Buffer.concat([left, right])))]);
    }
    nodes = next;
  }
  if (nodes.length !== 1) return null;
  return { root: hex(nodes[0][1]), consumed: cursor };
}

// ---------------------------------------------------------------------------
// Calldata layout v1 (private port of prover/stark-prover/src/layout.rs
// parse_layout; test/lib/layout.js can replace it once it lands). Needed for
// the mutation vectors, which carry no `layout` field.
// ---------------------------------------------------------------------------

class LayoutError extends Error {
  constructor(name) {
    super(name);
    this.name = name;
  }
}

function parseLayoutLocal(bytes, cfg) {
  if (bytes.length === 0) throw new LayoutError('BadLength');
  if (bytes[0] !== 1) throw new LayoutError('BadVersion');
  if (bytes.length < 3) throw new LayoutError('BadLength');
  const degreeBits = bytes[1];
  const numRounds = bytes[2];
  if (bytes.length < 3 + numRounds) throw new LayoutError('BadLength');
  const logArities = Array.from(bytes.subarray(3, 3 + numRounds));
  const lb = cfg.logBlowup;
  const lf = cfg.logFinalPolyLen;
  if (degreeBits === 0 || degreeBits + lb > TWO_ADICITY) throw new LayoutError('BadHeader');
  if (degreeBits < lf) throw new LayoutError('BadHeader');
  if (cfg.maxLogArity === 0 || cfg.numQueries === 0) throw new LayoutError('BadHeader');
  let sum = 0;
  for (const k of logArities) {
    if (k === 0 || k > cfg.maxLogArity) throw new LayoutError('BadHeader');
    sum += k;
  }
  if (sum !== degreeBits - lf) throw new LayoutError('BadHeader');

  const prefix = { version: 0, degreeBits: 1, numRounds: 2, logArity: 3 };
  prefix.traceRoot = 3 + numRounds;
  prefix.quotientRoot = prefix.traceRoot + DIGEST_BYTES;
  prefix.traceLocal = prefix.quotientRoot + DIGEST_BYTES;
  prefix.traceNext = prefix.traceLocal + TRACE_WIDTH * EF_BYTES;
  prefix.quotientChunk = prefix.traceNext + TRACE_WIDTH * EF_BYTES;
  let cursor = prefix.quotientChunk + TRACE_WIDTH * EF_BYTES;
  prefix.roundCommits = [];
  prefix.roundPowWitnesses = [];
  for (let r = 0; r < numRounds; r += 1) {
    prefix.roundCommits.push(cursor);
    cursor += DIGEST_BYTES;
    prefix.roundPowWitnesses.push(cursor);
    cursor += F_BYTES;
  }
  prefix.finalPoly = cursor;
  cursor += (1 << lf) * EF_BYTES;
  prefix.queryPowWitness = cursor;
  cursor += F_BYTES;
  prefix.pEnd = cursor;

  const readU16 = (off) => {
    if (off + SIB_COUNT_BYTES > bytes.length) throw new LayoutError('BadLength');
    return bytes.readUInt16BE(off);
  };
  const q = cfg.numQueries;
  const blocks = [];
  for (const name of ['trace', 'quotient']) {
    const rowsOffset = cursor;
    const rowsLen = q * INPUT_ROW_BYTES;
    const sibCountOffset = rowsOffset + rowsLen;
    const sibCount = readU16(sibCountOffset);
    const siblingsOffset = sibCountOffset + SIB_COUNT_BYTES;
    const end = siblingsOffset + sibCount * DIGEST_BYTES;
    blocks.push({ name, rowsOffset, rowsLen, sibCountOffset, siblingsOffset, sibCount, end });
    cursor = end;
  }
  const rounds = [];
  for (const logArity of logArities) {
    const siblingValuesOffset = cursor;
    const siblingValuesLen = q * ((1 << logArity) - 1) * EF_BYTES;
    const sibCountOffset = siblingValuesOffset + siblingValuesLen;
    const sibCount = readU16(sibCountOffset);
    const siblingsOffset = sibCountOffset + SIB_COUNT_BYTES;
    const end = siblingsOffset + sibCount * DIGEST_BYTES;
    rounds.push({
      logArity,
      siblingValuesOffset,
      siblingValuesLen,
      sibCountOffset,
      siblingsOffset,
      sibCount,
      end,
    });
    cursor = end;
  }
  if (cursor !== bytes.length) throw new LayoutError('BadLength');
  return {
    degreeBits,
    logArities,
    numQueries: q,
    pEnd: prefix.pEnd,
    prefix,
    blocks,
    rounds,
    totalLen: cursor,
  };
}

// ---------------------------------------------------------------------------
// Vectors
// ---------------------------------------------------------------------------

function readJson(file) {
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

function loadValidVectors() {
  const only = process.env.STARK_MERKLE_VECTORS
    ? new Set(process.env.STARK_MERKLE_VECTORS.split(',').map((s) => s.trim()))
    : null;
  return fs
    .readdirSync(VECTOR_DIR)
    .filter((f) => /^fib_.*\.json$/.test(f))
    .sort()
    .map((f) => readJson(path.join(VECTOR_DIR, f)))
    .filter((v) => v.expected && v.expected.valid === true)
    .filter((v) => !only || only.has(v.name));
}

function loadMerkleMutations() {
  if (!fs.existsSync(MUTATION_DIR)) return [];
  return fs
    .readdirSync(MUTATION_DIR)
    .filter((f) => f.endsWith('.json'))
    .sort()
    .map((f) => readJson(path.join(MUTATION_DIR, f)))
    .filter((m) => MERKLE_ERRORS.includes(m.expected.error));
}

// Every Merkle block of a valid vector with what the harness needs to replay it.
function blocksOf(v) {
  const proof = unhex(v.proofHex);
  return v.merkle.map((blk, k) => {
    const lay = k < 2 ? v.layout.blocks[k] : v.layout.rounds[k - 2];
    const siblings = proof.subarray(
      lay.siblingsOffset,
      lay.siblingsOffset + lay.sibCount * DIGEST_BYTES
    );
    return {
      k,
      name: blk.name,
      root: blk.root,
      height: blk.logHeight,
      indices: blk.indices,
      sortedUnique: blk.sortedUnique,
      leaves: blk.leaves.map((l) => l.digest),
      sibCount: blk.sibCount,
      layoutSibCount: lay.sibCount,
      siblingsOffset: lay.siblingsOffset,
      siblings,
      rowsOffset: k < 2 ? lay.rowsOffset : null,
      rowSize: k < 2 ? INPUT_ROW_BYTES : (1 << lay.logArity) * EF_BYTES,
      compressions: blk.levels.reduce((s, level) => s + level.length, 0),
      levels: blk.levels,
    };
  });
}

// Fold entries of round r in query order.
function foldRound(v, r) {
  return v.fold.filter((f) => f.round === r).sort((a, b) => a.query - b.query);
}

function cumulativeShift(v, r) {
  return v.layout.logArities.slice(0, r + 1).reduce((s, k) => s + k, 0);
}

function big(values) {
  return values.map((x) => BigInt(x));
}

function median(values) {
  const s = values.slice().sort((a, b) => a - b);
  return s.length % 2 ? s[(s.length - 1) / 2] : (s[s.length / 2 - 1] + s[s.length / 2]) / 2;
}

// Least squares fit gas = a + b * compressions + c * leaves over the measured blocks.
function fitGas(rows) {
  const cols = [() => 1, (r) => r.compressions, (r) => r.m];
  const n = 3;
  const ata = Array.from({ length: n }, () => new Array(n).fill(0));
  const atb = new Array(n).fill(0);
  for (const r of rows) {
    const x = cols.map((f) => f(r));
    for (let i = 0; i < n; i += 1) {
      atb[i] += x[i] * r.gasWalk;
      for (let j = 0; j < n; j += 1) ata[i][j] += x[i] * x[j];
    }
  }
  // Gaussian elimination on the 3x3 normal equations.
  const m = ata.map((row, i) => [...row, atb[i]]);
  for (let i = 0; i < n; i += 1) {
    let pivot = i;
    for (let r = i + 1; r < n; r += 1) if (Math.abs(m[r][i]) > Math.abs(m[pivot][i])) pivot = r;
    [m[i], m[pivot]] = [m[pivot], m[i]];
    for (let r = 0; r < n; r += 1) {
      if (r === i) continue;
      const f = m[r][i] / m[i][i];
      for (let c = i; c <= n; c += 1) m[r][c] -= f * m[i][c];
    }
  }
  return {
    intercept: m[0][3] / m[0][0],
    perCompression: m[1][3] / m[1][1],
    perLeaf: m[2][3] / m[2][2],
  };
}

// Name of the custom error a failed harness call reverted with.
function revertName(error) {
  const payload = H.revertData(error);
  if (payload === null) throw error;
  const name = SELECTOR_TO_ERROR.get(payload.slice(0, 10).toLowerCase());
  if (!name) throw new Error(`unexpected revert data ${payload.slice(0, 10)}: ${error.message}`);
  return name;
}

// ---------------------------------------------------------------------------
// Suite
// ---------------------------------------------------------------------------

test('Merkle harness', { skip, timeout: 3600000 }, async (t) => {
  const ctx = await H.connect();
  const h = await H.deployHarness(ctx, 'test/MerkleHarness.hyp');
  t.diagnostic(`MerkleHarness at ${h.address} (chain ${ctx.chainId})`);

  const vectors = loadValidVectors();
  assert.ok(vectors.length > 0, 'no valid vectors under test/vectors/');
  const mutations = loadMerkleMutations();
  const gasRows = [];

  await t.test('hashing primitives match keccak256', async () => {
    const empty = keccakHex(Buffer.alloc(0));
    assert.equal(await h.callOne(SIG.leaf, ['0x'], 'bytes32'), empty);
    const v = vectors[0];
    const proof = unhex(v.proofHex);
    for (const q of [0, 1, v.openInputs.length - 1]) {
      const off = v.layout.blocks[0].rowsOffset + q * INPUT_ROW_BYTES;
      const row = proof.subarray(off, off + INPUT_ROW_BYTES);
      assert.deepEqual(row, rowBytesF(v.openInputs[q].traceRow), `row bytes of query ${q}`);
      const expected = keccakHex(row);
      assert.equal(await h.callOne(SIG.leaf, [hex(row)], 'bytes32'), expected);
      assert.equal(await h.callOne(SIG.leafMemory, [hex(row)], 'bytes32'), expected);
    }
    // A 256-byte row (arity 16) exercises the copy beyond the 128-byte scratch.
    const wide = Buffer.from(Array.from({ length: 256 }, (_, i) => (i * 37) & 0xff));
    assert.equal(await h.callOne(SIG.leaf, [hex(wide)], 'bytes32'), keccakHex(wide));
    assert.equal(await h.callOne(SIG.leafMemory, [hex(wide)], 'bytes32'), keccakHex(wide));
    const [three] = await h.call(
      SIG.leaves,
      [hex(Buffer.concat([wide, wide, wide])), 256n],
      ['bytes32[]']
    );
    assert.deepEqual(three, [keccakHex(wide), keccakHex(wide), keccakHex(wide)]);

    const left = v.merkle[0].leaves[0].digest;
    const right = v.merkle[0].leaves[1].digest;
    const expectedCompress = keccakHex(Buffer.concat([unhex(left), unhex(right)]));
    assert.equal(await h.callOne(SIG.compress, [left, right], 'bytes32'), expectedCompress);
    assert.notEqual(await h.callOne(SIG.compress, [right, left], 'bytes32'), expectedCompress);
    // First parent of the trace block, built from the first frontier node and
    // either its frontier twin or the first calldata sibling.
    const blk = blocksOf(v)[0];
    const first = blk.sortedUnique[0];
    const sib = hex(blk.siblings.subarray(0, DIGEST_BYTES));
    let children;
    if (first & 1) {
      children = [sib, blk.leaves[0]];
    } else if (blk.sortedUnique[1] === first + 1) {
      children = [blk.leaves[0], blk.leaves[1]];
    } else {
      children = [blk.leaves[0], sib];
    }
    assert.equal(await h.callOne(SIG.compress, children, 'bytes32'), blk.levels[0][0].digest);
  });

  await t.test('local layout parser agrees with every vector layout', () => {
    for (const v of vectors) {
      const layout = parseLayoutLocal(unhex(v.proofHex), v.config);
      assert.deepEqual(layout, v.layout, `${v.name}: layout`);
      assert.equal(layout.totalLen, v.proofLength);
    }
    for (const m of mutations) {
      // Every Merkle mutation keeps a parseable layout (length rule holds).
      parseLayoutLocal(unhex(m.proofHex), m.config);
    }
    const lengthMutations = fs
      .readdirSync(MUTATION_DIR)
      .filter((f) => f.endsWith('__sib_count_field_plus_one.json'))
      .map((f) => readJson(path.join(MUTATION_DIR, f)));
    assert.ok(lengthMutations.length > 0);
    for (const m of lengthMutations) {
      assert.throws(() => parseLayoutLocal(unhex(m.proofHex), m.config), { name: 'BadLength' });
    }
  });

  await t.test('sortUnique, sortOrder and expectedSiblingCount on every block', async () => {
    let checked = 0;
    for (const v of vectors) {
      for (const blk of blocksOf(v)) {
        const ref = sortUniqueJs(blk.indices);
        assert.deepEqual(ref.unique, blk.sortedUnique, `${v.name} ${blk.name}: JS sortedUnique`);
        const [unique, rep] = await h.call(
          SIG.sortUnique,
          [big(blk.indices)],
          ['uint64[]', 'uint64[]']
        );
        assert.deepEqual(unique, big(blk.sortedUnique), `${v.name} ${blk.name}: sortedUnique`);
        assert.deepEqual(rep, big(ref.rep), `${v.name} ${blk.name}: representatives`);
        for (let s = 0; s < unique.length; s += 1) {
          assert.equal(BigInt(blk.indices[Number(rep[s])]), unique[s]);
        }
        const count = await h.callOne(
          SIG.expectedSiblingCount,
          [BigInt(blk.height), big(blk.sortedUnique)],
          'uint512'
        );
        assert.equal(count, BigInt(blk.sibCount), `${v.name} ${blk.name}: expected count`);
        assert.equal(frontierCount(blk.sortedUnique, blk.height), blk.sibCount);
        assert.equal(blk.layoutSibCount, blk.sibCount);
        checked += 1;
      }
      const order = await h.callOne(SIG.sortOrder, [big(v.merkle[0].indices)], 'uint64[]');
      assert.deepEqual(order, big(sortUniqueJs(v.merkle[0].indices).order), `${v.name}: order`);
    }
    // Duplicates, ties and an unsorted tail through the sort alone.
    const idx = [7, 3, 7, 0, 3, 9, 1, 1, 0];
    const ref = sortUniqueJs(idx);
    const [unique, rep] = await h.call(SIG.sortUnique, [big(idx)], ['uint64[]', 'uint64[]']);
    assert.deepEqual(unique, big(ref.unique));
    assert.deepEqual(rep, big(ref.rep));
    assert.deepEqual(await h.callOne(SIG.sortOrder, [big(idx)], 'uint64[]'), big(ref.order));
    const [emptyU, emptyR] = await h.call(SIG.sortUnique, [[]], ['uint64[]', 'uint64[]']);
    assert.deepEqual(emptyU, []);
    assert.deepEqual(emptyR, []);
    t.diagnostic(`sortUnique/expectedSiblingCount checked on ${checked} blocks`);
  });

  await t.test('every block verifies with the vector leaf digests', async () => {
    for (const v of vectors) {
      for (const blk of blocksOf(v)) {
        const js = frontierRoot(blk.sortedUnique, blk.leaves, blk.siblings, blk.height);
        assert.equal(js.root, blk.root, `${v.name} ${blk.name}: JS walk root`);
        assert.equal(js.consumed, blk.sibCount);
        const args = [
          blk.root,
          BigInt(blk.height),
          big(blk.sortedUnique),
          blk.leaves,
          hex(blk.siblings),
        ];
        const [ok, consumed, gasWalk] = await h.call(SIG.gasVerifyPruned, args, [
          'bool',
          'uint512',
          'uint512',
        ]);
        assert.equal(ok, true, `${v.name} ${blk.name}: root`);
        assert.equal(consumed, BigInt(blk.sibCount), `${v.name} ${blk.name}: consumed`);
        gasRows.push({
          vector: v.name,
          block: blk.name,
          height: blk.height,
          m: blk.sortedUnique.length,
          compressions: blk.compressions,
          sibCount: blk.sibCount,
          gasWalk: Number(gasWalk),
        });
      }
    }
    // The plain wrapper on one block, plus a wrong root and a truncated list.
    const blk = blocksOf(vectors[0])[0];
    const args = [
      blk.root,
      BigInt(blk.height),
      big(blk.sortedUnique),
      blk.leaves,
      hex(blk.siblings),
    ];
    assert.deepEqual(await h.call(SIG.verifyPruned, args, ['bool', 'uint512']), [
      true,
      BigInt(blk.sibCount),
    ]);
    const wrongRoot = [blocksOf(vectors[0])[1].root, ...args.slice(1)];
    assert.deepEqual(await h.call(SIG.verifyPruned, wrongRoot, ['bool', 'uint512']), [
      false,
      BigInt(blk.sibCount),
    ]);
    // Fewer siblings than the walk needs: the walk still consumes its count
    // (calldata past the end reads as zero), the caller compares counts.
    const short = [...args.slice(0, 4), hex(blk.siblings.subarray(0, DIGEST_BYTES))];
    const [okShort, consumedShort] = await h.call(SIG.verifyPruned, short, ['bool', 'uint512']);
    assert.equal(okShort, false);
    assert.equal(consumedShort, BigInt(blk.sibCount));
    // Indices above 2^height never converge.
    const [okHigh] = await h.call(
      SIG.verifyPruned,
      [blk.root, 2n, [1n, 5n], blk.leaves.slice(0, 2), '0x'],
      ['bool', 'uint512']
    );
    assert.equal(okHigh, false);
  });

  await t.test('input blocks verify from calldata rows', async () => {
    for (const v of vectors) {
      const blocks = blocksOf(v);
      for (const blk of blocks.slice(0, 2)) {
        const args = [
          v.proofHex,
          BigInt(blk.rowsOffset),
          BigInt(INPUT_ROW_BYTES),
          big(blk.indices),
          blk.root,
          BigInt(blk.height),
          BigInt(blk.siblingsOffset),
        ];
        const consumed = await h.callOne(
          SIG.verifyBlockFromCalldata,
          [...args, BigInt(blk.sibCount)],
          'uint512'
        );
        assert.equal(consumed, BigInt(blk.sibCount), `${v.name} ${blk.name}: consumed`);
        const [ok, consumed2, gasBlock] = await h.call(SIG.gasVerifyBlock, args, [
          'bool',
          'uint512',
          'uint512',
        ]);
        assert.equal(ok, true);
        assert.equal(consumed2, BigInt(blk.sibCount));
        const row = gasRows.find((r) => r.vector === v.name && r.block === blk.name);
        row.gasBlock = Number(gasBlock);
        row.queries = blk.indices.length;
      }
      // Duplicate queries share identical rows, so gather over all Q digests succeeds.
      const trace = blocks[0];
      const digests = v.openInputs.map((o) => keccakHex(rowBytesF(o.traceRow)));
      const [unique, gathered] = await h.call(
        SIG.gather,
        [big(trace.indices), digests, 0n],
        ['uint64[]', 'bytes32[]']
      );
      assert.deepEqual(unique, big(trace.sortedUnique));
      assert.deepEqual(gathered, trace.leaves, `${v.name}: gathered trace leaves`);
    }
    // Stage breakdown of the first vector's trace block.
    const v = vectors[0];
    const trace = blocksOf(v)[0];
    const [gasSort, gasHash, gasGather] = await h.call(
      SIG.gasStages,
      [v.proofHex, BigInt(trace.rowsOffset), BigInt(INPUT_ROW_BYTES), big(trace.indices)],
      ['uint512', 'uint512', 'uint512']
    );
    const row = gasRows.find((r) => r.vector === v.name && r.block === 'trace');
    t.diagnostic(
      `${v.name} trace block (Q=${trace.indices.length}, m=${trace.sortedUnique.length}, ` +
        `h=${trace.height}): sortKeys ${gasSort}, ${trace.indices.length} row hashes ${gasHash} ` +
        `(${(Number(gasHash) / trace.indices.length).toFixed(0)} each), gather ${gasGather}, ` +
        `walk ${row.gasWalk}, whole block ${row.gasBlock}`
    );
  });

  await t.test('round blocks verify from recomputed row digests', async () => {
    for (const v of vectors) {
      const blocks = blocksOf(v);
      const baseIndices = v.challenges.indices;
      assert.deepEqual(blocks[0].indices, baseIndices, `${v.name}: trace indices`);
      for (let r = 0; r < v.layout.rounds.length; r += 1) {
        const blk = blocks[2 + r];
        const entries = foldRound(v, r);
        assert.equal(entries.length, blk.indices.length, `${v.name} round ${r}: fold entries`);
        assert.deepEqual(
          entries.map((f) => f.foldedIndex),
          blk.indices,
          `${v.name} round ${r}: leaf indices`
        );
        const rows = entries.map((f) => rowBytesEF(f.row));
        for (const row of rows) assert.equal(row.length, blk.rowSize);
        const expected = entries.map((f) => f.leafDigest);
        for (let q = 0; q < rows.length; q += 1) {
          assert.equal(keccakHex(rows[q]), expected[q], `${v.name} round ${r}: JS leaf ${q}`);
        }
        const [digests] = await h.call(
          SIG.leaves,
          [hex(Buffer.concat(rows)), BigInt(blk.rowSize)],
          ['bytes32[]']
        );
        assert.deepEqual(digests, expected, `${v.name} round ${r}: on-chain leaves`);
        // Gather with the round's own leaf indices and, equivalently, with the
        // height-H indices shifted by the cumulative arity.
        const [u1, d1] = await h.call(
          SIG.gather,
          [big(blk.indices), digests, 0n],
          ['uint64[]', 'bytes32[]']
        );
        const shift = BigInt(cumulativeShift(v, r));
        const [u2, d2] = await h.call(
          SIG.gather,
          [big(baseIndices), digests, shift],
          ['uint64[]', 'bytes32[]']
        );
        assert.deepEqual(u1, big(blk.sortedUnique), `${v.name} round ${r}: unique`);
        assert.deepEqual(u2, u1);
        assert.deepEqual(d1, blk.leaves, `${v.name} round ${r}: gathered leaves`);
        assert.deepEqual(d2, d1);
        const [ok, consumed] = await h.call(
          SIG.verifyPruned,
          [blk.root, BigInt(blk.height), u1, d1, hex(blk.siblings)],
          ['bool', 'uint512']
        );
        assert.equal(ok, true, `${v.name} round ${r}: root`);
        assert.equal(consumed, BigInt(blk.sibCount));
      }
    }
  });

  await t.test('collapseByShift follows the round arities', async () => {
    let merges = 0;
    let negative = false;
    for (const v of vectors) {
      const blocks = blocksOf(v);
      let unique = blocks[0].sortedUnique;
      for (let r = 0; r < v.layout.rounds.length; r += 1) {
        const k = v.layout.rounds[r].logArity;
        // Slots that merge carry equal digests when the digest is a function of
        // the shifted index.
        const digests = unique.map((idx) => keccakHex(le8(idx >> k)));
        const [u, d] = await h.call(
          SIG.collapseByShift,
          [big(unique), digests, BigInt(k)],
          ['uint64[]', 'bytes32[]']
        );
        const expected = blocks[2 + r].sortedUnique;
        assert.deepEqual(u, big(expected), `${v.name} round ${r}: collapsed indices`);
        assert.deepEqual(
          d,
          expected.map((idx) => keccakHex(le8(idx))),
          `${v.name} round ${r}: collapsed digests`
        );
        if (expected.length < unique.length && !negative) {
          // Two slots that merge with different digests must be rejected.
          const s = unique.findIndex((idx, i) => i > 0 && idx >> k === unique[i - 1] >> k);
          assert.ok(s > 0);
          const bad = digests.slice();
          bad[s] = keccakHex(Buffer.from('mismatch'));
          await H.expectRevert(
            h,
            SIG.collapseByShift,
            [big(unique), bad, BigInt(k)],
            'DuplicateOpeningMismatch()'
          );
          negative = true;
        }
        merges += unique.length - expected.length;
        unique = expected;
      }
    }
    assert.ok(negative, 'no vector collapses any slot; the mismatch path stayed untested');
    t.diagnostic(`collapseByShift merged ${merges} slots across ${vectors.length} vectors`);
  });

  await t.test('gather rejects two queries that disagree on one leaf', async () => {
    const idx = [5, 9, 5, 2];
    const d = ['a', 'b', 'a', 'c'].map((s) => keccakHex(Buffer.from(s)));
    const [u, g] = await h.call(SIG.gather, [big(idx), d, 0n], ['uint64[]', 'bytes32[]']);
    assert.deepEqual(u, [2n, 5n, 9n]);
    assert.deepEqual(g, [d[3], d[0], d[1]]);
    const bad = d.slice();
    bad[2] = keccakHex(Buffer.from('z'));
    await H.expectRevert(h, SIG.gather, [big(idx), bad, 0n], 'DuplicateOpeningMismatch()');
    // A shift that makes 5 and 9 collide (both >> 3 == 0) with 2 as well.
    await H.expectRevert(h, SIG.gather, [big(idx), d, 3n], 'DuplicateOpeningMismatch()');
    const same = [d[0], d[0], d[0], d[0]];
    const [u3, g3] = await h.call(SIG.gather, [big(idx), same, 3n], ['uint64[]', 'bytes32[]']);
    assert.deepEqual(u3, [0n, 1n]);
    assert.deepEqual(g3, [d[0], d[0]]);
  });

  await t.test('Merkle mutation vectors fail at the expected block', async () => {
    assert.ok(mutations.length > 0, 'no Merkle mutation vectors under test/vectors/mutations/');
    const sources = new Map();
    for (const f of fs.readdirSync(VECTOR_DIR).filter((x) => /^fib_.*\.json$/.test(x))) {
      const v = readJson(path.join(VECTOR_DIR, f));
      sources.set(v.name, v);
    }
    const seen = new Set();
    for (const m of mutations) {
      const source = sources.get(m.source);
      assert.ok(source, `${m.name}: source vector ${m.source} is missing`);
      const proof = unhex(m.proofHex);
      const layout = parseLayoutLocal(proof, m.config);
      const mutation = m.expected.mutation;
      seen.add(mutation);

      // Run the blocks in verifier order and stop at the first failure.
      const outcomes = [];
      const failAt = async (name, fn) => {
        try {
          await fn();
          outcomes.push({ name, error: null });
          return false;
        } catch (error) {
          outcomes.push({ name, error: revertName(error) });
          return true;
        }
      };
      let failed = false;
      for (let k = 0; k < 2 && !failed; k += 1) {
        const blk = layout.blocks[k];
        const rootOffset = k === 0 ? layout.prefix.traceRoot : layout.prefix.quotientRoot;
        const root = hex(proof.subarray(rootOffset, rootOffset + DIGEST_BYTES));
        const srcBlock = source.merkle[k];
        failed = await failAt(blk.name, () =>
          h.callOne(
            SIG.verifyBlockFromCalldata,
            [
              m.proofHex,
              BigInt(blk.rowsOffset),
              BigInt(INPUT_ROW_BYTES),
              big(srcBlock.indices),
              root,
              BigInt(srcBlock.logHeight),
              BigInt(blk.siblingsOffset),
              BigInt(blk.sibCount),
            ],
            'uint512'
          )
        );
      }
      for (let r = 0; r < layout.rounds.length && !failed; r += 1) {
        const rl = layout.rounds[r];
        const commitOffset = layout.prefix.roundCommits[r];
        const root = hex(proof.subarray(commitOffset, commitOffset + DIGEST_BYTES));
        const srcBlock = source.merkle[2 + r];
        const siblings = proof.subarray(
          rl.siblingsOffset,
          rl.siblingsOffset + rl.sibCount * DIGEST_BYTES
        );
        const [ok, consumed] = await h.call(
          SIG.verifyPruned,
          [
            root,
            BigInt(srcBlock.logHeight),
            big(srcBlock.sortedUnique),
            srcBlock.leaves.map((l) => l.digest),
            hex(siblings),
          ],
          ['bool', 'uint512']
        );
        let error = null;
        if (consumed !== BigInt(rl.sibCount)) error = 'SiblingCountMismatch';
        else if (!ok) error = 'MerkleRootMismatch';
        outcomes.push({ name: `round[${r}]`, error });
        failed = error !== null;
      }

      let expectedBlock;
      if (mutation === 'flip_round_sibling') {
        const r = layout.rounds.findIndex((rl) => rl.sibCount > 0);
        expectedBlock = `round[${r}]`;
      } else {
        expectedBlock = 'trace';
      }
      const failure = outcomes.find((o) => o.error !== null);
      assert.ok(failure, `${m.name}: every block passed`);
      assert.equal(failure.name, expectedBlock, `${m.name}: failing block`);
      assert.equal(failure.error, m.expected.error, `${m.name}: error`);
      for (const o of outcomes.slice(0, outcomes.indexOf(failure))) {
        assert.equal(o.error, null, `${m.name}: ${o.name} failed before ${expectedBlock}`);
      }
    }
    t.diagnostic(`${mutations.length} Merkle mutation vectors: ${[...seen].sort().join(', ')}`);
    for (const required of [
      'flip_input_sibling',
      'flip_round_sibling',
      'sib_count_plus_one',
      'sib_count_minus_one',
      'swap_query_rows',
    ]) {
      assert.ok(seen.has(required), `mutation ${required} is missing`);
    }
  });

  await t.test('gas per block and per compression', () => {
    assert.ok(gasRows.length > 0);
    const per = gasRows.map((r) => r.gasWalk / r.compressions);
    const fit = fitGas(gasRows);
    const first = vectors[0].name;
    for (const r of gasRows.filter((x) => x.vector === first)) {
      t.diagnostic(
        `${r.vector} ${r.block}: h=${r.height} m=${r.m} siblings=${r.sibCount} ` +
          `compressions=${r.compressions} walk=${r.gasWalk} ` +
          `(${(r.gasWalk / r.compressions).toFixed(1)}/compression)` +
          (r.gasBlock ? ` block=${r.gasBlock} (Q=${r.queries} rows hashed)` : '')
      );
    }
    const worst = gasRows.reduce((a, b) => (a.gasWalk > b.gasWalk ? a : b));
    t.diagnostic(
      `walk gas per compression over ${gasRows.length} blocks: min ${Math.min(...per).toFixed(1)}, ` +
        `median ${median(per).toFixed(1)}, max ${Math.max(...per).toFixed(1)}; ` +
        `fit gas = ${fit.intercept.toFixed(0)} + ${fit.perCompression.toFixed(1)} * compressions ` +
        `+ ${fit.perLeaf.toFixed(1)} * leaves; largest block ${worst.vector} ${worst.block} ` +
        `(${worst.compressions} compressions, ${worst.gasWalk} gas)`
    );
    const verdict =
      fit.perCompression < GAS_TARGET_PER_COMPRESSION
        ? `MET (target ${GAS_TARGET_PER_COMPRESSION})`
        : `MISSED (target ${GAS_TARGET_PER_COMPRESSION}, marginal ${fit.perCompression.toFixed(1)})`;
    t.diagnostic(`per-compression gas target ${verdict}`);
    assert.ok(
      median(per) < GAS_CEILING_PER_COMPRESSION,
      `median ${median(per).toFixed(1)} gas per compression exceeds ${GAS_CEILING_PER_COMPRESSION}`
    );
  });
});
