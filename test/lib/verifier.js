// The complete JS reference verifier: layout decoding, transcript,
// constraint identity, FRI transcript, input batch Merkle checks, reduced
// openings, fold chains and per-round Merkle checks, in the check order of
// docs/PROTOCOL.md section 12 (the order decides which error a malformed
// proof raises). It is a port of prover/stark-prover/src/mirror.rs
// mirror_verify_raw and produces every intermediate in the vector file shapes
// (decimal strings, [c0, c1] pairs, 0x-hex), so a suite can compare a whole
// vector section with one deep equality.
//
// verifyProof(cfg, proofBytes, publicValuesBytes) returns
//   { ok: true, output } or { ok: false, error, detail }
// where `error` is one of vectors.ERROR_NAMES.

const G = require('./goldilocks');
const F2 = require('./fp2');
const { Challenger } = require('./challenger');
const fri = require('./fri');
const air = require('./fibonacciAir');
const layout = require('./layout');
const merkle = require('./merkle');
const { bytesToHex, efStr, fStr } = require('./vectors');

class VerifyError extends Error {
  constructor(name, detail) {
    super(detail ? `${name}: ${detail}` : name);
    this.name = name;
    this.errorName = name;
    this.detail = detail;
  }
}

function fail(name, detail) {
  throw new VerifyError(name, detail);
}

function rowBytes(row) {
  const out = new Uint8Array(row.length * layout.F_BYTES);
  row.forEach((v, i) => out.set(layout.fBytes(v), i * layout.F_BYTES));
  return out;
}

function merkleBlock(name, root, logHeight, indices, rows, siblings) {
  const result = merkle.verifyPrunedRows(root, logHeight, indices, rows, siblings);
  if (!result.ok) fail(result.error, `${name} block`);
  return {
    name,
    logHeight,
    indices: indices.slice(),
    sortedUnique: result.sortedUnique,
    sibCount: siblings.length,
    leaves: result.leaves,
    levels: result.levels,
    root: bytesToHex(root),
  };
}

// The verifier on an already decoded proof and decoded public values.
function verifyDecoded(cfg, proof, publicValues) {
  const n = proof.degreeBits;
  const h = n + cfg.logBlowup;
  const q = cfg.numQueries;
  const ch = new Challenger();

  // Instance and first commitment.
  ch.observeField(BigInt(n), 'degree_bits');
  ch.observeField(BigInt(n), 'base_degree_bits');
  ch.observeField(0n, 'preprocessed_width');
  ch.observeDigest(proof.traceRoot, 'trace_root');
  publicValues.forEach((v, i) => ch.observeField(v, `public_values[${i}]`));
  const alpha = ch.sampleExt('alpha');
  ch.observeDigest(proof.quotientRoot, 'quotient_root');
  const zeta = ch.sampleExt('zeta');

  // Out-of-domain point must be off the trace domain.
  let zPow = zeta;
  for (let i = 0; i < n; i += 1) zPow = F2.sq(zPow);
  if (F2.equal(zPow, F2.ONE)) fail('OodPointInDomain');
  const zetaNext = F2.mulBase(zeta, G.twoAdicGen(n));

  // Opened values in (round, matrix, point) order.
  ch.observeExt(proof.traceLocal[0], 'trace_local[0]');
  ch.observeExt(proof.traceLocal[1], 'trace_local[1]');
  ch.observeExt(proof.traceNext[0], 'trace_next[0]');
  ch.observeExt(proof.traceNext[1], 'trace_next[1]');
  ch.observeExt(proof.quotientChunk[0], 'quotient_chunk[0]');
  ch.observeExt(proof.quotientChunk[1], 'quotient_chunk[1]');

  // Constraint identity (fail fast, needs only the prefix).
  const constraints = air.evaluateConstraints({
    degreeBits: n,
    zeta,
    alpha,
    traceLocal: proof.traceLocal,
    traceNext: proof.traceNext,
    quotientChunk: proof.quotientChunk,
    publicValues,
  });
  if (!constraints.ok) fail('OodMismatch');

  // FRI transcript.
  const friAlpha = ch.sampleExt('fri_alpha');
  const betas = [];
  proof.rounds.forEach((round, r) => {
    ch.observeDigest(round.commit, `fri_commit[${r}]`);
    if (!ch.checkWitness(cfg.commitPowBits, round.powWitness, `commit_pow[${r}]`)) {
      fail('PowFailed', `commit_pow[${r}]`);
    }
    betas.push(ch.sampleExt(`beta[${r}]`));
  });
  proof.finalPoly.forEach((c, i) => ch.observeExt(c, `final_poly[${i}]`));
  proof.rounds.forEach((round, r) => ch.observeField(BigInt(round.logArity), `log_arity[${r}]`));
  if (!ch.checkWitness(cfg.queryPowBits, proof.queryPowWitness, 'query_pow')) {
    fail('PowFailed', 'query_pow');
  }
  const indices = [];
  for (let i = 0; i < q; i += 1) indices.push(ch.sampleBits(h, `index[${i}]`));

  // Input batches.
  const traceRows = proof.traceRows.map(rowBytes);
  const quotientRows = proof.quotientRows.map(rowBytes);
  const merkleBlocks = [
    merkleBlock('trace', proof.traceRoot, h, indices, traceRows, proof.traceSiblings),
    merkleBlock('quotient', proof.quotientRoot, h, indices, quotientRows, proof.quotientSiblings),
  ];

  // Reduced openings.
  const openInputs = [];
  const reduced = [];
  indices.forEach((idx, qi) => {
    const x = fri.queryPoint(idx, h);
    let ro;
    try {
      ro = fri.reducedOpening({
        friAlpha,
        zeta,
        zetaNext,
        x,
        traceLocal: proof.traceLocal,
        traceNext: proof.traceNext,
        quotientChunk: proof.quotientChunk,
        traceRow: proof.traceRows[qi],
        quotientRow: proof.quotientRows[qi],
      });
    } catch (e) {
      if (e instanceof fri.FriError) fail(e.errorName, `query ${qi}`);
      throw e;
    }
    reduced.push(ro.reducedOpening);
    openInputs.push({
      query: qi,
      index: idx,
      x: fStr(x),
      denomZeta: efStr(ro.denomZeta),
      denomZetaNext: efStr(ro.denomZetaNext),
      invDenomZeta: efStr(ro.invDenomZeta),
      invDenomZetaNext: efStr(ro.invDenomZetaNext),
      traceRow: proof.traceRows[qi].map(fStr),
      quotientRow: proof.quotientRows[qi].map(fStr),
      reducedOpening: efStr(ro.reducedOpening),
    });
  });

  // Fold chains.
  const fold = [];
  const finalPolyChecks = [];
  const roundGroups = proof.rounds.map(() => []);
  const roundRows = proof.rounds.map(() => []);
  for (let qi = 0; qi < q; qi += 1) {
    const chain = fri.foldChain({
      index: indices[qi],
      reduced: reduced[qi],
      logHeight: h,
      rounds: proof.rounds.map((r) => ({
        logArity: r.logArity,
        siblingValues: r.siblingValues[qi],
      })),
      betas,
      finalPoly: proof.finalPoly,
      efBytes: layout.efBytes,
    });
    chain.steps.forEach((step, r) => {
      if (!F2.equal(step.folded, step.foldedBarycentric)) {
        throw new Error(`fold forms disagree at query ${qi} round ${r} (internal error)`);
      }
      fold.push({
        query: qi,
        round: r,
        logArity: step.logArity,
        index: step.index,
        position: step.position,
        row: step.row.map(efStr),
        foldedIndex: step.foldedIndex,
        subgroupStart: fStr(step.subgroupStart),
        folded: efStr(step.folded),
        foldedBarycentric: efStr(step.foldedBarycentric),
        leafDigest: bytesToHex(merkle.leafDigest(step.rowBytes)),
      });
      roundGroups[r].push(step.foldedIndex);
      roundRows[r].push(step.rowBytes);
    });
    if (chain.finalHeight !== cfg.logBlowup + cfg.logFinalPolyLen) {
      throw new Error('fold chain ended at the wrong height (internal error)');
    }
    finalPolyChecks.push({
      query: qi,
      index: chain.finalIndex,
      x: fStr(chain.finalX),
      value: efStr(chain.finalValue),
    });
    if (!chain.ok) fail('FinalPolyMismatch', `query ${qi}`);
  }

  // Per-round Merkle checks.
  let height = h;
  proof.rounds.forEach((round, r) => {
    const foldedHeight = height - round.logArity;
    merkleBlocks.push(
      merkleBlock(
        `round[${r}]`,
        round.commit,
        foldedHeight,
        roundGroups[r],
        roundRows[r],
        round.siblings
      )
    );
    height = foldedHeight;
  });

  return {
    layout: proof.layout,
    proofId: proof.proofId,
    transcript: ch.events,
    challenges: {
      alpha: efStr(alpha),
      zeta: efStr(zeta),
      zetaNext: efStr(zetaNext),
      friAlpha: efStr(friAlpha),
      betas: betas.map(efStr),
      indices,
    },
    constraints: {
      zH: efStr(constraints.zH),
      isFirst: efStr(constraints.isFirst),
      isLast: efStr(constraints.isLast),
      isTrans: efStr(constraints.isTrans),
      invVan: efStr(constraints.invVan),
      values: constraints.values.map(efStr),
      acc: efStr(constraints.acc),
      quotient: efStr(constraints.quotient),
    },
    openInputs,
    fold,
    finalPolyChecks,
    merkle: merkleBlocks,
  };
}

// Decode and verify. Malformed input comes back as { ok: false, error };
// a throw signals an internal invariant violation.
function verifyProof(cfg, proofBytes, publicValuesBytes) {
  try {
    const proof = layout.decodeProof(proofBytes, cfg);
    const publicValues = layout.decodePublicValues(publicValuesBytes);
    return { ok: true, output: verifyDecoded(cfg, proof, publicValues) };
  } catch (e) {
    if (e instanceof layout.LayoutError || e instanceof VerifyError) {
      return { ok: false, error: e.errorName, detail: e.message };
    }
    throw e;
  }
}

module.exports = { VerifyError, verifyDecoded, verifyProof };
