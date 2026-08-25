// JS reference for the FRI side of the verifier (docs/PROTOCOL.md sections
// 6 to 8, prover/stark-prover/src/mirror.rs): query points, reduced openings,
// the binary fold chain, the literal barycentric fold_row for triangulation,
// row reconstruction and the final polynomial evaluation. Every function is
// pure BigInt arithmetic over test/lib/goldilocks.js and test/lib/fp2.js and
// is the executable specification of contracts/hyperion/lib/FriVerifier.hyp.
//
// Conventions: base elements are canonical BigInts, extension elements are
// [c0, c1] pairs, indices are JS numbers (all heights are <= 2^32).

const G = require('./goldilocks');
const F2 = require('./fp2');

// Plonky3 reverse_bits_len for any bit count including zero.
function revBits(x, bits) {
  if (!Number.isInteger(bits) || bits < 0 || bits > 32) {
    throw new RangeError(`bit count out of range: ${bits}`);
  }
  let v = BigInt(x);
  let r = 0n;
  for (let i = 0; i < bits; i += 1) {
    r = (r << 1n) | (v & 1n);
    v >>= 1n;
  }
  return Number(r);
}

// g_logHeight^rev(index, logHeight): the natural-order domain point of the
// bit-reversed row `index`.
function domainPoint(index, logHeight) {
  return G.pow(G.twoAdicGen(logHeight), BigInt(revBits(index, logHeight)));
}

// The LDE evaluation point of query index `index` at height 2^logHeight:
// x = 7 * g_H^rev(index, H) (shift = GENERATOR, PROTOCOL.md section 6).
function queryPoint(index, logHeight) {
  return G.mul(G.GENERATOR, domainPoint(index, logHeight));
}

class FriError extends Error {
  constructor(name, detail) {
    super(detail ? `${name}: ${detail}` : name);
    this.name = name;
    this.errorName = name;
  }
}

// Successive powers 1, a, ..., a^(n-1).
function powers(a, n) {
  const out = [F2.ONE];
  for (let i = 1; i < n; i += 1) out.push(F2.mul(out[i - 1], a));
  return out;
}

// The reduced opening of one query (PROTOCOL.md section 7). Returns every
// intermediate in BigInt form; throws FriError('ZeroDenominator') when the
// query point coincides with zeta or zeta_next.
function reducedOpening({
  friAlpha,
  zeta,
  zetaNext,
  x,
  traceLocal,
  traceNext,
  quotientChunk,
  traceRow,
  quotientRow,
}) {
  const xe = F2.fromBase(x);
  const denomZeta = F2.sub(zeta, xe);
  const denomZetaNext = F2.sub(zetaNext, xe);
  if (F2.equal(denomZeta, F2.ZERO) || F2.equal(denomZetaNext, F2.ZERO)) {
    throw new FriError('ZeroDenominator');
  }
  const [invDenomZeta, invDenomZetaNext] = F2.batchInverse([denomZeta, denomZetaNext]);
  const a = powers(friAlpha, 6);
  const [r0, r1] = traceRow.map(F2.fromBase);
  const [s0, s1] = quotientRow.map(F2.fromBase);
  const terms = [
    F2.mul(F2.mul(a[0], F2.sub(traceLocal[0], r0)), invDenomZeta),
    F2.mul(F2.mul(a[1], F2.sub(traceLocal[1], r1)), invDenomZeta),
    F2.mul(F2.mul(a[2], F2.sub(traceNext[0], r0)), invDenomZetaNext),
    F2.mul(F2.mul(a[3], F2.sub(traceNext[1], r1)), invDenomZetaNext),
    F2.mul(F2.mul(a[4], F2.sub(quotientChunk[0], s0)), invDenomZeta),
    F2.mul(F2.mul(a[5], F2.sub(quotientChunk[1], s1)), invDenomZeta),
  ];
  let reduced = F2.ZERO;
  for (const t of terms) reduced = F2.add(reduced, t);
  return {
    x,
    denomZeta,
    denomZetaNext,
    invDenomZeta,
    invDenomZetaNext,
    reducedOpening: reduced,
  };
}

// The row of a round: the query's current value at `position`, the proof's
// sibling values (arity - 1 of them) at the other positions, ascending.
function reconstructRow(position, current, siblingValues, arity) {
  if (siblingValues.length !== arity - 1) {
    throw new RangeError(`expected ${arity - 1} sibling values, got ${siblingValues.length}`);
  }
  const row = new Array(arity);
  let s = 0;
  for (let j = 0; j < arity; j += 1) {
    if (j === position) {
      row[j] = current;
    } else {
      row[j] = siblingValues[s];
      s += 1;
    }
  }
  return row;
}

// s = g_{h+k}^rev(foldedIndex, h): the start of the coset the row lives on
// (h = folded height, k = log arity).
function subgroupStart(foldedIndex, foldedLogHeight, logArity) {
  return G.pow(
    G.twoAdicGen(foldedLogHeight + logArity),
    BigInt(revBits(foldedIndex, foldedLogHeight))
  );
}

// fold_row as k sequential binary folds with challenges beta, beta^2, ...
// (PROTOCOL.md section 8.3, the on-chain form). The row is in bit-reversed
// order over the coset s * <g_k>; at a step with 2^m values the pair
// (row[2j], row[2j+1]) sits at (y, -y) with y = s * g_m^rev(j, m-1) and folds
// to (lo + hi) / 2 + b * (lo - hi) / (2y); then s <- s^2, b <- b^2.
function foldRowBinary(foldedIndex, foldedLogHeight, logArity, beta, row) {
  if (row.length !== 2 ** logArity) throw new RangeError('row length must be 2^logArity');
  let vals = row.slice();
  let s = subgroupStart(foldedIndex, foldedLogHeight, logArity);
  // 1 / (2y) = INV2 * s^-1 * g_m^-rev(j, m-1): one inversion per row, the
  // inverse coset start squares alongside s (the contract does the same).
  let sInv = G.inv(s);
  let b = beta;
  let m = logArity;
  while (m > 0) {
    const half = 2 ** (m - 1);
    const gInv = G.twoAdicGenInv(m);
    const next = new Array(half);
    for (let j = 0; j < half; j += 1) {
      const inv2y = G.mul(G.mul(G.INV2, sInv), G.pow(gInv, BigInt(revBits(j, m - 1))));
      const lo = vals[2 * j];
      const hi = vals[2 * j + 1];
      const even = F2.mulBase(F2.add(lo, hi), G.INV2);
      const odd = F2.mulBase(F2.mul(F2.sub(lo, hi), b), inv2y);
      next[j] = F2.add(even, odd);
    }
    vals = next;
    s = G.sq(s);
    sInv = G.sq(sInv);
    b = F2.sq(b);
    m -= 1;
  }
  return vals[0];
}

function lagrangeInterpolateAt(xs, ys, z) {
  const n = xs.length;
  if (n === 0) return F2.ZERO;
  for (let i = 0; i < n; i += 1) {
    if (F2.equal(z, F2.fromBase(xs[i]))) return ys[i];
  }
  const logN = Math.log2(n);
  const cosetPower = G.pow2k(xs[0], logN);
  const weightScale = G.inv(G.mul(BigInt(n), cosetPower));
  const diffs = xs.map((x) => F2.sub(z, F2.fromBase(x)));
  const diffInvs = F2.batchInverse(diffs);
  let lZ = F2.ONE;
  for (const d of diffs) lZ = F2.mul(lZ, d);
  let result = F2.ZERO;
  for (let i = 0; i < n; i += 1) {
    const weight = G.mul(xs[i], weightScale);
    result = F2.add(result, F2.mul(F2.mulBase(ys[i], weight), diffInvs[i]));
  }
  return F2.mul(result, lZ);
}

// Literal port of TwoAdicFriFolding::fold_row (barycentric interpolation at
// beta over the bit-reversed coset points), kept to triangulate mismatches.
function foldRowBarycentric(foldedIndex, foldedLogHeight, logArity, beta, row) {
  const arity = 2 ** logArity;
  if (row.length !== arity) throw new RangeError('row length must be 2^logArity');
  const s = subgroupStart(foldedIndex, foldedLogHeight, logArity);
  const g = G.twoAdicGen(logArity);
  const xsNatural = [];
  for (let i = 0; i < arity; i += 1) xsNatural.push(G.mul(s, G.pow(g, BigInt(i))));
  const xs = [];
  for (let i = 0; i < arity; i += 1) xs.push(xsNatural[revBits(i, logArity)]);
  return lagrangeInterpolateAt(xs, row, beta);
}

// coeffs[0] + coeffs[1] x + ... at a base field point.
function horner(coeffs, x) {
  const xe = F2.fromBase(x);
  let acc = F2.ZERO;
  for (let i = coeffs.length - 1; i >= 0; i -= 1) acc = F2.add(F2.mul(acc, xe), coeffs[i]);
  return acc;
}

// The fold chain of one query (PROTOCOL.md sections 8.2 to 8.4) from its
// reduced opening down to the final polynomial check. `rounds[r]` supplies
// { logArity, siblingValues } for this query; `betas[r]` the challenges.
// Returns { steps, finalIndex, finalX, finalValue, folded, ok }; each step
// carries the same fields as the vector `fold[]` entries in BigInt form plus
// the leaf preimage bytes.
function foldChain({ index, reduced, logHeight, rounds, betas, finalPoly, efBytes }) {
  let idx = index;
  let folded = reduced;
  let height = logHeight;
  const steps = [];
  rounds.forEach((round, r) => {
    const k = round.logArity;
    const arity = 2 ** k;
    const position = idx & (arity - 1);
    const row = reconstructRow(position, folded, round.siblingValues, arity);
    const foldedHeight = height - k;
    const foldedIndex = idx >> k;
    const binary = foldRowBinary(foldedIndex, foldedHeight, k, betas[r], row);
    const barycentric = foldRowBarycentric(foldedIndex, foldedHeight, k, betas[r], row);
    const rowBytes = new Uint8Array(arity * 16);
    row.forEach((e, j) => rowBytes.set(efBytes(e), 16 * j));
    steps.push({
      round: r,
      logArity: k,
      index: idx,
      position,
      row,
      foldedIndex,
      subgroupStart: subgroupStart(foldedIndex, foldedHeight, k),
      folded: binary,
      foldedBarycentric: barycentric,
      rowBytes,
      foldedHeight,
    });
    idx = foldedIndex;
    height = foldedHeight;
    folded = binary;
  });
  const finalX = domainPoint(idx, logHeight);
  const finalValue = horner(finalPoly, finalX);
  return {
    steps,
    finalIndex: idx,
    finalHeight: height,
    finalX,
    finalValue,
    folded,
    ok: F2.equal(finalValue, folded),
  };
}

module.exports = {
  FriError,
  domainPoint,
  foldChain,
  foldRowBarycentric,
  foldRowBinary,
  horner,
  lagrangeInterpolateAt,
  powers,
  queryPoint,
  reconstructRow,
  reducedOpening,
  revBits,
  subgroupStart,
};
