// JS reference for the constraint side of the verifier (docs/PROTOCOL.md
// section 10, prover/stark-prover/src/mirror.rs::evaluate_constraints): the
// trace-domain selectors at zeta, the five Fibonacci constraints in emission
// order, the alpha accumulator and the quotient recomposition. Executable
// specification of contracts/hyperion/air/FibonacciAir.hyp.

const G = require('./goldilocks');
const F2 = require('./fp2');

const W = 7n;

// Selectors of the trace domain (subgroup of size 2^degreeBits, shift 1).
function selectors(degreeBits, zeta) {
  const gInv = F2.fromBase(G.twoAdicGenInv(degreeBits));
  let zPow = zeta;
  for (let i = 0; i < degreeBits; i += 1) zPow = F2.sq(zPow);
  const zH = F2.sub(zPow, F2.ONE);
  const zetaMinusOne = F2.sub(zeta, F2.ONE);
  const isTrans = F2.sub(zeta, gInv);
  if (F2.equal(zH, F2.ZERO) || F2.equal(zetaMinusOne, F2.ZERO) || F2.equal(isTrans, F2.ZERO)) {
    throw new RangeError('zeta lies on the trace domain');
  }
  return {
    zH,
    isFirst: F2.mul(zH, F2.inv(zetaMinusOne)),
    isLast: F2.mul(zH, F2.inv(isTrans)),
    isTrans,
    invVan: F2.inv(zH),
  };
}

// q0 + X * q1 from the two opened basis coefficients: (q0.c0 + 7 q1.c1, q0.c1 + q1.c0).
function recomposeQuotient([q0, q1]) {
  return [G.add(q0[0], G.mul(W, q1[1])), G.add(q0[1], q1[0])];
}

// The five constraints in emission order, their alpha-folded accumulator and
// the recomposed quotient. `ok` is the identity acc * invVan == quotient.
function evaluateConstraints({
  degreeBits,
  zeta,
  alpha,
  traceLocal,
  traceNext,
  quotientChunk,
  publicValues,
}) {
  const sel = selectors(degreeBits, zeta);
  const [a, b, x] = publicValues.map(F2.fromBase);
  const [l0, l1] = traceLocal;
  const [n0, n1] = traceNext;
  const values = [
    F2.mul(sel.isFirst, F2.sub(l0, a)),
    F2.mul(sel.isFirst, F2.sub(l1, b)),
    F2.mul(sel.isTrans, F2.sub(l1, n0)),
    F2.mul(sel.isTrans, F2.sub(F2.add(l0, l1), n1)),
    F2.mul(sel.isLast, F2.sub(l1, x)),
  ];
  let acc = F2.ZERO;
  for (const c of values) acc = F2.add(F2.mul(acc, alpha), c);
  const quotient = recomposeQuotient(quotientChunk);
  return {
    ...sel,
    values,
    acc,
    quotient,
    ok: F2.equal(F2.mul(acc, sel.invVan), quotient),
  };
}

module.exports = { W, evaluateConstraints, recomposeQuotient, selectors };
