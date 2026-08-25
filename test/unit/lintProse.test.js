// Heuristics of scripts/lint-prose.js: em dashes are errors, the two
// contrastive-negation patterns are warnings.

const assert = require('node:assert/strict');
const test = require('node:test');

const { scanText } = require('../../scripts/lint-prose');

const EM_DASH = '\u2014';

test('reports every em dash with line and column', () => {
  const findings = scanText(`fine line\nbad ${EM_DASH} line ${EM_DASH} twice\n`);
  const emDashes = findings.filter((f) => f.kind === 'em-dash');
  assert.equal(emDashes.length, 2);
  assert.deepEqual(
    emDashes.map((f) => [f.line, f.column]),
    [
      [2, 5],
      [2, 12],
    ]
  );
});

test('flags ", not " and "not ..., but" as contrastive negation', () => {
  const findings = scanText('contracted development, not employment\n');
  assert.deepEqual(
    findings.map((f) => f.kind),
    ['comma-not']
  );
  const notBut = scanText('It is not a wallet, but a signer.\n');
  assert.deepEqual(
    notBut.map((f) => f.kind),
    ['not-but']
  );
});

test('clean prose with hyphens, colons and "but" alone passes', () => {
  const text = [
    'Use a hyphen - or a colon: both are fine.',
    'The verifier is a STARK verifier. It verifies proofs but never signs.',
    'Note that not every line with the word not is flagged.',
  ].join('\n');
  assert.deepEqual(scanText(text), []);
});
