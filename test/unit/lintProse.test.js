// Heuristics of scripts/lint-prose.js: em dashes are errors, the
// contrastive-negation patterns are warnings.

const assert = require('node:assert/strict');
const test = require('node:test');

const { WARNING_PATTERNS, scanText } = require('../../scripts/lint-prose');

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

test('flags " rather than ", " instead of ", ", never " and "no X, only Y"', () => {
  const cases = [
    ['Recursion rather than staging keeps the proof in one transaction.\n', 'rather-than'],
    ['Instead of a blanket limit the scripts send the estimate.\n', 'instead-of'],
    ['Facts are keyed by public values, never by proofId.\n', 'comma-never'],
    ['There is no split, only a documented boundary.\n', 'no-only'],
  ];
  for (const [text, kind] of cases) {
    const findings = scanText(text);
    assert.deepEqual(
      findings.map((f) => f.kind),
      [kind],
      text
    );
    assert.equal(findings[0].line, 1);
    assert.ok(findings[0].column >= 1);
  }
});

test('every warning kind has a label and a regex', () => {
  const kinds = WARNING_PATTERNS.map((p) => p.kind);
  assert.deepEqual(kinds, [
    'comma-not',
    'not-but',
    'rather-than',
    'instead-of',
    'comma-never',
    'no-only',
  ]);
  for (const pattern of WARNING_PATTERNS) {
    assert.ok(pattern.regex instanceof RegExp, pattern.kind);
    assert.ok(pattern.label.length > 0, pattern.kind);
  }
});

test('clean prose with hyphens, colons and "but" alone passes', () => {
  const text = [
    'Use a hyphen - or a colon: both are fine.',
    'The verifier is a STARK verifier. It verifies proofs but never signs.',
    'Note that not every line with the word not is flagged.',
    'The proof bytes never enter the key.',
    'Rather, the walk consumes siblings in wire order; the leaf is hashed instead.',
    'No per-preset files exist and only c3 is committed.',
  ].join('\n');
  assert.deepEqual(scanText(text), []);
});
