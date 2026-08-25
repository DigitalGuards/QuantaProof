const assert = require('node:assert/strict');
const test = require('node:test');

const {
  assertCommitMatch,
  parseGqrlCommit,
  parseHyperionCommit,
} = require('../../scripts/check-provenance');

test('parses the Hyperion compiler revision', () => {
  assert.equal(
    parseHyperionCommit('Version: 0.2.0-develop.2026.8.25+commit.cf176678.Linux.g++'),
    'cf176678'
  );
  assert.throws(() => parseHyperionCommit('Version: unknown'), /no embedded commit/);
});

test('parses the gqrl binary revision', () => {
  assert.equal(
    parseGqrlCommit(
      'Gqrl\nVersion: 0.3.3-stable\nGit Commit: b19c839884312b5e0a392c721a7fa5b416aeeecd'
    ),
    'b19c839884312b5e0a392c721a7fa5b416aeeecd'
  );
  assert.throws(() => parseGqrlCommit('Version: 0.3.3-stable'), /no embedded Git Commit/);
});

test('accepts full or abbreviated matching revisions and rejects drift', () => {
  const full = 'cf176678158ee15b4536cc68a49eaebbbde24983';
  assert.doesNotThrow(() => assertCommitMatch('hypc', full, 'cf176678'));
  assert.doesNotThrow(() => assertCommitMatch('hypc', full, full));
  assert.throws(() => assertCommitMatch('hypc', full, 'deadbee'), /does not match source HEAD/);
});
