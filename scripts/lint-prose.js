// Prose lint for the workspace style rules.
//
// Errors (exit 1): any U+2014 em dash in a tracked or untracked-but-not-ignored
// text file. Warnings (exit 0): the contrastive-negation shapes listed in
// WARNING_PATTERNS (kinds comma-not, not-but, rather-than, instead-of,
// comma-never and no-only), which also match legitimate sentences and therefore
// only get reported. Usage: npm run lint:prose [-- --strict] (--strict turns
// warnings into errors).

const fs = require('fs');
const path = require('path');
const { execFileSync } = require('child_process');

const repoRoot = path.join(__dirname, '..');

const BINARY_EXTENSIONS = new Set([
  '.png',
  '.jpg',
  '.jpeg',
  '.gif',
  '.ico',
  '.webp',
  '.svg',
  '.woff',
  '.woff2',
  '.ttf',
  '.otf',
  '.pdf',
  '.zip',
  '.gz',
  '.tar',
  '.wasm',
  '.bin',
  '.so',
  '.dylib',
  '.lock',
]);
// LICENSE is third-party text (GPL-3.0) and is never edited here.
const SKIP_BASENAMES = new Set(['package-lock.json', 'Cargo.lock', 'LICENSE']);
const MAX_FILE_BYTES = 8 * 1024 * 1024;

const EM_DASH = '\u2014';
const COMMA_NOT = /, not /;
const NOT_BUT = /\bnot\b[^.\n]*, but\b/i;
const RATHER_THAN = /\brather than\b/i;
const INSTEAD_OF = /\binstead of\b/i;
const COMMA_NEVER = /, never /;
const NO_ONLY = /\bno \w+, only\b/i;

// One warning per line per kind; the label names the shape the pattern looks for.
const WARNING_PATTERNS = [
  { kind: 'comma-not', regex: COMMA_NOT, label: 'possible contrastive negation ", not "' },
  { kind: 'not-but', regex: NOT_BUT, label: 'possible contrastive negation "not ..., but"' },
  {
    kind: 'rather-than',
    regex: RATHER_THAN,
    label: 'possible contrastive negation " rather than "',
  },
  { kind: 'instead-of', regex: INSTEAD_OF, label: 'possible contrastive negation " instead of "' },
  { kind: 'comma-never', regex: COMMA_NEVER, label: 'possible contrastive negation ", never "' },
  { kind: 'no-only', regex: NO_ONLY, label: 'possible contrastive negation "no X, only Y"' },
];

function listFiles(root = repoRoot) {
  const out = execFileSync(
    'git',
    ['ls-files', '--cached', '--others', '--exclude-standard', '-z'],
    { cwd: root }
  );
  return out
    .toString('utf8')
    .split('\0')
    .filter(Boolean)
    .filter((file) => !SKIP_BASENAMES.has(path.basename(file)))
    .filter((file) => !BINARY_EXTENSIONS.has(path.extname(file).toLowerCase()));
}

// Returns [{ line, column, kind, text }] for one file's content.
function scanText(text) {
  const findings = [];
  const lines = text.split('\n');
  lines.forEach((line, index) => {
    let column = line.indexOf(EM_DASH);
    while (column !== -1) {
      findings.push({ line: index + 1, column: column + 1, kind: 'em-dash', text: line.trim() });
      column = line.indexOf(EM_DASH, column + 1);
    }
    for (const pattern of WARNING_PATTERNS) {
      const match = line.match(pattern.regex);
      if (match) {
        findings.push({
          line: index + 1,
          column: match.index + 1,
          kind: pattern.kind,
          text: line.trim(),
        });
      }
    }
  });
  return findings;
}

function isProbablyBinary(buffer) {
  const sample = buffer.subarray(0, 8000);
  return sample.includes(0);
}

function lintFiles(files, root = repoRoot) {
  const errors = [];
  const warnings = [];
  for (const file of files) {
    const absolute = path.join(root, file);
    let stat;
    try {
      stat = fs.statSync(absolute);
    } catch {
      continue;
    }
    if (!stat.isFile() || stat.size > MAX_FILE_BYTES) continue;
    const buffer = fs.readFileSync(absolute);
    if (isProbablyBinary(buffer)) continue;
    for (const finding of scanText(buffer.toString('utf8'))) {
      const entry = { file, ...finding };
      if (finding.kind === 'em-dash') errors.push(entry);
      else warnings.push(entry);
    }
  }
  return { errors, warnings };
}

function formatFinding(entry) {
  const pattern = WARNING_PATTERNS.find((p) => p.kind === entry.kind);
  const label = pattern ? pattern.label : 'em dash (U+2014)';
  return `${entry.file}:${entry.line}:${entry.column}: ${label}: ${entry.text}`;
}

function main() {
  const strict = process.argv.includes('--strict');
  const files = listFiles();
  const { errors, warnings } = lintFiles(files);
  for (const warning of warnings) {
    console.warn(`warning: ${formatFinding(warning)}`);
  }
  for (const error of errors) {
    console.error(`error: ${formatFinding(error)}`);
  }
  console.log(
    `lint:prose scanned ${files.length} file(s): ${errors.length} error(s), ${warnings.length} warning(s)`
  );
  if (errors.length > 0 || (strict && warnings.length > 0)) {
    process.exit(1);
  }
}

if (require.main === module) {
  main();
}

module.exports = { WARNING_PATTERNS, lintFiles, listFiles, scanText };
