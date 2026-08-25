// Loader for the prover-generated test vectors (test/vectors/*.json and
// test/vectors/mutations/*.json), shared by every unit suite.
//
// The files are large (up to about 1 MB each), so every suite parses each
// file at most once per process through the cache below and reads the parsed
// object in place. The helpers convert the JSON wire forms (0x-hex bytes,
// decimal field elements, [c0, c1] extension pairs) into the BigInt and
// Uint8Array forms the JS references work with.
//
// Valid vectors live directly under test/vectors/ (tracked for degree bits
// <= 12). The gitignored test/vectors/large/ directory holds bigger instances
// and is only included when STARK_VECTORS_LARGE=1, so the default unit run
// stays short.

const fs = require('fs');
const path = require('path');

const VECTORS_DIR = path.join(__dirname, '..', 'vectors');
const MUTATIONS_DIR = path.join(VECTORS_DIR, 'mutations');
const LARGE_DIR = path.join(VECTORS_DIR, 'large');
const PLONKY3_VERSION_FILE = path.join(__dirname, '..', '..', 'prover', 'PLONKY3_VERSION');

// Vector schema version written by prover/stark-prover/src/vectors.rs.
const SCHEMA = 1;

// Every error name the verifier can raise (mirror.rs MirrorError::ALL_NAMES).
const ERROR_NAMES = Object.freeze([
  'BadVersion',
  'BadHeader',
  'BadLength',
  'NonCanonicalElement',
  'OodPointInDomain',
  'OodMismatch',
  'PowFailed',
  'DuplicateOpeningMismatch',
  'SiblingCountMismatch',
  'MerkleRootMismatch',
  'ZeroDenominator',
  'FinalPolyMismatch',
]);

const cache = new Map();

function listJsonFiles(dir) {
  if (!fs.existsSync(dir)) return [];
  return fs
    .readdirSync(dir)
    .filter((name) => name.endsWith('.json'))
    .sort()
    .map((name) => path.join(dir, name));
}

function includeLarge() {
  return process.env.STARK_VECTORS_LARGE === '1';
}

// Absolute paths of the valid vectors, sorted by name.
function listValidVectorFiles() {
  const files = listJsonFiles(VECTORS_DIR);
  return includeLarge() ? files.concat(listJsonFiles(LARGE_DIR)) : files;
}

// Absolute paths of the mutated vectors, sorted by name.
function listMutationVectorFiles() {
  return listJsonFiles(MUTATIONS_DIR);
}

// Parse one vector file (cached per process).
function loadVector(file) {
  const absolute = path.resolve(file);
  let vector = cache.get(absolute);
  if (vector === undefined) {
    vector = JSON.parse(fs.readFileSync(absolute, 'utf8'));
    cache.set(absolute, vector);
  }
  return vector;
}

function loadAll(files) {
  return files.map((file) => ({
    file,
    baseName: path.basename(file, '.json'),
    vector: loadVector(file),
  }));
}

// [{ file, baseName, vector }] for every valid vector.
function loadValidVectors() {
  return loadAll(listValidVectorFiles());
}

// [{ file, baseName, vector }] for every mutated vector.
function loadMutationVectors() {
  return loadAll(listMutationVectorFiles());
}

// The valid vector a mutation was derived from (its `source` field).
function loadSourceVector(mutated) {
  const candidates = [path.join(VECTORS_DIR, `${mutated.source}.json`)];
  if (includeLarge()) candidates.push(path.join(LARGE_DIR, `${mutated.source}.json`));
  const file = candidates.find((f) => fs.existsSync(f));
  if (!file) throw new Error(`source vector ${mutated.source} not found`);
  return loadVector(file);
}

function plonky3Version() {
  return fs.readFileSync(PLONKY3_VERSION_FILE, 'utf8').trim();
}

// Byte helpers.

function hexToBytes(hex) {
  if (typeof hex !== 'string') throw new TypeError('hex string expected');
  const body = hex.startsWith('0x') || hex.startsWith('0X') ? hex.slice(2) : hex;
  if (body.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(body)) {
    throw new TypeError(`malformed hex string of length ${body.length}`);
  }
  const buf = Buffer.from(body, 'hex');
  return new Uint8Array(buf.buffer, buf.byteOffset, buf.length);
}

// 0x-prefixed lowercase hex, the form the vectors use.
function bytesToHex(bytes) {
  return `0x${Buffer.from(bytes).toString('hex')}`;
}

// Path of the first difference between two JSON-like values (arrays, plain
// objects, primitives), or null when they are equal. Used by the suites to
// report a readable location; a raw deep-equality failure would print a
// multi-megabyte diff.
function firstDifference(a, b, at = '$') {
  if (Array.isArray(a) || Array.isArray(b)) {
    if (!Array.isArray(a) || !Array.isArray(b)) return `${at}: array on one side only`;
    if (a.length !== b.length) return `${at}: length ${a.length} vs ${b.length}`;
    for (let i = 0; i < a.length; i += 1) {
      const d = firstDifference(a[i], b[i], `${at}[${i}]`);
      if (d) return d;
    }
    return null;
  }
  if (a && b && typeof a === 'object' && typeof b === 'object') {
    const keys = [...new Set([...Object.keys(a), ...Object.keys(b)])].sort();
    for (const k of keys) {
      if (!(k in a)) return `${at}.${k}: missing on the left`;
      if (!(k in b)) return `${at}.${k}: missing on the right`;
      const d = firstDifference(a[k], b[k], `${at}.${k}`);
      if (d) return d;
    }
    return null;
  }
  if (a !== b) return `${at}: ${String(a)} vs ${String(b)}`;
  return null;
}

function bytesEqual(a, b) {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i += 1) if (a[i] !== b[i]) return false;
  return true;
}

function concatBytes(...parts) {
  let total = 0;
  for (const p of parts) total += p.length;
  const out = new Uint8Array(total);
  let off = 0;
  for (const p of parts) {
    out.set(p, off);
    off += p.length;
  }
  return out;
}

// Field element helpers (vectors carry decimal strings).

function f(str) {
  if (typeof str !== 'string' || !/^\d+$/.test(str)) {
    throw new TypeError(`decimal field element expected, got ${String(str)}`);
  }
  return BigInt(str);
}

function fStr(x) {
  return BigInt(x).toString();
}

// [c0, c1] decimal pair -> [BigInt, BigInt].
function ef(pair) {
  if (!Array.isArray(pair) || pair.length !== 2) {
    throw new TypeError('[c0, c1] pair expected');
  }
  return [f(pair[0]), f(pair[1])];
}

function efStr(e) {
  return [fStr(e[0]), fStr(e[1])];
}

function efList(list) {
  return list.map(ef);
}

// Proof and public value accessors.

function proofBytes(vector) {
  return hexToBytes(vector.proofHex);
}

function publicValuesBytes(vector) {
  return hexToBytes(vector.publicValuesHex);
}

// The three public values as BigInts (from the decimal strings).
function publicValues(vector) {
  return vector.publicValues.map(f);
}

module.exports = {
  ERROR_NAMES,
  LARGE_DIR,
  MUTATIONS_DIR,
  PLONKY3_VERSION_FILE,
  SCHEMA,
  VECTORS_DIR,
  bytesEqual,
  bytesToHex,
  concatBytes,
  ef,
  efList,
  efStr,
  f,
  fStr,
  firstDifference,
  hexToBytes,
  listMutationVectorFiles,
  listValidVectorFiles,
  loadMutationVectors,
  loadSourceVector,
  loadValidVectors,
  loadVector,
  plonky3Version,
  proofBytes,
  publicValues,
  publicValuesBytes,
};
