// Enforce the QRVM contract size limits on the compiled artifacts.
//
// Runtime bytecode is capped at 24,576 bytes and creation code at 49,152
// bytes on QRL 2.0. The script prints one table row per deployable listed in
// build/hyperion/manifest.json (falling back to every non-empty *.bin-runtime
// file in build/hyperion/) and exits 1 when any contract exceeds a limit.

const fs = require('fs');
const path = require('path');

const repoRoot = path.join(__dirname, '..');
const artifactsDir = path.join(repoRoot, 'build', 'hyperion');
const manifestPath = path.join(artifactsDir, 'manifest.json');

const MAX_RUNTIME_BYTES = 24576;
const MAX_INITCODE_BYTES = 49152;

function hexFileByteLength(file) {
  if (!fs.existsSync(file)) {
    return 0;
  }
  const hex = fs.readFileSync(file, 'utf8').trim();
  if (hex.length % 2 !== 0 || !/^[0-9a-fA-F]*$/.test(hex)) {
    throw new Error(`${file} is not a hex artifact`);
  }
  return hex.length / 2;
}

function collectEntries() {
  if (!fs.existsSync(artifactsDir)) {
    throw new Error(`${artifactsDir} does not exist. Run \`npm run compile\` first.`);
  }
  if (fs.existsSync(manifestPath)) {
    const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
    return manifest.contracts.map((entry) => ({
      contractName: entry.contractName,
      sourceFile: entry.sourceFile,
      runtimeBytes: hexFileByteLength(path.join(artifactsDir, entry.runtimeFile)),
      initcodeBytes: hexFileByteLength(path.join(artifactsDir, entry.binFile)),
    }));
  }
  const entries = [];
  for (const file of fs.readdirSync(artifactsDir).sort()) {
    if (!file.endsWith('.bin-runtime')) continue;
    const contractName = file.replace(/\.bin-runtime$/, '');
    const runtimeBytes = hexFileByteLength(path.join(artifactsDir, file));
    if (runtimeBytes === 0) continue; // interface or abstract contract
    entries.push({
      contractName,
      sourceFile: '(no manifest)',
      runtimeBytes,
      initcodeBytes: hexFileByteLength(path.join(artifactsDir, `${contractName}.bin`)),
    });
  }
  if (entries.length === 0) {
    throw new Error(`No runtime artifacts in ${artifactsDir}. Run \`npm run compile\` first.`);
  }
  return entries;
}

function formatTable(rows) {
  const header = ['Contract', 'Runtime bytes', 'Runtime headroom', 'Initcode bytes', 'Status'];
  const cells = rows.map((row) => [
    row.contractName,
    String(row.runtimeBytes),
    String(MAX_RUNTIME_BYTES - row.runtimeBytes),
    String(row.initcodeBytes),
    row.ok ? 'ok' : 'OVER LIMIT',
  ]);
  const widths = header.map((h, i) => Math.max(h.length, ...cells.map((c) => c[i].length)));
  const line = (parts) => parts.map((p, i) => p.padEnd(widths[i])).join('  ');
  return [line(header), line(widths.map((w) => '-'.repeat(w))), ...cells.map(line)].join('\n');
}

function checkCodeSize() {
  const rows = collectEntries().map((entry) => ({
    ...entry,
    ok: entry.runtimeBytes <= MAX_RUNTIME_BYTES && entry.initcodeBytes <= MAX_INITCODE_BYTES,
  }));
  console.log(formatTable(rows));
  console.log(
    `\nLimits: runtime ${MAX_RUNTIME_BYTES} bytes, initcode ${MAX_INITCODE_BYTES} bytes.`
  );
  const failures = rows.filter((row) => !row.ok);
  for (const row of failures) {
    if (row.runtimeBytes > MAX_RUNTIME_BYTES) {
      console.error(
        `${row.contractName}: runtime ${row.runtimeBytes} bytes exceeds ${MAX_RUNTIME_BYTES} ` +
          `by ${row.runtimeBytes - MAX_RUNTIME_BYTES} bytes`
      );
    }
    if (row.initcodeBytes > MAX_INITCODE_BYTES) {
      console.error(
        `${row.contractName}: initcode ${row.initcodeBytes} bytes exceeds ${MAX_INITCODE_BYTES} ` +
          `by ${row.initcodeBytes - MAX_INITCODE_BYTES} bytes`
      );
    }
  }
  if (failures.length > 0) {
    console.error(
      '\nCode-size contingency (docs/DECISIONS.md): HYPERION_OPTIMIZE_RUNS=1, then HYPERION_VIA_IR=1, ' +
        'then split the FRI verifier into a second contract.'
    );
  }
  return { rows, ok: failures.length === 0 };
}

if (require.main === module) {
  try {
    const { ok } = checkCodeSize();
    process.exit(ok ? 0 : 1);
  } catch (err) {
    console.error(err.message);
    process.exit(1);
  }
}

module.exports = { MAX_INITCODE_BYTES, MAX_RUNTIME_BYTES, checkCodeSize };
