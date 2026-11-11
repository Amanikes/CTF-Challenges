'use strict';

/**
 * Northstar License Manager — runtime artifact generator.
 *
 * Runs once per container start, before the download service. It reads the
 * per-team GZCTF_FLAG, encodes it with the repeating XOR key documented in
 * shared/xor-spec.json, writes the encoded license.dat and packages the
 * participant ZIP. The plaintext flag is never written to disk, never logged
 * and is removed from this process environment before the archive is built.
 */

const fs = require('node:fs');
const path = require('node:path');
const { pipeline } = require('node:stream/promises');

const yazl = require('yazl');

const spec = require('../shared/xor-spec.json');

const KEY = Buffer.from(spec.keyBytes, 'utf8');
const MAX_BYTES = spec.maxPlaintextBytes;
const MIN_BYTE = spec.plaintextByteRange[0];
const MAX_BYTE = spec.plaintextByteRange[1];

const APP_ROOT = path.resolve(__dirname, '..');
const PACKAGE_NAME = 'northstar-license-package';
const ARCHIVE_NAME = 'northstar-license-package.zip';

const ARTIFACT_DIR = path.resolve(process.env.ARTIFACT_DIR ?? path.join(APP_ROOT, 'runtime'));
const BINARY_PATH = path.resolve(process.env.BINARY_PATH ?? path.join(APP_ROOT, 'bin', 'northstar-license'));
const README_PATH = path.resolve(process.env.PACKAGE_README ?? path.join(APP_ROOT, 'package', 'README.txt'));

// Fixed timestamp keeps the archive deterministic apart from the license bytes.
const FIXED_MTIME = new Date('2026-01-01T00:00:00Z');

function fail(message) {
  console.error(`[northstar-artifact] ${message}`);
  process.exit(1);
}

function encode(plaintext) {
  const encoded = Buffer.allocUnsafe(plaintext.length);

  for (let index = 0; index < plaintext.length; index += 1) {
    encoded[index] = plaintext[index] ^ KEY[index % KEY.length];
  }

  return encoded;
}

async function main() {
  const raw = process.env.GZCTF_FLAG;

  if (typeof raw !== 'string' || raw.trim().length === 0) {
    fail('GZCTF_FLAG is missing or empty; refusing to start');
  }

  delete process.env.GZCTF_FLAG;

  const plaintext = Buffer.from(raw, 'utf8');

  if (plaintext.length === 0 || plaintext.length > MAX_BYTES) {
    fail(`the injected flag length is outside the supported range (1-${MAX_BYTES} bytes)`);
  }

  for (const byte of plaintext) {
    if (byte < MIN_BYTE || byte > MAX_BYTE) {
      fail('the injected flag contains characters outside the supported range');
    }
  }

  for (const file of [BINARY_PATH, README_PATH]) {
    if (!fs.existsSync(file)) {
      fail(`required packaging input is missing: ${path.basename(file)}`);
    }
  }

  const encoded = encode(plaintext);
  plaintext.fill(0);

  fs.mkdirSync(ARTIFACT_DIR, { recursive: true });

  const licensePath = path.join(ARTIFACT_DIR, 'license.dat');
  fs.writeFileSync(licensePath, encoded, { mode: 0o644 });

  const archivePath = path.join(ARTIFACT_DIR, ARCHIVE_NAME);
  const tempPath = `${archivePath}.tmp`;

  const zip = new yazl.ZipFile();
  zip.addFile(README_PATH, `${PACKAGE_NAME}/README.txt`, { mtime: FIXED_MTIME, mode: 0o644 });
  zip.addFile(BINARY_PATH, `${PACKAGE_NAME}/northstar-license`, { mtime: FIXED_MTIME, mode: 0o755 });
  zip.addFile(licensePath, `${PACKAGE_NAME}/license.dat`, { mtime: FIXED_MTIME, mode: 0o644 });
  zip.end();

  try {
    await pipeline(zip.outputStream, fs.createWriteStream(tempPath));
    fs.renameSync(tempPath, archivePath);
  } finally {
    fs.rmSync(tempPath, { force: true });
    fs.rmSync(licensePath, { force: true });
  }

  encoded.fill(0);

  console.log(
    `[northstar-artifact] packaged ${PACKAGE_NAME} (${fs.statSync(archivePath).size} bytes, ${MAX_BYTES} byte limit)`
  );
}

main().catch((error) => {
  fail(`artifact generation failed: ${error?.message ?? 'unknown error'}`);
});
