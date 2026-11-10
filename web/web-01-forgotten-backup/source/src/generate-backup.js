'use strict';

/**
 * Generates the operations backup archive at container startup.
 * The per-team flag is injected by GZ::CTF through GZCTF_FLAG and is written
 * only into config/production.env inside the archive.
 */

const fs = require('node:fs');
const path = require('node:path');
const yazl = require('yazl');

const APP_DIR = path.resolve(__dirname, '..');
const BACKUP_DIR = path.resolve(process.env.BACKUP_DIR ?? path.join(APP_DIR, 'runtime', 'backups'));
const ARCHIVE_NAME = 'northstar-site-backup.zip';
const STAGING_NAME = '.northstar-site-backup.zip.partial';
const ARCHIVE_MTIME = new Date('2025-10-18T02:14:00Z');

function fail(message) {
  console.error(`[backup] ${message}`);
  process.exit(1);
}

function readFlag() {
  const flag = process.env.GZCTF_FLAG;

  if (typeof flag !== 'string' || flag.trim().length === 0) {
    fail('GZCTF_FLAG is missing or empty; refusing to generate the backup archive');
  }

  // A flag containing a line break would corrupt the env file and could inject directives.
  if (/[\r\n\0]/.test(flag)) {
    fail('GZCTF_FLAG contains unsupported control characters');
  }

  return flag;
}

function productionEnv(flag) {
  return [
    '# Northstar Systems - production environment',
    '# Exported by the deployment pipeline. Confidential - do not distribute.',
    '',
    'APP_NAME=northstar-web',
    'APP_ENV=production',
    'APP_PORT=3000',
    'PUBLIC_ORIGIN=https://northstar-systems.example',
    'DATABASE_URL=postgresql://northstar_app:REDACTED@db.internal:5432/northstar',
    'SESSION_SECRET=REDACTED',
    'FEATURE_AUDIT_LOG=true',
    '',
    `CTF_FLAG=${flag}`,
    ''
  ].join('\n');
}

function collectSiteFiles() {
  const files = [
    'package.json',
    'src/server.js',
    'public/index.html',
    'public/style.css',
    'public/app.js',
    'public/robots.txt',
    'public/favicon.svg'
  ];

  return files.map((relative) => {
    const absolute = path.join(APP_DIR, relative);

    try {
      return { name: relative, data: fs.readFileSync(absolute) };
    } catch (error) {
      return fail(`unable to read site file ${relative}: ${error.message}`);
    }
  });
}

async function buildArchive(flag) {
  fs.mkdirSync(BACKUP_DIR, { recursive: true });

  const target = path.join(BACKUP_DIR, ARCHIVE_NAME);
  const staging = path.join(BACKUP_DIR, STAGING_NAME);

  const zip = new yazl.ZipFile();
  const entries = [
    { name: 'config/production.env', data: Buffer.from(productionEnv(flag), 'utf8') },
    ...collectSiteFiles()
  ];

  for (const entry of entries) {
    zip.addBuffer(entry.data, entry.name, { mtime: ARCHIVE_MTIME, mode: 0o644, compress: true });
  }

  await new Promise((resolve, reject) => {
    const output = fs.createWriteStream(staging, { mode: 0o644 });
    output.on('close', resolve);
    output.on('error', reject);
    zip.outputStream.on('error', reject);
    zip.outputStream.pipe(output);
    zip.end();
  });

  try {
    fs.renameSync(staging, target);
  } catch (error) {
    fs.rmSync(staging, { force: true });
    fail(`unable to publish backup archive: ${error.message}`);
  }

  const { size } = fs.statSync(target);
  console.log(`[backup] wrote ${ARCHIVE_NAME} (${entries.length} entries, ${size} bytes)`);
}

async function main() {
  const flag = readFlag();
  await buildArchive(flag);
}

main().catch((error) => fail(`backup generation failed: ${error.message}`));
