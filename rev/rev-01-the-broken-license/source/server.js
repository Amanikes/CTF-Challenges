'use strict';

/**
 * Northstar License Manager — download service.
 *
 * Serves the participant package generated at container start. It never reads
 * GZCTF_FLAG (the entrypoint removes it before this process starts) and only
 * ever serves the fixed archive path.
 */

const fs = require('node:fs');
const path = require('node:path');
const express = require('express');

const APP_ROOT = path.resolve(__dirname);
const PORT = Number.parseInt(process.env.PORT ?? '3000', 10);
const HOST = '0.0.0.0';
const ARTIFACT_DIR = path.resolve(process.env.ARTIFACT_DIR ?? path.join(APP_ROOT, 'runtime'));
const ARCHIVE_NAME = 'northstar-license-package.zip';
const ARCHIVE_PATH = path.join(ARTIFACT_DIR, ARCHIVE_NAME);
const PUBLIC_DIR = path.join(APP_ROOT, 'public');

const app = express();

app.disable('x-powered-by');

app.use((_req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; style-src 'self'; img-src 'self' data:; script-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
  );
  next();
});

const archiveReady = () => fs.existsSync(ARCHIVE_PATH);

app.get('/health', (_req, res) => {
  res.setHeader('Cache-Control', 'no-store');

  if (!archiveReady()) {
    res.status(503).json({ status: 'starting', service: 'northstar-license-download', archive: 'missing' });
    return;
  }

  res.status(200).json({ status: 'ok', service: 'northstar-license-download', archive: 'ready' });
});

app.get('/download', (_req, res, next) => {
  if (!archiveReady()) {
    res.status(503).json({ error: 'archive_unavailable' });
    return;
  }

  res.setHeader('Cache-Control', 'no-store');
  res.download(ARCHIVE_PATH, ARCHIVE_NAME, { headers: { 'Content-Type': 'application/zip' } }, (error) => {
    if (error && !res.headersSent) next(error);
  });
});

app.use('/assets', express.static(PUBLIC_DIR, { fallthrough: false, index: false, maxAge: 0 }));

app.get('/', (_req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.sendFile(path.join(PUBLIC_DIR, 'index.html'));
});

app.use((_req, res) => {
  res.status(404).json({ error: 'not_found' });
});

app.use((error, _req, res, _next) => {
  console.error('[northstar-download] request failed:', error?.code ?? error?.message ?? 'unknown');
  res.status(500).json({ error: 'internal_error' });
});

const server = app.listen(PORT, HOST, () => {
  console.log(`[northstar-download] listening on http://${HOST}:${PORT}`);
});

function shutdown(signal) {
  console.log(`[northstar-download] received ${signal}, shutting down`);
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 2000).unref();
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
