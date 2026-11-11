'use strict';

/**
 * Meridian Logistics — network capture download service.
 *
 * Serves the PCAP generated at container start. The service never reads
 * GZCTF_FLAG (the entrypoint removes it first), exposes no environment
 * inspection and serves a single fixed artifact path.
 */

const fs = require('node:fs');
const path = require('node:path');
const express = require('express');

const PORT = Number.parseInt(process.env.PORT ?? '3000', 10);
const HOST = '0.0.0.0';
const RUNTIME_DIR = path.resolve(process.env.RUNTIME_DIR ?? path.join(__dirname, 'runtime'));
const CAPTURE_NAME = 'meridian-traffic.pcap';
const CAPTURE_PATH = path.join(RUNTIME_DIR, CAPTURE_NAME);
const PUBLIC_DIR = path.join(__dirname, '..', 'public');

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

const captureReady = () => fs.existsSync(CAPTURE_PATH);

app.get('/health', (_req, res) => {
  res.setHeader('Cache-Control', 'no-store');

  if (!captureReady()) {
    res.status(503).json({ status: 'starting', service: 'meridian-capture-download', capture: 'missing' });
    return;
  }

  res.status(200).json({ status: 'ok', service: 'meridian-capture-download', capture: 'ready' });
});

app.get('/download', (_req, res, next) => {
  if (!captureReady()) {
    res.status(503).json({ error: 'capture_unavailable' });
    return;
  }

  res.setHeader('Cache-Control', 'no-store');
  res.download(
    CAPTURE_PATH,
    CAPTURE_NAME,
    { headers: { 'Content-Type': 'application/vnd.tcpdump.pcap' } },
    (error) => {
      if (error && !res.headersSent) next(error);
    }
  );
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
  console.error('[meridian-download] request failed:', error?.code ?? error?.message ?? 'unknown');
  res.status(500).json({ error: 'internal_error' });
});

const server = app.listen(PORT, HOST, () => {
  console.log(`[meridian-download] listening on http://${HOST}:${PORT}`);
});

function shutdown(signal) {
  console.log(`[meridian-download] received ${signal}, shutting down`);
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 2000).unref();
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
