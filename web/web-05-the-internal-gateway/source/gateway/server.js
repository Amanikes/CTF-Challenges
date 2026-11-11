'use strict';

const path = require('node:path');
const express = require('express');

const { integrations, router: integrationsRouter } = require('./routes/integrations');
const { DEFAULT_MAX_BYTES, DEFAULT_TIMEOUT_MS } = require('./lib/fetch-target');

const PORT = Number.parseInt(process.env.PORT ?? '3000', 10);
const HOST = '0.0.0.0';
const INTERFACE = 'console';
const PUBLIC_DIR = path.join(__dirname, '..', 'public');
const STARTED_AT = Date.now();

// The gateway never receives GZCTF_FLAG: the entrypoint injects it into the
// internal service and removes it from its own environment before this process
// starts. Nothing below reads or forwards that variable.
const app = express();

app.disable('x-powered-by');
app.use(express.json({ limit: '16kb' }));

app.use((_req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  res.setHeader(
    'Content-Security-Policy',
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'"
  );
  next();
});

app.get('/health', (_req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.status(200).json({ status: 'ok', service: 'meridian-integration-gateway' });
});

app.get('/api/status', (_req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.json({
    service: 'meridian-integration-gateway',
    interface: INTERFACE,
    version: '5.2.0',
    region: 'eu-west-2',
    environment: 'production',
    uptimeSeconds: Math.round((Date.now() - STARTED_AT) / 1000),
    integrations: {
      total: integrations.length,
      healthy: integrations.filter((i) => i.status === 'healthy').length
    },
    preview: {
      method: 'GET',
      timeoutMs: DEFAULT_TIMEOUT_MS,
      maxResponseBytes: DEFAULT_MAX_BYTES,
      followsRedirects: false
    }
  });
});

app.use('/api/integrations', integrationsRouter);

app.use('/assets', express.static(PUBLIC_DIR, { fallthrough: false, index: false, maxAge: 0 }));

app.get('/', (_req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.sendFile(path.join(PUBLIC_DIR, 'index.html'));
});

app.use((_req, res) => {
  res.status(404).json({ error: 'not_found' });
});

app.use((error, _req, res, _next) => {
  if (error?.type === 'entity.too.large' || error?.status === 413) {
    res.status(413).json({ success: false, error: 'payload_too_large' });
    return;
  }

  if (error?.status === 400) {
    res.status(400).json({ success: false, error: 'invalid_request' });
    return;
  }

  console.error('[meridian-gateway] unhandled request error:', error?.message ?? 'unknown');
  res.status(500).json({ success: false, error: 'internal_error' });
});

const server = app.listen(PORT, HOST, () => {
  console.log(`[meridian-gateway] listening on http://${HOST}:${PORT}`);
});

function shutdown(signal) {
  console.log(`[meridian-gateway] received ${signal}, shutting down`);
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 2000).unref();
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
