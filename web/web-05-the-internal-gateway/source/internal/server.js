'use strict';

const http = require('node:http');

const HOST = '127.0.0.1';
const PORT = Number.parseInt(process.env.INTERNAL_PORT ?? '9000', 10);

// The per-team flag only ever lives inside this process. The entrypoint injects
// it here and removes it from its own environment before starting the gateway.
const FLAG = process.env.GZCTF_FLAG;

if (typeof FLAG !== 'string' || FLAG.trim().length === 0) {
  console.error('[meridian-internal] GZCTF_FLAG is missing or empty; refusing to start');
  process.exit(1);
}

/**
 * INTENTIONAL CTF VULNERABILITY (data side): this restricted record carries the
 * flag and is served to anything that can reach the internal listener. The
 * listener binds 127.0.0.1 only, so it is not published to players.
 */
const diagnosticsRecord = {
  service: 'meridian-internal-diagnostics',
  record: {
    id: 'MD-OPS-204',
    classification: 'RESTRICTED',
    description: 'Internal diagnostics verification record',
    environment: 'meridian-int-01',
    reviewer: 'Platform Reliability',
    reviewedAt: '2026-10-28T04:12:00Z',
    checksum: 'a1c9f0e37b5d4c26',
    verification_token: FLAG
  }
};

const services = {
  host: 'meridian-int-01',
  environment: 'internal',
  services: [
    {
      id: 'gateway-egress',
      name: 'Integration Egress Proxy',
      classification: 'INTERNAL',
      status: 'healthy',
      basePath: '/internal/health'
    },
    {
      id: 'service-catalog',
      name: 'Service Catalog',
      classification: 'INTERNAL',
      status: 'healthy',
      basePath: '/internal/services'
    },
    {
      id: 'diagnostics',
      name: 'Operations Diagnostics',
      classification: 'RESTRICTED',
      status: 'degraded',
      basePath: '/internal/diagnostics',
      capabilities: ['record-export'],
      record: diagnosticsRecord.record.id,
      notes: 'Record export is unauthenticated on the internal network.'
    }
  ]
};

const routes = new Map([
  [
    '/internal/health',
    () => ({
      status: 'ok',
      service: 'meridian-internal-diagnostics',
      uptimeSeconds: Math.round(process.uptime()),
      time: new Date().toISOString()
    })
  ],
  ['/internal/services', () => services],
  ['/internal/diagnostics/record', () => diagnosticsRecord]
]);

function sendJson(res, status, payload) {
  const body = JSON.stringify(payload);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'content-length': Buffer.byteLength(body),
    'cache-control': 'no-store',
    'x-content-type-options': 'nosniff'
  });
  res.end(body);
}

const server = http.createServer((req, res) => {
  const pathname = (req.url ?? '/').split('?')[0].replace(/\/+$/, '') || '/';

  if (req.method !== 'GET') {
    sendJson(res, 405, { error: 'method_not_allowed' });
    return;
  }

  const handler = routes.get(pathname);
  if (!handler) {
    sendJson(res, 404, { error: 'not_found', path: pathname });
    return;
  }

  sendJson(res, 200, handler());
});

server.listen(PORT, HOST, () => {
  console.log(`[meridian-internal] listening on http://${HOST}:${PORT}`);
});

function shutdown(signal) {
  console.log(`[meridian-internal] received ${signal}, shutting down`);
  server.close(() => process.exit(0));
  setTimeout(() => process.exit(0), 2000).unref();
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));
