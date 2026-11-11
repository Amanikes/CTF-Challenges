'use strict';

// Test-only upstream used by tests/run-local-docker-tests.sh.
// It runs in a throwaway container next to the challenge container so the
// gateway has a deterministic, network-local destination to preview.
const http = require('node:http');

const PORT = Number.parseInt(process.env.PORT ?? '9100', 10);
const LARGE_BYTES = 200 * 1024;

const server = http.createServer((req, res) => {
  const pathname = (req.url ?? '/').split('?')[0];

  switch (pathname) {
    case '/ok': {
      const body = JSON.stringify({ status: 'ok', upstream: 'fixture' });
      res.writeHead(200, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(body) });
      res.end(body);
      return;
    }

    case '/redirect': {
      res.writeHead(302, {
        location: 'http://127.0.0.1:9000/internal/diagnostics/record',
        'content-type': 'text/plain'
      });
      res.end('redirecting');
      return;
    }

    case '/large': {
      const body = 'A'.repeat(LARGE_BYTES);
      res.writeHead(200, { 'content-type': 'text/plain', 'content-length': Buffer.byteLength(body) });
      res.end(body);
      return;
    }

    case '/slow': {
      setTimeout(() => {
        res.writeHead(200, { 'content-type': 'text/plain' });
        res.end('too late');
      }, 6000);
      return;
    }

    case '/html': {
      const body = '<html><body><script>alert("xss")</script><h1>fixture</h1></body></html>';
      res.writeHead(200, { 'content-type': 'text/html' });
      res.end(body);
      return;
    }

    case '/headers': {
      const body = JSON.stringify({ status: 'ok' });
      res.writeHead(200, {
        'content-type': 'application/json',
        'content-length': Buffer.byteLength(body),
        'set-cookie': 'session=leaked; HttpOnly',
        'x-request-id': 'fixture-request',
        'x-secret-debug': 'should-not-be-relayed'
      });
      res.end(body);
      return;
    }

    default: {
      res.writeHead(404, { 'content-type': 'application/json' });
      res.end(JSON.stringify({ error: 'not_found' }));
    }
  }
});

server.listen(PORT, '0.0.0.0', () => {
  console.log(`[fixture-upstream] listening on ${PORT}`);
});
