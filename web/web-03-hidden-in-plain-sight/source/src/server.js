'use strict';

const path = require('node:path');
const express = require('express');

const { workspace } = require('./data');

const PORT = Number.parseInt(process.env.PORT ?? '3000', 10);
const HOST = '0.0.0.0';
const PUBLIC_DIR = path.join(__dirname, '..', 'public');

// GZ::CTF injects the per-team flag through GZCTF_FLAG. The portal refuses to
// start without it rather than serving a challenge that can never be solved.
const FLAG = process.env.GZCTF_FLAG;
if (typeof FLAG !== 'string' || FLAG.trim().length === 0) {
  console.error('[meridian-portal] GZCTF_FLAG is missing or empty; refusing to start');
  process.exit(1);
}

/**
 * Internal project record.
 *
 * INTENTIONAL CTF VULNERABILITY: this record is exposed by the undocumented
 * endpoint below. It is held in server memory only and never appears in the
 * dashboard, the JavaScript bundle or any static asset.
 */
const internalProject = {
  project: {
    name: 'Orion Internal Platform',
    code: 'ORION',
    classification: 'Internal Development',
    status: 'Pre-release',
    owner: 'Platform Engineering',
    sponsor: 'Office of the CTO',
    environment: 'staging-eu-west',
    milestone: '2027-Q1 general availability',
    steeringGroup: ['Priya Raman', 'Tomas Berg', 'Marta Kowalski'],
    notes: 'Internal preview data exposed during deployment.'
  },
  flag: FLAG
};

const app = express();

app.disable('x-powered-by');

app.use((_req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('Referrer-Policy', 'no-referrer');
  next();
});

app.get('/health', (_req, res) => {
  res.status(200).json({ status: 'ok', service: 'meridian-portal' });
});

app.get('/api/projects', (_req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.json({
    workspace: {
      organization: workspace.organization,
      name: workspace.workspace
    },
    projects: workspace.projects
  });
});

/**
 * INTENTIONAL CTF VULNERABILITY — client-side information disclosure.
 *
 * The public JavaScript bundle still references this internal preview route,
 * so it is discoverable through browser DevTools even though the dashboard
 * never calls it. The endpoint has no authentication and returns the internal
 * project record together with the per-team flag.
 *
 * A real service must not rely on an undocumented URL for protection: internal
 * endpoints need server-side authorization and must not return sensitive data.
 */
app.get('/api/internal/project-preview', (_req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.json(internalProject);
});

app.use(
  express.static(PUBLIC_DIR, {
    index: 'index.html',
    dotfiles: 'ignore',
    extensions: false,
    setHeaders(res, filePath) {
      if (filePath.endsWith('.js') || filePath.endsWith('.css') || filePath.endsWith('.html')) {
        res.setHeader('Cache-Control', 'no-cache');
      }
    }
  })
);

app.use((req, res) => {
  if (req.path.startsWith('/api/')) {
    return res.status(404).json({ error: 'Not found' });
  }

  res.status(404).type('html').send(`<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Not found — Meridian</title>
<link rel="stylesheet" href="/assets/style.css"></head>
<body class="error-page">
  <main class="error-card">
    <p class="error-code">404</p>
    <h1>Page not found</h1>
    <p>The page you requested is not part of this workspace.</p>
    <a class="btn btn-primary" href="/">Back to the dashboard</a>
  </main>
</body>
</html>`);
});

app.use((error, _req, res, _next) => {
  console.error('[meridian-portal] request failed:', error.message);
  if (res.headersSent) return;
  res.status(500).json({ error: 'Internal server error' });
});

const server = app.listen(PORT, HOST, () => {
  console.log(`[meridian-portal] listening on http://${HOST}:${PORT}`);
});

for (const signal of ['SIGTERM', 'SIGINT']) {
  process.on(signal, () => {
    server.close(() => process.exit(0));
  });
}
