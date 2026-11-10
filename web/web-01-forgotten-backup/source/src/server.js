'use strict';

const path = require('node:path');
const fs = require('node:fs');
const express = require('express');

const PORT = Number.parseInt(process.env.PORT ?? '3000', 10);
const HOST = '0.0.0.0';
const PUBLIC_DIR = path.join(__dirname, '..', 'public');
const BACKUP_DIR = path.resolve(process.env.BACKUP_DIR ?? path.join(__dirname, '..', 'runtime', 'backups'));

const app = express();

app.disable('x-powered-by');
app.set('etag', 'strong');
app.set('strict routing', true);

app.get('/healthz', (_req, res) => {
  res.status(200).json({ status: 'ok', service: 'northstar-web' });
});

app.get('/backups', (_req, res) => res.redirect(308, '/backups/'));

app.get('/backups/', async (_req, res, next) => {
  try {
    const entries = await fs.promises.readdir(BACKUP_DIR, { withFileTypes: true });
    const files = [];

    for (const entry of entries) {
      if (!entry.isFile() || entry.name.startsWith('.')) continue;

      const stats = await fs.promises.stat(path.join(BACKUP_DIR, entry.name));
      files.push({
        name: entry.name,
        size: stats.size,
        modified: stats.mtime.toISOString().replace('T', ' ').slice(0, 19)
      });
    }

    files.sort((a, b) => a.name.localeCompare(b.name));
    res.type('html').send(renderListing(files));
  } catch (error) {
    next(error);
  }
});

app.get('/backups/:name', (req, res, next) => {
  const name = req.params.name;

  // Serve only plain files from the backup directory; reject anything that looks like a path.
  if (!/^[A-Za-z0-9._-]+$/.test(name) || name.startsWith('.')) {
    return res.status(404).type('html').send(renderNotFound());
  }

  const absolute = path.join(BACKUP_DIR, name);
  if (path.dirname(absolute) !== BACKUP_DIR) {
    return res.status(404).type('html').send(renderNotFound());
  }

  res.download(absolute, name, (error) => {
    if (!error) return;
    if (res.headersSent) return next(error);
    if (error.code === 'ENOENT' || error.code === 'EISDIR') {
      return res.status(404).type('html').send(renderNotFound());
    }
    next(error);
  });
});

app.use(express.static(PUBLIC_DIR, { index: 'index.html', dotfiles: 'ignore', redirect: true }));

app.use((_req, res) => {
  res.status(404).type('html').send(renderNotFound());
});

app.use((error, _req, res, _next) => {
  console.error('[northstar-web] request failed:', error.message);
  if (res.headersSent) return;
  res.status(500).type('html').send(renderError());
});

function escapeHtml(value) {
  return String(value)
    .replaceAll('&', '&amp;')
    .replaceAll('<', '&lt;')
    .replaceAll('>', '&gt;')
    .replaceAll('"', '&quot;')
    .replaceAll("'", '&#39;');
}

function formatSize(bytes) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KiB`;
  return `${(bytes / (1024 * 1024)).toFixed(1)} MiB`;
}

function renderListing(files) {
  const rows = files
    .map(
      (file) => `      <tr>
        <td><a href="/backups/${encodeURIComponent(file.name)}">${escapeHtml(file.name)}</a></td>
        <td class="num">${formatSize(file.size)}</td>
        <td class="num">${escapeHtml(file.modified)}</td>
      </tr>`
    )
    .join('\n');

  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Index of /backups/</title>
<style>
  :root { color-scheme: dark; }
  body { margin: 0; padding: 48px 24px; background: #05080f; color: #e8edf7;
         font: 15px/1.6 "SFMono-Regular", Consolas, "Liberation Mono", Menlo, monospace; }
  .container { width: min(820px, 100%); margin: 0 auto; }
  h1 { font-size: 18px; font-weight: 600; margin: 0 0 6px; }
  p.meta { margin: 0 0 28px; color: #64748b; font-size: 13px; }
  table { width: 100%; border-collapse: collapse; }
  th, td { text-align: left; padding: 10px 12px; border-bottom: 1px solid rgba(148, 163, 184, 0.14); }
  th { font-size: 12px; letter-spacing: 0.08em; text-transform: uppercase; color: #64748b; }
  td.num { text-align: right; color: #93a1b8; white-space: nowrap; }
  a { color: #e8edf7; text-decoration: none; border-bottom: 1px solid rgba(229, 72, 77, 0.5); }
  a:hover { color: #e5484d; }
  tr:hover td { background: rgba(148, 163, 184, 0.04); }
</style>
</head>
<body>
  <div class="container">
    <h1>Index of /backups/</h1>
    <p class="meta">Northstar Systems &middot; operations archive</p>
    <table>
      <thead>
        <tr><th>Name</th><th class="num">Size</th><th class="num">Last modified</th></tr>
      </thead>
      <tbody>
${rows}
      </tbody>
    </table>
  </div>
</body>
</html>`;
}

function renderNotFound() {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Not found — Northstar Systems</title>
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<style>
  body { margin: 0; min-height: 100vh; display: grid; place-items: center;
         background: #05080f; color: #e8edf7;
         font-family: "Segoe UI", system-ui, -apple-system, sans-serif; }
  main { text-align: center; padding: 24px; }
  p.code { margin: 0; font-size: 12px; letter-spacing: 0.24em; color: #e5484d; text-transform: uppercase; }
  h1 { font-size: 34px; margin: 14px 0 10px; letter-spacing: -0.02em; }
  p.msg { margin: 0 0 26px; color: #93a1b8; }
  a { color: #e8edf7; border-bottom: 1px solid rgba(229, 72, 77, 0.6); text-decoration: none; }
</style>
</head>
<body>
  <main>
    <p class="code">404</p>
    <h1>Page not found</h1>
    <p class="msg">The resource you requested is not available on this server.</p>
    <a href="/">Return to northstar-systems.example</a>
  </main>
</body>
</html>`;
}

function renderError() {
  return `<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Server error — Northstar Systems</title></head>
<body style="background:#05080f;color:#e8edf7;font-family:system-ui,sans-serif;padding:64px">
  <h1 style="font-size:28px;margin:0 0 12px">503 &middot; Service unavailable</h1>
  <p style="color:#93a1b8;margin:0">The request could not be completed. Please try again shortly.</p>
</body>
</html>`;
}

const server = app.listen(PORT, HOST, () => {
  console.log(`[northstar-web] listening on http://${HOST}:${PORT}`);
});

for (const signal of ['SIGTERM', 'SIGINT']) {
  process.on(signal, () => {
    server.close(() => process.exit(0));
  });
}
