'use strict';

const path = require('node:path');
const express = require('express');

const { attachCompetitionFlag, findAccount, findTransactions, accountExists } = require('./accounts');
const {
  verifyCredentials,
  createSession,
  getUserFromRequest,
  destroySession,
  sessionCookie,
  clearSessionCookie,
  requireAuth,
  requirePageAuth
} = require('./auth');

const PORT = Number.parseInt(process.env.PORT ?? '3000', 10);
const HOST = '0.0.0.0';
const PUBLIC_DIR = path.join(__dirname, '..', 'public');

// GZ::CTF injects the per-team flag through GZCTF_FLAG. The app refuses to run
// without it instead of serving an incomplete challenge.
const FLAG = process.env.GZCTF_FLAG;
if (typeof FLAG !== 'string' || FLAG.trim().length === 0) {
  console.error('[northstar-bank] GZCTF_FLAG is missing or empty; refusing to start');
  process.exit(1);
}

attachCompetitionFlag(FLAG);

const app = express();

app.disable('x-powered-by');
app.set('trust proxy', 1);

app.use(express.urlencoded({ extended: false, limit: '16kb' }));

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('Referrer-Policy', 'no-referrer');
  next();
});

const PROTECTED_PAGES = new Map([
  ['/dashboard', 'dashboard.html'],
  ['/dashboard.html', 'dashboard.html'],
  ['/account', 'account.html'],
  ['/account.html', 'account.html'],
  ['/transactions', 'transactions.html'],
  ['/transactions.html', 'transactions.html']
]);

app.use((req, res, next) => {
  if (req.path.startsWith('/api/') || PROTECTED_PAGES.has(req.path)) {
    res.setHeader('Cache-Control', 'no-store');
  }
  next();
});

app.get('/', (req, res) => {
  if (getUserFromRequest(req)) return res.redirect(302, '/dashboard');
  res.sendFile(path.join(PUBLIC_DIR, 'index.html'));
});

app.post('/login', (req, res) => {
  const { username, password } = req.body ?? {};

  if (typeof username !== 'string' || typeof password !== 'string' || !username || !password) {
    return res.redirect(303, '/?error=missing');
  }

  const user = verifyCredentials(username, password);

  if (!user) {
    return res.redirect(303, '/?error=invalid');
  }

  const sid = createSession(user);
  const cookie = sessionCookie(req, sid);
  res.cookie(cookie.name, cookie.value, cookie.options);
  res.redirect(303, '/dashboard');
});

app.post('/logout', (req, res) => {
  destroySession(req);
  const cookie = clearSessionCookie(req);
  res.clearCookie(cookie.name, cookie.options);
  res.redirect(303, '/');
});

for (const [route, file] of PROTECTED_PAGES) {
  app.get(route, requirePageAuth, (_req, res) => {
    res.sendFile(path.join(PUBLIC_DIR, file));
  });
}

app.get('/healthz', (_req, res) => {
  res.status(200).json({ status: 'ok', service: 'northstar-bank' });
});

app.get('/api/session', requireAuth, (req, res) => {
  res.json({
    user: {
      username: req.user.username,
      name: req.user.name,
      accountId: req.user.accountId
    }
  });
});

/**
 * INTENTIONAL CTF VULNERABILITY — IDOR / Broken Object-Level Authorization.
 *
 * The route requires an authenticated session (`requireAuth`) but the handler
 * looks the account up directly by the id in the URL and returns it without
 * checking that `req.user.accountId` matches. Any logged-in participant can
 * therefore read any account by changing the id.
 *
 * This is the only intended vulnerability in the challenge. A real application
 * must compare the requested object owner against the authenticated principal.
 */
function getAccountByIdor(req, res) {
  const { id } = req.params;

  if (!/^\d{1,10}$/.test(id) || !accountExists(id)) {
    return res.status(404).json({ error: 'Account not found' });
  }

  res.json(findAccount(id));
}

/**
 * INTENTIONAL CTF VULNERABILITY — same missing object-level check as above.
 * Transactions of any account are readable by any authenticated session.
 */
function getAccountTransactionsByIdor(req, res) {
  const { id } = req.params;

  if (!/^\d{1,10}$/.test(id) || !accountExists(id)) {
    return res.status(404).json({ error: 'Account not found' });
  }

  res.json({
    accountNumber: String(id),
    transactions: findTransactions(id) ?? []
  });
}

app.get('/api/accounts/:id', requireAuth, getAccountByIdor);
app.get('/api/accounts/:id/transactions', requireAuth, getAccountTransactionsByIdor);

app.use(express.static(PUBLIC_DIR, { index: false, dotfiles: 'ignore', extensions: false }));

app.use((req, res) => {
  if (req.path.startsWith('/api/')) {
    return res.status(404).json({ error: 'Not found' });
  }

  res.status(404).type('html').send(`<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Not found — Northstar Bank</title>
<link rel="stylesheet" href="/css/style.css"></head>
<body class="error-page">
  <main class="error-card">
    <p class="error-code">404</p>
    <h1>Page not found</h1>
    <p>The page you requested is not available.</p>
    <a class="btn btn-primary" href="/">Return to sign in</a>
  </main>
</body>
</html>`);
});

app.use((error, _req, res, _next) => {
  console.error('[northstar-bank] request failed:', error.message);
  if (res.headersSent) return;

  if (error.type === 'entity.too.large') {
    return res.status(413).json({ error: 'Request body too large' });
  }

  res.status(500).json({ error: 'Internal server error' });
});

const server = app.listen(PORT, HOST, () => {
  console.log(`[northstar-bank] listening on http://${HOST}:${PORT}`);
});

for (const signal of ['SIGTERM', 'SIGINT']) {
  process.on(signal, () => {
    server.close(() => process.exit(0));
  });
}
