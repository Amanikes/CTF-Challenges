'use strict';

const crypto = require('node:crypto');

const SESSION_COOKIE = 'nbsid';
const SESSION_TTL_MS = 12 * 60 * 60 * 1000;

// The participant credential is published in the challenge description, so it
// is hashed at startup rather than stored in clear text.
const DEMO_PASSWORD = 'Northstar@2026';
const DEMO_SALT = crypto.randomBytes(16);
const DEMO_HASH = crypto.scryptSync(DEMO_PASSWORD, DEMO_SALT, 32);

const USERS = new Map([
  [
    'alex',
    {
      id: 'u-1001',
      username: 'alex',
      name: 'Alex Morgan',
      accountId: '1001',
      salt: DEMO_SALT,
      hash: DEMO_HASH
    }
  ]
]);

/**
 * In-memory session store.
 *
 * A single-process, in-memory store is sufficient for this isolated challenge
 * container: sessions do not need to survive a restart, and every team gets its
 * own instance. It is not suitable for a multi-replica production deployment
 * (sessions would be lost on restart and not shared between replicas).
 */
const sessions = new Map();

const sweeper = setInterval(() => {
  const now = Date.now();
  for (const [sid, session] of sessions) {
    if (session.expiresAt <= now) sessions.delete(sid);
  }
}, 10 * 60 * 1000);
sweeper.unref();

function parseCookies(header) {
  const cookies = new Map();

  if (!header) return cookies;

  for (const part of header.split(';')) {
    const index = part.indexOf('=');
    if (index === -1) continue;
    const name = part.slice(0, index).trim();
    const value = part.slice(index + 1).trim();
    if (name) cookies.set(name, decodeURIComponent(value));
  }

  return cookies;
}

function verifyCredentials(username, password) {
  const user = USERS.get(String(username ?? '').trim().toLowerCase());

  if (!user) {
    // Perform the same expensive derivation for unknown users so the response
    // time does not reveal whether the username exists.
    crypto.scryptSync(String(password ?? ''), DEMO_SALT, 32);
    return null;
  }

  const candidate = crypto.scryptSync(String(password ?? ''), user.salt, 32);
  return crypto.timingSafeEqual(candidate, user.hash) ? user : null;
}

function createSession(user) {
  // A fresh session id is issued on every login (no session fixation).
  const sid = crypto.randomBytes(32).toString('base64url');
  const now = Date.now();

  sessions.set(sid, {
    userId: user.id,
    username: user.username,
    createdAt: now,
    expiresAt: now + SESSION_TTL_MS
  });

  return sid;
}

function getUserFromRequest(req) {
  const sid = parseCookies(req.headers.cookie).get(SESSION_COOKIE);
  if (!sid) return null;

  const session = sessions.get(sid);
  if (!session) return null;

  if (session.expiresAt <= Date.now()) {
    sessions.delete(sid);
    return null;
  }

  const user = USERS.get(session.username);

  return { id: session.userId, username: session.username, name: user.name, accountId: user.accountId };
}

function destroySession(req) {
  const sid = parseCookies(req.headers.cookie).get(SESSION_COOKIE);
  if (sid) sessions.delete(sid);
}

function sessionCookie(req, sid) {
  return {
    name: SESSION_COOKIE,
    value: sid,
    options: {
      httpOnly: true,
      sameSite: 'lax',
      path: '/',
      secure: req.secure,
      maxAge: SESSION_TTL_MS
    }
  };
}

function clearSessionCookie(req) {
  return {
    name: SESSION_COOKIE,
    options: {
      httpOnly: true,
      sameSite: 'lax',
      path: '/',
      secure: req.secure
    }
  };
}

function requireAuth(req, res, next) {
  const user = getUserFromRequest(req);

  if (!user) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  req.user = user;
  next();
}

function requirePageAuth(req, res, next) {
  const user = getUserFromRequest(req);

  if (!user) {
    return res.redirect(302, '/');
  }

  req.user = user;
  next();
}

module.exports = {
  verifyCredentials,
  createSession,
  getUserFromRequest,
  destroySession,
  sessionCookie,
  clearSessionCookie,
  requireAuth,
  requirePageAuth
};
