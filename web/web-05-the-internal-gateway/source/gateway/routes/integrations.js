'use strict';

const express = require('express');

const {
  DEFAULT_MAX_BYTES,
  DEFAULT_TIMEOUT_MS,
  UpstreamError,
  fetchTarget
} = require('../lib/fetch-target');

const MAX_URL_LENGTH = 2048;

/**
 * Connector catalogue. The third entry is the guided discovery hook: the
 * browser cannot reach the loopback endpoint, but the preview request is made
 * by the gateway process, which can.
 */
const integrations = [
  {
    id: 'int-1001',
    name: 'Payments Reconciliation',
    kind: 'outbound',
    endpoint: 'https://payments.meridian.test/v2/status',
    owner: 'Finance Systems',
    status: 'healthy',
    lastCheckedAt: '2026-11-11T04:10:00Z'
  },
  {
    id: 'int-1002',
    name: 'CRM Contact Sync',
    kind: 'outbound',
    endpoint: 'https://crm.meridian.test/api/v1/ping',
    owner: 'Revenue Operations',
    status: 'healthy',
    lastCheckedAt: '2026-11-11T04:10:00Z'
  },
  {
    id: 'int-1003',
    name: 'Local Diagnostics Probe',
    kind: 'internal',
    endpoint: 'http://127.0.0.1:9000/internal/health',
    owner: 'Platform Reliability',
    status: 'client-unreachable',
    lastCheckedAt: '2026-11-11T04:10:00Z',
    notes:
      'Loopback probe for the on-host operations agent. Browsers report ERR_CONNECTION_REFUSED; preview requests are executed by the gateway, not by your browser.'
  },
  {
    id: 'int-1004',
    name: 'Object Storage Health',
    kind: 'outbound',
    endpoint: 'https://storage.meridian.test/healthz',
    owner: 'Platform Reliability',
    status: 'healthy',
    lastCheckedAt: '2026-11-11T04:10:00Z'
  }
];

function parseTarget(rawUrl) {
  if (typeof rawUrl !== 'string' || rawUrl.trim().length === 0) {
    return { error: 'missing_url', message: 'A URL is required.' };
  }

  const candidate = rawUrl.trim();

  if (candidate.length > MAX_URL_LENGTH) {
    return { error: 'url_too_long', message: `URLs are limited to ${MAX_URL_LENGTH} characters.` };
  }

  let parsed;
  try {
    parsed = new URL(candidate);
  } catch {
    return { error: 'invalid_url', message: 'The supplied value is not a valid absolute URL.' };
  }

  if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') {
    return {
      error: 'unsupported_scheme',
      message: 'Only http and https endpoints can be previewed.'
    };
  }

  if (!parsed.hostname) {
    return { error: 'invalid_url', message: 'The supplied URL has no host.' };
  }

  return { target: parsed };
}

const router = express.Router();

router.get('/', (_req, res) => {
  res.setHeader('Cache-Control', 'no-store');
  res.json({
    integrations,
    preview: {
      timeoutMs: DEFAULT_TIMEOUT_MS,
      maxResponseBytes: DEFAULT_MAX_BYTES,
      method: 'GET'
    }
  });
});

router.post('/preview', async (req, res) => {
  const parsed = parseTarget(req.body?.url);

  if (parsed.error) {
    res.status(400).json({ success: false, error: parsed.error, message: parsed.message });
    return;
  }

  try {
    const result = await fetchTarget(parsed.target);

    res.setHeader('Cache-Control', 'no-store');
    res.json({
      success: true,
      target: parsed.target.href,
      status: result.status,
      statusText: result.statusText,
      headers: result.headers,
      body: result.body,
      truncated: result.truncated,
      durationMs: result.durationMs
    });
  } catch (error) {
    if (error instanceof UpstreamError && error.kind === 'timeout') {
      res.status(504).json({
        success: false,
        target: parsed.target.href,
        error: 'timeout',
        message: error.message
      });
      return;
    }

    const payload = {
      success: false,
      target: parsed.target.href,
      error: 'request_failed',
      message: 'The gateway could not complete the upstream request.'
    };

    if (error instanceof UpstreamError && error.code) {
      payload.code = error.code;
    }

    res.status(502).json(payload);
  }
});

module.exports = { router, integrations };
