'use strict';

const DEFAULT_TIMEOUT_MS = 3000;
const DEFAULT_MAX_BYTES = 64 * 1024;

// Only these upstream headers are relayed to the browser. Everything else is
// dropped so set-cookie style headers never travel through the preview.
const RELAYED_HEADERS = new Set([
  'content-type',
  'content-length',
  'content-encoding',
  'cache-control',
  'date',
  'etag',
  'last-modified',
  'server',
  'x-content-type-options',
  'x-request-id'
]);

const SAFE_SOCKET_CODES = new Set([
  'ECONNREFUSED',
  'ECONNRESET',
  'EHOSTUNREACH',
  'ENETUNREACH',
  'ENOTFOUND',
  'EAI_AGAIN',
  'ETIMEDOUT',
  'EPIPE',
  'CERT_HAS_EXPIRED',
  'DEPTH_ZERO_SELF_SIGNED_CERT',
  'ERR_INVALID_URL',
  'UND_ERR_CONNECT_TIMEOUT',
  'UND_ERR_SOCKET'
]);

function relayHeaders(headers) {
  const relayed = {};
  for (const [name, value] of headers.entries()) {
    if (RELAYED_HEADERS.has(name.toLowerCase())) {
      relayed[name.toLowerCase()] = value;
    }
  }
  return relayed;
}

class UpstreamError extends Error {
  constructor(kind, message, code) {
    super(message);
    this.kind = kind;
    this.code = code;
  }
}

async function readCapped(response, maxBytes) {
  if (!response.body) {
    return { text: '', truncated: false };
  }

  const reader = response.body.getReader();
  const chunks = [];
  let received = 0;
  let truncated = false;

  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;

    if (received + value.length > maxBytes) {
      chunks.push(value.subarray(0, maxBytes - received));
      received = maxBytes;
      truncated = true;
      await reader.cancel();
      break;
    }

    chunks.push(value);
    received += value.length;
  }

  return { text: Buffer.concat(chunks).toString('utf8'), truncated };
}

/**
 * Performs the outbound preview request.
 *
 * INTENTIONAL CTF VULNERABILITY: `target` is used verbatim as the request
 * destination. There is no destination allowlist and no block on loopback,
 * private ranges or internal hostnames, which is what makes the preview a
 * response-based SSRF primitive. The restrictions below only bound the damage
 * to this isolated container: GET only, http/https only, short timeout,
 * capped response size and no redirect following.
 */
async function fetchTarget(target, options = {}) {
  const timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const maxBytes = options.maxBytes ?? DEFAULT_MAX_BYTES;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  const startedAt = process.hrtime.bigint();

  try {
    const response = await fetch(target.href, {
      method: 'GET',
      redirect: 'manual',
      signal: controller.signal,
      headers: {
        accept: '*/*',
        'user-agent': 'Meridian-Integration-Console/5.2 (+endpoint-preview)'
      }
    });

    const { text, truncated } = await readCapped(response, maxBytes);

    return {
      status: response.status,
      statusText: response.statusText,
      headers: relayHeaders(response.headers),
      body: text,
      truncated,
      durationMs: elapsedMs(startedAt)
    };
  } catch (error) {
    if (controller.signal.aborted) {
      throw new UpstreamError(
        'timeout',
        `The upstream request exceeded the ${timeoutMs} ms gateway timeout.`
      );
    }

    const code = error?.cause?.code ?? error?.code;
    throw new UpstreamError(
      'request_failed',
      'The gateway could not complete the upstream request.',
      SAFE_SOCKET_CODES.has(code) ? code : undefined
    );
  } finally {
    clearTimeout(timer);
  }
}

function elapsedMs(startedAt) {
  return Number((process.hrtime.bigint() - startedAt) / 1000000n);
}

module.exports = {
  DEFAULT_TIMEOUT_MS,
  DEFAULT_MAX_BYTES,
  UpstreamError,
  fetchTarget,
  relayHeaders
};
