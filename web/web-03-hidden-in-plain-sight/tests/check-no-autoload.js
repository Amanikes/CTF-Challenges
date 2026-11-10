#!/usr/bin/env node
'use strict';

/**
 * Behavioural check: loading the public bundle must not request the internal
 * preview endpoint. The bundle is evaluated with a stub DOM and a recording
 * fetch, then the recorded URLs are asserted.
 *
 * Usage: node tests/check-no-autoload.js <path-to-app.js>
 */

const path = require('node:path');

const bundle = process.argv[2];

if (!bundle) {
  console.error('usage: node tests/check-no-autoload.js <path-to-app.js>');
  process.exit(2);
}

const fetched = [];

function makeNode() {
  return {
    className: '',
    textContent: '',
    colSpan: 0,
    hidden: false,
    style: {},
    classList: { add() {}, toggle: () => false, contains: () => false },
    append() {},
    appendChild() {},
    replaceChildren() {},
    addEventListener() {},
    querySelectorAll: () => [],
    setAttribute() {}
  };
}

global.document = {
  readyState: 'complete',
  getElementById: () => null,
  querySelector: () => null,
  querySelectorAll: () => [],
  createElement: makeNode,
  addEventListener() {}
};

global.window = { location: { replace() {} } };

global.fetch = (url) => {
  fetched.push(String(url));
  return Promise.resolve({
    ok: true,
    status: 200,
    json: async () => ({ workspace: {}, projects: [] })
  });
};

require(path.resolve(bundle));

setTimeout(() => {
  const internal = fetched.filter((url) => url.includes('/internal/'));

  console.log(JSON.stringify({ fetched, internalRequests: internal }, null, 2));

  if (internal.length > 0) {
    console.error('FAIL: bundle requested an internal endpoint on load');
    process.exit(1);
  }

  process.exit(0);
}, 100);
