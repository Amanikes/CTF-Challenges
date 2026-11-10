'use strict';

const { ACCOUNT_SEEDS, TRANSACTION_SEEDS } = require('./data');

const accounts = new Map();
const transactions = new Map();

for (const seed of ACCOUNT_SEEDS) {
  accounts.set(String(seed.id), structuredClone(seed));
}

for (const [accountId, entries] of Object.entries(TRANSACTION_SEEDS)) {
  transactions.set(accountId, entries.map((entry) => structuredClone(entry)));
}

/**
 * Stores the competition flag on the target account.
 *
 * The flag comes from the platform-provided GZCTF_FLAG environment variable and
 * is only ever held in memory. It is not written to disk, logs or public assets.
 */
function attachCompetitionFlag(flag) {
  const target = accounts.get('1002');

  if (!target) {
    throw new Error('target account 1002 is missing from the seed data');
  }

  target.flag = flag;
}

/**
 * Account lookup used by the account API.
 *
 * NOTE: this is the object-level lookup that the challenge intentionally leaves
 * unauthorized — see the IDOR handlers in server.js.
 */
function findAccount(id) {
  return accounts.get(String(id));
}

function findTransactions(id) {
  return transactions.get(String(id));
}

function accountExists(id) {
  return accounts.has(String(id));
}

module.exports = {
  attachCompetitionFlag,
  findAccount,
  findTransactions,
  accountExists
};
