'use strict';

/**
 * Static seed data for the Northstar Bank portal.
 *
 * Everything here is fictional. The competition flag is deliberately absent:
 * it is injected at startup into account 1002 by accounts.attachCompetitionFlag().
 */

const ACCOUNT_SEEDS = [
  {
    id: 1001,
    accountNumber: '1001',
    customer: {
      name: 'Alex Morgan',
      email: 'alex@example.test',
      phone: '+1 (415) 555-0142',
      address: '118 Harbour Street, San Francisco, CA 94105',
      customerSince: '2019-03-14'
    },
    type: 'Everyday Checking',
    currency: 'USD',
    balance: 8432.17,
    availableBalance: 8182.17,
    status: 'Active',
    openedAt: '2019-03-14',
    branch: 'Market Street Branch',
    iban: 'NB-1001-8842-0175',
    card: { network: 'Northstar Debit', last4: '4417', expires: '09/29' }
  },
  {
    id: 1002,
    accountNumber: '1002',
    customer: {
      name: 'Jordan Lee',
      email: 'jordan@example.test',
      phone: '+1 (212) 555-0188',
      address: '900 Park Avenue, New York, NY 10021',
      customerSince: '2014-08-02'
    },
    type: 'Private Banking',
    currency: 'USD',
    balance: 1284905.6,
    availableBalance: 1279905.6,
    status: 'Active',
    openedAt: '2014-08-02',
    branch: 'Northstar Private Office',
    iban: 'NB-1002-7731-0094',
    card: { network: 'Northstar Signature', last4: '8802', expires: '04/28' }
  }
];

const TRANSACTION_SEEDS = {
  1001: [
    { id: 'TX-1001-0005', date: '2026-11-08', description: 'Whole Foods Market', category: 'Groceries', amount: -58.32, balanceAfter: 8432.17 },
    { id: 'TX-1001-0004', date: '2026-11-07', description: 'Meridian Design Studio — payroll', category: 'Income', amount: 3420.0, balanceAfter: 8490.49 },
    { id: 'TX-1001-0003', date: '2026-11-06', description: 'Metro Transit', category: 'Transport', amount: -2.75, balanceAfter: 5070.49 },
    { id: 'TX-1001-0002', date: '2026-11-04', description: 'Northstar Bank — interest', category: 'Income', amount: 1.12, balanceAfter: 5073.24 },
    { id: 'TX-1001-0001', date: '2026-11-02', description: 'Cloud Nine Coffee', category: 'Dining', amount: -4.9, balanceAfter: 5072.12 }
  ],
  1002: [
    { id: 'TX-1002-0005', date: '2026-11-09', description: 'Private wealth transfer — in', category: 'Transfer', amount: 250000.0, balanceAfter: 1284905.6 },
    { id: 'TX-1002-0004', date: '2026-11-08', description: 'Geneva Family Office', category: 'Advisory', amount: -12500.0, balanceAfter: 1034905.6 },
    { id: 'TX-1002-0003', date: '2026-11-06', description: 'Harbor Trust — dividend', category: 'Income', amount: 8940.25, balanceAfter: 1047405.6 },
    { id: 'TX-1002-0002', date: '2026-11-03', description: 'Kessler Gallery — acquisition', category: 'Investments', amount: -95000.0, balanceAfter: 1038465.35 },
    { id: 'TX-1002-0001', date: '2026-11-01', description: 'Quarterly advisory fee', category: 'Fees', amount: -1250.0, balanceAfter: 1133465.35 }
  ]
};

module.exports = { ACCOUNT_SEEDS, TRANSACTION_SEEDS };
