'use strict';

const state = { user: null };

function byId(id) {
  return document.getElementById(id);
}

function setText(id, value) {
  const element = byId(id);
  if (element) element.textContent = value == null || value === '' ? '—' : String(value);
}

async function getJSON(url) {
  const response = await fetch(url, {
    headers: { Accept: 'application/json' },
    credentials: 'same-origin'
  });

  if (response.status === 401) {
    window.location.replace('/');
    throw new Error('unauthorized');
  }

  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body.error || `Request failed (${response.status})`);
  }

  return response.json();
}

const money = (value, currency = 'USD') =>
  new Intl.NumberFormat('en-US', { style: 'currency', currency }).format(Number(value) || 0);

function formatDate(isoDate) {
  if (!isoDate) return '—';
  const date = new Date(`${isoDate}T00:00:00Z`);
  if (Number.isNaN(date.getTime())) return isoDate;
  return new Intl.DateTimeFormat('en-US', {
    month: 'short',
    day: '2-digit',
    year: 'numeric',
    timeZone: 'UTC'
  }).format(date);
}

function formatDateTime(isoDate) {
  if (!isoDate) return '—';
  const date = new Date(isoDate);
  if (Number.isNaN(date.getTime())) return isoDate;
  return new Intl.DateTimeFormat('en-US', {
    month: 'short',
    day: '2-digit',
    year: 'numeric',
    timeZone: 'UTC'
  }).format(date);
}

function showPageError(message) {
  const banner = byId('page-error');
  if (!banner) return;
  banner.textContent = message;
  banner.hidden = false;
}

function amountCell(value, currency) {
  const cell = document.createElement('td');
  cell.className = `align-right amount ${Number(value) < 0 ? 'negative' : 'positive'}`;
  cell.textContent = money(value, currency);
  return cell;
}

function textCell(value, className) {
  const cell = document.createElement('td');
  if (className) cell.className = className;
  cell.textContent = value;
  return cell;
}

function initLogin() {
  const params = new URLSearchParams(window.location.search);
  const error = params.get('error');
  const banner = byId('login-error');

  if (error && banner) {
    banner.textContent =
      error === 'missing'
        ? 'Enter both your username and password.'
        : 'We could not verify those credentials. Please try again.';
    banner.hidden = false;
    byId('username')?.focus();
  }

  const toggle = byId('toggle-password');
  const password = byId('password');

  if (toggle && password) {
    toggle.addEventListener('click', () => {
      const visible = password.type === 'text';
      password.type = visible ? 'password' : 'text';
      toggle.textContent = visible ? 'Show' : 'Hide';
      toggle.setAttribute('aria-label', visible ? 'Show password' : 'Hide password');
      password.focus();
    });
  }
}

function initNavigation() {
  const burger = byId('nav-burger');
  const nav = byId('app-nav');

  if (!burger || !nav) return;

  burger.addEventListener('click', () => {
    const open = nav.classList.toggle('open');
    burger.setAttribute('aria-expanded', String(open));
  });
}

async function loadSession() {
  state.user = (await getJSON('/api/session')).user;
  setText('nav-user-name', state.user.name || state.user.username);
  return state.user;
}

async function loadAccount(accountId) {
  return getJSON(`/api/accounts/${encodeURIComponent(accountId)}`);
}

async function loadTransactions(accountId) {
  return getJSON(`/api/accounts/${encodeURIComponent(accountId)}/transactions`);
}

function renderRecentTransactions(transactions, currency) {
  const tbody = byId('recent-transactions');
  if (!tbody) return;

  tbody.replaceChildren();

  if (!transactions.length) {
    const row = document.createElement('tr');
    row.className = 'empty-row';
    const cell = textCell('No recent transactions.');
    cell.colSpan = 3;
    row.append(cell);
    tbody.append(row);
    return;
  }

  for (const transaction of transactions) {
    const row = document.createElement('tr');
    row.append(
      textCell(formatDate(transaction.date), 'nowrap muted'),
      textCell(transaction.description),
      amountCell(transaction.amount, currency)
    );
    tbody.append(row);
  }
}

async function initDashboard() {
  const user = await loadSession();
  setText('nav-user-name', user.name || user.username);
  setText('welcome-name', String(user.name || user.username).split(' ')[0]);

  const [account, history] = await Promise.all([loadAccount(user.accountId), loadTransactions(user.accountId)]);

  setText('account-type', account.type);
  setText('account-status', account.status);
  setText('account-balance', money(account.balance, account.currency));
  setText('account-number', account.accountNumber);
  setText('account-available', money(account.availableBalance, account.currency));
  setText('dashboard-subtitle', `${account.type} · ${account.branch}`);

  renderRecentTransactions((history.transactions || []).slice(0, 5), account.currency);
}

async function initAccountPage() {
  const user = await loadSession();
  const account = await loadAccount(user.accountId);

  setText('account-status', account.status);
  setText('detail-name', account.customer.name);
  setText('detail-email', account.customer.email);
  setText('detail-phone', account.customer.phone);
  setText('detail-address', account.customer.address);
  setText('detail-customer-since', formatDate(account.customer.customerSince));
  setText('detail-account-number', account.accountNumber);
  setText('detail-type', account.type);
  setText('detail-iban', account.iban);
  setText('detail-branch', account.branch);
  setText('detail-opened', formatDate(account.openedAt));
  setText('detail-currency', account.currency);
  setText('detail-balance', money(account.balance, account.currency));
  setText('detail-available', money(account.availableBalance, account.currency));
  setText('detail-card', `${account.card.network} ···· ${account.card.last4} (exp ${account.card.expires})`);
}

async function initTransactionsPage() {
  const user = await loadSession();
  const [account, history] = await Promise.all([loadAccount(user.accountId), loadTransactions(user.accountId)]);

  setText('transactions-account', account.accountNumber);
  setText('transactions-count', `${(history.transactions || []).length} posted`);

  const tbody = byId('transactions-body');
  if (!tbody) return;
  tbody.replaceChildren();

  const transactions = history.transactions || [];

  if (!transactions.length) {
    const row = document.createElement('tr');
    row.className = 'empty-row';
    const cell = textCell('No transactions on this account.');
    cell.colSpan = 5;
    row.append(cell);
    tbody.append(row);
    return;
  }

  for (const transaction of transactions) {
    const row = document.createElement('tr');
    row.append(
      textCell(formatDate(transaction.date), 'nowrap muted'),
      textCell(transaction.description),
      textCell(transaction.category, 'muted'),
      amountCell(transaction.amount, account.currency),
      textCell(money(transaction.balanceAfter, account.currency), 'align-right nowrap')
    );
    tbody.append(row);
  }
}

async function boot() {
  const page = document.body.dataset.page;

  if (page === 'login') {
    initLogin();
    return;
  }

  initNavigation();

  try {
    if (page === 'dashboard') await initDashboard();
    else if (page === 'account') await initAccountPage();
    else if (page === 'transactions') await initTransactionsPage();
  } catch (error) {
    if (error.message === 'unauthorized') return;
    showPageError(error.message || 'Unable to load account information.');
  }
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', boot);
} else {
  boot();
}
