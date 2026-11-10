'use strict';

/*
 * Meridian portal — dashboard runtime.
 *
 * The internal preview client is kept in this bundle for the internal build but
 * is disabled for the public rollout.
 */

const applicationConfig = {
  apiBase: '/api',
  build: '3.1.0',
  features: {
    projectOverview: true,
    taskBoard: true,
    activityFeed: true,
    internalPreview: false
  },
  internalPreview: '/api/internal/project-preview'
};

const state = {
  projects: [],
  loadedAt: null
};

function byId(id) {
  return document.getElementById(id);
}

function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text != null) node.textContent = text;
  return node;
}

async function getJSON(url) {
  const response = await fetch(url, {
    headers: { Accept: 'application/json' },
    credentials: 'same-origin'
  });

  if (!response.ok) {
    throw new Error(`Request to ${url} failed with ${response.status}`);
  }

  return response.json();
}

function formatDate(isoDate) {
  if (!isoDate) return '—';
  const date = new Date(`${isoDate}T00:00:00Z`);
  if (Number.isNaN(date.getTime())) return isoDate;
  return new Intl.DateTimeFormat('en-GB', {
    day: '2-digit',
    month: 'short',
    year: 'numeric',
    timeZone: 'UTC'
  }).format(date);
}

function healthLabel(health) {
  if (health === 'at-risk') return 'At risk';
  if (health === 'off-track') return 'Off track';
  return 'On track';
}

function renderProjectRow(project) {
  const row = el('tr');

  const nameCell = el('td');
  const nameWrap = el('div', 'project-cell');
  nameWrap.append(el('span', `project-code code-${project.code.toLowerCase()}`, project.code));
  const nameBlock = el('div');
  nameBlock.append(el('span', 'project-name', project.name));
  nameBlock.append(el('span', 'project-desc', project.description));
  nameWrap.append(nameBlock);
  nameCell.append(nameWrap);

  const ownerCell = el('td', 'nowrap');
  ownerCell.append(el('span', 'owner-name', project.lead));
  ownerCell.append(el('span', 'owner-team', project.owner));

  const progressCell = el('td');
  const progress = el('div', 'progress');
  const bar = el('span', 'progress-bar');
  bar.style.width = `${project.progress}%`;
  if (project.health === 'at-risk') bar.classList.add('warn');
  progress.append(bar);
  const progressWrap = el('div', 'progress-wrap');
  progressWrap.append(progress, el('span', 'progress-value', `${project.progress}%`));
  progressCell.append(progressWrap);

  const dueCell = el('td', 'nowrap muted', formatDate(project.due));

  const statusCell = el('td');
  const status = el('span', `status status-${project.health}`);
  status.append(el('span', 'status-dot'), document.createTextNode(healthLabel(project.health)));
  statusCell.append(status);

  row.append(nameCell, ownerCell, progressCell, dueCell, statusCell);
  return row;
}

function renderProjects() {
  const tbody = byId('projects-body');
  if (!tbody) return;

  tbody.replaceChildren();

  if (!state.projects.length) {
    const row = el('tr', 'empty-row');
    const cell = el('td', null, 'No projects in this workspace.');
    cell.colSpan = 5;
    row.append(cell);
    tbody.append(row);
    return;
  }

  for (const project of state.projects) {
    tbody.append(renderProjectRow(project));
  }
}

async function loadPortfolio() {
  const payload = await getJSON(`${applicationConfig.apiBase}/projects`);
  state.projects = Array.isArray(payload.projects) ? payload.projects : [];
  state.loadedAt = new Date();
  renderProjects();
}

/*
 * Internal preview client.
 *
 * Used by the internal build to render a project record before it is published
 * to the portfolio. It is not part of the public rollout: the feature switch is
 * off in this bundle and nothing calls it on page load.
 */
async function loadInternalProjectPreview() {
  const response = await fetch(applicationConfig.internalPreview, {
    headers: { Accept: 'application/json' },
    credentials: 'same-origin'
  });

  if (!response.ok) {
    throw new Error(`Preview request failed with ${response.status}`);
  }

  return response.json();
}

function initNavigation() {
  const button = byId('menu-btn');
  const sidebar = byId('sidebar');

  if (!button || !sidebar) return;

  button.addEventListener('click', () => {
    const open = sidebar.classList.toggle('open');
    button.setAttribute('aria-expanded', String(open));
  });

  sidebar.addEventListener('click', (event) => {
    if (event.target.closest('a') && sidebar.classList.contains('open')) {
      sidebar.classList.remove('open');
      button.setAttribute('aria-expanded', 'false');
    }
  });
}

function initSearch() {
  const input = document.querySelector('.search input');
  if (!input) return;

  input.addEventListener('input', () => {
    const term = input.value.trim().toLowerCase();
    const tbody = byId('projects-body');
    if (!tbody) return;

    for (const row of tbody.querySelectorAll('tr')) {
      if (row.classList.contains('empty-row')) continue;
      row.hidden = Boolean(term) && !row.textContent.toLowerCase().includes(term);
    }
  });
}

async function boot() {
  initNavigation();
  initSearch();

  try {
    await loadPortfolio();
  } catch (error) {
    console.error('[meridian] portfolio could not be loaded:', error.message);
    const tbody = byId('projects-body');
    if (tbody) {
      tbody.replaceChildren();
      const row = el('tr', 'empty-row');
      const cell = el('td', null, 'The portfolio is temporarily unavailable.');
      cell.colSpan = 5;
      row.append(cell);
      tbody.append(row);
    }
  }

  if (applicationConfig.features.internalPreview) {
    loadInternalProjectPreview().catch(() => {});
  }
}

if (document.readyState === 'loading') {
  document.addEventListener('DOMContentLoaded', boot);
} else {
  boot();
}
