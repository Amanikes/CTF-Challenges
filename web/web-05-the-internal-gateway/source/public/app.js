'use strict';

/**
 * Meridian Integration Console client.
 *
 * Everything returned by the gateway (including upstream response bodies) is
 * rendered with textContent / createElement so that previewed HTML is shown as
 * text and never interpreted.
 */
(() => {
  const MAX_HISTORY = 8;
  const history = [];

  const el = {
    gatewayChip: document.getElementById('gateway-chip'),
    clock: document.getElementById('clock'),
    integrationsCount: document.getElementById('metric-integrations'),
    integrationsNote: document.getElementById('metric-integrations-note'),
    uptime: document.getElementById('metric-uptime'),
    timeout: document.getElementById('metric-timeout'),
    limit: document.getElementById('metric-limit'),
    integrationsBody: document.getElementById('integrations-body'),
    form: document.getElementById('preview-form'),
    url: document.getElementById('preview-url'),
    submit: document.getElementById('preview-submit'),
    alert: document.getElementById('preview-alert'),
    status: document.getElementById('response-status'),
    target: document.getElementById('response-target'),
    duration: document.getElementById('response-duration'),
    size: document.getElementById('response-size'),
    headers: document.getElementById('response-headers'),
    body: document.getElementById('response-body'),
    historyList: document.getElementById('history'),
    clearHistory: document.getElementById('clear-history'),
    statusList: document.getElementById('status-list')
  };

  const setText = (node, value) => {
    if (node) node.textContent = value;
  };

  const formatBytes = (bytes) => {
    if (!Number.isFinite(bytes)) return '—';
    if (bytes < 1024) return `${bytes} B`;
    return `${(bytes / 1024).toFixed(1)} KB`;
  };

  const formatDuration = (ms) => (Number.isFinite(ms) ? `${ms} ms` : '—');

  const formatUptime = (seconds) => {
    if (!Number.isFinite(seconds)) return '—';
    const total = Math.max(0, Math.floor(seconds));
    const h = Math.floor(total / 3600);
    const m = Math.floor((total % 3600) / 60);
    const s = total % 60;
    if (h > 0) return `${h}h ${m}m`;
    if (m > 0) return `${m}m ${s}s`;
    return `${s}s`;
  };

  const api = async (path, options) => {
    const response = await fetch(path, {
      headers: { accept: 'application/json' },
      ...options
    });

    let payload = null;
    try {
      payload = await response.json();
    } catch {
      payload = null;
    }

    return { response, payload };
  };

  const showAlert = (message) => {
    if (!message) {
      el.alert.hidden = true;
      el.alert.textContent = '';
      return;
    }
    el.alert.hidden = false;
    el.alert.textContent = message;
  };

  const renderIntegrations = (integrations) => {
    el.integrationsBody.replaceChildren();

    if (!Array.isArray(integrations) || integrations.length === 0) {
      const row = document.createElement('tr');
      row.className = 'placeholder-row';
      const cell = document.createElement('td');
      cell.colSpan = 5;
      cell.textContent = 'No connectors registered.';
      row.append(cell);
      el.integrationsBody.append(row);
      return;
    }

    for (const item of integrations) {
      const row = document.createElement('tr');

      const nameCell = document.createElement('td');
      const name = document.createElement('span');
      name.className = 'connector-name';
      name.textContent = item.name ?? 'Unnamed connector';
      nameCell.append(name);
      if (item.notes) {
        const notes = document.createElement('span');
        notes.className = 'connector-notes';
        notes.textContent = item.notes;
        nameCell.append(notes);
      }

      const kindCell = document.createElement('td');
      kindCell.textContent = item.kind ?? '—';

      const endpointCell = document.createElement('td');
      const endpoint = document.createElement('span');
      endpoint.className = 'mono';
      endpoint.textContent = item.endpoint ?? '—';
      endpointCell.append(endpoint);

      const ownerCell = document.createElement('td');
      ownerCell.textContent = item.owner ?? '—';

      const statusCell = document.createElement('td');
      const status = document.createElement('span');
      status.className = 'status-dot';
      status.dataset.state = item.status ?? '';
      status.textContent = item.status ?? 'unknown';
      statusCell.append(status);

      row.append(nameCell, kindCell, endpointCell, ownerCell, statusCell);
      el.integrationsBody.append(row);
    }
  };

  const renderStatusList = (payload) => {
    const entries = [
      ['Service', payload.service],
      ['Version', payload.version],
      ['Region', payload.region],
      ['Environment', payload.environment],
      ['Uptime', formatUptime(payload.uptimeSeconds)],
      ['Integrations', `${payload.integrations?.total ?? 0} registered, ${payload.integrations?.healthy ?? 0} healthy`],
      ['Preview method', payload.preview?.method],
      ['Preview timeout', `${payload.preview?.timeoutMs ?? '—'} ms`],
      ['Response ceiling', formatBytes(payload.preview?.maxResponseBytes)],
      ['Follows redirects', payload.preview?.followsRedirects ? 'yes' : 'no']
    ];

    el.statusList.replaceChildren();
    for (const [label, value] of entries) {
      const row = document.createElement('div');
      const dt = document.createElement('dt');
      dt.textContent = label;
      const dd = document.createElement('dd');
      dd.textContent = value === undefined || value === null ? '—' : String(value);
      row.append(dt, dd);
      el.statusList.append(row);
    }
  };

  const renderHistory = () => {
    el.historyList.replaceChildren();

    if (history.length === 0) {
      const empty = document.createElement('li');
      empty.className = 'history-empty';
      empty.textContent = 'No previews yet in this session.';
      el.historyList.append(empty);
      return;
    }

    for (const entry of history) {
      const item = document.createElement('li');

      const url = document.createElement('span');
      url.className = 'history-url';
      url.textContent = entry.url;

      const meta = document.createElement('span');
      meta.className = 'history-meta';

      const status = document.createElement('span');
      status.textContent = entry.statusLabel;

      const duration = document.createElement('span');
      duration.textContent = formatDuration(entry.durationMs);

      meta.append(status, duration);
      item.append(url, meta);
      el.historyList.append(item);
    }
  };

  const pushHistory = (entry) => {
    history.unshift(entry);
    if (history.length > MAX_HISTORY) history.length = MAX_HISTORY;
    renderHistory();
  };

  const setStatusBadge = (state, label) => {
    el.status.dataset.state = state;
    el.status.textContent = label;
  };

  const renderPreviewResult = (payload, requestedUrl) => {
    setText(el.target, payload.target ?? requestedUrl);
    setText(el.duration, formatDuration(payload.durationMs));

    const headerEntries = Object.entries(payload.headers ?? {});
    setText(
      el.headers,
      headerEntries.length === 0
        ? 'No relayed headers.'
        : headerEntries.map(([key, value]) => `${key}: ${value}`).join('\n')
    );

    const bodyText = typeof payload.body === 'string' ? payload.body : '';
    setText(el.body, bodyText.length > 0 ? bodyText : '(empty response body)');
    setText(el.size, formatBytes(new TextEncoder().encode(bodyText).length));

    if (payload.truncated) {
      setStatusBadge('warn', `HTTP ${payload.status} · truncated`);
    } else {
      const state = payload.status >= 200 && payload.status < 400 ? 'ok' : 'warn';
      setStatusBadge(state, `HTTP ${payload.status}`);
    }
  };

  const submitPreview = async (event) => {
    event.preventDefault();
    showAlert('');

    const url = el.url.value.trim();
    if (url.length === 0) {
      showAlert('Enter an endpoint URL to preview.');
      return;
    }

    el.submit.disabled = true;
    el.submit.textContent = 'Previewing…';

    try {
      const { response, payload } = await api('/api/integrations/preview', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ url })
      });

      if (!response.ok || !payload || payload.success !== true) {
        const message = payload?.message ?? `Preview failed with HTTP ${response.status}.`;

        setStatusBadge('error', `HTTP ${response.status}`);
        setText(el.target, payload?.target ?? url);
        setText(el.duration, '—');
        setText(el.size, '—');
        setText(el.headers, '—');
        setText(el.body, message);
        showAlert(
          payload?.code ? `${message} (${payload.code})` : message
        );

        pushHistory({
          url,
          statusLabel: payload?.code ? `error: ${payload.code}` : `error ${response.status}`,
          durationMs: payload?.durationMs
        });
        return;
      }

      renderPreviewResult(payload, url);
      pushHistory({
        url: payload.target ?? url,
        statusLabel: `HTTP ${payload.status}`,
        durationMs: payload.durationMs
      });
    } catch {
      setStatusBadge('error', 'network error');
      setText(el.body, 'The gateway could not be reached from this browser.');
      showAlert('The gateway could not be reached from this browser.');
    } finally {
      el.submit.disabled = false;
      el.submit.textContent = 'Preview';
    }
  };

  const loadStatus = async () => {
    try {
      const { response, payload } = await api('/api/status');
      if (!response.ok || !payload) throw new Error('status unavailable');

      el.gatewayChip.dataset.state = 'ok';
      el.gatewayChip.textContent = 'Gateway · online';

      setText(el.uptime, formatUptime(payload.uptimeSeconds));
      setText(el.timeout, `${payload.preview?.timeoutMs ?? '—'} ms`);
      setText(el.limit, formatBytes(payload.preview?.maxResponseBytes));
      renderStatusList(payload);
    } catch {
      el.gatewayChip.dataset.state = 'error';
      el.gatewayChip.textContent = 'Gateway · unreachable';
    }
  };

  const loadIntegrations = async () => {
    try {
      const { response, payload } = await api('/api/integrations');
      if (!response.ok || !payload) throw new Error('catalogue unavailable');

      const integrations = payload.integrations ?? [];
      renderIntegrations(integrations);

      setText(el.integrationsCount, String(integrations.length));
      const internal = integrations.filter((item) => item.kind === 'internal').length;
      setText(
        el.integrationsNote,
        internal > 0 ? `${internal} internal connector(s)` : 'all connectors outbound'
      );
    } catch {
      renderIntegrations([]);
      setText(el.integrationsCount, '—');
      setText(el.integrationsNote, 'catalogue unavailable');
    }
  };

  const tick = () => {
    const now = new Date();
    setText(
      el.clock,
      now.toLocaleTimeString('en-GB', { hour: '2-digit', minute: '2-digit', second: '2-digit' })
    );
  };

  el.form.addEventListener('submit', submitPreview);
  el.clearHistory.addEventListener('click', () => {
    history.length = 0;
    renderHistory();
  });

  for (const link of document.querySelectorAll('.nav-item')) {
    link.addEventListener('click', () => {
      document.querySelectorAll('.nav-item').forEach((item) => item.classList.remove('is-active'));
      link.classList.add('is-active');
    });
  }

  tick();
  setInterval(tick, 1000);
  renderHistory();
  loadStatus();
  loadIntegrations();
})();
