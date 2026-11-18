/* NetMon frontend — single page app, no build step.
 * Views: setup / login / dashboard / host detail / ssh terminal / users.
 * All secrets stay server-side; the UI only ever sees booleans. */
'use strict';

const state = {
  user: null,
  initialized: true,
  hosts: [],
  charts: {},
  timers: [],
  term: null,
  termFit: null,
  termWs: null,
  termHostId: null,
  termResize: null,
  termObserver: null,
  hostStatusTimer: null,
  sshForm: {},
};

const $app = document.getElementById('app');
const $toasts = document.getElementById('toasts');

/* ----------------------------------------------------------- utilities */
function esc(value) {
  return String(value ?? '').replace(/[&<>"']/g, (c) => ({
    '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
  }[c]));
}

function fmtTs(ts, withDate) {
  if (!ts) return '—';
  const d = new Date(ts * 1000);
  const now = new Date();
  const sameDay = d.toDateString() === now.toDateString();
  const time = d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
  if (withDate || !sameDay) {
    return d.toLocaleDateString([], { month: 'short', day: '2-digit' }) + ' ' + time;
  }
  return time;
}

function fmtAgo(ts) {
  if (!ts) return 'never';
  const secs = Math.max(0, Math.floor(Date.now() / 1000 - ts));
  if (secs < 60) return secs + 's ago';
  if (secs < 3600) return Math.floor(secs / 60) + 'm ago';
  if (secs < 86400) return Math.floor(secs / 3600) + 'h ago';
  return Math.floor(secs / 86400) + 'd ago';
}

function fmtDur(seconds) {
  if (seconds == null) return '—';
  seconds = Math.round(seconds);
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  const s = seconds % 60;
  if (d) return `${d}d ${h}h ${m}m`;
  if (h) return `${h}h ${m}m`;
  if (m) return `${m}m ${s}s`;
  return `${s}s`;
}

async function api(path, options = {}) {
  const opts = {
    method: options.method || 'GET',
    headers: { 'Content-Type': 'application/json' },
    credentials: 'same-origin',
  };
  if (options.body !== undefined) opts.body = JSON.stringify(options.body);
  const res = await fetch(path, opts);
  let data = {};
  try { data = await res.json(); } catch (e) { /* non-JSON */ }
  if (res.status === 401 && !path.startsWith('/api/login') && !path.startsWith('/api/setup')) {
    state.user = null;
    if (!location.hash.startsWith('#/login')) location.hash = '#/login';
    throw new Error('Your session expired — please sign in again');
  }
  if (!res.ok) throw new Error(data.detail || `Request failed (${res.status})`);
  return data;
}

function toast(message, type = 'info') {
  const el = document.createElement('div');
  el.className = 'toast ' + type;
  el.textContent = message;
  $toasts.appendChild(el);
  setTimeout(() => { el.style.opacity = '0'; el.style.transition = 'opacity .3s'; }, 4200);
  setTimeout(() => el.remove(), 4700);
}

function later(fn, ms) {
  const id = setTimeout(fn, ms);
  state.timers.push(id);
  return id;
}

function destroyCharts() {
  for (const key of Object.keys(state.charts)) {
    try { state.charts[key].destroy(); } catch (e) { /* ignore */ }
    delete state.charts[key];
  }
}

function chart(canvasId, config) {
  if (state.charts[canvasId]) {
    state.charts[canvasId].destroy();
  }
  const ctx = document.getElementById(canvasId);
  if (!ctx) return null;
  state.charts[canvasId] = new Chart(ctx, config);
  return state.charts[canvasId];
}

const CHART_COLORS = ['#3d8bfd', '#3fb950', '#d29922', '#a371f7', '#f85149', '#39c5cf'];

if (window.Chart) {
  Chart.defaults.color = '#8b96a5';
  Chart.defaults.borderColor = 'rgba(35,42,54,.6)';
  Chart.defaults.font.family = "-apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif";
  Chart.defaults.font.size = 11;
}

function timeTicks(maxTicks) {
  return {
    maxTicksLimit: maxTicks || 8,
    callback(value) {
      const d = new Date(value);
      const sameDay = d.toDateString() === new Date().toDateString();
      return sameDay
        ? d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })
        : d.toLocaleDateString([], { month: 'short', day: '2-digit' });
    },
  };
}

function openModal({ title, body, wide, onConfirm, confirmLabel = 'Save' }) {
  const backdrop = document.createElement('div');
  backdrop.className = 'modal-backdrop';
  backdrop.innerHTML = `
    <div class="modal ${wide ? 'wide' : ''}" role="dialog" aria-modal="true">
      <h3>${esc(title)}</h3>
      <div class="modal-body">${body}</div>
      <div class="actions">
        <button type="button" data-act="cancel">Cancel</button>
        ${onConfirm ? `<button type="button" class="primary" data-act="confirm">${esc(confirmLabel)}</button>` : ''}
      </div>
    </div>`;
  document.body.appendChild(backdrop);
  const close = () => backdrop.remove();
  backdrop.addEventListener('click', (e) => { if (e.target === backdrop) close(); });
  backdrop.querySelector('[data-act="cancel"]').addEventListener('click', close);
  if (onConfirm) {
    backdrop.querySelector('[data-act="confirm"]').addEventListener('click', async () => {
      const btn = backdrop.querySelector('[data-act="confirm"]');
      btn.disabled = true;
      try {
        const result = await onConfirm(backdrop);
        if (result !== false) close();
      } catch (err) {
        toast(err.message, 'error');
        btn.disabled = false;
      }
    });
  }
  return { backdrop, close };
}

/* ----------------------------------------------------------- routing */
function parseRoute() {
  const hash = location.hash.replace(/^#\/?/, '');
  const parts = hash.split('/').filter(Boolean);
  if (!parts.length) return { name: 'dashboard' };
  if (parts[0] === 'login') return { name: 'login' };
  if (parts[0] === 'setup') return { name: 'setup' };
  if (parts[0] === 'host' && parts[1]) return { name: 'host', id: parseInt(parts[1], 10) };
  if (parts[0] === 'ssh') {
    // `#/ssh` (nav link) means "first host"; `#/ssh/0` or `#/ssh/abc` is a typo
    // and must not silently open the first host's console.
    if (!parts[1]) return { name: 'ssh', id: null };
    const n = parseInt(parts[1], 10);
    return Number.isInteger(n) && n > 0
      ? { name: 'ssh', id: n }
      : { name: 'ssh', id: null, badId: true };
  }
  if (parts[0] === 'users') return { name: 'users' };
  if (parts[0] === 'events') return { name: 'events' };
  return { name: 'dashboard' };
}

function cleanupViews() {
  for (const id of state.timers) clearTimeout(id);
  state.timers = [];
  if (state.hostStatusTimer) { clearTimeout(state.hostStatusTimer); state.hostStatusTimer = null; }
  destroyCharts();
  closeTerminal();
  // A modal backdrop is position:fixed over the whole page; navigating away
  // (Back button, history swipe) must not leave it swallowing clicks.
  document.querySelectorAll('.modal-backdrop').forEach((el) => el.remove());
}

async function route() {
  cleanupViews();
  const r = parseRoute();
  if (r.name === 'setup') return viewSetup();
  if (r.name === 'login') return viewLogin();
  if (!state.user) return viewLogin();
  // The nav hides these for non-admins, so typing the hash directly must not
  // open a page that can only ever fail.
  if ((r.name === 'ssh' || r.name === 'users') && state.user.role !== 'admin') {
    location.hash = '#/';
    return viewDashboard();
  }
  if (r.name === 'host') return viewHost(r.id);
  if (r.name === 'ssh') return viewSSH(r.id, r.badId);
  if (r.name === 'users') return viewUsers();
  if (r.name === 'events') return viewEvents();
  return viewDashboard();
}

window.addEventListener('hashchange', route);

/* ----------------------------------------------------------- shell */
function shell(content, activeNav) {
  // state.user can be nulled by a 401 while a view is still rendering.
  if (!state.user) return viewLogin();
  const isAdmin = state.user.role === 'admin';
  $app.innerHTML = `
    <div class="topbar">
      <div class="brand">Net<span>Mon</span></div>
      <nav>
        <a href="#/" class="${activeNav === 'dashboard' ? 'active' : ''}">Dashboard</a>
        <a href="#/events" class="${activeNav === 'events' ? 'active' : ''}">Events</a>
        ${isAdmin ? '<a href="#/ssh" class="' + (activeNav === 'ssh' ? 'active' : '') + '">SSH</a>' : ''}
        ${isAdmin ? '<a href="#/users" class="' + (activeNav === 'users' ? 'active' : '') + '">Users</a>' : ''}
      </nav>
      <div class="userbox">
        <span class="badge ${state.user.role}">${esc(state.user.role)}</span>
        <span>${esc(state.user.username)}</span>
        <button class="small" data-act="change-password">Password</button>
        <button class="small" data-act="logout">Sign out</button>
      </div>
    </div>
    <div class="container">${content}</div>`;
  $app.querySelector('[data-act="logout"]').addEventListener('click', async () => {
    await api('/api/logout', { method: 'POST' }).catch(() => {});
    state.user = null;
    location.hash = '#/login';
  });
  $app.querySelector('[data-act="change-password"]').addEventListener('click', showChangePassword);
}

/* ----------------------------------------------------------- boot / auth */
async function boot() {
  try {
    const s = await api('/api/state');
    state.initialized = s.initialized;
    state.user = s.user;
  } catch (e) {
    // A failed fetch is not the same as "not initialised": showing the
    // first-run form because the backend is restarting would be misleading.
    $app.innerHTML = `
      <div class="auth-wrap"><div class="auth-card">
        <div class="logo">Net<span>Mon</span></div>
        <h1>Cannot reach the server</h1>
        <div class="sub">${esc(e.message || 'Request failed')}. Check that NetMon is running, then retry.</div>
        <button class="primary" id="boot-retry">Retry</button>
      </div></div>`;
    document.getElementById('boot-retry').addEventListener('click', boot);
    return;
  }
  if (!state.initialized) { location.hash = '#/setup'; return route(); }
  if (!state.user) { location.hash = '#/login'; return route(); }
  if (parseRoute().name === 'login' || parseRoute().name === 'setup') location.hash = '#/';
  route();
}

function viewSetup() {
  $app.innerHTML = `
    <div class="auth-wrap"><div class="auth-card">
      <div class="logo">Net<span>Mon</span></div>
      <h1>First-run setup</h1>
      <div class="sub">Create the administrator account. There are no default credentials — this account is the only way in.</div>
      <form id="setup-form">
        <label class="field"><span>Admin username</span>
          <input type="text" name="username" autocomplete="username" required minlength="3" maxlength="32"></label>
        <label class="field"><span>Password (min. 10 characters)</span>
          <input type="password" name="password" autocomplete="new-password" required minlength="10"></label>
        <label class="field"><span>Repeat password</span>
          <input type="password" name="password2" autocomplete="new-password" required minlength="10"></label>
        <button class="primary" type="submit">Create administrator</button>
      </form>
    </div></div>`;
  document.getElementById('setup-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const f = e.target;
    if (f.password.value !== f.password2.value) return toast('Passwords do not match', 'error');
    try {
      const data = await api('/api/setup', {
        method: 'POST',
        body: { username: f.username.value.trim(), password: f.password.value },
      });
      state.user = data.user;
      state.initialized = true;
      toast('Administrator account created', 'success');
      location.hash = '#/';
      route();
    } catch (err) { toast(err.message, 'error'); }
  });
}

function viewLogin() {
  $app.innerHTML = `
    <div class="auth-wrap"><div class="auth-card">
      <div class="logo">Net<span>Mon</span></div>
      <h1>Sign in</h1>
      <div class="sub">Uptime, SNMP and SSH monitoring for your internal network.</div>
      <form id="login-form">
        <label class="field"><span>Username</span>
          <input type="text" name="username" autocomplete="username" required autofocus></label>
        <label class="field"><span>Password</span>
          <input type="password" name="password" autocomplete="current-password" required></label>
        <button class="primary" type="submit">Sign in</button>
      </form>
    </div></div>`;
  document.getElementById('login-form').addEventListener('submit', async (e) => {
    e.preventDefault();
    const f = e.target;
    try {
      const data = await api('/api/login', {
        method: 'POST',
        body: { username: f.username.value.trim(), password: f.password.value },
      });
      state.user = data.user;
      location.hash = '#/';
      route();
    } catch (err) { toast(err.message, 'error'); }
  });
}

function showChangePassword() {
  openModal({
    title: 'Change your password',
    body: `
      <label class="field"><span>Current password</span><input type="password" id="cp-old" autocomplete="current-password"></label>
      <label class="field"><span>New password (min. 10 characters)</span><input type="password" id="cp-new" autocomplete="new-password"></label>
      <div class="hint">All sessions will be signed out after the change.</div>`,
    confirmLabel: 'Change password',
    onConfirm: async (backdrop) => {
      const oldPw = backdrop.querySelector('#cp-old').value;
      const newPw = backdrop.querySelector('#cp-new').value;
      if (newPw.length < 10) { toast('New password must be at least 10 characters', 'error'); return false; }
      await api('/api/me/password', { method: 'POST', body: { old_password: oldPw, new_password: newPw } });
      state.user = null;
      toast('Password changed — please sign in again', 'success');
      location.hash = '#/login';
      route();
      return true;
    },
  });
}

/* ----------------------------------------------------------- dashboard */
async function loadHosts() {
  const data = await api('/api/hosts');
  state.hosts = data.hosts;
  return data.hosts;
}

function hostStatusDot(status, enabled) {
  if (!enabled) return '<span class="dot paused" title="Monitoring paused"></span>';
  if (status.up === true) return '<span class="dot up" title="Up"></span>';
  if (status.up === false) return '<span class="dot down" title="Down"></span>';
  return '<span class="dot unknown" title="Unknown"></span>';
}

async function viewDashboard() {
  shell('<div class="empty">Loading…</div>', 'dashboard');
  const [hosts, events] = await Promise.all([
    loadHosts().catch((e) => { toast(e.message, 'error'); return []; }),
    api('/api/events?limit=12').catch(() => ({ events: [] })),
  ]);
  const up = hosts.filter((h) => h.status.up === true).length;
  const down = hosts.filter((h) => h.status.up === false).length;
  const unknown = hosts.length - up - down;
  const isAdmin = state.user.role === 'admin';

  shell(`
    <div class="page-head">
      <div><h1>Dashboard</h1><div class="sub">${hosts.length} host${hosts.length === 1 ? '' : 's'} monitored</div></div>
      ${isAdmin ? '<button class="primary" data-act="add-host">+ Add host</button>' : ''}
    </div>
    ${!isAdmin ? '<div class="notice blue">Read-only account: you can view monitoring data, charts and history. Changes and SSH require an administrator account.</div>' : ''}
    <div class="stat-row">
      <div class="stat"><div class="label">Up</div><div class="value" style="color:var(--green)">${up}</div></div>
      <div class="stat"><div class="label">Down</div><div class="value" style="color:var(--red)">${down}</div></div>
      <div class="stat"><div class="label">Unknown</div><div class="value" style="color:var(--amber)">${unknown}</div></div>
      <div class="stat"><div class="label">SNMP agents</div><div class="value">${hosts.filter((h) => h.snmp_enabled).length}</div></div>
    </div>
    <div class="cards">
      ${hosts.map((h) => `
        <div class="card clickable host-card" data-host="${h.id}">
          <div class="row1">
            ${hostStatusDot(h.status, h.enabled)}
            <div><div class="hname">${esc(h.name)}</div>
            <div class="haddr">${esc(h.address)} · SNMP v${esc(h.snmp_version)}${h.snmp_enabled ? '' : ' (off)'} · ${esc(h.check_method)}</div></div>
          </div>
          <div class="metrics">
            <span>Last check <b>${fmtAgo(h.status.last_check)}</b></span>
            <span>Latency <b>${h.status.latency_ms != null ? h.status.latency_ms + ' ms' : '—'}</b></span>
            <span>Poll <b>${h.poll_interval}s</b></span>
          </div>
        </div>`).join('') || '<div class="empty">No hosts yet. Add your first host to start monitoring.</div>'}
    </div>
    <div class="section">
      <h2>Recent events <span class="tools"><a href="#/events">view all</a></span></h2>
      <div class="card"><div class="event-list">${renderEvents(events.events)}</div></div>
    </div>`, 'dashboard');

  $app.querySelectorAll('[data-host]').forEach((el) =>
    el.addEventListener('click', () => { location.hash = '#/host/' + el.dataset.host; }));
  const addBtn = $app.querySelector('[data-act="add-host"]');
  if (addBtn) addBtn.addEventListener('click', () => showHostModal(null, reloadRoute));
  later(async () => {
    if (parseRoute().name !== 'dashboard') return;
    try {
      const data = await api('/api/hosts');
      for (const h of data.hosts) {
        const card = $app.querySelector(`[data-host="${h.id}"]`);
        if (!card) return route();
        card.querySelector('.dot')?.replaceWith(makeDot(h.status, h.enabled));
      }
    } catch (e) { /* session expired etc. */ }
  }, 20000);
}

function makeDot(status, enabled) {
  const span = document.createElement('span');
  const cls = !enabled ? 'paused' : status.up === true ? 'up' : status.up === false ? 'down' : 'unknown';
  span.className = 'dot ' + cls;
  // Keep the tooltip the server-rendered dot had, or the 20 s dashboard
  // refresh silently drops it.
  span.title = !enabled ? 'Monitoring paused'
    : status.up === true ? 'Up' : status.up === false ? 'Down' : 'Unknown';
  return span;
}

function renderEvents(events) {
  if (!events.length) return '<div class="empty">No events recorded yet.</div>';
  return events.map((e) => `
    <div class="event">
      <span class="ts">${fmtTs(e.ts)}</span>
      <span class="tag ${esc(e.type)}">${esc(e.type.replace(/_/g, ' '))}</span>
      <span class="msg">${e.host_name ? `<span class="host">[${esc(e.host_name)}]</span> ` : ''}${esc(e.message)}${e.actor ? ` <span class="actor">— ${esc(e.actor)}</span>` : ''}</span>
    </div>`).join('');
}

async function viewEvents() {
  shell('<div class="empty">Loading…</div>', 'events');
  const data = await api('/api/events?limit=200').catch((e) => { toast(e.message, 'error'); return { events: [] }; });
  shell(`
    <div class="page-head">
      <div><h1>Event history</h1><div class="sub">Reachability changes, SNMP errors, SSH sessions and account activity</div></div>
    </div>
    <div class="card"><div class="event-list">${renderEvents(data.events)}</div></div>`, 'events');
}

/* ----------------------------------------------------------- host detail */
async function viewHost(id) {
  if (!Number.isInteger(id)) { location.hash = '#/'; return; }
  shell('<div class="empty">Loading…</div>', 'dashboard');
  const isAdmin = state.user.role === 'admin';
  let host;
  try {
    host = (await api('/api/hosts/' + id)).host;
  } catch (e) { toast(e.message, 'error'); location.hash = '#/'; return; }

  const render = async (refetchHost = false) => {
    if (refetchHost) {
      // The edit form can rename the host, change the interval or turn SNMP
      // off; re-rendering the pre-edit object showed stale values.
      try {
        host = (await api('/api/hosts/' + id)).host;
      } catch (e) { toast(e.message, 'error'); location.hash = '#/'; return; }
    }
    let status, uptime, oids, events;
    try {
      [status, uptime, oids, events] = await Promise.all([
        api(`/api/hosts/${id}/status`),
        api(`/api/hosts/${id}/uptime?hours=${state.hostRange || 24}`),
        api(`/api/hosts/${id}/oids`),
        api(`/api/hosts/${id}/events?limit=60`),
      ]);
    } catch (e) {
      // One failed sub-request must not leave the page stuck on "Loading…".
      toast(e.message, 'error');
      location.hash = '#/';
      return;
    }

    shell(`
      <div class="page-head">
        <div>
          <h1><span id="st-dot">${hostStatusDot(status, host.enabled)}</span> ${esc(host.name)}</h1>
          <div class="sub mono">${esc(host.address)} · SNMP v${esc(host.snmp_version)}${host.snmp_enabled ? '' : ' (polling off)'} · check: ${esc(host.check_method)}${host.check_method === 'tcp' ? ':' + host.check_port : ''} · every ${host.poll_interval}s · SSH port ${host.ssh_port}</div>
        </div>
        <div class="btnrow">
          ${isAdmin ? `<button data-act="test">Test connectivity</button>
          <button data-act="edit">Edit</button>
          <button class="danger" data-act="delete">Delete</button>
          <button class="primary" data-act="ssh">SSH →</button>` : ''}
        </div>
      </div>

      <div class="stat-row">
        <div class="stat"><div class="label">Status</div>
          <div class="value" id="st-status" style="color:${status.up === true ? 'var(--green)' : status.up === false ? 'var(--red)' : 'var(--amber)'};font-size:18px">
            ${!host.enabled ? 'PAUSED' : status.up === true ? 'UP' : status.up === false ? 'DOWN' : 'UNKNOWN'}</div></div>
        <div class="stat"><div class="label">Availability 24h</div>
          <div class="value" id="st-avail24">${uptime.availability.availability_pct == null ? '—' : uptime.availability.availability_pct.toFixed(2) + '%'}</div></div>
        <div class="stat"><div class="label">Availability 7d</div>
          <div class="value" id="st-avail7d">${status.availability_7d.availability_pct == null ? '—' : status.availability_7d.availability_pct.toFixed(2) + '%'}</div></div>
        <div class="stat"><div class="label">Last check</div>
          <div class="value" id="st-lastcheck" style="font-size:16px">${fmtAgo(status.last_check)}</div></div>
        <div class="stat"><div class="label">Last state change</div>
          <div class="value" id="st-lastchange" style="font-size:16px">${status.last_change ? fmtTs(status.last_change, true) : '—'}</div></div>
      </div>
      <div class="hint" style="margin-top:-8px;margin-bottom:14px">Last check detail: ${esc(status.detail || '—')}${status.latency_ms != null ? ` · ${status.latency_ms} ms` : ''}</div>

      <div class="section">
        <h2>Uptime history
          <span class="tools seg">
            ${[24, 168, 720].map((h) => `<button data-range="${h}" class="${(state.hostRange || 24) === h ? 'active' : ''}">${h === 24 ? '24h' : h === 168 ? '7d' : '30d'}</button>`).join('')}
          </span>
        </h2>
        <div class="card">
          <div class="chart-wrap"><canvas id="uptime-chart"></canvas></div>
          <div class="chart-legend">
            <span><span class="swatch" style="background:var(--green)"></span>≥99.9% up</span>
            <span><span class="swatch" style="background:var(--amber)"></span>90–99.9%</span>
            <span><span class="swatch" style="background:var(--red)"></span>&lt;90%</span>
            <span><span class="swatch" style="background:var(--text-dim)"></span>no data</span>
          </div>
          <table class="data">
            <tr><th>Window</th><th>Up</th><th>Down</th><th>Availability</th></tr>
            <tr><td>Selected range</td><td>${fmtDur(uptime.availability.up_seconds)}</td>
              <td>${fmtDur(uptime.availability.down_seconds)}</td>
              <td>${uptime.availability.availability_pct == null ? '—' : uptime.availability.availability_pct.toFixed(2) + '%'}</td></tr>
            <tr><td>Last 24 hours</td><td>${fmtDur(status.availability_24h.up_seconds)}</td>
              <td>${fmtDur(status.availability_24h.down_seconds)}</td>
              <td>${status.availability_24h.availability_pct == null ? '—' : status.availability_24h.availability_pct.toFixed(2) + '%'}</td></tr>
            <tr><td>Last 7 days</td><td>${fmtDur(status.availability_7d.up_seconds)}</td>
              <td>${fmtDur(status.availability_7d.down_seconds)}</td>
              <td>${status.availability_7d.availability_pct == null ? '—' : status.availability_7d.availability_pct.toFixed(2) + '%'}</td></tr>
          </table>
          ${uptime.availability.downtime_periods.length ? `
            <div style="margin-top:12px"><b style="font-size:13px">Downtime periods</b>
            <table class="data" style="margin-top:6px">
              <tr><th>From</th><th>To</th><th>Duration</th></tr>
              ${uptime.availability.downtime_periods.map((p) => `
                <tr><td class="mono">${fmtTs(p.start, true)}</td><td class="mono">${fmtTs(p.end, true)}</td>
                <td>${fmtDur(p.seconds)}</td></tr>`).join('')}
            </table></div>` : ''}
        </div>
      </div>

      <div class="section">
        <h2>SNMP values
          ${isAdmin ? '<span class="tools"><button class="small" data-act="add-oid">+ Add OID</button><button class="small" data-act="walk">Browse OIDs</button></span>' : ''}
        </h2>
        <div class="card">
          <table class="data">
            <tr><th>OID</th><th>Label</th><th>Last value</th><th>Updated</th><th>Chart</th>${isAdmin ? '<th></th>' : ''}</tr>
            ${oids.oids.map((o) => `
              <tr>
                <td class="mono">${esc(o.oid)}</td>
                <td>${esc(o.label)}${o.builtin ? ' <span class="badge">built-in</span>' : ''}</td>
                <td class="mono">${o.last_value == null ? '—' : esc(o.last_value)}</td>
                <td>${o.last_ts ? fmtTs(o.last_ts) : '—'}</td>
                <td><input type="checkbox" class="oid-pick" data-oid="${esc(o.oid)}" ${o.last_value == null ? 'disabled' : ''}></td>
                ${isAdmin ? `<td>${o.builtin ? '' : `<button class="small danger" data-del-oid="${esc(o.oid)}">Remove</button>`}</td>` : ''}
              </tr>`).join('')}
          </table>
          <div class="btnrow" style="margin-top:12px;align-items:center">
            <span class="seg">
              ${[1, 6, 24, 168, 720].map((h) => `<button data-srange="${h}" class="${(state.seriesRange || 24) === h ? 'active' : ''}">${h === 1 ? '1h' : h === 6 ? '6h' : h === 24 ? '24h' : h === 168 ? '7d' : '30d'}</button>`).join('')}
            </span>
            <button class="primary small" data-act="plot">Plot selected (max 4)</button>
            <span class="hint">Tick OIDs above, then plot. Numeric values (counters, gauges, TimeTicks) are charted; strings appear as gaps.</span>
          </div>
          <div class="chart-wrap tall" style="margin-top:10px"><canvas id="series-chart"></canvas></div>
        </div>
      </div>

      <div class="section">
        <h2>Host events</h2>
        <div class="card"><div class="event-list">${renderEvents(events.events)}</div></div>
      </div>`, 'dashboard');

    drawUptimeChart(uptime);
    bindHostActions(host, render);
    // Exactly one timer per page: re-arming it from render() (which runs on
    // every range-button click) used to start an additional independent 30 s
    // chain, so 5 clicks meant 5 concurrent status polls.
    if (state.hostStatusTimer) clearTimeout(state.hostStatusTimer);
    state.hostStatusTimer = setTimeout(() => {
      if (parseRoute().name === 'host' && parseRoute().id === id) refreshHostStatus(id, host);
    }, 30000);
  };

  await render();
}

async function refreshHostStatus(id, host) {
  state.hostStatusTimer = null;
  try {
    const status = await api(`/api/hosts/${id}/status`);
    const set = (sel, value) => { const el = document.getElementById(sel); if (el) el.textContent = value; };
    set('st-status', !host.enabled ? 'PAUSED' : status.up === true ? 'UP' : status.up === false ? 'DOWN' : 'UNKNOWN');
    const statusEl = document.getElementById('st-status');
    if (statusEl) statusEl.style.color = status.up === true ? 'var(--green)' : status.up === false ? 'var(--red)' : 'var(--amber)';
    const dot = document.getElementById('st-dot');
    if (dot) dot.innerHTML = hostStatusDot(status, host.enabled);
    set('st-avail24', status.availability_24h.availability_pct == null ? '—' : status.availability_24h.availability_pct.toFixed(2) + '%');
    set('st-avail7d', status.availability_7d.availability_pct == null ? '—' : status.availability_7d.availability_pct.toFixed(2) + '%');
    set('st-lastcheck', fmtAgo(status.last_check));
    set('st-lastchange', status.last_change ? fmtTs(status.last_change, true) : '—');
  } catch (e) { /* ignore background refresh errors */ }
  if (parseRoute().name === 'host' && parseRoute().id === id) {
    state.hostStatusTimer = setTimeout(() => refreshHostStatus(id, host), 30000);
  }
}

function drawUptimeChart(uptime) {
  const buckets = uptime.buckets;
  chart('uptime-chart', {
    type: 'bar',
    data: {
      datasets: [{
        data: buckets.map((b) => ({ x: b.t * 1000, y: b.up_pct })),
        backgroundColor: (ctx) => {
          const v = ctx.raw && ctx.raw.y;
          if (v == null) return 'rgba(139,150,165,.25)';
          if (v >= 99.9) return 'rgba(63,185,80,.75)';
          if (v >= 90) return 'rgba(210,153,34,.8)';
          return 'rgba(248,81,73,.8)';
        },
        barPercentage: 1.0,
        categoryPercentage: 1.0,
      }],
    },
    options: {
      responsive: true,
      maintainAspectRatio: false,
      plugins: { legend: { display: false }, tooltip: {
        callbacks: {
          title: (items) => new Date(items[0].parsed.x).toLocaleString(),
          label: (item) => (item.raw.y == null ? 'no data' : item.raw.y.toFixed(2) + '% up'),
        },
      } },
      scales: {
        x: { type: 'linear', ticks: timeTicks(8), grid: { display: false } },
        y: { min: 0, max: 100, ticks: { callback: (v) => v + '%' } },
      },
    },
  });
}

function bindHostActions(host, render) {
  const bind = (act, fn) => {
    const el = $app.querySelector(`[data-act="${act}"]`);
    if (el) el.addEventListener('click', fn);
  };

  $app.querySelectorAll('[data-range]').forEach((btn) =>
    btn.addEventListener('click', () => { state.hostRange = parseInt(btn.dataset.range, 10); render(); }));
  $app.querySelectorAll('[data-srange]').forEach((btn) =>
    btn.addEventListener('click', () => { state.seriesRange = parseInt(btn.dataset.srange, 10); render(); }));

  bind('test', async () => {
    const btn = $app.querySelector('[data-act="test"]');
    btn.disabled = true; btn.textContent = 'Testing…';
    try {
      const res = await api(`/api/hosts/${host.id}/test`, { method: 'POST' });
      const lines = [`Ping: ${res.ping.ok ? 'reachable' : 'unreachable'} (${res.ping.detail})`];
      if (res.snmp) {
        if (res.snmp.ok) {
          lines.push('SNMP:');
          for (const [oid, val] of Object.entries(res.snmp.values)) lines.push(`  ${oid} = ${val}`);
        } else {
          lines.push(`SNMP error: ${res.snmp.error}`);
        }
      }
      openModal({ title: `Test — ${host.name}`, body: `<pre class="mono" style="white-space:pre-wrap">${esc(lines.join('\n'))}</pre>` });
    } catch (e) { toast(e.message, 'error'); }
    btn.disabled = false; btn.textContent = 'Test connectivity';
  });

  bind('edit', () => showHostModal(host, render));
  bind('ssh', () => { location.hash = '#/ssh/' + host.id; });
  bind('delete', () => {
    openModal({
      title: `Delete host "${host.name}"?`,
      body: '<p>This removes the host together with its samples, events and saved SSH credentials. This cannot be undone.</p>',
      confirmLabel: 'Delete host',
      onConfirm: async () => {
        await api('/api/hosts/' + host.id, { method: 'DELETE' });
        toast('Host deleted', 'success');
        location.hash = '#/';
      },
    });
  });

  bind('add-oid', () => {
    openModal({
      title: 'Add OID to monitor',
      body: `
        <label class="field"><span>OID</span><input type="text" id="oid-input" class="mono" placeholder="1.3.6.1.2.1.2.2.1.10.1"></label>
        <label class="field"><span>Label (optional)</span><input type="text" id="oid-label" placeholder="ifInOctets.1"></label>
        <div class="hint">Tip: use “Browse OIDs” to discover what the agent exposes.</div>`,
      onConfirm: async (backdrop) => {
        await api(`/api/hosts/${host.id}/oids`, {
          method: 'POST',
          body: { oid: backdrop.querySelector('#oid-input').value.trim(), label: backdrop.querySelector('#oid-label').value.trim() },
        });
        toast('OID added — values appear after the next poll', 'success');
        render();
      },
    });
  });

  bind('walk', () => {
    openModal({
      title: `Browse SNMP tree — ${host.name}`,
      wide: true,
      body: `
        <div style="display:flex;gap:8px;margin-bottom:10px">
          <input type="text" id="walk-base" class="mono" value="1.3.6.1.2.1" placeholder="1.3.6.1.2.1">
          <button id="walk-go" class="primary">Walk</button>
        </div>
        <div id="walk-results" class="hint">Enter a base OID and press Walk (max 250 rows).</div>`,
      onConfirm: () => false,
    });
    const modal = document.querySelector('.modal-backdrop');
    const go = async () => {
      const out = modal.querySelector('#walk-results');
      out.textContent = 'Walking…';
      try {
        const res = await api(`/api/hosts/${host.id}/walk`, { method: 'POST', body: { oid: modal.querySelector('#walk-base').value.trim() } });
        if (!res.ok) { out.textContent = 'Error: ' + res.error; return; }
        out.innerHTML = res.rows.length
          ? `<table class="data" style="max-height:340px;overflow:auto;display:block"><tr><th>OID</th><th>Value</th><th></th></tr>
             ${res.rows.map((r) => `<tr><td class="mono">${esc(r.oid)}</td><td class="mono">${esc(r.value)}</td>
               <td><button class="small" data-walk-add="${esc(r.oid)}">Add</button></td></tr>`).join('')}</table>`
          : 'No rows returned.';
        out.querySelectorAll('[data-walk-add]').forEach((btn) => btn.addEventListener('click', async () => {
          await api(`/api/hosts/${host.id}/oids`, { method: 'POST', body: { oid: btn.dataset.walkAdd, label: '' } });
          btn.textContent = 'Added';
          btn.disabled = true;
          render();
        }));
      } catch (e) { out.textContent = 'Error: ' + e.message; }
    };
    modal.querySelector('#walk-go').addEventListener('click', go);
  });

  $app.querySelectorAll('[data-del-oid]').forEach((btn) => btn.addEventListener('click', async () => {
    await api(`/api/hosts/${host.id}/oids/${encodeURIComponent(btn.dataset.delOid)}`, { method: 'DELETE' });
    toast('OID removed', 'success');
    render();
  }));

  const plot = $app.querySelector('[data-act="plot"]');
  if (plot) plot.addEventListener('click', async () => {
    const picked = [...$app.querySelectorAll('.oid-pick:checked')].map((c) => c.dataset.oid).slice(0, 4);
    if (!picked.length) return toast('Select at least one OID first', 'error');
    plot.disabled = true; plot.textContent = 'Loading…';
    try {
      const hours = state.seriesRange || 24;
      const results = await Promise.all(picked.map((oid) =>
        api(`/api/hosts/${host.id}/series?oid=${encodeURIComponent(oid)}&hours=${hours}`)));
      chart('series-chart', {
        type: 'line',
        data: {
          datasets: results.map((res, i) => ({
            label: res.oid,
            data: res.points.filter((p) => p.v != null).map((p) => ({ x: p.t, y: p.v })),
            borderColor: CHART_COLORS[i % CHART_COLORS.length],
            backgroundColor: CHART_COLORS[i % CHART_COLORS.length] + '22',
            borderWidth: 1.6,
            pointRadius: 0,
            tension: 0.25,
          })),
        },
        options: {
          responsive: true,
          maintainAspectRatio: false,
          interaction: { mode: 'nearest', intersect: false },
          plugins: {
            legend: { display: true, position: 'bottom', labels: { boxWidth: 12 } },
            tooltip: { callbacks: { title: (items) => new Date(items[0].parsed.x).toLocaleString() } },
          },
          scales: {
            x: { type: 'linear', ticks: timeTicks(8) },
            y: { beginAtZero: false },
          },
        },
      });
    } catch (e) { toast(e.message, 'error'); }
    plot.disabled = false; plot.textContent = 'Plot selected (max 4)';
  });
}

/* ----------------------------------------------------------- host modal */
function showHostModal(host, onSaved) {
  const isEdit = !!host;
  const h = host || {};
  const version = h.snmp_version || '2c';
  openModal({
    title: isEdit ? `Edit host — ${h.name}` : 'Add host',
    wide: true,
    confirmLabel: isEdit ? 'Save changes' : 'Add host',
    body: `
      <div class="form-grid">
        <label class="field"><span>Display name *</span><input type="text" id="h-name" value="${esc(h.name || '')}" placeholder="core-switch"></label>
        <label class="field"><span>Address (IP or DNS) *</span><input type="text" id="h-address" class="mono" value="${esc(h.address || '')}" placeholder="192.168.1.1"></label>
        <label class="field"><span>Reachability check</span>
          <select id="h-method">
            <option value="icmp" ${h.check_method === 'icmp' ? 'selected' : ''}>ICMP ping</option>
            <option value="tcp" ${h.check_method === 'tcp' ? 'selected' : ''}>TCP connect</option>
            <option value="snmp" ${h.check_method === 'snmp' ? 'selected' : ''}>SNMP query (sysUpTime)</option>
          </select></label>
        <label class="field"><span>TCP port (for TCP check)</span><input type="number" id="h-check-port" value="${h.check_port || 22}" min="1" max="65535"></label>
        <label class="field"><span>Poll interval (seconds)</span><input type="number" id="h-interval" value="${h.poll_interval || 60}" min="10" max="3600"></label>
        <label class="field"><span>SSH port</span><input type="number" id="h-ssh-port" value="${h.ssh_port || 22}" min="1" max="65535"></label>
        <div class="checkline full"><input type="checkbox" id="h-snmp" ${h.snmp_enabled === false ? '' : 'checked'}><label for="h-snmp">Poll SNMP values</label></div>
        <div class="checkline full"><input type="checkbox" id="h-enabled" ${h.enabled === false ? '' : 'checked'}><label for="h-enabled">Monitoring enabled</label></div>

        <label class="field full"><span>SNMP version</span>
          <select id="h-version">
            <option value="2c" ${version === '2c' ? 'selected' : ''}>v2c</option>
            <option value="1" ${version === '1' ? 'selected' : ''}>v1</option>
            <option value="3" ${version === '3' ? 'selected' : ''}>v3 (auth/priv)</option>
          </select></label>

        <div id="v2c-block" class="full">
          <label class="field"><span>Community string *</span>
            <input type="password" id="h-community" autocomplete="off"
              placeholder="${isEdit && h.has_community ? '•••••••• (leave blank to keep)' : 'public'}"></label>
        </div>

        <div id="v3-block" class="full" style="display:none">
          <div class="form-grid">
            <label class="field"><span>Username (security name) *</span><input type="text" id="h-v3-user" class="mono" value="${esc(h.v3_user || '')}"></label>
            <label class="field"><span>Auth protocol</span>
              <select id="h-v3-auth-proto">
                ${['SHA', 'MD5', 'SHA224', 'SHA256'].map((p) => `<option ${h.v3_auth_proto === p ? 'selected' : ''}>${p}</option>`).join('')}
              </select></label>
            <label class="field"><span>Auth key</span>
              <input type="password" id="h-v3-auth-key" autocomplete="off"
                placeholder="${isEdit && h.has_v3_auth ? '•••••••• (leave blank to keep)' : ''}"></label>
            <label class="field"><span>Priv protocol</span>
              <select id="h-v3-priv-proto">
                ${['AES', 'DES', 'AES192', 'AES256'].map((p) => `<option ${h.v3_priv_proto === p ? 'selected' : ''}>${p}</option>`).join('')}
              </select></label>
            <label class="field full"><span>Priv key</span>
              <input type="password" id="h-v3-priv-key" autocomplete="off"
                placeholder="${isEdit && h.has_v3_priv ? '•••••••• (leave blank to keep)' : ''}"></label>
          </div>
          <div class="hint">Leave both keys empty for noAuthNoPriv; auth key only for authNoPriv.</div>
        </div>

        <label class="field full"><span>Notes</span><textarea id="h-notes" rows="2" placeholder="optional">${esc(h.notes || '')}</textarea></label>
      </div>`,
    onConfirm: async (backdrop) => {
      const val = (id) => backdrop.querySelector('#' + id).value;
      const versionValue = val('h-version');
      const payload = {
        name: val('h-name'),
        address: val('h-address'),
        check_method: val('h-method'),
        check_port: parseInt(val('h-check-port'), 10) || 22,
        poll_interval: parseInt(val('h-interval'), 10) || 60,
        ssh_port: parseInt(val('h-ssh-port'), 10) || 22,
        snmp_enabled: backdrop.querySelector('#h-snmp').checked,
        enabled: backdrop.querySelector('#h-enabled').checked,
        snmp_version: versionValue,
        notes: val('h-notes'),
      };
      if (versionValue === '3') {
        payload.v3_user = val('h-v3-user');
        payload.v3_auth_proto = val('h-v3-auth-proto');
        payload.v3_priv_proto = val('h-v3-priv-proto');
        payload.v3_auth_key = val('h-v3-auth-key');
        payload.v3_priv_key = val('h-v3-priv-key');
      } else {
        payload.community = val('h-community');
      }
      if (isEdit) {
        await api('/api/hosts/' + host.id, { method: 'PUT', body: payload });
        toast('Host updated', 'success');
      } else {
        await api('/api/hosts', { method: 'POST', body: payload });
        toast('Host added', 'success');
      }
      if (onSaved) onSaved(true);
    },
  });
  const modal = document.querySelector('.modal-backdrop');
  const toggleV = () => {
    const v = modal.querySelector('#h-version').value;
    modal.querySelector('#v2c-block').style.display = v === '3' ? 'none' : 'block';
    modal.querySelector('#v3-block').style.display = v === '3' ? 'block' : 'none';
  };
  modal.querySelector('#h-version').addEventListener('change', toggleV);
  toggleV();
}

function reloadRoute() { route(); }

/* ----------------------------------------------------------- SSH view */
function fitTerminal() {
  // Resize the live terminal to the box it is drawn into. Never throws: a
  // missing addon or a not-yet-measured cell just means "try again later".
  const term = state.term;
  if (!term || !state.termFit) return;
  try { state.termFit.fit(); } catch (e) { /* ignore */ }
}

function closeTerminal() {
  // The resize listener is added per connect; without removing it, dead
  // listeners accumulate and throw on every window resize.
  if (state.termResize) {
    window.removeEventListener('resize', state.termResize);
    state.termResize = null;
  }
  if (state.termObserver) {
    try { state.termObserver.disconnect(); } catch (e) { /* ignore */ }
    state.termObserver = null;
  }
  if (state.termWs) {
    try { state.termWs.close(); } catch (e) { /* ignore */ }
    state.termWs = null;
  }
  if (state.term) {
    // dispose() releases xterm's onData/onResize disposables and internal state.
    try { state.term.dispose(); } catch (e) { /* ignore */ }
  }
  state.term = null;
  state.termFit = null;
  state.termHostId = null;
}

async function viewSSH(hostId, badId) {
  // Re-rendering this view must not orphan a live WebSocket + paramiko shell.
  closeTerminal();
  shell('<div class="empty">Loading…</div>', 'ssh');
  if (badId) { toast('Invalid host id in the address', 'error'); location.hash = '#/ssh'; return; }
  const hosts = await loadHosts().catch((e) => { toast(e.message, 'error'); return []; });
  if (hostId == null && hosts.length) hostId = hosts[0].id;
  state.sshForm = { hostId };

  shell(`
    <div class="page-head">
      <div><h1>SSH console</h1>
      <div class="sub">Full interactive shell in the browser. Every session open/close is recorded in the host history.</div></div>
    </div>
    <div class="notice">Sessions use your own username and password. Credentials are transmitted once to the server and can be stored encrypted (Fernet, key outside the database) if you tick “save”. SSH is restricted to administrator accounts.</div>
    <div class="ssh-layout">
      <div class="ssh-side">
        <div class="card">
          <div style="font-size:12px;color:var(--text-dim);text-transform:uppercase;letter-spacing:.5px;margin-bottom:8px">Hosts</div>
          ${hosts.map((h) => `
            <div class="host-item ${h.id === hostId ? 'active' : ''}" data-ssh-host="${h.id}">
              ${hostStatusDot(h.status, h.enabled)}
              <span class="nm">${esc(h.name)}</span>
            </div>`).join('') || '<div class="hint">No hosts.</div>'}
        </div>
      </div>
      <div class="ssh-main" id="ssh-main"><div class="empty">Select a host.</div></div>
    </div>`, 'ssh');

  $app.querySelectorAll('[data-ssh-host]').forEach((el) =>
    el.addEventListener('click', () => { location.hash = '#/ssh/' + el.dataset.sshHost; }));
  if (hostId) renderSSHMain(hostId, hosts);
}

function renderSSHMain(hostId, hosts) {
  const host = hosts.find((h) => h.id === hostId);
  const main = document.getElementById('ssh-main');
  if (!host) { main.innerHTML = '<div class="empty">Host not found.</div>'; return; }
  const savedUser = host.ssh_cred_username;

  main.innerHTML = `
    <div class="card">
      <div class="term-toolbar">
        <b>${esc(host.name)}</b><span class="hint mono">${esc(host.address)}:${host.ssh_port}</span>
        <span class="term-status" id="term-status">Disconnected</span>
        <span style="flex:1"></span>
        <button class="small danger" id="term-disconnect" style="display:none">Disconnect</button>
      </div>
      <div class="form-grid" id="ssh-form" style="margin-bottom:12px">
        <label class="field"><span>Username</span><input type="text" id="ssh-user" value="${esc(savedUser || '')}" autocomplete="off"></label>
        <label class="field"><span>Password</span><input type="password" id="ssh-pass" autocomplete="off"></label>
        <div class="checkline"><input type="checkbox" id="ssh-save"><label for="ssh-save">Save credentials (encrypted)</label></div>
        <div class="checkline"><input type="checkbox" id="ssh-use-saved" ${savedUser ? '' : 'disabled'}><label for="ssh-use-saved">Use saved credentials${savedUser ? ` (${esc(savedUser)})` : ' (none saved)'}</label></div>
      </div>
      <div class="btnrow" style="margin-bottom:12px">
        <button class="primary" id="ssh-connect">Connect</button>
        ${savedUser ? '<button class="small danger" id="ssh-forget">Forget saved credentials</button>' : ''}
      </div>
      <div class="term-frame"><div id="terminal-container" style="display:none"></div></div>
    </div>`;

  document.getElementById('ssh-connect').addEventListener('click', () => connectTerminal(hostId, host));
  const forget = document.getElementById('ssh-forget');
  if (forget) forget.addEventListener('click', async () => {
    await api(`/api/hosts/${hostId}/ssh-credentials`, { method: 'DELETE' });
    toast('Saved credentials removed', 'success');
    viewSSH(hostId);
  });
}

async function connectTerminal(hostId, host) {
  const username = document.getElementById('ssh-user').value.trim();
  const password = document.getElementById('ssh-pass').value;
  const save = document.getElementById('ssh-save').checked;
  const useSaved = document.getElementById('ssh-use-saved').checked;
  const statusEl = document.getElementById('term-status');
  const disconnectBtn = document.getElementById('term-disconnect');

  if (!useSaved && (!username || !password)) return toast('Enter username and password', 'error');
  closeTerminal();

  if (save && !useSaved) {
    try {
      await api(`/api/hosts/${hostId}/ssh-credentials`, {
        method: 'POST', body: { username, password },
      });
      toast('Credentials saved (encrypted)', 'success');
    } catch (e) { toast(e.message, 'error'); return; }
  }

  const container = document.getElementById('terminal-container');
  container.style.display = 'block';
  statusEl.textContent = 'Connecting…';
  statusEl.className = 'term-status';

  state.term = new Terminal({
    fontSize: 13,
    fontFamily: "'SF Mono', Menlo, Consolas, monospace",
    theme: { background: '#0b0e14', foreground: '#d7dee8', cursor: '#3d8bfd' },
    cursorBlink: true,
    scrollback: 5000,
  });
  state.termFit = new FitAddon.FitAddon();
  state.term.loadAddon(state.termFit);
  state.term.open(container);
  // FitAddon reads computed styles, which can still be stale for a frame after
  // open(). Re-fit immediately, on the next frame, and on every later layout
  // change, so the terminal always matches the box it is drawn into.
  fitTerminal();
  requestAnimationFrame(fitTerminal);
  if (window.ResizeObserver) {
    state.termObserver = new ResizeObserver(() => fitTerminal());
    state.termObserver.observe(container);
  }
  state.term.writeln('\x1b[2mConnecting to ' + host.address + ':' + host.ssh_port + ' …\x1b[0m');
  state.term.focus();
  // The form sits above a 480px terminal; bring the whole terminal into view so
  // nothing is hidden below the fold right after connecting.
  try { container.scrollIntoView({ block: 'nearest', inline: 'nearest' }); } catch (e) { /* ignore */ }

  const proto = location.protocol === 'https:' ? 'wss://' : 'ws://';
  const ws = new WebSocket(`${proto}${location.host}/ws/ssh/${hostId}`);
  ws.binaryType = 'arraybuffer';
  state.termWs = ws;
  state.termHostId = hostId;

  const cols = state.term.cols, rows = state.term.rows;

  ws.onopen = () => {
    ws.send(JSON.stringify({ username, password, use_saved: useSaved, cols, rows }));
    // The size can still change between reading cols/rows and the socket opening
    // (a pending rAF fit, a late font, a layout shift). Push the current size so
    // the remote pty always agrees with what the browser actually draws.
    if (state.term && (state.term.cols !== cols || state.term.rows !== rows)) {
      ws.send(JSON.stringify({
        type: 'resize', cols: state.term.cols, rows: state.term.rows,
      }));
    }
  };
  ws.onmessage = (event) => {
    // A re-rendered view replaces the DOM nodes; only the live terminal may
    // be touched, otherwise a stale handler hides the *new* Disconnect button.
    if (!state.term) return;
    if (typeof event.data === 'string') {
      let msg = {};
      try { msg = JSON.parse(event.data); } catch (e) { return; }
      if (msg.type === 'status') {
        statusEl.textContent = msg.message;
        statusEl.className = 'term-status ' + (msg.phase === 'connected' ? 'connected' : msg.phase === 'error' ? 'error' : '');
        if (msg.phase === 'error') {
          state.term.writeln('\r\n\x1b[31m' + msg.message + '\x1b[0m');
          disconnectBtn.style.display = 'none';
        }
        if (msg.phase === 'connected') {
          disconnectBtn.style.display = '';
        }
      }
      return;
    }
    state.term.write(new Uint8Array(event.data));
  };
  ws.onclose = () => {
    if (!state.term) return;
    statusEl.textContent = 'Disconnected';
    statusEl.className = 'term-status';
    disconnectBtn.style.display = 'none';
    state.termWs = null;
  };
  ws.onerror = () => {
    if (!state.term) return;
    statusEl.textContent = 'Connection error';
    statusEl.className = 'term-status error';
  };

  state.term.onData((data) => {
    if (ws.readyState === WebSocket.OPEN) ws.send(new TextEncoder().encode(data));
  });
  state.term.onResize((ev) => {
    if (ws.readyState === WebSocket.OPEN) {
      ws.send(JSON.stringify({ type: 'resize', cols: ev.cols, rows: ev.rows }));
    }
  });
  const fitNow = () => fitTerminal();
  window.addEventListener('resize', fitNow);
  state.termResize = fitNow;
  disconnectBtn.addEventListener('click', () => {
    if (ws.readyState === WebSocket.OPEN) ws.close();
  });
}

/* ----------------------------------------------------------- users view */
async function viewUsers() {
  shell('<div class="empty">Loading…</div>', 'users');
  const data = await api('/api/users').catch((e) => { toast(e.message, 'error'); return { users: [] }; });
  shell(`
    <div class="page-head">
      <div><h1>Accounts</h1><div class="sub">Administrators can change hosts, view charts and open SSH. Read-only accounts can only look.</div></div>
    </div>
    <div class="card">
      <table class="data">
        <tr><th>ID</th><th>Username</th><th>Role</th><th>Created</th><th></th></tr>
        ${data.users.map((u) => `
          <tr>
            <td class="mono">${u.id}</td>
            <td>${esc(u.username)}${u.id === state.user.id ? ' <span class="badge">you</span>' : ''}</td>
            <td><span class="badge ${u.role}">${esc(u.role)}</span></td>
            <td class="mono">${fmtTs(u.created_at, true)}</td>
            <td style="text-align:right">
              ${u.id === state.user.id ? '' : `<button class="small danger" data-del-user="${u.id}">Delete</button>`}
            </td>
          </tr>`).join('')}
      </table>
    </div>
    <div class="section">
      <h2>Create account</h2>
      <div class="card">
        <div class="form-grid">
          <label class="field"><span>Username</span><input type="text" id="nu-user" placeholder="3-32 chars: letters, digits, _ . -"></label>
          <label class="field"><span>Role</span>
            <select id="nu-role"><option value="readonly">read-only</option><option value="admin">administrator</option></select></label>
          <label class="field"><span>Password (min. 10 characters)</span><input type="password" id="nu-pass" autocomplete="new-password"></label>
          <label class="field"><span>Repeat password</span><input type="password" id="nu-pass2" autocomplete="new-password"></label>
        </div>
        <button class="primary" id="nu-create">Create account</button>
      </div>
    </div>`, 'users');

  $app.querySelectorAll('[data-del-user]').forEach((btn) => btn.addEventListener('click', async () => {
    if (!confirm('Delete this account?')) return;
    try {
      await api('/api/users/' + btn.dataset.delUser, { method: 'DELETE' });
      toast('Account deleted', 'success');
      viewUsers();
    } catch (e) { toast(e.message, 'error'); }
  }));

  document.getElementById('nu-create').addEventListener('click', async () => {
    const username = document.getElementById('nu-user').value.trim();
    const role = document.getElementById('nu-role').value;
    const pass = document.getElementById('nu-pass').value;
    const pass2 = document.getElementById('nu-pass2').value;
    if (pass !== pass2) return toast('Passwords do not match', 'error');
    try {
      await api('/api/users', { method: 'POST', body: { username, role, password: pass } });
      toast('Account created', 'success');
      viewUsers();
    } catch (e) { toast(e.message, 'error'); }
  });
}

/* ----------------------------------------------------------- start */
boot();
