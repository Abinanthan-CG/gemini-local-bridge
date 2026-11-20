const invoke = window.__TAURI__.core.invoke;

let state = null;
let toastTimer = null;
let auditCategory = 'all';
let auditQuery = '';

function $(id) {
  return document.getElementById(id);
}

function showToast(msg, ms = 4200) {
  const el = $('toast');
  el.textContent = msg;
  el.classList.remove('hidden');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.add('hidden'), ms);
}

function esc(v) {
  return String(v ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function switchTab(name) {
  document.querySelectorAll('.nav-btn').forEach((b) => {
    const active = b.dataset.tab === name;
    b.classList.toggle('active', active);
    b.setAttribute('aria-selected', active ? 'true' : 'false');
  });
  document.querySelectorAll('.tab').forEach((t) => {
    t.classList.toggle('active', t.id === `tab-${name}`);
  });
}

document.querySelectorAll('.nav-btn').forEach((b) => {
  b.addEventListener('click', () => switchTab(b.dataset.tab));
});
document.querySelectorAll('[data-jump]').forEach((b) => {
  b.addEventListener('click', () => switchTab(b.dataset.jump));
});

// Keyboard shortcuts: Alt+1..5 for fast tab switching
const TAB_ORDER = ['overview', 'approvals', 'drive', 'clients', 'audit'];
document.addEventListener('keydown', (ev) => {
  if (ev.altKey && ev.key >= '1' && ev.key <= '5') {
    ev.preventDefault();
    switchTab(TAB_ORDER[Number(ev.key) - 1]);
  }
});

// Inline Copy button helper with brief checkmark feedback
document.querySelectorAll('.copy-btn').forEach((btn) => {
  btn.addEventListener('click', async () => {
    const target = $(btn.dataset.copyFrom);
    if (!target) return;
    await navigator.clipboard.writeText(target.textContent || '');
    const orig = btn.textContent;
    btn.textContent = 'Copied';
    btn.classList.add('copied');
    setTimeout(() => {
      btn.textContent = orig;
      btn.classList.remove('copied');
    }, 1500);
  });
});

function eventCategory(evName) {
  if (/oauth|client|pairing|pin/i.test(evName)) return 'auth';
  if (/file_|url_|share_/i.test(evName)) return 'files';
  if (/command/i.test(evName)) return 'commands';
  if (/drive_/i.test(evName)) return 'drive';
  if (/grant|access_|paused|resumed|funnel/i.test(evName)) return 'security';
  return 'security';
}

function eventTone(evName) {
  if (/failed|denied|blocked|lockout|revoked|paused/i.test(evName)) return 'ev-danger';
  if (/issued|approved|connected|synced|started|resumed|enabled/i.test(evName)) return 'ev-ok';
  if (/requested|pairing_enabled|rotated/i.test(evName)) return 'ev-warn';
  return '';
}

function summarizeAuditDetail(ev, d) {
  if (!d || typeof d !== 'object') return String(d ?? '');
  if (ev === 'command') {
    const args = Array.isArray(d.args) ? d.args.join(' ') : '';
    return `${d.program || ''} ${args} → exit ${d.code ?? '?'} (${d.durationMs ?? 0} ms)`.trim();
  }
  if (ev === 'file_written' || ev === 'file_patched') {
    return `${d.path || ''}${d.bytes != null ? ` (${d.bytes} B)` : ''}`;
  }
  if (ev === 'file_copied') {
    return `${d.from || ''} → ${d.to || ''} (${d.bytes ?? 0} B)`;
  }
  if (ev === 'url_downloaded') {
    return `${d.url || ''} → ${d.to || ''} (${d.bytes ?? 0} B)`;
  }
  if (ev.startsWith('client_') || ev.startsWith('oauth_') || ev.startsWith('pairing_')) {
    const parts = [];
    if (d.name) parts.push(d.name);
    if (d.clientId) parts.push(d.clientId);
    if (d.ip) parts.push(`ip ${d.ip}`);
    if (d.minutes) parts.push(`${d.minutes} min`);
    return parts.join(' · ') || '—';
  }
  if (ev.startsWith('grant_') || ev.startsWith('access_')) {
    return `${d.kind || ''} ${d.target || ''}${d.mode ? ` (${d.mode})` : ''}`.trim();
  }
  if (ev.startsWith('drive_')) {
    if (d.error) return d.error;
    if (d.folderName) return `${d.folderName} (${d.mode || ''})`;
    return `${d.mode || 'two_way'} sync completed`;
  }
  const s = JSON.stringify(d);
  return s === '{}' ? '—' : s;
}

function renderAuditList() {
  if (!state) return;
  const q = auditQuery.trim().toLowerCase();
  const rows = state.recentAudit.filter((a) => {
    if (auditCategory !== 'all' && eventCategory(a.event) !== auditCategory) return false;
    if (!q) return true;
    const hay = `${a.event} ${JSON.stringify(a.detail)}`.toLowerCase();
    return hay.includes(q);
  });

  if (rows.length === 0) {
    $('audit-list').innerHTML = '<div class="empty-state">No matching audit events.</div>';
    return;
  }

  $('audit-list').innerHTML = rows
    .map((a) => {
      const ts = a.ts.replace('T', ' ').slice(5, 19);
      const tone = eventTone(a.event);
      const summary = summarizeAuditDetail(a.event, a.detail);
      return `<div class="audit-row">
        <div class="audit-ts">${esc(ts)}</div>
        <div class="audit-ev ${tone}">${esc(a.event)}</div>
        <div class="audit-dt">${esc(summary)}</div>
      </div>`;
    })
    .join('');
}

document.querySelectorAll('.filter-chip').forEach((chip) => {
  chip.addEventListener('click', () => {
    auditCategory = chip.dataset.filter;
    document.querySelectorAll('.filter-chip').forEach((c) => {
      c.classList.toggle('active', c === chip);
    });
    renderAuditList();
  });
});

$('audit-search').addEventListener('input', (ev) => {
  auditQuery = ev.target.value || '';
  renderAuditList();
});

function formatCountdown(secs) {
  const m = Math.floor(secs / 60);
  const s = secs % 60;
  return `${m}:${String(s).padStart(2, '0')}`;
}

function render(s) {
  state = s;

  // Sidebar engine status + Kill Switch
  const sDot = $('sidebar-dot');
  const sStatus = $('sidebar-status');
  const killBtn = $('btn-kill');
  const killTxt = $('btn-kill-text');
  $('sidebar-bind').textContent = `${s.host}:${s.port}`;

  if (s.paused) {
    sDot.className = 'dot danger';
    sStatus.textContent = 'Bridge Paused';
    killTxt.textContent = 'Resume Bridge';
    killBtn.className = 'btn btn-primary full';
    $('stat-engine').innerHTML = '<span class="dot danger"></span>Paused';
  } else {
    sDot.className = 'dot ok';
    sStatus.textContent = 'Engine Active';
    killTxt.textContent = 'Pause Bridge';
    killBtn.className = 'btn btn-danger-subtle full';
    $('stat-engine').innerHTML = '<span class="dot ok"></span>Running';
  }
  $('stat-port').textContent = `${s.host}:${s.port}`;

  // One-time PIN banner
  if (s.ephemDisplayPin) {
    $('pin-value').textContent = s.ephemDisplayPin;
    $('pin-banner').classList.remove('hidden');
  } else {
    $('pin-banner').classList.add('hidden');
  }

  // Pending badges
  const pCount = s.pendingRequests.length;
  const badge = $('badge-pending');
  badge.textContent = String(pCount);
  badge.classList.toggle('hidden', pCount === 0);
  $('pending-count-pill').textContent = `${pCount} pending`;
  $('pending-count-pill').className = pCount > 0 ? 'pill warn' : 'pill';

  // Tailscale telemetry + card
  const ts = s.tailscale;
  const tsBadge = $('ts-badge');
  const tsNote = $('ts-note');
  if (!ts.installed) {
    tsBadge.textContent = 'Not Installed';
    tsBadge.className = 'pill danger';
    $('stat-ts').innerHTML = '<span class="dot danger"></span>Missing';
  } else if (!ts.loggedIn) {
    tsBadge.textContent = ts.backendState || 'Logged Out';
    tsBadge.className = 'pill warn';
    $('stat-ts').innerHTML = '<span class="dot warn"></span>Signed Out';
  } else if (ts.funnelActive) {
    tsBadge.textContent = 'Funnel Active';
    tsBadge.className = 'pill online';
    $('stat-ts').innerHTML = '<span class="dot ok"></span>Funnel Live';
  } else {
    tsBadge.textContent = 'Funnel Off';
    tsBadge.className = 'pill warn';
    $('stat-ts').innerHTML = '<span class="dot warn"></span>Funnel Off';
  }

  const base = ts.funnelUrl || (ts.dnsName ? `https://${ts.dnsName}` : `http://${s.host}:${s.port}`);
  $('stat-ts-host').textContent = ts.dnsName || `${s.host}:${s.port}`;
  $('stat-ts-host').title = ts.dnsName || `${s.host}:${s.port}`;
  $('mcp-url').textContent = `${base}/mcp`;
  $('mcp-url').title = `${base}/mcp`;
  $('approve-url').textContent = `${base}/approve`;
  $('approve-url').title = `${base}/approve`;

  if (ts.loginUrl) {
    tsNote.textContent = `Tailscale login required: ${ts.loginUrl}`;
    tsNote.classList.remove('hidden');
  } else if (ts.rawError) {
    tsNote.textContent = ts.rawError;
    tsNote.classList.remove('hidden');
  } else {
    tsNote.classList.add('hidden');
  }

  // Pairing telemetry
  if (s.pairingOpen) {
    const cd = formatCountdown(s.pairingRemainingSecs);
    $('stat-pair').innerHTML = `<span class="dot warn"></span>Open (${cd})`;
    $('sec-pairing-pill').textContent = `Open · ${cd}`;
    $('sec-pairing-pill').className = 'pill warn';
    $('btn-pair-label').textContent = `Pairing Open (${cd})`;
  } else {
    $('stat-pair').innerHTML = '<span class="dot ok"></span>Locked';
    $('sec-pairing-pill').textContent = 'Locked';
    $('sec-pairing-pill').className = 'pill online';
    $('btn-pair-label').textContent = 'Enable Pairing (5m)';
  }
  $('stat-clients').textContent = `${s.clientCount} paired client${s.clientCount === 1 ? '' : 's'}`;
  $('clients-count-pill').textContent = `${s.clientCount} client${s.clientCount === 1 ? '' : 's'}`;

  // Sandbox
  $('ws-path').textContent = s.workspace;
  $('grants-pill').textContent = `${s.activeGrants.length} active grant${s.activeGrants.length === 1 ? '' : 's'}`;
  $('grants-pill').className = s.activeGrants.length > 0 ? 'pill warn' : 'pill';
  $('active-grants-pill').textContent = `${s.activeGrants.length} active`;
  $('prog-chips').innerHTML = s.programs.length
    ? s.programs.map((p) => `<span class="chip">${esc(p)}</span>`).join('')
    : '<span class="muted small">None resolved</span>';

  // Drive Sync telemetry + tab
  const d = s.drive;
  const navDot = $('nav-drive-dot');
  let dBadgeText = 'Not Connected';
  let dBadgeClass = 'pill';
  if (!d.rcloneInstalled) {
    dBadgeText = 'rclone Missing';
    dBadgeClass = 'pill danger';
    navDot.className = 'nav-dot';
    $('stat-drive').innerHTML = '<span class="dot danger"></span>No rclone';
  } else if (d.syncing) {
    dBadgeText = 'Syncing…';
    dBadgeClass = 'pill warn';
    navDot.className = 'nav-dot warn';
    $('stat-drive').innerHTML = '<span class="dot warn"></span>Syncing';
  } else if (d.configured && d.enabled) {
    dBadgeText = 'Connected';
    dBadgeClass = 'pill online';
    navDot.className = 'nav-dot ok';
    $('stat-drive').innerHTML = '<span class="dot ok"></span>Synced';
  } else {
    navDot.className = 'nav-dot';
    $('stat-drive').innerHTML = '<span class="dot"></span>Not Linked';
  }

  $('stat-drive-files').textContent = d.configured
    ? `${d.remoteFolderName} · ${d.localFileCount} file${d.localFileCount === 1 ? '' : 's'}`
    : `${d.localFileCount} local file${d.localFileCount === 1 ? '' : 's'}`;

  $('ov-drive-badge').textContent = dBadgeText;
  $('ov-drive-badge').className = dBadgeClass;
  $('drive-badge').textContent = dBadgeText;
  $('drive-badge').className = dBadgeClass;

  $('ov-drive-summary').textContent = d.configured
    ? `${d.localDir} ↔ Drive "${d.remoteFolderName}" (${d.mode === 'two_way' ? 'Two-way' : 'Outbound-only'}) · ${d.lastResult}`
    : `Local sync folder: ${d.localDir}. Link one Google Drive folder for lossless Gemini vision.`;

  $('drive-local').textContent = d.localDir;
  $('drive-remote').textContent = d.configured ? `${d.remoteFolderName} (${d.remoteFolderId})` : '—';
  $('drive-mode').textContent = d.mode === 'two_way' ? 'Two-way (PC ↔ Drive)' : 'Outbound-only (drive.file)';
  $('drive-files').textContent = String(d.localFileCount);
  $('drive-last').textContent = d.lastSyncAt ? new Date(d.lastSyncAt).toLocaleString() : 'Never';
  $('drive-result').textContent = d.lastResult || '—';
  $('btn-drive-disconnect').classList.toggle('hidden', !d.configured);

  // Pending requests
  const pendEl = $('pending-list');
  if (s.pendingRequests.length === 0) {
    pendEl.innerHTML = '<div class="empty-state">No pending approval requests. Outside-workspace paths and non-allowlisted programs will appear here when requested.</div>';
  } else {
    pendEl.innerHTML = s.pendingRequests
      .map(
        (r) => `<div class="item-box">
          <div>
            <div><span class="item-tag ${r.kind === 'program' ? 'program' : ''}">${esc(r.kind)}</span><span class="mono">${esc(r.target)}</span></div>
            <div class="muted small mt-4">${esc(r.reason)} · Request ${esc(r.id)}</div>
          </div>
          <div class="row">
            <button class="btn btn-sm btn-primary" data-decide="${esc(r.id)}" data-val="allow_once">Once</button>
            <button class="btn btn-sm" data-decide="${esc(r.id)}" data-val="allow_session">Session</button>
            <button class="btn btn-sm btn-danger-subtle" data-decide="${esc(r.id)}" data-val="deny">Deny</button>
          </div>
        </div>`
      )
      .join('');
  }

  // Active grants
  const grantsEl = $('grants-list');
  if (s.activeGrants.length === 0) {
    grantsEl.innerHTML = '<div class="empty-state">No active grants. Everything stays strictly inside your workspace root.</div>';
  } else {
    grantsEl.innerHTML = s.activeGrants
      .map(
        (g) => `<div class="item-box">
          <div>
            <div><span class="item-tag ${g.kind === 'program' ? 'program' : ''}">${esc(g.kind)}</span><span class="mono">${esc(g.target)}</span></div>
            <div class="muted small mt-4">${g.mode === 'session' ? 'Active until app restarts' : 'Single-use (15 min expiry)'}</div>
          </div>
          <button class="btn btn-sm btn-danger-subtle" data-revoke-grant="${esc(g.id)}">Revoke</button>
        </div>`
      )
      .join('');
  }

  // Paired clients
  const clEl = $('clients-list');
  if (s.clients.length === 0) {
    clEl.innerHTML = '<div class="empty-state">No OAuth clients paired yet. Open Pairing Mode and add your Tailscale MCP URL in Gemini Connected Apps.</div>';
  } else {
    clEl.innerHTML = s.clients
      .map(
        (c) => `<div class="item-box">
          <div>
            <div><strong>${esc(c.clientName)}</strong></div>
            <div class="mono muted mt-4">${esc(c.clientId)} · paired ${new Date(c.createdAt).toLocaleString()}</div>
          </div>
          <button class="btn btn-sm btn-danger-subtle" data-revoke-client="${esc(c.clientId)}">Disconnect</button>
        </div>`
      )
      .join('');
  }

  renderAuditList();
}

async function refresh() {
  try {
    const snap = await invoke('get_dashboard');
    render(snap);
  } catch (e) {
    console.error('refresh failed:', e);
  }
}

// Actions
$('btn-kill').addEventListener('click', async () => {
  await invoke('set_paused', { paused: !state?.paused });
  showToast(state?.paused ? 'Bridge resumed.' : 'Bridge paused (Kill Switch active).');
  refresh();
});

$('btn-pair').addEventListener('click', async () => {
  if (state?.pairingOpen) {
    await invoke('set_pairing', { open: false, minutes: null });
    showToast('Pairing Mode locked.');
  } else {
    await invoke('set_pairing', { open: true, minutes: 5 });
    showToast('Pairing Mode open for 5 minutes.');
  }
  refresh();
});
$('btn-pair-open-5').addEventListener('click', async () => {
  await invoke('set_pairing', { open: true, minutes: 5 });
  showToast('Pairing Mode open for 5 minutes.');
  refresh();
});
$('btn-pair-open-15').addEventListener('click', async () => {
  await invoke('set_pairing', { open: true, minutes: 15 });
  showToast('Pairing Mode open for 15 minutes.');
  refresh();
});
$('btn-pair-close').addEventListener('click', async () => {
  await invoke('set_pairing', { open: false, minutes: null });
  showToast('Pairing Mode locked.');
  refresh();
});

$('btn-open-ws').addEventListener('click', () => state && invoke('open_folder', { path: state.workspace }));
$('btn-ov-open-sync').addEventListener('click', () => state && invoke('open_folder', { path: state.drive.localDir }));
$('btn-drive-open').addEventListener('click', () => state && invoke('open_folder', { path: state.drive.localDir }));

$('btn-copy-pin').addEventListener('click', async () => {
  await navigator.clipboard.writeText($('pin-value').textContent || '');
  showToast('Access PIN copied.');
});
$('btn-dismiss-pin').addEventListener('click', async () => {
  await invoke('dismiss_display_pin');
  refresh();
});

$('btn-rotate-pin').addEventListener('click', async () => {
  try {
    const pin = await invoke('rotate_pin', { customPin: null });
    showToast(`New Access PIN generated: ${pin}`);
    refresh();
  } catch (e) {
    showToast(`PIN rotate failed: ${e}`);
  }
});

$('pin-form').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const val = $('custom-pin').value.trim();
  try {
    const pin = await invoke('rotate_pin', { customPin: val || null });
    $('custom-pin').value = '';
    showToast(`Access PIN updated: ${pin}`);
    refresh();
  } catch (e) {
    showToast(`Error: ${e}`);
  }
});

$('btn-ts-enable').addEventListener('click', async () => {
  showToast('Enabling Tailscale Funnel…');
  try {
    const msg = await invoke('toggle_tailscale_funnel', { enable: true });
    showToast(msg, 6500);
  } catch (e) {
    showToast(`Tailscale Funnel error: ${e}`, 8000);
  }
  refresh();
});

$('btn-ts-disable').addEventListener('click', async () => {
  try {
    const msg = await invoke('toggle_tailscale_funnel', { enable: false });
    showToast(msg);
  } catch (e) {
    showToast(`Error: ${e}`);
  }
  refresh();
});

$('grant-form').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  try {
    await invoke('add_manual_grant', {
      kind: $('grant-kind').value,
      target: $('grant-target').value,
      mode: $('grant-mode').value,
    });
    $('grant-target').value = '';
    showToast('Access granted.');
    refresh();
  } catch (e) {
    showToast(`Grant failed: ${e}`, 6000);
  }
});

async function runDriveSync() {
  showToast('Syncing Google Drive folder…');
  try {
    const msg = await invoke('sync_google_drive_now');
    showToast(msg);
  } catch (e) {
    showToast(`Sync failed: ${e}`, 7000);
  }
  refresh();
}
$('btn-ov-sync').addEventListener('click', runDriveSync);
$('btn-drive-sync-now').addEventListener('click', runDriveSync);

$('drive-form').addEventListener('submit', async (ev) => {
  ev.preventDefault();
  const btn = $('btn-drive-connect');
  btn.disabled = true;
  showToast('Opening Google sign-in in your browser… complete consent to link the folder.', 10000);
  try {
    const msg = await invoke('connect_google_drive', {
      folderName: $('drive-folder-name').value.trim(),
      folderId: $('drive-folder-id').value.trim() || null,
      mode: $('drive-sync-mode').value,
    });
    showToast(msg, 8000);
  } catch (e) {
    showToast(`Drive connect failed: ${e}`, 9000);
  } finally {
    btn.disabled = false;
    refresh();
  }
});

$('btn-drive-disconnect').addEventListener('click', async () => {
  await invoke('disconnect_google_drive');
  showToast('Google Drive disconnected.');
  refresh();
});

document.addEventListener('click', async (ev) => {
  const t = ev.target.closest('button');
  if (!t) return;
  if (t.dataset?.decide) {
    await invoke('decide_access_request', { id: t.dataset.decide, decision: t.dataset.val });
    showToast('Decision saved.');
    refresh();
  } else if (t.dataset?.revokeGrant) {
    await invoke('revoke_grant', { id: t.dataset.revokeGrant });
    showToast('Grant revoked.');
    refresh();
  } else if (t.dataset?.revokeClient) {
    await invoke('revoke_client', { clientId: t.dataset.revokeClient });
    showToast('Client disconnected.');
    refresh();
  }
});

refresh();
setInterval(refresh, 2500);
