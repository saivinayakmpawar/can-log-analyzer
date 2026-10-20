'use strict';
/* CAN Log Analyzer UI. Vanilla JS + Chart.js (vendored). No inline handlers: the page runs under a strict CSP. */
const $ = (s, r = document) => r.querySelector(s);
const $$ = (s, r = document) => [...r.querySelectorAll(s)];
const esc = s => String(s ?? '').replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
const num = (v, d = 3) => v == null ? '-' : (Number.isInteger(v) ? String(v) : Number(v).toFixed(d).replace(/\.?0+$/, ''));
const SEV = ['high', 'medium', 'low'];
const css = n => getComputedStyle(document.documentElement).getPropertyValue(n).trim();

const S = {
  info: null, id: null, a: null, dbcOnly: null, tab: 'overview', token: sessionStorage.getItem('can-token') || '',
  f: {sev: 'all', cls: 'all', q: ''},
  fr: {offset: 0, limit: 100, sort: 'idx', order: 'asc', t0: '', t1: '', can_id: '', fmt: 'any', message: '', q: ''},
  sg: {name: null, t0: null, t1: null}, charts: {}, dbc: null, history: [],
};
const TABS = [['overview', 'Overview'], ['faults', 'Faults'], ['frames', 'Frames'], ['signals', 'Signals'],
              ['messages', 'Messages & ECUs'], ['dbc', 'DBC'], ['compare', 'Compare'], ['history', 'History']];

/* ---------- plumbing ---------- */
let tokenWaiter = null;
function askToken() {
  $('#token-box').hidden = false; $('#token').focus();
  return new Promise(res => { tokenWaiter = res; });
}
$('#token-form').addEventListener('submit', e => {
  e.preventDefault(); S.token = $('#token').value.trim(); sessionStorage.setItem('can-token', S.token);
  $('#token-box').hidden = true; tokenWaiter && tokenWaiter();
});
async function api(path, opts = {}) {
  const headers = new Headers(opts.headers || {});
  if (S.token) headers.set('Authorization', 'Bearer ' + S.token);
  const res = await fetch(path, {...opts, headers});
  if (res.status === 401) { sessionStorage.removeItem('can-token'); await askToken(); return api(path, opts); }
  if (!res.ok) {
    let d; try { d = (await res.json()).detail; } catch { /* not JSON */ }
    throw new Error(typeof d === 'string' ? d : Array.isArray(d) ? d.map(x => x.msg).join('; ') : `Request failed (${res.status})`);
  }
  return opts.raw ? res : res.json();
}
function status(msg, kind = '') {
  $('#status').innerHTML = msg ? `<div class="msg ${kind}">${kind === 'busy' ? '<span class="spinner" aria-hidden="true"></span>' : ''}<span>${esc(msg)}</span></div>` : '';
}
async function busy(msg, promise) {
  status(msg, 'busy');
  try { const r = await promise; status(''); return r; }
  catch (e) { status(e.message, 'error'); throw e; }
}
function chart(id, config) {
  if (S.charts[id]) S.charts[id].destroy();
  const el = $('#' + id); if (!el) return null;
  Chart.defaults.font.family = getComputedStyle(document.body).fontFamily; Chart.defaults.font.size = 12;
  Chart.defaults.color = css('--mute');
  return (S.charts[id] = new Chart(el, config));
}
const rid = () => encodeURIComponent(S.id);
const sevBadge = s => `<span class="badge ${s}">${s}</span>`;
const clsBadge = c => c === 'confirmed_violation' ? '<span class="badge conf">Confirmed rule violation</span>' : '<span class="badge plain">Observed anomaly</span>';
const nice = t => String(t).replace(/_/g, ' ');

/* ---------- views ---------- */
function show(view) {
  $$('.view').forEach(v => { v.hidden = v.id !== 'v-' + view; });
  const inResults = view !== 'landing';
  $('#tabs').hidden = !inResults || !S.a; $('#reports').hidden = !(S.a && inResults);
  $$('#tabs button').forEach(b => b.setAttribute('aria-selected', String(b.dataset.tab === view)));
  S.tab = view; $('#main').focus({preventScroll: true}); window.scrollTo(0, 0);
}
function buildTabs() {
  $('#tabs').innerHTML = TABS.map(([k, l]) => `<button type="button" role="tab" data-tab="${k}" aria-selected="false">${l}${k === 'faults' && S.a ? ` (${S.a.anomalies.length})` : ''}</button>`).join('');
}
$('#tabs').addEventListener('click', e => { const b = e.target.closest('button[data-tab]'); if (b) go(b.dataset.tab); });
$('#brand').addEventListener('click', () => { closeDrawer(); landing(); });
const RENDER = {overview: rOverview, faults: rFaults, frames: rFrames, signals: rSignals, messages: rMessages, dbc: rDbc, compare: rCompare, history: rHistory};
function go(tab) { closeDrawer(); show(tab); RENDER[tab](); }

/* ---------- landing ---------- */
const RULES_EXAMPLE = `{
  "gap_factor": 3.0,
  "thresholds": [ { "signal": "BMS_Pack.SOC", "min": 5, "max": 98, "severity": "medium" } ],
  "messages": { "BMS_Pack": { "cycle_ms": 100, "required": true } },
  "counters": [ { "message": "Motor_Cmd", "signal": "MC_Counter" } ],
  "checksums": [ { "message": "Motor_Cmd", "signal": "MC_Checksum", "algorithm": "crc8_sae_j1850" } ]
}`;
async function landing() {
  S.a = null; S.id = null; S.dbcOnly = null; show('landing'); $('#tabs').hidden = true; $('#reports').hidden = true;
  $('#rules-example').textContent = RULES_EXAMPLE + '\n\nAvailable checksum algorithms: ' + ((S.info && S.info.checksum_algorithms) || []).join(', ');
  try {
    const items = await api('/api/analyses');
    $('#recent-wrap').hidden = !items.length;
    $('#recent').innerHTML = items.slice(0, 5).map(i => `<div class="row" style="justify-content:space-between;align-items:center;border-bottom:1px solid var(--rule-soft);padding:6px 0">
      <span><b>${esc(i.log_name || '-')}</b> <span class="muted">with ${esc(i.dbc_name || '-')} · ${esc((i.analyzed_at || '').replace('T', ' ').slice(0, 16))} UTC · ${i.findings.high} high, ${i.findings.medium} medium, ${i.findings.low} low</span></span>
      <button type="button" data-open="${i.id}">Open</button></div>`).join('');
  } catch { /* history is optional on the landing page */ }
}
$('#recent').addEventListener('click', e => { const b = e.target.closest('[data-open]'); if (b) openById(b.dataset.open); });
$('#rules-help').addEventListener('click', e => { e.preventDefault(); $('#rules-doc').hidden = !$('#rules-doc').hidden; });

function pick(input) {
  const f = input.files[0], box = input.closest('.drop');
  $('#' + input.id + '-name').textContent = f ? `${f.name} (${(f.size / 1024).toFixed(f.size > 1048576 ? 0 : 1)} KB)` : '';
  box.classList.toggle('has', !!f);
}
$$('.drop input').forEach(inp => {
  inp.addEventListener('change', () => pick(inp));
  const box = inp.closest('.drop');
  ['dragenter', 'dragover'].forEach(t => inp.addEventListener(t, () => box.classList.add('over')));
  ['dragleave', 'drop'].forEach(t => inp.addEventListener(t, () => box.classList.remove('over')));
});
function validate() {
  const dbc = $('#dbc').files[0], log = $('#log').files[0], rules = $('#rules').files[0], lim = S.info || {};
  if (!dbc) return 'Choose a DBC file first.';
  if (!/\.dbc$/i.test(dbc.name)) return 'The database must be a .dbc file.';
  if (dbc.size > (lim.max_dbc_mb || 5) * 1048576) return `The DBC file is larger than ${lim.max_dbc_mb} MB.`;
  if (log && !/\.(asc|log|csv|blf)$/i.test(log.name)) return 'The log must be .asc, .log, .csv or .blf.';
  if (log && log.size > (lim.max_log_mb || 25) * 1048576) return `The log is larger than ${lim.max_log_mb} MB. Trim it first (for example to the time window of interest).`;
  if (rules && !/\.json$/i.test(rules.name)) return 'The rules file must be .json.';
  return '';
}
$('#form').addEventListener('submit', async e => {
  e.preventDefault(); const err = validate(); $('#form-err').textContent = err; if (err) return;
  const fd = new FormData(); const dbc = $('#dbc').files[0], log = $('#log').files[0], rules = $('#rules').files[0];
  fd.append('dbc', dbc); $('#go').disabled = true;
  try {
    if (!log) { S.dbcOnly = await busy('Reading DBC…', api('/api/inspect', {method: 'POST', body: fd})); S.a = null; S.id = null; S.dbc = S.dbcOnly; buildTabs(); showDbcOnly(); return; }
    fd.append('log', log); fd.append('bitrate', $('#bitrate').value); if (rules) fd.append('rules', rules);
    openResult(await busy('Analyzing… large logs can take a few seconds.', api('/api/analyze', {method: 'POST', body: fd})));
  } catch (x) { $('#form-err').textContent = x.message; } finally { $('#go').disabled = false; }
});
$('#sample').addEventListener('click', async () => {
  try { openResult(await busy('Analyzing sample…', api(`/api/sample?name=${encodeURIComponent($('#sample-name').value)}&bitrate=${$('#bitrate').value}`))); }
  catch (x) { $('#form-err').textContent = x.message; }
});
function showDbcOnly() { $('#tabs').innerHTML = '<button type="button" role="tab" data-tab="dbc" aria-selected="true">DBC</button>'; show('dbc'); $('#tabs').hidden = false; rDbc(); }
async function openById(id) { openResult(await busy('Loading analysis…', api('/api/analyses/' + encodeURIComponent(id)))); }
function openResult(r) {
  S.a = r; S.id = r.analysis_id; S.dbc = null; S.dbcOnly = null; S.sg = {name: null, t0: null, t1: null};
  S.f = {sev: 'all', cls: 'all', q: ''}; S.fr = {...S.fr, offset: 0, t0: '', t1: '', can_id: '', fmt: 'any', message: '', q: '', sort: 'idx', order: 'asc'};
  buildTabs(); go('overview');
}
$('#reports').addEventListener('change', async e => {
  const v = e.target.value; e.target.value = ''; if (!v || !S.id) return;
  const [ext, section] = v.split(':');
  try {
    const res = await busy('Preparing report…', api(`/api/analyses/${rid()}/report.${ext}${section ? '?section=' + section : ''}`, {raw: true}));
    const name = /filename="([^"]+)"/.exec(res.headers.get('content-disposition') || '')?.[1] || 'report.' + ext;
    const a = document.createElement('a'); a.href = URL.createObjectURL(await res.blob()); a.download = name;
    document.body.appendChild(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(a.href), 2000);
  } catch { /* shown in status */ }
});

/* ---------- overview ---------- */
function counts() {
  const c = {high: 0, medium: 0, low: 0, confirmed: 0};
  S.a.anomalies.forEach(f => { c[f.severity]++; if (f.classification === 'confirmed_violation') c.confirmed++; });
  return c;
}
function rOverview() {
  const a = S.a, s = a.summary, b = a.bus_load, m = a.meta, c = counts(), el = $('#v-overview');
  const notices = [];
  if (s.skipped_lines) notices.push(`${s.skipped_lines} line(s) of the log looked like frames but could not be parsed and were skipped.`);
  if (s.fd_frames) notices.push(`${s.fd_frames} CAN FD frame(s) were decoded but are excluded from the bus-load estimate.`);
  (m.dbc.warnings || []).forEach(w => notices.push(w));
  Object.entries(m.truncated_findings || {}).forEach(([k, v]) => notices.push(`Findings for ${k} were capped; ${v} more were not listed.`));
  el.innerHTML = `
    <div><h1 style="font-size:22px;max-width:none">${esc(m.log.name)}</h1>
      <p class="muted">Decoded with ${esc(m.dbc.name)} · analysed ${esc(m.analyzed_at.replace('T', ' ').replace(/\+00:00$/, ''))} UTC · software v${esc(m.software_version)} · assumed ${b.bitrate / 1000} kbit/s</p></div>
    ${notices.map(n => `<div class="panel" style="border-color:var(--med)"><b>Note.</b> ${esc(n)}</div>`).join('')}
    <div class="tiles">
      <div class="tile"><b>${s.frames.toLocaleString()}</b><span>data frames</span></div>
      <div class="tile"><b>${num(s.duration_s)} s</b><span>duration</span></div>
      <div class="tile"><b>${s.unique_ids}</b><span>unique CAN IDs</span></div>
      <div class="tile"><b>${s.unknown_ids}</b><span>IDs not in the DBC</span></div>
      <div class="tile"><b>${num(b.avg_pct, 2)}%</b><span>est. avg bus load</span></div>
      <div class="tile"><b>${num(b.peak_pct_worst_case, 2)}%</b><span>peak bus load, upper bound</span></div>
    </div>
    <div class="panel"><h2>Findings</h2>
      ${a.anomalies.length ? `<p>${SEV.map(k => `${sevBadge(k)} ${c[k]}`).join('&nbsp;&nbsp; ')}</p>
      <p class="hint">${c.confirmed} confirmed rule violation(s) and ${a.anomalies.length - c.confirmed} observed anomaly/anomalies. Observed anomalies deviate from an expectation but are not proof of a fault.</p>
      <div class="scroll"><table><thead><tr><th>Severity</th><th>Type</th><th>Where</th><th class="n">Start (s)</th><th>Summary</th><th></th></tr></thead><tbody>
      ${a.anomalies.slice(0, 6).map(f => `<tr class="sev-${f.severity}"><td>${sevBadge(f.severity)}</td><td>${esc(nice(f.type))}</td><td>${esc(f.message)}${f.signal ? '.' + esc(f.signal) : ''}</td><td class="n">${num(f.time)}</td><td>${esc(f.detail)}</td><td><button type="button" data-finding="${f.id}">Investigate</button></td></tr>`).join('')}
      </tbody></table></div>${a.anomalies.length > 6 ? '<p style="margin-top:12px"><button type="button" data-tab-go="faults">See all findings</button></p>' : ''}`
      : '<div class="empty">No findings. Every check that applies to this log passed. Checks that were not configured (counters, checksums) were not run.</div>'}
    </div>
    <div class="grid2">
      <div class="panel"><h2>Estimated bus load</h2>
        <div class="chartbox sm"><canvas id="c-bus" role="img" aria-label="Estimated bus load per second"></canvas></div>
        <div class="legend"><span><span class="sw"></span>Nominal (no bit stuffing)</span><span><span class="sw dash"></span>Upper bound (maximum stuffing)</span></div>
        <p class="hint" style="margin-top:8px">${esc(b.assumptions.join(' '))}</p></div>
      <div class="panel"><h2>Inputs</h2>
        <dl class="kv"><dt>DBC</dt><dd>${esc(m.dbc.name)}</dd><dt>DBC SHA-256</dt><dd>${esc(m.dbc.sha256.slice(0, 16))}…</dd>
        <dt>DBC contents</dt><dd>${m.dbc.messages} messages, ${m.dbc.signals} signals</dd>
        <dt>Log</dt><dd>${esc(m.log.name)} (${esc(m.log.format)}, ${(m.log.size_bytes / 1024).toFixed(0)} KB)</dd>
        <dt>Log SHA-256</dt><dd>${esc(m.log.sha256.slice(0, 16))}…</dd>
        <dt>Remote / error / FD</dt><dd>${s.remote_frames} / ${s.error_frames} / ${s.fd_frames}</dd>
        <dt>Frames decoded</dt><dd>${s.frames_decoded.toLocaleString()}</dd>
        <dt>Rules</dt><dd>gap factor ${m.config.rules.gap_factor}; ${m.config.rules.thresholds.length} threshold(s), ${m.config.rules.counters.length} counter(s), ${m.config.rules.checksums.length} checksum(s)</dd></dl></div>
    </div>
    <details class="fold"><summary>Limitations and assumptions</summary><ul>${a.limitations.map(l => `<li>${esc(l)}</li>`).join('')}</ul></details>`;
  const grid = css('--rule-soft');
  chart('c-bus', {type: 'line', data: {datasets: [
    {label: 'Nominal', data: b.points.map(p => ({x: p[0], y: p[2]})), borderColor: css('--trace'), borderWidth: 1.5, pointRadius: 0, tension: 0},
    {label: 'Upper bound', data: b.worst_case_points.map(p => ({x: p[0], y: p[1]})), borderColor: css('--high'), borderDash: [5, 4], borderWidth: 1, pointRadius: 0, tension: 0}]},
    options: {maintainAspectRatio: false, animation: false, parsing: false, interaction: {mode: 'nearest', intersect: false, axis: 'x'},
      scales: {x: {type: 'linear', title: {display: true, text: 'Time (s)'}, grid: {color: grid}}, y: {beginAtZero: true, title: {display: true, text: '% of capacity'}, grid: {color: grid}}},
      plugins: {legend: {display: false}, tooltip: {callbacks: {label: c => `${c.dataset.label}: ${c.parsed.y.toFixed(2)}%`}}}}});
}
document.addEventListener('click', e => {
  const f = e.target.closest('[data-finding]'); if (f) openFinding(f.dataset.finding);
  const g = e.target.closest('[data-tab-go]'); if (g) go(g.dataset.tabGo);
});

/* ---------- faults ---------- */
function rFaults() {
  const el = $('#v-faults'), F = S.f;
  el.innerHTML = `<h1 style="font-size:22px">Faults and anomalies</h1>
    <div class="toolbar">
      <div class="chips" role="group" aria-label="Filter by severity">${['all', ...SEV].map(k => `<button type="button" data-sev="${k}" aria-pressed="${F.sev === k}">${k === 'all' ? 'All severities' : k}</button>`).join('')}</div>
      <label>Classification<select id="f-cls"><option value="all">All</option><option value="confirmed_violation">Confirmed rule violations</option><option value="observed_anomaly">Observed anomalies</option></select></label>
      <label class="grow">Search<input type="text" id="f-q" placeholder="message, signal, type or text" value="${esc(F.q)}"></label>
    </div><div id="f-list"></div>`;
  $('#f-cls').value = F.cls;
  const draw = () => {
    const q = F.q.toLowerCase();
    const rows = S.a.anomalies.filter(f => (F.sev === 'all' || f.severity === F.sev) && (F.cls === 'all' || f.classification === F.cls)
      && (!q || `${f.message} ${f.signal || ''} ${f.type} ${f.detail}`.toLowerCase().includes(q)));
    $('#f-list').innerHTML = rows.length ? `<div class="scroll"><table><thead><tr><th>Severity</th><th>ID</th><th>Type</th><th>Where</th><th class="n">Start (s)</th><th class="n">End (s)</th><th>Summary</th><th></th></tr></thead><tbody>
      ${rows.map(f => `<tr class="sev-${f.severity}"><td>${sevBadge(f.severity)}</td><td class="m">${f.id}</td><td>${esc(nice(f.type))}<br>${clsBadge(f.classification)}</td>
      <td>${esc(f.message)}${f.signal ? '.' + esc(f.signal) : ''}</td><td class="n">${num(f.time)}</td><td class="n">${num(f.end_time)}</td><td>${esc(f.detail)}</td>
      <td><button type="button" data-finding="${f.id}">Investigate</button></td></tr>`).join('')}</tbody></table></div>`
      : `<div class="empty">${S.a.anomalies.length ? 'No findings match these filters.' : 'No findings in this analysis.'}</div>`;
  };
  draw();
  el.querySelector('.chips').addEventListener('click', e => { const b = e.target.closest('[data-sev]'); if (!b) return; F.sev = b.dataset.sev; $$('.chips button', el).forEach(x => x.setAttribute('aria-pressed', String(x === b))); draw(); });
  $('#f-cls').addEventListener('change', e => { F.cls = e.target.value; draw(); });
  $('#f-q').addEventListener('input', e => { F.q = e.target.value; draw(); });
}

/* ---------- fault investigation drawer ---------- */
let lastFocus = null;
function closeDrawer() { $('#drawer').hidden = true; if (S.charts['c-ev']) { S.charts['c-ev'].destroy(); delete S.charts['c-ev']; } if (lastFocus) { lastFocus.focus?.(); lastFocus = null; } }
$('#drawer-close').addEventListener('click', closeDrawer);
document.addEventListener('keydown', e => { if (e.key === 'Escape' && !$('#drawer').hidden) closeDrawer(); });
async function openFinding(fid) {
  lastFocus = document.activeElement; const d = $('#drawer'); d.hidden = false;
  $('#drawer-title').textContent = 'Finding ' + fid; $('#drawer-body').innerHTML = '<div class="skeleton"></div><div class="skeleton"></div><div class="skeleton"></div>';
  $('#drawer-close').focus();
  let r; try { r = await api(`/api/analyses/${rid()}/findings/${encodeURIComponent(fid)}`); } catch (e) { $('#drawer-body').innerHTML = `<div class="err">${esc(e.message)}</div>`; return; }
  const f = r.finding, ev = Object.entries(f.evidence || {});
  $('#drawer-title').textContent = `${nice(f.type)} · ${f.message}${f.signal ? '.' + f.signal : ''}`;
  $('#drawer-body').innerHTML = `
    <p>${sevBadge(f.severity)} ${clsBadge(f.classification)} <span class="kicker">${f.id} · ${num(f.time)} s${f.end_time > f.time ? ' to ' + num(f.end_time) + ' s' : ''}</span></p>
    <p>${esc(f.detail)}</p>
    <section><h3>How this was detected</h3><p>${esc(f.method)}</p></section>
    <section><h3>Evidence</h3><dl class="kv">${ev.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(typeof v === 'object' ? JSON.stringify(v) : v)}</dd>`).join('')}</dl></section>
    ${f.signal ? `<section><h3>Signal around the event</h3><div class="chartbox sm"><canvas id="c-ev" role="img" aria-label="Signal values around the finding"></canvas></div><p class="hint" id="ev-note"></p></section>` : ''}
    <section><h3>Related frames</h3>${r.related_frames.length ? `<div class="scroll"><table><thead><tr><th class="n">#</th><th class="n">Time (s)</th><th>ID</th><th>Data</th><th>Decoded</th></tr></thead><tbody>
      ${r.related_frames.map(x => `<tr><td class="n m">${x.idx}</td><td class="n m">${num(x.t, 4)}</td><td class="m">${x.id}</td><td class="m">${x.data}</td><td class="m">${x.signals ? esc(Object.entries(x.signals).map(([k, v]) => `${k}=${num(v.value)}`).join(' ')) : esc(x.status)}</td></tr>`).join('')}</tbody></table></div>
      <p class="hint">The nearest frames of the same message before and after the start time.</p>` : '<p class="hint">This finding is not tied to a single message, so no frames are listed.</p>'}
      <p><button type="button" id="ev-frames">Open these in the frame viewer</button> ${f.signal ? '<button type="button" id="ev-signal">Open in signal viewer</button>' : ''}</p></section>
    <section><h3>Possible causes</h3><p class="hint">Hypotheses to check. This tool has not confirmed any of them.</p><ul>${(f.possible_causes || []).map(c => `<li>${esc(c)}</li>`).join('')}</ul></section>`;
  $('#ev-frames').addEventListener('click', () => { Object.assign(S.fr, {message: f.message in msgNames() ? f.message : '', can_id: '', q: '', fmt: 'any', offset: 0,
    t0: String(Math.max(0, f.time - 0.5).toFixed(3)), t1: String((f.end_time + 0.5).toFixed(3))}); go('frames'); });
  $('#ev-signal')?.addEventListener('click', () => { const pad = Math.max(1, (f.end_time - f.time) * 2); S.sg = {name: `${f.message}.${f.signal}`, t0: Math.max(0, f.time - pad), t1: f.end_time + pad}; go('signals'); });
  if (f.signal) {
    const pad = Math.max(1, (f.end_time - f.time) * 2), t0 = Math.max(0, f.time - pad), t1 = f.end_time + pad, name = `${f.message}.${f.signal}`;
    try { const s = await api(`/api/analyses/${rid()}/signal?name=${encodeURIComponent(name)}&t0=${t0}&t1=${t1}&max_points=600`); drawSignal('c-ev', name, s, [f], false); $('#ev-note').textContent = `Shaded: the span of this finding. ${s.samples} samples shown${s.downsampled ? ' as a min/max envelope' : ''}.`; }
    catch (e) { $('#ev-note').textContent = e.message; }
  }
}
const msgNames = () => Object.fromEntries((S.a?.messages || []).map(m => [m.name, 1]));

/* ---------- frames ---------- */
function frQuery() {
  const F = S.fr, p = new URLSearchParams({offset: F.offset, limit: F.limit, sort: F.sort, order: F.order});
  ['t0', 't1', 'can_id', 'message', 'q'].forEach(k => { if (F[k] !== '') p.set(k, F[k]); });
  if (F.fmt !== 'any') p.set('fmt', F.fmt);
  return p.toString();
}
function rFrames() {
  const F = S.fr, el = $('#v-frames');
  el.innerHTML = `<h1 style="font-size:22px">Frames</h1>
    <form id="fr-form" class="toolbar panel">
      <label>From (s)<input type="number" step="any" id="fr-t0" value="${esc(F.t0)}"></label>
      <label>To (s)<input type="number" step="any" id="fr-t1" value="${esc(F.t1)}"></label>
      <label>CAN ID (hex)<input type="text" id="fr-id" placeholder="1A0" value="${esc(F.can_id)}"></label>
      <label>Format<select id="fr-fmt"><option value="any">Any</option><option value="std">11-bit</option><option value="ext">29-bit</option><option value="fd">CAN FD</option></select></label>
      <label>Message<select id="fr-msg"><option value="">Any</option>${S.a.messages.map(m => `<option>${esc(m.name)}</option>`).join('')}</select></label>
      <label class="grow">Search name or payload hex<input type="text" id="fr-q" value="${esc(F.q)}"></label>
      <button class="primary" type="submit">Apply</button><button type="button" id="fr-reset">Reset</button>
    </form><div id="fr-err" class="err" role="alert"></div><div id="fr-out"><div class="skeleton"></div><div class="skeleton"></div></div>`;
  $('#fr-fmt').value = F.fmt; $('#fr-msg').value = F.message;
  $('#fr-form').addEventListener('submit', e => { e.preventDefault(); Object.assign(F, {t0: $('#fr-t0').value, t1: $('#fr-t1').value, can_id: $('#fr-id').value.trim(), fmt: $('#fr-fmt').value, message: $('#fr-msg').value, q: $('#fr-q').value.trim(), offset: 0}); loadFrames(); });
  $('#fr-reset').addEventListener('click', () => { Object.assign(F, {t0: '', t1: '', can_id: '', fmt: 'any', message: '', q: '', offset: 0, sort: 'idx', order: 'asc'}); rFrames(); });
  loadFrames();
}
async function loadFrames() {
  const F = S.fr, out = $('#fr-out'); $('#fr-err').textContent = '';
  let r; try { r = await api(`/api/analyses/${rid()}/frames?${frQuery()}`); } catch (e) { $('#fr-err').textContent = e.message; out.innerHTML = ''; return; }
  const from = r.total ? r.offset + 1 : 0, to = Math.min(r.offset + r.limit, r.total);
  const th = (k, l, cls = '') => `<th class="${cls}"><button type="button" class="sort" data-sort="${k}" ${F.sort === k ? `data-dir="${F.order}"` : ''}>${l}</button></th>`;
  out.innerHTML = r.frames.length ? `<div class="scroll tall"><table><thead><tr>${th('idx', '#', 'n')}${th('t', 'Time (s)', 'n')}${th('id', 'ID')}<th>Format</th>${th('dlc', 'DLC', 'n')}<th>Data</th><th>Message</th><th>Decoded</th></tr></thead><tbody>
    ${r.frames.map(x => `<tr><td class="n m">${x.idx}</td><td class="n m">${num(x.t, 6)}</td><td class="m">${x.id}</td><td>${x.format}${x.remote ? ' remote' : ''}</td><td class="n">${x.dlc}</td><td class="m">${x.data}</td>
    <td>${x.message ? esc(x.message) : '<span class="badge low">not in DBC</span>'}${x.status === 'decode_error' ? ' <span class="badge medium">decode error</span>' : ''}</td>
    <td class="m">${x.signals ? `<details><summary>${Object.keys(x.signals).length} signal(s)</summary>${Object.entries(x.signals).map(([k, v]) => `${esc(k)} = ${esc(num(v.value))} ${esc(v.unit)}`).join('<br>')}</details>` : ''}</td></tr>`).join('')}
    </tbody></table></div>
    <div class="pager"><button type="button" id="pg-prev" ${r.offset === 0 ? 'disabled' : ''}>Previous</button><button type="button" id="pg-next" ${to >= r.total ? 'disabled' : ''}>Next</button>
      <span>${from.toLocaleString()}–${to.toLocaleString()} of ${r.total.toLocaleString()} frames</span>
      <label style="flex-direction:row;align-items:center">Rows <select id="pg-size">${[50, 100, 200, 500].map(n => `<option ${n === F.limit ? 'selected' : ''}>${n}</option>`).join('')}</select></label></div>`
    : '<div class="empty">No frames match these filters.</div>';
  out.querySelectorAll('[data-sort]').forEach(b => b.addEventListener('click', () => { const k = b.dataset.sort; F.order = F.sort === k && F.order === 'asc' ? 'desc' : 'asc'; F.sort = k; F.offset = 0; loadFrames(); }));
  $('#pg-prev')?.addEventListener('click', () => { F.offset = Math.max(0, F.offset - F.limit); loadFrames(); });
  $('#pg-next')?.addEventListener('click', () => { F.offset += F.limit; loadFrames(); });
  $('#pg-size')?.addEventListener('change', e => { F.limit = +e.target.value; F.offset = 0; loadFrames(); });
}

/* ---------- signals ---------- */
function thresholdsFor(name) {
  const [m, s] = name.split('.');
  return (S.a.meta.config.rules.thresholds || []).filter(t => t.signal === `${m}.${s}`);
}
function drawSignal(id, name, s, findings, interactive) {
  const base = S.a.signals[name] || {}, [m, sg] = name.split('.'), lines = [];
  if (base.min != null) lines.push([base.min, 'DBC min']); if (base.max != null) lines.push([base.max, 'DBC max']);
  thresholdsFor(name).forEach(t => { if (t.min != null) lines.push([t.min, 'rule min']); if (t.max != null) lines.push([t.max, 'rule max']); });
  const bands = findings.filter(f => f.message === m && (f.signal === sg || !f.signal)).map(f => [f.time, f.end_time]);
  const plugin = {id: 'bands', beforeDatasetsDraw(c) {
    const {ctx, chartArea: a, scales: {x}} = c; ctx.save(); ctx.fillStyle = css('--high-soft'); ctx.strokeStyle = css('--high');
    bands.forEach(([t0, t1]) => { const x0 = x.getPixelForValue(t0), x1 = Math.max(x.getPixelForValue(t1), x0 + 3); if (x1 < a.left || x0 > a.right) return;
      const l = Math.max(x0, a.left), r = Math.min(x1, a.right); ctx.fillRect(l, a.top, r - l, a.bottom - a.top); ctx.strokeRect(l, a.top, r - l, a.bottom - a.top); });
    ctx.restore(); },
    afterDatasetsDraw(c) { const {ctx, chartArea: a, scales: {y}} = c; ctx.save(); ctx.strokeStyle = css('--high'); ctx.setLineDash([6, 4]); ctx.fillStyle = css('--high'); ctx.font = '11px sans-serif';
      lines.forEach(([v, l]) => { const py = y.getPixelForValue(v); if (py < a.top || py > a.bottom) return; ctx.beginPath(); ctx.moveTo(a.left, py); ctx.lineTo(a.right, py); ctx.stroke(); ctx.fillText(`${l} ${num(v)}`, a.left + 4, py - 3); });
      ctx.restore(); }};
  return chart(id, {type: 'line', plugins: [plugin], data: {datasets: [{label: name, data: s.points.map(p => ({x: p[0], y: p[1]})), borderColor: css('--trace'), borderWidth: 1.4,
      pointRadius: s.points.length < 80 ? 2.5 : 0, stepped: true}]},
    options: {maintainAspectRatio: false, animation: false, parsing: false, interaction: {mode: 'nearest', intersect: false, axis: 'x'},
      scales: {x: {type: 'linear', title: {display: true, text: 'Time (s)'}, grid: {color: css('--rule-soft')}, min: interactive ? s.t0 ?? undefined : undefined, max: interactive ? s.t1 ?? undefined : undefined},
               y: {title: {display: true, text: base.unit || s.unit || ''}, grid: {color: css('--rule-soft')}}},
      plugins: {legend: {display: false}, tooltip: {callbacks: {title: i => `t = ${i[0].parsed.x.toFixed(4)} s`, label: c => `${c.parsed.y} ${s.unit || ''}`}}}}});
}
function rSignals() {
  const a = S.a, names = Object.keys(a.signals).sort(), el = $('#v-signals');
  if (!names.length) { el.innerHTML = '<div class="empty">No signals were decoded from this log, so there is nothing to plot.</div>'; return; }
  if (!S.sg.name || !a.signals[S.sg.name]) {
    const flagged = a.anomalies.find(f => f.signal && a.signals[`${f.message}.${f.signal}`]);
    S.sg = {name: flagged ? `${flagged.message}.${flagged.signal}` : names[0], t0: null, t1: null};
  }
  const byMsg = {}; names.forEach(n => (byMsg[n.split('.')[0]] ||= []).push(n));
  el.innerHTML = `<h1 style="font-size:22px">Signals</h1>
    <div class="panel"><div class="sigbar">
      <label>Signal<select id="sg-name">${Object.entries(byMsg).map(([m, l]) => `<optgroup label="${esc(m)}">${l.map(n => `<option value="${esc(n)}">${esc(n.split('.')[1])}${a.signals[n].unit ? ' (' + esc(a.signals[n].unit) + ')' : ''}</option>`).join('')}</optgroup>`).join('')}</select></label>
      <label>From (s)<input type="number" step="any" id="sg-t0" style="width:110px"></label><label>To (s)<input type="number" step="any" id="sg-t1" style="width:110px"></label>
      <button type="button" id="sg-apply">Apply range</button>
      <span class="chips"><button type="button" id="sg-left" aria-label="Pan left">◀ Pan</button><button type="button" id="sg-right" aria-label="Pan right">Pan ▶</button><button type="button" id="sg-out">Zoom out</button><button type="button" id="sg-reset">Reset</button></span>
    </div><p class="hint" style="margin-top:8px">Drag across the chart to zoom into a time range. The server re-reads the stored frames, so zooming shows full resolution.</p>
    <div class="chartbox" id="sg-box"><canvas id="c-sig" role="img" aria-label="Signal plot"></canvas><div id="sg-sel" hidden style="position:absolute;top:0;bottom:30px;background:rgba(11,110,138,.15);border:1px solid var(--trace);pointer-events:none"></div></div>
    <div class="legend"><span><span class="sw"></span>Signal</span><span><span class="sw dash"></span>DBC / rule limits</span><span><span class="sw band"></span>Span of a finding on this signal or its message</span></div>
    <p class="hint" id="sg-note"></p></div>
    <div class="grid2"><div class="panel"><h2>Statistics for the shown range</h2><div id="sg-stats"></div></div>
    <div class="panel"><h2>Correlation with another signal</h2><div class="sigbar"><label>Other signal<select id="cr-y">${names.map(n => `<option value="${esc(n)}">${esc(n)}</option>`).join('')}</select></label><button type="button" id="cr-go">Correlate</button></div><div id="cr-out" style="margin-top:12px"></div></div></div>`;
  $('#sg-name').value = S.sg.name;
  $('#sg-name').addEventListener('change', e => { S.sg = {name: e.target.value, t0: null, t1: null}; loadSignal(); });
  $('#sg-apply').addEventListener('click', () => { const t0 = $('#sg-t0').value, t1 = $('#sg-t1').value; S.sg.t0 = t0 === '' ? null : +t0; S.sg.t1 = t1 === '' ? null : +t1; if (S.sg.t0 != null && S.sg.t1 != null && S.sg.t1 <= S.sg.t0) { status('"To" must be later than "From".', 'error'); return; } status(''); loadSignal(); });
  $('#sg-reset').addEventListener('click', () => { S.sg.t0 = S.sg.t1 = null; loadSignal(); });
  const span = () => { const d = S.a.summary.duration_s, t0 = S.sg.t0 ?? 0, t1 = S.sg.t1 ?? d; return [t0, t1, d]; };
  $('#sg-out').addEventListener('click', () => { const [t0, t1, d] = span(), w = t1 - t0; S.sg.t0 = Math.max(0, t0 - w / 2); S.sg.t1 = Math.min(d, t1 + w / 2); if (S.sg.t0 === 0 && S.sg.t1 === d) S.sg.t0 = S.sg.t1 = null; loadSignal(); });
  const pan = dir => { const [t0, t1, d] = span(), w = t1 - t0; let n0 = t0 + dir * w / 2; n0 = Math.min(Math.max(0, n0), Math.max(0, d - w)); S.sg.t0 = n0; S.sg.t1 = n0 + w; loadSignal(); };
  $('#sg-left').addEventListener('click', () => pan(-1)); $('#sg-right').addEventListener('click', () => pan(1));
  $('#cr-go').addEventListener('click', correlate);
  dragZoom(); loadSignal();
}
function dragZoom() {
  const cv = $('#c-sig'), sel = $('#sg-sel'); let x0 = null;
  const px = e => e.clientX - cv.getBoundingClientRect().left;
  cv.addEventListener('pointerdown', e => { x0 = px(e); cv.setPointerCapture(e.pointerId); });
  cv.addEventListener('pointermove', e => { if (x0 == null) return; const x1 = px(e); sel.hidden = false; sel.style.left = Math.min(x0, x1) + 'px'; sel.style.width = Math.abs(x1 - x0) + 'px'; });
  cv.addEventListener('pointerup', e => {
    if (x0 == null) return; const x1 = px(e), c = S.charts['c-sig']; sel.hidden = true;
    if (c && Math.abs(x1 - x0) > 6) { const a = c.scales.x.getValueForPixel(Math.min(x0, x1)), b = c.scales.x.getValueForPixel(Math.max(x0, x1)); S.sg.t0 = Math.max(0, a); S.sg.t1 = b; loadSignal(); }
    x0 = null; });
  cv.addEventListener('pointercancel', () => { x0 = null; sel.hidden = true; });
}
async function loadSignal() {
  const {name, t0, t1} = S.sg; $('#sg-name').value = name; $('#sg-t0').value = t0 == null ? '' : +t0.toFixed(4); $('#sg-t1').value = t1 == null ? '' : +t1.toFixed(4);
  const q = new URLSearchParams({name, max_points: 1500}); if (t0 != null) q.set('t0', t0); if (t1 != null) q.set('t1', t1);
  let s; try { s = await api(`/api/analyses/${rid()}/signal?${q}`); } catch (e) { $('#sg-note').textContent = e.message; return; }
  if (!s.points.length) { $('#sg-note').textContent = 'No samples of this signal in the selected range.'; S.charts['c-sig']?.destroy(); return; }
  drawSignal('c-sig', name, s, S.a.anomalies, true);
  $('#sg-note').textContent = s.downsampled ? `${s.samples.toLocaleString()} samples reduced to ${s.points.length} points. Each bucket keeps its minimum and maximum, so spikes remain visible. Zoom in for every sample.` : `All ${s.samples.toLocaleString()} samples are shown.`;
  const st = s.stats; $('#sg-stats').innerHTML = st ? `<dl class="kv"><dt>Samples</dt><dd>${st.count.toLocaleString()}</dd><dt>Min / max</dt><dd>${num(st.min)} / ${num(st.max)} ${esc(s.unit)}</dd><dt>Mean</dt><dd>${num(st.mean)}</dd><dt>Std. deviation</dt><dd>${num(st.std)}</dd>
    <dt>Trend (slope)</dt><dd>${st.slope_per_s == null ? '-' : num(st.slope_per_s, 5) + ' ' + esc(s.unit) + '/s'}</dd></dl><p class="hint" style="margin-top:8px">${esc(s.trend_method)}</p>` : '<p class="hint">No samples.</p>';
}
async function correlate() {
  const y = $('#cr-y').value, {name, t0, t1} = S.sg, q = new URLSearchParams({x: name, y}); if (t0 != null) q.set('t0', t0); if (t1 != null) q.set('t1', t1);
  $('#cr-out').innerHTML = '<div class="skeleton"></div>';
  try { const r = await api(`/api/analyses/${rid()}/correlation?${q}`);
    $('#cr-out').innerHTML = r.r == null ? `<p>${esc(r.note || 'No coefficient available.')}</p>` : `<p><b class="mono" style="font-size:18px">r = ${r.r.toFixed(3)}</b> over ${r.n.toLocaleString()} paired samples</p>`;
    $('#cr-out').insertAdjacentHTML('beforeend', `<p class="hint">${esc(r.method)}</p>`);
  } catch (e) { $('#cr-out').innerHTML = `<div class="err">${esc(e.message)}</div>`; }
}

/* ---------- messages & ECUs ---------- */
function msgHealth(m) {
  const fs = S.a.anomalies.filter(f => f.message === m.name);
  if (!m.count) return {k: 'plain', t: 'not seen', n: fs.length};
  const worst = SEV.find(s => fs.some(f => f.severity === s));
  return worst ? {k: worst, t: worst, n: fs.length} : {k: 'ok', t: 'no findings', n: 0};
}
function rMessages() {
  const a = S.a, el = $('#v-messages'), ecus = {};
  a.messages.forEach(m => (m.senders.length ? m.senders : ['(no sender in DBC)']).forEach(s => { (ecus[s] ||= []).push(m); }));
  el.innerHTML = `<h1 style="font-size:22px">Messages and ECUs</h1>
    <p class="hint" style="max-width:70ch">Status summarises the findings listed under Faults for each message. It describes this log only and is not a verdict on the ECU.</p>
    <div class="panel"><h2>ECUs (transmitters named in the DBC)</h2><div class="scroll"><table><thead><tr><th>ECU</th><th class="n">Messages</th><th class="n">Frames</th><th>Worst finding</th><th class="n">Findings</th></tr></thead><tbody>
    ${Object.entries(ecus).map(([n, ms]) => { const hs = ms.map(msgHealth), worst = SEV.find(s => hs.some(h => h.k === s)); const notSeen = hs.filter(h => h.t === 'not seen').length;
      return `<tr><td>${esc(n)}</td><td class="n">${ms.length}${notSeen ? ` <span class="muted">(${notSeen} not seen)</span>` : ''}</td><td class="n">${ms.reduce((x, m) => x + m.count, 0).toLocaleString()}</td><td>${worst ? sevBadge(worst) : '<span class="badge ok">none</span>'}</td><td class="n">${hs.reduce((x, h) => x + h.n, 0)}</td></tr>`; }).join('')}</tbody></table></div></div>
    <div class="panel"><h2>Message timing</h2><div class="scroll"><table><thead><tr><th>Status</th><th>ID</th><th>Name</th><th class="n">Frames</th><th class="n">Expected (ms)</th><th>Expected from</th><th class="n">Mean (ms)</th><th class="n">Jitter (ms)</th><th class="n">Max gap (ms)</th><th class="n">Gaps</th><th></th></tr></thead><tbody>
    ${a.messages.map(m => { const h = msgHealth(m); return `<tr><td><span class="badge ${h.k}">${h.t}</span></td><td class="m">${m.id}${m.extended ? ' (29-bit)' : ''}</td><td>${esc(m.name)}</td><td class="n">${m.count.toLocaleString()}</td>
      <td class="n">${num(m.expected_ms)}</td><td>${esc(m.expected_source ? nice(m.expected_source) : '-')}</td><td class="n">${num(m.avg_ms)}</td><td class="n">${num(m.jitter_ms)}</td><td class="n">${num(m.max_gap_ms)}</td><td class="n">${m.gaps}</td>
      <td>${h.n ? `<button type="button" data-msg-faults="${esc(m.name)}">${h.n} finding(s)</button>` : ''}</td></tr>`; }).join('')}</tbody></table></div>
      <p class="hint" style="margin-top:8px">Mean and jitter exclude gaps. "log median estimate" means the DBC gives no cycle time, so the expected period was inferred from this log.</p></div>`;
  el.addEventListener('click', e => { const b = e.target.closest('[data-msg-faults]'); if (b) { S.f = {sev: 'all', cls: 'all', q: b.dataset.msgFaults}; go('faults'); } }, {once: true});
}

/* ---------- DBC ---------- */
async function rDbc() {
  const el = $('#v-dbc');
  if (!S.dbc) { el.innerHTML = '<div class="skeleton"></div><div class="skeleton"></div>'; try { S.dbc = await api(`/api/analyses/${rid()}/dbc`); } catch (e) { el.innerHTML = `<div class="err">${esc(e.message)}</div>`; return; } }
  const d = S.dbc;
  el.innerHTML = `<h1 style="font-size:22px">DBC browser</h1>
    <p class="muted">${d.summary.messages} messages, ${d.summary.signals} signals${d.summary.nodes.length ? ', nodes: ' + esc(d.summary.nodes.join(', ')) : ''}</p>
    ${d.summary.warnings.map(w => `<div class="panel" style="border-color:var(--med)">${esc(w)}</div>`).join('')}
    ${S.dbcOnly ? '<div class="panel">Only the DBC was loaded. Add a CAN log on the start page to run an analysis.</div>' : ''}
    <label style="max-width:360px">Search messages and signals<input type="text" id="dbc-q" placeholder="name, or ID such as 1A0"></label><div id="dbc-list" class="panel"></div>`;
  const draw = () => { const q = $('#dbc-q').value.toLowerCase().trim();
    const ms = d.messages.filter(m => !q || m.name.toLowerCase().includes(q) || m.id.toLowerCase().includes(q.replace(/^0x/, '0x')) || m.signals.some(s => s.name.toLowerCase().includes(q)));
    $('#dbc-list').innerHTML = ms.length ? ms.map(m => `<details class="msg" ${q && ms.length < 6 ? 'open' : ''}><summary><b>${esc(m.name)}</b><span class="mono">${m.id}</span><span>${m.extended ? '29-bit' : '11-bit'}${m.fd ? ' · FD' : ''}${m.multiplexed ? ' · multiplexed' : ''}</span><span class="muted">${m.dlc} bytes · ${m.cycle_ms ? m.cycle_ms + ' ms' : 'no cycle time'} · ${esc(m.senders.join(', ') || 'no sender')}</span></summary>
      <div class="scroll"><table><thead><tr><th>Signal</th><th class="n">Start</th><th class="n">Bits</th><th>Order</th><th>Sign</th><th class="n">Scale</th><th class="n">Offset</th><th>Range</th><th>Unit</th><th>Mux</th><th>Values</th></tr></thead><tbody>
      ${m.signals.map(s => `<tr><td>${esc(s.name)}</td><td class="n">${s.start}</td><td class="n">${s.length}</td><td>${s.byte_order === 'little_endian' ? 'Intel' : 'Motorola'}</td><td>${s.signed ? 'signed' : 'unsigned'}</td><td class="n">${num(s.scale)}</td><td class="n">${num(s.offset)}</td>
      <td class="m">${s.min == null && s.max == null ? '-' : `${num(s.min)} … ${num(s.max)}`}</td><td>${esc(s.unit)}</td><td>${s.multiplexer ? 'selector' : s.mux_ids ? 'when = ' + esc(s.mux_ids.join(',')) : ''}</td><td class="m">${s.choices ? esc(Object.entries(s.choices).map(([k, v]) => `${k}=${v}`).join(', ')) : ''}</td></tr>`).join('')}</tbody></table></div></details>`).join('') : '<div class="empty">Nothing in the DBC matches that search.</div>'; };
  $('#dbc-q').addEventListener('input', draw); draw();
}

/* ---------- compare ---------- */
async function rCompare() {
  const el = $('#v-compare'); el.innerHTML = '<div class="skeleton"></div>';
  try { S.history = await api('/api/analyses'); } catch (e) { el.innerHTML = `<div class="err">${esc(e.message)}</div>`; return; }
  const opt = i => `<option value="${i.id}">${esc(i.log_name)} · ${esc((i.analyzed_at || '').replace('T', ' ').slice(0, 16))}</option>`;
  if (S.history.length < 2) { el.innerHTML = '<h1 style="font-size:22px">Compare two logs</h1><div class="empty">Comparison needs two analyses. Analyze another log (or load the clean advanced sample next to the faulty one), then come back.</div>'; return; }
  el.innerHTML = `<h1 style="font-size:22px">Compare two logs</h1><div class="panel"><div class="sigbar">
    <label>Log A<select id="cmp-a">${S.history.map(opt).join('')}</select></label><label>Log B<select id="cmp-b">${S.history.map(opt).join('')}</select></label><button class="primary" id="cmp-go" type="button">Compare</button></div></div><div id="cmp-out"></div>`;
  $('#cmp-a').value = S.id; $('#cmp-b').selectedIndex = S.history.findIndex(i => i.id !== S.id);
  $('#cmp-go').addEventListener('click', async () => {
    const a = $('#cmp-a').value, b = $('#cmp-b').value; if (a === b) { $('#cmp-out').innerHTML = '<div class="empty">Choose two different analyses.</div>'; return; }
    let c; try { c = await busy('Comparing…', api(`/api/compare?a=${a}&b=${b}`)); } catch { return; }
    const lab = {only_in_a: 'only in A', only_in_b: 'only in B', in_both: 'in both'};
    $('#cmp-out').innerHTML = `${c.notes.map(n => `<div class="panel" style="border-color:var(--med)">${esc(n)}</div>`).join('')}
      <div class="panel"><h2>Findings</h2>${c.findings.length ? `<div class="scroll"><table><thead><tr><th>Status</th><th>Type</th><th>Message</th><th>Signal</th><th class="n">In A</th><th class="n">In B</th></tr></thead><tbody>${c.findings.map(f => `<tr><td><span class="badge ${f.status === 'in_both' ? 'plain' : f.status === 'only_in_a' ? 'medium' : 'low'}">${lab[f.status]}</span></td><td>${esc(nice(f.type))}</td><td>${esc(f.message)}</td><td>${esc(f.signal || '')}</td><td class="n">${f.count_a}</td><td class="n">${f.count_b}</td></tr>`).join('')}</tbody></table></div>` : '<div class="empty">Neither log has findings.</div>'}</div>
      <div class="panel"><h2>Messages</h2><div class="scroll"><table><thead><tr><th>Message</th><th class="n">Frames A</th><th class="n">Frames B</th><th class="n">Mean ms A</th><th class="n">Mean ms B</th><th class="n">Δ mean ms</th><th class="n">Gaps A</th><th class="n">Gaps B</th></tr></thead><tbody>
      ${c.messages.map(m => `<tr><td>${esc(m.name)}${m.extended ? ' (29-bit)' : ''}</td><td class="n">${num(m.count_a)}</td><td class="n">${num(m.count_b)}</td><td class="n">${num(m.avg_ms_a)}</td><td class="n">${num(m.avg_ms_b)}</td><td class="n">${num(m.avg_ms_delta)}</td><td class="n">${num(m.gaps_a)}</td><td class="n">${num(m.gaps_b)}</td></tr>`).join('')}</tbody></table></div></div>
      <div class="panel"><h2>Signals</h2><div class="scroll tall"><table><thead><tr><th>Signal</th><th class="n">Min A</th><th class="n">Min B</th><th class="n">Max A</th><th class="n">Max B</th><th class="n">Mean A</th><th class="n">Mean B</th><th class="n">Δ mean</th></tr></thead><tbody>
      ${c.signals.map(s => `<tr><td>${esc(s.name)}${s.present_a && s.present_b ? '' : ` <span class="badge low">${s.present_a ? 'only in A' : 'only in B'}</span>`}</td><td class="n">${num(s.min_a)}</td><td class="n">${num(s.min_b)}</td><td class="n">${num(s.max_a)}</td><td class="n">${num(s.max_b)}</td><td class="n">${num(s.mean_a)}</td><td class="n">${num(s.mean_b)}</td><td class="n">${num(s.mean_delta)}</td></tr>`).join('')}</tbody></table></div></div>
      <p class="hint">${esc(c.method)}</p>`;
  });
}

/* ---------- history ---------- */
async function rHistory() {
  const el = $('#v-history'); el.innerHTML = '<div class="skeleton"></div><div class="skeleton"></div>';
  try { S.history = await api('/api/analyses'); } catch (e) { el.innerHTML = `<div class="err">${esc(e.message)}</div>`; return; }
  el.innerHTML = `<h1 style="font-size:22px">Analysis history</h1><p class="hint">Stored on the server that runs this app (newest ${(S.info && S.info.max_analyses) || 25} are kept). Delete an analysis to remove its decoded frames.</p>
    ${S.history.length ? `<div class="scroll"><table><thead><tr><th>Analysed (UTC)</th><th>Log</th><th>DBC</th><th class="n">Frames</th><th>Findings</th><th></th></tr></thead><tbody>
    ${S.history.map(i => `<tr><td class="m">${esc((i.analyzed_at || '').replace('T', ' ').replace(/\+00:00$/, ''))}</td><td>${esc(i.log_name)}</td><td>${esc(i.dbc_name)}</td><td class="n">${(i.frames ?? 0).toLocaleString()}</td>
    <td>${i.findings.high} high · ${i.findings.medium} medium · ${i.findings.low} low</td><td><button type="button" data-open="${i.id}">Open</button> <button type="button" data-del="${i.id}">Delete</button></td></tr>`).join('')}</tbody></table></div>` : '<div class="empty">No stored analyses.</div>'}`;
  el.onclick = async e => {
    const o = e.target.closest('[data-open]'), d = e.target.closest('[data-del]');
    if (o) openById(o.dataset.open);
    if (d && confirm('Delete this analysis and its stored frames?')) { try { await api('/api/analyses/' + encodeURIComponent(d.dataset.del), {method: 'DELETE'}); if (d.dataset.del === S.id) { landing(); return; } rHistory(); } catch { /* shown in status */ } }
  };
}

/* ---------- start ---------- */
(async function init() {
  try {
    const gate = await fetch('/api/auth-check').then(r => r.json());
    if (gate.auth_required && !S.token) await askToken();
    S.info = await api('/api/info'); $('#version').textContent = 'v' + S.info.version;
  } catch (e) { status('Could not reach the API: ' + e.message, 'error'); }
  landing();
})();
