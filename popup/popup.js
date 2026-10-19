// ============================================================================
// PayloadForge — popup UI
// Reuses PAYLOADS / WAF_PROFILES / MUTATION_LABELS / mutate / applyPlaceholders
// from lib/payloads.js. No inline event handlers (MV3 CSP compliant).
// ============================================================================

const api = typeof browser !== 'undefined' ? browser : chrome;

// ── STATE ─────────────────────────────────────────────────────────────────────
const S = {
  cat: 'XSS',
  tab: 'library',
  search: '',
  pid: '',
  customPayload: '',
  mutResults: [],
  selMuts: new Set(),
  waf: '',
  filter: 'all',          // 'all' | 'fav' | 'recent'
  favs: new Set(),        // payload ids
  recent: [],             // payload ids, most-recent first
  placeholders: {},       // { TARGET, ATTACKER, OAST }
};

// ── UTILS ──────────────────────────────────────────────────────────────────────
function h(s) {
  return String(s)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

function ph(text) { return applyPlaceholders(text, S.placeholders); }

function toast(msg, color) {
  let t = document.getElementById('pf-toast');
  if (!t) {
    t = document.createElement('div');
    t.id = 'pf-toast';
    document.body.appendChild(t);
  }
  t.textContent = msg;
  t.style.borderColor = color || 'var(--green)';
  t.style.color = color || 'var(--green)';
  t.classList.add('show');
  clearTimeout(t._tm);
  t._tm = setTimeout(() => t.classList.remove('show'), 1600);
}

function flashBtn(btn, label) {
  if (!btn) return;
  const orig = btn.textContent;
  btn.textContent = label;
  btn.style.borderColor = 'var(--green)';
  btn.style.color = 'var(--green)';
  setTimeout(() => { btn.textContent = orig; btn.style.borderColor = ''; btn.style.color = ''; }, 1400);
}

function copyText(text, btn, label) {
  const done = () => { if (btn) flashBtn(btn, label || 'COPIED'); else toast('Copied'); };
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).then(done).catch(() => fallbackCopy(text, done));
  } else { fallbackCopy(text, done); }
}

function fallbackCopy(text, done) {
  const ta = document.createElement('textarea');
  ta.value = text; ta.style.cssText = 'position:fixed;opacity:0';
  document.body.appendChild(ta); ta.select();
  try { document.execCommand('copy'); } catch (_) {}
  document.body.removeChild(ta);
  done();
}

function download(content, filename, mime) {
  const blob = new Blob([content], { type: mime });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url; a.download = filename; a.click();
  URL.revokeObjectURL(url);
}

// ── INJECTION BRIDGE ────────────────────────────────────────────────────────────
function injectIntoActiveTab(text, btn) {
  api.runtime.sendMessage({ type: 'inject', text }).then((res) => {
    if (res && res.ok) {
      if (btn) flashBtn(btn, 'INSERTED');
      else toast('Inserted into ' + res.where);
    } else {
      const reason = res && res.reason === 'no-editable-field'
        ? 'Click a text field in the page first'
        : (res && res.reason) || 'Injection failed';
      toast(reason, 'var(--red)');
    }
  }).catch((e) => toast('Injection failed: ' + e.message, 'var(--red)'));
}

// ── STORAGE ──────────────────────────────────────────────────────────────────────
async function loadStore() {
  try {
    const d = await api.storage.local.get(['pf_favs', 'pf_recent', 'pf_placeholders']);
    S.favs = new Set(d.pf_favs || []);
    S.recent = d.pf_recent || [];
    S.placeholders = d.pf_placeholders || {};
  } catch (_) {}
}
function saveFavs() { api.storage.local.set({ pf_favs: [...S.favs] }); }
function saveRecent() { api.storage.local.set({ pf_recent: S.recent.slice(0, 15) }); }
function savePlaceholders() { api.storage.local.set({ pf_placeholders: S.placeholders }); }

function pushRecent(id) {
  S.recent = [id, ...S.recent.filter((x) => x !== id)].slice(0, 15);
  saveRecent();
}

// ── DATA HELPERS ───────────────────────────────────────────────────────────────
function findPayload(id) {
  for (const list of Object.values(PAYLOADS))
    for (const p of list) if (p.id === id) return p;
  return null;
}

function getFilteredPayloads() {
  let list;
  if (S.filter === 'fav') {
    list = [];
    for (const arr of Object.values(PAYLOADS))
      for (const p of arr) if (S.favs.has(p.id)) list.push(p);
  } else if (S.filter === 'recent') {
    list = S.recent.map(findPayload).filter(Boolean);
  } else {
    list = PAYLOADS[S.cat] || [];
  }
  if (!S.search) return list;
  const q = S.search.toLowerCase();
  return list.filter((p) =>
    p.name.toLowerCase().includes(q) ||
    p.tags.some((t) => t.includes(q)) ||
    p.payload.toLowerCase().includes(q));
}

// ── RENDER: header / filters / sidebar ──────────────────────────────────────────
function renderCatTabs() {
  document.getElementById('cat-tabs').innerHTML = Object.keys(PAYLOADS).map((cat) =>
    `<button class="cat-btn${S.cat === cat && S.filter === 'all' ? ' active' : ''}" data-act="cat" data-cat="${h(cat)}">${h(cat)}</button>`
  ).join('');
}

function renderFilters() {
  const f = [['all', 'ALL'], ['fav', '★ FAV'], ['recent', '⟲ RECENT']];
  document.getElementById('filter-chips').innerHTML = f.map(([k, lbl]) =>
    `<button class="fchip${S.filter === k ? ' active' : ''}" data-act="filter" data-f="${k}">${lbl}</button>`
  ).join('');
}

function renderSidebar() {
  const filtered = getFilteredPayloads();
  const scope = S.filter === 'fav' ? 'favorites' : S.filter === 'recent' ? 'recent' : S.cat;
  const total = S.filter === 'all' ? (PAYLOADS[S.cat] || []).length : filtered.length;
  document.getElementById('sidebar-meta').textContent = `${filtered.length}/${total} — ${scope}`;

  if (!filtered.length) {
    document.getElementById('payload-list').innerHTML =
      `<div class="side-empty">${S.filter === 'fav' ? 'No favorites yet — tap ☆ on a payload' : S.filter === 'recent' ? 'No recent payloads yet' : 'No matches'}</div>`;
    return;
  }

  document.getElementById('payload-list').innerHTML = filtered.map((p) =>
    `<div class="payload-card${S.pid === p.id ? ' active' : ''}">
      <a class="pc-main" href="#" data-act="select" data-id="${h(p.id)}">
        <div class="pname">${h(p.name)}<span class="sbadge ${p.source === 'PATT' ? 'spatt' : 'spf'}">${h(p.source)}</span></div>
        <div class="ppreview">${h(p.payload)}</div>
        <div class="tags">${p.tags.map((t) => `<span class="tag">${h(t)}</span>`).join('')}</div>
      </a>
      <button class="fav-btn${S.favs.has(p.id) ? ' on' : ''}" data-act="fav" data-id="${h(p.id)}" title="Toggle favorite">${S.favs.has(p.id) ? '★' : '☆'}</button>
    </div>`
  ).join('');
}

// ── RENDER: tabs ────────────────────────────────────────────────────────────────
function renderTabNav() {
  const tabs = ['library', 'custom', 'mutations'];
  document.getElementById('tab-nav').innerHTML = tabs.map((t) =>
    `<button class="tab-btn${S.tab === t ? ' active' : ''}" data-act="tab" data-tab="${t}">${t.toUpperCase()}</button>`
  ).join('');
}

function renderTabContent() {
  const el = document.getElementById('tab-content');
  if (S.tab === 'library') { el.innerHTML = buildLibrary(); return; }
  if (S.tab === 'custom') { el.innerHTML = buildCustom(); syncEditor(); return; }
  if (S.tab === 'mutations') { el.innerHTML = buildMutations(); return; }
}

function renderAll() {
  renderCatTabs();
  renderFilters();
  renderSidebar();
  renderTabNav();
  renderTabContent();
}

// ── LIBRARY TAB ──────────────────────────────────────────────────────────────────
function buildLibrary() {
  const list = getFilteredPayloads();
  const title = S.filter === 'fav' ? 'Favorites' : S.filter === 'recent' ? 'Recent' : `${S.cat} payloads`;
  const cards = list.map((p) =>
    `<div class="lib-card">
      <div class="lname">
        <span>${h(p.name)}<span class="sbadge ${p.source === 'PATT' ? 'spatt' : 'spf'}">${h(p.source)}</span></span>
        <button class="fav-btn${S.favs.has(p.id) ? ' on' : ''}" data-act="fav" data-id="${h(p.id)}">${S.favs.has(p.id) ? '★' : '☆'}</button>
      </div>
      <div class="lib-payload">${h(p.payload)}</div>
      <div class="tags">${p.tags.map((t) => `<span class="tag">${h(t)}</span>`).join('')}</div>
      <div class="lib-actions">
        <button class="mini-btn" data-act="select" data-id="${h(p.id)}">EDIT →</button>
        <button class="mini-btn" data-act="copy" data-v="${h(ph(p.payload))}">COPY</button>
        <button class="mini-btn inj" data-act="inject" data-v="${h(ph(p.payload))}">⇥ INSERT</button>
      </div>
    </div>`
  ).join('');
  return `<div class="lib-header">
    <h2>${h(title)}</h2>
    <p><span style="color:var(--green);opacity:.7">■ PATT</span> = PayloadsAllTheThings &nbsp;
       <span style="color:var(--orange);opacity:.7">■ PF</span> = PayloadForge original</p>
  </div>
  <div class="lib-grid">${cards || '<div class="side-empty">Nothing here yet.</div>'}</div>`;
}

// ── CUSTOM TAB ──────────────────────────────────────────────────────────────────
function buildCustom() {
  if (S.cat === 'JWT') return buildJwtEditor();
  if (S.cat === 'Clickjacking') return buildClickjacking();
  return buildMutationForm();
}

function buildMutationForm() {
  const sel = S.pid ? findPayload(S.pid) : null;
  const loaded = sel
    ? `<div class="loaded-info">LOADED: <span>${h(sel.name)}</span> <span class="sbadge ${sel.source === 'PATT' ? 'spatt' : 'spf'}">${h(sel.source)}</span></div>`
    : '';
  const wafChips = Object.keys(WAF_PROFILES).map((w) =>
    `<button type="button" class="chip${S.waf === w ? ' aw' : ''}" data-waf="${h(w)}">${h(w)}</button>`
  ).join('') + `<button type="button" class="chip cc" data-act="clearwaf">CLEAR</button>`;
  const mutChips = Object.entries(MUTATION_LABELS).map(([k, v]) =>
    `<button type="button" class="chip${S.selMuts.has(k) ? ' am' : ''}" data-mut="${h(k)}">${h(v)}</button>`
  ).join('');
  const wafNote = S.waf ? `→ ${WAF_PROFILES[S.waf].join(', ')}` : '';
  return `${loaded}
    <label class="slabel">PAYLOAD EDITOR</label>
    <textarea id="payload-editor" rows="4" placeholder="Paste or type your payload...">${h(S.customPayload)}</textarea>
    <div class="editor-actions">
      <button type="button" class="mini-btn" data-act="copy-editor">COPY</button>
      <button type="button" class="mini-btn inj" data-act="inject-editor">⇥ INSERT IN PAGE</button>
    </div>
    <label class="slabel">WAF BYPASS PROFILE</label>
    <div class="chip-group" id="waf-chips">${wafChips}</div>
    <div class="waf-note" id="waf-note">${wafNote}</div>
    <label class="slabel">MUTATIONS <span style="color:var(--t3)">— toggle to customize (none = all)</span></label>
    <div class="chip-group" id="mut-chips">${mutChips}</div>
    <button type="button" class="gen-btn" data-act="gen">✓ GENERATE MUTATIONS</button>`;
}

function syncEditor() {
  const ta = document.getElementById('payload-editor');
  if (ta) ta.addEventListener('input', () => { S.customPayload = ta.value; });
}

function clearWaf() {
  S.waf = '';
  S.selMuts.clear();
  renderTabContent();
}

function generateMutations() {
  const ta = document.getElementById('payload-editor');
  if (ta) S.customPayload = ta.value;
  const muts = S.selMuts.size > 0 ? [...S.selMuts] : Object.keys(MUTATION_LABELS);
  S.mutResults = muts
    .filter((m) => MUTATION_LABELS[m])
    .map((m) => ({ type: m, label: MUTATION_LABELS[m], result: mutate(S.customPayload, m) }));
  S.tab = 'mutations';
  renderTabNav();
  renderTabContent();
}

// ── MUTATIONS TAB ────────────────────────────────────────────────────────────────
function buildMutations() {
  if (!S.mutResults.length) {
    return `<div class="empty"><div class="ei">⚡</div><p>NO MUTATIONS YET</p><small>Go to CUSTOM → Generate Mutations</small></div>`;
  }
  const rows = S.mutResults.map((r) =>
    `<div class="mut-row">
      <div class="mut-lbl">${h(r.label)}</div>
      <div class="mut-val" title="${h(r.result)}" data-act="copy" data-v="${h(r.result)}">${h(r.result)}</div>
      <button class="copy-btn" data-act="copy" data-v="${h(r.result)}">COPY</button>
      <button class="copy-btn inj" data-act="inject" data-v="${h(r.result)}">⇥</button>
    </div>`
  ).join('');
  return `<div class="mut-header">
    <div class="mut-count">${S.mutResults.length} MUTATIONS</div>
    <div class="export-btns">
      <button class="exp-btn" data-act="export" data-fmt="txt">↓ .TXT</button>
      <button class="exp-btn" data-act="export" data-fmt="json">↓ .JSON</button>
    </div>
  </div>
  <div class="base-label">BASE: <span>${h(S.customPayload)}</span></div>
  <div class="mut-list">${rows}</div>`;
}

function exportMutations(fmt) {
  if (fmt === 'txt') {
    const c = S.mutResults.map((r) => `# ${r.label}\n${r.result}`).join('\n\n');
    download(c, 'payloads.txt', 'text/plain');
  } else {
    download(JSON.stringify(S.mutResults, null, 2), 'payloads.json', 'application/json');
  }
}

// ── JWT EDITOR ────────────────────────────────────────────────────────────────────
function buildJwtEditor() {
  return `<div class="jwt-editor">
    <div class="jp">
      <div class="jpt">JWT DECODER / FORGER</div>
      <label class="slabel">PASTE JWT TOKEN</label>
      <textarea class="jta" id="jwtInput" rows="3" placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."></textarea>
      <div style="margin-top:8px;display:flex;gap:8px;flex-wrap:wrap;align-items:center">
        <button type="button" class="jbtn" data-act="jwt-decode">↓ DECODE</button>
        <div id="jwtAlgBadge"></div>
      </div>
    </div>
    <div class="jrow">
      <div class="jp"><div class="jpt">HEADER</div>
        <textarea class="jta" id="jwtHeader" rows="5" placeholder='{"alg":"HS256","typ":"JWT"}'></textarea></div>
      <div class="jp"><div class="jpt">PAYLOAD / CLAIMS</div>
        <textarea class="jta" id="jwtPayload" rows="5" placeholder='{"sub":"user","role":"user","iat":1700000000}'></textarea></div>
    </div>
    <div class="jp">
      <div class="jpt">QUICK ATTACKS</div>
      <div class="jatk">
        <button type="button" class="jatkbtn" data-act="jwt-attack" data-atk="algnone">● Set alg: none (unsigned)</button>
        <button type="button" class="jatkbtn" data-act="jwt-attack" data-atk="admin">● Escalate role to admin</button>
        <button type="button" class="jatkbtn" data-act="jwt-attack" data-atk="exp">● Remove expiry</button>
        <button type="button" class="jatkbtn" data-act="jwt-attack" data-atk="isadmin">● Inject isAdmin: true</button>
        <button type="button" class="jatkbtn" data-act="jwt-attack" data-atk="kidnull">● kid: ../../dev/null traversal</button>
        <button type="button" class="jatkbtn" data-act="jwt-attack" data-atk="kidsqli">● kid: SQL injection</button>
      </div>
    </div>
    <div class="jp">
      <div class="jpt">FORGE TOKEN</div>
      <p style="font-size:10px;color:var(--t3);margin-bottom:10px;">
        Rebuilds token with modified header/payload. Signature will be
        <span style="color:var(--red)">INVALID</span> unless the server accepts alg:none or you have the secret.</p>
      <div style="display:flex;gap:7px;flex-wrap:wrap">
        <button type="button" class="jbtn" data-act="jwt-forge" data-none="0">✓ FORGE (keep sig)</button>
        <button type="button" class="jbtn" style="border-color:var(--red);color:var(--red)" data-act="jwt-forge" data-none="1">● FORGE alg:none</button>
        <button type="button" class="jbtn" style="border-color:var(--orange);color:var(--orange)" data-act="jwt-copy">↓ COPY TOKEN</button>
      </div>
      <div class="jforged" id="jwtForged"></div>
    </div>
  </div>`;
}

function b64ud(s) {
  s = s.replace(/-/g, '+').replace(/_/g, '/');
  while (s.length % 4) s += '=';
  try { return atob(s); } catch (e) { return null; }
}
function b64ue(s) {
  return btoa(unescape(encodeURIComponent(s))).replace(/\+/g, '-').replace(/\//g, '_').replace(/=/g, '');
}
function decodeJwt() {
  const raw = (document.getElementById('jwtInput').value || '').trim();
  const parts = raw.split('.');
  if (parts.length !== 3) { toast('Invalid JWT: expected 3 parts', 'var(--red)'); return; }
  try {
    const hd = JSON.parse(b64ud(parts[0]));
    const pd = JSON.parse(b64ud(parts[1]));
    document.getElementById('jwtHeader').value = JSON.stringify(hd, null, 2);
    document.getElementById('jwtPayload').value = JSON.stringify(pd, null, 2);
    const alg = (hd.alg || '').toUpperCase();
    let cls = 'jhs', warn = '';
    if (alg === 'NONE' || alg === '') { cls = 'jnone'; warn = ' — UNSIGNED'; }
    else if (alg[0] === 'R' || alg[0] === 'E') { cls = 'jrs'; }
    document.getElementById('jwtAlgBadge').innerHTML =
      `<span class="jbadge ${cls}">alg: ${h(alg || 'none')}${warn}</span>` +
      `<span style="font-size:9px;color:var(--t3);margin-left:6px">sig: ${h(parts[2].substring(0, 16))}...</span>`;
  } catch (e) { toast('Decode failed: ' + e.message, 'var(--red)'); }
}
function jwtAttack(type) {
  let hd, pd;
  try { hd = JSON.parse(document.getElementById('jwtHeader').value || '{}'); } catch (e) { hd = {}; }
  try { pd = JSON.parse(document.getElementById('jwtPayload').value || '{}'); } catch (e) { pd = {}; }
  if (type === 'algnone') hd.alg = 'none';
  else if (type === 'admin') { pd.role = 'admin'; pd.isAdmin = true; pd.admin = true; }
  else if (type === 'exp') { pd.exp = 9999999999; pd.iat = Math.floor(Date.now() / 1000); }
  else if (type === 'isadmin') { pd.isAdmin = true; pd.is_admin = true; pd.admin = 1; }
  else if (type === 'kidnull') { hd.kid = '../../dev/null'; hd.alg = 'HS256'; }
  else if (type === 'kidsqli') { hd.kid = "x' UNION SELECT 'secret'-- -"; hd.alg = 'HS256'; }
  document.getElementById('jwtHeader').value = JSON.stringify(hd, null, 2);
  document.getElementById('jwtPayload').value = JSON.stringify(pd, null, 2);
}
function forgeJwt(algNone) {
  let hd, pd;
  try { hd = JSON.parse(document.getElementById('jwtHeader').value); } catch (e) { toast('Invalid header JSON', 'var(--red)'); return; }
  try { pd = JSON.parse(document.getElementById('jwtPayload').value); } catch (e) { toast('Invalid payload JSON', 'var(--red)'); return; }
  if (algNone) hd.alg = 'none';
  const token = b64ue(JSON.stringify(hd)) + '.' + b64ue(JSON.stringify(pd)) + '.' + (algNone ? '' : 'REPLACE_WITH_REAL_SIGNATURE');
  const el = document.getElementById('jwtForged');
  el.textContent = token; el.style.display = 'block'; el._value = token;
}
function copyForged() {
  const el = document.getElementById('jwtForged');
  if (!el || el.style.display === 'none') { toast('Generate a token first', 'var(--red)'); return; }
  copyText(el._value || el.textContent, null);
}

// ── CLICKJACKING ──────────────────────────────────────────────────────────────────
let _ovOn = false;
function buildClickjacking() {
  const sel = S.pid ? findPayload(S.pid) : null;
  return `<div class="cj-wrap">
    <div>
      <div style="font-size:11px;color:var(--t3);letter-spacing:1px;margin-bottom:6px;text-transform:uppercase">Clickjacking Demo Tool</div>
      <p class="cj-desc">Test if a site can be embedded in an iframe.
        <strong style="color:var(--red)">Vulnerable</strong> = iframe loads (no X-Frame-Options / CSP frame-ancestors).<br>
        <strong style="color:var(--green)">Protected</strong> = browser blocks the load.</p>
    </div>
    <div class="cj-row">
      <input type="text" class="cj-inp" id="cjDomain" placeholder="https://example.com" value="https://example.com">
      <button type="button" class="cj-btn" data-act="cj-test">TEST</button>
      <button type="button" class="cj-btn sec" data-act="cj-overlay">OVERLAY</button>
    </div>
    <div class="cj-box" id="cjResult" style="display:none">
      <div class="cj-bar" id="cjBar">
        <span id="cjDot">●</span>&nbsp;<span id="cjTxt">TESTING...</span>
        <span id="cjHdr" style="margin-left:auto;font-size:9px"></span>
      </div>
      <div class="cj-ifwrap">
        <iframe id="cjFrame" class="cj-iframe" referrerpolicy="no-referrer"></iframe>
        <div class="cj-overlay" id="cjOv">
          <div class="cj-fake" data-act="cj-fake">🎁 CLAIM YOUR FREE PRIZE!</div>
        </div>
      </div>
    </div>
    <div class="cj-igrid">
      <div class="cj-card"><h4 style="color:var(--red)">VULNERABLE</h4><p>Page loads in the iframe. Attacker positions a transparent iframe over a fake UI to hijack clicks.</p></div>
      <div class="cj-card"><h4 style="color:var(--green)">PROTECTED</h4><p>Browser refuses to load. Protected by <code>X-Frame-Options: DENY/SAMEORIGIN</code> or <code>CSP: frame-ancestors 'none'</code>.</p></div>
      <div class="cj-card"><h4 style="color:var(--orange)">MITIGATION</h4><p>Add to HTTP response:<br><code>X-Frame-Options: DENY</code><br><code>Content-Security-Policy: frame-ancestors 'none'</code></p></div>
      <div class="cj-card"><h4 style="color:var(--accent)">POC PAYLOADS</h4><p>The LIBRARY tab has iframe embed snippets, overlay templates, and detection commands ready to copy.</p></div>
    </div>
    ${sel ? `<div style="margin-top:4px">
      <label class="slabel">SELECTED PAYLOAD</label>
      <textarea rows="3" readonly>${h(sel.payload)}</textarea>
      <button class="copy-btn" data-act="copy" data-v="${h(ph(sel.payload))}">COPY PAYLOAD</button>
    </div>` : ''}
  </div>`;
}
function testCJ() {
  let url = (document.getElementById('cjDomain').value || '').trim();
  if (!url) return;
  if (!url.startsWith('http')) url = 'https://' + url;
  _ovOn = false;
  const res = document.getElementById('cjResult');
  const frame = document.getElementById('cjFrame');
  const bar = document.getElementById('cjBar');
  const txt = document.getElementById('cjTxt');
  const dot = document.getElementById('cjDot');
  const hdr = document.getElementById('cjHdr');
  const ov = document.getElementById('cjOv');
  if (ov) ov.style.display = 'none';
  res.style.display = 'block';
  bar.className = 'cj-bar'; dot.style.color = 'var(--orange)';
  txt.textContent = 'LOADING...'; hdr.textContent = '';
  frame.src = '';
  frame.onload = function () {
    try {
      const doc = frame.contentDocument || frame.contentWindow.document;
      if (doc) { dot.style.color = 'var(--red)'; bar.className = 'cj-bar cj-vuln'; txt.textContent = 'VULNERABLE — page loaded in iframe'; hdr.textContent = 'X-Frame-Options: NOT SET'; }
    } catch (e) {
      dot.style.color = 'var(--red)'; bar.className = 'cj-bar cj-vuln';
      txt.textContent = 'VULNERABLE — page loaded (cross-origin)'; hdr.textContent = 'Check DevTools headers';
    }
  };
  frame.onerror = function () { dot.style.color = 'var(--t3)'; txt.textContent = 'Could not load — network error or HTTPS required'; };
  setTimeout(function () {
    if (dot.style.color === 'var(--orange)') {
      dot.style.color = 'var(--green)'; bar.className = 'cj-bar cj-safe';
      txt.textContent = 'PROTECTED — browser blocked iframe'; hdr.textContent = 'Check DevTools Network tab';
    }
  }, 3000);
  frame.src = url;
}
function toggleCjOv() {
  _ovOn = !_ovOn;
  const ov = document.getElementById('cjOv');
  if (ov) ov.style.display = _ovOn ? 'block' : 'none';
}

// ── ACTIONS ────────────────────────────────────────────────────────────────────
function setCategory(cat) {
  S.cat = cat; S.filter = 'all'; S.tab = 'library'; S.pid = ''; S.search = '';
  const si = document.getElementById('search-input'); if (si) si.value = '';
  renderAll();
}
function setFilter(f) {
  S.filter = f; S.tab = 'library'; S.search = '';
  const si = document.getElementById('search-input'); if (si) si.value = '';
  renderAll();
}
function setTab(tab) { S.tab = tab; renderTabNav(); renderTabContent(); }
function onSearch(q) { S.search = q.toLowerCase(); renderSidebar(); if (S.tab === 'library') renderTabContent(); }
function selectPayload(id) {
  S.pid = id;
  const p = findPayload(id);
  if (p) { S.customPayload = ph(p.payload); pushRecent(id); }
  S.tab = 'custom';
  renderSidebar(); renderTabNav(); renderTabContent();
}
function toggleFav(id) {
  if (S.favs.has(id)) S.favs.delete(id); else S.favs.add(id);
  saveFavs();
  renderSidebar();
  if (S.tab === 'library') renderTabContent();
}

// ── THEME ──────────────────────────────────────────────────────────────────────
function toggleTheme() {
  const light = document.documentElement.classList.toggle('light');
  try { localStorage.setItem('pf_theme', light ? 'light' : 'dark'); } catch (_) {}
  document.getElementById('theme-btn').textContent = light ? '◑ LIGHT' : '◐ DARK';
}

// ── PLACEHOLDER PANEL ────────────────────────────────────────────────────────────
function togglePlaceholderPanel() {
  const panel = document.getElementById('ph-panel');
  const open = panel.classList.toggle('open');
  if (open) {
    document.getElementById('ph-target').value = S.placeholders.TARGET || '';
    document.getElementById('ph-attacker').value = S.placeholders.ATTACKER || '';
    document.getElementById('ph-oast').value = S.placeholders.OAST || '';
  }
}
function savePlaceholderPanel() {
  S.placeholders = {
    TARGET: document.getElementById('ph-target').value.trim(),
    ATTACKER: document.getElementById('ph-attacker').value.trim(),
    OAST: document.getElementById('ph-oast').value.trim(),
  };
  savePlaceholders();
  document.getElementById('ph-panel').classList.remove('open');
  toast('Placeholders saved');
  // refresh so library insert/copy buttons use the new values
  renderTabContent();
}

// ── DELEGATED EVENTS ─────────────────────────────────────────────────────────────
function onClick(e) {
  const el = e.target.closest('[data-act]');
  if (!el) return;
  const act = el.dataset.act;

  // WAF / mutation chips keep their own data-* path
  switch (act) {
    case 'cat': setCategory(el.dataset.cat); break;
    case 'filter': setFilter(el.dataset.f); break;
    case 'tab': setTab(el.dataset.tab); break;
    case 'select': e.preventDefault(); selectPayload(el.dataset.id); break;
    case 'fav': toggleFav(el.dataset.id); break;
    case 'copy': copyText(el.dataset.v, el.classList.contains('mut-val') ? el.parentElement.querySelector('.copy-btn') : el); break;
    case 'inject': injectIntoActiveTab(el.dataset.v, el); break;
    case 'copy-editor': { const ta = document.getElementById('payload-editor'); copyText(ph(ta.value), el); break; }
    case 'inject-editor': { const ta = document.getElementById('payload-editor'); injectIntoActiveTab(ph(ta.value), el); break; }
    case 'clearwaf': clearWaf(); break;
    case 'gen': generateMutations(); break;
    case 'export': exportMutations(el.dataset.fmt); break;
    case 'jwt-decode': decodeJwt(); break;
    case 'jwt-attack': jwtAttack(el.dataset.atk); break;
    case 'jwt-forge': forgeJwt(el.dataset.none === '1'); break;
    case 'jwt-copy': copyForged(); break;
    case 'cj-test': testCJ(); break;
    case 'cj-overlay': toggleCjOv(); break;
    case 'cj-fake': toast('A real attack could trigger account deletion, password change, payment or OAuth approval.', 'var(--red)'); break;
    case 'theme': toggleTheme(); break;
    case 'ph-toggle': togglePlaceholderPanel(); break;
    case 'ph-save': savePlaceholderPanel(); break;
  }
}

// WAF / mutation chips (data-waf / data-mut) need their own handler (not data-act)
function onChipClick(e) {
  const waf = e.target.closest('[data-waf]');
  if (waf) {
    const w = waf.dataset.waf;
    S.waf = S.waf === w ? '' : w;
    if (S.waf) WAF_PROFILES[S.waf].forEach((m) => S.selMuts.add(m));
    renderTabContent();
    return;
  }
  const mut = e.target.closest('[data-mut]');
  if (mut) {
    const k = mut.dataset.mut;
    if (S.selMuts.has(k)) S.selMuts.delete(k); else S.selMuts.add(k);
    mut.classList.toggle('am', S.selMuts.has(k));
  }
}

function onInput(e) {
  if (e.target.id === 'search-input') onSearch(e.target.value);
}

// ── INIT ────────────────────────────────────────────────────────────────────────
async function init() {
  try { if (localStorage.getItem('pf_theme') === 'light') document.documentElement.classList.add('light'); } catch (_) {}
  await loadStore();
  const app = document.getElementById('app');
  app.addEventListener('click', onClick);
  app.addEventListener('click', onChipClick);
  app.addEventListener('input', onInput);
  const tb = document.getElementById('theme-btn');
  if (tb && document.documentElement.classList.contains('light')) tb.textContent = '◑ LIGHT';
  renderAll();
}

document.addEventListener('DOMContentLoaded', init);
