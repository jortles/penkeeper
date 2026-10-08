const API_BASE = '/api/v1';
const AUTH_BASE = '/api/auth';

// ---- Current state ----
let currentAssessment = null;
let currentHostId = null;
// Document-level "click outside to close" handlers for the notes editor menus.
// Tracked at module scope so each initNotesEditor() can remove the previous
// pair before installing new ones (prevents unbounded listener accumulation).
let _notesTmplCloser = null;
let _notesHlCloser = null;
let activeHostTab = 'ports';
let commandOsFilter = '';        // '' = All
let commandCategoryFilter = '';  // '' = All
let knownCategories = [];        // populated by renderCommands, used by modals

function getSidebarPortsSetting() {
  return localStorage.getItem('pk_sidebar_ports') !== 'false';
}

const DEFAULT_CATEGORIES = [
  'Active Directory', 'Credential Access', 'Defense Evasion', 'Enumeration',
  'Exfiltration', 'File Transfers', 'Lateral Movement', 'Persistence',
  'Post-Exploitation', 'Privilege Escalation', 'Reverse Shells', 'Tools', 'Web Application',
];

// Host tabs in their default order. A tab order the user drags into place is
// kept in pk_tab_order; it is filtered to these tabs and any tab it lacks is
// appended.
const HOST_TABS = ['ports', 'services', 'credentials', 'commands', 'notes'];
function hostTabOrder() {
  let saved = null;
  try { saved = JSON.parse(localStorage.getItem('pk_tab_order') || 'null'); } catch {}
  const order = Array.isArray(saved) ? saved.filter(t => HOST_TABS.includes(t)) : [];
  for (const t of HOST_TABS) if (!order.includes(t)) order.push(t);
  return order;
}
function saveHostTabOrder(order) {
  localStorage.setItem('pk_tab_order', JSON.stringify(order));
}

// SVG icons used for credential action buttons
const ICON_COPY    = `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="2" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>`;
const ICON_COPIED  = `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"/></svg>`;
const ICON_EYE     = `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>`;
const ICON_EYE_OFF = `<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M17.94 17.94A10.07 10.07 0 0 1 12 20c-7 0-11-8-11-8a18.45 18.45 0 0 1 5.06-5.94M9.9 4.24A9.12 9.12 0 0 1 12 4c7 0 11 8 11 8a18.5 18.5 0 0 1-2.16 3.19m-6.72-1.07a3 3 0 1 1-4.24-4.24"/><line x1="1" y1="1" x2="23" y2="23"/></svg>`;

/* ==========================================================
   Helpers
   ========================================================== */
function $(sel) { return document.querySelector(sel); }
function $$(sel) { return Array.from(document.querySelectorAll(sel)); }
// esc HTML-escapes a value for safe interpolation into markup. It escapes
// quotes as well as angle brackets so the result is safe in BOTH text content
// and inside single/double-quoted attribute values (e.g. data-* attributes).
function esc(s) {
  return String(s ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

// Convert ANSI escape sequences to HTML <span> tags with inline color styles.
// Handles SGR codes: reset (0), bold (1), italic (3), underline (4),
// standard FG (30-37), bright FG (90-97), standard BG (40-47).
function ansiToHtml(raw) {
  // HTML-escape the text first (no esc() helper since we need char-level control)
  const text = raw
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;');

  const FG = {
    30:'#808080', 31:'#e06c75', 32:'#98c379', 33:'#e5c07b',
    34:'#61afef', 35:'#c678dd', 36:'#56b6c2', 37:'#abb2bf',
    90:'#636d83', 91:'#ff7575', 92:'#b5f0a5', 93:'#ffd580',
    94:'#82aaff', 95:'#c792ea', 96:'#89ddff', 97:'#ffffff',
  };
  const BG = {
    40:'#808080', 41:'#e06c75', 42:'#98c379', 43:'#e5c07b',
    44:'#61afef', 45:'#c678dd', 46:'#56b6c2', 47:'#abb2bf',
  };

  let out = '';
  let depth = 0;
  // Split on SGR sequences (\x1b[ ... m), keeping the delimiters
  const parts = text.split(/(\x1b\[[0-9;]*m)/);
  for (const part of parts) {
    if (!part.startsWith('\x1b[')) { out += part; continue; }
    const codes = part.slice(2, -1).split(';').map(Number);
    // Reset: close all open spans
    if (codes.length === 0 || codes[0] === 0) {
      out += '</span>'.repeat(depth);
      depth = 0;
      // If there are more codes after the 0, process them as a new style
      const rest = codes.slice(1);
      if (rest.length) {
        let s = '';
        for (const c of rest) {
          if (c === 1) s += 'font-weight:bold;';
          else if (c === 3) s += 'font-style:italic;';
          else if (c === 4) s += 'text-decoration:underline;';
          else if (FG[c]) s += `color:${FG[c]};`;
          else if (BG[c]) s += `background:${BG[c]};`;
        }
        if (s) { out += `<span style="${s}">`; depth++; }
      }
      continue;
    }
    let style = '';
    for (const c of codes) {
      if (c === 1) style += 'font-weight:bold;';
      else if (c === 3) style += 'font-style:italic;';
      else if (c === 4) style += 'text-decoration:underline;';
      else if (c === 39) style += 'color:inherit;';
      else if (FG[c]) style += `color:${FG[c]};`;
      else if (BG[c]) style += `background:${BG[c]};`;
    }
    if (style) { out += `<span style="${style}">`; depth++; }
  }
  out += '</span>'.repeat(depth);
  return out;
}

// Sanitize HTML for rich-text content (notes editor).
// Allows safe formatting tags but strips dangerous elements and attributes.
const SAFE_TAGS = new Set([
  'p','br','b','i','u','strong','em','s','strike','del','sub','sup',
  'h1','h2','h3','h4','h5','h6','ul','ol','li','blockquote','pre','code',
  'span','div','a','table','thead','tbody','tr','td','th','hr','font','mark',
]);
const SAFE_ATTRS = new Set([
  'href','target','rel','class','style','colspan','rowspan','title','color',
]);
const DANGEROUS_STYLE_RE = /expression\s*\(|url\s*\(|javascript:|@import/i;
function sanitizeHTML(html) {
  if (!html) return '';
  const doc = new DOMParser().parseFromString(html, 'text/html');
  function walk(node) {
    const children = Array.from(node.childNodes);
    for (const child of children) {
      if (child.nodeType === Node.ELEMENT_NODE) {
        const tag = child.tagName.toLowerCase();
        if (!SAFE_TAGS.has(tag)) {
          // Replace dangerous element with its text content
          child.replaceWith(document.createTextNode(child.textContent));
          continue;
        }
        // Remove dangerous attributes
        for (const attr of Array.from(child.attributes)) {
          const name = attr.name.toLowerCase();
          if (name.startsWith('on') || !SAFE_ATTRS.has(name)) {
            child.removeAttribute(attr.name);
          } else if (name === 'href') {
            // Strip ALL whitespace and control characters before checking the
            // scheme — browsers ignore embedded tabs/newlines (e.g.
            // "java\tscript:") when resolving a URL, so a naive prefix check is
            // bypassable. Entities are already decoded by DOMParser.
            const val = attr.value.replace(/[\s\u0000-\u001F\u007F-\u009F]+/g, '').toLowerCase();
            if (val.startsWith('javascript:') || val.startsWith('vbscript:') || val.startsWith('data:')) {
              child.removeAttribute(attr.name);
            }
          } else if (name === 'style' && DANGEROUS_STYLE_RE.test(attr.value)) {
            child.removeAttribute(attr.name);
          }
        }
        walk(child);
      }
    }
  }
  walk(doc.body);
  return doc.body.innerHTML;
}

let modalCloseOnBackdrop = true;

function showModal(innerHTML, { closeOnBackdrop = true, wide = false } = {}) {
  modalCloseOnBackdrop = closeOnBackdrop;
  $('#modal-content').innerHTML = innerHTML;
  $('#modal-content').classList.toggle('modal-wide', wide);
  $('#modal').classList.remove('hidden');
}
function hideModal() { $('#modal').classList.add('hidden'); }

function authHeaders() {
  // JWT is now sent via HttpOnly cookie; no Authorization header needed
  // for browser requests. The cookie is attached automatically.
  return {};
}
function jsonHeaders() { return { 'Content-Type': 'application/json' }; }

function isTokenValid() {
  // Check the non-HttpOnly companion cookie set by the server.
  return document.cookie.split(';').some(c => c.trim().startsWith('pk_logged_in='));
}

// Signed-in state. The editor sessions (notes and scratch pads, see "Editor
// sessions" below) keep unsaved text in memory and save it only while the
// account they belong to is signed in. Unsaved text is never dropped on its
// own: after the session expires it is saved once its account signs in
// again, and while another account is signed in (in another tab, or here)
// it is kept unsent. Only the user drops it: Discard, Logout or signing in
// here as another account (each asks first), or deleting its note, host or
// assessment in this tab.
let signedIn = false;
let account = null; // the account signed in, as last seen (sign-in, GET /settings/me)

// End the signed-in state and show the sign-in form. The editors' unsaved
// text stays in memory. `ended`: the server already ended the session
// (the Logout menu item waited for it).
function logout({ ended = false } = {}) {
  // Already signed out with the sign-in (or 2FA) form up, e.g. a late 401:
  // keep what the user is typing there.
  if (!signedIn && $('#form-login, #form-totp')) return;
  signedIn = false;
  releaseEditors();
  // Ask the server to clear the HttpOnly cookie, without revoking the token:
  // a 401 can come from a cookie that a 2FA change has just replaced.
  if (!ended) {
    fetch(AUTH_BASE + '/logout', {
      method: 'POST', credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ revoke: false }),
    }).catch(() => {});
  }
  currentAssessment = null;
  currentHostId = null;
  showLoginForm();
}

// A request came back 401: the session expired or was revoked. Only the
// first one signs out; later ones (e.g. a save that was already in flight)
// must not re-render the sign-in form the user may be filling in. A 401
// while no sign-in screen is shown (e.g. the dashboard opened with a
// revoked session) shows the sign-in form too. The cookie is checked again
// first: a request sent with a cookie that was replaced meanwhile (enabling
// or disabling 2FA re-issues it, another tab may have signed in) gets a 401
// although this browser is still signed in, and signing out would end that
// new session. If it is, the saves waiting for a sign-in are sent again.
let sessionCheck = null;
function sessionExpired() {
  const signOut = () => signedIn || !$('.auth-container');
  if (sessionCheck || !signOut()) return;
  sessionCheck = fetch(API_BASE + '/settings/me', { headers: authHeaders(), credentials: 'same-origin' })
    .then(res => (res.ok ? res.json() : null))
    .catch(() => null)
    .then(me => {
      sessionCheck = null;
      if (!signOut()) return;
      if (me && me.email) adoptUser(me.email);
      else logout();
    });
}

// The account signed in is `email`: seen by GET /settings/me (page load,
// another tab signed in, the check after a save got 404) or signed in here.
// Its unsaved editor text is saved now; another account's waits, unsent,
// until that account is signed in again. (Whose text is whose is known from
// when it was loaded, see fetchAssessment, never from this.)
function adoptUser(email) {
  if (!email) return;
  account = email;
  signedIn = true;
  resumePendingSaves();
}

// Signed in here (sign-in form or 2FA step) as `email`. Unsaved text of
// another account can't be saved meanwhile: the user chooses between
// dropping it and keeping it (unsent) until that account signs in again.
function signedInHere(email) {
  if (account && account !== email) activeNoteId = null; // the other account's note isn't reopened
  adoptUser(email);
  const unsaved = editorSessions().filter(s => !s.discarded && s.owner !== email && (s.conflict || isDirty(s)));
  if (unsaved.length) {
    const owners = [...new Set(unsaved.map(s => s.owner))].join(', ');
    const notes = unsaved.filter(s => s.kind === 'note').length;
    const pads = unsaved.length - notes;
    const what = [notes && `${notes} note${notes > 1 ? 's' : ''}`, pads && `${pads} scratch pad${pads > 1 ? 's' : ''}`]
      .filter(Boolean).join(' and ');
    if (!confirm(`Changes to ${what} made as ${owners} have not been saved, and can't be while ${email} is signed in.\n\nDiscard them? (Cancel keeps them in this tab until ${owners} signs in again.)`)) return;
  }
  discardEditorSessions(s => s.owner !== email);
}

// The Logout menu item. This account's pending saves get a few seconds to
// finish; its text that still can't be saved is named before it is thrown
// away. Another account's unsent text stays for that account. The server
// must answer first: if it can't, the user is told and stays signed in
// (with the text kept) instead of seeing a sign-in form over a session that
// still works. If it cleared the cookies but could not revoke the token
// ("revoked": false, e.g. its database is down), this browser is signed
// out and the user is told the token stays valid until it expires.
async function logoutClicked() {
  if (signedIn) await flushAllEditorSessions(4000);
  const stuck = editorSessions().filter(s => !s.discarded && !heldForAccount(s) && (s.conflict || isDirty(s)));
  if (stuck.length && !confirm(`${describeUnsaved(stuck)} could not be saved and will be lost if you log out now.\n\nLog out anyway?`)) return;
  let revoked = true;
  try {
    const res = await fetch(AUTH_BASE + '/logout', { method: 'POST', credentials: 'same-origin' });
    const b = await res.json().catch(() => ({}));
    if (!res.ok) throw new Error(b.error || `server answered ${res.status}`);
    revoked = b.revoked !== false;
  } catch (e) {
    alert(`Logout failed: ${e.message}\n\nYou are still signed in. Try again in a moment.`);
    return;
  }
  discardEditorSessions(s => !heldForAccount(s));
  logout({ ended: true });
  if (!revoked) alert('You are signed out in this browser, but the server could not revoke the session right now: its token stays valid until it expires (within 24 hours).');
}

/* ==========================================================
   Theme
   ========================================================== */
function applyTheme(theme) {
  document.body.classList.toggle('theme-light', theme === 'light');
  localStorage.setItem('theme', theme);
}

function getFontSize() {
  return parseInt(localStorage.getItem('pk_font_size') || '13', 10);
}

function applyFontSize(px) {
  document.documentElement.style.zoom = px / 13;
  localStorage.setItem('pk_font_size', String(px));
}

function showSidebar() { $('#sidebar').classList.remove('hidden'); }
function hideSidebar() { $('#sidebar').classList.add('hidden'); $('#sidebar').innerHTML = ''; }

async function setUserEmail() {
  try {
    const me = await apiGet('/settings/me');
    const el = $('#user-email');
    if (el && me.email) el.textContent = me.email;
    // Only show Users nav button for admins
    const btnUsers = $('#btn-users');
    if (btnUsers) {
      if (me.role === 'admin') btnUsers.classList.remove('hidden');
      else btnUsers.classList.add('hidden');
    }
    // An existing session (page load, or signed in from another tab).
    if (me.email && (!signedIn || me.email !== account)) adoptUser(me.email);
  } catch {}
}

/* ==========================================================
   API Wrappers
   ========================================================== */
// A 503 with Retry-After means the server could not check the session for a
// moment (e.g. its database is restarting) and did not run the request: it
// is not a sign-out. Show a short notice and send the request again a few
// times; if the server is still unavailable, the caller gets the 503 error.
const RETRY_503_DELAYS = [1000, 2000, 4000];
async function apiFetch(url, opts) {
  for (let attempt = 0; ; attempt++) {
    const res = await fetch(url, opts);
    if (res.status !== 503 || !res.headers.has('Retry-After') || opts.keepalive || attempt >= RETRY_503_DELAYS.length) return res;
    showServerBusyNotice();
    await new Promise(resolve => setTimeout(resolve, RETRY_503_DELAYS[attempt]));
  }
}

let serverBusyTimer = null;
function showServerBusyNotice() {
  let el = $('#server-busy-notice');
  if (!el) {
    el = document.createElement('div');
    el.id = 'server-busy-notice';
    el.setAttribute('role', 'status');
    el.textContent = 'The server is briefly unavailable \u2014 retrying\u2026';
    Object.assign(el.style, {
      position: 'fixed', top: '56px', left: '50%', transform: 'translateX(-50%)', zIndex: '10000',
      padding: '6px 14px', borderRadius: 'var(--radius)', background: 'var(--bg-card)', color: 'var(--yellow)',
      border: '1px solid var(--border-light)', fontSize: '0.85rem',
    });
    document.body.appendChild(el);
  }
  el.hidden = false;
  clearTimeout(serverBusyTimer);
  serverBusyTimer = setTimeout(() => { el.hidden = true; }, 4000);
}

async function apiGet(path) {
  const res = await apiFetch(API_BASE + path, { headers: authHeaders(), credentials: 'same-origin' });
  if (res.status === 401) { sessionExpired(); throw Object.assign(new Error('Session expired'), { status: 401 }); }
  if (!res.ok) throw Object.assign(new Error(`GET ${path} failed (${res.status})`), { status: res.status });
  return res.json();
}

async function apiPost(path, body, method = 'POST', { keepalive = false } = {}) {
  const res = await apiFetch(API_BASE + path, {
    method,
    headers: { ...authHeaders(), ...jsonHeaders() },
    credentials: 'same-origin',
    body: JSON.stringify(body),
    keepalive,
  });
  if (res.status === 401) { sessionExpired(); throw Object.assign(new Error('Session expired'), { status: 401 }); }
  if (res.status === 204) return;
  if (!res.ok) {
    // Keep the status and the server's JSON body on the error so callers can
    // tell a version conflict (409) from a failure; the message is unchanged.
    const err = new Error(`${method} ${path} failed (${res.status})`);
    err.status = res.status;
    err.data = await res.json().catch(() => null);
    throw err;
  }
  return res.json();
}

async function apiDelete(path) {
  const res = await apiFetch(API_BASE + path, { method: 'DELETE', headers: authHeaders(), credentials: 'same-origin' });
  if (res.status === 401) { sessionExpired(); throw Object.assign(new Error('Session expired'), { status: 401 }); }
  if (!res.ok) throw Object.assign(new Error(`DELETE ${path} failed (${res.status})`), { status: res.status });
}
async function apiPatch(path, body) {
  const res = await apiFetch(API_BASE + path, { method: 'PATCH', headers: { ...authHeaders(), 'Content-Type': 'application/json' }, credentials: 'same-origin', body: JSON.stringify(body) });
  if (res.status === 401) { sessionExpired(); throw new Error('Session expired'); }
  if (!res.ok) throw new Error(`PATCH ${path} failed (${res.status})`);
}

/* ==========================================================
   Auth: Login
   ========================================================== */
function showNavButtons() {
  $('#btn-search').classList.remove('hidden');
  $('#btn-commands').classList.remove('hidden');
  $('#user-menu-btn').classList.remove('hidden');
  // btn-users visibility is controlled by setUserEmail() based on role
}
function hideNavButtons() {
  $('#btn-search').classList.add('hidden');
  $('#btn-commands').classList.add('hidden');
  $('#btn-users').classList.add('hidden');
  $('#user-menu-btn').classList.add('hidden');
  const dd = $('#user-dropdown');
  if (dd) dd.style.display = 'none';
}

function showLoginForm() {
  hideSidebar();
  hideNavButtons();
  $('#user-email').textContent = '';

  $('#app').innerHTML = `
    <div class="auth-container">
      <div class="auth-card">
        <div class="auth-brand">
          <span class="logo">&#9763;</span>
          <span class="app-name">Penkeeper</span>
        </div>
        <form id="form-login">
          <label>Email
            <input type="email" id="login-email" required placeholder="you@example.com">
          </label>
          <label>Password
            <input type="password" id="login-password" required minlength="8" placeholder="Min 8 characters">
          </label>
          <a href="#" id="forgot-link" class="forgot-link">Forgot password?</a>
          <button type="submit" class="btn btn-primary">Sign In</button>
        </form>
      </div>
    </div>`;

  $('#forgot-link').addEventListener('click', ev => { ev.preventDefault(); showForgotPasswordForm(); });

  $('#form-login').addEventListener('submit', async ev => {
    ev.preventDefault();
    const email = $('#login-email').value.trim();
    const password = $('#login-password').value;
    try {
      const res = await fetch(AUTH_BASE + '/login', {
        method: 'POST',
        headers: jsonHeaders(),
        credentials: 'same-origin',
        body: JSON.stringify({ email, password }),
      });
      if (!res.ok) {
        const b = await res.json().catch(() => ({}));
        throw new Error(b.error || 'Login failed');
      }
      const data = await res.json();
      if (data.requires_totp) {
        showTOTPLoginForm(data.partial_token, email);
        return;
      }
      // JWT is now set as an HttpOnly cookie by the server.
      signedInHere(email);
      renderDashboard();
    } catch (e) { alert(e.message); }
  });

}

/* ==========================================================
   Auth: TOTP step-2 login
   ========================================================== */
function showTOTPLoginForm(partialToken, email) {
  hideSidebar();
  hideNavButtons();
  $('#user-email').textContent = '';

  $('#app').innerHTML = `
    <div class="auth-container">
      <div class="auth-card">
        <div class="auth-brand">
          <span class="logo">&#9763;</span>
          <span class="app-name">Two-Factor Auth</span>
        </div>
        <p style="text-align:center;color:var(--fg-dim);margin-bottom:1.2rem;font-size:0.9rem">
          Enter the 6-digit code from your authenticator app.
        </p>
        <form id="form-totp">
          <label>Authentication Code
            <input type="text" id="totp-code" inputmode="numeric" maxlength="6"
              autocomplete="one-time-code" placeholder="000000" required
              style="letter-spacing:0.3em;font-size:1.4rem;text-align:center">
          </label>
          <button type="submit" class="btn btn-primary">Verify</button>
        </form>
        <p style="text-align:center;margin-top:1rem">
          <a href="#" id="totp-back">&#8592; Back to login</a>
        </p>
      </div>
    </div>`;

  $('#totp-code').focus();

  $('#form-totp').addEventListener('submit', async ev => {
    ev.preventDefault();
    const code = $('#totp-code').value.trim();
    try {
      const res = await fetch(AUTH_BASE + '/totp', {
        method: 'POST',
        headers: jsonHeaders(),
        credentials: 'same-origin',
        body: JSON.stringify({ partial_token: partialToken, code }),
      });
      if (!res.ok) {
        const b = await res.json().catch(() => ({}));
        throw new Error(b.error || '2FA verification failed');
      }
      await res.json();
      // JWT is now set as an HttpOnly cookie by the server.
      signedInHere(email);
      renderDashboard();
    } catch (e) {
      alert(e.message);
      $('#totp-code').value = '';
      $('#totp-code').focus();
    }
  });

  $('#totp-back').addEventListener('click', ev => { ev.preventDefault(); showLoginForm(); });
}

/* ==========================================================
   Auth: Forgot Password
   ========================================================== */
function showForgotPasswordForm() {
  hideSidebar();
  hideNavButtons();
  $('#user-email').textContent = '';

  $('#app').innerHTML = `
    <div class="auth-container">
      <div class="auth-card">
        <div class="auth-brand">
          <span class="logo">&#9763;</span>
          <span class="app-name">Reset Password</span>
        </div>
        <p class="auth-sub">Enter your email address and we'll send you a reset link.</p>
        <form id="form-forgot">
          <label>Email
            <input type="email" id="forgot-email" required placeholder="you@example.com">
          </label>
          <button type="submit" class="btn btn-primary">Send Reset Link</button>
        </form>
        <p style="text-align:center;margin-top:1rem">
          <a href="#" id="forgot-back">&#8592; Back to login</a>
        </p>
      </div>
    </div>`;

  $('#form-forgot').addEventListener('submit', async ev => {
    ev.preventDefault();
    const emailVal = $('#forgot-email').value.trim();
    const btn = ev.target.querySelector('button[type="submit"]');
    btn.disabled = true;
    btn.textContent = 'Sending…';
    try {
      await fetch(AUTH_BASE + '/forgot-password', {
        method: 'POST', headers: jsonHeaders(), credentials: 'same-origin',
        body: JSON.stringify({ email: emailVal }),
      });
      // Always show success regardless of response (no enumeration)
      $('#app').querySelector('.auth-card').innerHTML = `
        <div class="auth-brand">
          <span class="logo">&#9763;</span>
          <span class="app-name">Check Your Email</span>
        </div>
        <p class="auth-sub" style="text-align:center">
          If <strong>${esc(emailVal)}</strong> is registered, you'll receive a reset link shortly.<br>
          The link expires in 1 hour.
        </p>
        <p style="text-align:center;margin-top:1.5rem">
          <a href="#" id="forgot-done-back">&#8592; Back to login</a>
        </p>`;
      $('#forgot-done-back').addEventListener('click', ev => { ev.preventDefault(); showLoginForm(); });
    } catch {
      btn.disabled = false;
      btn.textContent = 'Send Reset Link';
    }
  });

  $('#forgot-back').addEventListener('click', ev => { ev.preventDefault(); showLoginForm(); });
}

/* ==========================================================
   Auth: Reset Password (from email link)
   ========================================================== */
async function showResetPasswordForm(token) {
  hideSidebar();
  hideNavButtons();
  $('#user-email').textContent = '';

  // Clear the token from the URL without reloading
  history.replaceState(null, '', window.location.pathname);

  $('#app').innerHTML = `
    <div class="auth-container">
      <div class="auth-card">
        <div class="auth-brand">
          <span class="logo">&#9763;</span>
          <span class="app-name">Set New Password</span>
        </div>
        <div id="reset-body">
          <p class="auth-sub" style="text-align:center">Validating link…</p>
        </div>
      </div>
    </div>`;

  // Validate token first (in a POST body: never put the token in a URL)
  let valid = false;
  try {
    const res = await fetch(AUTH_BASE + '/reset-password/validate', {
      method: 'POST', headers: jsonHeaders(), credentials: 'same-origin',
      body: JSON.stringify({ token }),
    });
    const data = await res.json().catch(() => ({}));
    valid = data.valid === true;
  } catch {}

  const body = $('#reset-body');
  if (!valid) {
    body.innerHTML = `
      <p class="auth-sub" style="text-align:center;color:var(--red)">
        This reset link is invalid or has expired.
      </p>
      <p style="text-align:center;margin-top:1rem">
        <a href="#" id="reset-invalid-back">&#8592; Back to login</a>
      </p>`;
    $('#reset-invalid-back').addEventListener('click', ev => { ev.preventDefault(); showLoginForm(); });
    return;
  }

  body.innerHTML = `
    <form id="form-reset">
      <label>New Password
        <input type="password" id="reset-password" required minlength="8" placeholder="Min 8 characters">
      </label>
      <label>Confirm Password
        <input type="password" id="reset-confirm" required minlength="8" placeholder="Re-enter password">
      </label>
      <button type="submit" class="btn btn-primary">Set New Password</button>
    </form>`;

  $('#form-reset').addEventListener('submit', async ev => {
    ev.preventDefault();
    const password = $('#reset-password').value;
    const confirm = $('#reset-confirm').value;
    if (password !== confirm) { alert('Passwords do not match.'); return; }
    if (password.length < 8) { alert('Password must be at least 8 characters.'); return; }
    const btn = ev.target.querySelector('button[type="submit"]');
    btn.disabled = true;
    btn.textContent = 'Saving…';
    try {
      const res = await fetch(AUTH_BASE + '/reset-password', {
        method: 'POST', headers: jsonHeaders(), credentials: 'same-origin',
        body: JSON.stringify({ token, password }),
      });
      if (!res.ok) {
        const b = await res.json().catch(() => ({}));
        throw new Error(b.error || 'Reset failed');
      }
      body.innerHTML = `
        <p class="auth-sub" style="text-align:center">
          &#10003; Password updated successfully.
        </p>
        <p style="text-align:center;margin-top:1rem">
          <a href="#" id="reset-done-back">Sign in with your new password</a>
        </p>`;
      $('#reset-done-back').addEventListener('click', ev => { ev.preventDefault(); showLoginForm(); });
    } catch (e) {
      alert(e.message);
      btn.disabled = false;
      btn.textContent = 'Set New Password';
    }
  });
}

/* ==========================================================
   Dashboard – Assessment Cards
   ========================================================== */
function dashGreeting() {
  const h = new Date().getHours();
  if (h < 12) return 'Good morning, assessor.';
  if (h < 17) return 'Good afternoon, assessor.';
  return 'Good evening, assessor.';
}

async function renderDashboard() {
  releaseEditors();
  hideSidebar();
  currentAssessment = null;
  currentHostId = null;

  showNavButtons();
  const userKnown = setUserEmail();

  const app = $('#app');
  app.innerHTML = `
    <div class="dash-container">
      <div class="dash-header">
        <div>
          <div class="dash-greeting">${dashGreeting()}</div>
          <h2 class="dash-title">Assessments</h2>
        </div>
        <button class="btn btn-primary" id="dash-new-btn">+ New Assessment</button>
      </div>
      <div id="dash-list" class="dash-list"></div>
    </div>`;

  $('#dash-new-btn').addEventListener('click', showCreateAssessmentModal);

  try {
    const engs = await apiGet('/assessments');
    const list = $('#dash-list');
    // Once it is known whose list this is (another tab may have signed in).
    userKnown.then(() => { if (list.isConnected) showUnlistedWork(engs, list); });

    if (engs.length === 0) {
      list.innerHTML = `
        <div class="dash-empty">
          <p>No assessments yet.</p>
          <button class="btn btn-primary" id="dash-first-btn">+ New Assessment</button>
        </div>`;
      $('#dash-first-btn').addEventListener('click', showCreateAssessmentModal);
      return;
    }

    engs.forEach(e => {
      const eid  = e.id || e.ID || '';
      const name = e.name || e.Name || '(unnamed)';
      const hosts = e.hosts || e.Hosts || [];
      const hostCount = e.host_count ?? hosts.length;
      let portCount = e.port_count ?? 0;
      if (e.port_count == null) hosts.forEach(h => { portCount += (h.ports || h.Ports || []).length; });

      const row = document.createElement('div');
      row.className = 'dash-row';
      row.draggable = true;
      row.dataset.eid = eid;
      row.innerHTML = `
        <div class="dash-row-handle" title="Drag to reorder">&#8801;</div>
        <div class="dash-row-main">
          <div class="dash-row-name">${esc(name)}</div>
          <div class="dash-row-meta">
            ${hostCount} host${hostCount !== 1 ? 's' : ''}
            <span class="dash-dot">&middot;</span>${portCount} open port${portCount !== 1 ? 's' : ''}
          </div>
        </div>
        <div class="dash-row-actions">
          <button class="dash-btn-launch" data-eid="${eid}">Open &rsaquo;</button>
          <button class="dash-btn-delete" data-eid="${eid}" title="Delete assessment">&#10005;</button>
        </div>`;
      list.appendChild(row);
    });

    // --- Drag-and-drop reordering ---
    let dragSrc = null;
    $$('.dash-row').forEach(row => {
      row.addEventListener('dragstart', ev => {
        dragSrc = row;
        ev.dataTransfer.effectAllowed = 'move';
        setTimeout(() => row.classList.add('drag-dragging'), 0);
      });
      row.addEventListener('dragend', () => {
        row.classList.remove('drag-dragging');
        $$('.dash-row.drag-over').forEach(r => r.classList.remove('drag-over'));
      });
      row.addEventListener('dragover', ev => {
        ev.preventDefault();
        ev.dataTransfer.dropEffect = 'move';
        if (row !== dragSrc) {
          $$('.dash-row.drag-over').forEach(r => r.classList.remove('drag-over'));
          row.classList.add('drag-over');
        }
      });
      row.addEventListener('dragleave', () => row.classList.remove('drag-over'));
      row.addEventListener('drop', async ev => {
        ev.preventDefault();
        if (!dragSrc || dragSrc === row) return;
        row.classList.remove('drag-over');
        // Reorder DOM
        const rows = [...$$('.dash-row')];
        const srcIdx = rows.indexOf(dragSrc);
        const dstIdx = rows.indexOf(row);
        if (srcIdx < dstIdx) list.insertBefore(dragSrc, row.nextSibling);
        else list.insertBefore(dragSrc, row);
        // Persist new order
        const ordered = [...$$('.dash-row')];
        await Promise.all(ordered.map((r, i) =>
          apiPost(`/assessments/${r.dataset.eid}/order`, { sort_order: i + 1 }, 'PUT').catch(() => {})
        ));
      });
    });

    $$('.dash-btn-launch').forEach(btn => btn.addEventListener('click', ev => {
      ev.stopPropagation();
      renderAssessment(ev.currentTarget.dataset.eid);
    }));

    $$('.dash-row').forEach(row => row.addEventListener('click', ev => {
      if (ev.target.closest('.dash-btn-delete') || ev.target.closest('.dash-btn-launch') || ev.target.closest('.dash-row-handle')) return;
      renderAssessment(row.dataset.eid);
    }));

    $$('.dash-btn-delete').forEach(btn => btn.addEventListener('click', async ev => {
      ev.stopPropagation();
      const eid = ev.currentTarget.dataset.eid;
      if (!confirm('Delete this assessment and all its data?')) return;
      try {
        await apiDelete(`/assessments/${eid}`);
        discardEditorSessions(s => s.eid === eid); // its scratch pad and notes have nowhere to save to
        renderDashboard();
      } catch (e) { alert(e.message); }
    }));

  } catch (err) {
    if (err.status === 401) return; // the sign-in form is shown instead
    $('#dash-list').innerHTML = `<p class="dash-error">${esc(err.message)}</p>`;
  }
}

// Unsaved text whose assessment or host is no longer listed (e.g. deleted
// elsewhere before the text was saved) can't be opened from anywhere else:
// it is listed above the assessments (list), to copy or discard.
function showUnlistedWork(engs, list) {
  const eids = new Set(engs.map(e => e.id || e.ID));
  const hids = new Set(engs.flatMap(e => (e.hosts || e.Hosts || []).map(h => h.id || h.ID)));
  const unlisted = editorSessions().filter(s => !s.discarded && !heldForAccount(s) && (s.conflict || isDirty(s)) &&
    (s.kind === 'note' ? !hids.has(s.hid) : !eids.has(s.eid)));
  if (!unlisted.length) return;
  const box = document.createElement('div');
  box.className = 'dash-unsaved';
  box.innerHTML = '<p>Not saved: what this text belongs to was not found (deleted elsewhere?).</p>';
  for (const s of unlisted) {
    const row = document.createElement('div');
    row.className = 'dash-unsaved-row';
    const name = document.createElement('span');
    name.textContent = s.kind === 'note' ? `Note “${(noteSnapshot(s) || s.base).title || 'Untitled'}”` : 'Scratch pad';
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'btn btn-sm btn-secondary';
    btn.textContent = 'Show…';
    btn.addEventListener('click', () => showUnlistedText(s, row));
    row.append(name, btn);
    box.appendChild(row);
  }
  list.before(box);
}

// The text of an unlisted session (see showUnlistedWork), to copy or discard.
function showUnlistedText(s, row) {
  showModal(`
    <h3>Not saved</h3>
    <p class="conflict-intro">This text could not be saved, and what it belongs to was not found. Copy it to keep it, then discard it here.</p>
    <textarea id="unlisted-text" rows="12" readonly></textarea>
    <div class="flex gap-2 mt-4">
      <button type="button" class="btn btn-primary" id="unlisted-copy">Copy</button>
      <button type="button" class="btn btn-danger" id="unlisted-discard">Discard</button>
      <button type="button" class="btn btn-secondary" id="cancel">Close</button>
    </div>`);
  const ta = $('#unlisted-text');
  ta.value = sessionText(s);
  $('#unlisted-copy').addEventListener('click', ev => copyText(ta.value, ev.currentTarget, ta));
  $('#unlisted-discard').addEventListener('click', () => {
    if (!confirm('Discard this text? It can’t be recovered afterwards.')) return;
    discardEditorSessions(x => x === s);
    hideModal();
    const box = row.parentElement;
    row.remove();
    if (box && !box.querySelector('.dash-unsaved-row')) box.remove();
  });
  $('#cancel').addEventListener('click', hideModal);
}

/* ==========================================================
   Create Assessment Modal
   ========================================================== */
function showCreateAssessmentModal() {
  showModal(`
    <h3>New Assessment</h3>
    <form id="form-create-eng">
      <label>Assessment Name
        <input type="text" id="eng-name" required minlength="3" placeholder="e.g. Client-2026-Q1">
      </label>
      <div class="flex gap-2 mt-4">
        <button type="submit" class="btn btn-primary">Create</button>
        <button type="button" class="btn btn-secondary" id="cancel">Cancel</button>
      </div>
    </form>`);

  $('#form-create-eng').addEventListener('submit', async ev => {
    ev.preventDefault();
    try {
      await apiPost('/assessments', { name: $('#eng-name').value.trim() });
      hideModal();
      renderDashboard();
    } catch (e) { alert(e.message); }
  });
  $('#cancel').addEventListener('click', hideModal);
}

/* ==========================================================
   Assessment View (sidebar + content)
   ========================================================== */
// GET /assessments/:eid, with GET /settings/me sent alongside. The account
// signed in at that moment owns the assessment, so the text typed into its
// notes and scratch pad is that account's (eng.account; it never changes).
// It is looked up here rather than taken from `account`, which can be out of
// date (another tab may have signed in meanwhile). If that lookup fails for
// any reason other than a 401 (e.g. a proxy error), the assessment still
// opens, owned by the last account seen.
async function fetchAssessment(eid) {
  const [eng, me] = await Promise.all([
    apiGet(`/assessments/${eid}`),
    apiGet('/settings/me').catch(err => { if (err.status === 401) throw err; return null; }),
  ]);
  if (me && signedIn && me.email && me.email !== account) adoptUser(me.email);
  eng.account = me ? me.email : account;
  return eng;
}

async function renderAssessment(eid) {
  const app = $('#app');
  app.innerHTML = '<p class="text-muted" style="padding:24px">Loading...</p>';

  try {
    const eng = await fetchAssessment(eid);
    currentAssessment = eng;
    currentHostId = null;

    showNavButtons();
    setUserEmail();
    showSidebar();

    renderSidebar(eng);
    renderAssessmentOverview(eng);
  } catch (err) {
    if (err.status === 401) return; // the sign-in form is shown
    alert(err.message);
    renderDashboard();
  }
}

/* ==========================================================
   Sidebar – Host Tree
   ========================================================== */
function renderSidebar(eng) {
  const eid  = eng.id || eng.ID;
  const name = eng.name || eng.Name || '(unnamed)';
  const hosts = eng.hosts || eng.Hosts || [];

  const sb = $('#sidebar');
  sb.innerHTML = `
    <div class="sidebar-header">
      <h2 id="sb-eng-name">${esc(name)}</h2>
    </div>
    <div class="sidebar-toolbar">
      <span class="toolbar-label">Hosts</span>
      <button id="sb-add-host" class="sb-add-host-btn" title="+ Add Host">+ Add Host</button>
    </div>
    <div id="host-tree" class="host-tree"></div>
    <div class="sidebar-footer">
      <button id="sb-back">&#8592; Dashboard</button>
    </div>`;

  const tree = $('#host-tree');

  // Restore saved host order for this assessment
  const savedHostOrder = (() => {
    try { return JSON.parse(localStorage.getItem(`pk_host_order_${eid}`) || 'null'); } catch { return null; }
  })();
  if (Array.isArray(savedHostOrder) && savedHostOrder.length) {
    hosts.sort((a, b) => {
      const ai = savedHostOrder.indexOf(a.id || a.ID);
      const bi = savedHostOrder.indexOf(b.id || b.ID);
      return (ai === -1 ? 9999 : ai) - (bi === -1 ? 9999 : bi);
    });
  }

  if (hosts.length === 0) {
    tree.innerHTML = '<div class="empty-state"><p>No hosts yet</p></div>';
  } else {
    hosts.forEach(host => {
      const hid   = host.id || host.ID || '';
      const ident = host.identifier || host.Identifier || '(no id)';
      const os    = host.os || host.OS || '';
      const ports = host.ports || host.Ports || [];

      const node = document.createElement('div');
      node.className = 'host-node';
      node.dataset.hid = hid;
      node.draggable = true;

      const hasPorts = ports.length > 0;
      const showPorts = getSidebarPortsSetting();
      const hasSub = hasPorts && showPorts;

      node.innerHTML = `
        <div class="host-header" data-hid="${hid}">
          <span class="host-toggle${hasSub ? '' : ' hidden'}">${hasSub ? '&#9654;' : ''}</span>
          <span class="host-identifier">${esc(ident)}</span>
          ${(host.compromised || host.Compromised) ? '<span class="host-skull" title="Compromised">&#9760;</span>' : ''}
          ${os ? `<span class="host-os-badge${os.toLowerCase().includes('windows') ? ' os-windows' : os.toLowerCase().includes('linux') ? ' os-linux' : ''}">${esc(os)}</span>` : ''}
        </div>
        <div class="port-list" data-hid="${hid}">
          ${showPorts ? ports.map(p => {
            const num = p.number ?? p.Number ?? '';
            const proto = p.protocol ?? p.Protocol ?? '';
            const svc = p.service ?? p.Service ?? '';
            return `<div class="port-entry" data-pid="${p.id ?? p.ID}" data-hid="${hid}">
              <span class="port-dot open"></span>
              <span class="port-number">${esc(String(num))}/${esc(proto)}</span>
              <span class="port-service">${esc(svc)}</span>
            </div>`;
          }).join('') : ''}
        </div>`;

      tree.appendChild(node);
    });

    // ---- Host drag-and-drop reordering ----
    let dragSrcHost = null;
    $$('.host-node').forEach(node => {
      node.addEventListener('dragstart', e => {
        dragSrcHost = node;
        node.classList.add('host-dragging');
        e.dataTransfer.effectAllowed = 'move';
      });
      node.addEventListener('dragend', () => {
        $$('.host-node').forEach(n => n.classList.remove('host-dragging', 'host-drag-over'));
        dragSrcHost = null;
      });
      node.addEventListener('dragover', e => {
        e.preventDefault();
        e.dataTransfer.dropEffect = 'move';
        if (dragSrcHost && node !== dragSrcHost) node.classList.add('host-drag-over');
      });
      node.addEventListener('dragleave', () => node.classList.remove('host-drag-over'));
      node.addEventListener('drop', e => {
        e.preventDefault();
        node.classList.remove('host-drag-over');
        if (!dragSrcHost || dragSrcHost === node) return;
        const allNodes = Array.from(tree.children);
        const fromIdx = allNodes.indexOf(dragSrcHost);
        const toIdx = allNodes.indexOf(node);
        if (fromIdx < toIdx) tree.insertBefore(dragSrcHost, node.nextSibling);
        else tree.insertBefore(dragSrcHost, node);
        const newOrder = Array.from(tree.querySelectorAll('.host-node')).map(n => n.dataset.hid);
        localStorage.setItem(`pk_host_order_${eid}`, JSON.stringify(newOrder));
      });
    });
  }

  // ---- Sidebar events ----
  $('#sb-back').addEventListener('click', renderDashboard);

  $('#sb-eng-name').addEventListener('click', () => {
    currentHostId = null;
    $$('.host-header.active').forEach(h => h.classList.remove('active'));
    renderAssessmentOverview(currentAssessment);
  });

  $('#sb-add-host').addEventListener('click', () => showAddHostModal(eid));

  // Toggle host expand/collapse + select host
  $$('.host-header').forEach(hdr => {
    hdr.addEventListener('click', () => {
      const hid = hdr.dataset.hid;
      const subList = hdr.nextElementSibling;
      const toggle = hdr.querySelector('.host-toggle');

      if (subList && subList.classList.contains('port-list')) {
        subList.classList.toggle('expanded');
        if (toggle) {
          toggle.classList.toggle('expanded');
          toggle.innerHTML = subList.classList.contains('expanded') ? '&#9660;' : '&#9654;';
        }
      }

      $$('.host-header.active').forEach(h => h.classList.remove('active'));
      hdr.classList.add('active');
      currentHostId = hid;
      activeHostTab = 'ports';

      const hostData = (currentAssessment.hosts || currentAssessment.Hosts || [])
        .find(h => (h.id || h.ID) === hid);
      if (hostData) renderHostDetail(hostData);
    });
  });

  $$('.port-entry').forEach(pe => {
    pe.addEventListener('click', () => {
      const hid = pe.dataset.hid;
      const hdr = $$(`.host-header[data-hid="${hid}"]`)[0];
      if (hdr && !hdr.classList.contains('active')) hdr.click();
    });
  });
}

/* ==========================================================
   Assessment Overview
   ========================================================== */
function renderAssessmentOverview(eng) {
  releaseEditors();
  const name  = eng.name || eng.Name || '(unnamed)';
  const hosts = eng.hosts || eng.Hosts || [];
  const eid   = eng.id || eng.ID;
  const scratch = scratchSessionFor(eng);

  let totalPorts = 0;
  let totalCreds = 0;
  hosts.forEach(h => {
    totalPorts += (h.ports || h.Ports || []).length;
    totalCreds += (h.creds || h.Creds || []).length;
  });

  $('#app').innerHTML = `
    <div class="page-header">
      <div class="page-header-left">
        <div class="page-breadcrumb">
          <span class="crumb-link" id="ov-back-dash">Dashboard</span>
          <span class="crumb-sep">/</span>
          <span>${esc(name)}</span>
        </div>
        <h2 class="page-title">${esc(name)}</h2>
      </div>
      <div class="page-header-actions">
        <button class="btn btn-secondary btn-sm" id="ov-bulk-nmap">Import Nmap</button>
        <button class="btn btn-primary btn-sm" id="ov-add-host">+ Add Host</button>
      </div>
    </div>
    <div class="ov-stats">
      <div class="ov-stat"><span class="ov-stat-value">${hosts.length}</span><span class="ov-stat-label">Hosts</span></div>
      <div class="ov-stat"><span class="ov-stat-value">${totalPorts}</span><span class="ov-stat-label">Open Ports</span></div>
      <div class="ov-stat"><span class="ov-stat-value">${totalCreds}</span><span class="ov-stat-label">Credentials</span></div>
    </div>
    ${hosts.length === 0 ? `
    <div class="ov-empty">
      <div class="ov-empty-icon">&#9653;</div>
      <p class="ov-hint">No hosts yet — click <strong>+ Add Host</strong> to add one.</p>
    </div>` : ''}
    <div class="scratch-pad-section">
      <div class="scratch-pad-header">
        <span class="scratch-pad-label">Scratch Pad</span>
        <span id="scratch-pad-status" class="scratch-pad-status"></span>
      </div>
      <textarea id="scratch-pad" class="scratch-pad" rows="4" placeholder="Free-form notes for this assessment…">${esc(scratch.text)}</textarea>
    </div>
    <details class="activity-log" id="activity-log">
      <summary>Recent Activity</summary>
      <div class="activity-entries" id="activity-entries"><span style="color:var(--fg-muted);font-size:0.8rem">Loading…</span></div>
    </details>`;

  $('#app').dataset.currentAssessment = eid;
  $('#ov-add-host').addEventListener('click', () => showAddHostModal(eid));
  $('#ov-bulk-nmap').addEventListener('click', () => showBulkNmapModal(eid));
  const ovBack = $('#ov-back-dash');
  if (ovBack) ovBack.addEventListener('click', renderDashboard);

  // Scratch pad auto-save
  bindScratchSession(scratch, $('#scratch-pad'), $('#scratch-pad-status'));

  // Load activity log when the details element is opened
  const actLog = $('#activity-log');
  if (actLog) {
    actLog.addEventListener('toggle', () => {
      if (actLog.open) loadActivityLog(eid);
    });
  }
}

// ---- Editor sessions (shared by notes and scratch pads) ---------------
// A session owns the saves of one note or scratch pad: the server version
// its text is based on (`base`), edit counters that tell whether the text
// still differs from it, and its own timers. Every save names the version it
// is based on, so a stale copy gets a 409 instead of overwriting. Each save
// also carries a random save_id; after a lost reply (network error or 5xx)
// the next attempt lists the earlier ids in base_save_ids, so it applies on
// top of the write that may or may not have landed, instead of conflicting
// with our own text. Saves run only while the session's account (`owner`)
// is signed in.
const MAX_UNACKED = 16;         // base_save_ids the server accepts
const KEEPALIVE_BUDGET = 60000; // bytes of keepalive request bodies in flight (browsers allow 64 KiB)

function newSaveId() {
  const b = new Uint8Array(16);
  crypto.getRandomValues(b);
  return Array.from(b, x => x.toString(16).padStart(2, '0')).join('');
}

// Has edits the server hasn't confirmed.
function isDirty(s) {
  return s.kind === 'note'
    ? NOTE_FIELDS.some(f => s.ed[f] !== s.baseEd[f])
    : s.ed !== s.baseEd;
}

function canSave(s) {
  return signedIn && !s.discarded && !s.conflict && isDirty(s);
}

// A save whose reply never came: it may or may not have been applied.
function rememberUnacked(s, attempt) {
  s.unacked.push(attempt);
  if (s.unacked.length > MAX_UNACKED) s.unacked.shift();
}

// Three-way merge of one text field. base: the server text our edits started
// from; ours: the local text; theirs: the server's current text; sent: texts
// of our own saves whose reply was lost (the server may hold one of them);
// edited: whether we changed the field since base. Returns the side to keep
// ('same' when both are equal), or null when both sides changed it.
function mergeEdit(base, ours, theirs, sent, edited) {
  if (ours === theirs) return 'same';
  if (theirs === base || sent.includes(theirs)) return 'ours';
  if (!edited || ours === base) return 'theirs';
  return null;
}

function editorSessions() {
  const all = [...parkedNoteSessions.values(), ...scratchSessions.values()];
  if (noteSession && !all.includes(noteSession)) all.unshift(noteSession);
  return all;
}

// Another account is signed in, as far as this tab knows: nothing of s is
// sent until its own account is back (see accountIsBack).
const heldForAccount = s => !!(s.owner && account && s.owner !== account);

const saveSession = (s, opts) => (s.kind === 'note' ? saveNoteSession(s, opts) : saveScratch(s, opts));
const showSessionState = s => (s.kind === 'note' ? showNoteState(s) : showScratchState(s));

// Stop a session for good: nothing more is sent, replies still in flight are
// ignored.
function discardSession(s) {
  s.discarded = true;
  clearTimeout(s.saveTimer);
  clearTimeout(s.retryTimer);
  s.saveTimer = s.retryTimer = null;
}

// Drop the sessions `match` selects: those of a note, host or assessment
// deleted in this tab, or the ones the user agreed to drop (Logout, signing
// in here as another account).
function discardEditorSessions(match) {
  for (const s of editorSessions()) {
    if (!match(s)) continue;
    if (s.kind === 'note') dropNoteSession(s);
    else dropScratchSession(s);
  }
}

// Signed in (again), or another account is: save this account's text that
// waited meanwhile, and keep looking (with the retry backoff) for the
// account of any other text that waits.
function resumePendingSaves() {
  for (const s of editorSessions()) {
    if (!canSave(s)) continue;
    if (heldForAccount(s)) {
      if (!s.retryTimer) retryLater(s);
      continue;
    }
    s.retryDelay = 0;
    saveSession(s);
  }
}

// Start this account's pending saves and wait (up to ms) until none is on
// its way.
async function flushAllEditorSessions(ms) {
  const mine = editorSessions().filter(s => !heldForAccount(s));
  for (const s of mine) saveSession(s);
  const busy = s => !s.discarded && (s.inflight || s.queued || s.saving || s.again);
  const until = Date.now() + ms;
  while (Date.now() < until && mine.some(busy)) {
    await new Promise(r => setTimeout(r, 50));
  }
}

function describeUnsaved(sessions) {
  const names = sessions.map(s => (s.kind === 'note'
    ? `"${((noteSnapshot(s) || s.base).title) || 'Untitled'}"`
    : 'a scratch pad'));
  return `Changes to ${names.join(', ')}`;
}

const OTHER_ACCOUNT = 'Not saved - another account is signed in';
const NOT_FOUND = 'Not saved - not found';

// Look up which account is signed in (another tab may have signed in as
// another one), and note it. Returns false when signed out.
async function checkAccount() {
  try {
    const me = await apiGet('/settings/me');
    if (signedIn && me.email && me.email !== account) adoptUser(me.email);
    return true;
  } catch (err) {
    return err.status !== 401;
  }
}

// A save got 404. That alone doesn't say why: the note (or the scratch
// pad's assessment) may have been deleted elsewhere, another account may
// have signed in (in another tab), or something in between answered (e.g. a
// proxy while the server restarts). So nothing is dropped: the account is
// looked up, and while it is still this one the text stays unsaved, with
// Retry, Save as new note, Copy and Discard, and saving is retried (backoff
// up to 30 s) until it works or the user chooses one of those.
async function saveNotFound(s) {
  const stillSignedIn = await checkAccount();
  if (s.discarded) return;
  if (!isDirty(s)) {
    s.error = null; // its changes were discarded meanwhile
  } else if (!stillSignedIn) {
    s.error = { text: 'Not saved - signed out' }; // saved after the next sign-in
  } else {
    s.error = heldForAccount(s) ? { text: OTHER_ACCOUNT } : notFoundError(s);
    retryLater(s);
  }
  showSessionState(s);
}

// Reading the saved copy to compare with got 404. With another account
// signed in, that is why: the conflict stays, and the error says so.
// Otherwise the session leaves the conflict and saves again: if the note (or
// assessment) is there after all, that ends in the conflict again (with the
// latest copy), and otherwise in "Not saved - not found".
async function savedCopyNotFound(s) {
  if (!(await checkAccount())) throw Object.assign(new Error('Session expired'), { status: 401 });
  if (heldForAccount(s)) {
    throw new Error(`Another account is signed in in this browser (another tab or window). Sign in as ${s.owner} again to compare and save this.`);
  }
  if (s.discarded || !s.conflict) return;
  s.conflict = null;
  saveSession(s);
}

// The status of a session whose save got 404: its text is kept, and the
// user can save it again, keep it as a new note, copy it or drop it.
function notFoundError(s) {
  const actions = [['Retry', () => { s.retryDelay = 0; saveSession(s); }]];
  if (s.kind === 'note') actions.push(['Save as new note', ev => saveAsNewNote(s, ev.currentTarget)]);
  actions.push(['Copy', ev => copySessionText(s, ev.currentTarget)], ['Discard', () => discardChanges(s)]);
  return { text: NOT_FOUND, actions };
}

function retryLater(s) {
  clearTimeout(s.retryTimer);
  s.retryDelay = Math.min((s.retryDelay || 1000) * 2, 30000);
  s.retryTimer = setTimeout(() => { s.retryTimer = null; saveSession(s); }, s.retryDelay);
}

// s is held for its account (another one is signed in): look the account up
// again, and keep looking (with the retry backoff) until it is back.
// Returns whether s can be saved now.
async function accountIsBack(s) {
  await checkAccount();
  if (s.discarded) return false;
  if (!heldForAccount(s)) return canSave(s);
  s.error = { text: OTHER_ACCOUNT };
  retryLater(s);
  showSessionState(s);
  return false;
}

// A session's text as plain text (a note's title, then its text).
function sessionText(s) {
  if (s.kind === 'scratch') return s.text;
  const snap = noteSnapshot(s) || s.base;
  return `${snap.title || 'Untitled'}\n\n${htmlToText(snap.content)}`;
}

// "Copy": the session's text to the clipboard. Never by selecting it in the
// note or scratch pad itself, where the next key would replace it all.
const copySessionText = (s, btn) => copyText(sessionText(s), btn);

// Copy text to the clipboard. Without clipboard access (e.g. plain HTTP)
// the text is selected in el, a read-only element showing it, for Ctrl+C.
// Without el, it is copied from a hidden read-only element made for it (or,
// if even that fails, left selected there for Ctrl+C until the focus moves
// on). btn (a "Copy" button) says which.
async function copyText(text, btn, el) {
  try {
    await navigator.clipboard.writeText(text);
    btn.textContent = 'Copied!';
    setTimeout(() => { btn.textContent = 'Copy'; }, 1500);
  } catch {
    const own = !el;
    if (own) {
      el = document.createElement('textarea');
      el.className = 'copy-source';
      el.readOnly = true;
      el.value = text;
      el.addEventListener('blur', () => el.remove());
      document.body.appendChild(el);
    }
    if (el.select) {
      el.focus();
      el.select();
    } else {
      const range = document.createRange();
      range.selectNodeContents(el);
      const sel = window.getSelection();
      sel.removeAllRanges();
      sel.addRange(range);
    }
    if (own && document.execCommand('copy')) {
      el.blur(); // which removes it
      btn.textContent = 'Copied!';
      setTimeout(() => { btn.textContent = 'Copy'; }, 1500);
      return;
    }
    btn.textContent = 'Press Ctrl+C';
  }
}

// Note HTML as plain text: one line per block, for the clipboard.
function htmlToText(html) {
  const doc = new DOMParser().parseFromString(sanitizeHTML(html), 'text/html');
  doc.querySelectorAll('br').forEach(br => br.replaceWith('\n'));
  doc.querySelectorAll('p, div, li, h1, h2, h3, h4, h5, h6, pre, blockquote, tr').forEach(el => el.append('\n'));
  return doc.body.textContent.replace(/\n{3,}/g, '\n\n').trim();
}

// "Discard": the unsaved changes go, after asking; the note or scratch pad
// shows its last saved text again.
function discardChanges(s) {
  if (!confirm('Discard the changes that could not be saved? The text goes back to how it was last saved.')) return;
  clearTimeout(s.saveTimer);
  clearTimeout(s.retryTimer);
  s.saveTimer = s.retryTimer = null;
  Object.assign(s, { conflict: null, error: null, unacked: [], retryDelay: 0 });
  if (s.kind === 'note') {
    for (const f of NOTE_FIELDS) {
      setNoteField(s, f, s.base[f]);
      s.baseEd[f] = s.ed[f];
    }
    clearNoteListMark(s);
    noteSynced(s, false);
  } else {
    s.text = s.base;
    if (s.el) s.el.value = s.text;
    s.baseEd = s.ed;
    syncScratchToAssessment(s);
    scratchSynced(s, false);
  }
}

// ---- Scratch pad save sessions -----------------------------------------
// One per assessment, kept across re-renders: going to a host and back shows
// the latest text (even while it is still saving) instead of the copy the
// assessment was loaded with.
const scratchSessions = new Map(); // eid -> session
let scratchSession = null;         // the session shown in the overview

function scratchSessionFor(eng) {
  const eid = eng.id || eng.ID;
  const text = eng.scratch_pad || '';
  const version = eng.scratch_pad_version ?? 0;
  let s = scratchSessions.get(eid);
  if (!s) {
    s = {
      kind: 'scratch', eid, text, version, owner: eng.account,
      base: text,                   // the server text `version` refers to
      ed: 0, baseEd: 0,             // edit count, and its value when text last matched base
      el: null, statusEl: null,     // set while shown in the overview
      saving: false, again: false,
      inflight: null,               // the save being sent: {id, text, ed, keepalive}
      unacked: [],                  // earlier saves whose reply was lost
      conflict: null,               // server copy that clashes with local edits
      error: null,                  // {text, actions} after a failed save
      saveTimer: null, retryTimer: null, retryDelay: 0, statusTimer: null,
      discarded: false,
    };
    scratchSessions.set(eid, s);
  } else if (version > s.version && !s.saving && !s.conflict) {
    // Saved elsewhere since this tab last saw it.
    scratchServerCopy(s, { text, version });
  }
  return s;
}

// Mirror the session into the cached assessment, which the breadcrumb and
// the sidebar title re-render the overview from.
function syncScratchToAssessment(s) {
  if (!currentAssessment || (currentAssessment.id || currentAssessment.ID) !== s.eid) return;
  currentAssessment.scratch_pad = s.text;
  currentAssessment.scratch_pad_version = s.version;
}

function setScratchStatus(s, text, cls, actions) {
  clearTimeout(s.statusTimer);
  s.statusTimer = null;
  setSaveStatus(s.statusEl, 'scratch-pad-status', text, cls, actions);
}

function showScratchState(s) {
  if (s.conflict) {
    setScratchStatus(s, 'Changed elsewhere', 'status-unsaved', [
      ['Compare\u2026', () => openScratchConflict(s)],
    ]);
  } else if (s.error) {
    setScratchStatus(s, s.error.text, 'status-unsaved', s.error.actions);
  } else {
    setScratchStatus(s, isDirty(s) ? 'Unsaved' : '', isDirty(s) ? 'status-unsaved' : '');
  }
}

function bindScratchSession(s, el, statusEl) {
  if (!el) return;
  scratchSession = s;
  s.el = el;
  s.statusEl = statusEl;
  syncScratchToAssessment(s);
  showScratchState(s);
  el.addEventListener('input', () => {
    if (s.el !== el || s.discarded) return;
    s.text = el.value;
    s.ed++;
    syncScratchToAssessment(s);
    if (s.conflict) return; // saving waits until the user picks a side
    if (!s.error) setScratchStatus(s, 'Unsaved', 'status-unsaved');
    clearTimeout(s.saveTimer);
    s.saveTimer = setTimeout(() => saveScratch(s), 800);
  });
}

// The overview is being replaced: save pending text now.
function releaseScratchSession() {
  const s = scratchSession;
  if (!s) return;
  scratchSession = null;
  clearTimeout(s.statusTimer);
  s.el = s.statusEl = null;
  saveScratch(s);
}

function dropScratchSession(s) {
  discardSession(s);
  if (scratchSessions.get(s.eid) === s) scratchSessions.delete(s.eid);
  if (scratchSession === s) scratchSession = null;
}

async function saveScratch(s, { keepalive = false } = {}) {
  clearTimeout(s.saveTimer);
  s.saveTimer = null;
  if (!canSave(s)) return;
  if (s.saving) { s.again = true; return; }
  clearTimeout(s.retryTimer);
  s.retryTimer = null;
  s.saving = true;
  if (heldForAccount(s) && !(await accountIsBack(s))) {
    s.saving = s.again = false;
    return;
  }
  const attempt = { id: newSaveId(), text: s.text, ed: s.ed };
  const body = { content: attempt.text, version: s.version, save_id: attempt.id };
  if (s.unacked.length) body.base_save_ids = s.unacked.map(u => u.id);
  attempt.keepalive = keepalive && fitsKeepalive(body);
  s.inflight = attempt;
  setScratchStatus(s, 'Saving\u2026', 'status-saving');
  try {
    const res = await apiPost(`/assessments/${s.eid}/scratchpad`, body, 'PUT', { keepalive: attempt.keepalive });
    s.inflight = null;
    if (!s.discarded) scratchSaved(s, attempt, res.scratch_pad_version);
  } catch (err) {
    s.inflight = null;
    if (!s.discarded) await scratchSaveFailed(s, attempt, err);
  } finally {
    s.saving = false;
    if (s.again) { s.again = false; saveScratch(s); }
  }
}

async function scratchSaveFailed(s, attempt, err) {
  const server = err.status === 409 && err.data;
  if (server) {
    scratchServerCopy(s, {
      text: server.scratch_pad ?? '', version: server.scratch_pad_version, saveId: server.scratch_pad_save_id,
    }, attempt);
    return;
  }
  if (err.status === 404) { await saveNotFound(s); return; }
  if (err.status === 401) {
    s.error = { text: 'Not saved - signed out' }; // saved after the next sign-in
  } else if (err.status >= 400 && err.status < 500) {
    s.error = { text: `Save failed (${err.status})` };
  } else {
    // Network or server error: it may still have been applied. The retry
    // lists it in base_save_ids, so it goes on top of it either way.
    rememberUnacked(s, attempt);
    s.error = { text: 'Save failed - retrying' };
    retryLater(s);
  }
  showScratchState(s);
}

// A save landed (attempt: the text it sent).
function scratchSaved(s, attempt, version) {
  Object.assign(s, { version, base: attempt.text, baseEd: attempt.ed, unacked: [], error: null, retryDelay: 0 });
  syncScratchToAssessment(s);
  scratchSynced(s, true);
}

// The session caught up with the server: save what is still ours, or show
// it as saved.
function scratchSynced(s, savedNow) {
  if (isDirty(s)) {
    setScratchStatus(s, 'Unsaved', 'status-unsaved');
    if (!s.saveTimer) {
      if (s.saving) s.again = true; else saveScratch(s);
    }
  } else if (savedNow) {
    setScratchStatus(s, 'Saved \u2713', 'status-saved');
    s.statusTimer = setTimeout(() => setScratchStatus(s, '', ''), 2000);
  } else {
    setScratchStatus(s, '', '');
  }
}

// The server has a newer copy (a 409, or a fresh load of the assessment).
// One of our own saves whose reply got lost is adopted as saved. Otherwise
// the side that changed the text wins; only when both did is the user asked.
function scratchServerCopy(s, server, attempt = null) {
  s.conflict = null;
  const mine = [attempt, ...s.unacked].find(u => u &&
    ((server.saveId && u.id === server.saveId) || u.text === server.text));
  if (mine) { scratchSaved(s, mine, server.version); return; }
  const take = mergeEdit(s.base, s.text, server.text, s.unacked.map(u => u.text), isDirty(s));
  if (!take) {
    s.conflict = server;
    showScratchState(s);
    return;
  }
  Object.assign(s, { version: server.version, base: server.text, unacked: [], error: null, retryDelay: 0 });
  if (take !== 'ours') s.baseEd = s.ed; // the text matches the server copy now
  if (take === 'theirs') {
    s.text = server.text;
    if (s.el) s.el.value = s.text;
  }
  syncScratchToAssessment(s);
  scratchSynced(s, false);
}

async function fetchScratchCopy(eid) {
  const a = await apiGet(`/assessments/${eid}`);
  return { text: a.scratch_pad || '', version: a.scratch_pad_version ?? 0 };
}

// "Compare...": fetch the saved text now and show it next to the local text
// before anything is replaced.
async function openScratchConflict(s) {
  let fresh;
  try {
    fresh = await fetchScratchCopy(s.eid);
  } catch (err) {
    try {
      if (err.status !== 404) throw err;
      await savedCopyNotFound(s);
    } catch (e) {
      if (e.status !== 401) alert(e.message);
    }
    return;
  }
  if (s.discarded || !s.conflict) return;
  scratchServerCopy(s, fresh); // it may have changed again: merge if possible
  if (s.conflict) showScratchConflictDialog(s, fresh);
}

function showScratchConflictDialog(s, theirs, notice = '') {
  showConflictDialog({
    heading: 'Scratch pad changed elsewhere',
    intro: 'The scratch pad was saved from another tab or device while you were editing it, and both versions changed. Compare them, then choose the one to keep.',
    notice,
    theirs: { text: theirs.text },
    mine: { text: s.text },
    keepLabel: 'Add the version you don\u2019t keep below the one you keep, after a separator line',
    act: (choice, keepOther) => resolveScratchConflict(s, theirs, choice, keepOther),
  });
}

// Apply "Load latest" / "Keep mine" with the saved text fetched now. If it
// changed again since the dialog showed it, show the new one instead.
async function resolveScratchConflict(s, shown, choice, keepOther) {
  if (s.discarded) return true;
  let fresh;
  try {
    fresh = await fetchScratchCopy(s.eid);
  } catch (err) {
    if (err.status !== 404) throw err;
    await savedCopyNotFound(s);
    return true;
  }
  if (fresh.version !== shown.version || fresh.text !== shown.text) {
    showScratchConflictDialog(s, fresh, 'The saved version changed again while you were comparing. This is the latest one.');
    return false;
  }
  const when = new Date().toLocaleString([], { dateStyle: 'short', timeStyle: 'short' });
  let text;
  if (choice === 'load') {
    text = keepOther && s.text.trim() ? `${fresh.text}\n\n----- my unsaved version, ${when} -----\n${s.text}` : fresh.text;
  } else {
    text = keepOther && fresh.text.trim() ? `${s.text}\n\n----- version saved elsewhere, ${when} -----\n${fresh.text}` : s.text;
  }
  clearTimeout(s.saveTimer);
  clearTimeout(s.retryTimer);
  s.saveTimer = s.retryTimer = null;
  Object.assign(s, { conflict: null, error: null, retryDelay: 0, unacked: [], version: fresh.version, base: fresh.text, text });
  if (s.el) s.el.value = text;
  if (text === fresh.text) s.baseEd = s.ed; else s.ed++; // the combined or kept text still has to be saved
  syncScratchToAssessment(s);
  if (isDirty(s)) {
    saveScratch(s);
  } else {
    setScratchStatus(s, 'Loaded latest', 'status-saved');
    s.statusTimer = setTimeout(() => setScratchStatus(s, '', ''), 2000);
  }
  return true;
}

// The dialog for a save conflict: the saved version next to the local one
// (each with a Copy button), and Load latest / Keep mine / Decide later.
// The previews are plain text (textContent) or sanitized note HTML.
// act(choice, keepOther) resolves; it returns false when it showed the
// dialog again instead.
function showConflictDialog({ heading, intro, notice, theirs, mine, keepLabel, act }) {
  const pane = (who, side, label) => `
    <section class="conflict-pane">
      <div class="conflict-pane-head">
        <span class="conflict-pane-label">${esc(label)}</span>
        ${side.meta ? `<span class="conflict-pane-meta">${esc(side.meta)}</span>` : ''}
        <button type="button" class="btn btn-sm btn-secondary conflict-copy" data-who="${who}">Copy</button>
      </div>
      ${side.html !== undefined ? `<div class="conflict-pane-title">${esc(side.title || 'Untitled')}</div>` : ''}
      <div class="conflict-preview ${side.html !== undefined ? 'notes-content' : 'conflict-text'}" id="conflict-${who}"></div>
    </section>`;
  showModal(`
    <div class="conflict-dialog">
      <h3>${esc(heading)}</h3>
      <p class="conflict-intro">${esc(intro)}</p>
      ${notice ? `<p class="conflict-notice">${esc(notice)}</p>` : ''}
      <div class="conflict-panes">
        ${pane('theirs', theirs, 'Saved version')}
        ${pane('mine', mine, 'Your version (not saved)')}
      </div>
      <label class="conflict-keep"><input type="checkbox" id="conflict-keep-other" checked> ${esc(keepLabel)}</label>
      <div class="flex gap-2 mt-4">
        <button type="button" class="btn btn-primary" id="conflict-load">Load latest</button>
        <button type="button" class="btn btn-primary" id="conflict-keep">Keep mine</button>
        <button type="button" class="btn btn-secondary" id="conflict-later">Decide later</button>
      </div>
    </div>`, { closeOnBackdrop: false, wide: true });

  for (const [who, side] of [['theirs', theirs], ['mine', mine]]) {
    const el = $(`#conflict-${who}`);
    if (side.html !== undefined) {
      el.innerHTML = sanitizeHTML(side.html);
      applyNoteHighlighting(el); // code blocks look as in the editor
    } else {
      el.textContent = side.text;
    }
  }
  $$('.conflict-copy').forEach(btn => btn.addEventListener('click', () => {
    const side = btn.dataset.who === 'theirs' ? theirs : mine;
    const el = $(`#conflict-${btn.dataset.who}`);
    copyText(side.html !== undefined ? `${side.title || ''}\n\n${el.innerText}` : side.text, btn, el);
  }));
  const buttons = $$('.conflict-dialog button');
  const run = async choice => {
    buttons.forEach(b => { b.disabled = true; });
    try {
      if (await act(choice, $('#conflict-keep-other').checked)) hideModal();
    } catch (err) {
      buttons.forEach(b => { b.disabled = false; });
      if (err.status === 401) hideModal();
      else alert(err.message);
    }
  };
  $('#conflict-load').addEventListener('click', () => run('load'));
  $('#conflict-keep').addEventListener('click', () => run('keep'));
  $('#conflict-later').addEventListener('click', hideModal);
  // The focus moves into the dialog, so keys pressed while comparing can't
  // change the text behind it (Enter picks Decide later).
  $('#conflict-later').focus();
}

const ACTION_ICONS = {
  host_added: '&#43;',
  host_deleted: '&#215;',
  credential_added: '&#128274;',
  port_added: '&#128268;',
  nmap_import: '&#128202;',
  nmap_scan: '&#128202;',
  nmap_bulk: '&#128202;',
};

function relativeTime(iso) {
  const diff = Math.floor((Date.now() - new Date(iso)) / 1000);
  if (diff < 60) return diff + 's ago';
  if (diff < 3600) return Math.floor(diff / 60) + 'm ago';
  if (diff < 86400) return Math.floor(diff / 3600) + 'h ago';
  return Math.floor(diff / 86400) + 'd ago';
}

async function loadActivityLog(eid) {
  const container = $('#activity-entries');
  if (!container) return;
  try {
    const entries = await apiGet(`/assessments/${eid}/activity`);
    if (!entries || entries.length === 0) {
      container.innerHTML = '<span style="color:var(--fg-muted);font-size:0.8rem">No activity recorded yet.</span>';
      return;
    }
    container.innerHTML = entries.map(e => {
      const icon = ACTION_ICONS[e.action] || '&#8226;';
      return `<div class="activity-entry">
        <span class="activity-icon">${icon}</span>
        <span class="activity-detail">${esc(e.detail)}</span>
        <span class="activity-meta">${esc(e.actor_email)} &middot; ${relativeTime(e.created_at)}</span>
      </div>`;
    }).join('');
  } catch (e) {
    if (container) container.innerHTML = `<span style="color:#ef4444;font-size:0.8rem">Failed to load activity.</span>`;
  }
}

function showBulkNmapModal(eid) {
  showModal(`
    <h3>Bulk Import Nmap XML</h3>
    <p style="color:var(--fg-dim);font-size:0.85rem;margin-bottom:1rem">
      Hosts will be created automatically from the IP addresses in the XML.
      Existing hosts whose identifier is a scanned host's address, or a hostname only one scanned address has, will be updated.
      Hosts that were down, or had no open ports in a -Pn scan, are not added.
    </p>
    <form id="form-bulk-nmap">
      <label>Nmap XML file (-sV / -sC output)
        <input type="file" id="bulk-nmap-file" accept=".xml" required>
      </label>
      <div class="flex gap-2 mt-4">
        <button type="submit" class="btn btn-primary">Upload &amp; Import</button>
        <button type="button" class="btn btn-secondary" id="cancel">Cancel</button>
      </div>
    </form>`);

  $('#form-bulk-nmap').addEventListener('submit', async ev => {
    ev.preventDefault();
    const file = $('#bulk-nmap-file').files[0];
    if (!file) { alert('Select an XML file'); return; }
    const fd = new FormData();
    fd.append('file', file);
    try {
      const res = await fetch(`${API_BASE}/assessments/${eid}/nmap`, {
        method: 'POST', headers: authHeaders(), credentials: 'same-origin', body: fd,
      });
      if (res.status === 401) { logout(); throw new Error('Session expired'); }
      if (!res.ok) {
        const d = await res.json().catch(() => ({}));
        throw new Error(d.error || `Upload failed (${res.status})`);
      }
      const data = await res.json();
      hideModal();
      await refreshAssessment();
      const hostsSkipped = data.hosts_skipped
        ? ` Skipped ${data.hosts_skipped} host entr${data.hosts_skipped !== 1 ? 'ies that were' : 'y that was'} down, not scanned, without an address, or (-Pn) without open ports.`
        : '';
      alert(`Import complete: ${data.hosts_found} host${data.hosts_found !== 1 ? 's' : ''} found, ${data.hosts_created} new, ${data.ports_added} port${data.ports_added !== 1 ? 's' : ''} added, ${data.ports_updated} updated.${hostsSkipped}${nmapKeptNote(data.kept)}${nmapSkippedNote(data.skipped)}`);
    } catch (e) { alert(e.message); }
  });
  $('#cancel').addEventListener('click', hideModal);
}

/* ==========================================================
   Host Detail (tabbed: Ports | Credentials)
   ========================================================== */

// A password or hash cell of the credentials table. value is undefined until
// GET /hosts/:hid/credentials has answered (see loadCredentialRows); failed
// marks a value the server could not decrypt.
function credSecretCell(kind, value, failed) {
  const label = kind === 'pass' ? 'password' : 'hash';
  if (failed) {
    return `<div class="${kind}-cell"><span style="color:#ef4444" title="The server cannot decrypt this ${label}: its ENCRYPTION_KEY does not match the one it was saved with. Editing the credential keeps the stored ${label} unless you type a new one.">&#9888; cannot be decrypted</span></div>`;
  }
  if (value === undefined) return `<div class="${kind}-cell"><span class="${kind}-masked">&hellip;</span></div>`;
  if (value === '') return `<div class="${kind}-cell"></div>`;
  return `<div class="${kind}-cell">
    <span class="${kind}-masked">&#8226;&#8226;&#8226;&#8226;&#8226;&#8226;&#8226;&#8226;</span>
    <span class="${kind}-plain mono hidden">${esc(value)}</span>
    <button class="btn-icon ${kind}-toggle" title="Show ${label}">${ICON_EYE}</button>
    <button class="btn-icon copy-cred-${kind}" title="Copy ${label}">${ICON_COPY}</button>
  </div>`;
}

// One credentials-table row. Until loaded, the password and hash are left
// out (the host payload has no flag for a value that failed to decrypt).
function credRowHTML(cr, hid, loaded) {
  const cid  = cr.id       ?? cr.ID       ?? '';
  const user = cr.username ?? cr.Username ?? '';
  const src  = cr.source   ?? cr.Source   ?? '';
  const pass = loaded ? (cr.password ?? '') : undefined;
  const hash = loaded ? (cr.hash ?? '') : undefined;
  const flags = (loaded ? '' : ' data-pending="1"') +
    (loaded && cr.password_error ? ' data-pass-error="1"' : '') +
    (loaded && cr.hash_error ? ' data-hash-error="1"' : '');
  return `<tr data-cred-id="${esc(cid)}" data-host-id="${esc(hid)}" data-user="${esc(user)}" data-pass="${esc(pass ?? '')}" data-hash="${esc(hash ?? '')}" data-source="${esc(src)}"${flags}>
    <td class="mono"><div class="cred-user-cell">${esc(user)}<button class="btn-icon copy-cred-user" title="Copy username">${ICON_COPY}</button></div></td>
    <td>${credSecretCell('pass', pass, loaded && cr.password_error)}</td>
    <td>${credSecretCell('hash', hash, loaded && cr.hash_error)}</td>
    <td>${esc(src)}</td>
    <td>
      <button class="btn btn-sm btn-secondary edit-cred">Edit</button>
      <button class="btn btn-sm btn-danger del-cred">Del</button>
    </td>
  </tr>`;
}

// Fills the credentials table from GET /hosts/:hid/credentials, which
// decrypts passwords and hashes and flags any it could not decrypt.
let credLoadSeq = 0;
async function loadCredentialRows(hid) {
  if (!$('#cred-table')) return;
  const seq = ++credLoadSeq;
  let creds = null, error = null;
  try { creds = await apiGet(`/hosts/${hid}/credentials`); } catch (e) { error = e; }
  const table = $('#cred-table');
  if (seq !== credLoadSeq || !table || table.dataset.hid !== String(hid)) return; // superseded
  if (error) {
    table.querySelectorAll('tr[data-pending] .pass-masked, tr[data-pending] .hash-masked').forEach(el => {
      el.textContent = 'not loaded';
      el.title = error.message;
    });
    return;
  }
  table.querySelector('tbody').innerHTML = creds.map(cr => credRowHTML(cr, hid, true)).join('');
}

function renderHostDetail(host) {
  releaseEditors();
  const hid   = host.id   || host.ID;
  const ident = host.identifier || host.Identifier || '';
  const label = host.label || host.Label || '';
  const dtype = host.device_type || host.DeviceType || '';
  const os    = host.os || host.OS || '';
  const ports   = host.ports        || host.Ports        || [];
  const creds   = host.creds        || host.Creds        || [];
  const notes   = host.notes        || host.Notes        || [];
  const outputs = host.tool_outputs || host.ToolOutputs  || [];
  const eid        = currentAssessment.id || currentAssessment.ID;
  const compromised = host.compromised || host.Compromised || false;

  const hostTabs = hostTabOrder();

  const app = $('#app');
  app.dataset.currentAssessment = eid;

  app.innerHTML = `
    <div class="page-header">
      <div class="page-header-left">
        <div class="page-breadcrumb">
          <span class="crumb-link" id="hd-back-ov">${esc(currentAssessment.name || currentAssessment.Name || 'Assessment')}</span>
          <span class="crumb-sep">/</span>
          <span>${esc(ident)}</span>
        </div>
        <div class="page-title-row">
          <h2 class="page-title">${esc(ident)}</h2>
          <button class="skull-btn skull-btn-lg${compromised ? ' compromised' : ''}" data-hid="${hid}" title="Mark as compromised">&#9760;</button>
        </div>
        <div class="host-meta">
          <div class="host-meta-item">Identifier: <span class="inline-editable" data-field="identifier" data-hid="${hid}" data-type="text">${esc(ident)}</span></div>
          <div class="host-meta-item">Label: <span class="inline-editable" data-field="label" data-hid="${hid}" data-type="text">${label ? esc(label) : '<em class="placeholder">Click to set</em>'}</span></div>
          <div class="host-meta-item">OS: <span class="inline-editable" data-field="os" data-hid="${hid}" data-type="select" data-options="Linux,Windows,macOS,FreeBSD,Other">${os ? esc(os) : '<em class="placeholder">Click to set</em>'}</span></div>
        </div>
      </div>
      <div class="page-header-actions">
        <button class="btn btn-sm btn-danger" id="hd-delete-host">Delete Host</button>
      </div>
    </div>

    <div class="tab-bar">
      ${hostTabs.map(tab => {
        const labels = { ports: `Ports (${ports.length})`, credentials: `Credentials (${creds.length})`, notes: `Notes (${notes.length})`, services: `Services (${outputs.length})`, commands: 'Commands' };
        return `<button class="tab-btn${activeHostTab === tab ? ' active' : ''}" data-tab="${tab}" draggable="true">${labels[tab]}</button>`;
      }).join('')}
    </div>

    <div id="tab-content-ports" class="tab-content${activeHostTab === 'ports' ? ' active' : ''}">
      <div class="tab-toolbar">
        <button class="btn btn-sm btn-primary" id="hd-add-port">+ Add Port</button>
        <button class="btn btn-sm btn-green" id="hd-import-nmap">Import Nmap</button>
      </div>
      ${ports.length > 0 ? `
      <table id="port-table">
        <thead>
          <tr><th>Port</th><th>Protocol</th><th>Service</th><th>Version</th><th>Script Data</th><th>Actions</th></tr>
        </thead>
        <tbody>
          ${ports.map(p => {
            const pid = p.id ?? p.ID ?? '';
            const num = p.number ?? p.Number ?? '';
            const proto = p.protocol ?? p.Protocol ?? '';
            const svc = p.service ?? p.Service ?? '';
            const info = p.info ?? p.Info ?? '';
            const scriptRaw = p.script_output ?? p.ScriptOutput ?? '';
            const scripts = (() => {
              if (!scriptRaw) return [];
              try { return JSON.parse(scriptRaw); } catch { return []; }
            })();
            const hasScripts = scripts.length > 0;
            const scriptRow = hasScripts ? `<tr class="port-scripts-row"><td colspan="6"><div class="port-scripts-content">${
              scripts.map(s => `<div class="port-script-entry"><div class="port-script-id">${esc(s.id)}</div><pre class="port-script-output">${esc(s.output)}</pre></div>`).join('')
            }</div></td></tr>` : '';
            return `<tr class="port-row${hasScripts ? ' has-scripts' : ''}" data-port-id="${pid}" data-host-id="${hid}" data-num="${num}">
              <td class="mono">${esc(String(num))}</td>
              <td>${esc(proto)}</td>
              <td>${portValueHTML(svc, p.service_edited)}</td>
              <td>${portValueHTML(info, p.info_edited)}</td>
              <td class="script-data-cell">${hasScripts ? '<span class="script-data-yes">&#10003;</span>' : '<span class="script-data-no">&#8212;</span>'}</td>
              <td>
                <button class="btn btn-sm btn-secondary edit-port">Edit</button>
                <button class="btn btn-sm btn-danger del-port">Del</button>
              </td>
            </tr>${scriptRow}`;
          }).join('')}
        </tbody>
      </table>` : '<div class="empty-state"><p>No ports discovered yet</p></div>'}
    </div>

    <div id="tab-content-credentials" class="tab-content${activeHostTab === 'credentials' ? ' active' : ''}">
      <div class="tab-toolbar">
        <button class="btn btn-sm btn-primary" id="hd-add-cred">+ Add Credential</button>
      </div>
      ${creds.length > 0 ? `
      <table id="cred-table" data-hid="${esc(hid)}">
        <thead>
          <tr><th>Username</th><th>Password</th><th>Hash</th><th>Source</th><th style="width:120px">Actions</th></tr>
        </thead>
        <tbody>
          ${creds.map(cr => credRowHTML(cr, hid, false)).join('')}
        </tbody>
      </table>` : '<div class="empty-state"><p>No credentials found yet</p></div>'}
    </div>

    <div id="tab-content-notes" class="tab-content${activeHostTab === 'notes' ? ' active' : ''}">
      <div class="notes-container" data-hid="${hid}">
        <div class="notes-file-list">
          <div class="notes-new-wrap">
            <button class="btn btn-sm btn-primary notes-new-btn" id="notes-new-file">+ New File</button>
            <div class="notes-tmpl-wrap">
              <button type="button" class="btn btn-sm btn-secondary notes-tmpl-btn" id="notes-tmpl-btn" title="New from template">&#9660;</button>
              <div class="notes-tmpl-menu hidden" id="notes-tmpl-menu">
                ${Object.entries(NOTE_TEMPLATES).map(([key, t]) => `<div class="notes-tmpl-item" data-template="${esc(key)}">${esc(t.title)}</div>`).join('')}
              </div>
            </div>
          </div>
          <div id="notes-list">
            ${notes.map(n => {
              const nid = n.id ?? n.ID ?? '';
              const title = n.title ?? n.Title ?? 'Untitled';
              const updatedAt = n.updated_at ?? n.UpdatedAt ?? '';
              const meta = updatedAt ? relativeTime(updatedAt) : '';
              return `<div class="notes-file-item" data-nid="${nid}" data-hid="${hid}" draggable="true">
                <span class="notes-file-handle" title="Drag to reorder">&#8942;&#8942;</span>
                <div class="notes-file-info">
                  <span class="notes-file-title">${esc(title)}</span>
                  ${meta ? `<span class="notes-file-meta">${meta}</span>` : ''}
                </div>
                <div class="notes-file-actions">
                  <button class="btn-icon notes-del-file" title="Delete">&#10005;</button>
                </div>
              </div>`;
            }).join('')}
          </div>
        </div>
        <div class="notes-editor-pane">
          <div id="notes-editor-empty" class="empty-state${notes.length > 0 ? ' hidden' : ''}">
            <p>Select or create a note file</p>
          </div>
          <div id="notes-editor-active" class="hidden">
            <input type="text" id="notes-title-input" class="notes-title-input" placeholder="Note title">
            <div class="notes-toolbar">
              <button type="button" data-cmd="bold" title="Bold" class="tb-btn"><svg width="11" height="14" viewBox="0 0 11 14"><path d="M0 0h5.5c2.5 0 4.5 1.2 4.5 3.5 0 1.4-.8 2.5-2 3 1.5.5 2.5 1.8 2.5 3.3C10.5 12.3 8.3 14 5.8 14H0V0zm2.2 5.8h3c1.4 0 2.3-.7 2.3-1.9s-.9-1.8-2.3-1.8h-3v3.7zm0 6.1h3.3c1.5 0 2.5-.8 2.5-2s-1-2-2.5-2H2.2v4z" fill="currentColor"/></svg></button>
              <button type="button" data-cmd="italic" title="Italic" class="tb-btn"><svg width="8" height="14" viewBox="0 0 8 14"><path d="M3 0h5l-.5 2H5.2L3.2 12h2.3L5 14H0l.5-2h2.3L4.8 2H2.5L3 0z" fill="currentColor"/></svg></button>
              <button type="button" data-cmd="underline" title="Underline" class="tb-btn"><svg width="12" height="16" viewBox="0 0 12 16"><path d="M1 0h2v7c0 2.2 1.3 3.5 3 3.5s3-1.3 3-3.5V0h2v7.2C11 10.8 8.8 12 6 12S1 10.8 1 7.2V0zM0 14h12v1.5H0V14z" fill="currentColor"/></svg></button>
              <span class="tb-sep"></span>
              <div class="notes-highlight-wrap">
                <button type="button" id="notes-highlight-btn" title="Highlight" class="tb-btn tb-highlight"><svg width="14" height="14" viewBox="0 0 14 14"><path d="M0 10l7-10 4 3-7 10-4.5 1L0 10z" fill="currentColor" opacity="0.85"/><rect x="0" y="12.5" width="14" height="1.5" rx="0.5" fill="#ffff00" id="hl-indicator"/></svg></button>
                <div class="notes-highlight-colors hidden" id="notes-highlight-colors">
                  <span data-color="#ffff00" style="background:#ffff00" title="Yellow"></span>
                  <span data-color="#00ff00" style="background:#00ff00" title="Green"></span>
                  <span data-color="#00cfff" style="background:#00cfff" title="Cyan"></span>
                  <span data-color="#ff6b6b" style="background:#ff6b6b" title="Red"></span>
                  <span data-color="#da70d6" style="background:#da70d6" title="Orchid"></span>
                  <span data-color="#ffa500" style="background:#ffa500" title="Orange"></span>
                  <span data-color="transparent" title="No highlight" class="hl-none">&#x2715;</span>
                </div>
              </div>
              <span class="tb-sep"></span>
              <button type="button" data-cmd="insertUnorderedList" title="Bullet List" class="tb-btn"><svg width="14" height="12" viewBox="0 0 14 12"><circle cx="1.5" cy="1.5" r="1.5" fill="currentColor"/><rect x="5" y="0.5" width="9" height="2" rx="0.5" fill="currentColor"/><circle cx="1.5" cy="6" r="1.5" fill="currentColor"/><rect x="5" y="5" width="9" height="2" rx="0.5" fill="currentColor"/><circle cx="1.5" cy="10.5" r="1.5" fill="currentColor"/><rect x="5" y="9.5" width="9" height="2" rx="0.5" fill="currentColor"/></svg></button>
              <button type="button" data-cmd="insertOrderedList" title="Numbered List" class="tb-btn"><svg width="14" height="12" viewBox="0 0 14 12"><text x="0" y="4" font-size="5" fill="currentColor">1.</text><rect x="5" y="0.5" width="9" height="2" rx="0.5" fill="currentColor"/><text x="0" y="8.5" font-size="5" fill="currentColor">2.</text><rect x="5" y="5" width="9" height="2" rx="0.5" fill="currentColor"/><text x="0" y="13" font-size="5" fill="currentColor">3.</text><rect x="5" y="9.5" width="9" height="2" rx="0.5" fill="currentColor"/></svg></button>
              <span class="tb-sep"></span>
              <button type="button" data-format="h2" title="Heading 2" class="tb-btn tb-btn-text">H2</button>
              <button type="button" data-format="h3" title="Heading 3" class="tb-btn tb-btn-text">H3</button>
              <button type="button" id="notes-code-btn" title="Code Block" class="tb-btn tb-btn-text">&lt;/&gt;</button>
              <span class="tb-sep"></span>
              <button type="button" id="notes-copy-btn" title="Copy note as plain text" class="tb-btn tb-btn-text">Copy</button>
              <div class="tb-spacer"></div>
              <span id="notes-save-status" class="notes-save-status"></span>
            </div>
            <div id="notes-content" class="notes-content" contenteditable="true"></div>
          </div>
        </div>
      </div>
    </div>

    <div id="tab-content-commands" class="tab-content${activeHostTab === 'commands' ? ' active' : ''}">
      <div class="tab-toolbar">
        <button class="btn btn-sm btn-primary" id="hd-add-command">+ Add Command</button>
      </div>
      <div id="host-commands-content">
        <div class="empty-state"><p>Loading commands...</p></div>
      </div>
    </div>

    <div id="tab-content-services" class="tab-content${activeHostTab === 'services' ? ' active' : ''}">
      <div class="tab-toolbar">
        <button class="btn btn-sm btn-secondary" id="hd-refresh-services">Refresh</button>
      </div>
      ${outputs.length === 0 ? `
      <div class="empty-state">
        <p>No tool output yet. Pipe results from the terminal:</p>
        <pre class="services-hint">whatweb http://${esc(ident)} | pk --target ${esc(ident)} --tool whatweb</pre>
      </div>` : `
      <table class="services-table">
        <thead><tr><th>Tool</th><th>Command</th><th>Time</th><th></th></tr></thead>
        <tbody>
          ${outputs.map(o => {
            const oid  = o.id      ?? o.ID      ?? '';
            const tool = o.tool    ?? o.Tool    ?? 'unknown';
            const cmd  = o.command ?? o.Command ?? '';
            const ts   = o.created_at ?? o.CreatedAt ?? '';
            return `<tr class="tool-output-row" data-oid="${oid}">
              <td><span class="tool-badge">${esc(tool)}</span></td>
              <td class="tool-cmd-cell">${cmd ? `<code>${esc(cmd)}</code>` : '<em style="color:var(--fg-muted)">—</em>'}</td>
              <td class="tool-ts-cell">${ts ? relativeTime(ts) : ''}</td>
              <td><button class="btn-icon tool-del-btn" data-oid="${oid}" data-hid="${hid}" title="Delete">&#10005;</button></td>
            </tr>
            <tr class="tool-output-detail hidden" data-oid="${oid}">
              <td colspan="4"><pre class="tool-output-pre">${ansiToHtml(o.output ?? o.Output ?? '')}</pre></td>
            </tr>`;
          }).join('')}
        </tbody>
      </table>`}
    </div>`;

  // Tab switching
  $$('.tab-btn').forEach(btn => {
    btn.addEventListener('click', async () => {
      $$('.tab-btn').forEach(b => b.classList.remove('active'));
      $$('.tab-content').forEach(tc => tc.classList.remove('active'));
      btn.classList.add('active');
      activeHostTab = btn.dataset.tab;
      const panel = $(`#tab-content-${activeHostTab}`);
      if (panel) panel.classList.add('active');
      // Services tab always re-fetches directly so externally piped data appears immediately.
      if (activeHostTab === 'services') {
        try {
          const outputs = await apiGet(`/hosts/${hid}/outputs`);
          const hosts = currentAssessment.hosts || currentAssessment.Hosts || [];
          const h = hosts.find(x => (x.id || x.ID) === hid);
          if (h) h.tool_outputs = outputs;
          renderHostDetail(h || { id: hid, tool_outputs: outputs });
        } catch (_) { /* ignore, stale data is fine */ }
      }
      // Commands tab fetches host-scoped commands.
      if (activeHostTab === 'commands') {
        renderHostCommandsTab(hid);
      }
    });
  });

  // Tab drag-and-drop reordering
  let dragSrcTab = null;
  $$('.tab-btn').forEach(btn => {
    btn.addEventListener('dragstart', e => {
      dragSrcTab = btn;
      btn.classList.add('tab-dragging');
      e.dataTransfer.effectAllowed = 'move';
    });
    btn.addEventListener('dragend', () => {
      $$('.tab-btn').forEach(b => b.classList.remove('tab-dragging', 'tab-drag-over'));
      dragSrcTab = null;
    });
    btn.addEventListener('dragover', e => {
      e.preventDefault();
      e.dataTransfer.dropEffect = 'move';
      if (dragSrcTab && btn !== dragSrcTab) btn.classList.add('tab-drag-over');
    });
    btn.addEventListener('dragleave', () => btn.classList.remove('tab-drag-over'));
    btn.addEventListener('drop', e => {
      e.preventDefault();
      btn.classList.remove('tab-drag-over');
      if (!dragSrcTab || dragSrcTab === btn) return;
      const bar = btn.parentElement;
      const btns = Array.from(bar.querySelectorAll('.tab-btn'));
      const fromIdx = btns.indexOf(dragSrcTab);
      const toIdx = btns.indexOf(btn);
      if (fromIdx < toIdx) bar.insertBefore(dragSrcTab, btn.nextSibling);
      else bar.insertBefore(dragSrcTab, btn);
      const newOrder = Array.from(bar.querySelectorAll('.tab-btn')).map(b => b.dataset.tab);
      saveHostTabOrder(newOrder);
    });
  });

  // Breadcrumb back to assessment overview
  const hdBackOv = $('#hd-back-ov');
  if (hdBackOv) hdBackOv.addEventListener('click', () => renderAssessmentOverview(currentAssessment));

  // Action buttons
  $('#hd-add-port').addEventListener('click', () => showAddPortModal(hid));
  $('#hd-add-cred').addEventListener('click', () => showAddCredentialModal(hid));
  loadCredentialRows(hid);
  const addCmdBtn = $('#hd-add-command');
  if (addCmdBtn) addCmdBtn.addEventListener('click', () => showAddHostCommandModal(hid));

  // Always fetch command count so the tab label shows immediately.
  // If the tab is already active, do the full load instead.
  if (activeHostTab === 'commands') {
    renderHostCommandsTab(hid);
  } else {
    apiGet(`/hosts/${hid}/commands`).then(cmds => {
      const tabBtn = document.querySelector('.tab-btn[data-tab="commands"]');
      if (tabBtn) tabBtn.textContent = `Commands (${cmds.length})`;
    }).catch(() => {});
  }
  const refreshServicesBtn = $('#hd-refresh-services');
  if (refreshServicesBtn) {
    refreshServicesBtn.addEventListener('click', async () => {
      try {
        const outputs = await apiGet(`/hosts/${hid}/outputs`);
        const hosts = currentAssessment.hosts || currentAssessment.Hosts || [];
        const h = hosts.find(x => (x.id || x.ID) === hid);
        if (h) h.tool_outputs = outputs;
        activeHostTab = 'services';
        renderHostDetail(h || { id: hid, tool_outputs: outputs });
      } catch (e) { alert(e.message); }
    });
  }
  $('#hd-delete-host').addEventListener('click', async () => {
    if (!confirm('Delete this host and all its data?')) return;
    try {
      await apiDelete(`/hosts/${hid}`);
      discardEditorSessions(s => s.kind === 'note' && s.hid === hid); // its notes have nowhere to save to
      await refreshAssessment();
    } catch (e) { alert(e.message); }
  });
  // Services tab — row expand + delete
  const servicesPanel = $('#tab-content-services');
  if (servicesPanel) {
    servicesPanel.addEventListener('click', async (e) => {
      // Delete button
      const delBtn = e.target.closest('.tool-del-btn');
      if (delBtn) {
        e.stopPropagation();
        if (!confirm('Delete this tool output?')) return;
        const oid = delBtn.dataset.oid;
        try {
          await apiDelete(`/hosts/${hid}/outputs/${oid}`);
          activeHostTab = 'services';
          await refreshAssessment();
        } catch (err) { alert(err.message); }
        return;
      }
      // Row expand/collapse
      const row = e.target.closest('.tool-output-row');
      if (row && !e.target.closest('button')) {
        const oid = row.dataset.oid;
        const detail = servicesPanel.querySelector(`.tool-output-detail[data-oid="${oid}"]`);
        if (detail) detail.classList.toggle('hidden');
      }
    });
  }

  $('#hd-import-nmap').addEventListener('click', () => showNmapImportModal(hid));

  // Notes
  $('#notes-new-file').addEventListener('click', () => createNoteFile(hid));
  initNotesEditor(hid);
}

/* ==========================================================
   Notes – file list + editor
   ========================================================== */
let activeNoteId = null; // note shown (or loading) in the editor, re-opened after re-renders

const NOTE_TEMPLATES = {
  'recon': {
    title: 'Recon',
    content: '<h2>Reconnaissance</h2><h3>Open Ports</h3><ul><li></li></ul><h3>Services</h3><ul><li></li></ul><h3>Findings</h3><ul><li></li></ul>'
  },
  'exploitation': {
    title: 'Exploitation',
    content: '<h2>Exploitation</h2><h3>Vulnerabilities</h3><ul><li></li></ul><h3>Exploits Used</h3><ul><li></li></ul><h3>Proof of Compromise</h3><ul><li></li></ul>'
  },
  'post-exploitation': {
    title: 'Post-Exploitation',
    content: '<h2>Post-Exploitation</h2><h3>Privilege Escalation</h3><ul><li></li></ul><h3>Persistence</h3><ul><li></li></ul><h3>Lateral Movement</h3><ul><li></li></ul>'
  },
  'loot': {
    title: 'Loot',
    content: '<h2>Loot</h2><h3>Credentials</h3><ul><li></li></ul><h3>Files</h3><ul><li></li></ul><h3>Other</h3><ul><li></li></ul>'
  }
};

// ---- Note save sessions ----------------------------------------------
// Every note loaded into the editor gets a session that owns its saves (see
// "Editor sessions" above). A save always goes to the session's note and
// reads the session's own text, never whatever the editor shows when a
// timer, blur or retry fires. A session with unsaved work that leaves the
// editor is parked with a copy of its text: it keeps saving in the
// background, and reopening the note shows that text instead of an older
// server copy. When the note changed elsewhere, title and text are merged
// field by field: a rename elsewhere and local text edits (or the other way
// round) both survive, and only a field changed on both sides needs the user.
let noteSession = null;               // the session shown in the editor
const parkedNoteSessions = new Map(); // nid -> session with unsaved work, out of the editor
const noteRequestQueues = new Map();  // nid -> tail of that note's PUTs (run one at a time)
let noteSelectSeq = 0;                // only the latest selectNote() renders
const NOTE_FIELDS = ['title', 'content'];

// note: the server copy the editor shows ({title, content, version, ...});
// owner: the account its assessment belongs to (see fetchAssessment).
function newNoteSession(eid, hid, nid, note, owner) {
  const title = note.title ?? note.Title ?? '';
  const content = note.content ?? note.Content ?? '';
  return {
    kind: 'note', eid, hid, nid,
    owner,                            // the account it is saved as
    version: note.version ?? 0,
    base: { title, content },         // the server copy `version` refers to
    updatedAt: note.updated_at ?? note.UpdatedAt ?? null,
    titleEl: null, contentEl: null, statusEl: null, // set while shown in the editor
    draft: null,                      // {title, content} captured when it left the editor
    ed: { title: 0, content: 0 },     // edits per field
    baseEd: { title: 0, content: 0 }, // ed when that field last matched base
    inflight: null,                   // the save being sent: {id, title, content, ed, keepalive}
    unacked: [],                      // earlier saves whose reply was lost
    conflict: null,                   // server copy that clashes with local edits
    error: null,                      // {text, actions} after a failed save
    queued: null, saveTimer: null, retryTimer: null, retryDelay: 0, statusTimer: null,
    savingAsNew: false,               // "Save as new note" is on its way: the editor stays read-only
    discarded: false,                 // dropped: deleted in this tab, or by the user's choice
  };
}

// A note copy from the server: a 409 body or GET /notes/:nid.
function serverNoteCopy(n) {
  return {
    title: n.title ?? n.Title ?? '',
    content: n.content ?? n.Content ?? '',
    version: n.version ?? 0,
    updatedAt: n.updated_at ?? n.UpdatedAt ?? null,
    saveId: n.save_id || null,
  };
}

// Write a save-status line. Actions become small buttons built with
// textContent, never markup. Pressing one leaves the focus in the editor:
// its blur would start a save that redraws this line, and the button with
// it, before the click lands.
function setSaveStatus(el, baseClass, text, cls, actions = []) {
  if (!el) return;
  el.textContent = text;
  el.className = baseClass + (cls ? ' ' + cls : '');
  for (const [label, onClick] of actions) {
    const btn = document.createElement('button');
    btn.type = 'button';
    btn.className = 'btn btn-sm btn-secondary save-status-action';
    btn.textContent = label;
    btn.addEventListener('mousedown', ev => ev.preventDefault());
    btn.addEventListener('click', onClick);
    el.appendChild(btn);
  }
}

// Every status update cancels a pending "Saved" fade, so an earlier success
// can never blank a later failure.
function setNoteSaveStatus(s, text, cls, actions) {
  clearTimeout(s.statusTimer);
  s.statusTimer = null;
  setSaveStatus(s.statusEl, 'notes-save-status', text, cls, actions);
}

function flashNoteStatus(s, text) {
  setNoteSaveStatus(s, text, 'status-saved');
  s.statusTimer = setTimeout(() => setNoteSaveStatus(s, '', ''), 2000);
}

// Show a session's state in the editor while it is shown there, and flag
// its entry in the file list while its text isn't safely saved.
function showNoteState(s) {
  markNoteListItem(s);
  if (!s.statusEl) return;
  if (s.conflict) {
    setNoteSaveStatus(s, 'Changed elsewhere', 'status-unsaved', [
      ['Compare\u2026', () => openNoteConflict(s)],
    ]);
  } else if (s.error) {
    setNoteSaveStatus(s, s.error.text, 'status-unsaved', s.error.actions);
  } else {
    setNoteSaveStatus(s, isDirty(s) ? 'Unsaved' : '', isDirty(s) ? 'status-unsaved' : '');
  }
}

const noteListMeta = nid => $(`.notes-file-item[data-nid="${nid}"] .notes-file-meta`);

// Flag a note in the file list while it is in conflict or failing to save.
function markNoteListItem(s) {
  const meta = noteListMeta(s.nid);
  if (!meta || !(s.conflict || s.error)) return;
  meta.textContent = s.conflict ? 'changed elsewhere' : 'not saved';
  meta.classList.add('status-unsaved');
}

// Back to the usual "updated" time once the note is in sync again (text:
// what to show instead, e.g. "just now" after our own save).
function clearNoteListMark(s, text) {
  const meta = noteListMeta(s.nid);
  if (!meta || (!text && !meta.classList.contains('status-unsaved'))) return;
  meta.textContent = text || (s.updatedAt ? relativeTime(s.updatedAt) : 'just now');
  meta.classList.remove('status-unsaved');
}

// The session's text: read from the editor while it is shown there,
// otherwise the copy taken when it left. Code blocks are saved as raw code
// (no hljs markup).
function noteSnapshot(s) {
  if (!s.contentEl) return s.draft;
  const clone = s.contentEl.cloneNode(true);
  clone.querySelectorAll('pre.hljs-code-block code').forEach(el => {
    el.textContent = el.textContent;
  });
  return { title: s.titleEl.value, content: clone.innerHTML };
}

// Put a server value into the session's editor, or its parked draft.
function setNoteField(s, field, value) {
  if (field === 'title') {
    if (s.titleEl) s.titleEl.value = value;
    else if (s.draft) s.draft.title = value;
  } else if (s.contentEl) {
    s.contentEl.innerHTML = sanitizeHTML(value);
    applyNoteHighlighting(s.contentEl);
  } else if (s.draft) {
    s.draft.content = value;
  }
}

// Record an edit of field ('title' or 'content') and (re)start the debounced
// save.
function noteEdited(s, field) {
  s.ed[field]++;
  if (s.conflict || s.discarded) return; // saving waits until the user picks a side
  if (!s.error) setNoteSaveStatus(s, 'Unsaved', 'status-unsaved');
  clearTimeout(s.saveTimer);
  s.saveTimer = setTimeout(() => saveNoteSession(s), 1000);
}

// PUTs of one note run one after another, so an autosave and a rename of the
// same note never race each other's version check.
function queueNoteRequest(nid, fn) {
  const run = (noteRequestQueues.get(nid) || Promise.resolve()).then(fn);
  const tail = run.catch(() => {});
  noteRequestQueues.set(nid, tail);
  tail.then(() => { if (noteRequestQueues.get(nid) === tail) noteRequestQueues.delete(nid); });
  return run;
}

// Save the session's note now if it has unsaved edits. Each attempt reads
// the latest text and version when it starts.
function saveNoteSession(s, opts) {
  clearTimeout(s.saveTimer);
  s.saveTimer = null;
  if (!canSave(s)) return Promise.resolve();
  if (!s.queued) {
    s.queued = queueNoteRequest(s.nid, () => {
      s.queued = null;
      return putNoteSession(s, opts);
    });
  }
  return s.queued;
}

async function putNoteSession(s, { keepalive = false } = {}) {
  if (!canSave(s) || (heldForAccount(s) && !(await accountIsBack(s)))) return;
  const snap = noteSnapshot(s);
  if (!snap) return;
  clearTimeout(s.retryTimer);
  s.retryTimer = null;
  const attempt = { id: newSaveId(), title: snap.title, content: snap.content, ed: { ...s.ed } };
  const body = { title: attempt.title, content: attempt.content, version: s.version, save_id: attempt.id };
  if (s.unacked.length) body.base_save_ids = s.unacked.map(u => u.id);
  attempt.keepalive = keepalive && fitsKeepalive(body);
  s.inflight = attempt;
  setNoteSaveStatus(s, 'Saving\u2026', 'status-saving');
  let res;
  try {
    res = await apiPost(`/hosts/${s.hid}/notes/${s.nid}`, body, 'PUT', { keepalive: attempt.keepalive });
  } catch (err) {
    s.inflight = null;
    if (!s.discarded) await noteSaveFailed(s, attempt, err);
    return;
  }
  s.inflight = null;
  if (!s.discarded) noteSaved(s, attempt, res.version);
}

async function noteSaveFailed(s, attempt, err) {
  const server = err.status === 409 && err.data && err.data.note;
  if (server) { noteServerCopy(s, serverNoteCopy(server), attempt); return; }
  if (err.status === 404) { await saveNotFound(s); return; }
  if (err.status === 401) {
    s.error = { text: 'Not saved - signed out' }; // saved after the next sign-in
  } else if (err.status >= 400 && err.status < 500) {
    s.error = { text: `Save failed (${err.status})` };
  } else {
    // Network or server error: it may still have been applied. The retry
    // lists it in base_save_ids, so it goes on top of it either way.
    rememberUnacked(s, attempt);
    s.error = { text: 'Save failed - retrying' };
    retryLater(s);
  }
  showNoteState(s);
}

// "Save as new note" (after a save got 404): if the note's host is still
// there, the text the editor shows becomes a new note on it, which is then
// opened, and this session is done. Otherwise nothing changes, and the user
// is told why. The note stays read-only meanwhile (also if it is opened
// again before then), so nothing typed or inserted is left behind.
async function saveAsNewNote(s, btn) {
  if (s.discarded || !s.contentEl || s.savingAsNew) return;
  btn.disabled = true;
  s.savingAsNew = true;
  setNoteEditorLoading(true);
  let nid;
  try {
    await apiGet(`/hosts/${s.hid}`);
    nid = await postNewNote(s.hid, noteSnapshot(s));
  } catch (err) {
    s.savingAsNew = false;
    btn.disabled = false;
    if (s.contentEl) setNoteEditorLoading(false);
    if (err.status === 404) {
      alert('The host of this note was not found either (it may have been deleted elsewhere), so the note can’t be saved as a new note there. Your text is kept: use Copy to keep it somewhere else.');
    } else if (err.status !== 401) {
      alert(`The note could not be saved as a new note (${err.message}). Your text is kept.`);
    }
    return;
  }
  dropNoteSession(s);
  openNewNote(s.hid, nid);
}

// Save a note's text ({title, content}) as a new note on host hid; returns
// its id.
async function postNewNote(hid, text) {
  const note = await apiPost(`/hosts/${hid}/notes`, { title: text.title || 'Untitled', content: text.content });
  return note.id || note.ID;
}

// Show note nid in the editor, if its host hid is the one shown.
function openNewNote(hid, nid) {
  if (currentHostId !== hid) return;
  activeNoteId = nid;
  activeHostTab = 'notes';
  refreshAssessment();
}

// A save landed (attempt: the text it sent). Update this note's entries,
// never whichever note is shown by now.
function noteSaved(s, attempt, version) {
  Object.assign(s, {
    version, base: { title: attempt.title, content: attempt.content }, baseEd: { ...attempt.ed },
    unacked: [], conflict: null, error: null, retryDelay: 0, updatedAt: new Date().toISOString(),
  });
  updateNoteTitleRefs(s.hid, s.nid, attempt.title, version);
  clearNoteListMark(s, 'just now');
  noteSynced(s, true);
}

// The session caught up with the server: save what is still ours, or show
// it as saved.
function noteSynced(s, savedNow) {
  if (isDirty(s)) {
    showNoteState(s); // more edits arrived while saving
    if (!s.saveTimer && !s.queued) saveNoteSession(s);
    return;
  }
  if (parkedNoteSessions.get(s.nid) === s) parkedNoteSessions.delete(s.nid);
  if (!s.statusEl) return;
  if (savedNow) flashNoteStatus(s, 'Saved \u2713');
  else setNoteSaveStatus(s, '', '');
}

// The server has a newer copy (a 409, or fetched for the compare dialog).
// One of our own saves whose reply got lost is adopted as saved. Otherwise
// each field keeps the side that changed it, and the editor takes the other
// side's changes; only a field changed on both sides puts the note in
// conflict, where saving waits for the user.
function noteServerCopy(s, server, attempt = null) {
  s.conflict = null;
  const mine = [attempt, ...s.unacked].find(u => u &&
    ((server.saveId && u.id === server.saveId) || (u.title === server.title && u.content === server.content)));
  if (mine) { noteSaved(s, mine, server.version); return; }
  const local = noteSnapshot(s);
  if (!local) return;
  const take = {};
  for (const f of NOTE_FIELDS) {
    take[f] = mergeNoteField(s, f, local, server);
    if (!take[f]) {
      s.conflict = server;
      showNoteState(s);
      return;
    }
  }
  Object.assign(s, {
    version: server.version, base: { title: server.title, content: server.content },
    unacked: [], error: null, retryDelay: 0, updatedAt: server.updatedAt,
  });
  for (const f of NOTE_FIELDS) {
    if (take[f] === 'ours') continue;
    s.baseEd[f] = s.ed[f]; // this field matches the server copy now
    if (take[f] === 'theirs') setNoteField(s, f, server[f]);
  }
  updateNoteTitleRefs(s.hid, s.nid, server.title, server.version);
  clearNoteListMark(s);
  noteSynced(s, false);
}

// Note HTML in one form for comparing copies: as sanitizeHTML keeps it, with
// code blocks as plain code (no hljs markup or class). The editor's HTML of
// a note and its stored copy can differ in such details (e.g. data-lang, or
// an entity written another way) and still hold the same text.
function canonicalNoteHTML(html) {
  const doc = new DOMParser().parseFromString(sanitizeHTML(html), 'text/html');
  doc.querySelectorAll('pre.hljs-code-block code').forEach(el => {
    el.textContent = el.textContent;
    el.classList.remove('hljs');
    if (!el.classList.length) el.removeAttribute('class');
  });
  return doc.body.innerHTML;
}

const comparableNoteField = f => (f === 'content' ? canonicalNoteHTML : v => v);

// mergeEdit for one note field of session s: local is its text, server the
// copy to merge with. Content is compared in canonical form.
function mergeNoteField(s, f, local, server) {
  const c = comparableNoteField(f);
  return mergeEdit(c(s.base[f]), c(local[f]), c(server[f]), s.unacked.map(u => c(u[f])), s.ed[f] !== s.baseEd[f]);
}

// "Compare..." on a note in conflict: fetch the saved copy now and show it
// next to the local text before anything is replaced.
async function openNoteConflict(s) {
  let fresh;
  try {
    fresh = serverNoteCopy(await apiGet(`/notes/${s.nid}`));
  } catch (err) {
    try {
      if (err.status !== 404) throw err;
      await savedCopyNotFound(s);
    } catch (e) {
      if (e.status !== 401) alert(e.message);
    }
    return;
  }
  if (s.discarded || !s.conflict) return;
  noteServerCopy(s, fresh); // it may have changed again: merge if possible
  if (s.conflict) showNoteConflictDialog(s, fresh);
}

function showNoteConflictDialog(s, theirs, notice = '') {
  const mine = noteSnapshot(s);
  const clash = NOTE_FIELDS.filter(f => !mergeNoteField(s, f, mine, theirs));
  const what = clash.map(f => (f === 'title' ? 'the title' : 'the text')).join(' and ');
  showConflictDialog({
    heading: 'Note changed elsewhere',
    intro: `This note was saved from another tab or device while you were editing it, and both versions changed ${what || 'it'}. Compare them, then choose the one to keep.`,
    notice,
    theirs: { title: theirs.title, html: theirs.content, meta: theirs.updatedAt ? `saved ${relativeTime(theirs.updatedAt)}` : '' },
    mine: { title: mine.title, html: mine.content },
    keepLabel: 'Save the version you don\u2019t keep as a separate note',
    act: (choice, keepOther) => resolveNoteConflict(s, theirs, choice, keepOther),
  });
}

// Apply "Load latest" / "Keep mine" with the saved copy fetched now (if it
// changed again since the dialog showed it, show the new one instead).
// Runs in the note's request queue, so no save or rename interleaves.
async function resolveNoteConflict(s, shown, choice, keepOther) {
  let copied = false;
  const done = await queueNoteRequest(s.nid, async () => {
    if (s.discarded) return true;
    let fresh;
    try {
      fresh = serverNoteCopy(await apiGet(`/notes/${s.nid}`));
    } catch (err) {
      if (err.status !== 404) throw err;
      await savedCopyNotFound(s);
      return true;
    }
    if (fresh.version !== shown.version) {
      showNoteConflictDialog(s, fresh, 'The saved version changed again while you were comparing. This is the latest one.');
      return false;
    }
    if (keepOther) {
      // The side not kept becomes a note of its own, so nothing is lost.
      const other = choice === 'load' ? noteSnapshot(s) : fresh;
      const when = new Date().toLocaleString([], { dateStyle: 'short', timeStyle: 'short' });
      await apiPost(`/hosts/${s.hid}/notes`, {
        title: `${other.title || 'Untitled'} (conflicting copy ${when})`, content: other.content,
      });
      copied = true;
    }
    if (choice === 'load') loadNoteCopy(s, fresh);
    else keepMyNoteOver(s, fresh);
    return true;
  });
  if (copied && currentAssessment) {
    if (s.queued) await s.queued; // the kept text is saved first...
    refreshAssessment();          // ...then the list is re-rendered with the copy
  }
  return done;
}

function adoptNoteCopy(s, fresh) {
  clearTimeout(s.saveTimer);
  clearTimeout(s.retryTimer);
  s.saveTimer = s.retryTimer = null;
  Object.assign(s, {
    version: fresh.version, base: { title: fresh.title, content: fresh.content },
    unacked: [], conflict: null, error: null, retryDelay: 0, updatedAt: fresh.updatedAt,
  });
}

// "Load latest": the editor (or parked draft) takes the saved copy.
function loadNoteCopy(s, fresh) {
  adoptNoteCopy(s, fresh);
  for (const f of NOTE_FIELDS) {
    setNoteField(s, f, fresh[f]);
    s.baseEd[f] = s.ed[f];
  }
  updateNoteTitleRefs(s.hid, s.nid, fresh.title, fresh.version);
  clearNoteListMark(s);
  if (parkedNoteSessions.get(s.nid) === s) parkedNoteSessions.delete(s.nid);
  if (s.statusEl) flashNoteStatus(s, 'Loaded latest');
}

// "Keep mine": our changes go on top of the saved copy. A field we didn't
// change takes the saved copy's value (e.g. a rename made elsewhere).
function keepMyNoteOver(s, fresh) {
  const mine = noteSnapshot(s);
  const edited = f => s.ed[f] !== s.baseEd[f] &&
    comparableNoteField(f)(mine[f]) !== comparableNoteField(f)(fresh[f]);
  const ours = NOTE_FIELDS.filter(edited);
  adoptNoteCopy(s, fresh);
  for (const f of NOTE_FIELDS) {
    if (ours.includes(f)) continue;
    setNoteField(s, f, fresh[f]);
    s.baseEd[f] = s.ed[f];
  }
  updateNoteTitleRefs(s.hid, s.nid, fresh.title, fresh.version);
  clearNoteListMark(s);
  noteSynced(s, false); // saves the fields we kept
}

// Take the shown session out of the editor (switching notes or hosts, or
// before the editor is re-rendered). Its unsaved text is captured and saved
// right away, and it stays parked until that save lands.
function releaseNoteSession() {
  const s = noteSession;
  if (!s) return;
  noteSession = null;
  if (isDirty(s) || s.conflict) {
    s.draft = noteSnapshot(s);
    parkedNoteSessions.set(s.nid, s);
  }
  clearTimeout(s.statusTimer);
  s.titleEl = s.contentEl = s.statusEl = null;
  markNoteListItem(s); // a note left in conflict or failing stays flagged in the list
  saveNoteSession(s);
}

// Bind a session to the editor (its text is already there) and make the
// editor editable (unless it is being saved as a new note).
function attachNoteSession(s) {
  s.titleEl = $('#notes-title-input');
  s.contentEl = $('#notes-content');
  s.statusEl = $('#notes-save-status');
  s.draft = null;
  if (parkedNoteSessions.get(s.nid) === s) parkedNoteSessions.delete(s.nid);
  s.contentEl.dataset.nid = s.nid;
  noteSession = s;
  activeNoteId = s.nid;
  highlightNoteItem(s.nid);
  setNoteEditorLoading(s.savingAsNew);
  if (!s.conflict && !s.error) clearNoteListMark(s);
  showNoteState(s);
}

function showNoteSession(s, title, content) {
  $('#notes-title-input').value = title;
  const contentEl = $('#notes-content');
  contentEl.innerHTML = sanitizeHTML(content);
  applyNoteHighlighting(contentEl);
  attachNoteSession(s);
}

// Read-only while a note loads, so nothing typed there can land in the
// wrong note.
function setNoteEditorLoading(loading) {
  const titleEl = $('#notes-title-input');
  const contentEl = $('#notes-content');
  if (titleEl) titleEl.readOnly = loading;
  if (contentEl) contentEl.contentEditable = loading ? 'false' : 'true';
}

function highlightNoteItem(nid) {
  $$('.notes-file-item').forEach(el => el.classList.toggle('active', el.dataset.nid === nid));
}

function dropNoteSession(s) {
  discardSession(s);
  if (noteSession === s) noteSession = null;
  if (parkedNoteSessions.get(s.nid) === s) parkedNoteSessions.delete(s.nid);
}

// The deleted note's session has nothing left to save.
function discardNoteSession(nid) {
  for (const s of [noteSession, parkedNoteSessions.get(nid)]) {
    if (s && s.nid === nid) dropNoteSession(s);
  }
}

let finishNoteRename = null; // commits the rename input open in the notes list (startNoteRename)

// Called before the main view is replaced: the note editor and the scratch
// pad hand their unsaved text to their sessions, which save it, and a
// rename typed in the notes list is committed (Firefox fires no blur when
// the input is removed).
function releaseEditors() {
  if (finishNoteRename) finishNoteRename();
  releaseNoteSession();
  releaseScratchSession();
}

// Start saving pending edits now (e.g. before a refresh re-renders the view).
function flushEditors() {
  if (noteSession) saveNoteSession(noteSession);
  if (scratchSession) saveScratch(scratchSession);
}

function jsonSize(body) {
  return new Blob([JSON.stringify(body)]).size;
}

// Bodies sent with keepalive must stay under the browser's 64 KiB budget.
function fitsKeepalive(body) {
  return jsonSize(body) < KEEPALIVE_BUDGET;
}

const sameEdits = (a, b) => (typeof a === 'number' ? a === b : NOTE_FIELDS.every(f => a[f] === b[f]));

// One last save of each session with unsaved edits, for when the page goes
// away. A save still in flight, or one whose reply was lost, may land
// before or after it: they are listed in base_save_ids, so this one applies
// on top of them either way (and still never over anyone else's change).
// Nothing is sent for a session held for its account: it would go out with
// the other account's cookie.
function lastChanceSaves() {
  const out = [];
  for (const s of editorSessions()) {
    if (!canSave(s) || heldForAccount(s)) continue;
    const inflight = s.inflight;
    if (inflight && inflight.keepalive && sameEdits(inflight.ed, s.ed)) continue; // already on its way with everything
    let path, body;
    if (s.kind === 'scratch') {
      path = `/assessments/${s.eid}/scratchpad`;
      body = { content: s.text, version: s.version };
    } else {
      const snap = noteSnapshot(s);
      if (!snap) continue;
      path = `/hosts/${s.hid}/notes/${s.nid}`;
      body = { title: snap.title, content: snap.content, version: s.version };
    }
    body.save_id = newSaveId();
    const ids = s.unacked.map(u => u.id);
    if (inflight) ids.push(inflight.id);
    if (ids.length) body.base_save_ids = ids.slice(-MAX_UNACKED);
    out.push({ path, body, size: jsonSize(body) });
  }
  return out;
}

// Leaving now could lose text: a conflict or a failing save, unsaved text
// while signed out or held for another account, or more unsaved text than
// keepalive requests can carry.
function unsavedWorkAtRisk() {
  const live = editorSessions().filter(s => !s.discarded);
  if (live.some(s => s.conflict || (isDirty(s) && (s.error || !signedIn || heldForAccount(s))))) return true;
  let budget = KEEPALIVE_BUDGET;
  return lastChanceSaves().some(({ size }) => (budget -= size) < 0);
}

// Last-chance saves: when the tab is hidden, pending edits are saved at once;
// when the page is going away they are sent with keepalive so the request
// outlives the page. Closing the tab asks first when that may not be enough.
// Nothing is sent while signed out.
function setupUnsavedWorkGuards() {
  document.addEventListener('visibilitychange', () => {
    if (document.visibilityState !== 'hidden' || !signedIn) return;
    for (const s of editorSessions()) saveSession(s, { keepalive: true });
  });
  window.addEventListener('pagehide', ev => {
    if (ev.persisted || !signedIn) return; // kept in the back/forward cache: still alive
    let budget = KEEPALIVE_BUDGET;
    for (const { path, body, size } of lastChanceSaves()) {
      const keepalive = size <= budget;
      if (keepalive) budget -= size;
      fetch(API_BASE + path, {
        method: 'PUT', headers: { ...authHeaders(), ...jsonHeaders() }, credentials: 'same-origin',
        body: JSON.stringify(body), keepalive,
      }).catch(() => {});
    }
  });
  window.addEventListener('beforeunload', ev => {
    if (!unsavedWorkAtRisk()) return;
    ev.preventDefault();
    ev.returnValue = '';
  });
}

function initNotesEditor(hid) {
  // Click delegation for file list items
  const list = $('#notes-list');
  if (!list) return;

  list.addEventListener('click', async (e) => {
    // Delete button
    const delBtn = e.target.closest('.notes-del-file');
    if (delBtn) {
      e.stopPropagation();
      const item = delBtn.closest('.notes-file-item');
      const nid = item.dataset.nid;
      if (!confirm('Delete this note?')) return;
      try {
        // Not found: it may be gone already (e.g. deleted elsewhere), or be
        // out of reach for now (another account signed in, a proxy during an
        // outage). So its text that isn't saved goes only if the user says so.
        let keep = false;
        await apiDelete(`/hosts/${hid}/notes/${nid}`).catch(err => {
          if (err.status !== 404) throw err;
          const s = noteSession && noteSession.nid === nid ? noteSession : parkedNoteSessions.get(nid);
          keep = !!s && (s.conflict || isDirty(s)) && !confirm('The note was not found, so it was not deleted here. It may be gone already, or be out of reach for now (e.g. another account is signed in).\n\nDiscard its unsaved changes? (Cancel keeps them.)');
        });
        if (!keep) discardNoteSession(nid);
        if (activeNoteId === nid && !keep) {
          activeNoteId = null;
          $('#notes-editor-active').classList.add('hidden');
          $('#notes-editor-empty').classList.remove('hidden');
        }
        activeHostTab = 'notes';
        await refreshAssessment();
      } catch (err) { alert(err.message); }
      return;
    }

    // Select a file
    const item = e.target.closest('.notes-file-item');
    if (item) {
      await selectNote(hid, item.dataset.nid);
    }
  });

  // Double-click to rename
  list.addEventListener('dblclick', (e) => {
    const titleSpan = e.target.closest('.notes-file-title');
    if (!titleSpan) return;
    const item = titleSpan.closest('.notes-file-item');
    startNoteRename(item, hid);
  });

  // Drag-and-drop reordering of note files (replaces the old up/down arrows).
  let dragSrcNote = null;
  $$('#notes-list .notes-file-item').forEach(item => {
    item.addEventListener('dragstart', e => {
      if (e.target.closest('input')) { e.preventDefault(); return; } // don't drag while renaming
      dragSrcNote = item;
      item.classList.add('note-dragging');
      e.dataTransfer.effectAllowed = 'move';
    });
    item.addEventListener('dragend', () => {
      $$('#notes-list .notes-file-item').forEach(i => i.classList.remove('note-dragging', 'note-drag-over'));
      dragSrcNote = null;
    });
    item.addEventListener('dragover', e => {
      e.preventDefault();
      e.dataTransfer.dropEffect = 'move';
      if (dragSrcNote && item !== dragSrcNote) item.classList.add('note-drag-over');
    });
    item.addEventListener('dragleave', () => item.classList.remove('note-drag-over'));
    item.addEventListener('drop', async e => {
      e.preventDefault();
      item.classList.remove('note-drag-over');
      if (!dragSrcNote || dragSrcNote === item) return;
      const listEl = item.parentElement;
      const items = Array.from(listEl.querySelectorAll('.notes-file-item'));
      const fromIdx = items.indexOf(dragSrcNote);
      const toIdx = items.indexOf(item);
      if (fromIdx < toIdx) listEl.insertBefore(dragSrcNote, item.nextSibling);
      else listEl.insertBefore(dragSrcNote, item);
      await persistNoteOrder(hid, listEl);
    });
  });

  // Template dropdown toggle
  const tmplBtn = $('#notes-tmpl-btn');
  const tmplMenu = $('#notes-tmpl-menu');
  if (tmplBtn && tmplMenu) {
    tmplBtn.addEventListener('click', (e) => {
      e.stopPropagation();
      tmplMenu.classList.toggle('hidden');
    });
    tmplMenu.querySelectorAll('.notes-tmpl-item').forEach(item => {
      item.addEventListener('click', () => {
        const tpl = NOTE_TEMPLATES[item.dataset.template];
        if (tpl) createNoteFile(hid, tpl);
        tmplMenu.classList.add('hidden');
      });
    });
    // Remove any closer installed by a prior initNotesEditor() call so these
    // document-level listeners can't accumulate across re-renders.
    if (_notesTmplCloser) document.removeEventListener('click', _notesTmplCloser);
    _notesTmplCloser = (e) => {
      if (!tmplBtn.contains(e.target) && !tmplMenu.contains(e.target)) {
        tmplMenu.classList.add('hidden');
      }
    };
    document.addEventListener('click', _notesTmplCloser);
  }

  // Toolbar: standard execCommand buttons
  $$('.notes-toolbar button[data-cmd]').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.preventDefault();
      document.execCommand(btn.dataset.cmd, false, null);
      $('#notes-content').focus();
    });
  });

  // Toolbar: formatBlock buttons (H2, H3)
  $$('.notes-toolbar button[data-format]').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.preventDefault();
      document.execCommand('formatBlock', false, btn.dataset.format);
      $('#notes-content').focus();
    });
  });

  // Toolbar: code block button — opens language picker modal. Pressing it
  // leaves the caret in the editor, so the block goes where the caret was.
  const codeBtn = $('#notes-code-btn');
  if (codeBtn) {
    codeBtn.addEventListener('mousedown', (e) => e.preventDefault());
    codeBtn.addEventListener('click', (e) => {
      e.preventDefault();
      const s = noteSession;
      if (!s || s.contentEl !== $('#notes-content')) return; // no note loaded yet
      if (s.savingAsNew) return; // read-only until it is saved as a new note
      showCodeBlockModal('bash', '', { session: s, range: editorSelectionRange(s.contentEl) });
    });
  }

  // Toolbar: copy as plain text
  const copyBtn = $('#notes-copy-btn');
  if (copyBtn) {
    copyBtn.addEventListener('click', () => {
      const contentEl = $('#notes-content');
      if (!contentEl) return;
      const text = contentEl.innerText || contentEl.textContent || '';
      navigator.clipboard.writeText(text).then(() => {
        copyBtn.textContent = 'Copied!';
        setTimeout(() => { copyBtn.textContent = 'Copy'; }, 1500);
      });
    });
  }

  // Highlight color picker
  const hlBtn = $('#notes-highlight-btn');
  const hlColors = $('#notes-highlight-colors');
  if (hlBtn && hlColors) {
    hlBtn.addEventListener('click', (e) => {
      e.preventDefault();
      hlColors.classList.toggle('hidden');
    });
    hlColors.querySelectorAll('span[data-color]').forEach(swatch => {
      swatch.addEventListener('mousedown', (e) => {
        e.preventDefault();
        const color = swatch.dataset.color;
        if (color === 'transparent') {
          document.execCommand('removeFormat', false, null);
        } else {
          document.execCommand('hiliteColor', false, color);
          // Update the indicator bar on the highlight button
          const indicator = hlBtn.querySelector('#hl-indicator');
          if (indicator) indicator.setAttribute('fill', color);
        }
        hlColors.classList.add('hidden');
        $('#notes-content').focus();
      });
    });
    // Close palette when clicking elsewhere (replace prior closer to avoid leak).
    if (_notesHlCloser) document.removeEventListener('click', _notesHlCloser);
    _notesHlCloser = (e) => {
      if (!hlBtn.contains(e.target) && !hlColors.contains(e.target)) {
        hlColors.classList.add('hidden');
      }
    };
    document.addEventListener('click', _notesHlCloser);
  }

  // Auto-save content on input (debounced) + paste as plain text + Ctrl+S.
  // Edits belong to the session shown in this editor; blur saves only when
  // something is unsaved, so a stale tab that is merely clicked into never
  // writes its old copy back, and not while the status line offers actions
  // (Retry, ...): that save would redraw them as the focus moves to one.
  const contentEl = $('#notes-content');
  const titleEl = $('#notes-title-input');
  const shownSession = () => (noteSession && noteSession.contentEl === contentEl ? noteSession : null);
  const saveOnBlur = () => {
    const s = shownSession();
    if (s && isDirty(s) && !(s.error && s.error.actions)) saveNoteSession(s);
  };
  if (contentEl) {
    contentEl.addEventListener('input', () => {
      const s = shownSession();
      if (s) noteEdited(s, 'content');
    });
    contentEl.addEventListener('blur', saveOnBlur);
    // Paste as plain text — strip all HTML from clipboard
    contentEl.addEventListener('paste', (e) => {
      e.preventDefault();
      const text = e.clipboardData.getData('text/plain');
      document.execCommand('insertText', false, text);
    });
    // Ctrl+S / Cmd+S — immediate save
    contentEl.addEventListener('keydown', (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 's') {
        e.preventDefault();
        const s = shownSession();
        if (!s) return;
        if (isDirty(s)) saveNoteSession(s);
        else if (!s.conflict && !s.error) flashNoteStatus(s, 'Saved \u2713');
      }
    });
  }

  // Auto-save title on change
  if (titleEl) {
    titleEl.addEventListener('input', () => {
      const s = shownSession();
      if (s) noteEdited(s, 'title');
    });
    titleEl.addEventListener('blur', saveOnBlur);
  }

  // A note with unsaved text that the server didn't list (e.g. deleted
  // elsewhere before its text was saved) stays listed, so that text can
  // still be opened and acted on.
  for (const s of parkedNoteSessions.values()) {
    if (s.hid !== hid || list.querySelector(`[data-nid="${s.nid}"]`)) continue;
    list.insertAdjacentHTML('beforeend', `
      <div class="notes-file-item" data-nid="${esc(s.nid)}" data-hid="${esc(hid)}">
        <div class="notes-file-info">
          <span class="notes-file-title">${esc(s.draft.title || 'Untitled')}</span>
          <span class="notes-file-meta status-unsaved">not saved</span>
        </div>
        <div class="notes-file-actions">
          <button class="btn-icon notes-del-file" title="Delete">&#10005;</button>
        </div>
      </div>`);
  }

  // If we had an active note, re-select it after re-render (a note with
  // unsaved work comes back from its parked session).
  if (activeNoteId) {
    const existing = list.querySelector(`[data-nid="${activeNoteId}"]`);
    if (existing) {
      selectNote(hid, activeNoteId);
    } else {
      activeNoteId = null;
    }
  }
  for (const s of parkedNoteSessions.values()) {
    if (s.hid === hid) markNoteListItem(s);
  }
}

// Open a note in the editor. The note being left is flushed first; the new
// one is bound only once its text is shown, and only if no later selection
// overtook this one. The editor is read-only while it loads.
async function selectNote(hid, nid) {
  const editorEl = $('#notes-content');
  if (!editorEl) return;
  const seq = ++noteSelectSeq;
  const prev = noteSession && noteSession.contentEl === editorEl ? noteSession : null;
  if (prev && prev.nid === nid && (isDirty(prev) || prev.conflict)) return; // already shown, unsaved
  releaseNoteSession();
  highlightNoteItem(nid);
  activeNoteId = nid;
  $('#notes-editor-empty').classList.add('hidden');
  $('#notes-editor-active').classList.remove('hidden');

  // A note with unsaved work comes back exactly as the user left it.
  const showParked = () => {
    const parked = parkedNoteSessions.get(nid);
    if (parked) showNoteSession(parked, parked.draft.title, parked.draft.content);
    return !!parked;
  };
  if (showParked()) return;

  setNoteEditorLoading(true);
  setSaveStatus($('#notes-save-status'), 'notes-save-status', 'Loading\u2026', 'status-saving');
  try {
    // Let a rename of this note in flight land first (or a code block being
    // added to it in the background, which parks it).
    await noteRequestQueues.get(nid);
    if (seq !== noteSelectSeq || $('#notes-content') !== editorEl) return; // overtaken
    if (showParked()) return;
    let note = await apiGet(`/notes/${nid}`);
    // A rename that landed after this read was served makes it stale.
    if (seq === noteSelectSeq && (noteVersionInMemory(hid, nid) ?? -1) > (note.version ?? 0)) {
      note = await apiGet(`/notes/${nid}`);
    }
    if (seq !== noteSelectSeq || $('#notes-content') !== editorEl) return; // overtaken
    const eid = currentAssessment && (currentAssessment.id || currentAssessment.ID);
    showNoteSession(newNoteSession(eid, hid, nid, note, currentAssessment && currentAssessment.account),
      note.title ?? note.Title ?? '', note.content ?? note.Content ?? '');
  } catch (err) {
    if (seq !== noteSelectSeq || $('#notes-content') !== editorEl) return;
    // Don't leave the editor pointing at a note it doesn't show: go back to
    // the previous note, or close it. While parked, that note's text may
    // have changed (a change saved elsewhere merged in, a rename from the
    // list, a code block), so it is shown from its session, not from what
    // the editor still shows.
    const back = prev && (parkedNoteSessions.get(prev.nid) || prev);
    if (back && !back.discarded) {
      if (back.draft) showNoteSession(back, back.draft.title, back.draft.content);
      else attachNoteSession(back);
    } else {
      activeNoteId = null;
      highlightNoteItem(null);
      setNoteEditorLoading(false);
      $('#notes-editor-active').classList.add('hidden');
      $('#notes-editor-empty').classList.remove('hidden');
    }
    alert(err.message);
  }
}

const CODE_LANGUAGES = [
  { value: 'bash',        label: 'Bash / Shell' },
  { value: 'python',      label: 'Python' },
  { value: 'powershell',  label: 'PowerShell' },
  { value: 'javascript',  label: 'JavaScript' },
  { value: 'php',         label: 'PHP' },
  { value: 'ruby',        label: 'Ruby' },
  { value: 'sql',         label: 'SQL' },
  { value: 'xml',         label: 'HTML / XML' },
  { value: 'json',        label: 'JSON' },
  { value: 'http',        label: 'HTTP' },
  { value: 'c',           label: 'C' },
  { value: 'cpp',         label: 'C++' },
  { value: 'csharp',      label: 'C#' },
  { value: 'java',        label: 'Java' },
  { value: 'go',          label: 'Go' },
  { value: 'plaintext',   label: 'Plain Text' },
];

// target: { session, range } — the note the block is for and the editor
// selection when </> was pressed.
function showCodeBlockModal(existingLang = 'bash', existingCode = '', target = null) {
  const opts = CODE_LANGUAGES.map(l =>
    `<option value="${l.value}"${l.value === existingLang ? ' selected' : ''}>${l.label}</option>`
  ).join('');

  showModal(`
    <h3>${existingCode ? 'Edit Code Block' : 'Insert Code Block'}</h3>
    <div class="form-group">
      <label>Language</label>
      <select id="code-block-lang" class="form-control">${opts}</select>
    </div>
    <div class="form-group">
      <label>Code</label>
      <textarea id="code-block-input" class="form-control code-block-textarea" rows="12" placeholder="Paste or type code here..." spellcheck="false" autocomplete="off">${esc(existingCode)}</textarea>
    </div>
    <div class="modal-actions">
      <button id="code-block-insert" class="btn btn-primary">${existingCode ? 'Update' : '+ Insert'}</button>
      <button id="cancel" class="btn btn-secondary">Cancel</button>
    </div>
  `);

  // Focus the textarea immediately
  const ta = $('#code-block-input');
  if (ta) ta.focus();

  $('#code-block-insert').addEventListener('click', () => {
    const lang = $('#code-block-lang').value;
    const code = $('#code-block-input').value;
    hideModal();
    if (!code.trim()) return;
    insertCodeBlock(lang, code, target);
  });

  // Allow Tab key to indent in the textarea
  if (ta) {
    ta.addEventListener('keydown', (e) => {
      if (e.key === 'Tab') {
        e.preventDefault();
        const start = ta.selectionStart;
        const end = ta.selectionEnd;
        ta.value = ta.value.substring(0, start) + '  ' + ta.value.substring(end);
        ta.selectionStart = ta.selectionEnd = start + 2;
      }
    });
  }

  $('#cancel').addEventListener('click', hideModal);
}

// The editor's current selection, if it is inside the editor.
function editorSelectionRange(contentEl) {
  const sel = window.getSelection();
  if (!sel || sel.rangeCount === 0) return null;
  const range = sel.getRangeAt(0);
  return contentEl.contains(range.commonAncestorContainer) ? range.cloneRange() : null;
}

// Insert a code block where the caret was when </> was pressed (or at the
// end), hand focus back to the editor and treat it as an edit, so it is
// autosaved like typing.
function insertCodeBlock(lang, code, target) {
  const pre = document.createElement('pre');
  pre.className = 'hljs-code-block';
  pre.dataset.lang = lang;
  const codeEl = document.createElement('code');
  codeEl.className = `language-${lang}`;
  codeEl.textContent = code;
  pre.appendChild(codeEl);

  const s = target ? target.session : noteSession;
  if (!s) return;
  if (s.contentEl) { placeCodeBlock(s, pre, target && target.range); return; }
  // The note left the editor while the dialog was open (a refresh
  // re-rendered the notes tab, or another note was opened): the block still
  // goes into that note.
  const shown = shownNoteSession(s.nid);
  const parked = parkedNoteSessions.get(s.nid);
  if (shown) placeCodeBlock(shown, pre, null);
  else if (parked) appendCodeBlockToDraft(parked, pre);
  else if (s.discarded) codeBlockNotInserted(code, 'The note was deleted');
  else appendCodeBlockInBackground(s, pre);
}

// The session showing note nid in the editor, if any.
function shownNoteSession(nid) {
  return noteSession && noteSession.nid === nid && noteSession.contentEl ? noteSession : null;
}

// Put the block into the editor after the paragraph (or other top-level
// block) holding the caret, so it never ends up nested inside a <p>; an
// empty line holding the caret is reused as the line after the block.
// Without a caret (range null), append it.
function placeCodeBlock(s, pre, range) {
  const contentEl = s.contentEl;
  const isEmptyLine = el => el && el.tagName === 'P' && !el.textContent.trim() && !el.querySelector(':not(br)');
  if (!range || !contentEl.contains(range.commonAncestorContainer)) {
    contentEl.appendChild(pre);
  } else if (range.endContainer === contentEl) {
    range.collapse(false); // caret between blocks
    range.insertNode(pre);
  } else {
    let block = range.endContainer;
    while (block.parentNode !== contentEl) block = block.parentNode;
    if (isEmptyLine(block)) block.before(pre); else block.after(pre);
  }
  if (typeof hljs !== 'undefined') hljs.highlightElement(pre.firstChild);

  // Continue on a line below the block (a caret right after a trailing <pre>
  // would land inside the code).
  let line = pre.nextElementSibling;
  if (!isEmptyLine(line)) {
    line = document.createElement('p');
    line.appendChild(document.createElement('br'));
    pre.after(line);
  }
  contentEl.focus();
  const caret = document.createRange();
  caret.setStart(line, 0);
  caret.collapse(true);
  const sel = window.getSelection();
  sel.removeAllRanges();
  sel.addRange(caret);
  noteEdited(s, 'content');
}

// Add the block at the end of a parked note's text (with an empty line
// after it, as in the editor); it is saved with that text.
function appendCodeBlockToDraft(s, pre) {
  s.draft.content += pre.outerHTML + '<p><br></p>';
  noteEdited(s, 'content');
}

// The note left the editor with nothing unsaved while the dialog was open:
// add the block to its latest saved text through a parked session, which
// saves it (with retries and conflict checks) like any edit. Runs in the
// note's request queue, so selecting the note meanwhile waits for it. If the
// note can't be fetched (signed out, another account, not found, network),
// the copy the session last saw is used: its save then merges with a newer
// copy, or ends in a conflict or "Not saved - not found". The block stays
// with the note's own account.
function appendCodeBlockInBackground(s, pre) {
  queueNoteRequest(s.nid, async () => {
    let note = { title: s.base.title, content: s.base.content, version: s.version, updated_at: s.updatedAt };
    if (signedIn && !heldForAccount(s)) {
      try {
        note = await apiGet(`/notes/${s.nid}`);
      } catch {}
    }
    const shown = shownNoteSession(s.nid);
    if (shown) { placeCodeBlock(shown, pre, null); return; }
    let p = parkedNoteSessions.get(s.nid);
    if (!p) {
      p = newNoteSession(s.eid, s.hid, s.nid, note, s.owner);
      p.draft = { ...p.base };
      parkedNoteSessions.set(p.nid, p);
    }
    appendCodeBlockToDraft(p, pre);
  });
}

// Last resort: keep the code on the clipboard and say so.
async function codeBlockNotInserted(code, why) {
  let copied = false;
  try {
    await navigator.clipboard.writeText(code);
    copied = true;
  } catch {}
  alert(`${why}, so the code block was not inserted.${copied ? ' The code was copied to the clipboard.' : ''}`);
}

function applyNoteHighlighting(contentEl) {
  if (!contentEl || typeof hljs === 'undefined') return;
  contentEl.querySelectorAll('pre.hljs-code-block code').forEach(el => {
    hljs.highlightElement(el);
  });
}

// The note's entry in the in-memory assessment, if loaded.
function findMemNote(hid, nid) {
  const host = currentAssessment && (currentAssessment.hosts || currentAssessment.Hosts || [])
    .find(h => (h.id || h.ID) === hid);
  return host && (host.notes || host.Notes || []).find(n => (n.id || n.ID) === nid);
}

// Latest version of a note known from the assessment data and our own saves.
function noteVersionInMemory(hid, nid) {
  const memNote = findMemNote(hid, nid);
  return memNote ? memNote.version : undefined;
}

// Reflect a note's new title (and version) everywhere it's shown without a
// full re-render: the Notes-tab file list and the in-memory assessment.
function updateNoteTitleRefs(hid, nid, newTitle, version) {
  const listTitle = $(`.notes-file-item[data-nid="${nid}"] .notes-file-title`);
  if (listTitle) listTitle.textContent = newTitle || 'Untitled';
  const memNote = findMemNote(hid, nid);
  if (!memNote) return;
  if ('title' in memNote) memNote.title = newTitle; else memNote.Title = newTitle;
  if (version !== undefined) memNote.version = Math.max(memNote.version ?? 0, version);
}

// Rename with a title-only update, so a rename never touches the note's
// text. It runs in the note's request queue, so it can't race an autosave.
// A title typed into the title box after the rename was started (one that
// differs from what the box showed then) is newer: it stays, and is saved
// on top of the rename.
function renameNote(hid, nid, title) {
  const sessionOf = () => (noteSession && noteSession.nid === nid ? noteSession : parkedNoteSessions.get(nid));
  const shownTitle = s => { const snap = noteSnapshot(s); return snap ? snap.title : null; };
  const s0 = sessionOf();
  const startTitle = s0 ? shownTitle(s0) : null;
  const startEdits = s0 ? s0.ed.title : null; // edits of the title box so far
  const memVersion = noteVersionInMemory(hid, nid); // the view may be gone by the time it runs
  return queueNoteRequest(nid, async () => {
    const s = sessionOf();
    let version = s ? s.version : (noteVersionInMemory(hid, nid) ?? memVersion);
    const put = v => apiPost(`/hosts/${hid}/notes/${nid}`, { title, version: v }, 'PUT');
    const lost = err => err.status === undefined || err.status >= 500;
    // The note as saved now; a lost reply here is tried again too.
    const look = async () => {
      for (let tries = 1; ; tries++) {
        try {
          return serverNoteCopy(await apiGet(`/notes/${nid}`));
        } catch (err) {
          if (tries >= 3 || !lost(err)) throw err;
          await new Promise(r => setTimeout(r, 1000 * tries));
        }
      }
    };
    let res;
    for (let tries = 1; ; tries++) { // the rename is sent 3 times at most
      try {
        res = await put(version);
        break;
      } catch (err) {
        const conflict = err.status === 409 && err.data && err.data.note;
        if (!conflict && !lost(err)) throw err;
        if (conflict) {
          // Changed elsewhere since we loaded it. Only the title is sent, so
          // the rename can go on top of that change.
          version = err.data.note.version;
        } else {
          // The reply was lost, so the rename may have landed: look before
          // sending it again.
          const n = await look();
          if (n.title === title) {
            res = { version: n.version };
            // Only our rename on top of the version we sent moves an open
            // session along; anything else is merged at its next save.
            if (!(n.version === version + 1 && (!s || n.content === s.base.content))) version = null;
            break;
          }
          version = n.version;
        }
        if (tries >= 3) throw err;
      }
    }
    updateNoteTitleRefs(hid, nid, title, res.version);
    // The note may have been opened while the rename was in flight. Its next
    // save must keep the new title, and moves to the new version only if
    // its text is the one the rename was based on.
    const cur = sessionOf();
    if (!cur) return;
    // Typed since: the title shown now differs from the rename and from the
    // title shown when it started (or, for a note opened since, loaded), and
    // the title box was edited since then (an earlier rename landing
    // meanwhile changes what it shows, but is no edit).
    const now = shownTitle(cur);
    const typed = now !== null && now !== title &&
      (cur === s0 ? cur.ed.title !== startEdits && now !== startTitle : now !== cur.base.title);
    const moved = version !== null && cur.version === version;
    if (moved) {
      Object.assign(cur, { version: res.version, unacked: [] });
      cur.base.title = title;
      if (!typed) {
        cur.baseEd.title = cur.ed.title;
      } else if (cur.ed.title === cur.baseEd.title) {
        // The typed title was saved before the rename went over it: save it
        // again, on top of the rename.
        cur.ed.title++;
        saveNoteSession(cur);
      }
    }
    if (typed) return; // the title box keeps what was typed since
    if (cur.titleEl) cur.titleEl.value = title;
    else if (cur.draft) cur.draft.title = title;
    if (moved && !cur.statusTimer) { // (a "Saved ✓" being shown is still right)
      if (!isDirty(cur)) { // in step with the server now
        cur.error = null;
        clearNoteListMark(cur);
      }
      noteSynced(cur, false); // e.g. a title typed and undone meanwhile left "Unsaved"
    }
  });
}

// Persist the current DOM order of note files as their sort_order, and mirror
// the new order into the in-memory assessment so later re-renders stay in sync
// without a full refresh (keeps reordering smooth). No order is sent for an
// entry kept only for unsaved text: a note the server no longer listed (such
// an entry can't be dragged) or whose save got 404 (see saveNotFound).
async function persistNoteOrder(hid, listEl) {
  const items = Array.from(listEl.querySelectorAll('.notes-file-item'));
  const order = items.map(i => i.dataset.nid);
  const host = (currentAssessment.hosts || currentAssessment.Hosts || [])
    .find(h => (h.id || h.ID) === hid);
  if (host) {
    const notes = host.notes || host.Notes || [];
    notes.sort((a, b) => order.indexOf(a.id || a.ID) - order.indexOf(b.id || b.ID));
  }
  const notFound = nid => [noteSession, parkedNoteSessions.get(nid)].some(s => s && s.nid === nid && s.error && s.error.text === NOT_FOUND);
  const listed = items.filter(i => i.draggable && !notFound(i.dataset.nid)).map(i => i.dataset.nid);
  try {
    await Promise.all(listed.map((nid, i) =>
      apiPost(`/hosts/${hid}/notes/${nid}/order`, { sort_order: i + 1 }, 'PUT')));
  } catch (err) { alert('Failed to save note order: ' + err.message); }
}

async function createNoteFile(hid, template = null) {
  const payload = template
    ? { title: template.title, content: template.content }
    : { title: 'Untitled' };
  try {
    const note = await apiPost(`/hosts/${hid}/notes`, payload);
    activeNoteId = note.id || note.ID;
    activeHostTab = 'notes';
    await refreshAssessment();
  } catch (err) { alert(err.message); }
}

function startNoteRename(item, hid) {
  const titleSpan = item.querySelector('.notes-file-title');
  const oldTitle = titleSpan.textContent;
  const nid = item.dataset.nid;

  const input = document.createElement('input');
  input.type = 'text';
  input.value = oldTitle;
  input.className = 'notes-rename-input';
  titleSpan.replaceWith(input);
  input.focus();
  input.select();

  let finished = false;
  const finish = async () => {
    if (finished) return;
    finished = true;
    if (finishNoteRename === finish) finishNoteRename = null;
    // Signed out meanwhile (the session expired): the rename isn't sent,
    // and the old title stays.
    const newTitle = signedIn ? input.value.trim() || 'Untitled' : oldTitle;
    const span = document.createElement('span');
    span.className = 'notes-file-title';
    span.textContent = newTitle;
    input.replaceWith(span);
    if (newTitle !== oldTitle) {
      try {
        // Title-only update; keeps the list, the in-memory note and (if the
        // note is open) the editor's title and version in sync.
        await renameNote(hid, nid, newTitle);
      } catch (err) {
        if (span.isConnected) span.textContent = oldTitle;
        if (err.status !== 401) alert(err.message); // a 401 shows the sign-in form instead
      }
    }
  };

  finishNoteRename = finish;
  input.addEventListener('blur', finish);
  input.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') { e.preventDefault(); input.blur(); }
    if (e.key === 'Escape') { input.value = oldTitle; input.blur(); }
  });
}

/* ==========================================================
   Refresh Assessment
   ========================================================== */
async function refreshAssessment() {
  if (!currentAssessment) return;
  flushEditors();
  const eid = currentAssessment.id || currentAssessment.ID;
  const owner = currentAssessment.account; // it stays the same (see fetchAssessment)
  try {
    const eng = await apiGet(`/assessments/${eid}`);
    eng.account = owner;
    currentAssessment = eng;
    renderSidebar(eng);

    if (currentHostId) {
      const hostData = (eng.hosts || eng.Hosts || [])
        .find(h => (h.id || h.ID) === currentHostId);
      if (hostData) {
        renderHostDetail(hostData);
        const hdr = $(`.host-header[data-hid="${currentHostId}"]`);
        if (hdr) {
          hdr.classList.add('active');
          const portList = hdr.nextElementSibling;
          if (portList) {
            portList.classList.add('expanded');
            const toggle = hdr.querySelector('.host-toggle');
            if (toggle) { toggle.classList.add('expanded'); toggle.innerHTML = '&#9660;'; }
          }
        }
      } else {
        currentHostId = null;
        renderAssessmentOverview(eng);
      }
    } else {
      renderAssessmentOverview(eng);
    }
  } catch (e) {
    if (e.status === 401) return; // the sign-in form is shown
    alert(e.message);
    renderDashboard();
  }
}

/* ==========================================================
   Modal: Add Host
   ========================================================== */
function showAddHostModal(eid) {
  showModal(`
    <h3>Add Host</h3>
    <form id="form-add-host">
      <label>Identifier (IP / CIDR / hostname)
        <textarea id="host-id" rows="2" required placeholder="e.g. 192.168.1.1"></textarea>
      </label>
      <label>Label
        <input type="text" id="host-label" placeholder="Optional friendly name">
      </label>
      <label>OS
        <select id="host-os">
          <option value="Linux">Linux</option>
          <option value="Windows">Windows</option>
          <option value="macOS">macOS</option>
          <option value="FreeBSD">FreeBSD</option>
          <option value="Other">Other</option>
        </select>
      </label>
      <div class="flex gap-2 mt-4">
        <button type="submit" class="btn btn-primary">Create</button>
        <button type="button" class="btn btn-secondary" id="cancel">Cancel</button>
      </div>
    </form>`);

  $('#form-add-host').addEventListener('submit', async ev => {
    ev.preventDefault();
    const payload = {
      identifier: $('#host-id').value.trim(),
      label:      $('#host-label').value.trim(),
      os:         $('#host-os').value,
    };
    if (!payload.identifier) { alert('Identifier is required'); return; }
    try {
      await apiPost(`/assessments/${eid}/hosts`, payload);
      hideModal();
      await refreshAssessment();
    } catch (e) { alert(e.message); }
  });
  $('#cancel').addEventListener('click', hideModal);
}

/* ==========================================================
   Modal: Add Port
   ========================================================== */
function showAddPortModal(hid) {
  showModal(`
    <h3>Add Port</h3>
    <form id="form-add-port">
      <label>Port Number (1-65535)
        <input type="number" id="port-number" min="1" max="65535" required placeholder="e.g. 80">
      </label>
      <label>Protocol
        <select id="port-proto">
          <option value="tcp">TCP</option>
          <option value="udp">UDP</option>
          <option value="sctp">SCTP</option>
        </select>
      </label>
      <label>Service / Banner
        <input type="text" id="port-service" placeholder="e.g. http, ssh">
      </label>
      <div class="flex gap-2 mt-4">
        <button type="submit" class="btn btn-primary">Add Port</button>
        <button type="button" class="btn btn-secondary" id="cancel">Cancel</button>
      </div>
    </form>`);

  $('#form-add-port').addEventListener('submit', async ev => {
    ev.preventDefault();
    const number = parseInt($('#port-number').value, 10);
    if (isNaN(number) || number < 1 || number > 65535) {
      alert('Port must be 1-65535'); return;
    }
    try {
      await apiPost(`/hosts/${hid}/ports`, {
        number,
        protocol: $('#port-proto').value,
        service: $('#port-service').value.trim(),
      });
      hideModal();
      await refreshAssessment();
    } catch (e) { alert(e.message); }
  });
  $('#cancel').addEventListener('click', hideModal);
}

/* ==========================================================
   Modal: Edit Port
   ========================================================== */
function showEditPortModal(hid, pid, values) {
  showModal(`
    <h3>Edit Port</h3>
    <form id="form-edit-port">
      <label><span id="edit-port-range">Port Number (1-65535)</span>
        <input type="number" id="edit-port-number" min="1" max="65535" required>
      </label>
      <label>Protocol
        <select id="edit-port-proto">
          <option value="tcp">TCP</option>
          <option value="udp">UDP</option>
          <option value="sctp">SCTP</option>
        </select>
      </label>
      <label>Service / Banner
        <input type="text" id="edit-port-service">
      </label>
      <label>Info
        <input type="text" id="edit-port-info">
      </label>
      <div class="flex gap-2 mt-4">
        <button type="submit" class="btn btn-primary">Save</button>
        <button type="button" class="btn btn-secondary" id="cancel-edit">Cancel</button>
      </div>
    </form>`);

  const numInput = $('#edit-port-number');
  numInput.value = values.number;
  // Preserve the port's existing protocol even if it's not one of the preset
  // options (e.g. an nmap-imported "ip" port) so editing doesn't clobber it.
  const editProtoSel = $('#edit-port-proto');
  const curProto = (values.proto || 'tcp').toLowerCase();
  if (![...editProtoSel.options].some(o => o.value === curProto)) {
    editProtoSel.add(new Option(curProto.toUpperCase(), curProto));
  }
  editProtoSel.value = curProto;
  $('#edit-port-service').value = values.service;
  $('#edit-port-info').value    = values.info;

  // The number's range depends on the protocol, as on the server: an IP
  // protocol number (protocol ip, from nmap -sO) is 0-255, a port 1-65535.
  const numberRange = proto => (proto === 'ip' ? [0, 255] : [1, 65535]);
  const showRange = () => {
    const [min, max] = numberRange(editProtoSel.value);
    numInput.min = min;
    numInput.max = max;
    $('#edit-port-range').textContent = `${editProtoSel.value === 'ip' ? 'Protocol' : 'Port'} Number (${min}-${max})`;
  };
  showRange();
  editProtoSel.addEventListener('change', showRange);

  // Only the fields the user changed are sent, compared with what the form
  // showed when it opened (as the inputs hold it: a text input drops
  // newlines). A field left alone keeps the server's value, which may be
  // newer than this page, and is not marked as entered by hand.
  const formValues = () => ({
    number: parseInt(numInput.value, 10),
    protocol: editProtoSel.value,
    service: $('#edit-port-service').value.trim(),
    info: $('#edit-port-info').value.trim(),
  });
  const opened = formValues();

  $('#form-edit-port').addEventListener('submit', async ev => {
    ev.preventDefault();
    const now = formValues();
    const [min, max] = numberRange(now.protocol);
    if (isNaN(now.number) || now.number < min || now.number > max) {
      alert(`${now.protocol === 'ip' ? 'Protocol number' : 'Port'} must be ${min}-${max}`); return;
    }
    const body = {};
    for (const key of ['number', 'protocol', 'service', 'info']) {
      if (now[key] !== opened[key]) body[key] = now[key];
    }
    if (!Object.keys(body).length) { hideModal(); return; }
    try {
      await apiPost(`/hosts/${hid}/ports/${pid}`, body, 'PUT');
      hideModal();
      await refreshAssessment();
    } catch (e) { alert(e.message); }
  });
  $('#cancel-edit').addEventListener('click', hideModal);
}

/* ==========================================================
   Modal: Add Credential
   ========================================================== */
function showAddCredentialModal(hid) {
  showModal(`
    <h3>Add Credential</h3>
    <form id="form-add-cred">
      <label>Username
        <input type="text" id="cred-username" required placeholder="e.g. admin">
      </label>
      <label>Password
        <input type="text" id="cred-password" placeholder="e.g. P@ssw0rd">
      </label>
      <label>Hash
        <input type="text" id="cred-hash" placeholder="e.g. aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0">
      </label>
      <label>Source
        <input type="text" id="cred-source" placeholder="e.g. manual, hashcat, responder">
      </label>
      <div class="flex gap-2 mt-4">
        <button type="submit" class="btn btn-primary">Add Credential</button>
        <button type="button" class="btn btn-secondary" id="cancel">Cancel</button>
      </div>
    </form>`, { closeOnBackdrop: false });

  $('#form-add-cred').addEventListener('submit', async ev => {
    ev.preventDefault();
    try {
      await apiPost(`/hosts/${hid}/credentials`, {
        username: $('#cred-username').value.trim(),
        password: $('#cred-password').value.trim(),
        hash:     $('#cred-hash').value.trim(),
        source:   $('#cred-source').value.trim(),
      });
      hideModal();
      await refreshAssessment();
    } catch (e) { alert(e.message); }
  });
  $('#cancel').addEventListener('click', hideModal);
}

/* ==========================================================
   Modal: Edit Credential
   ========================================================== */
function showEditCredentialModal(hid, cid, values) {
  showModal(`
    <h3>Edit Credential</h3>
    <form id="form-edit-cred">
      <label>Username
        <input type="text" id="edit-cred-username" required>
      </label>
      <label>Password
        <input type="text" id="edit-cred-password">
      </label>
      <label>Hash
        <input type="text" id="edit-cred-hash">
      </label>
      <label>Source
        <input type="text" id="edit-cred-source">
      </label>
      <div class="flex gap-2 mt-4">
        <button type="submit" class="btn btn-primary">Save</button>
        <button type="button" class="btn btn-secondary" id="cancel-edit-cred">Cancel</button>
      </div>
    </form>`);

  $('#edit-cred-username').value = values.username;
  $('#edit-cred-password').value = values.password;
  $('#edit-cred-hash').value     = values.hash;
  $('#edit-cred-source').value   = values.source;
  // A value that is not shown (not loaded yet, or cannot be decrypted) stays
  // as stored unless something is typed here.
  if (values.passUnknown) $('#edit-cred-password').placeholder = values.passError ? 'cannot be decrypted (kept unless you type a new one)' : 'unchanged';
  if (values.hashUnknown) $('#edit-cred-hash').placeholder = values.hashError ? 'cannot be decrypted (kept unless you type a new one)' : 'unchanged';

  $('#form-edit-cred').addEventListener('submit', async ev => {
    ev.preventDefault();
    const body = {
      username: $('#edit-cred-username').value.trim(),
      source:   $('#edit-cred-source').value.trim(),
    };
    // Only changed secrets are sent, so a value that is not shown is never
    // written back over the stored one.
    const pass = $('#edit-cred-password').value.trim();
    const hash = $('#edit-cred-hash').value.trim();
    if (pass !== values.password) body.password = pass;
    if (hash !== values.hash) body.hash = hash;
    try {
      await apiPost(`/hosts/${hid}/credentials/${cid}`, body, 'PUT');
      hideModal();
      await refreshAssessment();
    } catch (e) { alert(e.message); }
  });
  $('#cancel-edit-cred').addEventListener('click', hideModal);
}

/* ==========================================================
   Commands Page (global – not tied to assessments)
   ========================================================== */
/* ==========================================================
   Host Commands Tab
   ========================================================== */
async function renderHostCommandsTab(hid) {
  const container = $('#host-commands-content');
  if (!container) return;
  try {
    const cmds = await apiGet(`/hosts/${hid}/commands`);
    // Update the tab label with the current count.
    const tabBtn = document.querySelector('.tab-btn[data-tab="commands"]');
    if (tabBtn) tabBtn.textContent = `Commands (${cmds.length})`;
    if (cmds.length === 0) {
      container.innerHTML = '<div class="empty-state"><p>No commands logged yet. Click &quot;+ Add Command&quot; to log one.</p></div>';
      return;
    }
    container.innerHTML = `
      <table class="host-cmd-table">
        <thead><tr><th style="width:200px">Name</th><th>Command</th><th style="width:120px">Actions</th></tr></thead>
        <tbody>
          ${cmds.map(cmd => {
            const cid     = cmd.id ?? cmd.ID ?? '';
            const name    = cmd.name ?? cmd.Name ?? '';
            const command = cmd.command ?? cmd.Command ?? '';
            const notes   = cmd.notes ?? cmd.Notes ?? '';
            return `<tr class="host-cmd-row${notes ? ' has-notes' : ''}" data-cmd-id="${cid}" data-hid="${hid}">
              <td class="host-cmd-name"><span>${esc(name)}</span></td>
              <td class="cmd-text-cell"><div class="cmd-cell"><pre class="cmd-pre">${esc(command)}</pre><button class="btn-icon copy-host-cmd" title="Copy command">${ICON_COPY}</button></div></td>
              <td><div class="cmd-actions">
                <button class="btn btn-sm btn-secondary edit-host-cmd">Edit</button>
                <button class="btn btn-sm btn-danger del-host-cmd">Del</button>
              </div></td>
            </tr>
            ${notes ? `<tr class="host-cmd-notes-row hidden" data-cmd-id="${cid}">
              <td colspan="3"><div class="host-cmd-notes-content">${esc(notes)}</div></td>
            </tr>` : ''}`;
          }).join('')}
        </tbody>
      </table>`;
  } catch (e) {
    container.innerHTML = `<div class="empty-state"><p>Failed to load commands: ${esc(e.message)}</p></div>`;
  }
}

/* ==========================================================
   Modal: Add Host Command
   ========================================================== */
function showAddHostCommandModal(hid) {
  showModal(`
    <h3>Log Command</h3>
    <form id="form-add-host-cmd">
      <label>Name
        <input type="text" id="hcmd-name" required placeholder="e.g. Initial nmap scan">
      </label>
      <label>Command
        <textarea id="hcmd-command" rows="4" required class="mono-textarea" placeholder="e.g. nmap -sV -sC 10.0.0.1"></textarea>
      </label>
      <label>Notes
        <textarea id="hcmd-notes" rows="4" class="mono-textarea" placeholder="Findings, output summary, context..."></textarea>
      </label>
      <div class="flex gap-2 mt-4">
        <button type="submit" class="btn btn-primary">Save</button>
        <button type="button" class="btn btn-secondary" id="cancel-hcmd">Cancel</button>
      </div>
    </form>`);

  $('#form-add-host-cmd').addEventListener('submit', async ev => {
    ev.preventDefault();
    try {
      await apiPost(`/hosts/${hid}/commands`, {
        name:    $('#hcmd-name').value.trim(),
        command: $('#hcmd-command').value,
        notes:   $('#hcmd-notes').value,
      });
      hideModal();
      renderHostCommandsTab(hid);
    } catch (e) { alert(e.message); }
  });
  $('#cancel-hcmd').addEventListener('click', hideModal);
}

/* ==========================================================
   Modal: Edit Host Command
   ========================================================== */
function showEditHostCommandModal(cid, hid, values) {
  showModal(`
    <h3>Edit Command</h3>
    <form id="form-edit-host-cmd">
      <label>Name
        <input type="text" id="edit-hcmd-name" required>
      </label>
      <label>Command
        <textarea id="edit-hcmd-command" rows="4" required class="mono-textarea"></textarea>
      </label>
      <label>Notes
        <textarea id="edit-hcmd-notes" rows="4" class="mono-textarea" placeholder="Findings, output summary, context..."></textarea>
      </label>
      <div class="flex gap-2 mt-4">
        <button type="submit" class="btn btn-primary">Save</button>
        <button type="button" class="btn btn-secondary" id="cancel-edit-hcmd">Cancel</button>
      </div>
    </form>`);

  $('#edit-hcmd-name').value    = values.name    || '';
  $('#edit-hcmd-command').value = values.command || '';
  $('#edit-hcmd-notes').value   = values.notes   || '';

  $('#form-edit-host-cmd').addEventListener('submit', async ev => {
    ev.preventDefault();
    try {
      await apiPost(`/hosts/${hid}/commands/${cid}`, {
        name:    $('#edit-hcmd-name').value.trim(),
        command: $('#edit-hcmd-command').value,
        notes:   $('#edit-hcmd-notes').value,
      }, 'PUT');
      hideModal();
      renderHostCommandsTab(hid);
    } catch (e) { alert(e.message); }
  });
  $('#cancel-edit-hcmd').addEventListener('click', hideModal);
}

async function renderCommands() {
  hideSidebar();
  currentAssessment = null;
  currentHostId = null;

  showNavButtons();
  setUserEmail();

  const app = $('#app');
  app.innerHTML = '<p class="text-muted" style="padding:24px">Loading commands...</p>';

  try {
    const allCmds = await apiGet('/commands');

    // Derive unique categories from saved commands, merged with defaults
    const savedCats = [...new Set(allCmds.map(c => (c.category || '').trim()).filter(Boolean))];
    knownCategories = [...new Set([...DEFAULT_CATEGORIES, ...savedCats])].sort();

    // Apply OS + category filters client-side
    let cmds = allCmds;
    if (commandOsFilter) cmds = cmds.filter(c => (c.os || '') === commandOsFilter);
    if (commandCategoryFilter) cmds = cmds.filter(c => (c.category || '') === commandCategoryFilter);

    const catOptions = knownCategories.map(cat =>
      `<option value="${esc(cat)}"${commandCategoryFilter === cat ? ' selected' : ''}>${esc(cat)}</option>`
    ).join('');

    app.innerHTML = `
      <div class="page-header">
        <div class="page-header-left">
          <div class="page-breadcrumb">Dashboard</div>
          <h2 class="page-title">Commands</h2>
        </div>
        <div class="page-header-actions">
          <button class="btn btn-sm btn-primary" id="cmd-add-new">+ New Command</button>
        </div>
      </div>
      <div class="commands-toolbar">
        <select id="cmd-cat-filter" class="cmd-filter-select">
          <option value="">All Categories</option>
          ${catOptions}
        </select>
        <select id="cmd-os-filter" class="cmd-filter-select">
          <option value="">All OS</option>
          <option value="Linux"${commandOsFilter === 'Linux' ? ' selected' : ''}>Linux</option>
          <option value="Windows"${commandOsFilter === 'Windows' ? ' selected' : ''}>Windows</option>
          <option value="macOS"${commandOsFilter === 'macOS' ? ' selected' : ''}>macOS</option>
          <option value="Any"${commandOsFilter === 'Any' ? ' selected' : ''}>Any / Cross-platform</option>
        </select>
        <input type="text" id="cmd-search" class="cmd-search-input" placeholder="Search commands...">
      </div>
      ${cmds.length > 0 ? `
      <table id="commands-table">
        <thead>
          <tr><th style="width:140px">Category</th><th style="width:75px">OS</th><th style="width:130px">Host</th><th style="width:160px">Name</th><th>Command</th><th style="width:100px">Actions</th></tr>
        </thead>
        <tbody>
          ${cmds.map(cmd => {
            const cid            = cmd.id ?? cmd.ID ?? '';
            const os             = cmd.os ?? cmd.OS ?? '';
            const category       = cmd.category ?? '';
            const name           = cmd.name ?? cmd.Name ?? '';
            const command        = cmd.command ?? cmd.Command ?? '';
            const notes          = cmd.notes ?? cmd.Notes ?? '';
            const hostIdentifier = cmd.host_identifier ?? '';
            return `<tr class="cmd-main-row${notes ? ' has-notes' : ''}" data-cmd-id="${cid}">
              <td class="cmd-category-cell">${category ? `<span class="cmd-cat-badge">${esc(category)}</span>` : '<span class="cmd-cat-none">—</span>'}</td>
              <td><span class="os-badge os-${esc(os).toLowerCase()}">${esc(os) || '—'}</span></td>
              <td class="cmd-host-cell">${hostIdentifier ? `<span class="cmd-host-badge">${esc(hostIdentifier)}</span>` : '<span class="cmd-cat-none">—</span>'}</td>
              <td class="cmd-name-cell">${esc(name)}</td>
              <td class="cmd-text-cell"><div class="cmd-cell"><pre class="cmd-pre">${esc(command)}</pre><button class="btn-icon copy-cmd" title="Copy command">${ICON_COPY}</button></div></td>
              <td><div class="cmd-actions">
                <button class="btn btn-sm btn-secondary edit-cmd">Edit</button>
                <button class="btn btn-sm btn-danger del-cmd">Del</button>
              </div></td>
            </tr>
            ${notes ? `<tr class="cmd-notes-row hidden" data-cmd-id="${cid}">
              <td colspan="6" class="cmd-notes-td"><div class="cmd-notes-content">${esc(notes)}</div></td>
            </tr>` : ''}`;
          }).join('')}
        </tbody>
      </table>` : `<div class="empty-state"><p>${commandOsFilter || commandCategoryFilter ? 'No commands match the selected filters.' : 'No commands saved yet. Click &quot;+ New Command&quot; to add your first one.'}</p></div>`}
      <div id="cmd-back-row" class="mt-6">
        <button class="btn btn-orange" id="cmd-back-dash">&#8592; Dashboard</button>
      </div>`;

    // Category filter
    $('#cmd-cat-filter').addEventListener('change', ev => {
      commandCategoryFilter = ev.target.value;
      renderCommands();
    });

    // OS filter
    $('#cmd-os-filter').addEventListener('change', ev => {
      commandOsFilter = ev.target.value;
      renderCommands();
    });

    // Live search (category + name + command + host)
    $('#cmd-search').addEventListener('input', ev => {
      const q = ev.target.value.toLowerCase();
      $$('#commands-table tbody tr.cmd-main-row').forEach(row => {
        const cat  = row.children[0].textContent.toLowerCase();
        const host = row.children[2].textContent.toLowerCase();
        const name = row.children[3].textContent.toLowerCase();
        const cmd  = row.children[4].textContent.toLowerCase();
        const visible = (cat.includes(q) || name.includes(q) || cmd.includes(q) || host.includes(q));
        row.style.display = visible ? '' : 'none';
        // Keep notes row in sync with its parent visibility
        const notesRow = row.nextElementSibling;
        if (notesRow && notesRow.classList.contains('cmd-notes-row') && !visible) {
          notesRow.style.display = 'none';
        }
      });
    });

    $('#cmd-add-new').addEventListener('click', showAddCommandModal);
    $('#cmd-back-dash').addEventListener('click', renderDashboard);

  } catch (err) {
    app.innerHTML = `<p class="text-muted">${esc(err.message)}</p>`;
  }
}

/* ==========================================================
   Modal: Import Nmap XML
   ========================================================== */
function showNmapImportModal(hid) {
  showModal(`
    <h3>Import Nmap XML</h3>
    <p style="color:var(--fg-dim);font-size:0.85rem;margin-bottom:1rem">
      Only the scan entry whose IP address or hostname is this host's identifier is imported.
      Service and Info values you entered by hand (shown in italics) are kept.
    </p>
    <form id="form-nmap">
      <label>Select Nmap XML file (-sV output)
        <input type="file" id="nmap-file" accept=".xml" required>
      </label>
      <div class="flex gap-2 mt-4">
        <button type="submit" class="btn btn-primary">Upload &amp; Parse</button>
        <button type="button" class="btn btn-secondary" id="cancel">Cancel</button>
      </div>
    </form>`);

  $('#form-nmap').addEventListener('submit', async ev => {
    ev.preventDefault();
    const file = $('#nmap-file').files[0];
    if (!file) { alert('Select an XML file'); return; }
    const fd = new FormData();
    fd.append('file', file);
    try {
      const res = await fetch(`${API_BASE}/hosts/${hid}/nmap`, {
        method: 'POST', headers: authHeaders(), credentials: 'same-origin', body: fd,
      });
      if (res.status === 401) { logout(); throw new Error('Session expired'); }
      if (!res.ok) {
        const d = await res.json().catch(() => ({}));
        throw new Error(d.error || `Upload failed (${res.status})`);
      }
      const data = await res.json();
      hideModal();
      await refreshAssessment();
      alert(nmapHostImportSummary(data));
    } catch (e) { alert(e.message); }
  });
  $('#cancel').addEventListener('click', hideModal);
}

// Result of a host's Nmap import, always shown. The server reports which
// file host(s) the ports came from (imported_from) and the state the file
// lists this host in (host_state, '' when the file does not list it).
function nmapHostImportSummary(d) {
  const from = d.imported_from;
  if (Array.isArray(from) && !from.length) {
    return d.host_state && d.host_state !== 'up'
      ? `Nothing imported: nmap did not find this host up in this scan (state: ${d.host_state}).`
      : 'Nothing imported: no host in the file is up.';
  }
  let msg = d.added || d.updated
    ? `Import complete: ${d.added} port${d.added !== 1 ? 's' : ''} added, ${d.updated} updated.`
    : 'Import complete: no new or changed ports.';
  if (Array.isArray(from) && d.host_state === '') {
    msg += ` The file does not list this host's identifier, so the ports of its only scanned host, ${from.join(', ')}, were imported.`;
  }
  return msg + nmapKeptNote(d.kept) + nmapSkippedNote(d.skipped);
}

// Suffix for the import alerts: open ports the server ignored because their
// number or protocol is invalid (hand-edited or converted XML).
function nmapSkippedNote(skipped) {
  return skipped ? ` Skipped ${skipped} port${skipped !== 1 ? 's' : ''} with an invalid number or protocol.` : '';
}

// Suffix for the import alerts: ports whose Service/Info the user typed and
// the scan would have changed (shown in italics in the port table).
function nmapKeptNote(kept) {
  return kept ? ` Kept the Service/Info you entered on ${kept} port${kept !== 1 ? 's' : ''} (shown in italics); clear a field in Edit Port to let scans fill it again.` : '';
}

// A port table cell's content: a Service/Info value the user typed is shown
// in italics, since Nmap imports keep it instead of the scanned value. The
// cell's text stays the bare value (the Edit Port modal reads it).
function portValueHTML(value, edited) {
  return edited && value
    ? `<em title="Entered by hand: Nmap imports keep this value">${esc(value)}</em>`
    : esc(value);
}

/* ==========================================================
   Modal: Add Command
   ========================================================== */
function showAddCommandModal() {
  const catListOptions = knownCategories.map(c => `<option value="${esc(c)}">`).join('');
  showModal(`
    <h3>New Command</h3>
    <form id="form-add-cmd">
      <label>Category
        <input type="text" id="cmd-category" list="cmd-cat-datalist" placeholder="e.g. Reverse Shells (type to search or create new)">
        <datalist id="cmd-cat-datalist">${catListOptions}</datalist>
      </label>
      <label>OS
        <select id="cmd-os">
          <option value="Linux">Linux</option>
          <option value="Windows">Windows</option>
          <option value="macOS">macOS</option>
          <option value="Any">Any / Cross-platform</option>
        </select>
      </label>
      <label>Name
        <input type="text" id="cmd-name" required placeholder="e.g. PowerShell Reverse Shell">
      </label>
      <label>Command
        <textarea id="cmd-command" rows="4" required placeholder="e.g. powershell -e ..." class="mono-textarea"></textarea>
      </label>
      <label>Notes
        <textarea id="cmd-notes" rows="3" class="mono-textarea" placeholder="Optional notes, context, or findings..."></textarea>
      </label>
      <div class="flex gap-2 mt-4">
        <button type="submit" class="btn btn-primary">Save Command</button>
        <button type="button" class="btn btn-secondary" id="cancel">Cancel</button>
      </div>
    </form>`);

  if (commandCategoryFilter) $('#cmd-category').value = commandCategoryFilter;

  $('#form-add-cmd').addEventListener('submit', async ev => {
    ev.preventDefault();
    try {
      await apiPost('/commands', {
        os:       $('#cmd-os').value,
        category: $('#cmd-category').value.trim(),
        name:     $('#cmd-name').value.trim(),
        command:  $('#cmd-command').value,
        notes:    $('#cmd-notes').value,
      });
      hideModal();
      renderCommands();
    } catch (e) { alert(e.message); }
  });
  $('#cancel').addEventListener('click', hideModal);
}

/* ==========================================================
   Modal: Edit Command
   ========================================================== */
function showEditCommandModal(cid, values) {
  const catListOptions = knownCategories.map(c => `<option value="${esc(c)}">`).join('');
  showModal(`
    <h3>Edit Command</h3>
    <form id="form-edit-cmd">
      <label>Category
        <input type="text" id="edit-cmd-category" list="edit-cmd-cat-datalist" placeholder="e.g. Reverse Shells">
        <datalist id="edit-cmd-cat-datalist">${catListOptions}</datalist>
      </label>
      <label>OS
        <select id="edit-cmd-os">
          <option value="Linux">Linux</option>
          <option value="Windows">Windows</option>
          <option value="macOS">macOS</option>
          <option value="Any">Any / Cross-platform</option>
        </select>
      </label>
      <label>Name
        <input type="text" id="edit-cmd-name" required>
      </label>
      <label>Command
        <textarea id="edit-cmd-command" rows="4" required class="mono-textarea"></textarea>
      </label>
      <label>Notes
        <textarea id="edit-cmd-notes" rows="3" class="mono-textarea" placeholder="Optional notes, context, or findings..."></textarea>
      </label>
      <div class="flex gap-2 mt-4">
        <button type="submit" class="btn btn-primary">Save</button>
        <button type="button" class="btn btn-secondary" id="cancel-edit-cmd">Cancel</button>
      </div>
    </form>`);

  $('#edit-cmd-category').value = values.category || '';
  $('#edit-cmd-os').value       = values.os || 'Linux';
  $('#edit-cmd-name').value     = values.name;
  $('#edit-cmd-command').value  = values.command;
  $('#edit-cmd-notes').value    = values.notes || '';

  $('#form-edit-cmd').addEventListener('submit', async ev => {
    ev.preventDefault();
    try {
      await apiPost(`/commands/${cid}`, {
        os:       $('#edit-cmd-os').value,
        category: $('#edit-cmd-category').value.trim(),
        name:     $('#edit-cmd-name').value.trim(),
        command:  $('#edit-cmd-command').value,
        notes:    $('#edit-cmd-notes').value,
      }, 'PUT');
      hideModal();
      renderCommands();
    } catch (e) { alert(e.message); }
  });
  $('#cancel-edit-cmd').addEventListener('click', hideModal);
}


/* ==========================================================
   Inline Editing for Host Fields
   ========================================================== */
function startInlineEdit(span) {
  if (span.querySelector('input, select')) return; // already editing

  const field   = span.dataset.field;
  const hid     = span.dataset.hid;
  const type    = span.dataset.type;
  const options = span.dataset.options ? span.dataset.options.split(',') : [];

  // Get the current raw value (not the placeholder HTML)
  const currentHost = (currentAssessment.hosts || currentAssessment.Hosts || [])
    .find(h => (h.id || h.ID) === hid);
  const currentVal = currentHost ? (currentHost[field] || currentHost[field.replace(/_([a-z])/g, (_, c) => c.toUpperCase())] || '') : '';

  let el;
  if (type === 'select') {
    el = document.createElement('select');
    el.className = 'inline-edit-input';
    options.forEach(opt => {
      const o = document.createElement('option');
      o.value = opt;
      o.textContent = opt;
      if (opt === currentVal) o.selected = true;
      el.appendChild(o);
    });
  } else {
    el = document.createElement('input');
    el.type = 'text';
    el.className = 'inline-edit-input';
    el.value = currentVal;
    el.placeholder = 'Enter value...';
  }

  span.textContent = '';
  span.appendChild(el);
  el.focus();

  async function save() {
    const newVal = el.value;
    // Build the full host payload with updated field
    const h = currentHost || {};
    const payload = {
      identifier:  h.identifier || h.Identifier || '',
      label:       h.label || h.Label || '',
      device_type: h.device_type || h.DeviceType || '',
      os:          h.os || h.OS || '',
    };
    payload[field] = newVal;

    try {
      await apiPost(`/hosts/${hid}`, payload, 'PUT');
      await refreshAssessment();
    } catch (e) {
      alert(e.message);
      await refreshAssessment();
    }
  }

  let saved = false;
  el.addEventListener('blur', () => { if (!saved) { saved = true; save(); } });
  el.addEventListener('keydown', ev => {
    if (ev.key === 'Enter') { ev.preventDefault(); if (!saved) { saved = true; save(); } }
    if (ev.key === 'Escape') { ev.preventDefault(); refreshAssessment(); }
  });
  if (type === 'select') {
    el.addEventListener('change', () => { if (!saved) { saved = true; save(); } });
  }
}

/* ==========================================================
   Global Event Delegation (port edit/delete in table)
   ========================================================== */
function setupGlobalDelegation() {
  document.body.addEventListener('click', ev => {
    // Skull (compromised) toggle
    const skullBtn = ev.target.closest('.skull-btn');
    if (skullBtn) {
      ev.stopPropagation();
      const hid = skullBtn.dataset.hid;
      const nowCompromised = !skullBtn.classList.contains('compromised');
      apiPatch(`/hosts/${hid}/compromised`, { compromised: nowCompromised })
        .then(() => refreshAssessment())
        .catch(e => alert(e.message));
      return;
    }

    // Inline editable fields (host label/type/os)
    const editable = ev.target.closest('.inline-editable');
    if (editable && !editable.querySelector('input, select')) {
      ev.stopPropagation();
      startInlineEdit(editable);
      return;
    }

    // Toggle port script dropdown
    const portRow = ev.target.closest('.port-row.has-scripts');
    if (portRow && !ev.target.closest('button')) {
      portRow.classList.toggle('open');
      return;
    }

    // Edit Port
    if (ev.target.matches('.edit-port')) {
      const row = ev.target.closest('tr');
      if (!row) return;
      const pid = row.dataset.portId;
      const hid = row.dataset.hostId;
      if (!pid || !hid) return;

      const cells = row.querySelectorAll('td');
      showEditPortModal(hid, pid, {
        number:  parseInt(row.dataset.num, 10),
        proto:   cells[1].textContent.trim(),
        service: cells[2].textContent.trim(),
        info:    cells[3].textContent.trim(),
      });
    }

    // Delete Port
    if (ev.target.matches('.del-port')) {
      const row = ev.target.closest('tr');
      if (!row) return;
      const pid = row.dataset.portId;
      const hid = row.dataset.hostId;
      if (!pid || !hid) return;
      if (!confirm('Delete this port?')) return;
      apiDelete(`/hosts/${hid}/ports/${pid}`)
        .then(() => refreshAssessment())
        .catch(e => alert(e.message));
    }

    // Edit Credential
    if (ev.target.matches('.edit-cred')) {
      const row = ev.target.closest('tr');
      if (!row) return;
      const cid = row.dataset.credId;
      const hid = row.dataset.hostId;
      if (!cid || !hid) return;

      showEditCredentialModal(hid, cid, {
        username: row.dataset.user   || '',
        password: row.dataset.pass   || '',
        hash:     row.dataset.hash   || '',
        source:   row.dataset.source || '',
        passUnknown: 'pending' in row.dataset || 'passError' in row.dataset,
        hashUnknown: 'pending' in row.dataset || 'hashError' in row.dataset,
        passError: 'passError' in row.dataset,
        hashError: 'hashError' in row.dataset,
      });
    }

    // Delete Credential
    if (ev.target.matches('.del-cred')) {
      const row = ev.target.closest('tr');
      if (!row) return;
      const cid = row.dataset.credId;
      const hid = row.dataset.hostId;
      if (!cid || !hid) return;
      if (!confirm('Delete this credential?')) return;
      apiDelete(`/hosts/${hid}/credentials/${cid}`)
        .then(() => refreshAssessment())
        .catch(e => alert(e.message));
    }

    // Toggle credential password visibility
    const passToggleBtn = ev.target.closest('.pass-toggle');
    if (passToggleBtn) {
      const div = passToggleBtn.closest('.pass-cell');
      if (!div) return;
      const masked  = div.querySelector('.pass-masked');
      const plain   = div.querySelector('.pass-plain');
      const showing = !plain.classList.contains('hidden');
      masked.classList.toggle('hidden', !showing);
      plain.classList.toggle('hidden', showing);
      passToggleBtn.innerHTML = showing ? ICON_EYE : ICON_EYE_OFF;
      passToggleBtn.title = showing ? 'Show password' : 'Hide password';
    }

    // Toggle credential hash visibility
    const hashToggleBtn = ev.target.closest('.hash-toggle');
    if (hashToggleBtn) {
      const div = hashToggleBtn.closest('.hash-cell');
      if (!div) return;
      const masked  = div.querySelector('.hash-masked');
      const plain   = div.querySelector('.hash-plain');
      const showing = !plain.classList.contains('hidden');
      masked.classList.toggle('hidden', !showing);
      plain.classList.toggle('hidden', showing);
      hashToggleBtn.innerHTML = showing ? ICON_EYE : ICON_EYE_OFF;
      hashToggleBtn.title = showing ? 'Show hash' : 'Hide hash';
    }

    // Copy credential username
    const copyUserBtn = ev.target.closest('.copy-cred-user');
    if (copyUserBtn) {
      const row = copyUserBtn.closest('tr');
      if (!row) return;
      navigator.clipboard.writeText(row.dataset.user || '').then(() => {
        copyUserBtn.innerHTML = ICON_COPIED;
        copyUserBtn.classList.add('btn-icon-copied');
        setTimeout(() => { copyUserBtn.innerHTML = ICON_COPY; copyUserBtn.classList.remove('btn-icon-copied'); }, 1500);
      }).catch(() => alert('Failed to copy'));
    }

    // Copy credential password
    const copyPassBtn = ev.target.closest('.copy-cred-pass');
    if (copyPassBtn) {
      const row = copyPassBtn.closest('tr');
      if (!row) return;
      navigator.clipboard.writeText(row.dataset.pass || '').then(() => {
        copyPassBtn.innerHTML = ICON_COPIED;
        copyPassBtn.classList.add('btn-icon-copied');
        setTimeout(() => { copyPassBtn.innerHTML = ICON_COPY; copyPassBtn.classList.remove('btn-icon-copied'); }, 1500);
      }).catch(() => alert('Failed to copy'));
    }

    // Copy credential hash
    const copyHashBtn = ev.target.closest('.copy-cred-hash');
    if (copyHashBtn) {
      const row = copyHashBtn.closest('tr');
      if (!row) return;
      navigator.clipboard.writeText(row.dataset.hash || '').then(() => {
        copyHashBtn.innerHTML = ICON_COPIED;
        copyHashBtn.classList.add('btn-icon-copied');
        setTimeout(() => { copyHashBtn.innerHTML = ICON_COPY; copyHashBtn.classList.remove('btn-icon-copied'); }, 1500);
      }).catch(() => alert('Failed to copy'));
    }

    // Copy Command
    if (ev.target.matches('.copy-cmd')) {
      const row = ev.target.closest('tr');
      if (!row) return;
      const pre = row.querySelector('.cmd-pre');
      if (!pre) return;
      navigator.clipboard.writeText(pre.textContent).then(() => {
        const btn = ev.target.closest('.copy-cmd');
        btn.innerHTML = ICON_COPIED;
        btn.classList.add('btn-icon-copied');
        setTimeout(() => { btn.innerHTML = ICON_COPY; btn.classList.remove('btn-icon-copied'); }, 1500);
      }).catch(() => alert('Failed to copy'));
    }

    // Toggle global command notes by clicking anywhere on a has-notes row
    // (ignore clicks on buttons and interactive elements inside the row)
    const cmdRow = ev.target.closest('tr.cmd-main-row.has-notes');
    if (cmdRow && !ev.target.closest('button, a, input, select, textarea')) {
      const notesRow = cmdRow.nextElementSibling;
      if (notesRow && notesRow.classList.contains('cmd-notes-row')) {
        notesRow.classList.toggle('hidden');
      }
      return;
    }

    // Edit Command (global)
    if (ev.target.matches('.edit-cmd')) {
      const row = ev.target.closest('tr');
      if (!row) return;
      const cid = row.dataset.cmdId;
      if (!cid) return;
      const category = row.querySelector('.cmd-cat-badge')?.textContent.trim() || '';
      const os = row.querySelector('.os-badge')?.textContent.trim() || '';
      const name = row.querySelector('.cmd-name-cell')?.textContent.trim() || '';
      const command = row.querySelector('.cmd-pre')?.textContent || '';
      // Notes are stored in the sibling notes row
      const notesRow = row.nextElementSibling;
      const notes = notesRow?.classList.contains('cmd-notes-row')
        ? (notesRow.querySelector('.cmd-notes-content')?.textContent || '') : '';
      showEditCommandModal(cid, { category, os, name, command, notes });
    }

    // Delete Command (global)
    if (ev.target.matches('.del-cmd')) {
      const row = ev.target.closest('tr');
      if (!row) return;
      const cid = row.dataset.cmdId;
      if (!cid) return;
      if (!confirm('Delete this command?')) return;
      apiDelete(`/commands/${cid}`)
        .then(() => renderCommands())
        .catch(e => alert(e.message));
    }

    // Toggle host command notes by clicking anywhere on a has-notes row
    const hostCmdRow = ev.target.closest('tr.host-cmd-row.has-notes');
    if (hostCmdRow && !ev.target.closest('button, a, input, select, textarea')) {
      const notesRow = hostCmdRow.nextElementSibling;
      if (notesRow && notesRow.classList.contains('host-cmd-notes-row')) {
        notesRow.classList.toggle('hidden');
      }
      return;
    }

    // Copy host command
    if (ev.target.closest('.copy-host-cmd')) {
      const row = ev.target.closest('tr.host-cmd-row');
      if (!row) return;
      const pre = row.querySelector('.cmd-pre');
      if (!pre) return;
      const btn = ev.target.closest('.copy-host-cmd');
      navigator.clipboard.writeText(pre.textContent).then(() => {
        btn.innerHTML = ICON_COPIED;
        btn.classList.add('btn-icon-copied');
        setTimeout(() => { btn.innerHTML = ICON_COPY; btn.classList.remove('btn-icon-copied'); }, 1500);
      }).catch(() => alert('Failed to copy'));
      return;
    }

    // Edit host command
    if (ev.target.matches('.edit-host-cmd')) {
      const row = ev.target.closest('tr.host-cmd-row');
      if (!row) return;
      const cid = row.dataset.cmdId;
      const hid = row.dataset.hid;
      if (!cid || !hid) return;
      const name    = row.querySelector('.host-cmd-name span:last-child')?.textContent || '';
      const command = row.querySelector('.cmd-pre')?.textContent || '';
      const notesRow = row.nextElementSibling;
      const notes = notesRow?.classList.contains('host-cmd-notes-row')
        ? (notesRow.querySelector('.host-cmd-notes-content')?.textContent || '') : '';
      showEditHostCommandModal(cid, hid, { name, command, notes });
    }

    // Delete host command
    if (ev.target.matches('.del-host-cmd')) {
      const row = ev.target.closest('tr.host-cmd-row');
      if (!row) return;
      const cid = row.dataset.cmdId;
      const hid = row.dataset.hid;
      if (!cid || !hid) return;
      if (!confirm('Delete this command?')) return;
      apiDelete(`/hosts/${hid}/commands/${cid}`)
        .then(() => renderHostCommandsTab(hid))
        .catch(e => alert(e.message));
    }
  });
}

/* ==========================================================
   Settings – 2FA / TOTP
   ========================================================== */
async function renderSettings() {
  hideSidebar();
  currentAssessment = null;
  currentHostId = null;
  showNavButtons();
  setUserEmail();

  const app = $('#app');
  app.innerHTML = `
    <div class="page-header">
      <div class="page-header-left">
        <div class="page-breadcrumb">Dashboard</div>
        <h2 class="page-title">Settings</h2>
      </div>
    </div>
    <div class="settings-card">
      <div class="settings-section">
        <h3 class="settings-section-title">Appearance</h3>
        <div class="theme-toggle-row">
          <div>
            <div class="settings-item-label">Theme</div>
            <div class="settings-item-desc">Choose how Penkeeper looks to you</div>
          </div>
          <div class="theme-seg" id="theme-seg">
            <button class="theme-seg-btn${(localStorage.getItem('theme') || 'dark') !== 'light' ? ' active' : ''}" data-theme="dark">Dark</button>
            <button class="theme-seg-btn${localStorage.getItem('theme') === 'light' ? ' active' : ''}" data-theme="light">Light</button>
          </div>
        </div>
        <div class="theme-toggle-row" style="margin-top:1rem">
          <div>
            <div class="settings-item-label">Sidebar Ports</div>
            <div class="settings-item-desc">Show port list under each host in the assessment sidebar</div>
          </div>
          <label class="toggle-switch">
            <input type="checkbox" id="setting-sidebar-ports" ${getSidebarPortsSetting() ? 'checked' : ''}>
            <span class="toggle-slider"></span>
          </label>
        </div>
        <div class="theme-toggle-row" style="margin-top:1rem">
          <div>
            <div class="settings-item-label">Font Size</div>
            <div class="settings-item-desc">Adjust the base text size across the application</div>
          </div>
          <div class="theme-seg" id="font-size-seg">
            ${[11,13,15,17].map(s => `<button class="theme-seg-btn${getFontSize()===s?' active':''}" data-size="${s}">${s===11?'S':s===13?'M':s===15?'L':'XL'}</button>`).join('')}
          </div>
        </div>
      </div>
    </div>
    <div class="settings-card">
      <div class="settings-section">
        <h3 class="settings-section-title">Two-Factor Authentication</h3>
        <div id="totp-status-area"><p style="color:var(--muted)">Loading\u2026</p></div>
      </div>
    </div>
    <div class="settings-card">
      <div class="settings-section">
        <h3 class="settings-section-title">Data Transfer</h3>
        <p style="color:var(--fg-dim);font-size:0.85rem;margin-bottom:1.4rem">
          Export all assessments, hosts, notes, credentials, and commands to a JSON file.
          Import that file into any other installation to transfer your data.
          Credentials are decrypted in the export and re-encrypted on import &mdash; an
          unencrypted export therefore contains plaintext passwords, so store it carefully.
        </p>
        <div style="display:flex;align-items:center;gap:0.6rem;margin-bottom:1rem">
          <label class="toggle-switch" style="margin:0">
            <input type="checkbox" id="export-encrypt-toggle">
            <span class="toggle-slider"></span>
          </label>
          <span style="font-size:0.85rem;color:var(--fg-dim)">
            Encrypt export &mdash; produces a passphrase-protected <code>.pne</code> file (AES-256-GCM). You choose the passphrase and need it to import.
          </span>
        </div>
        <div style="display:flex;gap:0.75rem;flex-wrap:wrap;align-items:center">
          <button id="export-btn" class="btn btn-primary btn-sm">Export Data</button>
          <label class="btn btn-secondary btn-sm" style="cursor:pointer;margin:0">
            Import Data
            <input type="file" id="import-file-input" accept=".json,.pne" style="display:none">
          </label>
          <span id="transfer-msg" style="font-size:0.82rem"></span>
        </div>
      </div>
    </div>`;

  // Wire theme toggle
  $$('.theme-seg-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const t = btn.dataset.theme;
      applyTheme(t);
      $$('.theme-seg-btn').forEach(b => b.classList.toggle('active', b.dataset.theme === t));
    });
  });

  // Wire sidebar ports toggle
  $('#setting-sidebar-ports').addEventListener('change', e => {
    localStorage.setItem('pk_sidebar_ports', e.target.checked ? 'true' : 'false');
  });

  // Wire font size toggle
  $$('#font-size-seg .theme-seg-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      const sz = parseInt(btn.dataset.size, 10);
      applyFontSize(sz);
      $$('#font-size-seg .theme-seg-btn').forEach(b => b.classList.toggle('active', parseInt(b.dataset.size, 10) === sz));
    });
  });

  try {
    const me = await apiGet('/settings/me');
    renderTOTPStatus(me.totp_enabled);
  } catch (e) {
    $('#totp-status-area').innerHTML = `<p style="color:#ef4444">Error: ${e.message}</p>`;
  }

  // Export
  $('#export-btn').addEventListener('click', async () => {
    const btn = $('#export-btn');
    const msg = $('#transfer-msg');
    const encrypt = $('#export-encrypt-toggle') && $('#export-encrypt-toggle').checked;
    let passphrase = '';
    if (encrypt) {
      passphrase = prompt('Choose a passphrase to encrypt the export.\nYou will need this exact passphrase to import the file later.');
      if (passphrase === null) return; // cancelled
      if (passphrase.length < 8) {
        msg.style.color = '#ef4444';
        msg.textContent = 'Passphrase must be at least 8 characters.';
        return;
      }
    }
    btn.disabled = true;
    btn.textContent = 'Exporting\u2026';
    msg.textContent = '';
    try {
      const exportURL = '/api/v1/export' + (encrypt ? '?encrypt=true' : '');
      const res = await fetch(exportURL, {
        credentials: 'same-origin',
        headers: encrypt ? { 'X-Bundle-Passphrase': passphrase } : {}
      });
      if (!res.ok) {
        const d = await res.json().catch(() => ({}));
        throw new Error(d.error || 'Export failed');
      }
      const disposition = res.headers.get('Content-Disposition') || '';
      const match = disposition.match(/filename="([^"]+)"/);
      const filename = match ? match[1] : (encrypt ? 'penkeeper-export.pne' : 'penkeeper-export.json');
      const blob = await res.blob();
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = filename;
      document.body.appendChild(a); a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
      msg.style.color = 'var(--success, #98c379)';
      msg.textContent = 'Export downloaded.';
    } catch (e) {
      msg.style.color = '#ef4444';
      msg.textContent = e.message;
    } finally {
      btn.disabled = false;
      btn.textContent = 'Export Data';
      setTimeout(() => { if ($('#transfer-msg')) $('#transfer-msg').textContent = ''; }, 4000);
    }
  });

  // Import
  $('#import-file-input').addEventListener('change', async (e) => {
    const file = e.target.files[0];
    if (!file) return;
    const msg = $('#transfer-msg');
    try {
      const text = await file.text();
      const headers = { 'Content-Type': 'text/plain' };
      // Encrypted bundles (pne_enc: 2) need the passphrase used at export time.
      try {
        const env = JSON.parse(text);
        if (env && env.pne_enc === 2) {
          const pass = prompt('This bundle is encrypted. Enter its passphrase:');
          if (pass === null) return; // cancelled
          headers['X-Bundle-Passphrase'] = pass;
        }
      } catch (_) { /* plain .json export, not an encrypted envelope */ }
      msg.textContent = 'Importing\u2026';
      msg.style.color = 'var(--fg-dim)';
      const res = await fetch('/api/v1/import', {
        method: 'POST',
        credentials: 'same-origin',
        headers,
        body: text
      });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || 'Import failed');
      msg.style.color = 'var(--success, #98c379)';
      msg.textContent = `Imported ${data.assessments_imported} assessment(s), ${data.hosts_imported} host(s), ${data.commands_imported} command(s).`;
      // Values the import changed to meet the app's rules.
      if (Array.isArray(data.repaired) && data.repaired.length) {
        msg.textContent += ` Repaired: ${data.repaired.join('; ')}.`;
      }
      // Assessments the import skipped because they are not infrastructure ones.
      if (Array.isArray(data.skipped) && data.skipped.length) {
        msg.style.color = 'var(--yellow, #e5c07b)';
        msg.textContent += ` Skipped, only infrastructure assessments are imported: ${data.skipped.join('; ')}.`;
      }
    } catch (e) {
      msg.style.color = '#ef4444';
      msg.textContent = e.message;
    } finally {
      e.target.value = '';
    }
  });
}

function renderTOTPStatus(enabled) {
  const area = $('#totp-status-area');
  if (!area) return;

  if (enabled) {
    area.innerHTML = `
      <div class="totp-status-row">
        <span class="totp-badge totp-badge-on">&#10003; Enabled</span>
        <p style="color:var(--fg-dim);margin:.6rem 0 1.2rem">
          Your account is protected with a time-based one-time password.
        </p>
        <button id="totp-disable-btn" class="btn btn-danger btn-sm">Disable 2FA</button>
      </div>`;
    $('#totp-disable-btn').addEventListener('click', async () => {
      const code = prompt('Enter a current 6-digit code from your authenticator app to disable 2FA:');
      if (code === null) return; // cancelled
      try {
        const res = await fetch(API_BASE + '/settings/totp', {
          method: 'DELETE',
          headers: { ...authHeaders(), ...jsonHeaders() },
          credentials: 'same-origin',
          body: JSON.stringify({ code: code.trim() }),
        });
        if (res.status === 401) { sessionExpired(); return; }
        if (!res.ok) {
          const d = await res.json().catch(() => ({}));
          throw new Error(d.error || 'Failed to disable 2FA');
        }
        renderTOTPStatus(false);
      } catch (e) { alert(e.message); }
    });
  } else {
    area.innerHTML = `
      <div class="totp-status-row">
        <span class="totp-badge totp-badge-off">&#10005; Disabled</span>
        <p style="color:var(--fg-dim);margin:.6rem 0 1.2rem">
          Protect your account with an authenticator app.
        </p>
        <button id="totp-setup-btn" class="btn btn-primary btn-sm">Enable 2FA</button>
      </div>
      <div id="totp-setup-area" class="hidden"></div>`;
    $('#totp-setup-btn').addEventListener('click', startTOTPSetup);
  }
}

async function startTOTPSetup() {
  $('#totp-setup-btn').disabled = true;
  $('#totp-setup-btn').textContent = 'Generating\u2026';
  try {
    const data = await apiPost('/settings/totp/setup', {});
    const setupArea = $('#totp-setup-area');
    setupArea.classList.remove('hidden');
    setupArea.innerHTML = `
      <hr class="settings-divider">
      <p style="color:var(--fg-dim);margin-bottom:1rem;font-size:0.9rem">
        Scan this QR code with your authenticator app, then enter the 6-digit code to confirm.
      </p>
      <div class="totp-qr">
        <img src="${data.qr_code}" alt="TOTP QR Code">
      </div>
      <details class="totp-secret-reveal">
        <summary>Can't scan? Enter code manually</summary>
        <div style="display:flex;align-items:center;gap:0.5rem;margin-top:0.4rem">
          <code class="totp-secret-text" id="totp-secret-val">${data.secret}</code>
          <button class="btn btn-sm btn-secondary" id="totp-copy-secret">Copy</button>
        </div>
      </details>
      <div style="margin-top:1.2rem">
        <label style="display:block;margin-bottom:.4rem;color:var(--fg-dim);font-size:.85rem">
          Verification Code
        </label>
        <input type="text" id="totp-verify-code" inputmode="numeric" maxlength="6"
          placeholder="000000" autocomplete="one-time-code"
          style="letter-spacing:.3em;font-size:1.2rem;text-align:center;width:10rem">
        <button id="totp-verify-btn" class="btn btn-primary btn-sm" style="margin-left:.8rem">
          Verify &amp; Enable
        </button>
        <span id="totp-verify-msg" style="margin-left:.8rem;font-size:.85rem"></span>
      </div>`;

    $('#totp-copy-secret').addEventListener('click', () => {
      const val = $('#totp-secret-val');
      if (!val) return;
      navigator.clipboard.writeText(val.textContent).then(() => {
        const btn = $('#totp-copy-secret');
        btn.textContent = 'Copied!';
        setTimeout(() => { btn.textContent = 'Copy'; }, 1500);
      }).catch(() => alert('Failed to copy'));
    });

    $('#totp-verify-btn').addEventListener('click', async () => {
      const code = $('#totp-verify-code').value.trim();
      if (code.length !== 6) { alert('Enter the 6-digit code from your app.'); return; }
      const msg = $('#totp-verify-msg');
      try {
        await apiPost('/settings/totp/enable', { code });
        msg.textContent = '';
        renderTOTPStatus(true);
      } catch (e) {
        msg.style.color = '#ef4444';
        msg.textContent = e.data?.error || e.message;
        $('#totp-verify-code').value = '';
        $('#totp-verify-code').focus();
      }
    });
  } catch (e) {
    alert(e.data?.error || e.message);
    const btn = $('#totp-setup-btn');
    if (btn) { btn.disabled = false; btn.textContent = 'Enable 2FA'; }
  }
}

/* ==========================================================
   Search
   ========================================================== */
let searchDebounce = null;

// gotoHostFromSearch loads the assessment, looks up the host OBJECT (not just
// its id — renderHostDetail expects the full host), sets it active, and renders
// it, optionally focusing a specific tab.
async function gotoHostFromSearch(eid, hostId, tab) {
  currentAssessment = await fetchAssessment(eid);
  const hosts = currentAssessment.hosts || currentAssessment.Hosts || [];
  const host = hosts.find(h => (h.id || h.ID) === hostId);
  if (!host) throw new Error('host not found in assessment');
  currentHostId = hostId;
  if (tab) activeHostTab = tab;
  renderHostDetail(host);
}

function renderSearch() {
  hideSidebar();
  currentAssessment = null;
  currentHostId = null;
  showNavButtons();
  setUserEmail();

  $('#app').innerHTML = `
    <div class="page-header">
      <div class="page-header-left">
        <div class="page-breadcrumb">Dashboard</div>
        <h2 class="page-title">Search</h2>
      </div>
    </div>
    <div class="search-input-wrap">
      <input type="text" id="search-input" class="search-main-input" placeholder="Search assessments, hosts, credentials, notes, commands…" autocomplete="off">
    </div>
    <div id="search-results"></div>`;

  const input = $('#search-input');
  input.focus();
  input.addEventListener('input', () => {
    clearTimeout(searchDebounce);
    const q = input.value.trim();
    if (q.length < 2) {
      $('#search-results').innerHTML = '<p class="search-hint">Type at least 2 characters to search.</p>';
      return;
    }
    searchDebounce = setTimeout(() => runSearch(q), 300);
  });
  $('#search-results').innerHTML = '<p class="search-hint">Type at least 2 characters to search.</p>';
}

async function runSearch(q) {
  const container = $('#search-results');
  if (!container) return;
  container.innerHTML = '<p class="search-hint">Searching…</p>';
  try {
    const data = await apiGet(`/search?q=${encodeURIComponent(q)}`);
    const total = (data.assessments?.length || 0) + (data.hosts?.length || 0) +
                  (data.credentials?.length || 0) + (data.notes?.length || 0) +
                  (data.commands?.length || 0);
    if (total === 0) {
      container.innerHTML = `<p class="search-hint">No results for <strong>${esc(q)}</strong>.</p>`;
      return;
    }

    let html = '';

    if (data.assessments?.length) {
      html += `<div class="search-section"><div class="search-section-title">Assessments</div>`;
      html += data.assessments.map(a =>
        `<div class="search-result-row" data-action="goto-assessment" data-id="${a.id}">
          <span class="search-result-title">${esc(a.name)}</span>
        </div>`).join('');
      html += '</div>';
    }

    if (data.hosts?.length) {
      html += `<div class="search-section"><div class="search-section-title">Hosts</div>`;
      html += data.hosts.map(h =>
        `<div class="search-result-row" data-action="goto-host" data-id="${h.id}" data-eid="${h.assessment_id}">
          <span class="search-result-title">${esc(h.identifier)}${h.label ? ' <span class="search-result-label">'+esc(h.label)+'</span>' : ''}</span>
          <span class="search-result-meta">${esc(h.assessment_name)}</span>
        </div>`).join('');
      html += '</div>';
    }

    if (data.credentials?.length) {
      html += `<div class="search-section"><div class="search-section-title">Credentials</div>`;
      html += data.credentials.map(cr =>
        `<div class="search-result-row" data-action="goto-host-creds" data-id="${cr.host_id}" data-eid="${cr.assessment_id}">
          <span class="search-result-title">${esc(cr.username)}</span>
          <span class="search-result-meta">${esc(cr.host_identifier)} &middot; ${esc(cr.assessment_name)}</span>
        </div>`).join('');
      html += '</div>';
    }

    if (data.notes?.length) {
      html += `<div class="search-section"><div class="search-section-title">Notes</div>`;
      html += data.notes.map(n =>
        `<div class="search-result-row" data-action="goto-host-notes" data-id="${n.host_id}" data-eid="${n.assessment_id}">
          <div>
            <span class="search-result-title">${esc(n.title || '(untitled)')}</span>
            ${n.snippet ? `<div class="search-result-snippet">${esc(n.snippet)}</div>` : ''}
          </div>
          <span class="search-result-meta">${esc(n.host_identifier)} &middot; ${esc(n.assessment_name)}</span>
        </div>`).join('');
      html += '</div>';
    }

    if (data.commands?.length) {
      html += `<div class="search-section"><div class="search-section-title">Commands</div>`;
      html += data.commands.map(cmd =>
        `<div class="search-result-row" data-action="goto-commands">
          <span class="search-result-title">${esc(cmd.name)}</span>
          <span class="search-result-meta">${esc(cmd.os)}</span>
        </div>`).join('');
      html += '</div>';
    }

    container.innerHTML = html;

    // Wire click navigation
    $$('.search-result-row').forEach(row => {
      row.addEventListener('click', async () => {
        const action = row.dataset.action;
        const id = row.dataset.id;
        const eid = row.dataset.eid;
        try {
          if (action === 'goto-assessment') {
            const eng = await fetchAssessment(id);
            renderAssessmentOverview(eng);
          } else if (action === 'goto-host') {
            await gotoHostFromSearch(eid, id);
          } else if (action === 'goto-host-creds') {
            await gotoHostFromSearch(eid, id, 'credentials');
          } else if (action === 'goto-host-notes') {
            await gotoHostFromSearch(eid, id, 'notes');
          } else if (action === 'goto-commands') {
            renderCommands();
          }
        } catch (e) { alert('Navigation failed: ' + e.message); }
      });
    });
  } catch (e) {
    if (container) container.innerHTML = `<p style="color:#ef4444">Search failed: ${esc(e.message)}</p>`;
  }
}

/* ==========================================================
   Admin – User List
   ========================================================== */
async function renderAdminUsers() {
  hideSidebar();
  currentAssessment = null;
  currentHostId = null;
  showNavButtons();
  setUserEmail();

  const app = $('#app');
  app.innerHTML = `
    <div class="page-header">
      <div class="page-header-left">
        <div class="page-breadcrumb">Dashboard</div>
        <h2 class="page-title">Registered Users</h2>
      </div>
    </div>
    <div id="admin-users-wrap" style="padding:1.5rem 0">
      <p style="color:var(--muted)">Loading\u2026</p>
    </div>`;

  try {
    const data = await apiGet('/admin/users');
    const wrap = $('#admin-users-wrap');
    if (!data.users || data.users.length === 0) {
      wrap.innerHTML = `<p style="color:var(--muted)">No users found.</p>`;
      return;
    }
    wrap.innerHTML = `
      <p style="margin-bottom:1rem;color:var(--muted)">
        <strong style="color:var(--fg)">${data.count}</strong> registered user${data.count === 1 ? '' : 's'}
      </p>
      <table class="admin-users-table">
        <thead>
          <tr><th>#</th><th>Email</th><th>Role</th><th>2FA</th><th>Registered</th></tr>
        </thead>
        <tbody>
          ${data.users.map((u, i) => `
            <tr>
              <td style="color:var(--muted)">${i + 1}</td>
              <td>${esc(u.email)}</td>
              <td><span class="role-badge role-${esc(u.role)}">${esc(u.role)}</span></td>
              <td>${u.totp_enabled
                ? '<span class="totp-badge totp-badge-on" style="font-size:0.72rem;padding:2px 8px">On</span>'
                : '<span class="totp-badge totp-badge-off" style="font-size:0.72rem;padding:2px 8px">Off</span>'}</td>
              <td style="color:var(--muted)">${esc(u.created_at)}</td>
            </tr>`).join('')}
        </tbody>
      </table>`;
  } catch (e) {
    $('#admin-users-wrap').innerHTML = `<p style="color:#ef4444">Error: ${e.message}</p>`;
  }
}

/* ==========================================================
   Init
   ========================================================== */
document.addEventListener('DOMContentLoaded', () => {
  // Apply saved theme and font size before first render to avoid flash
  applyTheme(localStorage.getItem('theme') || 'dark');
  applyFontSize(getFontSize());

  setupGlobalDelegation();
  setupUnsavedWorkGuards();

  // Close modal on backdrop click (only if the modal allows it)
  $('#modal').addEventListener('click', ev => {
    if (ev.target === $('#modal') && modalCloseOnBackdrop) hideModal();
  });

  $('#nav-home').addEventListener('click', () => {
    if (isTokenValid()) renderDashboard();
    else if (signedIn) logout(); // the session has ended: sign in again (unsaved text is kept)
    else showLoginForm();
  });
  $('#btn-logout').addEventListener('click', ev => { ev.preventDefault(); $('#user-dropdown').style.display = 'none'; logoutClicked(); });
  $('#btn-search').addEventListener('click', ev => { ev.preventDefault(); renderSearch(); });
  $('#btn-commands').addEventListener('click', ev => { ev.preventDefault(); renderCommands(); });
  $('#btn-users').addEventListener('click', ev => { ev.preventDefault(); renderAdminUsers(); });
  $('#btn-settings').addEventListener('click', ev => { ev.preventDefault(); $('#user-dropdown').style.display = 'none'; renderSettings(); });

  // User menu dropdown toggle
  const userMenuBtn = $('#user-menu-btn');
  const userDropdown = $('#user-dropdown');
  userMenuBtn.addEventListener('click', e => {
    e.stopPropagation();
    const isOpen = userDropdown.style.display !== 'none';
    userDropdown.style.display = isOpen ? 'none' : 'block';
    userMenuBtn.setAttribute('aria-expanded', String(!isOpen));
  });
  document.addEventListener('click', () => {
    userDropdown.style.display = 'none';
    userMenuBtn.setAttribute('aria-expanded', 'false');
  });
  userDropdown.addEventListener('click', e => e.stopPropagation());

  // Handle password reset links. The token is in the fragment
  // (#reset_token=...), which never reaches the server; links sent before
  // that change carry it in the query string (?reset_token=...).
  const resetTokenFromURL = () =>
    new URLSearchParams(window.location.hash.slice(1)).get('reset_token') ||
    new URLSearchParams(window.location.search).get('reset_token');
  // A link opened in a tab already showing the app only changes the
  // fragment: load the page again so it opens the reset form.
  window.addEventListener('hashchange', () => { if (resetTokenFromURL()) location.reload(); });
  const resetToken = resetTokenFromURL();
  if (resetToken) {
    showResetPasswordForm(resetToken);
    return;
  }

  if (isTokenValid()) {
    signedIn = true; // setUserEmail() then records which account it is
    renderDashboard();
  } else {
    showLoginForm();
  }
});
