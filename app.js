import { argon2id } from 'hash-wasm';
import { xchacha20poly1305 } from '@noble/ciphers/chacha';

const MAGIC = 'PANDORA1';
const HEADER_LEN = 60;
const SALT_LEN = 16;
const MAX_M_COST_KIB = 2 * 1024 * 1024;
const MAX_T_COST = 50;
const MAX_P_COST = 16;
const CACHE_KEY = 'pandora:vault-cache';     // encrypted bytes, base64
const CACHE_TIME_KEY = 'pandora:vault-cached-at';

const state = { vaultBytes: null, vault: null };
const $ = (sel) => document.querySelector(sel);

function saveVaultToCache(bytes) {
  try {
    let binary = '';
    for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    localStorage.setItem(CACHE_KEY, btoa(binary));
    localStorage.setItem(CACHE_TIME_KEY, String(Date.now()));
  } catch (e) {
    console.warn('cache save failed:', e);
  }
}

function downloadVaultFile(bytes) {
  const blob = new Blob([bytes], { type: 'application/octet-stream' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'vault.pandora';
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  setTimeout(() => URL.revokeObjectURL(url), 1000);
  toast('vault.pandora downloaded');
}
function loadVaultFromCache() {
  const b64 = localStorage.getItem(CACHE_KEY);
  if (!b64) return null;
  try {
    const binary = atob(b64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  } catch {
    return null;
  }
}

function clearVaultCache() {
  localStorage.removeItem(CACHE_KEY);
  localStorage.removeItem(CACHE_TIME_KEY);
}

function cachedAt() {
  const t = localStorage.getItem(CACHE_TIME_KEY);
  return t ? new Date(Number(t)) : null;
}

function toast(msg) {
  const t = $('#toast');
  t.textContent = msg;
  t.classList.add('show');
  clearTimeout(toast._t);
  toast._t = setTimeout(() => t.classList.remove('show'), 2000);
}

async function copyText(text, label) {
  try { await navigator.clipboard.writeText(text); toast(label + ' copied'); }
  catch { toast('copy failed'); }
}

function fmtDate(unix) { return new Date(unix * 1000).toISOString().slice(0, 10); }
function escapeHtml(s) { const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }

function parseHeader(bytes) {
  if (bytes.byteLength < HEADER_LEN + 16) throw new Error('file is too small to be a Pandora vault');
  const magic = new TextDecoder().decode(bytes.subarray(0, 8));
  if (magic !== MAGIC) throw new Error('not a Pandora vault');
  const view = new DataView(bytes.buffer, bytes.byteOffset, bytes.byteLength);
  const mCost = view.getUint32(8, true);
  const tCost = view.getUint32(12, true);
  const pCost = view.getUint32(16, true);
  if (mCost > MAX_M_COST_KIB || tCost > MAX_T_COST || pCost > MAX_P_COST) {
    throw new Error('unreasonable KDF parameters in file');
  }
  return {
    mCost, tCost, pCost,
    salt:  bytes.subarray(20, 20 + SALT_LEN),
    nonce: bytes.subarray(20 + SALT_LEN, HEADER_LEN),
    header: bytes.subarray(0, HEADER_LEN),
    ct:    bytes.subarray(HEADER_LEN),
  };
}

async function decryptVault(bytes, password) {
  const h = parseHeader(bytes);
  const pwBytes = new TextEncoder().encode(password);
  const key = await argon2id({
    password: pwBytes, salt: h.salt,
    parallelism: h.pCost, iterations: h.tCost,
    memorySize: h.mCost, hashLength: 32, outputType: 'binary',
  });
  let plaintext;
  try {
    const cipher = xchacha20poly1305(key, h.nonce, h.header);
    plaintext = cipher.decrypt(h.ct);
  } catch {
    throw new Error('wrong master password, or file is corrupted');
  }
  const vault = JSON.parse(new TextDecoder().decode(plaintext));
  if (!vault || !Array.isArray(vault.entries)) throw new Error('vault is malformed');
  return vault;
}
async function fetchVaultFromRelay(id, token, expectedHash) {
  const relayBaseRaw = document.querySelector('meta[name="pandora-relay"]')?.content || '';
  const relayBase = relayBaseRaw.replace(/\/+$/, '');
  if (!relayBase) {
    $('#app').innerHTML = '<div class="card"><div class="err">This PWA has no relay configured. Set the meta tag in index.html.</div></div>';
    return;
  }

  $('#app').innerHTML =
    '<div class="card"><div class="caps">Fetching vault</div>' +
    '<div id="status" class="hint"><span class="spinner"></span> Downloading encrypted vault…</div>' +
    '<div id="err" class="err"></div></div>';

  let buf = null;
  try {
    const url = relayBase + '/fetch/' + encodeURIComponent(id);
    console.log('[pandora] fetching', url);
    const res = await fetch(url, {
      headers: { 'X-Pandora-Token': token },
    });
    console.log('[pandora] fetch status', res.status);
    if (!res.ok) throw new Error('relay returned ' + res.status);
    buf = new Uint8Array(await res.arrayBuffer());
    console.log('[pandora] got bytes', buf.length);
    if (expectedHash) {
      const digest = await crypto.subtle.digest('SHA-256', buf);
      const got = Array.from(new Uint8Array(digest), b => b.toString(16).padStart(2, '0')).join('');
      console.log('[pandora] hash match?', got === expectedHash);
      if (got !== expectedHash) throw new Error('vault hash mismatch — connection may have been tampered with');
    }
    state.vaultBytes = buf;
    saveVaultToCache(buf);
    history.replaceState(null, '', window.location.pathname);
    renderPassword();
  } catch (e) {
    const diag = [
      'ERROR: ' + (e && e.message ? e.message : String(e)),
      'NAME: ' + (e && e.name ? e.name : '(none)'),
      'STACK: ' + (e && e.stack ? String(e.stack).slice(0, 400) : '(none)'),
      'FETCHED_BYTES: ' + (buf ? buf.length : 'null'),
      'VAULT_BYTES: ' + (state.vaultBytes ? state.vaultBytes.length : 'null'),
      'RELAY: ' + relayBase,
      'ID: ' + id,
      'URL_FRAG: ' + window.location.hash.slice(0, 80),
    ].join('\n');
    console.error('[pandora] fetch failed', e, diag);
    const status = $('#status');
    const err = $('#err');
    if (status) status.textContent = 'Failed.';
    if (err) {
      err.style.whiteSpace = 'pre-wrap';
      err.style.fontSize = '10px';
      err.style.fontFamily = 'monospace';
      err.textContent = diag;
    }
  }
}
async function boot() {
  if ('serviceWorker' in navigator) {
    navigator.serviceWorker.register('./sw.js').catch(() => {});
  }
  const h = new URLSearchParams(window.location.hash.slice(1));
  const token = h.get('t');
  const hash  = h.get('h');
  const pc    = h.get('pc');
  const relay = h.get('r');    // NEW: relay id

  if (relay && token) {
    await fetchVaultFromRelay(relay, token, hash);
  } else if (token && pc) {
    await fetchVault(`https://${pc}/vault?t=${encodeURIComponent(token)}`, hash);
  } else {
    renderEntry();
  }
}

async function fetchVault(url, expectedHash) {
  $('#app').innerHTML =
    '<div class="card"><div class="caps">Fetching from PC</div>' +
    '<div id="status" class="hint"><span class="spinner"></span> Downloading encrypted vault…</div>' +
    '<div id="err" class="err"></div></div>';
  try {
    const res = await fetch(url);
    if (!res.ok) throw new Error('server returned ' + res.status);
    const buf = new Uint8Array(await res.arrayBuffer());
    if (expectedHash) {
      const digest = await crypto.subtle.digest('SHA-256', buf);
      const got = Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, '0')).join('');
      if (got !== expectedHash) throw new Error('vault hash mismatch — connection may have been tampered with');
    }
    state.vaultBytes = buf;
    saveVaultToCache(buf);
    history.replaceState(null, '', window.location.pathname);
    renderPassword();
  } catch (e) {
    $('#status').textContent = 'Failed.';
    $('#err').textContent = e.message;
  }
}

function renderEntry() {
  const cached = loadVaultFromCache();
  const when = cachedAt();
  const whenStr = when ? when.toLocaleString() : '';

  let html = '<div class="card">';
  if (cached) {
    html +=
      '<div class="caps">Cached vault</div>' +
      '<div class="hint" style="margin-bottom:8px">Last synced from PC: ' + whenStr +
      ' · ' + cached.length + ' bytes</div>' +
      '<div class="row" style="margin-bottom:8px">' +
      '<button class="primary grow" id="use-cache">Open cached vault</button>' +
      '</div>' +
      '<div class="row" style="margin-bottom:12px">' +
      '<button class="ghost grow" id="download-cache">Download .pandora file</button>' +
      '<button class="ghost" id="drop-cache">Forget</button>' +
      '</div>' +
      '<div class="caps" style="margin-top:16px">Sync fresh from PC</div>' +
      '<div class="hint" style="margin-bottom:8px">On PC: click Share to phone → scan QR.</div>';
  
  } else {
    html += '<div class="caps">No vault yet</div>' +
      '<div class="hint" style="margin-bottom:12px">On PC: click Share to phone → scan QR. ' +
      'Or load a .pandora file manually below.</div>';
  }
  html +=
    '<div class="caps" style="margin-top:16px">Or open a file</div>' +
    '<input type="file" id="file" accept=".pandora,application/octet-stream">' +
    '<div id="err" class="err"></div>' +
    '</div>';

  $('#app').innerHTML = html;

  if (cached) {
    $('#use-cache').onclick = () => {
      try {
        parseHeader(cached);
        state.vaultBytes = cached;
        renderPassword();
      } catch (e) {
        $('#err').textContent = 'cached vault is corrupt: ' + e.message;
      }
    };
    $('#download-cache').onclick = () => downloadVaultFile(cached);
    $('#drop-cache').onclick = () => {
      clearVaultCache();
      renderEntry();
    };
  }

  $('#file').addEventListener('change', async (ev) => {
    const f = ev.target.files && ev.target.files[0];
    if (!f) return;
    const buf = new Uint8Array(await f.arrayBuffer());
    try {
      parseHeader(buf);
      state.vaultBytes = buf;
      saveVaultToCache(buf);
      renderPassword();
    } catch (e) {
      $('#err').textContent = e.message;
    }
  });
}

function renderPassword() {
  $('#app').innerHTML =
    '<div class="card"><div class="caps">Master password</div>' +
    '<div class="row"><input type="password" id="pw" class="grow" autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false">' +
    '<button class="ghost" id="toggle">SHOW</button></div>' +
    '<div class="row" style="margin-top:8px"><button class="primary grow" id="unlock">Unlock</button>' +
    '<button class="ghost" id="back">Change file</button></div>' +
    '<div id="err" class="err"></div>' +
    '<div id="busy" class="hint" style="display:none"><span class="spinner"></span>Deriving key… 10–30 s on a phone (intentionally slow)</div></div>';
  const pw = $('#pw'), toggle = $('#toggle'), unlock = $('#unlock'), busy = $('#busy'), err = $('#err');
  setTimeout(() => pw.focus(), 50);
  toggle.onclick = () => { const p = pw.type === 'password'; pw.type = p ? 'text' : 'password'; toggle.textContent = p ? 'HIDE' : 'SHOW'; };
  const go = async () => {
    if (!pw.value) return;
    err.textContent = ''; busy.style.display = 'block'; unlock.disabled = true; pw.disabled = true;
    await new Promise(r => setTimeout(r, 30));
    try {
      state.vault = await decryptVault(state.vaultBytes, pw.value);
      pw.value = ''; renderVault();
    } catch (e) {
      err.textContent = e.message; busy.style.display = 'none'; unlock.disabled = false; pw.disabled = false; pw.focus();
    }
  };
  unlock.onclick = go;
  pw.addEventListener('keydown', (e) => { if (e.key === 'Enter') go(); });
  $('#back').onclick = () => { state.vaultBytes = null; state.vault = null; renderEntry(); };
}

function renderVault() {
  $('#app').innerHTML =
    '<div class="card"><div class="row"><input type="text" id="search" class="grow" placeholder="search…" autocorrect="off" autocapitalize="off" spellcheck="false">' +
    '<button class="ghost" id="lock">Lock</button></div>' +
    '<div id="list" class="entries" style="margin-top:12px"></div>' +
    '<div class="hint" id="count"></div></div>';
  $('#search').addEventListener('input', (e) => renderList(e.target.value));
  $('#lock').onclick = () => { state.vault = null; state.vaultBytes = null; renderEntry(); };
  renderList('');
}

function renderList(query) {
  const all = state.vault.entries;
  const n = query.trim().toLowerCase();
  const entries = all.filter((e) =>
    !n ||
    (e.label    || '').toLowerCase().includes(n) ||
    (e.username || '').toLowerCase().includes(n) ||
    (e.email    || '').toLowerCase().includes(n) ||
    (e.url      || '').toLowerCase().includes(n)
  ).sort((a, b) => (a.label || '').toLowerCase().localeCompare((b.label || '').toLowerCase()));

  const list = $('#list'); list.innerHTML = '';
  if (entries.length === 0) {
    list.innerHTML = '<div class="hint" style="text-align:center;padding:20px">' +
      (all.length === 0 ? 'NO ENTRIES YET' : 'NO MATCHES') + '</div>';
  } else {
    for (const e of entries) {
      const div = document.createElement('div');
      div.className = 'entry';
      div.innerHTML = '<div class="label"></div><div class="sub2"></div>';
      div.querySelector('.label').textContent = e.label || '(untitled)';
      div.querySelector('.sub2').textContent = e.username || e.email || '';
      div.onclick = () => renderDetail(e);
      list.appendChild(div);
    }
  }
  $('#count').textContent = entries.length + ' of ' + all.length + ' entries';
}

function renderDetail(e) {
  const overlay = document.createElement('div');
  overlay.className = 'detail-overlay';
  const close = () => overlay.remove();
  overlay.onclick = (ev) => { if (ev.target === overlay) close(); };
  overlay.innerHTML =
    '<div class="detail"><div class="row" style="margin-bottom:16px">' +
    '<div class="grow" style="font-size:18px;font-weight:bold">' + escapeHtml(e.label || '(untitled)') + '</div>' +
    '<button class="ghost" id="close">CLOSE</button></div>' +
    '<div id="fields"></div>' +
    '<div class="hint" style="margin-top:16px">CREATED ' + fmtDate(e.created) + ' · MODIFIED ' + fmtDate(e.modified) + '</div></div>';
  overlay.querySelector('#close').onclick = close;
  const fields = overlay.querySelector('#fields');
  const addField = (label, value, mask) => {
    if (!value) return;
    const div = document.createElement('div');
    div.className = 'field';
    const lbl = document.createElement('div'); lbl.className = 'lbl'; lbl.textContent = label.toUpperCase();
    const val = document.createElement('div'); val.className = 'val';
    const hint = document.createElement('div'); hint.className = 'copy-hint'; hint.textContent = 'TAP TO COPY';
    let revealed = false;
    const masked = '•'.repeat(Math.min(value.length, 24));
    val.textContent = mask ? masked : value;
    div.appendChild(lbl); div.appendChild(val); div.appendChild(hint);
    if (mask) {
      const eye = document.createElement('button');
      eye.className = 'ghost'; eye.textContent = 'SHOW';
      eye.style.position = 'absolute'; eye.style.bottom = '6px'; eye.style.right = '6px';
      eye.onclick = (ev) => { ev.stopPropagation(); revealed = !revealed; val.textContent = revealed ? value : masked; eye.textContent = revealed ? 'HIDE' : 'SHOW'; };
      div.appendChild(eye);
    }
    div.onclick = () => copyText(value, label);
    fields.appendChild(div);
  };
  addField('password', e.password, true);
  addField('username', e.username, false);
  addField('email', e.email, false);
  addField('url', e.url, false);
  if (Array.isArray(e.security_questions)) {
    for (const q of e.security_questions) {
      addField('security question', q.question, false);
      addField('security answer', q.answer, false);
    }
  }
  addField('notes', e.notes, false);
  document.body.appendChild(overlay);
}

boot();