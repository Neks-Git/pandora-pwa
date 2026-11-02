import { argon2id } from 'hash-wasm';
import { xchacha20poly1305 } from '@noble/ciphers/chacha';

// ---------------------------------------------------------------------------
// Constants (must match pandora-core/src/vault.rs)
// ---------------------------------------------------------------------------
const MAGIC = 'PANDORA1';
const HEADER_LEN = 60;          // 8 magic + 4 m + 4 t + 4 p + 16 salt + 24 nonce
const SALT_LEN = 16;
const NONCE_LEN = 24;
const MAX_M_COST_KIB = 2 * 1024 * 1024;
const MAX_T_COST = 50;
const MAX_P_COST = 16;

// ---------------------------------------------------------------------------
// State
// ---------------------------------------------------------------------------
const state = {
  vaultBytes: null,   // Uint8Array of the encrypted file
  vault: null,        // decrypted { entries: [...] }
};

// ---------------------------------------------------------------------------
// Small utilities
// ---------------------------------------------------------------------------
const $ = (sel) => document.querySelector(sel);

function toast(msg) {
  const t = $('#toast');
  t.textContent = msg;
  t.classList.add('show');
  clearTimeout(toast._t);
  toast._t = setTimeout(() => t.classList.remove('show'), 2000);
}

async function copyText(text, label) {
  try {
    await navigator.clipboard.writeText(text);
    toast(`${label} copied`);
  } catch (e) {
    toast('copy failed');
  }
}

function fmtDate(unix) {
  return new Date(unix * 1000).toISOString().slice(0, 10);
}

function escapeHtml(s) {
  const d = document.createElement('div');
  d.textContent = s;
  return d.innerHTML;
}

// ---------------------------------------------------------------------------
// Vault format
//   magic(8) | m_cost u32 LE | t_cost u32 LE | p_cost u32 LE
//   | salt(16) | nonce(24) | ciphertext+tag
// The 60-byte header is the AEAD associated data.
// ---------------------------------------------------------------------------
function parseHeader(bytes) {
  if (bytes.byteLength < HEADER_LEN + 16) {
    throw new Error('file is too small to be a Pandora vault');
  }
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

  // Derive the 32-byte key exactly the same way the Rust app did.
  const pwBytes = new TextEncoder().encode(password);
  const key = await argon2id({
    password: pwBytes,
    salt: h.salt,
    parallelism: h.pCost,
    iterations: h.tCost,
    memorySize: h.mCost,     // KiB
    hashLength: 32,
    outputType: 'binary',
  });

  // XChaCha20-Poly1305 with the header as AAD.
  let plaintext;
  try {
    const cipher = xchacha20poly1305(key, h.nonce, h.header);
    plaintext = cipher.decrypt(h.ct);
  } catch {
    throw new Error('wrong master password, or file is corrupted');
  }

  const vault = JSON.parse(new TextDecoder().decode(plaintext));
  if (!vault || !Array.isArray(vault.entries)) {
    throw new Error('vault is malformed');
  }
  return vault;
}

// ---------------------------------------------------------------------------
// View 1 — pick the file
// ---------------------------------------------------------------------------
function renderPickFile() {
  $('#app').innerHTML = `
    <div class="card">
      <div class="caps">Vault file</div>
      <input type="file" id="file" accept=".pandora,application/octet-stream">
      <div class="hint">Pick <code>vault.pandora</code> from your PC. It's already encrypted — safe to transfer via email, AirDrop, cloud drive, whatever.</div>
      <div id="err" class="err"></div>
    </div>
  `;
  $('#file').addEventListener('change', async (ev) => {
    const f = ev.target.files?.[0];
    if (!f) return;
    const buf = new Uint8Array(await f.arrayBuffer());
    try {
      parseHeader(buf);            // validate before we bother the user for a password
      state.vaultBytes = buf;
      renderPassword();
    } catch (e) {
      $('#err').textContent = e.message;
    }
  });
}

// ---------------------------------------------------------------------------
// View 2 — master password
// ---------------------------------------------------------------------------
function renderPassword() {
  $('#app').innerHTML = `
    <div class="card">
      <div class="caps">Master password</div>
      <div class="row">
        <input type="password" id="pw" class="grow" autocomplete="off" autocorrect="off" autocapitalize="off" spellcheck="false">
        <button class="ghost" id="toggle">SHOW</button>
      </div>
      <div class="row" style="margin-top: 8px;">
        <button class="primary grow" id="unlock">Unlock</button>
        <button class="ghost" id="back">Change file</button>
      </div>
      <div id="err" class="err"></div>
      <div id="busy" class="hint" style="display:none;">
        <span class="spinner"></span>Deriving key… this is slow on purpose (10–30 s on a phone)
      </div>
    </div>
  `;

  const pw = $('#pw');
  const toggle = $('#toggle');
  const unlock = $('#unlock');
  const busy = $('#busy');
  const err = $('#err');

  setTimeout(() => pw.focus(), 50);

  toggle.onclick = () => {
    const isPw = pw.type === 'password';
    pw.type = isPw ? 'text' : 'password';
    toggle.textContent = isPw ? 'HIDE' : 'SHOW';
  };

  const go = async () => {
    if (!pw.value) return;
    err.textContent = '';
    busy.style.display = 'block';
    unlock.disabled = true;
    pw.disabled = true;
    // Yield to let the spinner paint before Argon2 blocks the main thread.
    await new Promise(r => setTimeout(r, 30));
    try {
      state.vault = await decryptVault(state.vaultBytes, pw.value);
      pw.value = '';
      renderVault();
    } catch (e) {
      err.textContent = e.message;
      busy.style.display = 'none';
      unlock.disabled = false;
      pw.disabled = false;
      pw.focus();
    }
  };

  unlock.onclick = go;
  pw.addEventListener('keydown', (e) => { if (e.key === 'Enter') go(); });
  $('#back').onclick = () => {
    state.vaultBytes = null;
    state.vault = null;
    renderPickFile();
  };
}

// ---------------------------------------------------------------------------
// View 3 — the vault list
// ---------------------------------------------------------------------------
function renderVault() {
  $('#app').innerHTML = `
    <div class="card">
      <div class="row">
        <input type="text" id="search" class="grow" placeholder="search…"
               autocorrect="off" autocapitalize="off" spellcheck="false">
        <button class="ghost" id="lock">Lock</button>
      </div>
      <div id="list" class="entries" style="margin-top: 12px;"></div>
      <div class="hint" id="count"></div>
    </div>
  `;
  $('#search').addEventListener('input', (e) => renderList(e.target.value));
  $('#lock').onclick = () => {
    state.vault = null;
    state.vaultBytes = null;
    renderPickFile();
  };
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
  ).sort((a, b) =>
    (a.label || '').toLowerCase().localeCompare((b.label || '').toLowerCase())
  );

  const list = $('#list');
  list.innerHTML = '';

  if (entries.length === 0) {
    list.innerHTML =
      `<div class="hint" style="text-align:center;padding:20px;">` +
      (all.length === 0 ? 'NO ENTRIES YET' : 'NO MATCHES') +
      `</div>`;
  } else {
    for (const e of entries) {
      const div = document.createElement('div');
      div.className = 'entry';
      const label = e.label || '(untitled)';
      const sub = e.username || e.email || '';
      div.innerHTML = `<div class="label"></div><div class="sub2"></div>`;
      div.querySelector('.label').textContent = label;
      div.querySelector('.sub2').textContent = sub;
      div.onclick = () => renderDetail(e);
      list.appendChild(div);
    }
  }
  $('#count').textContent = `${entries.length} of ${all.length} entries`;
}

// ---------------------------------------------------------------------------
// Detail overlay
// ---------------------------------------------------------------------------
function renderDetail(e) {
  const overlay = document.createElement('div');
  overlay.className = 'detail-overlay';
  const close = () => overlay.remove();
  overlay.onclick = (ev) => { if (ev.target === overlay) close(); };

  const title = e.label || '(untitled)';
  overlay.innerHTML = `
    <div class="detail">
      <div class="row" style="margin-bottom: 16px;">
        <div class="grow" style="font-size: 18px; font-weight: bold;">${escapeHtml(title)}</div>
        <button class="ghost" id="close">CLOSE</button>
      </div>
      <div id="fields"></div>
      <div class="hint" style="margin-top: 16px;">
        CREATED ${fmtDate(e.created)} · MODIFIED ${fmtDate(e.modified)}
      </div>
    </div>
  `;
  overlay.querySelector('#close').onclick = close;

  const fields = overlay.querySelector('#fields');

  const addField = (label, value, mask) => {
    if (!value) return;
    const div = document.createElement('div');
    div.className = 'field';

    const lbl = document.createElement('div');
    lbl.className = 'lbl';
    lbl.textContent = label.toUpperCase();

    const val = document.createElement('div');
    val.className = 'val';

    const hint = document.createElement('div');
    hint.className = 'copy-hint';
    hint.textContent = 'TAP TO COPY';

    let revealed = false;
    const masked = '•'.repeat(Math.min(value.length, 24));
    val.textContent = mask ? masked : value;

    div.appendChild(lbl);
    div.appendChild(val);
    div.appendChild(hint);

    if (mask) {
      const eye = document.createElement('button');
      eye.className = 'ghost';
      eye.textContent = 'SHOW';
      eye.style.position = 'absolute';
      eye.style.bottom = '6px';
      eye.style.right = '6px';
      eye.onclick = (ev) => {
        ev.stopPropagation();
        revealed = !revealed;
        val.textContent = revealed ? value : masked;
        eye.textContent = revealed ? 'HIDE' : 'SHOW';
      };
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

// ---------------------------------------------------------------------------
// Boot
// ---------------------------------------------------------------------------
renderPickFile();