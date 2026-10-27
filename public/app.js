const $ = (s) => document.querySelector(s);
let token = localStorage.getItem('token') || null;
let me = null, ws = null, currentPeer = null;
let identity = null;
let masterBits = null;     // 256 bits из PBKDF2, для вывода ключей
let historyKey = null;     // AES-GCM для IndexedDB
let sessionPassword = null;
const history = {};
let historyLoaded = false;

const backBtns = [document.getElementById('back-btn'), document.getElementById('back-btn2')];
const wsStatus = document.getElementById('ws-status');
const verifyBtn = document.getElementById('verify-btn');

const b64 = { enc: (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))), dec: (s) => Uint8Array.from(atob(s), c => c.charCodeAt(0)) };

function uuid() {
  if (crypto && typeof crypto.randomUUID === 'function') return crypto.randomUUID();
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    return (c === 'x' ? r : ((r & 0x3) | 0x8)).toString(16);
  });
}

// ---------- Crypto ----------
async function deriveMaster(password, salt) {
  const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  return crypto.subtle.deriveBits({ name: 'PBKDF2', salt, iterations: 200000, hash: 'SHA-256' }, base, 256);
}
async function deriveAes(masterBits, info) {
  const mk = await crypto.subtle.importKey('raw', masterBits, 'HKDF', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'HKDF', hash: 'SHA-256', salt: new Uint8Array(0), info: new TextEncoder().encode(info) },
    mk, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
  );
}

async function encryptPrivateKey(privateKey, masterBits) {
  const kek = await deriveAes(masterBits, 'minichat-identity');
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const raw = await crypto.subtle.exportKey('pkcs8', privateKey);
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, kek, raw);
  return { iv: b64.enc(iv), ct: b64.enc(ct) };
}
async function decryptPrivateKey(enc, masterBits) {
  const kek = await deriveAes(masterBits, 'minichat-identity');
  const raw = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64.dec(enc.iv) }, kek, b64.dec(enc.ct));
  return crypto.subtle.importKey('pkcs8', raw, { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveKey', 'deriveBits']);
}
async function encryptHistoryText(text) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, historyKey, new TextEncoder().encode(text));
  return { iv: b64.enc(iv), ct: b64.enc(ct) };
}
async function decryptHistoryText(ivB64, ctB64) {
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64.dec(ivB64) }, historyKey, b64.dec(ctB64));
  return new TextDecoder().decode(pt);
}

async function createIdentity(master) {
  const kp = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']);
  const publicJwk = await crypto.subtle.exportKey('jwk', kp.publicKey);
  const enc = await encryptPrivateKey(kp.privateKey, master);
  const privateKey = await crypto.subtle.importKey('pkcs8', await crypto.subtle.exportKey('pkcs8', kp.privateKey), { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveKey', 'deriveBits']);
  return { publicJwk, privateKey, encrypted: enc };
}

async function deriveSharedAesKey(peerPublicKey) {
  return crypto.subtle.deriveKey(
    { name: 'ECDH', public: peerPublicKey },
    identity.privateKey,
    { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
  );
}
async function encryptFor(peer, text) {
  const pk = await getPeerPublicKey(peer);
  const aes = await deriveSharedAesKey(pk);
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, aes, new TextEncoder().encode(text));
  return { iv: b64.enc(iv), ct: b64.enc(ct) };
}
async function decryptFrom(peer, ivB64, ctB64) {
  const pk = await getPeerPublicKey(peer);
  const aes = await deriveSharedAesKey(pk);
  const pt = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64.dec(ivB64) }, aes, b64.dec(ctB64));
  return new TextDecoder().decode(pt);
}

const peerKeyCache = new Map();
async function getPeerPublicKey(username) {
  if (peerKeyCache.has(username)) return peerKeyCache.get(username);
  const res = await fetch('/api/keys/' + encodeURIComponent(username), { headers: { Authorization: 'Bearer ' + token } });
  if (!res.ok) throw new Error('У пользователя ' + username + ' нет опубликованного ключа');
  const { publicKey } = await res.json();
  const key = await crypto.subtle.importKey('jwk', publicKey, { name: 'ECDH', namedCurve: 'P-256' }, false, []);
  peerKeyCache.set(username, key);
  return key;
}

// ---------- Safety Number ----------
async function computeSafetyNumber(myJwk, peerJwk) {
  const a = JSON.stringify(myJwk, Object.keys(myJwk).sort());
  const b = JSON.stringify(peerJwk, Object.keys(peerJwk).sort());
  const [f, s] = [a, b].sort();
  const data = new TextEncoder().encode(f + '|' + s);
  const hash = await crypto.subtle.digest('SHA-256', data);
  const bytes = new Uint8Array(hash);
  let code = '';
  for (let i = 0; i < 12; i++) {
    const n = (bytes[i * 2] << 8) | bytes[i * 2 + 1];
    code += String(n % 100000).padStart(5, '0');
    if (i < 11) code += ' ';
  }
  return code;
}

// ---------- IndexedDB ----------
const DB_NAME = 'minichat';
const DB_VERSION = 3;
const STORE_MSG = 'messages';
const STORE_IDENT = 'identity';
const STORE_VERIFIED = 'verified';
let dbPromise = null;

function openDB() {
  if (dbPromise) return dbPromise;
  dbPromise = new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE_MSG)) {
        const s = db.createObjectStore(STORE_MSG, { keyPath: 'id' });
        s.createIndex('user', 'user');
      }
      if (!db.objectStoreNames.contains(STORE_IDENT)) db.createObjectStore(STORE_IDENT, { keyPath: 'user' });
      if (!db.objectStoreNames.contains(STORE_VERIFIED)) db.createObjectStore(STORE_VERIFIED, { keyPath: 'peer' });
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
    req.onblocked = () => reject(new Error('IndexedDB blocked'));
  });
  return dbPromise;
}
async function idbPutMsg(rec) {
  try {
    const db = await openDB();
    return await new Promise((res, rej) => {
      const tx = db.transaction(STORE_MSG, 'readwrite');
      tx.objectStore(STORE_MSG).put(rec);
      tx.oncomplete = () => res(); tx.onerror = () => rej(tx.error);
    });
  } catch (e) { console.warn('[idbPutMsg]', e); }
}
async function idbGetAllMsgs() {
  const db = await openDB();
  return new Promise((res, rej) => {
    const tx = db.transaction(STORE_MSG, 'readonly');
    const req = tx.objectStore(STORE_MSG).getAll();
    req.onsuccess = () => res(req.result); req.onerror = () => rej(req.error);
  });
}
async function idbUpdateStatus(user, id, status) {
  try {
    const db = await openDB();
    await new Promise((res, rej) => {
      const tx = db.transaction(STORE_MSG, 'readwrite');
      const store = tx.objectStore(STORE_MSG);
      const get = store.get(id);
      get.onsuccess = () => { const rec = get.result; if (!rec || rec.user !== user) return; rec.status = status; store.put(rec); };
      tx.oncomplete = () => res(); tx.onerror = () => rej(tx.error);
    });
  } catch (e) { console.warn('[idbUpdateStatus]', e); }
}
async function idbClearAll(user) {
  const db = await openDB();
  return new Promise((res, rej) => {
    const tx = db.transaction(STORE_MSG, 'readwrite');
    const store = tx.objectStore(STORE_MSG);
    const req = store.openCursor();
    req.onsuccess = (ev) => { const c = ev.target.result; if (!c) return; if (c.value.user === user) c.delete(); c.continue(); };
    tx.oncomplete = () => res(); tx.onerror = () => rej(tx.error);
  });
}
async function idbGetIdentity(user) {
  const db = await openDB();
  return new Promise((res, rej) => {
    const tx = db.transaction(STORE_IDENT, 'readonly');
    const req = tx.objectStore(STORE_IDENT).get(user);
    req.onsuccess = () => res(req.result || null); req.onerror = () => rej(req.error);
  });
}
async function idbPutIdentity(rec) {
  const db = await openDB();
  return new Promise((res, rej) => {
    const tx = db.transaction(STORE_IDENT, 'readwrite');
    tx.objectStore(STORE_IDENT).put(rec);
    tx.oncomplete = () => res(); tx.onerror = () => rej(tx.error);
  });
}
async function idbGetVerified(peer) {
  const db = await openDB();
  return new Promise((res, rej) => {
    const tx = db.transaction(STORE_VERIFIED, 'readonly');
    const req = tx.objectStore(STORE_VERIFIED).get(peer);
    req.onsuccess = () => res(req.result || null); req.onerror = () => rej(req.error);
  });
}
async function idbPutVerified(rec) {
  const db = await openDB();
  return new Promise((res, rej) => {
    const tx = db.transaction(STORE_VERIFIED, 'readwrite');
    tx.objectStore(STORE_VERIFIED).put(rec);
    tx.oncomplete = () => res(); tx.onerror = () => rej(tx.error);
  });
}
async function idbGetPending(user) {
  const all = await idbGetAllMsgs();
  return all.filter(r => r.user === user && r.status === 'pending');
}

async function loadHistory() {
  if (historyLoaded || !me || !historyKey) return;
  try {
    const all = await idbGetAllMsgs();
    let n = 0;
    const ttl = Number(localStorage.getItem('historyTTL') || 0);
    const cutoff = ttl > 0 ? Date.now() - ttl : 0;
    for (const r of all) {
      if (r.user !== me) continue;
      if (cutoff && r.ts < cutoff) continue;
      let text;
      try { text = await decryptHistoryText(r.iv, r.ct); }
      catch (e) { text = '[не удалось расшифровать]'; }
      let status = r.status || null;
      if (status === 'sending') status = 'unknown';
      if (!history[r.peer]) history[r.peer] = [];
      if (history[r.peer].some(m => m.id === r.id)) continue;
      history[r.peer].push({ id: r.id, from: r.from, text, ts: r.ts, status, offline: r.offline, senderPubJwk: r.senderPubJwk });
      n++;
    }
    for (const p of Object.keys(history)) history[p].sort((a, b) => a.ts - b.ts);
    historyLoaded = true;
    console.log(`[minichat] restored ${n} encrypted messages for ${me}`);
  } catch (e) { console.error('[loadHistory]', e); }
}

// ---------- Auth UI ----------
document.querySelectorAll('.tab').forEach(t => {
  t.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach(x => x.classList.toggle('active', x === t));
    $('#login-form').classList.toggle('hidden', t.dataset.tab !== 'login');
    $('#register-form').classList.toggle('hidden', t.dataset.tab !== 'register');
  });
});

async function api(path, body, method = 'POST') {
  const headers = { 'Content-Type': 'application/json' };
  if (token) headers['Authorization'] = 'Bearer ' + token;
  const res = await fetch(path, { method, headers, body: body ? JSON.stringify(body) : undefined });
  const data = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(data.error || ('HTTP ' + res.status));
  return data;
}

$('#login-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  $('#auth-error').textContent = '';
  const f = e.target;
  const password = f.password.value;
  try {
    const d = await api('/api/login', { username: f.username.value.trim(), password });
    token = d.token; localStorage.setItem('token', token);
    sessionPassword = password;
    await enterChat();
  } catch (err) { $('#auth-error').textContent = err.message; }
});
$('#register-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  $('#auth-error').textContent = '';
  const f = e.target;
  const password = f.password.value;
  try {
    const d = await api('/api/register', { username: f.username.value.trim(), password, invite: f.invite.value.trim() });
    token = d.token; localStorage.setItem('token', token);
    sessionPassword = password;
    await enterChat();
  } catch (err) { $('#auth-error').textContent = err.message; }
});
$('#logout').addEventListener('click', () => {
  localStorage.removeItem('token'); localStorage.removeItem('lastPeer');
  if (ws) ws.close();
  location.reload();
});

// ---------- Unlock ----------
function askPassword(title) {
  return new Promise((resolve) => {
    $('#unlock-modal').classList.remove('hidden');
    if (title) $('#unlock-title').textContent = title;
    $('#unlock-password').value = '';
    $('#unlock-error').textContent = '';
    $('#unlock-password').focus();
    const submit = async () => {
      const pwd = $('#unlock-password').value;
      if (!pwd) return;
      try {
        await unlockWithPassword(pwd);
        $('#unlock-modal').classList.add('hidden');
        sessionPassword = pwd;
        resolve(true);
      } catch (e) {
        $('#unlock-error').textContent = 'Неверный пароль';
      }
    };
    $('#unlock-btn').onclick = submit;
    $('#unlock-password').onkeydown = (e) => { if (e.key === 'Enter') submit(); };
  });
}
async function unlockWithPassword(password) {
  const rec = await idbGetIdentity(me);
  if (!rec) throw new Error('no identity');
  masterBits = await deriveMaster(password, b64.dec(rec.salt));
  identity = { publicJwk: rec.publicJwk, privateKey: await decryptPrivateKey(rec.encrypted, masterBits) };
  historyKey = await deriveAes(masterBits, 'minichat-history');
}
async function ensureIdentity() {
  if (identity && historyKey) return;
  const rec = await idbGetIdentity(me);
  if (rec) {
    if (sessionPassword) {
      try { await unlockWithPassword(sessionPassword); return; } catch { sessionPassword = null; }
    }
    await askPassword('Расшифровка сообщений');
    return;
  }
  // Создание
  let pwd = sessionPassword;
  if (!pwd) {
    pwd = await new Promise((resolve) => {
      $('#unlock-modal').classList.remove('hidden');
      $('#unlock-title').textContent = 'Создание ключа шифрования';
      $('#unlock-password').value = '';
      $('#unlock-error').textContent = '';
      $('#unlock-password').focus();
      const submit = () => { const v = $('#unlock-password').value; if (v) { $('#unlock-modal').classList.add('hidden'); resolve(v); } };
      $('#unlock-btn').onclick = submit;
      $('#unlock-password').onkeydown = (e) => { if (e.key === 'Enter') submit(); };
    });
  }
  const salt = crypto.getRandomValues(new Uint8Array(16));
  masterBits = await deriveMaster(pwd, salt);
  historyKey = await deriveAes(masterBits, 'minichat-history');
  const { publicJwk, privateKey, encrypted } = await createIdentity(masterBits);
  await idbPutIdentity({ user: me, publicJwk, encrypted, salt: b64.enc(salt) });
  identity = { publicJwk, privateKey };
  await api('/api/keys', { publicKey: publicJwk });
  console.log('[minichat] new identity created');
}

// ---------- Navigation ----------
function showList() {
  currentPeer = null;
  document.body.classList.add('view-list');
  document.body.classList.remove('view-chat');
  document.querySelectorAll('#users li').forEach(li => li.classList.remove('active'));
  verifyBtn.classList.add('hidden');
}
async function selectPeer(u) {
  currentPeer = u;
  localStorage.setItem('lastPeer', u);
  $('#peer-name').textContent = u;
  $('#send-form').classList.remove('hidden');
  verifyBtn.classList.remove('hidden');
  document.querySelectorAll('#users li').forEach(li => li.classList.toggle('active', li.dataset.user === u));
  renderMessages();
  document.body.classList.remove('view-list');
  document.body.classList.add('view-chat');
  await refreshVerifyStatus();
}
backBtns.forEach(b => { if (b) b.addEventListener('click', showList); });
window.addEventListener('popstate', showList);

// ---------- Verify ----------
async function refreshVerifyStatus() {
  if (!currentPeer) return;
  const v = await idbGetVerified(currentPeer);
  verifyBtn.textContent = v && v.verified ? '🔓' : '🔑';
  verifyBtn.title = v && v.verified ? 'Проверен' : 'Не проверен';
}
verifyBtn.addEventListener('click', async () => {
  if (!currentPeer) return;
  try {
    const peerJwkRes = await fetch('/api/keys/' + encodeURIComponent(currentPeer), { headers: { Authorization: 'Bearer ' + token } });
    if (!peerJwkRes.ok) throw new Error('У собеседника нет ключа');
    const { publicKey: peerJwk } = await peerJwkRes.json();
    const code = await computeSafetyNumber(identity.publicJwk, peerJwk);
    $('#safety-number').textContent = code;
    $('#verify-modal').classList.remove('hidden');
    const v = await idbGetVerified(currentPeer);
    $('#verify-status').textContent = v && v.verified ? 'Статус: проверен' : 'Статус: не проверен';
    $('#confirm-verify').onclick = async () => {
      await idbPutVerified({ peer: currentPeer, safetyNumber: code, verifiedAt: Date.now() });
      $('#verify-modal').classList.add('hidden');
      await refreshVerifyStatus();
    };
  } catch (e) { alert(e.message); }
});
$('#close-verify').addEventListener('click', () => $('#verify-modal').classList.add('hidden'));

// ---------- WS ----------
function setWsStatus(state) {
  if (!wsStatus) return;
  wsStatus.classList.remove('online', 'offline', 'connecting');
  wsStatus.classList.add(state);
}
function connectWS() {
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  setWsStatus('connecting');
  ws = new WebSocket(`${proto}://${location.host}/ws?token=${encodeURIComponent(token)}`);
  ws.addEventListener('open', () => { setWsStatus('online'); flushPending(); });
  ws.addEventListener('close', () => { setWsStatus('offline'); if (token) setTimeout(connectWS, 2000); });
  ws.addEventListener('error', () => setWsStatus('offline'));
  ws.addEventListener('message', async (ev) => {
    let m; try { m = JSON.parse(ev.data); } catch { return; }
    if (m.type === 'msg') {
      let text = null;
      try { text = await decryptFrom(m.from, m.iv, m.ct); } catch { text = '[не удалось расшифровать]'; }
      pushMessage(m.from, { id: m.id || null, from: m.from, text, iv: m.iv, ct: m.ct, ts: m.ts, offline: m.offline || false, senderPubJwk: m.senderPubJwk });
      if (m.from === currentPeer) renderMessages();
    } else if (m.type === 'queued') { setStatus(m.to, m.id, 'queued'); if (m.to === currentPeer) renderMessages(); }
    else if (m.type === 'delivered') { setStatus(m.to, m.id, 'delivered'); if (m.to === currentPeer) renderMessages(); }
  });
}
async function flushPending() {
  if (!me || !identity || !ws || ws.readyState !== ws.OPEN) return;
  const pending = await idbGetPending(me);
  for (const r of pending) {
    if (!ws || ws.readyState !== ws.OPEN) break;
    ws.send(JSON.stringify({ type: 'msg', to: r.peer, id: r.id, iv: r.iv, ct: r.ct, senderPubJwk: identity.publicJwk }));
    setStatus(r.peer, r.id, 'sending');
  }
  if (pending.length) renderMessages();
}

// ---------- Users ----------
async function loadUsers() {
  const res = await fetch('/api/users', { headers: { Authorization: 'Bearer ' + token } });
  if (!res.ok) return;
  const users = await res.json();
  renderUserList(users);
  const last = localStorage.getItem('lastPeer');
  if (last && users.some(u => u.username === last)) selectPeer(last);
}
function renderUserList(users) {
  const ul = $('#users'); ul.innerHTML = '';
  for (const u of users) {
    const li = document.createElement('li');
    li.dataset.user = u.username;
    const s = document.createElement('span'); s.textContent = u.username; li.appendChild(s);
    if (!u.hasKey) { const w = document.createElement('span'); w.className = 'nokey'; w.textContent = 'нет ключа'; li.appendChild(w); }
    li.addEventListener('click', () => selectPeer(u.username));
    ul.appendChild(li);
  }
}

// ---------- Search ----------
$('#open-search').addEventListener('click', () => {
  $('#search-modal').classList.remove('hidden');
  $('#search-input').value = ''; $('#search-results').innerHTML = ''; $('#search-error').textContent = '';
  $('#search-input').focus();
});
$('#close-search').addEventListener('click', () => $('#search-modal').classList.add('hidden'));
let searchTimer = null;
$('#search-input').addEventListener('input', (e) => {
  clearTimeout(searchTimer);
  const q = e.target.value.trim();
  if (q.length < 2) { $('#search-results').innerHTML = ''; return; }
  searchTimer = setTimeout(async () => {
    try {
      const res = await fetch('/api/users/search?q=' + encodeURIComponent(q), { headers: { Authorization: 'Bearer ' + token } });
      if (!res.ok) return;
      const arr = await res.json();
      const ul = $('#search-results'); ul.innerHTML = '';
      for (const u of arr) {
        const li = document.createElement('li');
        li.className = 'invite-item';
        const s = document.createElement('span'); s.textContent = u.username; s.style.flex = '1'; li.appendChild(s);
        const btn = document.createElement('button'); btn.className = 'mini'; btn.textContent = 'Открыть';
        btn.addEventListener('click', () => { $('#search-modal').classList.add('hidden'); startChatWith(u.username); });
        li.appendChild(btn);
        ul.appendChild(li);
      }
    } catch (e) { $('#search-error').textContent = e.message; }
  }, 300);
});
async function startChatWith(username) {
  // Добавляем в список локально, открываем чат
  const ul = $('#users');
  if (![...ul.querySelectorAll('li')].some(li => li.dataset.user === username)) {
    const li = document.createElement('li');
    li.dataset.user = username;
    const s = document.createElement('span'); s.textContent = username; li.appendChild(s);
    li.addEventListener('click', () => selectPeer(username));
    ul.insertBefore(li, ul.firstChild);
  }
  await selectPeer(username);
}

// ---------- History ----------
function pushMessage(peer, msg) {
  if (!history[peer]) history[peer] = [];
  if (msg.id && history[peer].some(m => m.id === msg.id)) return;
  history[peer].push({ ...msg, text: msg.text != null ? msg.text : null });
  if (me && msg.id && msg.iv && msg.ct) {
    idbPutMsg({
      id: msg.id, user: me, peer,
      from: msg.from, iv: msg.iv, ct: msg.ct, ts: msg.ts,
      status: msg.status || null, offline: msg.offline || false,
      senderPubJwk: msg.senderPubJwk || null,
    });
  }
}
function setStatus(peer, id, status) {
  const arr = history[peer]; if (!arr || !id) return;
  for (const m of arr) if (m.id === id) { m.status = status; if (me) idbUpdateStatus(me, id, status); return; }
}
function renderMessages() {
  const box = $('#messages'); box.innerHTML = '';
  const icons = { pending: '⏳', sending: '·', queued: '⏳', delivered: '✓', failed: '✗', unknown: '?' };
  for (const m of (history[currentPeer] || [])) {
    const d = document.createElement('div');
    d.className = 'msg ' + (m.from === me ? 'out' : 'in') + (m.system ? ' system' : '');
    d.textContent = m.text != null ? m.text : '…';
    if (m.status && icons[m.status]) {
      const s = document.createElement('span'); s.className = 'msg-status ' + m.status; s.textContent = icons[m.status]; d.appendChild(s);
    }
    box.appendChild(d);
  }
  box.scrollTop = box.scrollHeight;
}

// ---------- Send ----------
$('#send-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const input = $('#text');
  const text = input.value.trim();
  if (!text) return;
  if (!currentPeer) { alert('Сначала выберите собеседника'); return; }
  if (!identity) { alert('Ключ шифрования не разблокирован'); return; }
  const id = uuid();
  const ts = Date.now();
  let enc;
  try { enc = await encryptFor(currentPeer, text); }
  catch (err) { alert('Не удалось зашифровать: ' + err.message); return; }
  if (ws && ws.readyState === ws.OPEN) {
    ws.send(JSON.stringify({ type: 'msg', to: currentPeer, id, iv: enc.iv, ct: enc.ct, senderPubJwk: identity.publicJwk }));
    pushMessage(currentPeer, { id, from: me, text, iv: enc.iv, ct: enc.ct, ts, status: 'sending', senderPubJwk: identity.publicJwk });
  } else {
    pushMessage(currentPeer, { id, from: me, text, iv: enc.iv, ct: enc.ct, ts, status: 'pending', senderPubJwk: identity.publicJwk });
    setWsStatus('offline');
  }
  renderMessages();
  input.value = ''; input.focus();
});

// ---------- Invites ----------
const invitesModal = $('#invites-modal');
$('#open-invites').addEventListener('click', () => { invitesModal.classList.remove('hidden'); loadInvites(); });
$('#close-invites').addEventListener('click', () => invitesModal.classList.add('hidden'));
invitesModal.addEventListener('click', (e) => { if (e.target === invitesModal) invitesModal.classList.add('hidden'); });
$('#new-invite').addEventListener('click', async () => {
  $('#invites-error').textContent = '';
  try { await api('/api/invites', {}); await loadInvites(); }
  catch (err) { $('#invites-error').textContent = err.message; }
});
async function loadInvites() {
  const res = await fetch('/api/invites', { headers: { Authorization: 'Bearer ' + token } });
  if (!res.ok) { $('#invites-error').textContent = 'не удалось загрузить'; return; }
  const data = await res.json();
  $('#invites-meta').textContent = `Активных: ${data.active} из ${data.limit} · всего: ${data.invites.length}`;
  const ul = $('#invites-list'); ul.innerHTML = '';
  if (data.invites.length === 0) { const li = document.createElement('li'); li.className = 'muted'; li.textContent = 'Пока нет кодов.'; ul.appendChild(li); return; }
  for (const inv of data.invites) {
    const li = document.createElement('li');
    li.className = 'invite-item' + (inv.used ? ' used' : '');
    const code = document.createElement('code'); code.textContent = inv.code; li.appendChild(code);
    if (inv.used) {
      const b = document.createElement('span'); b.className = 'badge'; b.textContent = inv.used_by ? `использован: ${inv.used_by}` : 'использован'; li.appendChild(b);
    } else {
      const copy = document.createElement('button'); copy.className = 'mini'; copy.textContent = 'Скопировать';
      copy.addEventListener('click', async () => {
        const link = `${location.origin}/?invite=${inv.code}`;
        try { await navigator.clipboard.writeText(link); copy.textContent = 'Скопировано ✓'; setTimeout(() => copy.textContent = 'Скопировать', 1500); }
        catch { prompt('Скопируйте:', link); }
      });
      li.appendChild(copy);
      const del = document.createElement('button'); del.className = 'mini danger'; del.textContent = 'Удалить';
      del.addEventListener('click', async () => {
        if (!confirm(`Удалить код ${inv.code}?`)) return;
        try { await api('/api/invites/' + encodeURIComponent(inv.code), null, 'DELETE'); await loadInvites(); }
        catch (err) { $('#invites-error').textContent = err.message; }
      });
      li.appendChild(del);
    }
    ul.appendChild(li);
  }
}

// ---------- Settings ----------
$('#open-settings').addEventListener('click', () => {
  $('#settings-modal').classList.remove('hidden');
  loadSessions();
});
$('#close-settings').addEventListener('click', () => $('#settings-modal').classList.add('hidden'));

$('#rotate-key').addEventListener('click', async () => {
  if (!confirm('Сменить ключ? Старые сообщения станут недоступны.')) return;
  try {
    const pwd = sessionPassword || await new Promise((resolve) => {
      const p = prompt('Введите пароль для нового ключа:');
      if (p) resolve(p);
    });
    if (!pwd) return;
    const salt = crypto.getRandomValues(new Uint8Array(16));
    masterBits = await deriveMaster(pwd, salt);
    historyKey = await deriveAes(masterBits, 'minichat-history');
    const { publicJwk, privateKey, encrypted } = await createIdentity(masterBits);
    await idbPutIdentity({ user: me, publicJwk, encrypted, salt: b64.enc(salt) });
    identity = { publicJwk, privateKey };
    peerKeyCache.clear();
    await api('/api/keys', { publicKey: publicJwk });
    alert('Ключ обновлён. Собеседники должны заново получить ваш ключ.');
  } catch (e) { $('#settings-error').textContent = e.message; }
});

async function loadSessions() {
  const ul = $('#sessions-list'); ul.innerHTML = '';
  try {
    const res = await fetch('/api/sessions', { headers: { Authorization: 'Bearer ' + token } });
    if (!res.ok) return;
    const arr = await res.json();
    for (const s of arr) {
      const li = document.createElement('li');
      li.className = 'invite-item' + (s.revoked ? ' used' : '');
      const info = document.createElement('span');
      info.style.flex = '1';
      const dt = new Date(s.last_seen).toLocaleString();
      info.textContent = `${s.current ? 'Это устройство · ' : ''}${dt} · ${s.ip || ''} · ${(s.user_agent || '').slice(0, 40)}`;
      li.appendChild(info);
      if (!s.current && !s.revoked) {
        const btn = document.createElement('button'); btn.className = 'mini danger'; btn.textContent = 'Завершить';
        btn.addEventListener('click', async () => {
          try { await api('/api/sessions/' + encodeURIComponent(s.jti), null, 'DELETE'); await loadSessions(); }
          catch (e) { $('#settings-error').textContent = e.message; }
        });
        li.appendChild(btn);
      }
      if (s.revoked) { const b = document.createElement('span'); b.className = 'badge'; b.textContent = 'отозвана'; li.appendChild(b); }
      ul.appendChild(li);
    }
  } catch (e) { $('#settings-error').textContent = e.message; }
}
$('#revoke-others').addEventListener('click', async () => {
  if (!confirm('Завершить все остальные сессии?')) return;
  try { await api('/api/sessions', null, 'DELETE'); await loadSessions(); }
  catch (e) { $('#settings-error').textContent = e.message; }
});
$('#clear-history').addEventListener('click', async () => {
  if (!confirm('Очистить историю на этом устройстве? Восстановить нельзя.')) return;
  await idbClearAll(me);
  for (const k of Object.keys(history)) delete history[k];
  historyLoaded = false;
  await loadHistory();
  renderMessages();
});

// ---------- Self-test ----------
async function selfTest() {
  try {
    const testText = 'self-test-' + Date.now();
    const enc = await encryptFor(me, testText);
    const dec = await decryptFrom(me, enc.iv, enc.ct);
    if (dec !== testText) throw new Error('decrypt mismatch');
    console.log('[self-test] E2EE OK');
  } catch (e) { console.error('[self-test] E2EE FAILED', e); alert('Ошибка шифрования. Проверьте консоль.'); }
}

// ---------- Enter chat ----------
async function enterChat() {
  if (!crypto || !crypto.subtle) {
    $('#e2ee-warn').classList.remove('hidden');
    $('#e2ee-warn').textContent = 'E2EE недоступно: откройте сайт по HTTPS.';
    return;
  }
  const res = await fetch('/api/me', { headers: { Authorization: 'Bearer ' + token } });
  if (!res.ok) { localStorage.removeItem('token'); location.reload(); return; }
  me = (await res.json()).username;
  $('#me').textContent = me;
  $('#auth').classList.add('hidden');
  $('#chat').classList.remove('hidden');
  await ensureIdentity();
  await loadHistory();
  connectWS();
  await loadUsers();
  await selfTest();
  if (currentPeer) {
    document.body.classList.remove('view-list');
    document.body.classList.add('view-chat');
  } else {
    document.body.classList.add('view-list');
    document.body.classList.remove('view-chat');
  }
}

// ---------- Boot ----------
const qInvite = new URLSearchParams(location.search).get('invite');
if (qInvite) {
  const reg = document.querySelector('#register-form [name=invite]');
  if (reg) { reg.value = qInvite.toUpperCase(); document.querySelector('.tab[data-tab=register]')?.click(); }
}
if (token) enterChat().catch(e => { console.error(e); localStorage.removeItem('token'); location.reload(); });