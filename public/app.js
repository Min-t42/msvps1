const $ = (s) => document.querySelector(s);
let token = localStorage.getItem('token') || null;
let me = null, ws = null, currentPeer = null;
let identity = null;             // { publicJwk, privateKey }
let sessionPassword = null;      // пароль в памяти на время сессии
const history = {};
let historyLoaded = false;

const backBtns = [document.getElementById('back-btn'), document.getElementById('back-btn2')];
const wsStatus = document.getElementById('ws-status');

// ---------- Base64 helpers ----------
const b64 = {
  enc: (buf) => btoa(String.fromCharCode(...new Uint8Array(buf))),
  dec: (s) => Uint8Array.from(atob(s), c => c.charCodeAt(0)),
};

function uuid() {
  if (crypto && typeof crypto.randomUUID === 'function') return crypto.randomUUID();
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    return (c === 'x' ? r : ((r & 0x3) | 0x8)).toString(16);
  });
}

// ---------- Crypto (E2EE) ----------
async function deriveKek(password, salt) {
  const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey(
    { name: 'PBKDF2', salt, iterations: 200000, hash: 'SHA-256' },
    base,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
  );
}

async function encryptPrivateKey(privateKey, password) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const kek = await deriveKek(password, salt);
  const raw = await crypto.subtle.exportKey('pkcs8', privateKey);
  const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, kek, raw);
  return { salt: b64.enc(salt), iv: b64.enc(iv), ct: b64.enc(ct) };
}

async function decryptPrivateKey(enc, password) {
  const kek = await deriveKek(password, b64.dec(enc.salt));
  const raw = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: b64.dec(enc.iv) }, kek, b64.dec(enc.ct));
  return crypto.subtle.importKey('pkcs8', raw, { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveKey', 'deriveBits']);
}

async function createIdentity(password) {
  const kp = await crypto.subtle.generateKey(
    { name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveKey', 'deriveBits']
  );
  const publicJwk = await crypto.subtle.exportKey('jwk', kp.publicKey);
  const enc = await encryptPrivateKey(kp.privateKey, password);
  const privateKey = await crypto.subtle.importKey(
    'pkcs8',
    await crypto.subtle.exportKey('pkcs8', kp.privateKey),
    { name: 'ECDH', namedCurve: 'P-256' }, false, ['deriveKey', 'deriveBits']
  );
  return { publicJwk, privateKey, encrypted: enc };
}

async function deriveSharedAesKey(peerPublicKey) {
  return crypto.subtle.deriveKey(
    { name: 'ECDH', public: peerPublicKey },
    identity.privateKey,
    { name: 'AES-GCM', length: 256 },
    false,
    ['encrypt', 'decrypt']
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

// ---------- IndexedDB ----------
const DB_NAME = 'minichat';
const DB_VERSION = 2;
const STORE_MSG = 'messages';
const STORE_IDENT = 'identity';
let dbPromise = null;

function openDB() {
  if (dbPromise) return dbPromise;
  dbPromise = new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = (e) => {
      const db = req.result;
      const tx = req.transaction;
      if (!db.objectStoreNames.contains(STORE_MSG)) {
        const s = db.createObjectStore(STORE_MSG, { keyPath: 'id' });
        s.createIndex('user', 'user');
      }
      if (!db.objectStoreNames.contains(STORE_IDENT)) {
        db.createObjectStore(STORE_IDENT, { keyPath: 'user' });
      }
      // Миграция v1→v2: удалить старые сообщения без iv/ct (открытый текст, несовместим с E2EE)
      if (tx && db.objectStoreNames.contains(STORE_MSG)) {
        const store = tx.objectStore(STORE_MSG);
        store.openCursor().onsuccess = (ev) => {
          const cursor = ev.target.result;
          if (!cursor) return;
          const v = cursor.value;
          if (!v.iv || !v.ct) cursor.delete();
          cursor.continue();
        };
      }
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
      tx.oncomplete = () => res();
      tx.onerror = () => rej(tx.error);
    });
  } catch (e) { console.warn('[idbPutMsg]', e); }
}
async function idbGetAllMsgs() {
  const db = await openDB();
  return new Promise((res, rej) => {
    const tx = db.transaction(STORE_MSG, 'readonly');
    const req = tx.objectStore(STORE_MSG).getAll();
    req.onsuccess = () => res(req.result);
    req.onerror = () => rej(req.error);
  });
}
async function idbUpdateStatus(user, id, status) {
  try {
    const db = await openDB();
    await new Promise((res, rej) => {
      const tx = db.transaction(STORE_MSG, 'readwrite');
      const store = tx.objectStore(STORE_MSG);
      const get = store.get(id);
      get.onsuccess = () => {
        const rec = get.result;
        if (!rec || rec.user !== user) return;
        rec.status = status;
        store.put(rec);
      };
      tx.oncomplete = () => res();
      tx.onerror = () => rej(tx.error);
    });
  } catch (e) { console.warn('[idbUpdateStatus]', e); }
}
async function idbGetIdentity(user) {
  const db = await openDB();
  return new Promise((res, rej) => {
    const tx = db.transaction(STORE_IDENT, 'readonly');
    const req = tx.objectStore(STORE_IDENT).get(user);
    req.onsuccess = () => res(req.result || null);
    req.onerror = () => rej(req.error);
  });
}
async function idbPutIdentity(rec) {
  const db = await openDB();
  return new Promise((res, rej) => {
    const tx = db.transaction(STORE_IDENT, 'readwrite');
    tx.objectStore(STORE_IDENT).put(rec);
    tx.oncomplete = () => res();
    tx.onerror = () => rej(tx.error);
  });
}
async function idbGetPending(user) {
  const all = await idbGetAllMsgs();
  return all.filter(r => r.user === user && r.status === 'pending');
}

async function loadHistory() {
  if (historyLoaded || !me) return;
  try {
    const all = await idbGetAllMsgs();
    let n = 0;
    for (const r of all) {
      if (r.user !== me) continue;
      let status = r.status || null;
      if (status === 'sending') status = 'unknown';
      if (!history[r.peer]) history[r.peer] = [];
      if (history[r.peer].some(m => m.id === r.id)) continue;
      history[r.peer].push({
        id: r.id, from: r.from, iv: r.iv, ct: r.ct, ts: r.ts,
        status, offline: r.offline, text: null,
      });
      n++;
    }
    for (const p of Object.keys(history)) history[p].sort((a, b) => a.ts - b.ts);
    historyLoaded = true;
    console.log(`[minichat] restored ${n} encrypted messages for ${me}`);
  } catch (e) { console.error('[loadHistory]', e); }
}

async function decryptHistoryFor(peer) {
  const arr = history[peer];
  if (!arr) return;
  for (const m of arr) {
    if (m.text != null) continue;
    try {
      const other = m.from === me ? peer : m.from;
      m.text = await decryptFrom(other, m.iv, m.ct);
    } catch (e) {
      m.text = '[не удалось расшифровать]';
      console.warn('[decrypt]', e);
    }
  }
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
    const d = await api('/api/register', {
      username: f.username.value.trim(), password, invite: f.invite.value.trim(),
    });
    token = d.token; localStorage.setItem('token', token);
    sessionPassword = password;
    await enterChat();
  } catch (err) { $('#auth-error').textContent = err.message; }
});

$('#logout').addEventListener('click', () => {
  localStorage.removeItem('token');
  localStorage.removeItem('lastPeer');
  if (ws) ws.close();
  location.reload();
});

// ---------- Unlock modal ----------
function askPassword() {
  return new Promise((resolve) => {
    $('#unlock-modal').classList.remove('hidden');
    $('#unlock-password').value = '';
    $('#unlock-error').textContent = '';
    $('#unlock-password').focus();
    const submit = async () => {
      const pwd = $('#unlock-password').value;
      if (!pwd) return;
      try {
        await unlockIdentity(pwd);
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

async function unlockIdentity(password) {
  const rec = await idbGetIdentity(me);
  if (!rec) throw new Error('no identity');
  const priv = await decryptPrivateKey(rec.encrypted, password);
  identity = { publicJwk: rec.publicJwk, privateKey: priv };
}

async function ensureIdentity() {
  // Если identity уже разблокирована — ок
  if (identity) return;
  const rec = await idbGetIdentity(me);

  if (rec) {
    // Есть сохранённая identity — нужен пароль
    if (sessionPassword) {
      try {
        await unlockIdentity(sessionPassword);
        return;
      } catch (e) {
        sessionPassword = null;
      }
    }
    await askPassword();
    return;
  }

  // Нет identity — генерируем новую (нужен пароль)
  let pwd = sessionPassword;
  if (!pwd) {
    // Спросим пароль через ту же модалку, но с сообщением «создание ключа»
    pwd = await new Promise((resolve) => {
      $('#unlock-modal').classList.remove('hidden');
      $('#unlock-password').value = '';
      $('#unlock-error').textContent = '';
      $('.modal-head h2').textContent = 'Создание ключа шифрования';
      $('#unlock-password').focus();
      const submit = () => {
        const v = $('#unlock-password').value;
        if (v) { $('#unlock-modal').classList.add('hidden'); resolve(v); }
      };
      $('#unlock-btn').onclick = submit;
      $('#unlock-password').onkeydown = (e) => { if (e.key === 'Enter') submit(); };
    });
  }

  const { publicJwk, privateKey, encrypted } = await createIdentity(pwd);
  await idbPutIdentity({ user: me, publicJwk, encrypted });
  identity = { publicJwk, privateKey };

  // Публикуем публичный ключ на сервере
  await api('/api/keys', { publicKey: publicJwk });
  console.log('[minichat] new identity created & published');
}

// ---------- Navigation ----------
function showList() {
  currentPeer = null;
  document.body.classList.add('view-list');
  document.body.classList.remove('view-chat');
  document.querySelectorAll('#users li').forEach(li => li.classList.remove('active'));
}
async function selectPeer(u) {
  currentPeer = u;
  localStorage.setItem('lastPeer', u);
  ($('#peer-name') || $('#peer')).textContent = u;
  $('#send-form').classList.remove('hidden');
  document.querySelectorAll('#users li').forEach(li => li.classList.toggle('active', li.dataset.user === u));
  await decryptHistoryFor(u);
  renderMessages();
  document.body.classList.remove('view-list');
  document.body.classList.add('view-chat');
}
backBtns.forEach(b => { if (b) b.addEventListener('click', showList); });
window.addEventListener('popstate', showList);

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
      try { text = await decryptFrom(m.from, m.iv, m.ct); } catch (e) { text = '[не удалось расшифровать]'; }
      pushMessage(m.from, {
        id: m.id || null, from: m.from, iv: m.iv, ct: m.ct, ts: m.ts,
        offline: m.offline || false, text,
      });
      if (m.from === currentPeer) renderMessages();
    } else if (m.type === 'queued') {
      setStatus(m.to, m.id, 'queued');
      if (m.to === currentPeer) renderMessages();
    } else if (m.type === 'delivered') {
      setStatus(m.to, m.id, 'delivered');
      if (m.to === currentPeer) renderMessages();
    }
  });
}

async function flushPending() {
  if (!me || !identity || !ws || ws.readyState !== ws.OPEN) return;
  const pending = await idbGetPending(me);
  for (const r of pending) {
    if (!ws || ws.readyState !== ws.OPEN) break;
    ws.send(JSON.stringify({ type: 'msg', to: r.peer, id: r.id, iv: r.iv, ct: r.ct }));
    setStatus(r.peer, r.id, 'sending');
  }
  if (pending.length) renderMessages();
}

async function loadUsers() {
  const res = await fetch('/api/users', { headers: { Authorization: 'Bearer ' + token } });
  if (!res.ok) return;
  const users = await res.json();
  const ul = $('#users'); ul.innerHTML = '';
  for (const u of users) {
    const li = document.createElement('li');
    li.dataset.user = u.username;
    const span = document.createElement('span');
    span.textContent = u.username;
    li.appendChild(span);
    if (!u.hasKey) {
      const warn = document.createElement('span');
      warn.className = 'nokey'; warn.textContent = 'нет ключа';
      warn.title = 'Пользователь ещё не заходил после обновления — E2EE пока недоступно';
      li.appendChild(warn);
    }
    li.addEventListener('click', () => selectPeer(u.username));
    ul.appendChild(li);
  }
  const last = localStorage.getItem('lastPeer');
  if (last && users.some(u => u.username === last)) selectPeer(last);
}

// ---------- History ----------
function pushMessage(peer, msg) {
  if (!history[peer]) history[peer] = [];
  if (msg.id && history[peer].some(m => m.id === msg.id)) return;
  history[peer].push(msg);
  if (me && msg.id) {
    idbPutMsg({
      id: msg.id, user: me, peer,
      from: msg.from, iv: msg.iv, ct: msg.ct, ts: msg.ts,
      status: msg.status || null, offline: msg.offline || false,
    });
  }
}
function setStatus(peer, id, status) {
  const arr = history[peer];
  if (!arr || !id) return;
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
      const s = document.createElement('span');
      s.className = 'msg-status ' + m.status;
      s.textContent = icons[m.status];
      d.appendChild(s);
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
  if (!currentPeer) {
    const el = $('#peer-name'); const old = el.textContent;
    el.textContent = 'Сначала выберите собеседника';
    setTimeout(() => el.textContent = old, 2000);
    return;
  }
  if (!identity) { alert('Ключ шифрования не разблокирован'); return; }

  const id = uuid();
  const ts = Date.now();

  let enc;
  try {
    enc = await encryptFor(currentPeer, text);
  } catch (err) {
    alert('Не удалось зашифровать: ' + err.message);
    return;
  }

  if (ws && ws.readyState === ws.OPEN) {
    ws.send(JSON.stringify({ type: 'msg', to: currentPeer, id, iv: enc.iv, ct: enc.ct }));
    pushMessage(currentPeer, { id, from: me, iv: enc.iv, ct: enc.ct, ts, text, status: 'sending' });
  } else {
    pushMessage(currentPeer, { id, from: me, iv: enc.iv, ct: enc.ct, ts, text, status: 'pending' });
    setWsStatus('offline');
  }
  renderMessages();
  input.value = '';
  input.focus();
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
  if (data.invites.length === 0) {
    const li = document.createElement('li'); li.className = 'muted';
    li.textContent = 'Пока нет кодов.'; ul.appendChild(li); return;
  }
  for (const inv of data.invites) {
    const li = document.createElement('li');
    li.className = 'invite-item' + (inv.used ? ' used' : '');
    const code = document.createElement('code'); code.textContent = inv.code; li.appendChild(code);
    if (inv.used) {
      const b = document.createElement('span'); b.className = 'badge';
      b.textContent = inv.used_by ? `использован: ${inv.used_by}` : 'использован'; li.appendChild(b);
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

// ---------- Enter chat ----------
async function enterChat() {
  if (!crypto || !crypto.subtle) {
    $('#e2ee-warn').classList.remove('hidden');
    $('#e2ee-warn').textContent = 'E2EE недоступно: откройте сайт по HTTPS (не по http://IP).';
    return;
  }
  const res = await fetch('/api/me', { headers: { Authorization: 'Bearer ' + token } });
  if (!res.ok) { localStorage.removeItem('token'); location.reload(); return; }
  me = (await res.json()).username;
  $('#me').textContent = me;
  $('#auth').classList.add('hidden');
  $('#chat').classList.remove('hidden');
  await loadHistory();
  await ensureIdentity();
  connectWS();
  await loadUsers();
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