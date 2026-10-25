const $ = (s) => document.querySelector(s);
let token = localStorage.getItem('token') || null;
let me = null, ws = null, currentPeer = null;
const history = {};
let historyLoaded = false;

const backBtns = [document.getElementById('back-btn'), document.getElementById('back-btn2')];
const wsStatus = document.getElementById('ws-status');

// ---------- UUID (работает и на HTTP) ----------
function uuid() {
  if (crypto && typeof crypto.randomUUID === 'function') return crypto.randomUUID();
  if (crypto && typeof crypto.getRandomValues === 'function') {
    return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
      const r = crypto.getRandomValues(new Uint8Array(1))[0] % 16;
      return (c === 'x' ? r : ((r & 0x3) | 0x8)).toString(16);
    });
  }
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    return (c === 'x' ? r : ((r & 0x3) | 0x8)).toString(16);
  });
}

// ---------- IndexedDB ----------
const DB_NAME = 'minichat';
const DB_VERSION = 1;
const STORE = 'messages';
let dbPromise = null;

function openDB() {
  if (dbPromise) return dbPromise;
  dbPromise = new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE)) {
        const store = db.createObjectStore(STORE, { keyPath: 'id' });
        store.createIndex('user', 'user');
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
    req.onblocked = () => reject(new Error('IndexedDB blocked'));
  });
  return dbPromise;
}

async function idbPut(rec) {
  try {
    const db = await openDB();
    return await new Promise((res, rej) => {
      const tx = db.transaction(STORE, 'readwrite');
      tx.objectStore(STORE).put(rec);
      tx.oncomplete = () => res();
      tx.onerror = () => rej(tx.error);
    });
  } catch (e) { console.warn('[idbPut]', e); }
}

async function idbGetAll() {
  const db = await openDB();
  return new Promise((res, rej) => {
    const tx = db.transaction(STORE, 'readonly');
    const req = tx.objectStore(STORE).getAll();
    req.onsuccess = () => res(req.result);
    req.onerror = () => rej(req.error);
  });
}

async function idbUpdateStatus(user, id, status) {
  try {
    const db = await openDB();
    await new Promise((res, rej) => {
      const tx = db.transaction(STORE, 'readwrite');
      const store = tx.objectStore(STORE);
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

async function idbGetPending(user) {
  const all = await idbGetAll();
  return all.filter(r => r.user === user && r.status === 'pending');
}

async function loadHistory() {
  if (historyLoaded || !me) return;
  try {
    const all = await idbGetAll();
    let n = 0;
    for (const r of all) {
      if (r.user !== me) continue;
      let status = r.status || null;
      if (status === 'sending') status = 'unknown';
      if (!history[r.peer]) history[r.peer] = [];
      if (history[r.peer].some(m => m.id === r.id)) continue;
      history[r.peer].push({
        from: r.from, text: r.text, ts: r.ts, id: r.id,
        status, offline: r.offline,
      });
      n++;
    }
    for (const p of Object.keys(history)) history[p].sort((a, b) => a.ts - b.ts);
    historyLoaded = true;
    console.log(`[minichat] restored ${n} messages for ${me} from IndexedDB`);
  } catch (e) {
    console.error('[minichat] loadHistory failed:', e);
  }
}

// ---------- Авторизация ----------
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
  try {
    const d = await api('/api/login', { username: f.username.value.trim(), password: f.password.value });
    token = d.token; localStorage.setItem('token', token);
    await enterChat();
  } catch (err) { $('#auth-error').textContent = err.message; }
});

$('#register-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  $('#auth-error').textContent = '';
  const f = e.target;
  try {
    const d = await api('/api/register', {
      username: f.username.value.trim(),
      password: f.password.value,
      invite: f.invite.value.trim(),
    });
    token = d.token; localStorage.setItem('token', token);
    await enterChat();
  } catch (err) { $('#auth-error').textContent = err.message; }
});

$('#logout').addEventListener('click', () => {
  localStorage.removeItem('token');
  localStorage.removeItem('lastPeer');
  if (ws) ws.close();
  location.reload();
});

// ---------- Навигация (мобильная) ----------
function showList() {
  currentPeer = null;
  document.body.classList.add('view-list');
  document.body.classList.remove('view-chat');
  document.querySelectorAll('#users li').forEach(li => li.classList.remove('active'));
}

function selectPeer(u) {
  currentPeer = u;
  localStorage.setItem('lastPeer', u);
  const nameEl = $('#peer-name') || $('#peer');
  nameEl.textContent = u;
  $('#send-form').classList.remove('hidden');
  document.querySelectorAll('#users li').forEach(li => li.classList.toggle('active', li.textContent === u));
  renderMessages();
  document.body.classList.remove('view-list');
  document.body.classList.add('view-chat');
}

backBtns.forEach(b => { if (b) b.addEventListener('click', showList); });
window.addEventListener('popstate', showList);

// ---------- WS статус ----------
function setWsStatus(state) {
  if (!wsStatus) return;
  wsStatus.classList.remove('online', 'offline', 'connecting');
  wsStatus.classList.add(state);
  wsStatus.title =
    state === 'online'     ? 'Соединение активно' :
    state === 'offline'    ? 'Нет соединения — переподключение...' :
    'Подключение...';
}

// ---------- Вход ----------
async function enterChat() {
  const res = await fetch('/api/me', { headers: { Authorization: 'Bearer ' + token } });
  if (!res.ok) { localStorage.removeItem('token'); location.reload(); return; }
  me = (await res.json()).username;
  $('#me').textContent = me;
  $('#auth').classList.add('hidden');
  $('#chat').classList.remove('hidden');
  await loadHistory();
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

function connectWS() {
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  setWsStatus('connecting');
  ws = new WebSocket(`${proto}://${location.host}/ws?token=${encodeURIComponent(token)}`);

  ws.addEventListener('open', () => {
    console.log('[minichat] ws connected');
    setWsStatus('online');
    flushPending();
  });

  ws.addEventListener('close', () => {
    console.log('[minichat] ws closed');
    setWsStatus('offline');
    if (token) setTimeout(connectWS, 2000);
  });

  ws.addEventListener('error', () => setWsStatus('offline'));

  ws.addEventListener('message', (ev) => {
    let m; try { m = JSON.parse(ev.data); } catch { return; }
    if (m.type === 'msg') {
      pushMessage(m.from, {
        from: m.from, text: m.text, ts: m.ts,
        id: m.id || null,
        offline: m.offline || false,
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
  if (!me || !ws || ws.readyState !== ws.OPEN) return;
  try {
    const pending = await idbGetPending(me);
    for (const r of pending) {
      if (!ws || ws.readyState !== ws.OPEN) break;
      ws.send(JSON.stringify({ type: 'msg', to: r.peer, text: r.text, id: r.id }));
      setStatus(r.peer, r.id, 'sending');
    }
    if (pending.length) renderMessages();
  } catch (e) { console.warn('[flushPending]', e); }
}

async function loadUsers() {
  const res = await fetch('/api/users', { headers: { Authorization: 'Bearer ' + token } });
  if (!res.ok) return;
  const users = await res.json();
  const ul = $('#users'); ul.innerHTML = '';
  for (const u of users) {
    const li = document.createElement('li');
    li.textContent = u;
    li.addEventListener('click', () => selectPeer(u));
    ul.appendChild(li);
  }
  const last = localStorage.getItem('lastPeer');
  if (last && users.includes(last)) selectPeer(last);
}

// ---------- История ----------
function pushMessage(peer, msg) {
  if (!history[peer]) history[peer] = [];
  if (msg.id && history[peer].some(m => m.id === msg.id)) return;
  if (!msg.id && history[peer].some(m => m.from === msg.from && m.ts === msg.ts && m.text === msg.text)) return;
  history[peer].push(msg);
  if (me && msg.id) {
    idbPut({
      id: msg.id, user: me, peer,
      from: msg.from, text: msg.text, ts: msg.ts,
      status: msg.status || null, offline: msg.offline || false,
    });
  }
}

function setStatus(peer, id, status) {
  const arr = history[peer];
  if (!arr || !id) return;
  for (const m of arr) {
    if (m.id === id) {
      m.status = status;
      if (me) idbUpdateStatus(me, id, status);
      return;
    }
  }
}

function renderMessages() {
  const box = $('#messages'); box.innerHTML = '';
  const icons = {
    pending: '⏳', sending: '·', queued: '⏳',
    delivered: '✓', failed: '✗', unknown: '?',
  };
  for (const m of (history[currentPeer] || [])) {
    const d = document.createElement('div');
    d.className = 'msg ' + (m.from === me ? 'out' : 'in') + (m.system ? ' system' : '');
    d.textContent = m.text;
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

// ---------- Отправка ----------
$('#send-form').addEventListener('submit', async (e) => {
  e.preventDefault();
  const input = $('#text');
  const text = input.value.trim();
  if (!text) return;
  if (!currentPeer) {
    // Подсказка: нужно выбрать собеседника
    const msgEl = $('#peer-name');
    const old = msgEl.textContent;
    msgEl.textContent = 'Сначала выберите собеседника';
    setTimeout(() => { msgEl.textContent = old; }, 2000);
    return;
  }

  const id = uuid();
  const ts = Date.now();

  if (ws && ws.readyState === ws.OPEN) {
    ws.send(JSON.stringify({ type: 'msg', to: currentPeer, text, id }));
    pushMessage(currentPeer, { from: me, text, ts, id, status: 'sending' });
  } else {
    // Нет соединения — сохраняем локально как pending, отправим при подключении
    pushMessage(currentPeer, { from: me, text, ts, id, status: 'pending' });
    setWsStatus('offline');
  }

  renderMessages();
  input.value = '';
  input.focus();
});

// ---------- Приглашения ----------
const invitesModal = $('#invites-modal');

$('#open-invites').addEventListener('click', () => {
  invitesModal.classList.remove('hidden');
  loadInvites();
});
$('#close-invites').addEventListener('click', () => invitesModal.classList.add('hidden'));
invitesModal.addEventListener('click', (e) => {
  if (e.target === invitesModal) invitesModal.classList.add('hidden');
});

$('#new-invite').addEventListener('click', async () => {
  $('#invites-error').textContent = '';
  try {
    await api('/api/invites', {});
    await loadInvites();
  } catch (err) {
    $('#invites-error').textContent = err.message;
  }
});

async function loadInvites() {
  const res = await fetch('/api/invites', { headers: { Authorization: 'Bearer ' + token } });
  if (!res.ok) { $('#invites-error').textContent = 'не удалось загрузить'; return; }
  const data = await res.json();
  $('#invites-meta').textContent =
    `Активных: ${data.active} из ${data.limit} · всего создано: ${data.invites.length}`;
  const ul = $('#invites-list'); ul.innerHTML = '';
  if (data.invites.length === 0) {
    const li = document.createElement('li');
    li.className = 'muted';
    li.textContent = 'Пока нет кодов. Нажмите «Сгенерировать новый».';
    ul.appendChild(li);
    return;
  }
  for (const inv of data.invites) {
    const li = document.createElement('li');
    li.className = 'invite-item' + (inv.used ? ' used' : '');
    const code = document.createElement('code');
    code.textContent = inv.code;
    li.appendChild(code);
    if (inv.used) {
      const b = document.createElement('span');
      b.className = 'badge';
      b.textContent = inv.used_by ? `использован: ${inv.used_by}` : 'использован';
      li.appendChild(b);
    } else {
      const copy = document.createElement('button');
      copy.className = 'mini'; copy.textContent = 'Скопировать';
      copy.addEventListener('click', async () => {
        const link = `${location.origin}/?invite=${inv.code}`;
        try {
          await navigator.clipboard.writeText(link);
          copy.textContent = 'Скопировано ✓';
          setTimeout(() => copy.textContent = 'Скопировать', 1500);
        } catch { prompt('Скопируйте вручную:', link); }
      });
      li.appendChild(copy);
      const del = document.createElement('button');
      del.className = 'mini danger'; del.textContent = 'Удалить';
      del.addEventListener('click', async () => {
        if (!confirm(`Удалить код ${inv.code}?`)) return;
        try {
          await api('/api/invites/' + encodeURIComponent(inv.code), null, 'DELETE');
          await loadInvites();
        } catch (err) { $('#invites-error').textContent = err.message; }
      });
      li.appendChild(del);
    }
    ul.appendChild(li);
  }
}

// ---------- Boot ----------
const qInvite = new URLSearchParams(location.search).get('invite');
if (qInvite) {
  const reg = document.querySelector('#register-form [name=invite]');
  if (reg) {
    reg.value = qInvite.toUpperCase();
    document.querySelector('.tab[data-tab=register]')?.click();
  }
}

if (token) enterChat().catch(e => {
  console.error(e);
  localStorage.removeItem('token');
  location.reload();
});