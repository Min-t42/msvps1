const $ = (s) => document.querySelector(s);
let token = localStorage.getItem('token') || null;
let me = null, ws = null, currentPeer = null;
const history = {};

// ---------- Вкладки ----------
document.querySelectorAll('.tab').forEach(t => {
  t.addEventListener('click', () => {
    document.querySelectorAll('.tab').forEach(x => x.classList.toggle('active', x === t));
    $('#login-form').classList.toggle('hidden', t.dataset.tab !== 'login');
    $('#register-form').classList.toggle('hidden', t.dataset.tab !== 'register');
  });
});

async function api(path, body, method = 'POST') {
  const res = await fetch(path, {
    method,
    headers: { 'Content-Type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined,
  });
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
  if (ws) ws.close();
  location.reload();
});

// ---------- Чат ----------
async function enterChat() {
  const res = await fetch('/api/me', { headers: { Authorization: 'Bearer ' + token } });
  if (!res.ok) { localStorage.removeItem('token'); location.reload(); return; }
  me = (await res.json()).username;
  $('#me').textContent = me;
  $('#auth').classList.add('hidden');
  $('#chat').classList.remove('hidden');
  connectWS();
  await loadUsers();
}

function connectWS() {
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  ws = new WebSocket(`${proto}://${location.host}/ws?token=${encodeURIComponent(token)}`);
  ws.addEventListener('close', () => { if (token) setTimeout(connectWS, 2000); });
  ws.addEventListener('message', (ev) => {
    let m; try { m = JSON.parse(ev.data); } catch { return; }
    if (m.type === 'msg') {
      pushMessage(m.from, { from: m.from, text: m.text, ts: m.ts });
      if (m.from === currentPeer) renderMessages();
    } else if (m.type === 'undelivered') {
      pushMessage(m.to, { from: me, text: '⚠ не доставлено (получатель офлайн)', ts: Date.now(), system: true });
      if (m.to === currentPeer) renderMessages();
    }
  });
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
}

function selectPeer(u) {
  currentPeer = u;
  $('#peer').textContent = u;
  $('#send-form').classList.remove('hidden');
  document.querySelectorAll('#users li').forEach(li => li.classList.toggle('active', li.textContent === u));
  renderMessages();
}

function pushMessage(peer, msg) {
  if (!history[peer]) history[peer] = [];
  history[peer].push(msg);
}

function renderMessages() {
  const box = $('#messages'); box.innerHTML = '';
  for (const m of (history[currentPeer] || [])) {
    const d = document.createElement('div');
    d.className = 'msg ' + (m.from === me ? 'out' : 'in') + (m.system ? ' system' : '');
    d.textContent = m.text;
    box.appendChild(d);
  }
  box.scrollTop = box.scrollHeight;
}

$('#send-form').addEventListener('submit', (e) => {
  e.preventDefault();
  const input = $('#text');
  const text = input.value.trim();
  if (!text || !currentPeer || !ws || ws.readyState !== ws.OPEN) return;
  const id = crypto.randomUUID();
  ws.send(JSON.stringify({ type: 'msg', to: currentPeer, text, id }));
  pushMessage(currentPeer, { from: me, text, ts: Date.now() });
  renderMessages();
  input.value = '';
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
      const badge = document.createElement('span');
      badge.className = 'badge';
      badge.textContent = inv.used_by ? `использован: ${inv.used_by}` : 'использован';
      li.appendChild(badge);
    } else {
      const copyBtn = document.createElement('button');
      copyBtn.className = 'mini';
      copyBtn.textContent = 'Скопировать';
      copyBtn.addEventListener('click', async () => {
        const link = `${location.origin}/?invite=${inv.code}`;
        try {
          await navigator.clipboard.writeText(link);
          copyBtn.textContent = 'Скопировано ✓';
          setTimeout(() => copyBtn.textContent = 'Скопировать', 1500);
        } catch {
          prompt('Скопируйте вручную:', link);
        }
      });
      li.appendChild(copyBtn);

      const delBtn = document.createElement('button');
      delBtn.className = 'mini danger';
      delBtn.textContent = 'Удалить';
      delBtn.addEventListener('click', async () => {
        if (!confirm(`Удалить код ${inv.code}?`)) return;
        try {
          await api('/api/invites/' + encodeURIComponent(inv.code), null, 'DELETE');
          await loadInvites();
        } catch (err) { $('#invites-error').textContent = err.message; }
      });
      li.appendChild(delBtn);
    }

    ul.appendChild(li);
  }
}

// ---------- Boot ----------
// Предзаполнить поле приглашения из ?invite=XXX
const qInvite = new URLSearchParams(location.search).get('invite');
if (qInvite) {
  const reg = document.querySelector('#register-form [name=invite]');
  if (reg) {
    reg.value = qInvite.toUpperCase();
    document.querySelector('.tab[data-tab=register]')?.click();
  }
}

if (token) enterChat().catch(() => { localStorage.removeItem('token'); location.reload(); });