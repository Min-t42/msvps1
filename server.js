require('dotenv').config();
const express = require('express');
const http = require('http');
const path = require('path');
const { WebSocketServer } = require('ws');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const PORT = Number(process.env.PORT || 8081);
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  console.error('FATAL: JWT_SECRET is not set in .env');
  process.exit(1);
}
const TOKEN_TTL = '7d';
const MAX_ACTIVE_INVITES = 10;
const OFFLINE_TTL_MS = 30 * 24 * 60 * 60 * 1000; // 30 дней

// ---------- База ----------
const db = new Database(process.env.DB_PATH || 'chat.db');
db.pragma('journal_mode = WAL');
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    invite_code TEXT NOT NULL,
    created_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS invites (
    code TEXT PRIMARY KEY,
    used INTEGER NOT NULL DEFAULT 0,
    used_by TEXT,
    created_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS offline_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    msg_id TEXT,
    to_user TEXT NOT NULL,
    from_user TEXT NOT NULL,
    text TEXT NOT NULL,
    ts INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_offline_to ON offline_messages(to_user);
`);

{
  const cols = db.prepare('PRAGMA table_info(invites)').all().map(c => c.name);
  if (!cols.includes('created_by')) {
    db.exec('ALTER TABLE invites ADD COLUMN created_by TEXT');
    console.log('migration: added invites.created_by');
  }
}

// ---------- CLI: генерация инвайта ----------
if (process.argv[2] === 'invite') {
  const code = crypto.randomBytes(6).toString('hex').toUpperCase();
  db.prepare('INSERT INTO invites (code, created_at) VALUES (?, ?)').run(code, Date.now());
  console.log('Invite code:', code);
  process.exit(0);
}

// ---------- Первый запуск ----------
if (db.prepare('SELECT COUNT(*) AS c FROM invites').get().c === 0) {
  const code = crypto.randomBytes(6).toString('hex').toUpperCase();
  db.prepare('INSERT INTO invites (code, created_at) VALUES (?, ?)').run(code, Date.now());
  console.log('====================================');
  console.log('FIRST-RUN invite code:', code);
  console.log('Register with it, then generate more from the UI.');
  console.log('====================================');
}

// ---------- Auth ----------
const signToken = (u) => jwt.sign({ u }, JWT_SECRET, { expiresIn: TOKEN_TTL });
const verifyToken = (t) => { try { return jwt.verify(t, JWT_SECRET); } catch { return null; } };
function authMiddleware(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  const payload = token && verifyToken(token);
  if (!payload) return res.status(401).json({ error: 'unauthorized' });
  req.username = payload.u;
  next();
}

// ---------- HTTP API ----------
const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.post('/api/register', (req, res) => {
  const { username, password, invite } = req.body || {};
  if (!username || !password || !invite) return res.status(400).json({ error: 'missing fields' });
  if (!/^[a-zA-Z0-9_]{3,32}$/.test(username)) return res.status(400).json({ error: 'invalid username' });
  if (String(password).length < 8) return res.status(400).json({ error: 'password too short (min 8)' });

  const inv = db.prepare('SELECT * FROM invites WHERE code = ?').get(String(invite).toUpperCase());
  if (!inv || inv.used) return res.status(400).json({ error: 'invalid or used invite' });
  if (db.prepare('SELECT 1 FROM users WHERE username = ?').get(username)) {
    return res.status(409).json({ error: 'username taken' });
  }

  const hash = bcrypt.hashSync(password, 10);
  db.transaction(() => {
    db.prepare('INSERT INTO users (username, password_hash, invite_code, created_at) VALUES (?, ?, ?, ?)')
      .run(username, hash, inv.code, Date.now());
    db.prepare('UPDATE invites SET used = 1, used_by = ? WHERE code = ?').run(username, inv.code);
  })();
  res.json({ token: signToken(username), username });
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'missing fields' });
  const row = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!row || !bcrypt.compareSync(password, row.password_hash)) {
    return res.status(401).json({ error: 'invalid credentials' });
  }
  res.json({ token: signToken(username), username });
});

app.get('/api/me', authMiddleware, (req, res) => res.json({ username: req.username }));

app.get('/api/users', authMiddleware, (req, res) => {
  const rows = db.prepare('SELECT username FROM users WHERE username != ? ORDER BY username').all(req.username);
  res.json(rows.map(r => r.username));
});

// ---------- Приглашения ----------
app.get('/api/invites', authMiddleware, (req, res) => {
  const rows = db.prepare(
    'SELECT code, used, used_by, created_at FROM invites WHERE created_by = ? ORDER BY created_at DESC'
  ).all(req.username);
  const active = rows.filter(r => !r.used).length;
  res.json({ invites: rows, limit: MAX_ACTIVE_INVITES, active });
});

app.post('/api/invites', authMiddleware, (req, res) => {
  const active = db.prepare(
    'SELECT COUNT(*) AS c FROM invites WHERE created_by = ? AND used = 0'
  ).get(req.username).c;
  if (active >= MAX_ACTIVE_INVITES) {
    return res.status(429).json({ error: `limit reached: ${MAX_ACTIVE_INVITES} active invites` });
  }
  const code = crypto.randomBytes(6).toString('hex').toUpperCase();
  db.prepare('INSERT INTO invites (code, created_by, created_at) VALUES (?, ?, ?)')
    .run(code, req.username, Date.now());
  res.json({ code });
});

app.delete('/api/invites/:code', authMiddleware, (req, res) => {
  const code = String(req.params.code || '').toUpperCase();
  const row = db.prepare('SELECT * FROM invites WHERE code = ?').get(code);
  if (!row) return res.status(404).json({ error: 'not found' });
  if (row.created_by !== req.username) return res.status(403).json({ error: 'forbidden' });
  if (row.used) return res.status(400).json({ error: 'cannot delete a used invite' });
  db.prepare('DELETE FROM invites WHERE code = ?').run(code);
  res.json({ ok: true });
});

// ---------- WebSocket ----------
const server = http.createServer(app);
const wss = new WebSocketServer({ server, path: '/ws' });

const sockets = new Map();
const addSocket = (u, ws) => {
  if (!sockets.has(u)) sockets.set(u, new Set());
  sockets.get(u).add(ws);
};
const removeSocket = (u, ws) => {
  const s = sockets.get(u);
  if (!s) return;
  s.delete(ws);
  if (s.size === 0) sockets.delete(u);
};

function deliverPending(ws, username) {
  const rows = db.prepare(
    'SELECT id, msg_id, from_user, text, ts FROM offline_messages WHERE to_user = ? ORDER BY id'
  ).all(username);
  if (rows.length === 0) return;

  const ids = rows.map(r => r.id);
  const placeholders = ids.map(() => '?').join(',');
  db.prepare(`DELETE FROM offline_messages WHERE id IN (${placeholders})`).run(...ids);

  const myConns = sockets.get(username) || new Set([ws]);
  for (const m of rows) {
    const payload = JSON.stringify({
      type: 'msg',
      from: m.from_user,
      text: m.text,
      ts: m.ts,
      id: m.msg_id,
      offline: true,
    });
    for (const s of myConns) {
      if (s.readyState === s.OPEN) s.send(payload);
    }
    const ss = sockets.get(m.from_user);
    if (ss) for (const s of ss) if (s.readyState === s.OPEN) {
      s.send(JSON.stringify({ type: 'delivered', id: m.msg_id, to: username, late: true }));
    }
  }
  console.log(`delivered ${rows.length} offline messages to ${username}`);
}

wss.on('connection', (ws, req) => {
  const url = new URL(req.url, 'http://localhost');
  const payload = verifyToken(url.searchParams.get('token'));
  if (!payload) { ws.close(4001, 'unauthorized'); return; }

  const username = payload.u;
  ws.username = username;
  ws.isAlive = true;
  ws.on('pong', () => { ws.isAlive = true; });

  addSocket(username, ws);
  ws.send(JSON.stringify({ type: 'ready', username }));
  console.log(`[ws] connected: ${username}`);

  try { deliverPending(ws, username); } catch (e) { console.error('deliverPending:', e); }

  ws.on('message', (raw) => {
    let m; try { m = JSON.parse(raw.toString()); } catch { return; }
    if (!m || m.type !== 'msg') return;
    const to = String(m.to || '').trim();
    const text = String(m.text || '');
    if (!to || !text || text.length > 8000) return;

    const msgId = m.id || crypto.randomUUID();
    const ts = Date.now();
    const out = JSON.stringify({ type: 'msg', from: username, text, ts, id: msgId });
    const rs = sockets.get(to);

    if (rs && rs.size > 0) {
      for (const r of rs) if (r.readyState === r.OPEN) r.send(out);
      ws.send(JSON.stringify({ type: 'delivered', id: msgId, to }));
    } else {
      db.prepare(
        'INSERT INTO offline_messages (msg_id, to_user, from_user, text, ts) VALUES (?, ?, ?, ?, ?)'
      ).run(msgId, to, username, text, ts);
      ws.send(JSON.stringify({ type: 'queued', id: msgId, to }));
    }
  });

  ws.on('close', () => {
    console.log(`[ws] closed: ${username}`);
    removeSocket(username, ws);
  });
  ws.on('error', () => removeSocket(username, ws));
});

const hb = setInterval(() => {
  for (const ws of wss.clients) {
    if (ws.isAlive === false) { try { ws.terminate(); } catch {} continue; }
    ws.isAlive = false;
    try { ws.ping(); } catch {}
  }
}, 30000);
wss.on('close', () => clearInterval(hb));

setInterval(() => {
  const cutoff = Date.now() - OFFLINE_TTL_MS;
  const r = db.prepare('DELETE FROM offline_messages WHERE ts < ?').run(cutoff);
  if (r.changes > 0) console.log(`cleanup: removed ${r.changes} expired offline messages`);
}, 60 * 60 * 1000);

server.listen(PORT, '0.0.0.0', () => console.log(`minichat listening on :${PORT}`));