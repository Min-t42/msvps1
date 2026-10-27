require('dotenv').config();
const express = require('express');
const http = require('http');
const path = require('path');
const fs = require('fs');
const { WebSocketServer } = require('ws');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const crypto = require('crypto');

const PORT = Number(process.env.PORT || 8081);
const JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) { console.error('FATAL: JWT_SECRET missing'); process.exit(1); }
const TOKEN_TTL = '7d';
const MAX_ACTIVE_INVITES = 10;
const OFFLINE_TTL_MS = 30 * 24 * 60 * 60 * 1000;
const FILES_TTL_MS = 7 * 24 * 60 * 60 * 1000;
const MAX_FILE_SIZE = 35 * 1024 * 1024;       // 35 MB
const MAX_FILE_SIZE_BODY = 36 * 1024 * 1024;  // + запас на GCM-тег
const WS_ALERT_THRESHOLD = 20;
const WS_ALERT_WINDOW = 60 * 1000;

const UPLOAD_DIR = path.join(__dirname, 'uploads');
if (!fs.existsSync(UPLOAD_DIR)) fs.mkdirSync(UPLOAD_DIR, { recursive: true });

const db = new Database(process.env.DB_PATH || 'chat.db');
db.pragma('journal_mode = WAL');
db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    invite_code TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    public_key TEXT
  );
  CREATE TABLE IF NOT EXISTS invites (
    code TEXT PRIMARY KEY,
    used INTEGER NOT NULL DEFAULT 0,
    used_by TEXT,
    created_at INTEGER NOT NULL,
    created_by TEXT
  );
  CREATE TABLE IF NOT EXISTS offline_messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    msg_id TEXT,
    to_user TEXT NOT NULL,
    from_user TEXT NOT NULL,
    text TEXT,
    iv TEXT,
    ct TEXT,
    sender_pub_jwk TEXT,
    ts INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_offline_to ON offline_messages(to_user);

  CREATE TABLE IF NOT EXISTS dialogs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_a TEXT NOT NULL,
    user_b TEXT NOT NULL,
    last_message_at INTEGER NOT NULL,
    UNIQUE(user_a, user_b)
  );
  CREATE INDEX IF NOT EXISTS idx_dialogs_a ON dialogs(user_a);
  CREATE INDEX IF NOT EXISTS idx_dialogs_b ON dialogs(user_b);

  CREATE TABLE IF NOT EXISTS sessions (
    jti TEXT PRIMARY KEY,
    username TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    last_seen INTEGER NOT NULL,
    user_agent TEXT,
    ip TEXT,
    revoked INTEGER NOT NULL DEFAULT 0
  );
  CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(username);

  CREATE TABLE IF NOT EXISTS files (
    id TEXT PRIMARY KEY,
    owner TEXT NOT NULL,
    peer TEXT NOT NULL,
    size INTEGER NOT NULL,
    created_at INTEGER NOT NULL
  );
  CREATE INDEX IF NOT EXISTS idx_files_owner ON files(owner);
  CREATE INDEX IF NOT EXISTS idx_files_peer ON files(peer);
`);

{
  const cols = db.prepare('PRAGMA table_info(users)').all().map(c => c.name);
  if (!cols.includes('public_key')) { db.exec('ALTER TABLE users ADD COLUMN public_key TEXT'); console.log('migration: users.public_key'); }
}
{
  const cols = db.prepare('PRAGMA table_info(invites)').all().map(c => c.name);
  if (!cols.includes('created_by')) { db.exec('ALTER TABLE invites ADD COLUMN created_by TEXT'); console.log('migration: invites.created_by'); }
}
{
  const cols = db.prepare('PRAGMA table_info(offline_messages)').all().map(c => c.name);
  if (!cols.includes('iv')) { db.exec('ALTER TABLE offline_messages ADD COLUMN iv TEXT'); }
  if (!cols.includes('ct')) { db.exec('ALTER TABLE offline_messages ADD COLUMN ct TEXT'); }
  if (!cols.includes('sender_pub_jwk')) { db.exec('ALTER TABLE offline_messages ADD COLUMN sender_pub_jwk TEXT'); }
  const r = db.prepare('DELETE FROM offline_messages WHERE iv IS NULL OR ct IS NULL').run();
  if (r.changes > 0) console.log(`migration: removed ${r.changes} unencrypted offline messages`);
}

if (process.argv[2] === 'invite') {
  const code = crypto.randomBytes(6).toString('hex').toUpperCase();
  db.prepare('INSERT INTO invites (code, created_at) VALUES (?, ?)').run(code, Date.now());
  console.log('Invite code:', code);
  process.exit(0);
}
if (db.prepare('SELECT COUNT(*) AS c FROM invites').get().c === 0) {
  const code = crypto.randomBytes(6).toString('hex').toUpperCase();
  db.prepare('INSERT INTO invites (code, created_at) VALUES (?, ?)').run(code, Date.now());
  console.log('====================================');
  console.log('FIRST-RUN invite code:', code);
  console.log('====================================');
}

const signToken = (u, jti) => jwt.sign({ u, jti }, JWT_SECRET, { expiresIn: TOKEN_TTL });
const verifyToken = (t) => { try { return jwt.verify(t, JWT_SECRET); } catch { return null; } };

function authMiddleware(req, res, next) {
  const h = req.headers.authorization || '';
  const token = h.startsWith('Bearer ') ? h.slice(7) : null;
  const payload = token && verifyToken(token);
  if (!payload) return res.status(401).json({ error: 'unauthorized' });
  const s = db.prepare('SELECT revoked FROM sessions WHERE jti = ?').get(payload.jti);
  if (!s || s.revoked) return res.status(401).json({ error: 'session revoked' });
  db.prepare('UPDATE sessions SET last_seen = ? WHERE jti = ?').run(Date.now(), payload.jti);
  req.username = payload.u;
  req.jti = payload.jti;
  next();
}

const app = express();
app.use(express.json({ limit: '64kb' }));
app.use(express.static(path.join(__dirname, 'public')));

// ---------- Files (35 MB) ----------
app.use('/api/files/upload', express.raw({ type: 'application/octet-stream', limit: '40mb' }));

app.post('/api/files/upload', authMiddleware, (req, res) => {
  const peer = String(req.headers['x-peer'] || '').trim();
  if (!peer) return res.status(400).json({ error: 'X-Peer required' });
  if (!db.prepare('SELECT 1 FROM users WHERE username = ?').get(peer)) return res.status(404).json({ error: 'peer not found' });
  if (!Buffer.isBuffer(req.body) || req.body.length === 0) return res.status(400).json({ error: 'empty body' });
  if (req.body.length > MAX_FILE_SIZE_BODY) return res.status(413).json({ error: 'too large', max: MAX_FILE_SIZE });

  const id = crypto.randomUUID();
  const filePath = path.join(UPLOAD_DIR, id);
  try { fs.writeFileSync(filePath, req.body); }
  catch (e) { console.error('write file:', e); return res.status(500).json({ error: 'storage error' }); }
  db.prepare('INSERT INTO files (id, owner, peer, size, created_at) VALUES (?, ?, ?, ?, ?)')
    .run(id, req.username, peer, req.body.length, Date.now());
  res.json({ fileId: id, size: req.body.length });
});

app.get('/api/files/:fileId', authMiddleware, (req, res) => {
  const row = db.prepare('SELECT * FROM files WHERE id = ?').get(req.params.fileId);
  if (!row) return res.status(404).json({ error: 'not found' });
  if (row.owner !== req.username && row.peer !== req.username) return res.status(403).json({ error: 'forbidden' });
  const filePath = path.join(UPLOAD_DIR, row.id);
  if (!fs.existsSync(filePath)) return res.status(404).json({ error: 'file missing' });
  res.setHeader('Content-Type', 'application/octet-stream');
  res.setHeader('Content-Length', row.size);
  fs.createReadStream(filePath).pipe(res);
});

// ---------- Auth ----------
app.post('/api/register', (req, res) => {
  const { username, password, invite } = req.body || {};
  if (!username || !password || !invite) return res.status(400).json({ error: 'missing fields' });
  if (!/^[a-zA-Z0-9_]{3,32}$/.test(username)) return res.status(400).json({ error: 'invalid username' });
  if (String(password).length < 8) return res.status(400).json({ error: 'password too short (min 8)' });
  const inv = db.prepare('SELECT * FROM invites WHERE code = ?').get(String(invite).toUpperCase());
  if (!inv || inv.used) return res.status(400).json({ error: 'invalid or used invite' });
  if (db.prepare('SELECT 1 FROM users WHERE username = ?').get(username)) return res.status(409).json({ error: 'username taken' });
  const hash = bcrypt.hashSync(password, 10);
  db.transaction(() => {
    db.prepare('INSERT INTO users (username, password_hash, invite_code, created_at) VALUES (?, ?, ?, ?)').run(username, hash, inv.code, Date.now());
    db.prepare('UPDATE invites SET used = 1, used_by = ? WHERE code = ?').run(username, inv.code);
  })();
  const jti = crypto.randomUUID();
  db.prepare('INSERT INTO sessions (jti, username, created_at, last_seen, user_agent, ip) VALUES (?, ?, ?, ?, ?, ?)')
    .run(jti, username, Date.now(), Date.now(), String(req.headers['user-agent'] || '').slice(0, 200), req.ip || '');
  res.json({ token: signToken(username, jti), username });
});

app.post('/api/login', (req, res) => {
  const { username, password } = req.body || {};
  if (!username || !password) return res.status(400).json({ error: 'missing fields' });
  const row = db.prepare('SELECT * FROM users WHERE username = ?').get(username);
  if (!row || !bcrypt.compareSync(password, row.password_hash)) return res.status(401).json({ error: 'invalid credentials' });
  const jti = crypto.randomUUID();
  db.prepare('INSERT INTO sessions (jti, username, created_at, last_seen, user_agent, ip) VALUES (?, ?, ?, ?, ?, ?)')
    .run(jti, username, Date.now(), Date.now(), String(req.headers['user-agent'] || '').slice(0, 200), req.ip || '');
  res.json({ token: signToken(username, jti), username });
});

app.get('/api/me', authMiddleware, (req, res) => res.json({ username: req.username }));

app.get('/api/users', authMiddleware, (req, res) => {
  const rows = db.prepare(`
    SELECT u.username, u.public_key
    FROM users u
    JOIN dialogs d ON (
      (d.user_a = ? AND d.user_b = u.username) OR
      (d.user_b = ? AND d.user_a = u.username)
    )
    WHERE u.username != ?
    ORDER BY d.last_message_at DESC
  `).all(req.username, req.username, req.username);
  res.json(rows.map(r => ({ username: r.username, hasKey: !!r.public_key })));
});

app.get('/api/users/search', authMiddleware, (req, res) => {
  const q = String(req.query.q || '').trim();
  if (q.length < 2) return res.json([]);
  const rows = db.prepare(`
    SELECT username, public_key FROM users
    WHERE username LIKE ? AND username != ?
    ORDER BY username LIMIT 10
  `).all(`%${q}%`, req.username);
  res.json(rows.map(r => ({ username: r.username, hasKey: !!r.public_key })));
});

app.post('/api/keys', authMiddleware, (req, res) => {
  const { publicKey } = req.body || {};
  if (!publicKey || typeof publicKey !== 'object') return res.status(400).json({ error: 'invalid key' });
  if (publicKey.kty !== 'EC' || publicKey.crv !== 'P-256' || !publicKey.x || !publicKey.y) {
    return res.status(400).json({ error: 'unsupported key' });
  }
  db.prepare('UPDATE users SET public_key = ? WHERE username = ?').run(JSON.stringify(publicKey), req.username);
  res.json({ ok: true });
});

app.get('/api/keys/:username', authMiddleware, (req, res) => {
  const row = db.prepare('SELECT public_key FROM users WHERE username = ?').get(req.params.username);
  if (!row) return res.status(404).json({ error: 'user not found' });
  if (!row.public_key) return res.status(404).json({ error: 'no key published' });
  res.json({ publicKey: JSON.parse(row.public_key) });
});

app.get('/api/invites', authMiddleware, (req, res) => {
  const rows = db.prepare('SELECT code, used, used_by, created_at FROM invites WHERE created_by = ? ORDER BY created_at DESC').all(req.username);
  const active = rows.filter(r => !r.used).length;
  res.json({ invites: rows, limit: MAX_ACTIVE_INVITES, active });
});

app.post('/api/invites', authMiddleware, (req, res) => {
  const active = db.prepare('SELECT COUNT(*) AS c FROM invites WHERE created_by = ? AND used = 0').get(req.username).c;
  if (active >= MAX_ACTIVE_INVITES) return res.status(429).json({ error: `limit reached: ${MAX_ACTIVE_INVITES} active invites` });
  const code = crypto.randomBytes(6).toString('hex').toUpperCase();
  db.prepare('INSERT INTO invites (code, created_by, created_at) VALUES (?, ?, ?)').run(code, req.username, Date.now());
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

app.get('/api/sessions', authMiddleware, (req, res) => {
  const rows = db.prepare('SELECT jti, created_at, last_seen, user_agent, ip, revoked FROM sessions WHERE username = ? ORDER BY last_seen DESC').all(req.username);
  res.json(rows.map(r => ({ ...r, current: r.jti === req.jti })));
});
app.delete('/api/sessions/:jti', authMiddleware, (req, res) => {
  const r = db.prepare('UPDATE sessions SET revoked = 1 WHERE jti = ? AND username = ?').run(req.params.jti, req.username);
  if (r.changes === 0) return res.status(404).json({ error: 'not found' });
  res.json({ ok: true });
});
app.delete('/api/sessions', authMiddleware, (req, res) => {
  const r = db.prepare('UPDATE sessions SET revoked = 1 WHERE username = ? AND jti != ?').run(req.username, req.jti);
  res.json({ ok: true, revoked: r.changes });
});

// ---------- WebSocket ----------
const server = http.createServer(app);
const wss = new WebSocketServer({ server, path: '/ws' });

const sockets = new Map();
const addSocket = (u, ws) => { if (!sockets.has(u)) sockets.set(u, new Set()); sockets.get(u).add(ws); };
const removeSocket = (u, ws) => { const s = sockets.get(u); if (!s) return; s.delete(ws); if (s.size === 0) sockets.delete(u); };

function upsertDialog(u1, u2) {
  const [a, b] = [u1, u2].sort();
  db.prepare(`
    INSERT INTO dialogs (user_a, user_b, last_message_at)
    VALUES (?, ?, ?)
    ON CONFLICT(user_a, user_b) DO UPDATE SET last_message_at = excluded.last_message_at
  `).run(a, b, Date.now());
}

function deliverPending(ws, username) {
  const rows = db.prepare('SELECT id, msg_id, from_user, iv, ct, sender_pub_jwk, ts FROM offline_messages WHERE to_user = ? ORDER BY id').all(username);
  if (rows.length === 0) return;
  const ids = rows.map(r => r.id);
  const ph = ids.map(() => '?').join(',');
  db.prepare(`DELETE FROM offline_messages WHERE id IN (${ph})`).run(...ids);
  const myConns = sockets.get(username) || new Set([ws]);
  for (const m of rows) {
    const payload = JSON.stringify({ type: 'msg', from: m.from_user, iv: m.iv, ct: m.ct, senderPubJwk: m.sender_pub_jwk ? JSON.parse(m.sender_pub_jwk) : null, ts: m.ts, id: m.msg_id, offline: true });
    for (const s of myConns) if (s.readyState === s.OPEN) s.send(payload);
    const ss = sockets.get(m.from_user);
    if (ss) for (const s of ss) if (s.readyState === s.OPEN) s.send(JSON.stringify({ type: 'delivered', id: m.msg_id, to: username, late: true }));
  }
}

const closeEvents = new Map();
function recordClose(username) {
  const now = Date.now();
  if (!closeEvents.has(username)) closeEvents.set(username, []);
  const arr = closeEvents.get(username).filter(t => now - t < WS_ALERT_WINDOW);
  arr.push(now); closeEvents.set(username, arr);
  if (arr.length >= WS_ALERT_THRESHOLD) console.warn(`[ALERT] ${arr.length} ws closes for ${username}`);
}

wss.on('connection', (ws, req) => {
  const url = new URL(req.url, 'http://localhost');
  const payload = verifyToken(url.searchParams.get('token'));
  if (!payload) { ws.close(4001, 'unauthorized'); return; }
  const s = db.prepare('SELECT revoked FROM sessions WHERE jti = ?').get(payload.jti);
  if (!s || s.revoked) { ws.close(4001, 'session revoked'); return; }
  const username = payload.u;
  ws.username = username; ws.isAlive = true;
  ws.on('pong', () => { ws.isAlive = true; });
  addSocket(username, ws);
  ws.send(JSON.stringify({ type: 'ready', username }));
  try { deliverPending(ws, username); } catch (e) { console.error(e); }

  ws.on('message', (raw) => {
    let m; try { m = JSON.parse(raw.toString()); } catch { return; }
    if (!m || m.type !== 'msg') return;
    const to = String(m.to || '').trim();
    const iv = String(m.iv || '');
    const ct = String(m.ct || '');
    const senderJwk = m.senderPubJwk && typeof m.senderPubJwk === 'object' ? JSON.stringify(m.senderPubJwk) : null;
    if (!to || !iv || !ct || iv.length > 64 || ct.length > 30000) return;
    const msgId = m.id || crypto.randomUUID();
    const ts = Date.now();
    const out = JSON.stringify({ type: 'msg', from: username, iv, ct, senderPubJwk: senderJwk ? JSON.parse(senderJwk) : null, ts, id: msgId });
    const rs = sockets.get(to);
    upsertDialog(username, to);
    if (rs && rs.size > 0) {
      for (const r of rs) if (r.readyState === r.OPEN) r.send(out);
      ws.send(JSON.stringify({ type: 'delivered', id: msgId, to }));
    } else {
      db.prepare('INSERT INTO offline_messages (msg_id, to_user, from_user, iv, ct, sender_pub_jwk, ts) VALUES (?, ?, ?, ?, ?, ?, ?)').run(msgId, to, username, iv, ct, senderJwk, ts);
      ws.send(JSON.stringify({ type: 'queued', id: msgId, to }));
    }
  });

  ws.on('close', () => { recordClose(username); removeSocket(username, ws); });
  ws.on('error', () => removeSocket(username, ws));
});

const hb = setInterval(() => {
  for (const ws of wss.clients) {
    if (ws.isAlive === false) { try { ws.terminate(); } catch {} continue; }
    ws.isAlive = false; try { ws.ping(); } catch {}
  }
}, 30000);
wss.on('close', () => clearInterval(hb));

setInterval(() => {
  const cutoff = Date.now() - OFFLINE_TTL_MS;
  const r = db.prepare('DELETE FROM offline_messages WHERE ts < ?').run(cutoff);
  if (r.changes > 0) console.log(`cleanup: offline ${r.changes}`);
}, 60 * 60 * 1000);

setInterval(() => {
  const cutoff = Date.now() - FILES_TTL_MS;
  const old = db.prepare('SELECT id FROM files WHERE created_at < ?').all(cutoff);
  for (const r of old) {
    try { fs.unlinkSync(path.join(UPLOAD_DIR, r.id)); } catch {}
    db.prepare('DELETE FROM files WHERE id = ?').run(r.id);
  }
  if (old.length) console.log(`cleanup: files ${old.length}`);
}, 60 * 60 * 1000);

server.listen(PORT, '0.0.0.0', () => console.log(`minichat listening on :${PORT}`));