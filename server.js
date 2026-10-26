'use strict';
/**
 * ClipBox — 零知识在线剪切板
 * 服务端只存储客户端加密后的密文（AES-GCM），密钥永不离开浏览器。
 *
 * 安全边界：
 *  - 阅后即焚：读取一次即从 SQLite 删除
 *  - 过期：TTL 到期后由定时器清理
 *  - 限流：express-rate-limit 防扫描/滥用
 *  - 可选访问口令：服务端只存 PBKDF2 派生的验证哈希（明文口令不落盘）
 *  - 存储配额：每 IP 存量条数上限，防 SQLite 被塞爆
 */
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const express = require('express');
const rateLimit = require('express-rate-limit');
const Database = require('better-sqlite3');

const app = express();
const PORT = process.env.PORT || 3000;
const STARTED_AT = Date.now();
const VERSION = require('./package.json').version || '0.0.0';
const GIT_SHA = process.env.GIT_SHA || 'unknown';

// ---------- 结构化日志（JSON lines，可被 log drains/采集器直接消费） ----------
function log(level, event, fields = {}) {
  const line = JSON.stringify({ ts: new Date().toISOString(), level, event, ...fields });
  (level === 'error' ? console.error : console.log)(line);
}
const MAX_BODY = 64 * 1024;            // 密文上限 64KB
const MAX_TTL_SECONDS = 7 * 24 * 3600; // 最长保留 7 天
const MAX_CLIPS_PER_IP = 20;           // 每 IP 存量上限
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || ''; // 管理接口令牌（未设置则禁用管理接口）
// 反代信任：仅在明确设置 TRUST_PROXY=1（如 docker-compose + caddy 场景）时信任 X-Forwarded-For，
// 直连暴露公网时不信任，防止伪造 XFF 绕过限流/配额
if (process.env.TRUST_PROXY === '1') app.set('trust proxy', 1);
const BACKUP_INTERVAL_MIN = parseInt(process.env.BACKUP_INTERVAL_MIN || '30', 10);
const BACKUP_DIR = process.env.BACKUP_DIR || path.join(__dirname, 'backups');

const DB_PATH = process.env.DB_PATH || path.join(__dirname, 'clipbox.db');
// DB_PATH 父目录不存在时自动创建（避免容器/新环境启动即崩）
require('fs').mkdirSync(path.dirname(DB_PATH), { recursive: true });
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.exec(`
  CREATE TABLE IF NOT EXISTS clips (
    id TEXT PRIMARY KEY,
    ciphertext TEXT NOT NULL,
    burn INTEGER NOT NULL DEFAULT 0,
    expires_at INTEGER NOT NULL,
    ip TEXT NOT NULL DEFAULT '',
    pw_salt TEXT,
    pw_hash TEXT
  );
`);

// 旧库迁移：老表缺列则补上（CREATE TABLE IF NOT EXISTS 不会改既有表）
function addColumnIfMissing(table, col, ddl) {
  const cols = db.prepare(`PRAGMA table_info(${table})`).all().map(c => c.name);
  if (!cols.includes(col)) db.exec(`ALTER TABLE ${table} ADD COLUMN ${ddl}`);
}
addColumnIfMissing('clips', 'ip', `ip TEXT NOT NULL DEFAULT ''`);
addColumnIfMissing('clips', 'pw_salt', 'pw_salt TEXT');
addColumnIfMissing('clips', 'pw_hash', 'pw_hash TEXT');

// 索引必须在列迁移之后建（旧库的 ip 列由迁移补出）
db.exec(`
  CREATE INDEX IF NOT EXISTS idx_clips_expires ON clips (expires_at);
  CREATE INDEX IF NOT EXISTS idx_clips_ip ON clips (ip);
`);

app.use(express.json({ limit: MAX_BODY }));

// ---------- 安全响应头（CSP 等） ----------
app.use((req, res, next) => {
  res.set({
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
    // 本站无内联第三方脚本；qrcode 本地托管；style/script 允许内联（单文件前端）
    'Content-Security-Policy':
      "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'"
  });
  next();
});

// ---------- Origin 校验：写/管理类请求须同源（防其他网页滥用 API） ----------
// 无 Origin 头（curl、同源 GET 导航）放行；有 Origin 则必须匹配 Host
app.use((req, res, next) => {
  if (req.method === 'GET' || req.method === 'HEAD' || req.method === 'OPTIONS') return next();
  const origin = req.headers.origin;
  if (!origin) return next();
  const host = req.headers['x-forwarded-host'] || req.headers.host || '';
  try {
    if (new URL(origin).host !== host) {
      return res.status(403).json({ error: 'cross-origin write forbidden' });
    }
  } catch {
    return res.status(403).json({ error: 'bad origin' });
  }
  next();
});

app.use(express.static(path.join(__dirname, 'public')));

// ---------- 请求日志 + 指标（只记 ID/状态/耗时，绝不记密文或口令） ----------
const metrics = { requests: 0, errors_4xx: 0, errors_5xx: 0, creates: 0, reads: 0 };
app.use((req, res, next) => {
  const t0 = Date.now();
  res.on('finish', () => {
    metrics.requests++;
    if (res.statusCode >= 500) metrics.errors_5xx++;
    else if (res.statusCode >= 400) metrics.errors_4xx++;
    if (req.method === 'POST' && req.path === '/api/clips') metrics.creates++;
    if (req.method === 'POST' && req.path.endsWith('/read')) metrics.reads++;
    if (req.path.startsWith('/api/')) {
      log('info', 'http_request', {
        method: req.method, path: req.path, status: res.statusCode,
        ms: Date.now() - t0, ip: clientIp(req)
      });
    }
  });
  next();
});

// 请求超时：挂起的连接 30 秒断掉，防慢速攻击占资源
app.use((req, res, next) => { req.setTimeout(30000); next(); });

// 全局限流：每个 IP 每 15 分钟最多 100 次写 + 300 次读
const writeLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100 });
const readLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 300 });
// 口令尝试限流：防暴力猜口令，每 IP 每 15 分钟 30 次
const pwLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 30 });

function clientIp(req) {
  return (req.headers['x-forwarded-for'] || '').split(',')[0].trim() ||
         req.socket.remoteAddress || '';
}

// 生成 6 位短 ID：数字 + 大小写字母（62 字符集）
const ID_ALPHABET = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
const ID_LENGTH = 6;

function newId() {
  const bytes = crypto.randomBytes(ID_LENGTH);
  let id = '';
  for (const b of bytes) id += ID_ALPHABET[b % ID_ALPHABET.length];
  return id;
}

// 短 ID 撞车时重试（唯一约束冲突则换一个再插）
function insertClip(row) {
  const stmt = db.prepare(
    'INSERT INTO clips (id, ciphertext, burn, expires_at, ip, pw_salt, pw_hash) VALUES (?, ?, ?, ?, ?, ?, ?)'
  );
  for (let attempt = 0; attempt < 5; attempt++) {
    try {
      stmt.run(newId(), row.ciphertext, row.burn, row.expires_at, row.ip, row.pw_salt, row.pw_hash);
      return true;
    } catch (e) {
      if (!String(e.message).includes('UNIQUE')) throw e;
    }
  }
  return false;
}

// 口令 → PBKDF2 派生哈希（服务端只见哈希）
function derivePassword(pw, salt) {
  return crypto.pbkdf2Sync(pw, salt, 120000, 32, 'sha256').toString('hex');
}

// 创建
app.post('/api/clips', writeLimiter, (req, res) => {
  const { ciphertext, burn, ttl, password } = req.body || {};
  if (typeof ciphertext !== 'string' || !ciphertext.length) {
    return res.status(400).json({ error: 'ciphertext required' });
  }
  if (ciphertext.length > MAX_BODY) {
    return res.status(413).json({ error: 'too large' });
  }
  let ttlSeconds = parseInt(ttl, 10);
  if (!Number.isFinite(ttlSeconds) || ttlSeconds <= 0) ttlSeconds = 24 * 3600;
  ttlSeconds = Math.min(ttlSeconds, MAX_TTL_SECONDS);

  // 存储配额：每 IP 未过期存量上限
  const ip = clientIp(req);
  const used = db.prepare(
    'SELECT COUNT(*) AS n FROM clips WHERE ip = ? AND expires_at > ?'
  ).get(ip, Date.now()).n;
  if (used >= MAX_CLIPS_PER_IP) {
    return res.status(429).json({ error: `quota exceeded (max ${MAX_CLIPS_PER_IP} active clips)` });
  }

  // 可选口令：明文不落盘，只存 PBKDF2 哈希
  let pw_salt = null, pw_hash = null;
  if (typeof password === 'string' && password.length) {
    if (password.length < 4 || password.length > 128) {
      return res.status(400).json({ error: 'password must be 4-128 chars' });
    }
    pw_salt = crypto.randomBytes(16).toString('hex');
    pw_hash = derivePassword(password, pw_salt);
  }

  const expiresAt = Date.now() + ttlSeconds * 1000;
  const ok = insertClip({ ciphertext, burn: burn ? 1 : 0, expires_at: expiresAt, ip, pw_salt, pw_hash });
  if (!ok) return res.status(500).json({ error: 'id collision' });
  const id = db.prepare('SELECT id FROM clips WHERE rowid = last_insert_rowid()').get().id;
  res.json({ id, expires_at: expiresAt, protected: !!pw_hash });
});

// 读取（阅后即焚：读后即删，事务保证原子性；带口令需验证）
// 口令通过 POST body 传递，不走 URL query（避免进访问日志/浏览器历史）
app.post('/api/clips/:id/read', readLimiter, pwLimiter, (req, res) => {
  const row = db.prepare('SELECT * FROM clips WHERE id = ?').get(req.params.id);
  if (!row) return res.status(404).json({ error: 'not found or expired' });
  if (Date.now() > row.expires_at) {
    db.prepare('DELETE FROM clips WHERE id = ?').run(row.id);
    return res.status(404).json({ error: 'not found or expired' });
  }
  // 口令校验（timingSafeEqual 防时序侧信道）
  if (row.pw_hash) {
    const pw = String((req.body || {}).pw || '');
    const calc = derivePassword(pw, row.pw_salt);
    const a = Buffer.from(calc, 'hex'), b = Buffer.from(row.pw_hash, 'hex');
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
      return res.status(401).json({ error: 'password required or wrong', protected: true });
    }
  }
  if (row.burn) db.prepare('DELETE FROM clips WHERE id = ?').run(row.id);
  res.json({ ciphertext: row.ciphertext, burn: !!row.burn, protected: !!row.pw_hash });
});

// ---------- 运维端点 ----------

// 健康检查（供反代/监控）
app.get('/healthz', (req, res) => {
  const n = db.prepare('SELECT COUNT(*) AS n FROM clips').get().n;
  res.json({ ok: true, clips: n, uptime_s: Math.round(process.uptime()) });
});

// 版本端点（部署核对用）
app.get('/versionz', (req, res) => {
  res.json({ version: VERSION, git_sha: GIT_SHA, started_at: new Date(STARTED_AT).toISOString() });
});

// 指标端点（供监控拉取；无敏感数据）
app.get('/metricsz', (req, res) => {
  res.json({
    ...metrics,
    active_clips: db.prepare('SELECT COUNT(*) AS n FROM clips WHERE expires_at > ?').get(Date.now()).n,
    db_bytes: fs.existsSync(DB_PATH) ? fs.statSync(DB_PATH).size : 0,
    uptime_s: Math.round(process.uptime())
  });
});

// 管理接口鉴权（Bearer token）
function requireAdmin(req, res, next) {
  if (!ADMIN_TOKEN) return res.status(403).json({ error: 'admin api disabled (set ADMIN_TOKEN)' });
  if (req.headers.authorization !== 'Bearer ' + ADMIN_TOKEN) {
    return res.status(401).json({ error: 'unauthorized' });
  }
  next();
}

// 存量统计
app.get('/api/admin/stats', requireAdmin, (req, res) => {
  const total = db.prepare('SELECT COUNT(*) AS n FROM clips').get().n;
  const active = db.prepare('SELECT COUNT(*) AS n FROM clips WHERE expires_at > ?').get(Date.now()).n;
  const burning = db.prepare('SELECT COUNT(*) AS n FROM clips WHERE burn = 1').get().n;
  const bytes = db.prepare('SELECT SUM(LENGTH(ciphertext)) AS b FROM clips').get().b || 0;
  res.json({ total, active, burning, ciphertext_bytes: bytes, max_per_ip: MAX_CLIPS_PER_IP });
});

// 列出 ID（只列元数据，绝不返回密文）
app.get('/api/admin/list', requireAdmin, (req, res) => {
  const rows = db.prepare(
    'SELECT id, burn, expires_at, LENGTH(ciphertext) AS size, (pw_hash IS NOT NULL) AS protected FROM clips ' +
    'ORDER BY expires_at DESC LIMIT 500'
  ).all();
  res.json({ count: rows.length, clips: rows });
});

// 删除指定 / 清空全部
app.delete('/api/admin/clips/:id', requireAdmin, (req, res) => {
  const n = db.prepare('DELETE FROM clips WHERE id = ?').run(req.params.id).changes;
  res.json({ deleted: n });
});
app.delete('/api/admin/clips', requireAdmin, (req, res) => {
  const n = db.prepare('DELETE FROM clips').run().changes;
  res.json({ deleted: n });
});

// 每 5 分钟清理过期数据
setInterval(() => {
  const n = db.prepare('DELETE FROM clips WHERE expires_at < ?').run(Date.now()).changes;
  if (n) log('info', 'cleanup_expired', { removed: n });
}, 5 * 60 * 1000).unref();

// 路径直达：/:id（6 位 62 字符集）直接返回查看页；其余 404 到 API
app.get('/:id([A-Za-z0-9]{6})', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const server = app.listen(PORT, () => {
  log('info', 'server_started', { port: PORT, version: VERSION, admin_api: !!ADMIN_TOKEN });
});

// ---------- 稳定性：统一错误处理 + 优雅关闭 ----------

// 统一 JSON 错误响应（畸形 JSON 等不再返回 HTML 错误页）
// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  const isBodyParse = err.type === 'entity.parse.failed' || err.type === 'entity.too.large';
  if (!isBodyParse) log('error', 'unhandled_error', { message: err.message, path: req.path });
  if (res.headersSent) return;
  res.status(err.statusCode || (isBodyParse ? 400 : 500))
     .json({ error: isBodyParse ? 'bad request' : 'internal error' });
});

// 优雅关闭：先停收新请求，再 checkpoint + 关库，避免 WAL 数据滞留
let shuttingDown = false;
function shutdown(signal) {
  if (shuttingDown) return;
  shuttingDown = true;
  log('info', 'shutdown', { signal });
  server.close(() => {
    try {
      db.pragma('wal_checkpoint(TRUNCATE)');
      db.close();
      log('info', 'db_closed_cleanly', {});
    } catch (e) {
      log('error', 'db_close_error', { message: e.message });
    }
    process.exit(0);
  });
  // 10 秒强退兜底
  setTimeout(() => process.exit(0), 10000).unref();
}
process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT', () => shutdown('SIGINT'));

// ---------- 定时热备（better-sqlite3 backup API，可在线执行不阻塞） ----------
fs.mkdirSync(BACKUP_DIR, { recursive: true });
setInterval(() => {
  const target = path.join(BACKUP_DIR, `clipbox-${new Date().toISOString().slice(0, 10)}.db`);
  db.backup(target)
    .then(() => log('info', 'backup_ok', { target }))
    .catch(e => log('error', 'backup_failed', { message: e.message }));
  // 只保留最近 7 个备份
  const files = fs.readdirSync(BACKUP_DIR).filter(f => f.startsWith('clipbox-') && f.endsWith('.db')).sort();
  while (files.length > 7) {
    const old = files.shift();
    try { fs.unlinkSync(path.join(BACKUP_DIR, old)); } catch {}
  }
}, BACKUP_INTERVAL_MIN * 60 * 1000).unref();

