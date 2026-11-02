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

// ---------- 告警（webhook：兼容 Slack/钉钉/飞书/自建接收端，未配置则静默跳过） ----------
// ALERT_WEBHOOK_URL 配置后，error 级事件与关键告警会 POST JSON 过去（fire-and-forget，不阻塞主流程）
const ALERT_WEBHOOK_URL = process.env.ALERT_WEBHOOK_URL || '';
const alertCooldown = new Map(); // 同类告警 10 分钟内只发一次，防风暴
function alert(event, fields = {}) {
  log('error', event, fields);
  if (!ALERT_WEBHOOK_URL) return Promise.resolve();
  const key = event + JSON.stringify(fields).slice(0, 50);
  const last = alertCooldown.get(key) || 0;
  if (Date.now() - last < 10 * 60 * 1000) return Promise.resolve();
  alertCooldown.set(key, Date.now());
  const payload = JSON.stringify({
    text: `[ClipBox] ${event} ${JSON.stringify(fields)} @ ${new Date().toISOString()}`
  });
  try {
    // 用 http/https 原生模块，不引新依赖；3 秒超时，失败仅记日志。
    // 返回 Promise：致命场景（启动自检失败）可 await 发完再退出。
    const mod = ALERT_WEBHOOK_URL.startsWith('https') ? require('https') : require('http');
    return new Promise(resolve => {
      const req = mod.request(ALERT_WEBHOOK_URL, { method: 'POST', timeout: 3000,
        headers: { 'Content-Type': 'application/json' } }, () => {});
      req.on('error', () => { log('warn', 'alert_send_failed', {}); resolve(); });
      req.on('timeout', () => { req.destroy(); });
      req.end(payload, () => resolve());
    });
  } catch { return Promise.resolve(); /* 告警通道故障绝不影响主服务 */ }
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

// ---------- 启动自检（第一批）：DB 打开/合法性/可写性 ----------
// 必须在一切 DB 操作之前——损坏的库在 new Database 后第一条 PRAGMA 就会抛异常
try {
  var db = new Database(DB_PATH);
  db.pragma('journal_mode = WAL');
  db.pragma('quick_check', { simple: true }); // 损坏库此处抛 SqliteError
  db.exec('CREATE TEMP TABLE IF NOT EXISTS _selfcheck(x INTEGER); DROP TABLE IF EXISTS _selfcheck;');
  log('info', 'startup_db_open_ok', { db_path: DB_PATH });
} catch (e) {
  alert('startup_selfcheck_failed', { message: e.message, db_path: DB_PATH })
    .finally(() => {
      console.error('[fatal] 启动自检失败：数据库不可用，退出以交给进程管理器重启策略');
      process.exit(1);
    });
  return; // 关键：阻断后续 DB 操作，等待告警发完由 finally 退出
}

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
addColumnIfMissing('clips', 'del_token_hash', 'del_token_hash TEXT');
addColumnIfMissing('clips', 'max_reads', 'max_reads INTEGER NOT NULL DEFAULT 0');
addColumnIfMissing('clips', 'read_count', 'read_count INTEGER NOT NULL DEFAULT 0');
addColumnIfMissing('clips', 'pw_rounds', 'pw_rounds INTEGER NOT NULL DEFAULT 120000');

// 运营设置（KV）：邀请码等运行时可改的配置（管理后台读写，无需重启）
db.exec('CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT)');
function getSetting(key) {
  const row = db.prepare('SELECT value FROM settings WHERE key = ?').get(key);
  return row ? row.value : null;
}
function setSetting(key, value) {
  db.prepare('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value')
    .run(key, value);
}

// 索引必须在列迁移之后建（旧库的 ip 列由迁移补出）
db.exec(`
  CREATE INDEX IF NOT EXISTS idx_clips_expires ON clips (expires_at);
  CREATE INDEX IF NOT EXISTS idx_clips_ip ON clips (ip);
`);

// ---------- 启动自检（第二批）：深层完整性（迁移之后） ----------
(function startupSelfCheck2() {
  try {
    const integrity = db.pragma('quick_check', { simple: true });
    if (integrity !== 'ok') throw new Error(`sqlite quick_check: ${integrity}`);
    log('info', 'startup_selfcheck_ok', { db_path: DB_PATH });
  } catch (e) {
    alert('startup_selfcheck_failed', { message: e.message, db_path: DB_PATH })
      .finally(() => {
        console.error('[fatal] 启动自检失败：数据库不可用，退出以交给进程管理器重启策略');
        process.exit(1);
      });
    return;
  }
})();

// ---------- 磁盘水位监控（每 5 分钟检查；低于阈值拒绝写入并告警，防 SQLite 写满盘报错） ----------
const DISK_MIN_FREE_MB = parseInt(process.env.DISK_MIN_FREE_MB || '100', 10);
let diskLowNotified = false;
function diskFreeMB() {
  try {
    const stat = fs.statfsSync(path.dirname(DB_PATH));
    return Math.round((stat.bavail * stat.bsize) / (1024 * 1024));
  } catch { return -1; } // 平台不支持时跳过检查
}
setInterval(() => {
  const free = diskFreeMB();
  if (free < 0) return;
  metrics.disk_free_mb = free;
  if (free < DISK_MIN_FREE_MB && !diskLowNotified) {
    diskLowNotified = true;
    alert('disk_low', { free_mb: free, threshold_mb: DISK_MIN_FREE_MB });
  } else if (free >= DISK_MIN_FREE_MB && diskLowNotified) {
    diskLowNotified = false; // 恢复后重置，允许下次低水位再告警
    log('info', 'disk_recovered', { free_mb: free });
  }
}, 5 * 60 * 1000).unref();

app.use(express.json({ limit: MAX_BODY }));

// ---------- 安全响应头（CSP 等）----------
// script 用 per-request nonce（消除 'unsafe-inline'）；style 保留 unsafe-inline（单文件前端的内联样式，风险低）
const nonces = new WeakMap();
app.use((req, res, next) => {
  const nonce = crypto.randomBytes(16).toString('base64');
  nonces.set(res, nonce);
  res.set({
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'no-referrer',
    'Content-Security-Policy':
      `default-src 'self'; script-src 'self' 'nonce-${nonce}'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'`
  });
  next();
});

// 给 HTML 响应注入 nonce（其内联 <script> 才能通过 CSP）
// 覆盖两条路径：express.static 的 index.html 和显式 sendFile 的 /:id 页面
app.use((req, res, next) => {
  const origSend = res.send.bind(res);
  res.send = (body) => {
    const nonce = nonces.get(res);
    if (nonce && typeof body === 'string' && body.includes('<script>') && !body.includes('nonce=')) {
      body = body.replace(/<script>/g, `<script nonce="${nonce}">`);
    }
    return origSend(body);
  };
  const origSendFile = res.sendFile.bind(res);
  res.sendFile = (p, opts, cb) => {
    const nonce = nonces.get(res);
    if (!nonce || !String(p).endsWith('.html')) return origSendFile(p, opts, cb);
    const html = fs.readFileSync(p, 'utf8').replace(/<script>/g, `<script nonce="${nonce}">`);
    res.set('Content-Type', 'text/html; charset=UTF-8');
    res.set('Cache-Control', 'no-store');   // nonce 每请求不同，禁止缓存
    res.send(html);
  };
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

app.use(express.static(path.join(__dirname, 'public'), {
  index: false,           // 首页由下方显式路由处理（需要注入 CSP nonce）
  etag: true,
  setHeaders: (res, p) => {
    // HTML 由路由注入 nonce，这里不做缓存避免 nonce 复用
    if (p.endsWith('.html')) res.set('Cache-Control', 'no-store');
  }
}));

// ---------- 请求日志 + 指标（只记 ID/状态/耗时，绝不记密文或口令） ----------
const metrics = { requests: 0, errors_4xx: 0, errors_5xx: 0, creates: 0, reads: 0, disk_free_mb: -1 };
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
    'INSERT INTO clips (id, ciphertext, burn, expires_at, ip, pw_salt, pw_hash, del_token_hash, max_reads, read_count, pw_rounds) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)'
  );
  for (let attempt = 0; attempt < 5; attempt++) {
    try {
      stmt.run(newId(), row.ciphertext, row.burn, row.expires_at, row.ip, row.pw_salt, row.pw_hash, row.del_token_hash, row.max_reads || 0, row.read_count || 0, row.pw_rounds || PBKDF2_ROUNDS);
      return true;
    } catch (e) {
      if (!String(e.message).includes('UNIQUE')) throw e;
    }
  }
  return false;
}

// 口令 → PBKDF2 派生哈希。异步版（worker 线程池执行，不阻塞事件循环）：
// 轮数按 OWASP 2023 建议 60 万（原 12 万为吞吐妥协，2026 GPU 破解成本已不足，提升）。
// 兼容说明：旧 clip 存的 12 万轮哈希用 PBKDF2_ROUNDS_LEGACY 校验，新写入一律 60 万。
const PBKDF2_ROUNDS = parseInt(process.env.PBKDF2_ROUNDS || '600000', 10);
const PBKDF2_ROUNDS_LEGACY = 120000;
function pbkdf2Async(pw, salt, rounds) {
  return new Promise((resolve, reject) => {
    crypto.pbkdf2(pw, salt, rounds, 32, 'sha256', (err, key) =>
      err ? reject(err) : resolve(key.toString('hex')));
  });
}
async function derivePassword(pw, salt, rounds = PBKDF2_ROUNDS) {
  return pbkdf2Async(pw, salt, rounds);
}

// 创建（async：口令 PBKDF2 异步派生）
app.post('/api/clips', writeLimiter, async (req, res) => {
  const { ciphertext, burn, ttl, password } = req.body || {};
  if (typeof ciphertext !== 'string' || !ciphertext.length) {
    return res.status(400).json({ error: 'ciphertext required' });
  }
  if (ciphertext.length > MAX_BODY) {
    return res.status(413).json({ error: 'too large' });
  }
  // 邀请码（运营设置，管理后台可开关）：设置后创建需携带正确 invite_code，读取不受限
  const invite = getSetting('invite_code');
  if (invite) {
    const given = String((req.body || {}).invite_code || '');
    const a = Buffer.from(given), b = Buffer.from(invite);
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
      return res.status(403).json({ error: 'invite code required or wrong', invite_required: true });
    }
  }
  let ttlSeconds = parseInt(ttl, 10);
  if (!Number.isFinite(ttlSeconds) || ttlSeconds <= 0) ttlSeconds = 24 * 3600;
  ttlSeconds = Math.min(ttlSeconds, MAX_TTL_SECONDS);

  // 磁盘水位保护：低于阈值拒绝新写入（已有内容读取不受影响）
  const freeMB = diskFreeMB();
  if (freeMB >= 0 && freeMB < DISK_MIN_FREE_MB) {
    return res.status(503).json({ error: 'service degraded: disk low, write temporarily disabled' });
  }

  // 存储配额：每 IP 未过期存量上限
  const ip = clientIp(req);
  const used = db.prepare(
    'SELECT COUNT(*) AS n FROM clips WHERE ip = ? AND expires_at > ?'
  ).get(ip, Date.now()).n;
  if (used >= MAX_CLIPS_PER_IP) {
    return res.status(429).json({ error: `quota exceeded (max ${MAX_CLIPS_PER_IP} active clips)` });
  }

  // 可选口令：明文不落盘，只存 PBKDF2 哈希（异步派生，不阻塞事件循环）
  let pw_salt = null, pw_hash = null;
  if (typeof password === 'string' && password.length) {
    if (password.length < 4 || password.length > 128) {
      return res.status(400).json({ error: 'password must be 4-128 chars' });
    }
    pw_salt = crypto.randomBytes(16).toString('hex');
    pw_hash = await derivePassword(password, pw_salt);
  }

  // 可选阅读次数上限（max_reads）：0/缺省 = 不限；1 等价阅后即焚的次数语义
  let maxReads = parseInt(req.body && req.body.max_reads, 10);
  if (!Number.isFinite(maxReads) || maxReads < 0) maxReads = 0;
  maxReads = Math.min(maxReads, 1000);

  const expiresAt = Date.now() + ttlSeconds * 1000;
  // 创建者自删令牌：明文只在创建响应里出现一次，服务端只存 SHA-256 哈希
  const delToken = crypto.randomBytes(24).toString('hex');
  const delTokenHash = crypto.createHash('sha256').update(delToken).digest('hex');
  const ok = insertClip({ ciphertext, burn: burn ? 1 : 0, expires_at: expiresAt, ip, pw_salt, pw_hash, del_token_hash: delTokenHash, max_reads: maxReads, read_count: 0 });
  if (!ok) return res.status(500).json({ error: 'id collision' });
  const id = db.prepare('SELECT id FROM clips WHERE rowid = last_insert_rowid()').get().id;
  res.json({ id, expires_at: expiresAt, protected: !!pw_hash, delete_token: delToken, max_reads: maxReads || null });
});

// 创建者自删：凭删除令牌（body 传递，不进 URL/日志）；令牌哈希比对，误删有口令的内容仍需先过口令吗——不需要，删除不暴露密文
app.delete('/api/clips/:id', writeLimiter, (req, res) => {
  const token = String((req.body || {}).delete_token || '');
  if (!/^[0-9a-f]{48}$/.test(token)) return res.status(400).json({ error: 'delete_token required' });
  const row = db.prepare('SELECT id, del_token_hash FROM clips WHERE id = ?').get(req.params.id);
  if (!row || !row.del_token_hash) return res.status(404).json({ error: 'not found' });
  const calc = crypto.createHash('sha256').update(token).digest('hex');
  // 两侧都是 hex 字符串 → 按 utf8 编码比较（与口令校验一致）；digest('hex') 的 Buffer 是原始 32 字节，与 utf8 不匹配会永远失败
  const a = Buffer.from(calc), b = Buffer.from(row.del_token_hash);
  if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
    return res.status(403).json({ error: 'wrong delete token' });
  }
  db.prepare('DELETE FROM clips WHERE id = ?').run(row.id);
  log('info', 'clip_deleted_by_owner', { id: row.id });
  res.json({ deleted: true });
});

// 读取（阅后即焚/次数上限：读后计数或即删；带口令需验证；async：口令异步派生）
// 口令通过 POST body 传递，不走 URL query（避免进访问日志/浏览器历史）
app.post('/api/clips/:id/read', readLimiter, pwLimiter, async (req, res) => {
  const row = db.prepare('SELECT * FROM clips WHERE id = ?').get(req.params.id);
  if (!row) return res.status(404).json({ error: 'not found or expired' });
  if (Date.now() > row.expires_at) {
    db.prepare('DELETE FROM clips WHERE id = ?').run(row.id);
    return res.status(404).json({ error: 'not found or expired' });
  }
  // 口令校验（timingSafeEqual 防时序侧信道；按该 clip 存档的轮数派生，兼容 12 万旧数据）
  if (row.pw_hash) {
    const pw = String((req.body || {}).pw || '');
    const rounds = row.pw_rounds || PBKDF2_ROUNDS_LEGACY;
    const calc = await derivePassword(pw, row.pw_salt, rounds);
    const a = Buffer.from(calc, 'hex'), b = Buffer.from(row.pw_hash, 'hex');
    if (a.length !== b.length || !crypto.timingSafeEqual(a, b)) {
      return res.status(401).json({ error: 'password required or wrong', protected: true });
    }
  }
  // 次数上限：递增后超限则拒绝并删除（原子事务，防并发超额读）
  if (row.max_reads > 0) {
    const exceeded = db.transaction(() => {
      const n = db.prepare('UPDATE clips SET read_count = read_count + 1 WHERE id = ? AND read_count < max_reads').run(row.id).changes;
      if (!n) return true;
      // 达到上限：本次是最后一次允许的读取（已计数），删除内容（下次读取 404）
      const cur = db.prepare('SELECT read_count FROM clips WHERE id = ?').get(row.id);
      if (cur && cur.read_count >= row.max_reads) db.prepare('DELETE FROM clips WHERE id = ?').run(row.id);
      return false;
    })();
    if (exceeded) return res.status(404).json({ error: 'read limit exceeded' });
  } else if (row.burn) {
    db.prepare('DELETE FROM clips WHERE id = ?').run(row.id);
  }
  res.json({ ciphertext: row.ciphertext, burn: !!(row.burn || row.max_reads === 1), protected: !!row.pw_hash });
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

// 运营设置：读取（邀请码状态；明文只在管理接口返回）
app.get('/api/admin/settings', requireAdmin, (req, res) => {
  const invite = getSetting('invite_code');
  res.json({ invite_code: invite || '', invite_enabled: !!invite });
});

// 运营设置：更新（invite_code 传空字符串 = 关闭邀请码）
app.post('/api/admin/settings', requireAdmin, (req, res) => {
  const code = String((req.body || {}).invite_code || '').trim();
  if (code) {
    if (code.length < 4 || code.length > 64) {
      return res.status(400).json({ error: 'invite_code must be 4-64 chars' });
    }
    setSetting('invite_code', code);
    log('info', 'settings_invite_enabled', {});
  } else {
    db.prepare('DELETE FROM settings WHERE key = ?').run('invite_code');
    log('info', 'settings_invite_disabled', {});
  }
  res.json({ invite_enabled: !!code });
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

// 管理后台页（静态托管提供 /admin；CSP nonce 由统一中间件注入）
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});

// 路径直达：/:id（6 位 62 字符集）直接返回查看页；其余 404 到 API
// 首页 / 同样显式返回（express.static index:false），统一走 sendFile 注入 nonce
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});
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
// 备份加密：设置 BACKUP_KEY（32 字节 hex 或任意口令）后，备份以 AES-256-GCM 加密落盘（拖库场景备份不裸奔）
const BACKUP_KEY_RAW = process.env.BACKUP_KEY || '';
const BACKUP_KEY = BACKUP_KEY_RAW
  ? crypto.createHash('sha256').update(BACKUP_KEY_RAW).digest() // 任意口令归一成 32 字节密钥
  : null;
function encryptBackup(buf) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', BACKUP_KEY, iv);
  const ct = Buffer.concat([cipher.update(buf), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), ct]); // 格式：iv(12) + tag(16) + ciphertext
}
setInterval(() => {
  const target = path.join(BACKUP_DIR, `clipbox-${new Date().toISOString().slice(0, 10)}.db`);
  const finalTarget = BACKUP_KEY ? target + '.enc' : target;
  db.backup(target)
    .then(() => {
      if (!BACKUP_KEY) { log('info', 'backup_ok', { target }); return; }
      // 加密后删除明文临时文件
      const plain = fs.readFileSync(target);
      fs.writeFileSync(finalTarget, encryptBackup(plain));
      fs.unlinkSync(target);
      log('info', 'backup_ok_encrypted', { target: finalTarget });
    })
    .catch(e => log('error', 'backup_failed', { message: e.message }));
  // 只保留最近 7 个备份（含 .enc）
  const files = fs.readdirSync(BACKUP_DIR)
    .filter(f => f.startsWith('clipbox-') && (f.endsWith('.db') || f.endsWith('.db.enc')))
    .sort();
  while (files.length > 7) {
    const old = files.shift();
    try { fs.unlinkSync(path.join(BACKUP_DIR, old)); } catch {}
  }
}, BACKUP_INTERVAL_MIN * 60 * 1000).unref();

