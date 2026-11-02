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
 *
 * 结构（v1.9 起模块化）：
 *   lib/log.js        结构化日志 + webhook 告警
 *   lib/db.js         DB 打开/自检/迁移 + settings KV
 *   lib/middleware.js CSP nonce/Origin 校验/静态托管/请求日志/限流
 *   lib/admin.js      /api/admin/* 管理接口
 *   lib/backup.js     定时加密备份
 *   server.js（本文件）装配 + clips API + 运维端点 + 页面路由 + 优雅关闭
 */
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const express = require('express');
const { log, alert } = require('./lib/log');
const { db, DB_PATH, getSetting, setSetting } = require('./lib/db');
const { setupCommon, writeLimiter, readLimiter, pwLimiter, clientIp, MAX_BODY } = require('./lib/middleware');
const { setupAdmin } = require('./lib/admin');
const { setupBackups, BACKUP_DIR, BACKUP_KEY } = require('./lib/backup');

const app = express();
const PORT = process.env.PORT || 3000;
const STARTED_AT = Date.now();
const VERSION = require('./package.json').version || '0.0.0';
const GIT_SHA = process.env.GIT_SHA || 'unknown';

const MAX_TTL_SECONDS = 7 * 24 * 3600; // 最长保留 7 天
const MAX_CLIPS_PER_IP = 20;           // 每 IP 存量上限
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || ''; // 管理接口令牌（未设置则禁用管理接口）

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

// ---------- 中间件 + 指标 ----------
const { metrics } = setupCommon(app);

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
  // 邀请码（多码模式，invite_codes 表；单码 settings 兼容迁移）：任一有效码即可创建
  const nActiveInvites = db.prepare('SELECT COUNT(*) AS n FROM invite_codes WHERE revoked = 0').get().n;
  if (nActiveInvites > 0) {
    const given = String((req.body || {}).invite_code || '');
    // 常量时间比对：取出全部有效码逐一 timingSafeEqual，避免 B-tree 查找时间随码值微变
    const codes = db.prepare('SELECT code FROM invite_codes WHERE revoked = 0').all();
    const givenBuf = Buffer.from(given);
    const ok = codes.some(c => {
      const cb = Buffer.from(c.code);
      return cb.length === givenBuf.length && crypto.timingSafeEqual(cb, givenBuf);
    });
    if (!ok) {
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
  const free = diskFreeMB();
  if (free >= 0) metrics.disk_free_mb = free; // 请求时即时刷新，消除 5 分钟巡检周期的冷启动窗口
  res.json({
    ...metrics,
    active_clips: db.prepare('SELECT COUNT(*) AS n FROM clips WHERE expires_at > ?').get(Date.now()).n,
    db_bytes: fs.existsSync(DB_PATH) ? fs.statSync(DB_PATH).size : 0,
    uptime_s: Math.round(process.uptime())
  });
});

// ---------- 管理接口（lib/admin.js） ----------
setupAdmin(app, { db: { db, getSetting, setSetting }, ADMIN_TOKEN, MAX_CLIPS_PER_IP, BACKUP_DIR, BACKUP_KEY, diskFreeMB, metrics });

// 每 5 分钟清理过期数据
setInterval(() => {
  const n = db.prepare('DELETE FROM clips WHERE expires_at < ?').run(Date.now()).changes;
  if (n) log('info', 'cleanup_expired', { removed: n });
}, 5 * 60 * 1000).unref();

// 定时热备
setupBackups(db);

// ---------- 页面路由 ----------
// 管理后台页（CSP nonce 由统一中间件注入）
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});
// 路径直达：/:id（6 位 62 字符集）直接返回查看页；首页 / 显式返回（express.static index:false）
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
