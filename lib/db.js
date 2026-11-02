// 数据库：打开 + 启动自检 + schema 迁移（从原 server.js 原样抽出）
const path = require('path');
const fs = require('fs');
const Database = require('better-sqlite3');
const { log, alert } = require('./log');

const DB_PATH = process.env.DB_PATH || path.join(__dirname, '..', 'clipbox.db');
// DB_PATH 父目录不存在时自动创建（避免容器/新环境启动即崩）
fs.mkdirSync(path.dirname(DB_PATH), { recursive: true });

// ---------- 启动自检（第一批）：DB 打开/合法性/可写性 ----------
// 必须在一切 DB 操作之前——损坏的库在 new Database 后第一条 PRAGMA 就会抛异常
let db;
try {
  db = new Database(DB_PATH);
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

// 邀请码表（多码：每人/每批独立发放，可单独作废/恢复）
db.exec(`CREATE TABLE IF NOT EXISTS invite_codes (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  code TEXT NOT NULL UNIQUE,
  label TEXT NOT NULL DEFAULT '',
  revoked INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL
)`);

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
  }
})();

module.exports = { db, DB_PATH, getSetting, setSetting };
