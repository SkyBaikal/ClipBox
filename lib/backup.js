// 备份：定时热备（better-sqlite3 backup API，在线执行不阻塞）+ AES-256-GCM 加密 + 保留策略
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { log } = require('./log');

const BACKUP_INTERVAL_MIN = parseInt(process.env.BACKUP_INTERVAL_MIN || '30', 10);
const BACKUP_DIR = process.env.BACKUP_DIR || path.join(__dirname, '..', 'backups');
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

function setupBackups(db) {
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
}

module.exports = { setupBackups, BACKUP_DIR, BACKUP_KEY, encryptBackup };
