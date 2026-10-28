#!/usr/bin/env bash
# ClipBox 备份恢复脚本（备份恢复演练用：没演练过的备份等于没有备份）
# 用法：
#   BACKUP_KEY=xxx ./scripts/restore.sh backups/clipbox-2026-01-01.db.enc   # 解密并验证
#   BACKUP_KEY=xxx ./scripts/restore.sh backups/clipbox-2026-01-01.db.enc ./restored.db
#   ./scripts/restore.sh backups/clipbox-2026-01-01.db ./restored.db        # 明文备份
set -euo pipefail

SRC="${1:?用法: restore.sh <backup.db[.enc]> [目标.db]}"
KEY="${BACKUP_KEY:-}"
DEST="${2:-}"

command -v node >/dev/null || { echo "需要 node"; exit 1; }

node - "$SRC" "$KEY" "$DEST" << 'EOF'
const crypto = require('crypto'), fs = require('fs'), path = require('path');
const [src, keyRaw, destArg] = process.argv.slice(2);
const Database = require(path.join(process.cwd(), 'node_modules', 'better-sqlite3'));

let dbFile = src;
if (src.endsWith('.enc')) {
  if (!keyRaw) { console.error('[fatal] 加密备份需要 BACKUP_KEY 环境变量'); process.exit(1); }
  const buf = fs.readFileSync(src);
  if (buf.length < 28) { console.error('[fatal] 备份文件损坏（过短）'); process.exit(1); }
  const iv = buf.subarray(0, 12), tag = buf.subarray(12, 28), ct = buf.subarray(28);
  const key = crypto.createHash('sha256').update(keyRaw).digest();
  let plain;
  try {
    const d = crypto.createDecipheriv('aes-256-gcm', key, iv);
    d.setAuthTag(tag);
    plain = Buffer.concat([d.update(ct), d.final()]);   // GCM tag 校验失败会在此抛异常
  } catch {
    console.error('[fatal] 解密失败：密钥错误或备份被篡改（GCM 校验不过）');
    process.exit(1);
  }
  dbFile = destArg || src.replace(/\.enc$/, '') + '.restored';
  fs.writeFileSync(dbFile, plain);
  console.log('[ok] 解密成功 →', dbFile);
} else {
  dbFile = destArg || src;
  if (destArg) fs.copyFileSync(src, destArg);
}

// 完整性 + 内容可用性验证（quick_check + 能查询 clips 表）
const db = new Database(dbFile, { readonly: true });
const check = db.pragma('quick_check', { simple: true });
if (check !== 'ok') { console.error('[fatal] 恢复的数据库损坏:', check); process.exit(1); }
const n = db.prepare('SELECT COUNT(*) AS n FROM clips').get().n;
console.log('[ok] 完整性校验通过，clips 行数:', n);
db.close();
console.log('[done] 备份恢复演练成功 ✅  数据库文件:', dbFile);
console.log('     恢复流程: 停服务 → 用此文件替换 clipbox.db → 启动服务');
EOF
