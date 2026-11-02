// 管理接口：鉴权 + 统计/设置/邀请码/批量清理/备份/内容列表
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { log } = require('./log');

function setupAdmin(app, ctx) {
  const { db, getSetting, setSetting } = ctx.db;
  const { MAX_CLIPS_PER_IP, BACKUP_DIR, BACKUP_KEY, diskFreeMB, metrics } = ctx;

  // 管理接口鉴权（Bearer token）
  function requireAdmin(req, res, next) {
    if (!ctx.ADMIN_TOKEN) return res.status(403).json({ error: 'admin api disabled (set ADMIN_TOKEN)' });
    if (req.headers.authorization !== 'Bearer ' + ctx.ADMIN_TOKEN) {
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

  // ---------- 邀请码（多码管理） ----------
  app.get('/api/admin/invites', requireAdmin, (req, res) => {
    const invites = db.prepare('SELECT id, code, label, revoked, created_at FROM invite_codes ORDER BY created_at DESC').all();
    res.json({ invites });
  });

  app.post('/api/admin/invites', requireAdmin, (req, res) => {
    const code = String((req.body || {}).code || '').trim();
    const label = String((req.body || {}).label || '').trim().slice(0, 64);
    if (!/^[A-Za-z0-9_-]{4,64}$/.test(code)) {
      return res.status(400).json({ error: 'invite_code must be 4-64 chars [A-Za-z0-9_-]' });
    }
    try {
      db.prepare('INSERT INTO invite_codes (code, label, created_at) VALUES (?, ?, ?)').run(code, label, Date.now());
    } catch (e) {
      if (String(e.message).includes('UNIQUE')) return res.status(409).json({ error: 'invite code already exists' });
      throw e;
    }
    log('info', 'invite_created', {});
    res.json({ ok: true });
  });

  app.post('/api/admin/invites/:id', requireAdmin, (req, res) => {
    const op = (req.body || {}).op;
    if (op !== 'revoke' && op !== 'restore') return res.status(400).json({ error: 'op must be revoke|restore' });
    const n = db.prepare('UPDATE invite_codes SET revoked = ? WHERE id = ?').run(op === 'revoke' ? 1 : 0, req.params.id).changes;
    if (!n) return res.status(404).json({ error: 'not found' });
    log('info', 'invite_' + op, { id: req.params.id });
    res.json({ ok: true });
  });

  // ---------- 批量清理 ----------
  app.post('/api/admin/cleanup', requireAdmin, (req, res) => {
    const kind = (req.body || {}).kind;
    let sql;
    if (kind === 'expired') sql = 'DELETE FROM clips WHERE expires_at <= ?';
    else if (kind === 'burned') sql = "DELETE FROM clips WHERE burn = 1 AND read_count > 0";  // 已被读取的焚毁件残留
    else if (kind === 'all') sql = 'DELETE FROM clips';
    else return res.status(400).json({ error: 'kind must be expired|burned|all' });
    const n = kind === 'expired'
      ? db.prepare(sql).run(Date.now()).changes
      : db.prepare(sql).run().changes;
    log('info', 'admin_cleanup', { kind, removed: n });
    res.json({ deleted: n });
  });

  // ---------- 备份管理 ----------
  app.get('/api/admin/backups', requireAdmin, (req, res) => {
    const files = fs.readdirSync(BACKUP_DIR)
      .filter(f => f.startsWith('clipbox-') && (f.endsWith('.db') || f.endsWith('.db.enc')))
      .map(f => {
        const st = fs.statSync(path.join(BACKUP_DIR, f));
        return { name: f, size: st.size, mtime: st.mtimeMs };
      })
      .sort((a, b) => b.mtime - a.mtime);
    res.json({ backups: files });
  });

  app.post('/api/admin/backup', requireAdmin, (req, res) => {
    const target = path.join(BACKUP_DIR, `clipbox-manual-${Date.now()}.db`);
    db.backup(target)
      .then(() => {
        if (BACKUP_KEY) {
          const plain = fs.readFileSync(target);
          const iv = crypto.randomBytes(12);
          const c = crypto.createCipheriv('aes-256-gcm', BACKUP_KEY, iv);
          const ct = Buffer.concat([c.update(plain), c.final()]);
          fs.writeFileSync(target + '.enc', Buffer.concat([iv, c.getAuthTag(), ct]));
          fs.unlinkSync(target);
        }
        const finalName = path.basename(target) + (BACKUP_KEY ? '.enc' : '');
        log('info', 'backup_manual_ok', { file: finalName });
        res.json({ file: finalName });
      })
      .catch(e => {
        log('error', 'backup_manual_failed', { message: e.message });
        res.status(500).json({ error: e.message });
      });
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
}

module.exports = { setupAdmin };
