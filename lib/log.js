// 结构化日志（JSON lines，可被 log drains/采集器直接消费）+ webhook 告警
const ALERT_WEBHOOK_URL = process.env.ALERT_WEBHOOK_URL || '';
const alertCooldown = new Map(); // 同类告警 10 分钟内只发一次，防风暴

function log(level, event, fields = {}) {
  const line = JSON.stringify({ ts: new Date().toISOString(), level, event, ...fields });
  (level === 'error' ? console.error : console.log)(line);
}

async function alert(event, fields = {}) {
  if (!ALERT_WEBHOOK_URL) return;
  const last = alertCooldown.get(event) || 0;
  if (Date.now() - last < 10 * 60 * 1000) return;
  alertCooldown.set(event, Date.now());
  try {
    const body = JSON.stringify({ content: `[ClipBox] ${event}`, event, ...fields, ts: new Date().toISOString() });
    const mod = ALERT_WEBHOOK_URL.startsWith('https') ? require('https') : require('http');
    await new Promise((resolve, reject) => {
      const req = mod.request(ALERT_WEBHOOK_URL, { method: 'POST', headers: { 'Content-Type': 'application/json' } }, res => {
        res.resume();
        res.on('end', resolve);
      });
      req.on('error', reject);
      req.end(body);
    });
  } catch { return Promise.resolve(); /* 告警通道故障绝不影响主服务 */ }
}

module.exports = { log, alert };
