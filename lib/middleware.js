// 通用中间件：CSP/nonce、Origin 校验、静态托管、请求日志/指标、限流、IP 提取
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const express = require('express');
const rateLimit = require('express-rate-limit');
const { log } = require('./log');

const MAX_BODY = 64 * 1024; // 密文上限 64KB

function setupCommon(app) {
  // 反代信任：仅在明确设置 TRUST_PROXY=1（如 docker-compose + caddy 场景）时信任 X-Forwarded-For，
  // 直连暴露公网时不信任，防止伪造 XFF 绕过限流/配额
  if (process.env.TRUST_PROXY === '1') app.set('trust proxy', 1);

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
  // 匹配任意无 nonce 的 script 开标签（裸 <script> 或带 data-cfasync 等属性），已有 nonce 的跳过
  const injectNonce = (html, nonce) => html
    .replace(/<script(?![^>]*\bnonce=)([^>]*)>/g, `<script$1 nonce="${nonce}">`);
  app.use((req, res, next) => {
    const origSend = res.send.bind(res);
    res.send = (body) => {
      const nonce = nonces.get(res);
      if (nonce && typeof body === 'string' && body.includes('<script') && !body.includes('nonce=')) {
        body = injectNonce(body, nonce);
      }
      return origSend(body);
    };
    const origSendFile = res.sendFile.bind(res);
    res.sendFile = (p, opts, cb) => {
      const nonce = nonces.get(res);
      if (!nonce || !String(p).endsWith('.html')) return origSendFile(p, opts, cb);
      const html = injectNonce(fs.readFileSync(p, 'utf8'), nonce);
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

  app.use(express.static(path.join(__dirname, '..', 'public'), {
    index: false,           // 首页由显式路由处理（需要注入 CSP nonce）
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

  return { metrics, nonces };
}

// 全局限流：每个 IP 每 15 分钟最多 100 次写 + 300 次读
const writeLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 100 });
const readLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 300 });
// 口令尝试限流：防暴力猜口令，每 IP 每 15 分钟 30 次
const pwLimiter = rateLimit({ windowMs: 15 * 60 * 1000, max: 30 });

function clientIp(req) {
  return (req.headers['x-forwarded-for'] || '').split(',')[0].trim() ||
         req.socket.remoteAddress || '';
}

module.exports = { setupCommon, writeLimiter, readLimiter, pwLimiter, clientIp, MAX_BODY };
