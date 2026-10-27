# ClipBox · Zero-Knowledge Online Clipboard

[中文文档](README.md) | English

Self-hosted text sharing: content is encrypted **in your browser** with AES-256-GCM before upload. The key lives only in the `#` fragment of the share link (fragments are never sent to the server) — the server only ever sees ciphertext. **Even a full database leak exposes nothing.**

Pure JavaScript stack (Node.js + Express + SQLite), only 3 production dependencies, no frontend framework, no build step.

> 🇨🇳 中文完整文档见 [README.md](README.md) — the Chinese version is the canonical, most up-to-date documentation.

## Features

- ✅ Short IDs (6 chars, [a-zA-Z0-9], automatic collision retry)
- ✅ Auto-expiry (1h / 24h / 7d + server-side cleanup every 5 min)
- ✅ Burn after reading (deleted atomically on first read)
- ✅ Client-side end-to-end encryption (zero knowledge)
- ✅ Optional access password (server stores only a PBKDF2-SHA256 hash, 120k iterations; timing-safe comparison; password sent via POST body — never in URLs or logs)
- ✅ Owner self-delete (creation response includes a one-time delete token — server stores only its SHA-256 hash; `DELETE /api/clips/:id` with the token)
- ✅ Markdown rendering + syntax highlighting on the viewer side (vendored marked + highlight.js, no CDN; rendering happens after decryption, server still sees only ciphertext)
- ✅ QR code (rendered locally by qrcode-generator, no external CDN)
- ✅ Direct-path view page (`/:id` without key → manual key entry)
- ✅ Insecure-context detection (clear notice when `crypto.subtle` is unavailable)
- ✅ Rate limiting (100 writes / 300 reads / 30 password attempts per IP per 15 min — verified under load testing)
- ✅ Per-IP storage quota (max 20 active clips)
- ✅ Same-origin enforcement (cross-origin writes rejected with 403)
- ✅ Security headers (CSP, nosniff, X-Frame-Options: DENY, no-referrer)
- ✅ Health check `GET /healthz`
- ✅ Admin API (requires `ADMIN_TOKEN`; stats / list / delete / purge — never returns ciphertext)
- ✅ 64KB size cap (chunked base64 conversion, no stack overflow risk)

## Operations & Observability

| Endpoint | Description |
|---|---|
| `GET /healthz` | Liveness + clip count (for reverse proxies / monitoring) |
| `GET /versionz` | Version + git SHA + start time |
| `GET /metricsz` | Requests, 4xx/5xx, creates/reads, active clips, DB size, disk headroom |

Logs are **JSON lines** (`ts/level/event/...`) — pipe straight into any log drain. Request logs contain path/status/duration/IP only; **never ciphertext or passwords**.

Self-healing & stability:

- **Startup self-check**: SQLite integrity (quick_check) + writability; on failure → alert → fast exit for the process manager
- **Failure alerting**: set `ALERT_WEBHOOK_URL` and error-level events are POSTed (works with Slack/DingTalk/Feishu/custom; 10-min cooldown per alert; fatal paths await delivery before exiting)
- **Disk watermark**: checked every 5 min; below `DISK_MIN_FREE_MB` (default 100MB) → alert + reject new writes (503); auto-recovers
- 30s request timeout (slow-loris protection)
- Graceful shutdown on SIGTERM/SIGINT: stop accepting → WAL checkpoint → clean close
- Scheduled hot backups to `backups/` (`BACKUP_INTERVAL_MIN`, default 30, 0 disables; keeps 7)
- systemd unit included: `deploy/clipbox.service` (auto-restart + hardening)

## Quick Start

### Option 1: bare metal / systemd

```bash
cd clipbox
npm install
ADMIN_TOKEN=$(openssl rand -hex 32) PORT=3000 npm start
```

For production, use the provided systemd unit (`deploy/clipbox.service`).

Database schema auto-migrates on startup. Data file defaults to `./clipbox.db` (override with `DB_PATH`).

### Option 2: Docker Compose (recommended, auto-HTTPS)

```bash
cd clipbox
cp .env.example .env            # set ADMIN_TOKEN (openssl rand -hex 32)
docker compose up -d --build
```

Architecture: `clipbox` (app, bound to 127.0.0.1:3000 only) + `caddy` (auto-HTTPS reverse proxy). Edit the domain in `Caddyfile`.

### CI (GitHub Actions)

On push: dependency audit (fail on high severity in prod deps) → syntax check → isolated smoke tests → dual-arch Docker build (amd64 + arm64 via QEMU).

## Testing

```bash
npm run smoke        # 12 checks
npx autocannon -d 10 -c 100 http://localhost:3000/healthz
```

Measured baseline (2-core cloud VM): healthz ~2600 req/s; creates (no password) ~1800 req/s; **password-protected creates cap at ~15 req/s** (synchronous PBKDF2 blocks the event loop — shielded by rate limiting, fine for personal scale).

## Environment Variables

| Variable | Default | Description |
|---|---|---|
| `PORT` | 3000 | Listen port |
| `ADMIN_TOKEN` | (empty = admin API disabled) | Bearer token — use `openssl rand -hex 32` |
| `DB_PATH` | `./clipbox.db` | SQLite path (parent dir auto-created) |
| `TRUST_PROXY` | 0 | Set 1 only behind a trusted reverse proxy (prevents XFF spoofing) |
| `ALERT_WEBHOOK_URL` | (empty = alerts off) | Webhook for failure alerts |
| `DISK_MIN_FREE_MB` | 100 | Disk watermark for alerting / write rejection |
| `BACKUP_INTERVAL_MIN` | 30 | Hot backup interval (0 disables) |
| `BACKUP_DIR` | `./backups` | Backup directory |
| `GIT_SHA` | unknown | Shown by `/versionz` (injected by CI/compose) |

## Compatibility

| Platform | Status |
|---|---|
| linux x64 (glibc) | ✅ prebuilt (tested) |
| linux arm64 (Raspberry Pi 4/5, Graviton) | ✅ source build with toolchain in deps stage; CI guards dual-arch |
| Alpine (musl) x64/arm64 | ✅ official prebuilts |
| macOS x64/Apple Silicon | ✅ prebuilt |
| Windows x64/ARM | ⚠️ works; ops scripts are POSIX |
| 32-bit / s390x / riscv64 | ❌ not supported |

Frontend requires HTTPS or localhost (Web Crypto constraint).

## Security Boundaries (read this)

1. **Plaintext exists only in browser memory** — the link *is* the key; leaking the full link leaks the content.
2. Chat platforms see the link but not the key after `#`. Want more? Strip the key and send it separately (the view page supports manual key entry).
3. **Zero knowledge ≠ anonymity**: server sees IPs, timestamps, ciphertext sizes.
4. Per-IP rate limiting offers limited protection against distributed abuse (proxy pools).
5. For public deployments: HTTPS via reverse proxy + strong ADMIN_TOKEN + watch for abuse reports.
6. 6-char IDs are enumerable by design — security rests entirely on the key fragment and password.

## API

| Method | Path | Description |
|---|---|---|
| POST | `/api/clips` | `{ ciphertext, burn, ttl, password? }` → `{ id, expires_at, protected }` |
| POST | `/api/clips/:id/read` | `{ pw? }` → `{ ciphertext, burn, protected }` (burn deletes on read; 401 = wrong password) |
| GET | `/healthz` `/versionz` `/metricsz` | Ops endpoints |
| GET/DELETE | `/api/admin/...` | Admin API (Bearer ADMIN_TOKEN) |

`ciphertext` format: `base64(key).base64(iv).base64(aes-gcm-ciphertext)`, encrypted/decrypted in the browser (Web Crypto AES-256-GCM).

## Known Limitations

- Single-node architecture, no HA; host failure requires manual migration (data is one file — cheap to move)
- Synchronous PBKDF2 caps password-protected create throughput (~15 req/s)
- Backups are automatic but restore is manual
- No centralized log/alert collection (formats are ready — plug in when needed)
