# ClipBox · 零知识在线剪切板

[部署指南](DEPLOY.md)

自托管的文本分享服务：内容在**浏览器内**用 AES-256-GCM 加密后才上传，密钥只存在于分享链接的 `#` 片段中（fragment 不会随 HTTP 请求发送），服务端全程只接触密文——**服务器被拖库也拿不到明文**。

纯 JavaScript 技术栈（Node.js + Express + SQLite），依赖仅 3 个生产包，无前端框架、无编译步骤。

## 功能

- ✅ 短 ID 存取（6 位数字+大小写字母，62 字符集，撞车自动重试）
- ✅ 自动过期（1 小时 / 24 小时 / 7 天，服务端另有 5 分钟清理定时器）
- ✅ 阅后即焚（读一次即删，事务原子操作）
- ✅ 客户端端到端加密（零知识）
- ✅ 可选访问口令（服务端只存 PBKDF2-SHA256 12 万轮派生哈希，校验用 timingSafeEqual 防时序侧信道；口令经 POST body 传输，不进 URL/日志）
- ✅ 创建者自删：创建响应返回一次性删除令牌（服务端只存 SHA-256 哈希），凭令牌 `DELETE /api/clips/:id`
- ✅ Markdown 渲染 + 代码高亮（查看端解密后渲染，marked + highlight.js 本地 vendor，服务端仍只见密文；**DOMPurify 消毒**，直插 HTML 的 XSS 面已关闭）
- ✅ 二维码（qrcode-generator 本地渲染，无外联 CDN）
- ✅ 路径直达查看页（`/:id` 不带密钥时手动输入密钥解密）
- ✅ 非 HTTPS 环境检测（`crypto.subtle` 不可用时给出明确提示页）
- ✅ 限流（写 100 次/15 分钟，读 300 次/15 分钟，口令尝试 30 次/15 分钟，按 IP；压测实证有效）
- ✅ 存储配额（每 IP 最多 20 条未过期内容）
- ✅ Origin 同源校验（跨域写请求 403 拒绝，不影响命令行/直链访问）
- ✅ 安全响应头（CSP、nosniff、X-Frame-Options: DENY、no-referrer）
- ✅ 健康检查 `GET /healthz`
- ✅ 管理后台 `/admin`（需 `ADMIN_TOKEN`；统计/健康/多邀请码管理/批量清理/备份管理/内容元数据列表——**永远无法查看密文**）
- ✅ 多邀请码（后台发放/作废/恢复，一人一码精准吊销；启用后创建需携带有效码，读取不受限）
- ✅ 体积上限 64KB（前端大 buffer 分块转换，无栈溢出风险）

## 运维与可观测性

| 端点 | 说明 |
|---|---|
| `GET /healthz` | 存活 + 存量（反代/监控探针用）|
| `GET /versionz` | 版本 + git SHA + 启动时间（部署核对）|
| `GET /metricsz` | 请求数、4xx/5xx、创建/读取数、活跃条数、DB 大小、磁盘余量 |

日志为 **JSON lines** 结构化格式（`ts/level/event/...`），可直接接 log drains 或采集器；请求日志只记 path/status/耗时/IP，**绝不记录密文与口令**。

自愈与稳定性：

- **启动自检**：SQLite 完整性（quick_check）+ 可写性验证，失败 → 告警 → 快速退出交进程管理器
- **失败告警**：`ALERT_WEBHOOK_URL` 配置后，error 级事件 POST 通知（兼容 Slack/钉钉/飞书/自建；10 分钟同类冷却防风暴；异步发送、致命场景等待发完再退出）
- **磁盘水位**：每 5 分钟检查，低于 `DISK_MIN_FREE_MB`（默认 100MB）→ 告警 + 拒绝新写入（503），恢复自动解除
- 挂起请求 30 秒超时（防慢速攻击）
- SIGTERM/SIGINT 优雅关闭：停收请求 → WAL checkpoint → 干净关库（Docker stop / systemd restart 均安全）
- 定时热备到 `backups/`（`BACKUP_INTERVAL_MIN` 分钟，默认 30，0 关闭；保留 7 份）
- 裸机部署用 systemd 单元：`deploy/clipbox.service`（崩溃自动重启 + NoNewPrivileges/ProtectSystem 进程加固）

## 快速开始

### 方式一：裸机 / systemd

```bash
cd clipbox
npm install
ADMIN_TOKEN=$(openssl rand -hex 32) PORT=3000 npm start
```

生产环境建议用 systemd：复制 `deploy/clipbox.service` 到 `/etc/systemd/system/` 并按注释修改路径与令牌。

数据库 schema 自动迁移（旧库缺列启动时补齐）。数据文件默认 `./clipbox.db`，可用 `DB_PATH` 指定。

### 方式二：Docker Compose（推荐，含自动 HTTPS）

```bash
cd clipbox
cp .env.example .env            # 编辑 .env，ADMIN_TOKEN 用 openssl rand -hex 32 生成
docker compose up -d --build
docker compose logs -f clipbox  # 观察启动
```

架构：`clipbox`（应用，仅绑定 127.0.0.1:3000）+ `caddy`（自动 HTTPS 反代）。域名改在 `Caddyfile` 里。

数据持久化在 `clipbox-data` 卷（容器内 `/app/data/`）。

### CI（GitHub Actions）

推送后自动执行：依赖审计（生产依赖高危即失败）→ 语法检查 → 隔离环境冒烟测试 → Docker 双架构构建（amd64 + arm64 via QEMU）。

## 测试

```bash
# 冒烟测试（12 项：健康、创建、直达、读取、口令、焚毁、畸形 JSON、CSP、版本端点、管理鉴权）
npm run smoke
SMOKE_URL=http://localhost:3902 SMOKE_TOKEN=xxx npm run smoke

# 压力测试（autocannon，dev 依赖）
npx autocannon -d 10 -c 100 http://localhost:3000/healthz
```

已测基准（2 核云主机参考值）：healthz ~2600 req/s；创建（无口令）~1800 req/s；**带口令创建上限约 15 req/s**（PBKDF2 同步计算阻塞事件循环，被写入限流掩护，个人规模无影响）。

## 运维命令

```bash
# 健康与状态
curl https://你的域名/healthz

# 管理接口（本地示例，TOKEN 换成你的 ADMIN_TOKEN）
curl -H "Authorization: Bearer TOKEN" http://127.0.0.1:3000/api/admin/stats
curl -H "Authorization: Bearer TOKEN" http://127.0.0.1:3000/api/admin/list
curl -X DELETE -H "Authorization: Bearer TOKEN" http://127.0.0.1:3000/api/admin/clips/某ID   # 删单条
curl -X DELETE -H "Authorization: Bearer TOKEN" http://127.0.0.1:3000/api/admin/clips        # 清空

# 备份（应用内热备自动进行；手动冷备：）
docker run --rm -v clipbox_clipbox-data:/data -v $PWD:/backup alpine \
  cp /data/clipbox.db /backup/clipbox-backup.db

# 更新版本
docker compose up -d --build
```

⚠️ SQLite 卷内数据库不兼容 NFS/网络盘；备份文件含 IP 元数据，注意权限（`chmod 600`）与存放位置。

## 环境变量

| 变量 | 默认 | 说明 |
|---|---|---|
| `PORT` | 3000 | 监听端口 |
| `ADMIN_TOKEN` | （空=禁用管理接口）| 管理接口 Bearer 令牌，务必 `openssl rand -hex 32` |
| `DB_PATH` | `./clipbox.db` | SQLite 路径（父目录自动创建）|
| `TRUST_PROXY` | 0 | 置 1 信任 X-Forwarded-For（仅反代后部署时；直连暴露公网勿开，防伪造绕过限流）|
| `ALERT_WEBHOOK_URL` | （空=禁用告警）| 告警 webhook 地址 |
| `DISK_MIN_FREE_MB` | 100 | 磁盘余量告警/拒绝写入阈值 |
| `BACKUP_INTERVAL_MIN` | 30 | 热备间隔（0 关闭）|
| `BACKUP_DIR` | `./backups` | 热备目录 |
| `GIT_SHA` | unknown | 版本端点显示用（CI/compose 注入）|

## 兼容性

| 平台 | 状态 |
|---|---|
| linux x64 (glibc) | ✅ 预编译（实测）|
| linux arm64 (glibc，树莓派 4/5、Graviton) | ✅ deps 阶段带工具链源码编译，CI 双架构把关 |
| Alpine (musl) x64/arm64 | ✅ 官方预编译 |
| macOS x64/Apple Silicon | ✅ 预编译 |
| Windows x64/ARM | ⚠️ 可跑，运维脚本为 POSIX |
| 32 位 / s390x / riscv64 | ❌ 不支持 |

前端要求 HTTPS 或 localhost（Web Crypto 限制，非安全上下文会显示提示页）。

## 安全边界（务必知晓）

1. **明文只存在于浏览器内存**——链接即密钥，泄露完整链接等于泄露内容。
2. 聊天平台能看到链接本身，但看不到 `#` 后的密钥；介意就删掉密钥段分开两条消息发（查看页支持手动输入密钥）。
3. **零知识 ≠ 匿名**：IP、时间、密文大小等元数据服务端可见。
4. per-IP 限流对代理池式分布式滥用防护有限（固有限制）。
5. 公网部署务必：反代 HTTPS（Caddy 一行）+ 强 ADMIN_TOKEN + 关注滥用举报（境内服务器尤其注意）。
6. 6 位短 ID 可被穷举枚举，安全性完全依赖密钥段与口令——这是设计而非漏洞。

## API

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/clips` | `{ ciphertext, burn, ttl, password? }` → `{ id, expires_at, protected }` |
| POST | `/api/clips/:id/read` | `{ pw? }` → `{ ciphertext, burn, protected }`（burn 时读后即删；401=口令错误）|
| GET | `/healthz` `/versionz` `/metricsz` | 运维端点 |
| GET/DELETE | `/api/admin/...` | 管理接口（Bearer ADMIN_TOKEN）|

`ciphertext` 格式：`base64(key).base64(iv).base64(aes-gcm-ciphertext)`，加密解密均在前端完成（Web Crypto AES-256-GCM）。

## 项目结构

```
clipbox/
├── server.js              # 全部服务端逻辑（~430 行）
├── public/
│   ├── index.html         # 单文件前端（创建/查看/解密）
│   └── vendor/qrcode.min.js
├── scripts/smoke.sh       # 冒烟测试
├── deploy/clipbox.service # systemd 单元
├── Dockerfile             # 多阶段构建，amd64+arm64
├── docker-compose.yml     # 应用 + Caddy
├── Caddyfile              # 自动 HTTPS 反代
├── .github/workflows/ci.yml
└── clipbox.db             # SQLite（运行时生成，勿提交）
```

## 已知局限

- 单机架构，无高可用；主机故障需人工迁移（数据就一个文件，成本低）
- PBKDF2 同步计算限制带口令创建吞吐（~15 req/s）
- 备份自动进行但恢复需人工
- 无集中式日志/告警采集（格式已就绪，接入即可）
