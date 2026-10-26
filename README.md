# ClipBox · 零知识在线剪切板

自托管的文本分享服务：内容在**浏览器内**用 AES-256-GCM 加密后才上传，密钥只存在于分享链接的 `#` 片段中（fragment 不会随 HTTP 请求发送），服务端全程只接触密文。

## 功能

- ✅ 短 ID 存取（6 位数字+大小写字母，62 字符集）
- ✅ 自动过期（1 小时 / 24 小时 / 7 天，服务端另有 5 分钟清理定时器）
- ✅ 阅后即焚（读一次即删，事务原子操作）
- ✅ 客户端端到端加密（零知识：服务器被拖库也拿不到明文）
- ✅ 可选访问口令（服务端只存 PBKDF2-SHA256 12 万轮派生哈希，校验用 timingSafeEqual 防时序侧信道）
- ✅ 二维码（qrcode-generator 本地渲染，无外联 CDN）
- ✅ 路径直达查看页（`/:id` 不带密钥时手动输入密钥解密）
- ✅ 限流（写 100 次/15 分钟，读 300 次/15 分钟，口令尝试 30 次/15 分钟，按 IP）
- ✅ 存储配额（每 IP 最多 20 条未过期内容）
- ✅ 健康检查 `GET /healthz`
- ✅ 管理接口（需 `ADMIN_TOKEN` 环境变量；stats / list / 删除单条 / 清空，绝不返回密文）
- ✅ 体积上限 64KB

## 运维与可观测性（v1.1）

| 端点 | 说明 |
|---|---|
| `GET /healthz` | 存活 + 存量（反代/监控探针用）|
| `GET /versionz` | 版本 + git SHA + 启动时间（部署核对）|
| `GET /metricsz` | 请求数、4xx/5xx、创建/读取数、活跃条数、DB 大小 |

日志为 **JSON lines** 结构化格式（`ts/level/event/...`），可直接接 log drains 或采集器；请求日志只记 path/status/耗时/IP，**绝不记录密文与口令**。

- 挂起请求 30 秒超时（防慢速攻击）
- SIGTERM/SIGINT 优雅关闭：停收请求 → WAL checkpoint → 干净关库（Docker stop / systemd restart 均安全）
- 定时热备到 `backups/`（`BACKUP_INTERVAL_MIN` 分钟，默认 30，0 关闭；保留 7 份）
- 裸机部署用 systemd 单元：`deploy/clipbox.service`（含崩溃自动重启与进程加固）

## 冒烟测试

```bash
npm run smoke                                  # 默认 http://localhost:3000
SMOKE_URL=http://localhost:3902 SMOKE_TOKEN=xxx npm run smoke
```

覆盖：健康检查、创建、路径直达、读取、口令、焚毁、畸形 JSON、CSP、版本端点、管理接口鉴权。

## 运行

```bash
cd clipbox
npm install
ADMIN_TOKEN=换成随机长令牌 PORT=3000 npm start
```

数据库 schema 自动迁移（旧库缺列会在启动时补齐）。数据文件默认 `./clipbox.db`，可用 `DB_PATH` 环境变量指定（Docker 中为 `/app/data/clipbox.db`）。

## Docker 部署

```bash
cd clipbox
cp .env.example .env            # 编辑 .env，ADMIN_TOKEN 用 openssl rand -hex 32 生成
docker compose up -d --build
docker compose logs -f clipbox  # 观察启动
```

架构：`clipbox`（应用，仅绑定 127.0.0.1:3000）+ `caddy`（自动 HTTPS 反代）。域名改在 `Caddyfile` 里。

数据持久化在 `clipbox-data` 卷（容器内 `/app/data/`）；健康检查走 `/healthz`。

### 运维命令

```bash
# 健康与状态
curl https://你的域名/healthz

# 管理接口（本地示例）
curl -H "Authorization: Bearer $ADMIN_TOKEN" http://127.0.0.1:3000/api/admin/stats
curl -H "Authorization: Bearer $ADMIN_TOKEN" http://127.0.0.1:3000/api/admin/list
curl -X DELETE -H "Authorization: Bearer $ADMIN_TOKEN" http://127.0.0.1:3000/api/admin/clips/某ID   # 删单条
curl -X DELETE -H "Authorization: Bearer $ADMIN_TOKEN" http://127.0.0.1:3000/api/admin/clips        # 清空

# 备份（SQLite，建议停写或用 sqlite3 .backup）
docker compose exec clipbox node -e "console.log(process.env.DB_PATH)"
docker run --rm -v clipbox_clipbox-data:/data -v $PWD:/backup alpine \
  cp /data/clipbox.db /backup/clipbox-backup.db

# 更新版本
docker compose up -d --build
```

⚠️ 注意：SQLite 卷内数据库不兼容 NFS/网络盘；备份时最好避开写入瞬间。

## 安全边界（务必知晓）

1. **明文只存在于浏览器内存**——但用户自己打开的页面、生成的链接本身仍需自行保管（链接即密钥，泄露链接等于泄露内容）。
2. 链接通过聊天工具发送时，聊天平台能看到链接本身；**但看不到 # 后面的密钥**（浏览器不会把 fragment 发给任何服务器，聊天客户端若存了完整 URL 则存了密钥——介意的话手动删掉 # 后段分开两条消息发）。
3. 限流只防低强度滥用，公网部署还需：反代加 HTTPS（强烈建议 Caddy）、加访问口令、关注滥用举报风险。
4. SQLite 文件里存的是密文，仍建议对 `clipbox.db` 做好文件权限（`chmod 600`）。

## API

| 方法 | 路径 | 说明 |
|---|---|---|
| POST | `/api/clips` | `{ ciphertext, burn, ttl }` → `{ id, expires_at }` |
| GET | `/api/clips/:id` | → `{ ciphertext, burn }`（burn 为 true 时读后即删）|

`ciphertext` 格式：`base64(key).base64(iv).base64(aes-gcm-ciphertext)`，加密解密均在前端完成。
