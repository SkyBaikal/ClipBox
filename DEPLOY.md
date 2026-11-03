# ClipBox 部署指南（Deploy Guide）

面向"拿到仓库的人能独立部署"。三种路径按推荐顺序排列，全部基于已验证的操作（v1.9.x，Docker 镜像实测构建+运行+数据卷持久化；CI 亦验证构建）。

## 前置条件

- Linux x86_64 服务器（ARM64 亦可，见附录）
- 已装 Docker（`curl -fsSL https://get.docker.com | sh`）或 Node.js 22
- 一个域名（推荐，HTTPS 是 Web Crypto 的硬要求；熟人圈可先用 IP+HTTP 过渡，但浏览器加密功能要求 HTTPS 或 localhost）

## 路径 A：Docker 镜像直跑（推荐）

本机或 CI 构建镜像并导出：

```bash
docker build --build-arg GIT_SHA=$(git rev-parse --short HEAD) -t clipbox:1.9.0 .
docker save clipbox:1.9.0 | gzip > clipbox-1.9.0.tar.gz   # ~85MB
scp clipbox-1.9.0.tar.gz user@SERVER:~/
```

服务器上：

```bash
docker load < ~/clipbox-1.9.0.tar.gz
mkdir -p /opt/clipbox/data /opt/clipbox/backups

# 密钥（生成后立即离线抄存！BACKUP_KEY 丢失 = 加密备份永久作废）
openssl rand -hex 32   # → ADMIN_TOKEN
openssl rand -hex 32   # → BACKUP_KEY
cat > /etc/clipbox.env << EOF
ADMIN_TOKEN=<第一个值>
BACKUP_KEY=<第二个值>
EOF
chmod 600 /etc/clipbox.env

cp deploy/clipbox-docker.service /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now clipbox

curl http://127.0.0.1:3000/healthz   # {"ok":true,...}
docker logs clipbox | tail -5        # 应看到 server_started
```

## 路径 B：docker compose（含 Caddy 自动 HTTPS）

```bash
cp .env.example .env      # 填 ADMIN_TOKEN / BACKUP_KEY / 域名
# Caddyfile 里把 clip.example.com 改成你的域名
docker compose up -d --build
```

适合：有域名、想自动签证书。Caddy 会自动处理 Let's Encrypt 续期。

## 路径 C：systemd 直跑（无 Docker）

```bash
# 服务器上安装 Node 22（NodeSource 或 nvm）
git clone <repo> /opt/clipbox && cd /opt/clipbox
npm ci --omit=dev
# 同路径 A 生成 /etc/clipbox.env
cp deploy/clipbox.service /etc/systemd/system/   # 裸 node 版
systemctl enable --now clipbox
```

## HTTPS 反向代理（无域名时跳过）

推荐 Caddy（自动 HTTPS、配置最少）：

```
# /etc/caddy/Caddyfile
your.domain.com {
    reverse_proxy 127.0.0.1:3000
}
```

Nginx 等价配置需手动处理证书续期 + WebSocket 无关（本项目无 WS）。
反代后面务必设 `TRUST_PROXY=1`（clipbox-docker.service 已内置），否则限流/日志 IP 可被 XFF 伪造。

## 上线后检查清单

- [ ] `curl https://域名/healthz` 返回 ok
- [ ] `/versionz` 显示预期版本和 git_sha
- [ ] 创建一条测试 clip → 打开链接能解密 → 阅后即焚生效
- [ ] `ls backups/` 30 分钟后出现 `.db.enc`（加密备份生效）
- [ ] 用 `BACKUP_KEY=xxx scripts/restore.sh backups/<file>.enc /tmp/test.db` 做一次恢复演练
- [ ] `systemctl status clipbox` 无异常；日志无 error 级事件
- [ ] 防火墙只开 22/80/443；SSH 禁密码登录

## 备份与恢复

- 热备每 `BACKUP_INTERVAL_MIN`（默认 30）分钟落盘 `backups/`，保留 7 份
- 设置 `BACKUP_KEY` 后备份以 AES-256-GCM 加密（`.db.enc`）
- 恢复：`BACKUP_KEY=xxx scripts/restore.sh backups/clipbox-YYYY-MM-DD.db.enc ./restored.db`
  - 脚本会解密 + quick_check 完整性校验 + 报告 clip 行数；错误密钥会被 GCM 校验拒绝
- **恢复流程**：停服务 → 用恢复文件替换 `clipbox.db` → 启动服务
- **强烈建议**：定期把 `backups/` 同步到异机/对象存储（rsync/cron 一行即可）——同盘备份扛不住磁盘故障

## 环境变量速查

| 变量 | 必填 | 说明 |
|---|---|---|
| `ADMIN_TOKEN` | 推荐 | 管理接口 Bearer 令牌；不设则管理 API 关闭 |
| `BACKUP_KEY` | 推荐 | 备份加密密钥；**离线另存**，丢失即备份作废 |
| `PORT` | 否 | 默认 3000（容器内） |
| `DB_PATH` | 否 | 默认 /app/data/clipbox.db（容器）|
| `TRUST_PROXY` | 否 | 反代后设 1 |
| `ALERT_WEBHOOK_URL` | 推荐 | 故障告警 webhook（钉钉/飞书/Slack 兼容） |
| `BACKUP_INTERVAL_MIN` | 否 | 默认 30，0 关闭 |
| `PBKDF2_ROUNDS` | 否 | 默认 600000 |
| `GIT_SHA` | 否 | git 短 SHA，/versionz 展示（部署核对） |

## 管理后台（v1.8+）

部署后访问 `https://域名/admin`：

- 登录：输入 `ADMIN_TOKEN`（仅存 sessionStorage，关标签即失效）
- **概览**：统计卡片、服务健康（运行时长/DB/磁盘/请求）、批量清理（过期/焚毁残留/清空）
- **邀请码**：多码管理——添加（可备注）、单码作废/恢复；启用后创建需携带任一有效码，读取不受限
- **内容**：最近 500 条元数据（**永远无法查看密文**），单条删除
- **备份**：备份列表 + 手动触发（自动走加密）

界面为中文单语。

## 已知限制（部署前须知）

- 单机架构：主机故障需人工迁移（数据就一个 SQLite 文件，成本低）
- 备份同盘：不配异地同步则磁盘故障 = 全丢
- 零知识架构下服务端**无法**扫描/审核内容——公开运营前请评估自身司法辖区的合规责任（服务条款、举报渠道、滥用处理流程）
- per-IP 限流可被代理池绕过；公开服务建议前置 Cloudflare

## 升级流程

```bash
# 本机构建新版本镜像 → 传输 → 服务器上：
systemctl stop clipbox
docker load < clipbox-<新版>.tar.gz
# 更新 clipbox-docker.service 里的镜像 tag
systemctl start clipbox
curl http://127.0.0.1:3000/versionz   # 核对新版本
```

数据库 schema 自动迁移（旧库缺列自动补），升级无需手动处理数据。
