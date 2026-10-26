# ClipBox — 多阶段构建
# 构建阶段：安装生产依赖（better-sqlite3 需要编译，用完整 python 工具链）
FROM node:22-bookworm-slim AS deps
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm install --omit=dev

# 运行阶段：瘦身镜像
FROM node:22-bookworm-slim
ENV NODE_ENV=production
WORKDIR /app

# 非 root 用户
RUN groupadd -r clipbox && useradd -r -g clipbox clipbox

COPY --from=deps /app/node_modules ./node_modules
COPY server.js package.json ./
COPY public ./public

RUN mkdir -p /app/data && chown -R clipbox:clipbox /app
USER clipbox

# 数据目录（卷挂载点）
ENV DB_PATH=/app/data/clipbox.db
VOLUME /app/data

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "fetch('http://localhost:'+(process.env.PORT||3000)+'/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "server.js"]
