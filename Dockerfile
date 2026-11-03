# ClipBox — 多阶段构建
# 构建阶段：安装生产依赖（better-sqlite3 无预编译的平台如 linux-arm64 glibc 需要源码编译，
# 因此带上完整工具链；x64/arm64 musl、x64 glibc 会直接命中预编译，工具链不增加最终镜像体积）
FROM node:22-bookworm-slim AS deps
RUN apt-get update && apt-get install -y --no-install-recommends python3 make g++ \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY package.json package-lock.json* ./
RUN npm ci --omit=dev

# 运行阶段：瘦身镜像
FROM node:22-bookworm-slim
ARG GIT_SHA=unknown
ENV NODE_ENV=production
ENV GIT_SHA=${GIT_SHA}
WORKDIR /app

# 非 root 用户
RUN groupadd -r clipbox && useradd -r -g clipbox clipbox

COPY --from=deps /app/node_modules ./node_modules
COPY server.js package.json ./
COPY lib ./lib
COPY public ./public

RUN mkdir -p /app/data && chown -R clipbox:clipbox /app
USER clipbox

# 数据目录（卷挂载点）
# 注意：挂载宿主目录时必须先 chown 999:999 <宿主目录>，否则容器用户无写权限，启动即失败
# （新版 db.js 会给出明确的 fatal 提示而不是误导性的 undefined 错误）
ENV DB_PATH=/app/data/clipbox.db
VOLUME /app/data

EXPOSE 3000

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
  CMD node -e "fetch('http://localhost:'+(process.env.PORT||3000)+'/healthz').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))"

CMD ["node", "server.js"]
