#!/usr/bin/env bash
# ClipBox 冒烟测试：对运行中的实例做核心功能回归
# 用法: SMOKE_URL=http://localhost:3902 SMOKE_TOKEN=xxx ./scripts/smoke.sh
set -u
BASE="${SMOKE_URL:-http://localhost:3000}"
TOKEN="${SMOKE_TOKEN:-}"
PASS=0; FAIL=0

check() { # name expected actual
  if [ "$2" = "$3" ]; then PASS=$((PASS+1)); echo "✅ $1"; else FAIL=$((FAIL+1)); echo "❌ $1 (期望 $2 实得 $3)"; fi
}
code() { curl -s -o /dev/null -w '%{http_code}' "$@"; }

# 1. 健康
check "healthz" 200 "$(code "$BASE/healthz")"

# 邀请码模式自适应（TOKEN 存在时探测有效码；创建请求体按需携带）
if [ -n "$TOKEN" ]; then
  INVITES=$(curl -s -H "Authorization: Bearer $TOKEN" "$BASE/api/admin/invites")
  ACTIVE=$(echo "$INVITES" | python3 -c "
import sys, json
inv = json.load(sys.stdin)['invites']
print(next((i['code'] for i in inv if not i['revoked']), ''))")
else
  ACTIVE=""
fi
# 创建请求体（邀请码启用时自动携带有效码）
CREATE1="{\"ciphertext\":\"smoke.key.iv.smoke\",\"burn\":false,\"ttl\":120"
CREATE2="{\"ciphertext\":\"smoke2.iv.ct\",\"burn\":true,\"ttl\":120,\"password\":\"smokepw\""
if [ -n "${ACTIVE:-}" ]; then CREATE1="$CREATE1,\"invite_code\":\"$ACTIVE\""; CREATE2="$CREATE2,\"invite_code\":\"$ACTIVE\""; fi
CREATE1="$CREATE1}"; CREATE2="$CREATE2}"

# 2. 创建（无口令）
ID=$(curl -s -X POST "$BASE/api/clips" -H 'Content-Type: application/json' \
  -d "$CREATE1" | python3 -c "import sys,json;print(json.load(sys.stdin).get('id',''))")
[ -n "$ID" ] && check "创建短ID" 6 "${#ID}" || { echo "❌ 创建失败"; FAIL=$((FAIL+1)); }
# 3. 路径直达页面
check "路径直达" 200 "$(code "$BASE/$ID")"
# 4. POST 读取
check "POST读取" 200 "$(code -X POST "$BASE/api/clips/$ID/read" -H 'Content-Type: application/json' -d '{}')"
# 5. 带口令创建 + 校验
R=$(curl -s -X POST "$BASE/api/clips" -H 'Content-Type: application/json' \
  -d "$CREATE2")
ID2=$(echo "$R" | python3 -c "import sys,json;print(json.load(sys.stdin).get('id',''))")
check "口令缺失401" 401 "$(code -X POST "$BASE/api/clips/$ID2/read" -H 'Content-Type: application/json' -d '{}')"
check "口令正确200" 200 "$(code -X POST "$BASE/api/clips/$ID2/read" -H 'Content-Type: application/json' -d '{"pw":"smokepw"}')"
check "焚毁后404" 404 "$(code -X POST "$BASE/api/clips/$ID2/read" -H 'Content-Type: application/json' -d '{"pw":"smokepw"}')"
# 6. 畸形 JSON
check "畸形JSON400" 400 "$(code -X POST "$BASE/api/clips" -H 'Content-Type: application/json' -d '{bad')"
# 7. 安全头
CSP=$(curl -sI "$BASE/" | grep -ci "content-security-policy")
check "CSP头" 1 "$CSP"
# 8. 版本端点
check "versionz" 200 "$(code "$BASE/versionz")"
# 9. 管理接口（可选）
if [ -n "$TOKEN" ]; then
  check "stats(带token)" 200 "$(code -H "Authorization: Bearer $TOKEN" "$BASE/api/admin/stats")"
  check "stats(无token)" 401 "$(code "$BASE/api/admin/stats")"
fi

# 11. 新增管理端点回归（可选，TOKEN 存在时）
if [ -n "$TOKEN" ]; then
  A="Authorization: Bearer $TOKEN"
  H='-H Content-Type:application/json'
  check "invites列表" 200 "$(code -H "$A" "$BASE/api/admin/invites")"
  check "invites未授权401" 401 "$(code "$BASE/api/admin/invites")"
  check "backups列表" 200 "$(code -H "$A" "$BASE/api/admin/backups")"
  check "cleanup非法kind400" 400 "$(code -X POST -H "$A" $H -d '{\"kind\":\"bogus\"}' "$BASE/api/admin/cleanup")"
fi

echo "———————"
echo "通过 $PASS / $((PASS+FAIL))"
[ "$FAIL" -eq 0 ] && exit 0 || exit 1
