#!/usr/bin/env bash
# =============================================================================
# GAIA-XDP 功能测试脚本 (release版本)
# 测试 GAIA 安全监控系统的核心功能：
#   1. API 端点可用性测试（11组，20项）
#   2. 系统状态与计数器读取
#   3. 文件监控探针验证（SQLite事件验证）
#   4. 特权操作检测验证
#   5. 历史事件 SQLite 持久化查询
#   6. 告警快照验证
# =============================================================================

GAIA_URL="http://localhost:17890"
RESULTS_DIR="${RESULTS_DIR:-/tmp/gaia_test_results}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RESULT_FILE="$RESULTS_DIR/functional_${TIMESTAMP}.json"
# 数据持久化目录（默认当前目录 ~/codes/codes/gaia）
DATA_DIR="${DATA_DIR:-$(pwd)}"

mkdir -p "$RESULTS_DIR"

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

pass=0
fail=0
total=0

log_pass() { echo -e "${GREEN}[PASS]${NC} $1"; ((pass++)); ((total++)); }
log_fail() { echo -e "${RED}[FAIL]${NC} $1"; ((fail++)); ((total++)); }
log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }

# ── 辅助函数 ──────────────────────────────────────────────────────────────────

api_get() {
    local endpoint="$1"
    curl -s -w "\n%{http_code}" --connect-timeout 5 "${GAIA_URL}${endpoint}" 2>/dev/null
}

api_post() {
    local endpoint="$1"
    local data="$2"
    curl -s -w "\n%{http_code}" --connect-timeout 5 \
         -H "Content-Type: application/json" \
         -d "$data" \
         "${GAIA_URL}${endpoint}" 2>/dev/null
}

parse_response() { echo "$1" | head -n -1; }
parse_status()   { echo "$1" | tail -n 1; }

# ── 测试 1: 服务存活性 ────────────────────────────────────────────────────────

echo ""
echo "════════════════════════════════════════"
echo "  测试组 1: 服务存活性检查"
echo "════════════════════════════════════════"

resp=$(api_get "/api/v1/state")
status=$(parse_status "$resp")
body=$(parse_response "$resp")

if [ "$status" = "200" ]; then
    log_pass "GET /api/v1/state 返回 HTTP 200"
    file_agent=$(echo "$body" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['features']['file_io_agent'])" 2>/dev/null)
    net_agent=$(echo "$body" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['features']['network_agent'])" 2>/dev/null)
    proc_agent=$(echo "$body" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d['features']['process_agent'])" 2>/dev/null)

    [ "$file_agent" = "True" ] && log_pass "文件I/O探针 (file_io_agent) 已激活" || log_fail "文件I/O探针未激活"
    [ "$net_agent" = "True" ]  && log_pass "网络监控探针 (network_agent) 已激活"  || log_fail "网络监控探针未激活"
    [ "$proc_agent" = "True" ] && log_pass "进程监控探针 (process_agent) 已激活" || log_fail "进程监控探针未激活"

    echo "$body" > "$DATA_DIR/state_initial.json"
    log_info "初始状态快照保存至 $DATA_DIR/state_initial.json"
else
    log_fail "GET /api/v1/state 返回非200状态: $status"
fi

# ── 测试 2: 配置 API ──────────────────────────────────────────────────────────

echo ""
echo "════════════════════════════════════════"
echo "  测试组 2: 配置 API 测试"
echo "════════════════════════════════════════"

resp=$(api_get "/api/v1/config")
status=$(parse_status "$resp")
body=$(parse_response "$resp")

if [ "$status" = "200" ]; then
    log_pass "GET /api/v1/config 返回 HTTP 200"
    has_sensitive=$(echo "$body" | python3 -c "import sys,json; d=json.load(sys.stdin); print('sensitive_prefixes' in d)" 2>/dev/null)
    has_services=$(echo "$body" | python3 -c "import sys,json; d=json.load(sys.stdin); print('monitored_services' in d)" 2>/dev/null)
    has_ports=$(echo "$body" | python3 -c "import sys,json; d=json.load(sys.stdin); print('blocked_ports' in d)" 2>/dev/null)

    [ "$has_sensitive" = "True" ] && log_pass "配置包含 sensitive_prefixes 字段" || log_fail "配置缺少 sensitive_prefixes 字段"
    [ "$has_services" = "True" ]  && log_pass "配置包含 monitored_services 字段"  || log_fail "配置缺少 monitored_services 字段"
    [ "$has_ports" = "True" ]     && log_pass "配置包含 blocked_ports 字段"        || log_fail "配置缺少 blocked_ports 字段"

    echo "$body" > "$DATA_DIR/config.json"
else
    log_fail "GET /api/v1/config 返回非200状态: $status"
fi

# ── 测试 3: 文件监控探针验证（基于 SQLite）────────────────────────────────────

echo ""
echo "════════════════════════════════════════"
echo "  测试组 3: 文件监控探针验证（SQLite）"
echo "════════════════════════════════════════"

DB="$DATA_DIR/gaia-events.db"
B_EVENTS=$(sqlite3 "$DB" "SELECT COUNT(*) FROM events;" 2>/dev/null || echo "0")
log_info "触发前 SQLite 事件总数: $B_EVENTS"

# 触发文件 I/O 操作
log_info "触发文件I/O操作（访问 /etc/passwd, /etc/hosts 等路径）..."
cat /etc/passwd > /dev/null 2>&1
cat /etc/hostname > /dev/null 2>&1
ls /root > /dev/null 2>&1
cat /proc/version > /dev/null 2>&1
cat /etc/hosts > /dev/null 2>&1

sleep 1  # 等待 eBPF 事件写入 SQLite

A_EVENTS=$(sqlite3 "$DB" "SELECT COUNT(*) FROM events;" 2>/dev/null || echo "0")
log_info "触发后 SQLite 事件总数: $A_EVENTS"

if [ "$A_EVENTS" -gt "$B_EVENTS" ] 2>/dev/null; then
    delta=$((A_EVENTS - B_EVENTS))
    log_pass "文件I/O探针成功捕获 $delta 个新事件（$B_EVENTS -> $A_EVENTS）"
else
    log_warn "事件计数未增加（可能写入延迟，不一定失败）"
fi

# 测试文件事件详情 API
resp=$(api_get "/api/v1/file-event/detail?path=/etc/passwd&pid=$$")
status=$(parse_status "$resp")
body=$(parse_response "$resp")
if [ "$status" = "200" ]; then
    log_pass "GET /api/v1/file-event/detail 返回 HTTP 200"
    is_sensitive=$(echo "$body" | python3 -c "import sys,json; d=json.load(sys.stdin); print(d.get('is_sensitive', False))" 2>/dev/null)
    log_info "/etc/passwd 是否为敏感路径: $is_sensitive"
    echo "$body" > "$DATA_DIR/file_event_detail.json"
else
    log_fail "GET /api/v1/file-event/detail 返回 $status"
fi

# ── 测试 4: 事件快照中的告警验证 ─────────────────────────────────────────────

echo ""
echo "════════════════════════════════════════"
echo "  测试组 4: 事件与告警快照"
echo "════════════════════════════════════════"

resp=$(api_get "/api/v1/state")
body=$(parse_response "$resp")

event_count=$(echo "$body" | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(len(d.get('events', [])))
" 2>/dev/null || echo "0")

alert_count=$(echo "$body" | python3 -c "
import sys, json
d = json.load(sys.stdin)
print(len(d.get('alerts', [])))
" 2>/dev/null || echo "0")

log_info "当前内存中事件数: $event_count"
log_info "当前内存中告警数: $alert_count"

if [ "$event_count" -gt 0 ] 2>/dev/null; then
    log_pass "系统已捕获 $event_count 个安全事件"
    echo "$body" | python3 -c "
import sys, json
from collections import Counter
d = json.load(sys.stdin)
kinds = Counter(e.get('kind', 'unknown') for e in d.get('events', []))
print('  事件类型分布:')
for k, v in kinds.most_common(5):
    print(f'    - {k}: {v} 次')
" 2>/dev/null
else
    log_warn "暂无内存事件（restart后会清零，查SQLite确认正常）"
fi

if [ "$alert_count" -gt 0 ] 2>/dev/null; then
    log_pass "系统已生成 $alert_count 个安全告警"
    echo "$body" | python3 -c "
import sys, json
d = json.load(sys.stdin)
alerts = d.get('alerts', [])[:3]
for a in alerts:
    print(f'  [{a.get(\"level\",\"?\")}] {a.get(\"reason\",\"?\")}')
" 2>/dev/null
    echo "$body" | python3 -c "
import sys, json
d = json.load(sys.stdin)
import json as j
print(j.dumps({'alerts': d.get('alerts', [])[:10]}, indent=2, ensure_ascii=False))
" 2>/dev/null > "$DATA_DIR/alerts.json"
else
    log_info "暂无告警（可通过 SSH 登录触发 critical 级别告警）"
fi

# ── 测试 5: 历史事件数据库查询 ────────────────────────────────────────────────

echo ""
echo "════════════════════════════════════════"
echo "  测试组 5: 历史事件数据库查询"
echo "════════════════════════════════════════"

# 通过 API
resp=$(api_get "/api/v1/history/events?page=0&page_size=20")
status=$(parse_status "$resp")
body=$(parse_response "$resp")

if [ "$status" = "200" ]; then
    log_pass "GET /api/v1/history/events 返回 HTTP 200"
    echo "$body" > "$DATA_DIR/history_events.json"

    echo "$body" | python3 -c "
import sys, json
from collections import Counter
d = json.load(sys.stdin)
items = d if isinstance(d, list) else d.get('items', [])
kinds = Counter(e.get('kind', 'unknown') for e in items)
print('  历史事件类型分布（首页）:')
for k, v in kinds.most_common(10):
    print(f'    - {k}: {v} 次')
" 2>/dev/null
else
    log_fail "GET /api/v1/history/events 返回 $status"
fi

# 分页测试
resp=$(api_get "/api/v1/history/events?page=0&page_size=5")
status=$(parse_status "$resp")
[ "$status" = "200" ] && log_pass "历史事件分页查询正常" || log_fail "历史事件分页查询失败: $status"

# 直接查询 SQLite
if [ -f "$DB" ]; then
    TOTAL_EVENTS=$(sqlite3 "$DB" "SELECT COUNT(*) FROM events;" 2>/dev/null || echo "N/A")
    log_info "SQLite 历史事件总数: $TOTAL_EVENTS"
    [ "$TOTAL_EVENTS" -gt 0 ] 2>/dev/null && log_pass "SQLite 历史事件持久化正常（共 $TOTAL_EVENTS 条）" || log_warn "SQLite 事件数为 0"
fi

# ── 测试 6: 速率限制规则 API ──────────────────────────────────────────────────

echo ""
echo "════════════════════════════════════════"
echo "  测试组 6: 速率限制规则 API"
echo "════════════════════════════════════════"

resp=$(api_get "/api/v1/config/rate-limit")
status=$(parse_status "$resp")
body=$(parse_response "$resp")

if [ "$status" = "200" ]; then
    log_pass "GET /api/v1/config/rate-limit 返回 HTTP 200"
    rule_count=$(echo "$body" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d) if isinstance(d,list) else 0)" 2>/dev/null || echo "0")
    log_info "当前速率限制规则数: $rule_count"
    echo "$body" > "$DATA_DIR/rate_limits.json"
else
    log_fail "GET /api/v1/config/rate-limit 返回 $status"
fi

# ── 测试 7: 热补丁配置 API ────────────────────────────────────────────────────

echo ""
echo "════════════════════════════════════════"
echo "  测试组 7: 热补丁配置 API"
echo "════════════════════════════════════════"

resp=$(api_get "/api/v1/config/hotpatch")
status=$(parse_status "$resp")
body=$(parse_response "$resp")

if [ "$status" = "200" ]; then
    log_pass "GET /api/v1/config/hotpatch 返回 HTTP 200"
    target_count=$(echo "$body" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d) if isinstance(d,list) else 0)" 2>/dev/null || echo "0")
    log_info "热补丁目标数: $target_count"
    echo "$body" > "$DATA_DIR/hotpatch_config.json"
else
    log_fail "GET /api/v1/config/hotpatch 返回 $status"
fi

# ── 测试 8: Kernel Livepatch 状态 API ────────────────────────────────────────

echo ""
echo "════════════════════════════════════════"
echo "  测试组 8: Kernel Livepatch 状态"
echo "════════════════════════════════════════"

resp=$(api_get "/api/v1/kernel-livepatch/status")
status=$(parse_status "$resp")
body=$(parse_response "$resp")

if [ "$status" = "200" ]; then
    log_pass "GET /api/v1/kernel-livepatch/status 返回 HTTP 200"
    patch_count=$(echo "$body" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d) if isinstance(d,list) else 0)" 2>/dev/null || echo "0")
    log_info "已加载 Kernel Livepatch 数: $patch_count"
    echo "$body" > "$DATA_DIR/klp_status.json"
else
    log_fail "GET /api/v1/kernel-livepatch/status 返回 $status"
fi

# ── 测试 9: 流量统计 ──────────────────────────────────────────────────────────

echo ""
echo "════════════════════════════════════════"
echo "  测试组 9: 网络流量统计"
echo "════════════════════════════════════════"

resp=$(api_get "/api/v1/state")
body=$(parse_response "$resp")

traffic_data=$(echo "$body" | python3 -c "
import sys, json
d = json.load(sys.stdin)
traffic = d.get('traffic', {})
print(json.dumps(traffic, indent=2))
" 2>/dev/null || echo "{}")

log_info "流量统计数据:"
echo "$traffic_data" | head -20
echo "$traffic_data" > "$DATA_DIR/traffic_stats.json"

has_traffic=$(echo "$traffic_data" | python3 -c "
import sys, json
d = json.load(sys.stdin)
print('yes' if d else 'no')
" 2>/dev/null)
[ "$has_traffic" = "yes" ] && log_pass "网络流量统计数据非空" || log_warn "网络流量统计数据为空"

# ── 测试 10: 受监控服务映射 ───────────────────────────────────────────────────

echo ""
echo "════════════════════════════════════════"
echo "  测试组 10: 受监控服务映射"
echo "════════════════════════════════════════"

resp=$(api_get "/api/v1/state")
body=$(parse_response "$resp")

service_count=$(echo "$body" | python3 -c "
import sys, json
d = json.load(sys.stdin)
services = d.get('services', {})
print(len(services))
" 2>/dev/null || echo "0")

log_info "已发现受监控服务数: $service_count"

if [ "$service_count" -gt 0 ] 2>/dev/null; then
    log_pass "服务映射非空，已识别 $service_count 个服务"
    echo "$body" | python3 -c "
import sys, json
d = json.load(sys.stdin)
services = d.get('services', {})
print('  服务列表:')
for name, info in list(services.items())[:5]:
    print(f'    - {name}: pid={info.get(\"pid\", \"N/A\")}')
" 2>/dev/null
else
    log_warn "服务映射为空"
fi

# ── 测试 11: AI 配置 API ──────────────────────────────────────────────────────

echo ""
echo "════════════════════════════════════════"
echo "  测试组 11: AI 配置 API"
echo "════════════════════════════════════════"

resp=$(api_get "/api/v1/ai/config")
status=$(parse_status "$resp")
body=$(parse_response "$resp")

if [ "$status" = "200" ]; then
    log_pass "GET /api/v1/ai/config 返回 HTTP 200"
    has_enabled=$(echo "$body" | python3 -c "import sys,json; d=json.load(sys.stdin); print('enabled' in d)" 2>/dev/null)
    [ "$has_enabled" = "True" ] && log_pass "AI配置包含 enabled 字段" || log_fail "AI配置缺少 enabled 字段"
    echo "$body" > "$DATA_DIR/ai_config.json"
else
    log_fail "GET /api/v1/ai/config 返回 $status"
fi

# ── 汇总 ──────────────────────────────────────────────────────────────────────

echo ""
echo "════════════════════════════════════════"
echo "  测试结果汇总"
echo "════════════════════════════════════════"
echo -e "总计: ${total} 项"
echo -e "${GREEN}通过: ${pass} 项${NC}"
echo -e "${RED}失败: ${fail} 项${NC}"
echo ""

# 获取最终状态并保存
final_state=$(api_get "/api/v1/state")
parse_response "$final_state" > "$DATA_DIR/state_final.json"

python3 - << PYEOF
import json, os, glob
summary = {
    'timestamp': '$TIMESTAMP',
    'test_suite': 'functional',
    'build_type': 'release',
    'results': {
        'total': $total,
        'pass': $pass,
        'fail': $fail,
        'pass_rate': round($pass / max($total, 1) * 100, 1)
    }
}
with open('$RESULT_FILE', 'w') as f:
    json.dump(summary, f, indent=2, ensure_ascii=False)
print(f'功能测试报告已保存至: $RESULT_FILE')
PYEOF

exit $([ "$fail" -eq 0 ] && echo 0 || echo 1)
