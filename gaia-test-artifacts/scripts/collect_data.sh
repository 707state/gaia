#!/usr/bin/env bash
# =============================================================================
# GAIA-XDP 综合数据采集脚本 (release版本)
# 一次性采集系统状态、API延迟、内存、CPU、吞吐量等全部测试数据
# 使用方式：cd ~/codes/codes/gaia && bash collect_data.sh
# =============================================================================
GAIA_URL="http://localhost:17890"
DATA_DIR="${DATA_DIR:-$(pwd)}"
OUT_DIR="/tmp/gaia_test_results"
mkdir -p "$OUT_DIR"

# 精确获取 gaia-xdp 进程 PID（找 RSS 最大的那个，即实际进程而非 sudo）
GAIA_PID=$(ps aux | grep 'gaia-xdp --config' | grep -v grep | awk '{print $2, $6}' | sort -k2 -rn | awk 'NR==1{print $1}')
if [ -z "$GAIA_PID" ]; then
    echo "ERROR: gaia-xdp not running"
    exit 1
fi
echo "gaia-xdp PID: $GAIA_PID"

# ── 1. 系统与进程基本信息 ─────────────────────────────────────────────────────
echo ""
echo "=== 1. 进程状态 ==="
ps -p $GAIA_PID -o pid,ppid,rss,nlwp,pcpu,comm 2>/dev/null
echo ""
cat /proc/$GAIA_PID/status | grep -E "^(VmRSS|VmPeak|VmSize|VmHWM|Threads)"

# ── 2. 系统状态快照 ───────────────────────────────────────────────────────────
echo ""
echo "=== 2. API 状态快照 ==="
curl -s "${GAIA_URL}/api/v1/state" | python3 -c "
import sys, json
d = json.load(sys.stdin)
counters = d.get('counters', {})
print('Counters:', json.dumps(counters, indent=2))
print('Events count:', len(d.get('events', [])))
print('Alerts count:', len(d.get('alerts', [])))
print('Services:', list(d.get('services', {}).keys()))
with open('$DATA_DIR/state_full.json', 'w') as f:
    json.dump(d, f, indent=2, ensure_ascii=False)
" 2>/dev/null
echo ""

# ── 3. API 响应延迟（50次/接口）────────────────────────────────────────────
echo "=== 3. API 延迟测试 ==="

measure_api() {
    local endpoint="$1"
    local label="$2"
    local N=50
    local LATS=""
    echo "  Testing $label ($N requests)..."
    for i in $(seq 1 $N); do
        T=$(curl -s -o /dev/null -w "%{time_total}" --connect-timeout 5 "${GAIA_URL}${endpoint}" 2>/dev/null)
        T_MS=$(python3 -c "print(round(float('${T:-0}')*1000,2))" 2>/dev/null || echo "0")
        LATS="$LATS $T_MS"
    done
    python3 - << PYEOF
import json, statistics
lats = [float(x) for x in "$LATS".split() if x]
lats.sort()
n = len(lats)
if n > 0:
    avg = sum(lats)/n
    p50 = lats[int(n*0.50)]
    p95 = lats[min(int(n*0.95), n-1)]
    p99 = lats[min(int(n*0.99), n-1)]
    print(f'  $label: avg={avg:.2f}ms p50={p50:.2f}ms p95={p95:.2f}ms p99={p99:.2f}ms min={lats[0]:.2f}ms max={lats[-1]:.2f}ms')
    result = {'endpoint': '$endpoint', 'label': '$label',
              'samples_ms': lats, 'avg_ms': avg, 'p50_ms': p50, 'p95_ms': p95,
              'p99_ms': p99, 'min_ms': lats[0], 'max_ms': lats[-1]}
    with open('$DATA_DIR/lat_$label.json', 'w') as f: json.dump(result, f)
PYEOF
}

measure_api "/api/v1/state" "state"
measure_api "/api/v1/config" "config"
measure_api "/api/v1/history/events" "history"
measure_api "/api/v1/kernel-livepatch/status" "klp_status"

# ── 4. 内存采样（30s）────────────────────────────────────────────────────────
echo ""
echo "=== 4. 内存采样（30s）==="
RSS_SUM=0; RSS_MIN=999999999; RSS_MAX=0; RSS_VALS=""
for i in $(seq 1 30); do
    RSS=$(awk '/VmRSS/{print $2}' /proc/$GAIA_PID/status 2>/dev/null || echo 0)
    RSS_VALS="$RSS_VALS $RSS"
    RSS_SUM=$((RSS_SUM + RSS))
    [ "$RSS" -lt "$RSS_MIN" ] && RSS_MIN=$RSS
    [ "$RSS" -gt "$RSS_MAX" ] && RSS_MAX=$RSS
    sleep 1
done
python3 - << PYEOF
import json, statistics
s = [int(x) for x in "$RSS_VALS".split() if x]
if s:
    avg = sum(s)/len(s)
    std = statistics.stdev(s) if len(s)>1 else 0
    print(f'Memory RSS: avg={avg/1024:.2f}MB min={min(s)/1024:.2f}MB max={max(s)/1024:.2f}MB std={std:.1f}KB')
    data = {'samples_kb': s, 'avg_kb': avg, 'min_kb': min(s), 'max_kb': max(s), 'stdev_kb': std}
    with open('$DATA_DIR/memory_samples.json', 'w') as f: json.dump(data, f)
PYEOF

# ── 5. 空闲 CPU 采样（15次x2s）──────────────────────────────────────────────
echo ""
echo "=== 5. CPU 空闲采样（15*2s）==="
CPU_IDLE_VALS=""
for i in $(seq 1 15); do
    CPU=$(ps -p $GAIA_PID -o pcpu --no-headers 2>/dev/null | tr -d ' ')
    echo "  idle $i: CPU=${CPU}%"
    CPU_IDLE_VALS="$CPU_IDLE_VALS $CPU"
    sleep 2
done
python3 - << PYEOF
import json, statistics
s = [float(x) for x in "$CPU_IDLE_VALS".split() if x]
if s:
    avg = sum(s)/len(s)
    std = statistics.stdev(s) if len(s)>1 else 0
    print(f'CPU idle: avg={avg:.2f}% min={min(s):.2f}% max={max(s):.2f}% std={std:.2f}%')
    data = {'mode': 'idle', 'samples_pct': s, 'avg_pct': avg, 'min_pct': min(s), 'max_pct': max(s), 'stdev_pct': std}
    with open('$DATA_DIR/cpu_idle.json', 'w') as f: json.dump(data, f)
PYEOF

# ── 6. 负载 CPU 采样（15次x2s）──────────────────────────────────────────────
echo ""
echo "=== 6. CPU 负载采样（15*2s）==="
bash -c "for i in \$(seq 1 300); do ls /proc > /dev/null 2>&1; curl -s ${GAIA_URL}/api/v1/state > /dev/null 2>&1; sleep 0.1; done" &
LOAD_PID=$!
CPU_LOAD_VALS=""
for i in $(seq 1 15); do
    CPU=$(ps -p $GAIA_PID -o pcpu --no-headers 2>/dev/null | tr -d ' ')
    echo "  load $i: CPU=${CPU}%"
    CPU_LOAD_VALS="$CPU_LOAD_VALS $CPU"
    sleep 2
done
kill $LOAD_PID 2>/dev/null; wait $LOAD_PID 2>/dev/null
python3 - << PYEOF
import json, statistics
s = [float(x) for x in "$CPU_LOAD_VALS".split() if x]
if s:
    avg = sum(s)/len(s)
    std = statistics.stdev(s) if len(s)>1 else 0
    print(f'CPU load: avg={avg:.2f}% min={min(s):.2f}% max={max(s):.2f}% std={std:.2f}%')
    data = {'mode': 'loaded', 'samples_pct': s, 'avg_pct': avg, 'min_pct': min(s), 'max_pct': max(s), 'stdev_pct': std}
    with open('$DATA_DIR/cpu_load.json', 'w') as f: json.dump(data, f)
PYEOF

# ── 7. 吞吐量测试（SQLite计数法）────────────────────────────────────────────
echo ""
echo "=== 7. 吞吐量测试（SQLite）==="
DB="$DATA_DIR/gaia-events.db"
if [ -f "$DB" ]; then
    B_SQL=$(sqlite3 "$DB" "SELECT COUNT(*) FROM events;" 2>/dev/null || echo "0")
    START_NS=$(date +%s%N)
    for i in $(seq 1 1000); do ls /proc > /dev/null 2>&1; done
    END_NS=$(date +%s%N)
    sleep 3
    A_SQL=$(sqlite3 "$DB" "SELECT COUNT(*) FROM events;" 2>/dev/null || echo "0")
    ELAPSED_MS=$(( (END_NS - START_NS) / 1000000 ))
    ELAPSED_S=$(python3 -c "print(round($ELAPSED_MS/1000, 3))")
    EVENTS_SQL=$((A_SQL - B_SQL))
    TPUT=$(python3 -c "print(int($EVENTS_SQL * 1000 / max($ELAPSED_MS, 1)))")
    echo "  SQLite: before=$B_SQL after=$A_SQL events=$EVENTS_SQL elapsed=${ELAPSED_S}s throughput=$TPUT eps"
    python3 - << PYEOF
import json
result = {
    'method': 'sqlite_count',
    'syscall_triggers': 1000,
    'before': $B_SQL, 'after': $A_SQL,
    'events': $EVENTS_SQL,
    'elapsed_s': float('$ELAPSED_S'),
    'elapsed_ms': $ELAPSED_MS,
    'throughput_eps': $TPUT
}
with open('$DATA_DIR/throughput.json', 'w') as f: json.dump(result, f)
PYEOF
else
    echo "  [WARN] SQLite DB not found at $DB"
fi

# ── 8. 历史事件统计 ───────────────────────────────────────────────────────────
echo ""
echo "=== 8. 历史事件统计 ==="
curl -s "${GAIA_URL}/api/v1/history/events?page=0&page_size=200" > "$DATA_DIR/history_events.json"
python3 - << PYEOF
import json
with open('$DATA_DIR/history_events.json') as f:
    d = json.load(f)
items = d if isinstance(d, list) else d.get('items', d.get('events', []))
from collections import Counter
kinds = Counter(e.get('kind','?') for e in items)
print(f'历史事件数(首页): {len(items)}')
print('类型分布:')
for k,v in kinds.most_common():
    print(f'  {k}: {v}')
PYEOF

# ── 9. 告警快照 ──────────────────────────────────────────────────────────────
echo ""
echo "=== 9. 告警快照 ==="
curl -s "${GAIA_URL}/api/v1/state" | python3 - << PYEOF
import sys, json
d = json.load(sys.stdin)
alerts = d.get('alerts', [])
print(f'告警总数: {len(alerts)}')
from collections import Counter
levels = Counter(a.get('level','?') for a in alerts)
for k,v in levels.most_common():
    print(f'  {k}: {v}')
with open('$DATA_DIR/alerts.json', 'w') as f:
    json.dump(alerts, f, indent=2, ensure_ascii=False)
PYEOF

echo ""
echo "=== 数据采集完成 ==="
echo "输出目录: $DATA_DIR"
ls -la "$DATA_DIR"/*.json 2>/dev/null | tail -20
