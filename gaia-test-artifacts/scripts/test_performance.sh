#!/usr/bin/env bash
# =============================================================================
# GAIA-XDP 性能测试脚本 (release版本)
# 测量 GAIA 安全监控系统的性能指标：
#   1. CPU 使用率（空闲 vs 负载）
#   2. 内存占用（RSS/VSZ）
#   3. API 响应时延（平均/P50/P95/P99）
#   4. 事件处理吞吐量（基于 SQLite 计数）
# =============================================================================

GAIA_URL="http://localhost:17890"
RESULTS_DIR="${RESULTS_DIR:-/tmp/gaia_test_results}"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
PERF_FILE="$RESULTS_DIR/performance_${TIMESTAMP}.json"
# 数据持久化目录（默认当前目录 ~/codes/codes/gaia）
DATA_DIR="${DATA_DIR:-$(pwd)}"

mkdir -p "$RESULTS_DIR"

# 颜色定义
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m'

log_info() { echo -e "${BLUE}[INFO]${NC} $1"; }
log_ok()   { echo -e "${GREEN}[ OK ]${NC} $1"; }
log_warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }

# ── 辅助函数 ──────────────────────────────────────────────────────────────────

get_gaia_pid() {
    # 精确匹配 release 版本进程（避免捕获 sudo 进程）
    ps aux | grep 'gaia-xdp --config' | grep -v grep | awk 'NR==1{print $2}'
}

# ── 1. 进程基本信息 ───────────────────────────────────────────────────────────

echo ""
echo "════════════════════════════════════════"
echo "  性能测试 1: 进程信息采集"
echo "════════════════════════════════════════"

GAIA_PID=$(get_gaia_pid)
if [ -z "$GAIA_PID" ]; then
    echo "ERROR: gaia-xdp 未在运行，终止测试"
    exit 1
fi

log_info "gaia-xdp PID: $GAIA_PID"

# 进程启动时间
START_TIME=$(ps -o lstart= -p $GAIA_PID 2>/dev/null | xargs)
log_info "启动时间: $START_TIME"

# 线程数
THREAD_COUNT=$(ls /proc/${GAIA_PID}/task 2>/dev/null | wc -l)
log_info "线程数: $THREAD_COUNT"

# FD 数量
FD_COUNT=$(ls /proc/${GAIA_PID}/fd 2>/dev/null | wc -l)
log_info "打开的文件描述符数: $FD_COUNT"

# ── 2. 内存采集（30次 x 1s）────────────────────────────────────────────────

echo ""
echo "════════════════════════════════════════"
echo "  性能测试 2: 内存占用采样（30s）"
echo "════════════════════════════════════════"

RSS_SUM=0
RSS_MIN=999999999
RSS_MAX=0
RSS_VALS=""
SAMPLE_COUNT=30

log_info "采集 ${SAMPLE_COUNT} 次内存样本，间隔 1s..."

for i in $(seq 1 $SAMPLE_COUNT); do
    RSS=$(awk '/VmRSS/{print $2}' /proc/$GAIA_PID/status 2>/dev/null || echo 0)
    echo "  采样 $i/${SAMPLE_COUNT}: RSS=${RSS}KB"
    RSS_VALS="$RSS_VALS $RSS"
    RSS_SUM=$((RSS_SUM + RSS))
    [ "$RSS" -lt "$RSS_MIN" ] && RSS_MIN=$RSS
    [ "$RSS" -gt "$RSS_MAX" ] && RSS_MAX=$RSS
    sleep 1
done

RSS_AVG=$((RSS_SUM / SAMPLE_COUNT))

python3 - << PYEOF
import statistics, json
samples = [int(x) for x in "$RSS_VALS".split() if x]
if samples:
    avg = sum(samples)/len(samples)
    mn = min(samples)
    mx = max(samples)
    std = statistics.stdev(samples) if len(samples) > 1 else 0
    print(f'  内存统计 (RSS, KB):')
    print(f'    平均值: {avg:.1f} KB ({avg/1024:.2f} MB)')
    print(f'    最小值: {mn} KB ({mn/1024:.2f} MB)')
    print(f'    最大值: {mx} KB ({mx/1024:.2f} MB)')
    print(f'    标准差: {std:.1f} KB')
    result = {'samples_kb': samples, 'avg_kb': avg, 'min_kb': mn, 'max_kb': mx, 'stdev_kb': std}
    with open('/tmp/gaia_mem_stats.json', 'w') as f: json.dump(result, f)
PYEOF

# VmStatus
echo ""
log_info "VmStatus:"
cat /proc/$GAIA_PID/status | grep -E "^(VmRSS|VmPeak|VmSize|VmHWM|Threads)"

# 保存详细内存样本
echo "$RSS_VALS" > "$DATA_DIR/memory_samples.json"

# ── 3. CPU 使用率采样（空闲状态，15次 x 2s）────────────────────────────────────

echo ""
echo "════════════════════════════════════════"
echo "  性能测试 3: CPU 使用率采样（空闲）"
echo "════════════════════════════════════════"

log_info "采集 CPU 使用率（空闲状态，15次 x 2s = 30s）..."

CPU_IDLE_VALS=""
for i in $(seq 1 15); do
    CPU=$(ps -p $GAIA_PID -o %cpu --no-headers 2>/dev/null | tr -d ' ')
    echo "  CPU idle 采样 $i/15: CPU=${CPU}%"
    CPU_IDLE_VALS="$CPU_IDLE_VALS $CPU"
    sleep 2
done

python3 - << PYEOF
import statistics, json
samples = [float(x) for x in "$CPU_IDLE_VALS".split() if x]
if samples:
    avg = sum(samples)/len(samples)
    mn = min(samples)
    mx = max(samples)
    std = statistics.stdev(samples) if len(samples) > 1 else 0
    print(f'  CPU 使用率统计 (空闲状态):')
    print(f'    平均值: {avg:.2f}%')
    print(f'    最小值: {mn:.2f}%')
    print(f'    最大值: {mx:.2f}%')
    print(f'    标准差: {std:.2f}%')
    result = {'samples_idle': samples, 'avg_pct': avg, 'min_pct': mn, 'max_pct': mx, 'stdev_pct': std}
    with open('/tmp/gaia_cpu_stats.json', 'w') as f: json.dump(result, f)
PYEOF

# ── 4. API 响应时延测试（50次/接口）────────────────────────────────────────

echo ""
echo "════════════════════════════════════════"
echo "  性能测试 4: API 响应时延（50次/接口）"
echo "════════════════════════════════════════"

measure_latency() {
    local endpoint="$1"
    local label="$2"
    local N=50

    LATS=""
    log_info "测试 $label ($N 次请求)..."

    for i in $(seq 1 $N); do
        T=$(curl -s -o /dev/null -w "%{time_total}" --connect-timeout 5 \
              "${GAIA_URL}${endpoint}" 2>/dev/null)
        T_MS=$(python3 -c "print(round(float('${T:-0}')*1000,2))" 2>/dev/null || echo "0")
        LATS="$LATS $T_MS"
    done

    python3 - << PYEOF
import json
lats = [float(x) for x in "$LATS".split() if x]
lats.sort()
n = len(lats)
if n > 0:
    avg = sum(lats)/n
    p50 = lats[int(n*0.50)]
    p95 = lats[min(int(n*0.95), n-1)]
    p99 = lats[min(int(n*0.99), n-1)]
    mn = lats[0]
    mx = lats[-1]
    print(f'  $label 时延统计 (ms):')
    print(f'    平均: {avg:.2f}ms  P50: {p50:.2f}ms  P95: {p95:.2f}ms  P99: {p99:.2f}ms  Min: {mn:.2f}ms  Max: {mx:.2f}ms')
    result = {'endpoint': '$endpoint', 'label': '$label',
              'samples_ms': lats, 'avg_ms': avg, 'p50_ms': p50, 'p95_ms': p95,
              'p99_ms': p99, 'min_ms': mn, 'max_ms': mx}
    with open('/tmp/gaia_lat_${label// /_}.json', 'w') as f: json.dump(result, f)
PYEOF
}

measure_latency "/api/v1/state" "state"
measure_latency "/api/v1/config" "config"
measure_latency "/api/v1/history/events" "history"
measure_latency "/api/v1/kernel-livepatch/status" "klp_status"

# ── 5. 高负载下的 CPU 使用率（15次 x 2s）────────────────────────────────────

echo ""
echo "════════════════════════════════════════"
echo "  性能测试 5: 负载状态 CPU 使用率"
echo "════════════════════════════════════════"

log_info "在持续 API 请求 + 文件I/O下采集 CPU 使用率..."

# 启动后台压力
( for i in $(seq 1 300); do
    curl -s "${GAIA_URL}/api/v1/state" > /dev/null 2>&1
    curl -s "${GAIA_URL}/api/v1/config" > /dev/null 2>&1
    ls /proc > /dev/null 2>&1
    sleep 0.1
done ) &
LOAD_PID=$!

CPU_LOAD_VALS=""
for i in $(seq 1 15); do
    CPU=$(ps -p $GAIA_PID -o %cpu --no-headers 2>/dev/null | tr -d ' ')
    echo "  CPU load 采样 $i/15: CPU=${CPU}%"
    CPU_LOAD_VALS="$CPU_LOAD_VALS $CPU"
    sleep 2
done

kill $LOAD_PID 2>/dev/null; wait $LOAD_PID 2>/dev/null

python3 - << PYEOF
import json
samples = [float(x) for x in "$CPU_LOAD_VALS".split() if x]
if samples:
    avg = sum(samples)/len(samples)
    mn = min(samples)
    mx = max(samples)
    print(f'  CPU 使用率统计 (负载状态):')
    print(f'    平均值: {avg:.2f}%')
    print(f'    最小值: {mn:.2f}%')
    print(f'    最大值: {mx:.2f}%')
    try:
        with open('/tmp/gaia_cpu_stats.json') as f:
            d = json.load(f)
    except:
        d = {}
    d.update({'samples_load': samples, 'avg_pct_load': avg, 'min_pct_load': mn, 'max_pct_load': mx})
    with open('/tmp/gaia_cpu_stats.json', 'w') as f: json.dump(d, f)
PYEOF

# ── 6. 事件处理吞吐量（SQLite计数法）────────────────────────────────────────

echo ""
echo "════════════════════════════════════════"
echo "  性能测试 6: 事件处理吞吐量（SQLite）"
echo "════════════════════════════════════════"

DB="$DATA_DIR/gaia-events.db"
if [ ! -f "$DB" ]; then
    log_warn "SQLite数据库 $DB 不存在，跳过吞吐量测试"
else
    log_info "通过 SQLite 事件计数测量吞吐量..."

    B_SQL=$(sqlite3 "$DB" "SELECT COUNT(*) FROM events;" 2>/dev/null || echo "0")
    START_NS=$(date +%s%N)

    # 触发 1000 次 ls /proc 系统调用（产生 eBPF 事件）
    for i in $(seq 1 1000); do ls /proc > /dev/null 2>&1; done

    END_NS=$(date +%s%N)
    sleep 3  # 等待事件写入 SQLite

    A_SQL=$(sqlite3 "$DB" "SELECT COUNT(*) FROM events;" 2>/dev/null || echo "0")
    ELAPSED_MS=$(( (END_NS - START_NS) / 1000000 ))
    ELAPSED_S=$(python3 -c "print(round($ELAPSED_MS/1000, 3))" 2>/dev/null || echo "0")
    EVENTS_SQL=$((A_SQL - B_SQL))

    if [ "$ELAPSED_MS" -gt 0 ]; then
        TPUT=$(python3 -c "print(int($EVENTS_SQL * 1000 / $ELAPSED_MS))" 2>/dev/null || echo "0")
    else
        TPUT=0
    fi

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
with open('/tmp/gaia_throughput.json', 'w') as f: json.dump(result, f)
print(f'  吞吐量: {$TPUT} events/s（触发{$EVENTS_SQL}个事件，耗时{float("$ELAPSED_S"):.3f}s）')
PYEOF

    # 保存到数据目录
    cp /tmp/gaia_throughput.json "$DATA_DIR/throughput.json" 2>/dev/null
fi

# ── 7. 汇总所有性能数据 ───────────────────────────────────────────────────────

echo ""
echo "════════════════════════════════════════"
echo "  性能测试汇总"
echo "════════════════════════════════════════"

python3 - << PYEOF
import json, os

perf_data = {
    'timestamp': '$TIMESTAMP',
    'gaia_pid': $GAIA_PID,
    'thread_count': $THREAD_COUNT,
    'fd_count': $FD_COUNT,
    'build_type': 'release',
}

try:
    with open('/tmp/gaia_mem_stats.json') as f:
        perf_data['memory'] = json.load(f)
except: pass

try:
    with open('/tmp/gaia_cpu_stats.json') as f:
        perf_data['cpu'] = json.load(f)
except: pass

for label in ['state', 'config', 'history', 'klp_status']:
    try:
        with open(f'/tmp/gaia_lat_{label}.json') as f:
            perf_data.setdefault('api_latency', {})[label] = json.load(f)
    except: pass

try:
    with open('/tmp/gaia_throughput.json') as f:
        perf_data['throughput'] = json.load(f)
except: pass

print('  性能指标摘要 (release版本):')
if 'memory' in perf_data:
    mem = perf_data['memory']
    print(f"    内存占用 (RSS): 平均 {mem['avg_kb']/1024:.2f} MB，峰值 {mem['max_kb']/1024:.2f} MB，σ={mem['stdev_kb']:.1f}KB")
if 'cpu' in perf_data:
    cpu = perf_data['cpu']
    print(f"    CPU 使用率 (空闲): 平均 {cpu.get('avg_pct', 0):.2f}%")
    if 'avg_pct_load' in cpu:
        print(f"    CPU 使用率 (负载): 平均 {cpu['avg_pct_load']:.2f}%")
if 'api_latency' in perf_data:
    for ep, data in perf_data['api_latency'].items():
        print(f"    API [{ep}]: 平均 {data['avg_ms']:.2f}ms，P95 {data['p95_ms']:.2f}ms，P99 {data['p99_ms']:.2f}ms")
if 'throughput' in perf_data:
    tp = perf_data['throughput']
    print(f"    事件处理吞吐: {tp['throughput_eps']} events/s")

with open('$PERF_FILE', 'w') as f:
    json.dump(perf_data, f, indent=2, ensure_ascii=False)
print(f'  性能报告已保存至: $PERF_FILE')
PYEOF

# 清理临时文件
rm -f /tmp/gaia_mem_stats.json /tmp/gaia_cpu_stats.json \
      /tmp/gaia_throughput.json /tmp/gaia_lat_*.json

echo ""
log_ok "性能测试完成（release版本）"
