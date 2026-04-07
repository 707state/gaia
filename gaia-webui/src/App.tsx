import { useCallback, useEffect, useMemo, useState } from 'react'
import './App.css'

// ── Types ──

type EventRecord = {
  timestamp_ns: number
  kind: string
  action: string
  pid: number
  tgid: number
  uid: number
  gid: number
  comm: string
  detail: string
  network?: { port: number; address: string }
  service?: string
}

type AlertRecord = { level: string; reason: string; event: EventRecord }

type NetIfTraffic = {
  name: string
  rx_bytes_per_sec: number
  tx_bytes_per_sec: number
  rx_packets_per_sec: number
  tx_packets_per_sec: number
}

type TrafficSnapshot = {
  interfaces: NetIfTraffic[]
  total_rx_bytes_per_sec: number
  total_tx_bytes_per_sec: number
}

type Snapshot = {
  features: {
    file_io_agent: boolean
    process_agent: boolean
    network_agent: boolean
    hotpatch_agent: boolean
    anomaly_engine: boolean
    symbol_resolver: boolean
  }
  counters: Record<string, number>
  services: Record<string, ServiceStatusInfo>
  events: EventRecord[]
  alerts: AlertRecord[]
  traffic: TrafficSnapshot
}

type ServiceStatusInfo = {
  active_state: string
  sub_state: string
  state: string
  pids: number[]
}

type ToggleItem = {
  value: string
  enabled: boolean
}

type ProcessMemory = {
  vm_peak_kb: number; vm_size_kb: number; vm_rss_kb: number; vm_swap_kb: number
  vm_data_kb: number; vm_stk_kb: number; vm_exe_kb: number; vm_lib_kb: number
}
type ProcessIo = {
  rchar: number; wchar: number; syscr: number; syscw: number
  read_bytes: number; write_bytes: number
}
type FdEntry = { fd: number; target: string }
type ProcessDetail = {
  pid: number; name: string; state: string; ppid: number
  uid: number; gid: number; euid: number; egid: number; threads: number
  cmdline: string; exe: string; cwd: string; uptime_secs: number
  mem: ProcessMemory; io: ProcessIo; fds: FdEntry[]
  voluntary_ctxt_switches: number; nonvoluntary_ctxt_switches: number
  oom_score: number; seccomp: string; cap_eff: string
  environ: string[]; cpus_allowed_list: string
}

type TogglePort = {
  port: number
  enabled: boolean
}

type RateLimitRule = {
  cidr: string
  max_conn_per_sec: number
  action: 'log' | 'block' | 'throttle'
  enabled: boolean
}

type PatchAction = 'monitor' | 'override_return' | 'skip_call' | 'replace_function'

type HotpatchTarget = {
  binary: string
  symbol: string
  pid?: number | null
  enabled: boolean
  patch_action: PatchAction
  override_return_value: number
  replace_lib?: string | null
  replace_symbol?: string | null
}

type MonitorPolicy = {
  sensitive_prefixes: ToggleItem[]
  monitored_services: ToggleItem[]
  exec_whitelist_prefixes: ToggleItem[]
  blocked_ports: TogglePort[]
  baseline_thresholds: Record<string, number>
  hotpatch: { targets: HotpatchTarget[] }
  rate_limit_rules: RateLimitRule[]
}

type Tab = 'overview' | 'file' | 'process' | 'network' | 'hotpatch' | 'alerts' | 'config'
type Lang = 'zh' | 'en'

// ── Mock data ──

const mockSnapshot: Snapshot = {
  features: {
    file_io_agent: true,
    process_agent: true,
    network_agent: true,
    hotpatch_agent: true,
    anomaly_engine: true,
    symbol_resolver: true,
  },
  counters: { file_io: 341, process: 88, privilege: 5, network: 152, hotpatch: 11 },
  services: {
    'sshd.service': { active_state: 'active', sub_state: 'running', state: 'active (running)', pids: [721] },
    'nginx.service': { active_state: 'active', sub_state: 'running', state: 'active (running)', pids: [1142, 1145, 1148] },
    'redis.service': { active_state: 'active', sub_state: 'running', state: 'active (running)', pids: [2001] },
    'postgresql.service': { active_state: 'active', sub_state: 'running', state: 'active (running)', pids: [3010, 3011] },
  },
  events: [
    {
      timestamp_ns: Date.now() * 1e6 - 1e9 * 0,
      kind: 'network', action: 'blocked', pid: 1148, tgid: 1148, uid: 33, gid: 33,
      comm: 'nginx', detail: 'connect attempt matched blocked_ports policy',
      network: { port: 4444, address: '192.168.1.19' },
    },
    {
      timestamp_ns: Date.now() * 1e6 - 1e9 * 2,
      kind: 'file_io', action: 'alert', pid: 721, tgid: 721, uid: 0, gid: 0,
      comm: 'sshd', detail: '/etc/shadow',
    },
    {
      timestamp_ns: Date.now() * 1e6 - 1e9 * 5,
      kind: 'process', action: 'enter', pid: 5521, tgid: 5521, uid: 0, gid: 0,
      comm: 'bash', detail: '/usr/bin/curl',
    },
    {
      timestamp_ns: Date.now() * 1e6 - 1e9 * 8,
      kind: 'privilege', action: 'alert', pid: 5521, tgid: 5521, uid: 1000, gid: 1000,
      comm: 'sudo', detail: 'setuid:0',
    },
    {
      timestamp_ns: Date.now() * 1e6 - 1e9 * 12,
      kind: 'network', action: 'enter', pid: 1142, tgid: 1142, uid: 33, gid: 33,
      comm: 'nginx', detail: 'outbound connection',
      network: { port: 443, address: '93.184.216.34' },
    },
    {
      timestamp_ns: Date.now() * 1e6 - 1e9 * 15,
      kind: 'file_io', action: 'enter', pid: 2001, tgid: 2001, uid: 999, gid: 999,
      comm: 'redis-server', detail: '/var/lib/redis/dump.rdb',
    },
    {
      timestamp_ns: Date.now() * 1e6 - 1e9 * 20,
      kind: 'hotpatch', action: 'enter', pid: 1142, tgid: 1142, uid: 33, gid: 33,
      comm: 'nginx', detail: 'uprobe-entry',
    },
    {
      timestamp_ns: Date.now() * 1e6 - 1e9 * 25,
      kind: 'network', action: 'rate_limited', pid: 9921, tgid: 9921, uid: 0, gid: 0,
      comm: 'scanner', detail: 'rate-limit:exceeded',
      network: { port: 80, address: '10.0.0.55' },
    },
    {
      timestamp_ns: Date.now() * 1e6 - 1e9 * 30,
      kind: 'file_io', action: 'alert', pid: 3010, tgid: 3010, uid: 26, gid: 26,
      comm: 'postgres', detail: '/etc/ssl/private/server.key',
    },
    {
      timestamp_ns: Date.now() * 1e6 - 1e9 * 35,
      kind: 'process', action: 'enter', pid: 7788, tgid: 7788, uid: 0, gid: 0,
      comm: 'cron', detail: '/usr/sbin/logrotate',
    },
  ],
  traffic: {
    interfaces: [
      { name: 'eth0', rx_bytes_per_sec: 125400, tx_bytes_per_sec: 48200, rx_packets_per_sec: 320, tx_packets_per_sec: 180 },
      { name: 'lo', rx_bytes_per_sec: 8500, tx_bytes_per_sec: 8500, rx_packets_per_sec: 42, tx_packets_per_sec: 42 },
    ],
    total_rx_bytes_per_sec: 125400,
    total_tx_bytes_per_sec: 48200,
  },
  alerts: [
    {
      level: 'critical',
      reason: 'Blocked outbound connection on port 4444 — active defense policy triggered',
      event: {
        timestamp_ns: Date.now() * 1e6, kind: 'network', action: 'blocked',
        pid: 1148, tgid: 1148, uid: 33, gid: 33, comm: 'nginx',
        detail: 'connect attempt matched blocked_ports policy',
        network: { port: 4444, address: '192.168.1.19' },
      },
    },
    {
      level: 'high',
      reason: 'Sensitive file /etc/shadow accessed by sshd (pid 721)',
      event: {
        timestamp_ns: Date.now() * 1e6 - 2e9, kind: 'file_io', action: 'alert',
        pid: 721, tgid: 721, uid: 0, gid: 0, comm: 'sshd', detail: '/etc/shadow',
      },
    },
    {
      level: 'high',
      reason: 'Privilege escalation: setuid:0 by sudo (pid 5521)',
      event: {
        timestamp_ns: Date.now() * 1e6 - 8e9, kind: 'privilege', action: 'alert',
        pid: 5521, tgid: 5521, uid: 1000, gid: 1000, comm: 'sudo', detail: 'setuid:0',
      },
    },
    {
      level: 'high',
      reason: 'IP rate limit exceeded from 10.0.0.55',
      event: {
        timestamp_ns: Date.now() * 1e6 - 25e9, kind: 'network', action: 'rate_limited',
        pid: 9921, tgid: 9921, uid: 0, gid: 0, comm: 'scanner', detail: 'rate-limit:exceeded',
        network: { port: 80, address: '10.0.0.55' },
      },
    },
    {
      level: 'medium',
      reason: 'Syscall baseline exceeded for file_io: 215 > 200 in 30s window',
      event: {
        timestamp_ns: Date.now() * 1e6 - 40e9, kind: 'file_io', action: 'enter',
        pid: 1142, tgid: 1142, uid: 33, gid: 33, comm: 'nginx', detail: '/var/log/nginx/access.log',
      },
    },
  ],
}

// ── i18n helpers ──

const featureMeta: [string, { zh: string; en: string; icon: string; desc_zh: string; desc_en: string }][] = [
  ['file_io_agent', { zh: '文件 I/O 代理', en: 'File I/O Agent', icon: '📁', desc_zh: '监控 openat 系统调用，检测敏感文件访问', desc_en: 'Monitors openat syscalls, detects sensitive file access' }],
  ['process_agent', { zh: '进程与权限代理', en: 'Process & Privilege Agent', icon: '⚙️', desc_zh: '追踪 execve/setuid/setgid，检测权限提升', desc_en: 'Tracks execve/setuid/setgid, detects privilege escalation' }],
  ['network_agent', { zh: '网络遥测代理', en: 'Network Telemetry Agent', icon: '🌐', desc_zh: '监控 connect/bind，检测异常外连与端口绑定', desc_en: 'Monitors connect/bind, detects abnormal outbound & port binding' }],
  ['hotpatch_agent', { zh: '热补丁代理', en: 'Hot-patching Agent', icon: '🔥', desc_zh: '通过 kprobe/uprobe 实现运行时函数热补丁', desc_en: 'Runtime function hot-patching via kprobe/uprobe' }],
  ['anomaly_engine', { zh: '异常检测引擎', en: 'Anomaly Detection Engine', icon: '🧠', desc_zh: '白名单规则校验 + 统计基线异常检测', desc_en: 'Whitelist rule checks + statistical baseline anomaly detection' }],
  ['symbol_resolver', { zh: '动态符号解析器', en: 'Symbol Resolver', icon: '🔍', desc_zh: '解析 ELF 符号表与 /proc/maps，克服 ASLR', desc_en: 'Parses ELF symbol tables & /proc/maps, bypasses ASLR' }],
]

function initialLang(): Lang {
  const saved = localStorage.getItem('gaia_lang')
  if (saved === 'zh' || saved === 'en') return saved
  return navigator.language.toLowerCase().startsWith('zh') ? 'zh' : 'en'
}

function mapKind(kind: string, lang: Lang) {
  const m: Record<string, { zh: string; en: string }> = {
    file_io: { zh: '文件 I/O', en: 'File I/O' },
    process: { zh: '进程', en: 'Process' },
    privilege: { zh: '权限提升', en: 'Privilege' },
    network: { zh: '网络', en: 'Network' },
    hotpatch: { zh: '热补丁', en: 'Hotpatch' },
    unknown: { zh: '未知', en: 'Unknown' },
  }
  return (m[kind] ?? { zh: kind, en: kind })[lang]
}

function mapAction(action: string, lang: Lang) {
  const m: Record<string, { zh: string; en: string }> = {
    enter: { zh: '进入', en: 'Enter' },
    exit: { zh: '退出', en: 'Exit' },
    alert: { zh: '告警', en: 'Alert' },
    blocked: { zh: '阻断', en: 'Blocked' },
    rate_limited: { zh: '限流', en: 'Rate Limited' },
    unknown: { zh: '未知', en: 'Unknown' },
  }
  return (m[action] ?? { zh: action, en: action })[lang]
}

function formatTimestamp(ns: number) {
  const ms = ns / 1e6
  const d = new Date(ms)
  if (isNaN(d.getTime())) return '-'
  return d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit' })
}

function relativeTime(ns: number, lang: Lang) {
  const diff = Date.now() - ns / 1e6
  if (diff < 0 || isNaN(diff)) return '-'
  const secs = Math.floor(diff / 1000)
  if (secs < 60) return lang === 'zh' ? `${secs}秒前` : `${secs}s ago`
  const mins = Math.floor(secs / 60)
  if (mins < 60) return lang === 'zh' ? `${mins}分钟前` : `${mins}m ago`
  const hrs = Math.floor(mins / 60)
  return lang === 'zh' ? `${hrs}小时前` : `${hrs}h ago`
}

// ── Tab definitions ──

const tabDefs: { key: Tab; zh: string; en: string; icon: string }[] = [
  { key: 'overview', zh: '总览', en: 'Overview', icon: '📊' },
  { key: 'file', zh: '文件监控', en: 'File I/O', icon: '📁' },
  { key: 'process', zh: '进程监控', en: 'Process', icon: '⚙️' },
  { key: 'network', zh: '网络监控', en: 'Network', icon: '🌐' },
  { key: 'hotpatch', zh: '热补丁', en: 'Hotpatch', icon: '🔥' },
  { key: 'alerts', zh: '告警中心', en: 'Alerts', icon: '🚨' },
  { key: 'config', zh: '系统配置', en: 'Config', icon: '⚡' },
]

// ── Main App ──

function App() {
  const [tab, setTab] = useState<Tab>('overview')
  const [lang, setLang] = useState<Lang>(initialLang)
  const [snapshot, setSnapshot] = useState<Snapshot>(mockSnapshot)
  const [live, setLive] = useState(false)
  const [procDetail, setProcDetail] = useState<ProcessDetail | null>(null)
  const [procLoading, setProcLoading] = useState(false)

  const tr = useCallback((zh: string, en: string) => (lang === 'zh' ? zh : en), [lang])

  const openProcessDetail = useCallback(async (pid: number) => {
    setProcLoading(true)
    setProcDetail(null)
    try {
      const r = await fetch(`/api/v1/process/${pid}`)
      if (r.ok) {
        const data = (await r.json()) as ProcessDetail
        setProcDetail(data)
      }
    } catch { /* ignore */ }
    setProcLoading(false)
  }, [])

  useEffect(() => { localStorage.setItem('gaia_lang', lang) }, [lang])

  useEffect(() => {
    let cancelled = false
    const pull = async () => {
      try {
        const r = await fetch('/api/v1/state')
        if (!r.ok) return
        const data = (await r.json()) as Snapshot
        if (!cancelled) { setSnapshot(data); setLive(true) }
      } catch { if (!cancelled) setLive(false) }
    }
    pull()
    const timer = window.setInterval(pull, 2000)
    return () => { cancelled = true; window.clearInterval(timer) }
  }, [])

  const totalEvents = useMemo(
    () => Object.values(snapshot.counters).reduce((s, v) => s + v, 0),
    [snapshot.counters],
  )

  const alertCount = snapshot.alerts.length
  const criticalCount = snapshot.alerts.filter(a => a.level === 'critical').length

  return (
    <div className="gaia-app">
      {/* ── Sidebar ── */}
      <aside className="sidebar">
        <div className="sidebar-brand">
          <div className="brand-icon">🛡️</div>
          <div className="brand-text">
            <h1>GAIA</h1>
            <span>{tr('安全监控平面', 'Security Plane')}</span>
          </div>
        </div>

        <nav className="sidebar-nav">
          {tabDefs.map(t => (
            <button
              key={t.key}
              className={`nav-item ${tab === t.key ? 'active' : ''}`}
              onClick={() => setTab(t.key)}
            >
              <span className="nav-icon">{t.icon}</span>
              <span className="nav-label">{t[lang]}</span>
              {t.key === 'alerts' && alertCount > 0 && (
                <span className={`nav-badge ${criticalCount > 0 ? 'critical' : ''}`}>{alertCount}</span>
              )}
            </button>
          ))}
        </nav>

        <div className="sidebar-footer">
          <div className={`status-indicator ${live ? 'live' : 'offline'}`}>
            <span className="status-dot" />
            <span>{live ? tr('实时数据', 'Live') : tr('模拟数据', 'Mock')}</span>
          </div>
          <button className="lang-btn" onClick={() => setLang(l => l === 'zh' ? 'en' : 'zh')}>
            {lang === 'zh' ? 'EN' : '中文'}
          </button>
        </div>
      </aside>

      {/* ── Main content ── */}
      <main className="main-content">
        <header className="content-header">
          <h2>{tabDefs.find(t => t.key === tab)?.icon} {tabDefs.find(t => t.key === tab)?.[lang]}</h2>
          <div className="header-meta">
            <span className="meta-chip">{tr('事件总数', 'Total Events')}: <strong>{totalEvents.toLocaleString()}</strong></span>
            <span className="meta-chip">{tr('跟踪服务', 'Services')}: <strong>{Object.keys(snapshot.services).length}</strong></span>
          </div>
        </header>

        <div className="content-body">
          {tab === 'overview' && <OverviewTab snapshot={snapshot} totalEvents={totalEvents} lang={lang} tr={tr} onPidClick={openProcessDetail} />}
          {tab === 'file' && <FileTab snapshot={snapshot} lang={lang} tr={tr} />}
          {tab === 'process' && <ProcessTab snapshot={snapshot} lang={lang} tr={tr} />}
          {tab === 'network' && <NetworkTab snapshot={snapshot} lang={lang} tr={tr} />}
          {tab === 'hotpatch' && <HotpatchTab snapshot={snapshot} lang={lang} tr={tr} />}
          {tab === 'alerts' && <AlertsTab snapshot={snapshot} lang={lang} tr={tr} />}
          {tab === 'config' && <ConfigTab lang={lang} tr={tr} />}
        </div>
      </main>

      <ProcessDetailModal
        detail={procDetail}
        loading={procLoading}
        tr={tr}
        onClose={() => { setProcDetail(null); setProcLoading(false) }}
      />
    </div>
  )
}

// ── Overview Tab ──

function OverviewTab({ snapshot, totalEvents, lang, tr, onPidClick }: {
  snapshot: Snapshot; totalEvents: number; lang: Lang; tr: (zh: string, en: string) => string; onPidClick?: (pid: number) => void
}) {
  const criticals = snapshot.alerts.filter(a => a.level === 'critical').length
  const highs = snapshot.alerts.filter(a => a.level === 'high').length

  return (
    <div className="tab-content">
      {/* Stats cards */}
      <div className="stats-grid">
        <div className="stat-card accent-blue">
          <div className="stat-icon">📈</div>
          <div className="stat-body">
            <span className="stat-label">{tr('事件总数', 'Total Events')}</span>
            <span className="stat-value">{totalEvents.toLocaleString()}</span>
          </div>
        </div>
        <div className="stat-card accent-red">
          <div className="stat-icon">🚨</div>
          <div className="stat-body">
            <span className="stat-label">{tr('严重告警', 'Critical Alerts')}</span>
            <span className="stat-value">{criticals}</span>
          </div>
        </div>
        <div className="stat-card accent-orange">
          <div className="stat-icon">⚠️</div>
          <div className="stat-body">
            <span className="stat-label">{tr('高危告警', 'High Alerts')}</span>
            <span className="stat-value">{highs}</span>
          </div>
        </div>
        <div className="stat-card accent-green">
          <div className="stat-icon">🖥️</div>
          <div className="stat-body">
            <span className="stat-label">{tr('跟踪服务', 'Tracked Services')}</span>
            <span className="stat-value">{Object.keys(snapshot.services).length}</span>
          </div>
        </div>
      </div>

      {/* Agent status */}
      <div className="card">
        <div className="card-header">
          <h3>{tr('代理探针状态', 'Agent Probe Status')}</h3>
          <span className="card-badge">{featureMeta.filter(([k]) => snapshot.features[k as keyof typeof snapshot.features]).length}/{featureMeta.length} {tr('运行中', 'Active')}</span>
        </div>
        <div className="agent-grid">
          {featureMeta.map(([key, meta]) => {
            const active = snapshot.features[key as keyof typeof snapshot.features]
            return (
              <div key={key} className={`agent-card ${active ? 'active' : 'down'}`}>
                <div className="agent-icon">{meta.icon}</div>
                <div className="agent-info">
                  <span className="agent-name">{meta[lang]}</span>
                  <span className="agent-desc">{lang === 'zh' ? meta.desc_zh : meta.desc_en}</span>
                </div>
                <span className={`agent-status ${active ? 'active' : 'down'}`}>
                  {active ? tr('运行中', 'ACTIVE') : tr('离线', 'DOWN')}
                </span>
              </div>
            )
          })}
        </div>
      </div>

      {/* Two-column: Services + Counters */}
      <div className="grid-2col">
        <div className="card">
          <div className="card-header">
            <h3>{tr('Systemd 服务追踪', 'Systemd Service Tracker')}</h3>
          </div>
          <div className="service-list">
            {Object.entries(snapshot.services).map(([svc, info]) => (
              <div key={svc} className="service-item">
                <div className="service-name">
                  <span className={`service-dot ${info.active_state === 'active' ? 'dot-active' : info.active_state === 'failed' ? 'dot-failed' : 'dot-inactive'}`} />
                  {svc}
                  <span className={`systemd-state ${info.active_state === 'active' ? 'state-active' : info.active_state === 'failed' ? 'state-failed' : 'state-inactive'}`}>{info.state}</span>
                </div>
                <div className="service-pids">
                  {info.pids.map(p => <code key={p} className="pid-tag clickable" onClick={() => onPidClick?.(p)} title={tr('点击查看进程详情', 'Click to view process details')}>{p}</code>)}
                </div>
              </div>
            ))}
            {Object.keys(snapshot.services).length === 0 && (
              <div className="empty-state">{tr('暂无跟踪服务', 'No tracked services')}</div>
            )}
          </div>
        </div>

        <div className="card">
          <div className="card-header">
            <h3>{tr('事件计数器', 'Event Counters')}</h3>
            <span className="card-badge">{tr('30秒窗口', '30s window')}</span>
          </div>
          <div className="counter-list">
            {Object.entries(snapshot.counters).map(([k, v]) => {
              const max = Math.max(...Object.values(snapshot.counters), 1)
              const pct = (v / max) * 100
              return (
                <div key={k} className="counter-item">
                  <div className="counter-header">
                    <span className="counter-label">{mapKind(k, lang)}</span>
                    <span className="counter-value">{v.toLocaleString()}</span>
                  </div>
                  <div className="counter-bar">
                    <div className="counter-fill" style={{ width: `${pct}%` }} />
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      </div>

      {/* Recent events */}
      <div className="card">
        <div className="card-header">
          <h3>{tr('最新事件流', 'Recent Event Stream')}</h3>
        </div>
        <EventTable events={snapshot.events.slice(0, 8)} lang={lang} tr={tr} />
      </div>
    </div>
  )
}

// ── File I/O Tab ──

function FileTab({ snapshot, lang, tr }: {
  snapshot: Snapshot; lang: Lang; tr: (zh: string, en: string) => string
}) {
  const fileEvents = snapshot.events.filter(e => e.kind === 'file_io')
  const fileAlerts = snapshot.alerts.filter(a => a.event.kind === 'file_io')
  const sensitiveAccess = fileEvents.filter(e => e.action === 'alert').length

  return (
    <div className="tab-content">
      <div className="tab-intro">
        <p>{tr(
          '文件 I/O 代理通过 tracepoint/syscalls/sys_enter_openat 和 sys_exit_openat 挂载点，在内核态进行轻量级路径前缀匹配，仅将对敏感目标（如 /etc/shadow、SSL 证书、SSH 密钥等）的访问事件上报至用户态。',
          'The File I/O Agent hooks into tracepoint/syscalls/sys_enter_openat and sys_exit_openat, performing lightweight path prefix matching in kernel space. Only access events targeting sensitive files (e.g., /etc/shadow, SSL certs, SSH keys) are forwarded to user space.'
        )}</p>
      </div>

      <div className="stats-grid stats-3">
        <div className="stat-card accent-blue">
          <div className="stat-icon">📁</div>
          <div className="stat-body">
            <span className="stat-label">{tr('文件事件总数', 'Total File Events')}</span>
            <span className="stat-value">{(snapshot.counters.file_io ?? 0).toLocaleString()}</span>
          </div>
        </div>
        <div className="stat-card accent-red">
          <div className="stat-icon">🔒</div>
          <div className="stat-body">
            <span className="stat-label">{tr('敏感文件访问', 'Sensitive Access')}</span>
            <span className="stat-value">{sensitiveAccess}</span>
          </div>
        </div>
        <div className="stat-card accent-orange">
          <div className="stat-icon">⚠️</div>
          <div className="stat-body">
            <span className="stat-label">{tr('文件告警', 'File Alerts')}</span>
            <span className="stat-value">{fileAlerts.length}</span>
          </div>
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <h3>{tr('文件访问事件', 'File Access Events')}</h3>
          <span className="card-badge">{tr('实时', 'Live')}</span>
        </div>
        {fileEvents.length > 0 ? (
          <EventTable events={fileEvents} lang={lang} tr={tr} />
        ) : (
          <div className="empty-state">{tr('暂无文件事件', 'No file events yet')}</div>
        )}
      </div>

      {fileAlerts.length > 0 && (
        <div className="card">
          <div className="card-header">
            <h3>{tr('文件相关告警', 'File-related Alerts')}</h3>
          </div>
          <AlertList alerts={fileAlerts} lang={lang} />
        </div>
      )}

      <div className="card">
        <div className="card-header">
          <h3>{tr('挂载点详情', 'Hook Points')}</h3>
        </div>
        <div className="hook-list">
          <div className="hook-item">
            <code>tracepoint/syscalls/sys_enter_openat</code>
            <span>{tr('捕获文件打开请求，进行路径前缀匹配', 'Captures file open requests, performs path prefix matching')}</span>
          </div>
          <div className="hook-item">
            <code>tracepoint/syscalls/sys_exit_openat</code>
            <span>{tr('捕获文件打开返回值，记录操作结果', 'Captures file open return values, records operation results')}</span>
          </div>
        </div>
      </div>
    </div>
  )
}

// ── Process Tab ──

function ProcessTab({ snapshot, lang, tr }: {
  snapshot: Snapshot; lang: Lang; tr: (zh: string, en: string) => string
}) {
  const processEvents = snapshot.events.filter(e => e.kind === 'process' || e.kind === 'privilege')
  const privEvents = snapshot.events.filter(e => e.kind === 'privilege')
  const processAlerts = snapshot.alerts.filter(a => a.event.kind === 'process' || a.event.kind === 'privilege')

  return (
    <div className="tab-content">
      <div className="tab-intro">
        <p>{tr(
          '进程与权限代理通过 tracepoint/syscalls/sys_enter_execve、setuid、setgid 挂载点，追踪进程树的生命周期，检测未经授权的特权提升行为。结合可执行文件白名单前缀校验，识别异常进程创建。',
          'The Process & Privilege Agent hooks into tracepoint/syscalls/sys_enter_execve, setuid, and setgid to track process tree lifecycles and detect unauthorized privilege escalations. Combined with executable whitelist prefix validation, it identifies abnormal process creation.'
        )}</p>
      </div>

      <div className="stats-grid stats-3">
        <div className="stat-card accent-blue">
          <div className="stat-icon">⚙️</div>
          <div className="stat-body">
            <span className="stat-label">{tr('进程事件', 'Process Events')}</span>
            <span className="stat-value">{(snapshot.counters.process ?? 0).toLocaleString()}</span>
          </div>
        </div>
        <div className="stat-card accent-red">
          <div className="stat-icon">🔑</div>
          <div className="stat-body">
            <span className="stat-label">{tr('权限变更', 'Privilege Changes')}</span>
            <span className="stat-value">{(snapshot.counters.privilege ?? 0).toLocaleString()}</span>
          </div>
        </div>
        <div className="stat-card accent-orange">
          <div className="stat-icon">⚠️</div>
          <div className="stat-body">
            <span className="stat-label">{tr('进程告警', 'Process Alerts')}</span>
            <span className="stat-value">{processAlerts.length}</span>
          </div>
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <h3>{tr('进程与权限事件', 'Process & Privilege Events')}</h3>
        </div>
        {processEvents.length > 0 ? (
          <EventTable events={processEvents} lang={lang} tr={tr} />
        ) : (
          <div className="empty-state">{tr('暂无进程事件', 'No process events yet')}</div>
        )}
      </div>

      {privEvents.length > 0 && (
        <div className="card">
          <div className="card-header">
            <h3>{tr('权限提升事件', 'Privilege Escalation Events')}</h3>
            <span className="card-badge danger">{privEvents.length}</span>
          </div>
          <EventTable events={privEvents} lang={lang} tr={tr} />
        </div>
      )}

      <div className="card">
        <div className="card-header">
          <h3>{tr('挂载点详情', 'Hook Points')}</h3>
        </div>
        <div className="hook-list">
          <div className="hook-item">
            <code>tracepoint/syscalls/sys_enter_execve</code>
            <span>{tr('捕获进程创建，校验可执行文件路径白名单', 'Captures process creation, validates executable path whitelist')}</span>
          </div>
          <div className="hook-item">
            <code>tracepoint/syscalls/sys_enter_setuid</code>
            <span>{tr('检测 UID 变更，识别权限提升', 'Detects UID changes, identifies privilege escalation')}</span>
          </div>
          <div className="hook-item">
            <code>tracepoint/syscalls/sys_enter_setgid</code>
            <span>{tr('检测 GID 变更，识别组权限提升', 'Detects GID changes, identifies group privilege escalation')}</span>
          </div>
        </div>
      </div>
    </div>
  )
}

// ── Network Tab ──

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B/s`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB/s`
  return `${(bytes / (1024 * 1024)).toFixed(2)} MB/s`
}

function NetworkTab({ snapshot, lang, tr }: {
  snapshot: Snapshot; lang: Lang; tr: (zh: string, en: string) => string
}) {
  const netEvents = snapshot.events.filter(e => e.kind === 'network')
  const blockedEvents = netEvents.filter(e => e.action === 'blocked')
  const netAlerts = snapshot.alerts.filter(a => a.event.kind === 'network')
  const traffic = snapshot.traffic

  return (
    <div className="tab-content">
      <div className="tab-intro">
        <p>{tr(
          '网络遥测代理通过 tracepoint/syscalls/sys_enter_connect 和 bind 挂载点，监控被托管关键服务的外连请求与端口监听变更事件。支持基于 CIDR 的 IP 限流规则，在内核态直接评估并执行阻断/限速策略。',
          'The Network Telemetry Agent hooks into tracepoint/syscalls/sys_enter_connect and bind to monitor outbound connections and port binding events of tracked services. It supports CIDR-based IP rate limiting rules, evaluated and enforced directly in kernel space.'
        )}</p>
      </div>

      {/* Real-time traffic cards */}
      <div className="stats-grid">
        <div className="stat-card accent-green">
          <div className="stat-icon">📥</div>
          <div className="stat-body">
            <span className="stat-label">{tr('入站流量', 'Inbound Traffic')}</span>
            <span className="stat-value">{formatBytes(traffic?.total_rx_bytes_per_sec ?? 0)}</span>
          </div>
        </div>
        <div className="stat-card accent-blue">
          <div className="stat-icon">📤</div>
          <div className="stat-body">
            <span className="stat-label">{tr('出站流量', 'Outbound Traffic')}</span>
            <span className="stat-value">{formatBytes(traffic?.total_tx_bytes_per_sec ?? 0)}</span>
          </div>
        </div>
        <div className="stat-card accent-red">
          <div className="stat-icon">🚫</div>
          <div className="stat-body">
            <span className="stat-label">{tr('阻断连接', 'Blocked')}</span>
            <span className="stat-value">{blockedEvents.length}</span>
          </div>
        </div>
        <div className="stat-card accent-orange">
          <div className="stat-icon">⚠️</div>
          <div className="stat-body">
            <span className="stat-label">{tr('网络告警', 'Net Alerts')}</span>
            <span className="stat-value">{netAlerts.length}</span>
          </div>
        </div>
      </div>

      {/* Per-interface traffic table */}
      {traffic && traffic.interfaces && traffic.interfaces.length > 0 && (
        <div className="card">
          <div className="card-header">
            <h3>{tr('实时网卡流量', 'Real-time Interface Traffic')}</h3>
            <span className="card-badge">{tr('每秒刷新', '1s refresh')}</span>
          </div>
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>{tr('网卡', 'Interface')}</th>
                  <th>{tr('入站速率', 'RX Rate')}</th>
                  <th>{tr('出站速率', 'TX Rate')}</th>
                  <th>{tr('入站包/秒', 'RX pkt/s')}</th>
                  <th>{tr('出站包/秒', 'TX pkt/s')}</th>
                </tr>
              </thead>
              <tbody>
                {traffic.interfaces.map(iface => (
                  <tr key={iface.name}>
                    <td><code>{iface.name}</code></td>
                    <td className="traffic-rx">{formatBytes(iface.rx_bytes_per_sec)}</td>
                    <td className="traffic-tx">{formatBytes(iface.tx_bytes_per_sec)}</td>
                    <td>{iface.rx_packets_per_sec.toLocaleString()}</td>
                    <td>{iface.tx_packets_per_sec.toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      <div className="card">
        <div className="card-header">
          <h3>{tr('网络事件流', 'Network Event Stream')}</h3>
          <span className="card-badge">{tr('网络事件', 'Events')}: {(snapshot.counters.network ?? 0).toLocaleString()}</span>
        </div>
        {netEvents.length > 0 ? (
          <div className="table-wrap">
            <table>
              <thead>
                <tr>
                  <th>{tr('时间', 'Time')}</th>
                  <th>{tr('动作', 'Action')}</th>
                  <th>{tr('进程', 'Process')}</th>
                  <th>PID</th>
                  <th>{tr('目标地址', 'Address')}</th>
                  <th>{tr('端口', 'Port')}</th>
                  <th>{tr('详情', 'Detail')}</th>
                </tr>
              </thead>
              <tbody>
                {netEvents.map((e, i) => (
                  <tr key={`${e.timestamp_ns}-${i}`} className={e.action === 'blocked' ? 'row-blocked' : e.action === 'rate_limited' ? 'row-rate-limited' : ''}>
                    <td className="td-time">{formatTimestamp(e.timestamp_ns)}</td>
                    <td><span className={`action-tag action-${e.action}`}>{mapAction(e.action, lang)}</span></td>
                    <td><code>{e.comm}</code></td>
                    <td>{e.pid}</td>
                    <td><code>{e.network?.address ?? '-'}</code></td>
                    <td><code>{e.network?.port ?? '-'}</code></td>
                    <td className="td-detail">{e.detail || '-'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="empty-state">{tr('暂无网络事件', 'No network events yet')}</div>
        )}
      </div>

      <div className="card">
        <div className="card-header">
          <h3>{tr('挂载点详情', 'Hook Points')}</h3>
        </div>
        <div className="hook-list">
          <div className="hook-item">
            <code>tracepoint/syscalls/sys_enter_connect</code>
            <span>{tr('监控外连请求，检测异常 C2 通信与反向 Shell', 'Monitors outbound connections, detects abnormal C2 communication & reverse shells')}</span>
          </div>
          <div className="hook-item">
            <code>tracepoint/syscalls/sys_enter_bind</code>
            <span>{tr('监控端口绑定，检测非预期的端口监听', 'Monitors port binding, detects unexpected port listening')}</span>
          </div>
        </div>
      </div>
    </div>
  )
}

// ── Hotpatch Tab ──

function HotpatchTab({ snapshot, lang, tr }: {
  snapshot: Snapshot; lang: Lang; tr: (zh: string, en: string) => string
}) {
  const hotpatchEvents = snapshot.events.filter(e => e.kind === 'hotpatch')
  const isActive = snapshot.features.hotpatch_agent
  const symbolOk = snapshot.features.symbol_resolver
  const [reloading, setReloading] = useState(false)
  const [reloadMsg, setReloadMsg] = useState('')

  const handleReload = async () => {
    setReloading(true)
    setReloadMsg('')
    try {
      const r = await fetch('/api/v1/reload-hotpatch', { method: 'POST' })
      const data = await r.json() as { success: boolean; message: string; targets_count: number }
      setReloadMsg(data.success
        ? tr(`探针重载成功，已处理 ${data.targets_count} 个目标`, `Reload succeeded: ${data.targets_count} target(s) processed`)
        : tr('重载失败: ', 'Reload failed: ') + data.message
      )
    } catch {
      setReloadMsg(tr('重载失败: 网络错误', 'Reload failed: network error'))
    }
    setReloading(false)
    setTimeout(() => setReloadMsg(''), 5000)
  }

  return (
    <div className="tab-content">
      <div className="tab-intro">
        <p>{tr(
          '热补丁代理（主动防御）通过 kprobe/kretprobe 和 uprobe/uretprobe 挂载点，针对高危漏洞函数动态下发补丁。支持四种模式：监控出入口、替换返回值、跳过调用、以及函数替换（通过上传 .so 动态链接库，利用 ptrace 注入并写入 trampoline 跳转指令，实现零停机的函数级热修复）。',
          'The Hot-patching Agent (Active Defense) uses kprobe/kretprobe and uprobe/uretprobe hooks to dynamically deploy patches to vulnerable functions. Four modes: monitor entry/exit, override return value, skip call, and replace function (upload a .so shared library, inject via ptrace and write a trampoline jump — zero-downtime function-level hot-fix).'
        )}</p>
      </div>

      {reloadMsg && <div className="toast">{reloadMsg}</div>}

      <div className="stats-grid stats-3">
        <div className="stat-card accent-blue">
          <div className="stat-icon">🔥</div>
          <div className="stat-body">
            <span className="stat-label">{tr('热补丁事件', 'Hotpatch Events')}</span>
            <span className="stat-value">{(snapshot.counters.hotpatch ?? 0).toLocaleString()}</span>
          </div>
        </div>
        <div className={`stat-card ${isActive ? 'accent-green' : 'accent-red'}`}>
          <div className="stat-icon">🛡️</div>
          <div className="stat-body">
            <span className="stat-label">{tr('热补丁代理', 'Hotpatch Agent')}</span>
            <span className="stat-value">{isActive ? tr('运行中', 'ACTIVE') : tr('离线', 'DOWN')}</span>
          </div>
        </div>
        <div className={`stat-card ${symbolOk ? 'accent-green' : 'accent-red'}`}>
          <div className="stat-icon">🔍</div>
          <div className="stat-body">
            <span className="stat-label">{tr('符号解析器', 'Symbol Resolver')}</span>
            <span className="stat-value">{symbolOk ? tr('正常', 'OK') : tr('异常', 'ERROR')}</span>
          </div>
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <h3>{tr('热补丁事件流', 'Hotpatch Event Stream')}</h3>
          <button className="btn-reload" onClick={handleReload} disabled={reloading}>
            {reloading ? tr('重载中...', 'Reloading...') : tr('重载探针', 'Reload Probes')}
          </button>
        </div>
        {hotpatchEvents.length > 0 ? (
          <EventTable events={hotpatchEvents} lang={lang} tr={tr} />
        ) : (
          <div className="empty-state">{tr('暂无热补丁事件', 'No hotpatch events yet')}</div>
        )}
      </div>

      <div className="card">
        <div className="card-header">
          <h3>{tr('技术架构', 'Technical Architecture')}</h3>
        </div>
        <div className="arch-info">
          <div className="arch-section">
            <h4>{tr('内核态函数热补丁', 'Kernel-space Function Hot-patching')}</h4>
            <p>{tr(
              '通过 kprobe + bpf_override_return 对高危内核函数进行参数校验和返回值干预。当检测到恶意参数时，直接在内核态阻断调用。',
              'Uses kprobe + bpf_override_return to validate arguments and intervene return values of high-risk kernel functions. When malicious arguments are detected, the call is blocked directly in kernel space.'
            )}</p>
          </div>
          <div className="arch-section">
            <h4>{tr('用户态函数热补丁', 'User-space Function Hot-patching')}</h4>
            <p>{tr(
              '通过 uprobe/uretprobe 对 Nginx、OpenSSH、Redis 等关键服务的高危函数进行运行时缓解。动态符号解析器实时解析 ELF 符号表（.symtab/.dynsym）和 /proc/[pid]/maps，克服 ASLR 限制精准挂载。',
              'Uses uprobe/uretprobe to apply runtime mitigations to vulnerable functions in critical services like Nginx, OpenSSH, and Redis. The dynamic symbol resolver parses ELF symbol tables (.symtab/.dynsym) and /proc/[pid]/maps in real-time, bypassing ASLR for precise attachment.'
            )}</p>
          </div>
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <h3>{tr('挂载点详情', 'Hook Points')}</h3>
        </div>
        <div className="hook-list">
          <div className="hook-item">
            <code>kprobe / kretprobe</code>
            <span>{tr('内核函数入口/出口探针，用于参数校验与返回值控制', 'Kernel function entry/exit probes for argument validation & return value control')}</span>
          </div>
          <div className="hook-item">
            <code>uprobe / uretprobe</code>
            <span>{tr('用户态函数入口/出口探针，用于运行时漏洞缓解', 'User-space function entry/exit probes for runtime vulnerability mitigation')}</span>
          </div>
        </div>
      </div>
    </div>
  )
}

// ── Alerts Tab ──

function AlertsTab({ snapshot, lang, tr }: {
  snapshot: Snapshot; lang: Lang; tr: (zh: string, en: string) => string
}) {
  const [filter, setFilter] = useState<string>('all')
  const filtered = filter === 'all' ? snapshot.alerts : snapshot.alerts.filter(a => a.level === filter)

  const criticals = snapshot.alerts.filter(a => a.level === 'critical').length
  const highs = snapshot.alerts.filter(a => a.level === 'high').length
  const mediums = snapshot.alerts.filter(a => a.level === 'medium').length

  return (
    <div className="tab-content">
      <div className="tab-intro">
        <p>{tr(
          '告警中心汇聚所有代理探针产生的安全告警。异常检测引擎基于白名单规则校验和统计基线分析，自动识别偏离正常模式的异常行为并生成告警。',
          'The Alert Center aggregates security alerts from all agent probes. The Anomaly Detection Engine uses whitelist rule validation and statistical baseline analysis to automatically identify abnormal behaviors deviating from normal patterns.'
        )}</p>
      </div>

      <div className="stats-grid stats-3">
        <div className="stat-card accent-red">
          <div className="stat-icon">🔴</div>
          <div className="stat-body">
            <span className="stat-label">{tr('严重', 'Critical')}</span>
            <span className="stat-value">{criticals}</span>
          </div>
        </div>
        <div className="stat-card accent-orange">
          <div className="stat-icon">🟠</div>
          <div className="stat-body">
            <span className="stat-label">{tr('高危', 'High')}</span>
            <span className="stat-value">{highs}</span>
          </div>
        </div>
        <div className="stat-card accent-yellow">
          <div className="stat-icon">🟡</div>
          <div className="stat-body">
            <span className="stat-label">{tr('中危', 'Medium')}</span>
            <span className="stat-value">{mediums}</span>
          </div>
        </div>
      </div>

      <div className="card">
        <div className="card-header">
          <h3>{tr('告警列表', 'Alert List')}</h3>
          <div className="filter-group">
            {['all', 'critical', 'high', 'medium'].map(f => (
              <button key={f} className={`filter-btn ${filter === f ? 'active' : ''}`} onClick={() => setFilter(f)}>
                {f === 'all' ? tr('全部', 'All') : f === 'critical' ? tr('严重', 'Critical') : f === 'high' ? tr('高危', 'High') : tr('中危', 'Medium')}
              </button>
            ))}
          </div>
        </div>
        {filtered.length > 0 ? (
          <AlertList alerts={filtered} lang={lang} />
        ) : (
          <div className="empty-state">{tr('暂无告警', 'No alerts')}</div>
        )}
      </div>
    </div>
  )
}

// ── Config Tab ──

function ConfigTab({ lang, tr }: { lang: Lang; tr: (zh: string, en: string) => string }) {
  const [policy, setPolicy] = useState<MonitorPolicy | null>(null)
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [msg, setMsg] = useState('')

  const fetchConfig = useCallback(async () => {
    try {
      const r = await fetch('/api/v1/config')
      if (r.ok) setPolicy(await r.json())
    } catch { /* offline */ }
    setLoading(false)
  }, [])

  useEffect(() => { fetchConfig() }, [fetchConfig])

  const flash = (text: string) => {
    setMsg(text)
    setTimeout(() => setMsg(''), 3000)
  }

  const toggle = async (section: string, index: number, enabled: boolean) => {
    try {
      const r = await fetch('/api/v1/config/toggle', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ section, index, enabled }),
      })
      if (r.ok) {
        const updated = await r.json() as MonitorPolicy
        setPolicy(updated)
        flash(enabled ? tr('已启用', 'Enabled') : tr('已禁用', 'Disabled'))
      }
    } catch { flash(tr('切换失败', 'Toggle failed')) }
  }

  if (loading) return <div className="tab-content"><div className="empty-state">{tr('加载配置中...', 'Loading configuration...')}</div></div>
  if (!policy) return <div className="tab-content"><div className="empty-state">{tr('无法加载配置（后端离线？）', 'Unable to load configuration (backend offline?)')}</div></div>

  return (
    <div className="tab-content">
      {msg && <div className="toast">{msg}</div>}

      <div className="tab-intro">
        <p>{tr(
          '在此配置监控策略。所有配置项均支持启用/禁用开关，禁用的配置项将不会参与内核态 eBPF 探针的规则匹配，但会保留在配置文件中以便随时重新启用。',
          'Configure monitoring policies here. All items support enable/disable toggles. Disabled items are excluded from kernel-space eBPF rule matching but remain in the config file for easy re-enabling.'
        )}</p>
      </div>

      <ToggleListPanel
        title={tr('敏感文件前缀', 'Sensitive File Prefixes')}
        desc={tr('匹配的文件访问将触发告警。禁用后该前缀不再参与匹配。', 'Matching file access triggers alerts. Disabled prefixes are excluded from matching.')}
        items={policy.sensitive_prefixes}
        section="sensitive_prefixes"
        toggle={toggle}
        renderValue={item => item.value}
        addPlaceholder="/etc/shadow"
        onAdd={async (value) => {
          const body = { sensitive_prefixes: [...policy.sensitive_prefixes, { value, enabled: true }] }
          try {
            const r = await fetch('/api/v1/config', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
            if (r.ok) { setPolicy(await r.json()); flash(tr('已添加', 'Added')) }
          } catch { flash(tr('添加失败', 'Add failed')) }
        }}
        onDelete={async (index) => {
          const items = policy.sensitive_prefixes.filter((_, i) => i !== index)
          const body = { sensitive_prefixes: items }
          try {
            const r = await fetch('/api/v1/config', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
            if (r.ok) { setPolicy(await r.json()); flash(tr('已删除', 'Deleted')) }
          } catch { flash(tr('删除失败', 'Delete failed')) }
        }}
        tr={tr}
      />

      <ToggleListPanel
        title={tr('可执行白名单前缀', 'Exec Whitelist Prefixes')}
        desc={tr('允许的 execve 路径前缀，不在白名单内的将触发告警。', 'Allowed execve path prefixes; non-whitelisted paths trigger alerts.')}
        items={policy.exec_whitelist_prefixes}
        section="exec_whitelist_prefixes"
        toggle={toggle}
        renderValue={item => item.value}
        addPlaceholder="/usr/bin"
        onAdd={async (value) => {
          const body = { exec_whitelist_prefixes: [...policy.exec_whitelist_prefixes, { value, enabled: true }] }
          try {
            const r = await fetch('/api/v1/config', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
            if (r.ok) { setPolicy(await r.json()); flash(tr('已添加', 'Added')) }
          } catch { flash(tr('添加失败', 'Add failed')) }
        }}
        onDelete={async (index) => {
          const items = policy.exec_whitelist_prefixes.filter((_, i) => i !== index)
          const body = { exec_whitelist_prefixes: items }
          try {
            const r = await fetch('/api/v1/config', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
            if (r.ok) { setPolicy(await r.json()); flash(tr('已删除', 'Deleted')) }
          } catch { flash(tr('删除失败', 'Delete failed')) }
        }}
        tr={tr}
      />

      <ToggleListPanel
        title={tr('监控服务', 'Monitored Services')}
        desc={tr('systemd unit 名称，自动追踪其 PID。禁用后不再追踪。', 'Systemd unit names; PIDs are tracked automatically. Disabled services are not tracked.')}
        items={policy.monitored_services}
        section="monitored_services"
        toggle={toggle}
        renderValue={item => item.value}
        addPlaceholder="sshd.service"
        onAdd={async (value) => {
          const body = { monitored_services: [...policy.monitored_services, { value, enabled: true }] }
          try {
            const r = await fetch('/api/v1/config', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
            if (r.ok) { setPolicy(await r.json()); flash(tr('已添加', 'Added')) }
          } catch { flash(tr('添加失败', 'Add failed')) }
        }}
        onDelete={async (index) => {
          const items = policy.monitored_services.filter((_, i) => i !== index)
          const body = { monitored_services: items }
          try {
            const r = await fetch('/api/v1/config', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
            if (r.ok) { setPolicy(await r.json()); flash(tr('已删除', 'Deleted')) }
          } catch { flash(tr('删除失败', 'Delete failed')) }
        }}
        tr={tr}
      />

      <BlockedPortsPanel policy={policy} setPolicy={setPolicy} toggle={toggle} flash={flash} tr={tr} />
      <BaselinePanel policy={policy} setPolicy={setPolicy} saving={saving} setSaving={setSaving} flash={flash} lang={lang} tr={tr} />
      <RateLimitPanel rules={policy.rate_limit_rules} setRules={r => setPolicy({ ...policy, rate_limit_rules: r })} toggle={toggle} flash={flash} tr={tr} />
      <HotpatchConfigPanel targets={policy.hotpatch.targets} setTargets={t => setPolicy({ ...policy, hotpatch: { targets: t } })} toggle={toggle} flash={flash} tr={tr} />
    </div>
  )
}

// ── Shared components ──

function EventTable({ events, lang, tr }: { events: EventRecord[]; lang: Lang; tr: (zh: string, en: string) => string }) {
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>{tr('时间', 'Time')}</th>
            <th>{tr('类型', 'Kind')}</th>
            <th>{tr('动作', 'Action')}</th>
            <th>{tr('服务', 'Service')}</th>
            <th>{tr('进程', 'Process')}</th>
            <th>PID</th>
            <th>UID</th>
            <th>{tr('详情', 'Detail')}</th>
            <th>{tr('网络', 'Network')}</th>
          </tr>
        </thead>
        <tbody>
          {events.map((e, i) => (
            <tr key={`${e.timestamp_ns}-${i}`} className={e.action === 'blocked' ? 'row-blocked' : e.action === 'alert' ? 'row-alert' : e.action === 'rate_limited' ? 'row-rate-limited' : ''}>
              <td className="td-time">{formatTimestamp(e.timestamp_ns)}</td>
              <td><span className={`kind-tag kind-${e.kind}`}>{mapKind(e.kind, lang)}</span></td>
              <td><span className={`action-tag action-${e.action}`}>{mapAction(e.action, lang)}</span></td>
              <td>{e.service ? <span className="service-badge">{e.service}</span> : <span className="no-service">-</span>}</td>
              <td><code>{e.comm || '-'}</code></td>
              <td>{e.pid}</td>
              <td>{e.uid}</td>
              <td className="td-detail">{e.detail || '-'}</td>
              <td>{e.network ? <code>{e.network.address}:{e.network.port}</code> : '-'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function AlertList({ alerts, lang }: { alerts: AlertRecord[]; lang: Lang }) {
  return (
    <div className="alert-list">
      {alerts.map((a, i) => (
        <div key={`${a.reason}-${i}`} className={`alert-item level-${a.level}`}>
          <div className="alert-header">
            <span className={`level-badge level-${a.level}`}>{a.level.toUpperCase()}</span>
            <span className="alert-time">{relativeTime(a.event.timestamp_ns, lang)}</span>
          </div>
          <p className="alert-reason">{a.reason}</p>
          <div className="alert-meta">
            <span>{mapKind(a.event.kind, lang)}</span>
            <span>{mapAction(a.event.action, lang)}</span>
            {a.event.service && <span className="service-badge">{a.event.service}</span>}
            <span>PID: {a.event.pid}</span>
            <span>{a.event.comm}</span>
            {a.event.network && <span>{a.event.network.address}:{a.event.network.port}</span>}
          </div>
        </div>
      ))}
    </div>
  )
}

// ── Config sub-panels ──

// Generic toggle list panel for ToggleItem arrays
function ToggleListPanel({ title, desc, items, section, toggle, renderValue, addPlaceholder, onAdd, onDelete, tr }: {
  title: string; desc: string; items: ToggleItem[]; section: string
  toggle: (section: string, index: number, enabled: boolean) => void
  renderValue: (item: ToggleItem) => string
  addPlaceholder: string
  onAdd: (value: string) => void
  onDelete: (index: number) => void
  tr: (zh: string, en: string) => string
}) {
  const [draft, setDraft] = useState('')
  const enabled = items.filter(i => i.enabled).length

  return (
    <div className="card">
      <div className="card-header">
        <h3>{title}</h3>
        <span className="card-badge">{enabled}/{items.length} {tr('启用', 'enabled')}</span>
      </div>
      <p className="card-desc">{desc}</p>

      {items.length > 0 && (
        <div className="toggle-list">
          {items.map((item, i) => (
            <div key={i} className={`toggle-row ${item.enabled ? '' : 'disabled'}`}>
              <button
                className={`switch ${item.enabled ? 'on' : 'off'}`}
                onClick={() => toggle(section, i, !item.enabled)}
                title={item.enabled ? tr('点击禁用', 'Click to disable') : tr('点击启用', 'Click to enable')}
              >
                <span className="switch-knob" />
              </button>
              <code className="toggle-value">{renderValue(item)}</code>
              <button className="btn-danger-sm" onClick={() => onDelete(i)}>{tr('删除', 'Delete')}</button>
            </div>
          ))}
        </div>
      )}

      {items.length === 0 && <div className="empty-state">{tr('暂无配置项', 'No items configured')}</div>}

      <div className="add-form">
        <div className="add-row">
          <input type="text" placeholder={addPlaceholder} value={draft} onChange={e => setDraft(e.target.value)} onKeyDown={e => { if (e.key === 'Enter' && draft.trim()) { onAdd(draft.trim()); setDraft('') } }} />
          <button className="btn-primary" onClick={() => { if (draft.trim()) { onAdd(draft.trim()); setDraft('') } }}>{tr('添加', 'Add')}</button>
        </div>
      </div>
    </div>
  )
}

// Blocked ports panel
function BlockedPortsPanel({ policy, setPolicy, toggle, flash, tr }: {
  policy: MonitorPolicy; setPolicy: (p: MonitorPolicy) => void
  toggle: (section: string, index: number, enabled: boolean) => void
  flash: (msg: string) => void; tr: (zh: string, en: string) => string
}) {
  const [draft, setDraft] = useState('')
  const ports = policy.blocked_ports
  const enabled = ports.filter(p => p.enabled).length

  const handleAdd = async () => {
    const port = parseInt(draft.trim(), 10)
    if (isNaN(port) || port < 1 || port > 65535) { flash(tr('请输入有效端口号 (1-65535)', 'Enter a valid port (1-65535)')); return }
    const body = { blocked_ports: [...ports, { port, enabled: true }] }
    try {
      const r = await fetch('/api/v1/config', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
      if (r.ok) { setPolicy(await r.json()); setDraft(''); flash(tr('已添加', 'Added')) }
    } catch { flash(tr('添加失败', 'Add failed')) }
  }

  const handleDelete = async (index: number) => {
    const items = ports.filter((_, i) => i !== index)
    const body = { blocked_ports: items }
    try {
      const r = await fetch('/api/v1/config', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
      if (r.ok) { setPolicy(await r.json()); flash(tr('已删除', 'Deleted')) }
    } catch { flash(tr('删除失败', 'Delete failed')) }
  }

  return (
    <div className="card">
      <div className="card-header">
        <h3>{tr('阻断端口', 'Blocked Ports')}</h3>
        <span className="card-badge">{enabled}/{ports.length} {tr('启用', 'enabled')}</span>
      </div>
      <p className="card-desc">{tr('匹配的连接将被阻断。禁用后该端口不再参与阻断规则。', 'Matching connections are blocked. Disabled ports are excluded from blocking rules.')}</p>

      {ports.length > 0 && (
        <div className="toggle-list">
          {ports.map((item, i) => (
            <div key={i} className={`toggle-row ${item.enabled ? '' : 'disabled'}`}>
              <button
                className={`switch ${item.enabled ? 'on' : 'off'}`}
                onClick={() => toggle('blocked_ports', i, !item.enabled)}
              >
                <span className="switch-knob" />
              </button>
              <code className="toggle-value">{item.port}</code>
              <button className="btn-danger-sm" onClick={() => handleDelete(i)}>{tr('删除', 'Delete')}</button>
            </div>
          ))}
        </div>
      )}

      <div className="add-form">
        <div className="add-row">
          <input type="number" min={1} max={65535} placeholder="4444" value={draft} onChange={e => setDraft(e.target.value)} onKeyDown={e => { if (e.key === 'Enter') handleAdd() }} />
          <button className="btn-primary" onClick={handleAdd}>{tr('添加', 'Add')}</button>
        </div>
      </div>
    </div>
  )
}

// Baseline thresholds panel
function BaselinePanel({ policy, setPolicy, saving, setSaving, flash, lang, tr }: {
  policy: MonitorPolicy; setPolicy: (p: MonitorPolicy) => void; saving: boolean; setSaving: (v: boolean) => void
  flash: (msg: string) => void; lang: Lang; tr: (zh: string, en: string) => string
}) {
  const [thresholds, setThresholds] = useState({ ...policy.baseline_thresholds })

  const handleSave = async () => {
    setSaving(true)
    try {
      const r = await fetch('/api/v1/config', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ baseline_thresholds: thresholds }) })
      if (r.ok) { setPolicy(await r.json()); flash(tr('基线阈值已保存', 'Baseline thresholds saved')) }
      else flash(tr('保存失败', 'Save failed'))
    } catch { flash(tr('保存失败', 'Save failed')) }
    setSaving(false)
  }

  return (
    <div className="card">
      <div className="card-header"><h3>{tr('基线阈值（每 30 秒窗口）', 'Baseline Thresholds (per 30s window)')}</h3></div>
      <p className="card-desc">{tr('超过阈值的系统调用频率将触发中危告警。', 'Syscall frequencies exceeding thresholds trigger medium-level alerts.')}</p>
      <div className="threshold-grid">
        {['file_io', 'process', 'privilege', 'network', 'hotpatch'].map(k => (
          <div key={k} className="threshold-item">
            <label>{mapKind(k, lang)}</label>
            <input type="number" min={0} value={thresholds[k] ?? 0} onChange={e => setThresholds({ ...thresholds, [k]: parseInt(e.target.value, 10) || 0 })} />
          </div>
        ))}
      </div>
      <button className="btn-primary" onClick={handleSave} disabled={saving}>
        {saving ? tr('保存中...', 'Saving...') : tr('保存阈值', 'Save Thresholds')}
      </button>
    </div>
  )
}

const emptyRule: RateLimitRule = { cidr: '', max_conn_per_sec: 100, action: 'log', enabled: true }

function RateLimitPanel({ rules, setRules, toggle, flash, tr }: {
  rules: RateLimitRule[]; setRules: (r: RateLimitRule[]) => void
  toggle: (section: string, index: number, enabled: boolean) => void
  flash: (msg: string) => void; tr: (zh: string, en: string) => string
}) {
  const [draft, setDraft] = useState<RateLimitRule>({ ...emptyRule })
  const enabled = rules.filter(r => r.enabled).length

  const handleAdd = async () => {
    if (!draft.cidr.trim()) { flash(tr('CIDR 必填', 'CIDR is required')); return }
    try {
      const r = await fetch('/api/v1/config/rate-limit', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ...draft, cidr: draft.cidr.trim() }) })
      if (r.ok) { setRules(await r.json()); setDraft({ ...emptyRule }); flash(tr('限流规则已添加', 'Rate limit rule added')) }
      else flash(tr('添加失败: ', 'Add failed: ') + r.statusText)
    } catch { flash(tr('添加失败: 网络错误', 'Add failed: network error')) }
  }

  const handleDelete = async (index: number) => {
    try {
      const r = await fetch(`/api/v1/config/rate-limit/${index}`, { method: 'DELETE' })
      if (r.ok) { setRules(await r.json()); flash(tr('规则已删除', 'Rule deleted')) }
    } catch { flash(tr('删除失败', 'Delete failed')) }
  }

  return (
    <div className="card">
      <div className="card-header">
        <h3>{tr('IP 限流规则', 'IP Rate Limiting Rules')}</h3>
        <span className="card-badge">{enabled}/{rules.length} {tr('启用', 'enabled')}</span>
      </div>
      <p className="card-desc">{tr(
        '配置基于 CIDR 的连接速率限制。规则由网络遥测代理在内核态实时评估。',
        'Define per-CIDR connection rate limits. Rules are evaluated by the network telemetry agent in kernel space at runtime.'
      )}</p>

      {rules.length > 0 && (
        <div className="toggle-list">
          {rules.map((rule, i) => (
            <div key={i} className={`toggle-row ${rule.enabled ? '' : 'disabled'}`}>
              <button
                className={`switch ${rule.enabled ? 'on' : 'off'}`}
                onClick={() => toggle('rate_limit_rules', i, !rule.enabled)}
              >
                <span className="switch-knob" />
              </button>
              <div className="toggle-detail">
                <code>{rule.cidr}</code>
                <span className="toggle-meta">{rule.max_conn_per_sec} conn/s</span>
                <span className={`action-tag action-${rule.action}`}>{rule.action}</span>
              </div>
              <button className="btn-danger-sm" onClick={() => handleDelete(i)}>{tr('删除', 'Delete')}</button>
            </div>
          ))}
        </div>
      )}

      <div className="add-form">
        <h4>{tr('新增规则', 'Add Rule')}</h4>
        <div className="add-row">
          <input type="text" placeholder="10.0.0.0/8" value={draft.cidr} onChange={e => setDraft({ ...draft, cidr: e.target.value })} />
          <input type="number" min={1} placeholder="100" value={draft.max_conn_per_sec} onChange={e => setDraft({ ...draft, max_conn_per_sec: parseInt(e.target.value, 10) || 1 })} />
          <select value={draft.action} onChange={e => setDraft({ ...draft, action: e.target.value as RateLimitRule['action'] })}>
            <option value="log">{tr('记录', 'Log')}</option>
            <option value="block">{tr('阻断', 'Block')}</option>
            <option value="throttle">{tr('限速', 'Throttle')}</option>
          </select>
          <button className="btn-primary" onClick={handleAdd}>{tr('添加', 'Add')}</button>
        </div>
      </div>
    </div>
  )
}

const emptyTarget: HotpatchTarget = { binary: '', symbol: '', pid: null, enabled: true, patch_action: 'monitor', override_return_value: 0, replace_lib: null, replace_symbol: null }

const patchActionLabel = (action: PatchAction, tr: (zh: string, en: string) => string) => {
  switch (action) {
    case 'monitor': return tr('监控', 'Monitor')
    case 'override_return': return tr('替换返回值', 'Override Return')
    case 'skip_call': return tr('跳过调用', 'Skip Call')
    case 'replace_function': return tr('函数替换', 'Replace Function')
  }
}

const patchActionClass = (action: PatchAction) => {
  switch (action) {
    case 'monitor': return 'action-log'
    case 'override_return': return 'action-blocked'
    case 'skip_call': return 'action-alert'
    case 'replace_function': return 'action-replace'
  }
}

function HotpatchConfigPanel({ targets, setTargets, toggle, flash, tr }: {
  targets: HotpatchTarget[]; setTargets: (t: HotpatchTarget[]) => void
  toggle: (section: string, index: number, enabled: boolean) => void
  flash: (msg: string) => void; tr: (zh: string, en: string) => string
}) {
  const [draft, setDraft] = useState<HotpatchTarget>({ ...emptyTarget })
  const [reloading, setReloading] = useState(false)
  const [uploading, setUploading] = useState(false)
  const [uploadedLib, setUploadedLib] = useState<string | null>(null)
  const enabled = targets.filter(t => t.enabled).length
  const overrides = targets.filter(t => t.enabled && t.patch_action !== 'monitor').length

  const handleUploadLib = async (file: File) => {
    setUploading(true)
    try {
      const form = new FormData()
      form.append('file', file)
      const r = await fetch('/api/v1/upload-lib', { method: 'POST', body: form })
      if (r.ok) {
        const data = await r.json() as { path: string; size: number; arch: string; name: string }
        setUploadedLib(data.path)
        setDraft(d => ({ ...d, replace_lib: data.path }))
        flash(tr(`库已上传: ${data.name} (${data.arch}, ${data.size} bytes)`, `Library uploaded: ${data.name} (${data.arch}, ${data.size} bytes)`))
      } else {
        const text = await r.text()
        flash(tr('上传失败: ', 'Upload failed: ') + text)
      }
    } catch { flash(tr('上传失败: 网络错误', 'Upload failed: network error')) }
    setUploading(false)
  }

  const handleAdd = async () => {
    if (!draft.binary.trim() || !draft.symbol.trim()) { flash(tr('二进制路径和符号名必填', 'Binary path and symbol name are required')); return }
    if (draft.patch_action === 'replace_function' && !draft.replace_lib) {
      flash(tr('函数替换模式需要先上传动态链接库', 'Replace function mode requires uploading a shared library first')); return
    }
    if (draft.patch_action === 'replace_function' && !draft.pid) {
      flash(tr('函数替换模式需要指定 PID', 'Replace function mode requires a PID')); return
    }
    const payload: Record<string, unknown> = {
      binary: draft.binary.trim(),
      symbol: draft.symbol.trim(),
      pid: draft.pid || null,
      enabled: true,
      patch_action: draft.patch_action,
      override_return_value: draft.override_return_value,
    }
    if (draft.patch_action === 'replace_function') {
      payload.replace_lib = draft.replace_lib
      payload.replace_symbol = draft.replace_symbol?.trim() || null
    }
    try {
      const r = await fetch('/api/v1/config/hotpatch', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) })
      if (r.ok) { setTargets(await r.json()); setDraft({ ...emptyTarget }); setUploadedLib(null); flash(tr('热补丁目标已添加', 'Hotpatch target added')) }
      else flash(tr('添加失败: ', 'Add failed: ') + await r.text())
    } catch { flash(tr('添加失败: 网络错误', 'Add failed: network error')) }
  }

  const handleDelete = async (index: number) => {
    try {
      const r = await fetch(`/api/v1/config/hotpatch/${index}`, { method: 'DELETE' })
      if (r.ok) { setTargets(await r.json()); flash(tr('目标已删除', 'Target removed')) }
    } catch { flash(tr('删除失败', 'Delete failed')) }
  }

  const handleUpdateTarget = async (index: number, updates: Partial<HotpatchTarget>) => {
    const target = { ...targets[index], ...updates }
    try {
      const r = await fetch('/api/v1/config/hotpatch', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ index, ...target }),
      })
      if (r.ok) { setTargets(await r.json()); flash(tr('已更新', 'Updated')) }
    } catch { flash(tr('更新失败', 'Update failed')) }
  }

  const handleReload = async () => {
    setReloading(true)
    try {
      const r = await fetch('/api/v1/reload-hotpatch', { method: 'POST' })
      const data = await r.json() as { success: boolean; message: string; targets_count: number }
      flash(data.success
        ? tr(`探针重载成功，已处理 ${data.targets_count} 个目标`, `Reload succeeded: ${data.targets_count} target(s) processed`)
        : tr('重载失败: ', 'Reload failed: ') + data.message
      )
    } catch { flash(tr('重载失败: 网络错误', 'Reload failed: network error')) }
    setReloading(false)
  }

  return (
    <div className="card">
      <div className="card-header">
        <h3>{tr('热补丁 — 运行期函数替换', 'Hot-Patch — Runtime Function Replacement')}</h3>
        <div className="header-actions">
          <button className="btn-reload" onClick={handleReload} disabled={reloading || targets.length === 0}>
            {reloading ? tr('重载中...', 'Reloading...') : tr('重载探针', 'Reload Probes')}
          </button>
          <span className="card-badge">{enabled}/{targets.length} {tr('启用', 'enabled')}</span>
          {overrides > 0 && <span className="card-badge danger">{overrides} {tr('替换中', 'overriding')}</span>}
        </div>
      </div>
      <p className="card-desc">{tr(
        '通过 uprobe/uretprobe 在运行时挂载到目标函数。支持四种模式：监控（仅记录出入口）、替换返回值（通过 bpf_override_return 强制函数返回指定值）、跳过调用（语义同替换返回值）、函数替换（上传编译好的 .so 动态链接库，通过 ptrace 注入并用 trampoline 替换原函数实现，无需停机重启）。修改补丁动作后需点击"重载探针"生效。',
        'Attach uprobe/uretprobe to target functions at runtime. Four modes: Monitor (log entry/exit only), Override Return (force return value via bpf_override_return), Skip Call (same mechanism, marked as "skip"), Replace Function (upload a compiled .so, inject via ptrace and replace the original function with a trampoline — zero-downtime). Click "Reload Probes" after changing patch actions.'
      )}</p>

      {targets.length > 0 && (
        <div className="toggle-list">
          {targets.map((t, i) => (
            <div key={i} className={`toggle-row hotpatch-row ${t.enabled ? '' : 'disabled'}`}>
              <button
                className={`switch ${t.enabled ? 'on' : 'off'}`}
                onClick={() => toggle('hotpatch_targets', i, !t.enabled)}
              >
                <span className="switch-knob" />
              </button>
              <div className="toggle-detail hotpatch-detail">
                <div className="hotpatch-main">
                  <code>{t.binary}</code>
                  <span className="toggle-meta">{t.symbol}</span>
                  <span className="toggle-meta">PID: {t.pid ?? tr('全部', 'all')}</span>
                </div>
                <div className="hotpatch-action-row">
                  <select
                    className="hotpatch-action-select"
                    value={t.patch_action}
                    onChange={e => handleUpdateTarget(i, { patch_action: e.target.value as PatchAction })}
                    disabled={!t.enabled}
                  >
                    <option value="monitor">{tr('监控', 'Monitor')}</option>
                    <option value="override_return">{tr('替换返回值', 'Override Return')}</option>
                    <option value="skip_call">{tr('跳过调用', 'Skip Call')}</option>
                    <option value="replace_function">{tr('函数替换', 'Replace Function')}</option>
                  </select>
                  {(t.patch_action === 'override_return' || t.patch_action === 'skip_call') && (
                    <div className="hotpatch-retval">
                      <label>{tr('返回值:', 'Return:')}</label>
                      <input
                        type="number"
                        className="hotpatch-retval-input"
                        value={t.override_return_value}
                        onChange={e => handleUpdateTarget(i, { override_return_value: parseInt(e.target.value, 10) || 0 })}
                        disabled={!t.enabled}
                        title={tr('常用值: 0=成功, -1=EPERM, -13=EACCES, -22=EINVAL', 'Common: 0=success, -1=EPERM, -13=EACCES, -22=EINVAL')}
                      />
                    </div>
                  )}
                  {t.patch_action === 'replace_function' && t.replace_lib && (
                    <span className="toggle-meta" title={t.replace_lib}>.so: {t.replace_lib.split('/').pop()}</span>
                  )}
                  {t.patch_action === 'replace_function' && t.replace_symbol && (
                    <span className="toggle-meta">→ {t.replace_symbol}</span>
                  )}
                  <span className={`action-tag ${patchActionClass(t.patch_action)}`}>
                    {patchActionLabel(t.patch_action, tr)}
                  </span>
                </div>
              </div>
              <button className="btn-danger-sm" onClick={() => handleDelete(i)}>{tr('删除', 'Delete')}</button>
            </div>
          ))}
        </div>
      )}

      <div className="add-form">
        <h4>{tr('新增目标', 'Add Target')}</h4>
        <div className="add-row">
          <input type="text" placeholder="/usr/sbin/nginx" value={draft.binary} onChange={e => setDraft({ ...draft, binary: e.target.value })} />
          <input type="text" placeholder="ngx_http_process_request" value={draft.symbol} onChange={e => setDraft({ ...draft, symbol: e.target.value })} />
          <input type="number" min={0} placeholder={tr('PID（可选）', 'PID (optional)')} value={draft.pid ?? ''} onChange={e => setDraft({ ...draft, pid: e.target.value ? parseInt(e.target.value, 10) : null })} />
          <select value={draft.patch_action} onChange={e => setDraft({ ...draft, patch_action: e.target.value as PatchAction })}>
            <option value="monitor">{tr('监控', 'Monitor')}</option>
            <option value="override_return">{tr('替换返回值', 'Override Return')}</option>
            <option value="skip_call">{tr('跳过调用', 'Skip Call')}</option>
            <option value="replace_function">{tr('函数替换', 'Replace Function')}</option>
          </select>
          {(draft.patch_action === 'override_return' || draft.patch_action === 'skip_call') && (
            <input type="number" placeholder={tr('返回值 (如 -1)', 'Return value (e.g. -1)')} value={draft.override_return_value} onChange={e => setDraft({ ...draft, override_return_value: parseInt(e.target.value, 10) || 0 })} />
          )}
          <button className="btn-primary" onClick={handleAdd}>{tr('添加', 'Add')}</button>
        </div>
        {draft.patch_action === 'replace_function' && (
          <div className="add-row" style={{ marginTop: 10 }}>
            <label className="btn-upload" style={{
              padding: '8px 16px', background: uploadedLib ? '#f0fdf4' : '#f8fafc',
              border: `1px solid ${uploadedLib ? '#bbf7d0' : '#e2e8f0'}`, borderRadius: 8,
              fontSize: '12.5px', cursor: 'pointer', display: 'inline-flex', alignItems: 'center', gap: 6,
            }}>
              {uploading ? tr('上传中...', 'Uploading...') : uploadedLib
                ? `✅ ${uploadedLib.split('/').pop()}`
                : tr('📁 上传 .so 动态链接库', '📁 Upload .so Library')}
              <input
                type="file"
                accept=".so,.so.*"
                style={{ display: 'none' }}
                onChange={e => { const f = e.target.files?.[0]; if (f) handleUploadLib(f); e.target.value = '' }}
                disabled={uploading}
              />
            </label>
            <input
              type="text"
              placeholder={tr('替换符号名（可选，默认同原符号）', 'Replace symbol (optional, defaults to original)')}
              value={draft.replace_symbol ?? ''}
              onChange={e => setDraft({ ...draft, replace_symbol: e.target.value || null })}
              style={{ minWidth: 240 }}
            />
          </div>
        )}
      </div>
    </div>
  )
}

// ── Process Detail Modal ──

function ProcessDetailModal({ detail, loading, tr, onClose }: {
  detail: ProcessDetail | null; loading: boolean
  tr: (zh: string, en: string) => string; onClose: () => void
}) {
  if (!loading && !detail) return null

  const formatBytes = (b: number) => {
    if (b < 1024) return `${b} B`
    if (b < 1048576) return `${(b / 1024).toFixed(1)} KB`
    if (b < 1073741824) return `${(b / 1048576).toFixed(1)} MB`
    return `${(b / 1073741824).toFixed(2)} GB`
  }

  const formatUptime = (secs: number) => {
    const d = Math.floor(secs / 86400)
    const h = Math.floor((secs % 86400) / 3600)
    const m = Math.floor((secs % 3600) / 60)
    const s = Math.floor(secs % 60)
    const parts: string[] = []
    if (d > 0) parts.push(`${d}d`)
    if (h > 0) parts.push(`${h}h`)
    if (m > 0) parts.push(`${m}m`)
    parts.push(`${s}s`)
    return parts.join(' ')
  }

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-panel" onClick={e => e.stopPropagation()}>
        <div className="modal-header">
          <h3>{tr('进程详情', 'Process Detail')}{detail ? ` — PID ${detail.pid}` : ''}</h3>
          <button className="modal-close" onClick={onClose}>✕</button>
        </div>
        <div className="modal-body">
          {loading && <div className="modal-loading">{tr('加载中...', 'Loading...')}</div>}
          {!loading && detail && (
            <>
              {/* Basic Info */}
              <section className="detail-section">
                <h4>{tr('基本信息', 'Basic Info')}</h4>
                <div className="detail-grid">
                  <div className="detail-item"><span className="detail-label">PID</span><span className="detail-value">{detail.pid}</span></div>
                  <div className="detail-item"><span className="detail-label">PPID</span><span className="detail-value">{detail.ppid}</span></div>
                  <div className="detail-item"><span className="detail-label">{tr('进程名', 'Name')}</span><span className="detail-value">{detail.name}</span></div>
                  <div className="detail-item"><span className="detail-label">{tr('状态', 'State')}</span><span className="detail-value"><span className={`state-badge state-${detail.state.toLowerCase()}`}>{detail.state}</span></span></div>
                  <div className="detail-item"><span className="detail-label">UID / EUID</span><span className="detail-value">{detail.uid} / {detail.euid}</span></div>
                  <div className="detail-item"><span className="detail-label">GID / EGID</span><span className="detail-value">{detail.gid} / {detail.egid}</span></div>
                  <div className="detail-item"><span className="detail-label">{tr('线程数', 'Threads')}</span><span className="detail-value">{detail.threads}</span></div>
                  <div className="detail-item"><span className="detail-label">{tr('运行时间', 'Uptime')}</span><span className="detail-value">{formatUptime(detail.uptime_secs)}</span></div>
                  <div className="detail-item"><span className="detail-label">OOM Score</span><span className="detail-value">{detail.oom_score}</span></div>
                </div>
              </section>

              {/* Executable & Paths */}
              <section className="detail-section">
                <h4>{tr('路径信息', 'Paths')}</h4>
                <div className="detail-paths">
                  <div className="path-row"><span className="detail-label">{tr('可执行文件', 'Executable')}</span><code>{detail.exe}</code></div>
                  <div className="path-row"><span className="detail-label">{tr('工作目录', 'CWD')}</span><code>{detail.cwd}</code></div>
                  <div className="path-row"><span className="detail-label">{tr('命令行', 'Cmdline')}</span><code className="cmdline">{detail.cmdline}</code></div>
                </div>
              </section>

              {/* Memory */}
              <section className="detail-section">
                <h4>{tr('内存使用', 'Memory')}</h4>
                <div className="detail-grid">
                  <div className="detail-item"><span className="detail-label">VmPeak</span><span className="detail-value">{formatBytes(detail.mem.vm_peak_kb * 1024)}</span></div>
                  <div className="detail-item"><span className="detail-label">VmSize</span><span className="detail-value">{formatBytes(detail.mem.vm_size_kb * 1024)}</span></div>
                  <div className="detail-item"><span className="detail-label">VmRSS</span><span className="detail-value">{formatBytes(detail.mem.vm_rss_kb * 1024)}</span></div>
                  <div className="detail-item"><span className="detail-label">VmData</span><span className="detail-value">{formatBytes(detail.mem.vm_data_kb * 1024)}</span></div>
                  <div className="detail-item"><span className="detail-label">VmStk</span><span className="detail-value">{formatBytes(detail.mem.vm_stk_kb * 1024)}</span></div>
                  <div className="detail-item"><span className="detail-label">VmExe</span><span className="detail-value">{formatBytes(detail.mem.vm_exe_kb * 1024)}</span></div>
                  <div className="detail-item"><span className="detail-label">VmLib</span><span className="detail-value">{formatBytes(detail.mem.vm_lib_kb * 1024)}</span></div>
                  <div className="detail-item"><span className="detail-label">VmSwap</span><span className="detail-value">{formatBytes(detail.mem.vm_swap_kb * 1024)}</span></div>
                </div>
              </section>

              {/* I/O */}
              <section className="detail-section">
                <h4>{tr('I/O 统计', 'I/O Stats')}</h4>
                <div className="detail-grid">
                  <div className="detail-item"><span className="detail-label">{tr('逻辑读', 'Logical Read')}</span><span className="detail-value">{formatBytes(detail.io.rchar)}</span></div>
                  <div className="detail-item"><span className="detail-label">{tr('逻辑写', 'Logical Write')}</span><span className="detail-value">{formatBytes(detail.io.wchar)}</span></div>
                  <div className="detail-item"><span className="detail-label">{tr('磁盘读', 'Disk Read')}</span><span className="detail-value">{formatBytes(detail.io.read_bytes)}</span></div>
                  <div className="detail-item"><span className="detail-label">{tr('磁盘写', 'Disk Write')}</span><span className="detail-value">{formatBytes(detail.io.write_bytes)}</span></div>
                  <div className="detail-item"><span className="detail-label">{tr('读系统调用', 'Read Syscalls')}</span><span className="detail-value">{detail.io.syscr.toLocaleString()}</span></div>
                  <div className="detail-item"><span className="detail-label">{tr('写系统调用', 'Write Syscalls')}</span><span className="detail-value">{detail.io.syscw.toLocaleString()}</span></div>
                </div>
              </section>

              {/* Security & Scheduling */}
              <section className="detail-section">
                <h4>{tr('安全与调度', 'Security & Scheduling')}</h4>
                <div className="detail-grid">
                  <div className="detail-item"><span className="detail-label">CapEff</span><span className="detail-value" style={{fontSize: 11, wordBreak: 'break-all'}}>{detail.cap_eff}</span></div>
                  <div className="detail-item"><span className="detail-label">Seccomp</span><span className="detail-value">{detail.seccomp}</span></div>
                  <div className="detail-item"><span className="detail-label">{tr('允许 CPU', 'CPUs Allowed')}</span><span className="detail-value">{detail.cpus_allowed_list}</span></div>
                  <div className="detail-item"><span className="detail-label">{tr('主动上下文切换', 'Vol. Ctx Switches')}</span><span className="detail-value">{detail.voluntary_ctxt_switches.toLocaleString()}</span></div>
                  <div className="detail-item"><span className="detail-label">{tr('被动上下文切换', 'Invol. Ctx Switches')}</span><span className="detail-value">{detail.nonvoluntary_ctxt_switches.toLocaleString()}</span></div>
                </div>
              </section>

              {/* File Descriptors */}
              <section className="detail-section">
                <h4>{tr('文件描述符', 'File Descriptors')} ({detail.fds.length})</h4>
                <div className="fd-table-wrap">
                  <table className="fd-table">
                    <thead>
                      <tr><th>FD</th><th>{tr('目标', 'Target')}</th></tr>
                    </thead>
                    <tbody>
                      {detail.fds.slice(0, 50).map(fd => (
                        <tr key={fd.fd}><td className="fd-num">{fd.fd}</td><td className="fd-path"><code>{fd.target}</code></td></tr>
                      ))}
                      {detail.fds.length > 50 && (
                        <tr><td colSpan={2} className="fd-more">{tr(`... 还有 ${detail.fds.length - 50} 个`, `... ${detail.fds.length - 50} more`)}</td></tr>
                      )}
                    </tbody>
                  </table>
                </div>
              </section>

              {/* Environment Variables */}
              {detail.environ.length > 0 && (
                <section className="detail-section">
                  <h4>{tr('环境变量', 'Environment Variables')} ({detail.environ.length})</h4>
                  <div className="env-list">
                    {detail.environ.slice(0, 30).map((env, i) => {
                      const eq = env.indexOf('=')
                      const k = eq > 0 ? env.slice(0, eq) : env
                      const v = eq > 0 ? env.slice(eq + 1) : ''
                      return <div key={i} className="env-row"><span className="env-key">{k}</span><span className="env-eq">=</span><span className="env-val">{v}</span></div>
                    })}
                    {detail.environ.length > 30 && (
                      <div className="env-more">{tr(`... 还有 ${detail.environ.length - 30} 个`, `... ${detail.environ.length - 30} more`)}</div>
                    )}
                  </div>
                </section>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  )
}

export default App
