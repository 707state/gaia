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
}

type AlertRecord = { level: string; reason: string; event: EventRecord }

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
  services: Record<string, number[]>
  events: EventRecord[]
  alerts: AlertRecord[]
}

type RateLimitRule = {
  cidr: string
  max_conn_per_sec: number
  action: 'log' | 'block' | 'throttle'
  enabled: boolean
}

type HotpatchTarget = {
  binary: string
  symbol: string
  pid?: number | null
}

type MonitorPolicy = {
  sensitive_prefixes: string[]
  monitored_services: string[]
  exec_whitelist_prefixes: string[]
  blocked_ports: number[]
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
    'sshd.service': [721],
    'nginx.service': [1142, 1145, 1148],
    'redis.service': [2001],
    'postgresql.service': [3010, 3011],
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

  const tr = useCallback((zh: string, en: string) => (lang === 'zh' ? zh : en), [lang])

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
          {tab === 'overview' && <OverviewTab snapshot={snapshot} totalEvents={totalEvents} lang={lang} tr={tr} />}
          {tab === 'file' && <FileTab snapshot={snapshot} lang={lang} tr={tr} />}
          {tab === 'process' && <ProcessTab snapshot={snapshot} lang={lang} tr={tr} />}
          {tab === 'network' && <NetworkTab snapshot={snapshot} lang={lang} tr={tr} />}
          {tab === 'hotpatch' && <HotpatchTab snapshot={snapshot} lang={lang} tr={tr} />}
          {tab === 'alerts' && <AlertsTab snapshot={snapshot} lang={lang} tr={tr} />}
          {tab === 'config' && <ConfigTab lang={lang} tr={tr} />}
        </div>
      </main>
    </div>
  )
}

// ── Overview Tab ──

function OverviewTab({ snapshot, totalEvents, lang, tr }: {
  snapshot: Snapshot; totalEvents: number; lang: Lang; tr: (zh: string, en: string) => string
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
            {Object.entries(snapshot.services).map(([svc, pids]) => (
              <div key={svc} className="service-item">
                <div className="service-name">
                  <span className="service-dot" />
                  {svc}
                </div>
                <div className="service-pids">
                  {pids.map(p => <code key={p} className="pid-tag">{p}</code>)}
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

function NetworkTab({ snapshot, lang, tr }: {
  snapshot: Snapshot; lang: Lang; tr: (zh: string, en: string) => string
}) {
  const netEvents = snapshot.events.filter(e => e.kind === 'network')
  const blockedEvents = netEvents.filter(e => e.action === 'blocked')
  const rateLimited = netEvents.filter(e => e.action === 'rate_limited')
  const netAlerts = snapshot.alerts.filter(a => a.event.kind === 'network')

  return (
    <div className="tab-content">
      <div className="tab-intro">
        <p>{tr(
          '网络遥测代理通过 tracepoint/syscalls/sys_enter_connect 和 bind 挂载点，监控被托管关键服务的外连请求与端口监听变更事件。支持基于 CIDR 的 IP 限流规则，在内核态直接评估并执行阻断/限速策略。',
          'The Network Telemetry Agent hooks into tracepoint/syscalls/sys_enter_connect and bind to monitor outbound connections and port binding events of tracked services. It supports CIDR-based IP rate limiting rules, evaluated and enforced directly in kernel space.'
        )}</p>
      </div>

      <div className="stats-grid">
        <div className="stat-card accent-blue">
          <div className="stat-icon">🌐</div>
          <div className="stat-body">
            <span className="stat-label">{tr('网络事件', 'Network Events')}</span>
            <span className="stat-value">{(snapshot.counters.network ?? 0).toLocaleString()}</span>
          </div>
        </div>
        <div className="stat-card accent-red">
          <div className="stat-icon">🚫</div>
          <div className="stat-body">
            <span className="stat-label">{tr('阻断连接', 'Blocked')}</span>
            <span className="stat-value">{blockedEvents.length}</span>
          </div>
        </div>
        <div className="stat-card accent-purple">
          <div className="stat-icon">⏱️</div>
          <div className="stat-body">
            <span className="stat-label">{tr('限流触发', 'Rate Limited')}</span>
            <span className="stat-value">{rateLimited.length}</span>
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

      <div className="card">
        <div className="card-header">
          <h3>{tr('网络事件流', 'Network Event Stream')}</h3>
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

  return (
    <div className="tab-content">
      <div className="tab-intro">
        <p>{tr(
          '热补丁代理（主动防御）通过 kprobe/kretprobe 和 uprobe/uretprobe 挂载点，针对高危漏洞函数动态下发补丁。在函数入口校验参数，或通过 bpf_override_return 强制返回错误码，从而在运行时阻断漏洞利用，无需重启服务。',
          'The Hot-patching Agent (Active Defense) uses kprobe/kretprobe and uprobe/uretprobe hooks to dynamically deploy patches to vulnerable functions. It validates arguments at function entry or forces error returns via bpf_override_return, neutralizing exploits at runtime without service restarts.'
        )}</p>
      </div>

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

  if (loading) return <div className="tab-content"><div className="empty-state">{tr('加载配置中...', 'Loading configuration...')}</div></div>
  if (!policy) return <div className="tab-content"><div className="empty-state">{tr('无法加载配置（后端离线？）', 'Unable to load configuration (backend offline?)')}</div></div>

  return (
    <div className="tab-content">
      {msg && <div className="toast">{msg}</div>}

      <div className="tab-intro">
        <p>{tr(
          '在此配置监控策略，包括敏感文件路径、可执行白名单、监控服务、阻断端口、基线阈值、IP 限流规则和热补丁目标。所有配置变更将实时同步到内核态 eBPF 探针。',
          'Configure monitoring policies here, including sensitive file paths, executable whitelists, monitored services, blocked ports, baseline thresholds, IP rate limiting rules, and hotpatch targets. All changes are synced to kernel-space eBPF probes in real-time.'
        )}</p>
      </div>

      <GeneralPolicyPanel policy={policy} setPolicy={setPolicy} saving={saving} setSaving={setSaving} flash={flash} lang={lang} tr={tr} />
      <RateLimitPanel rules={policy.rate_limit_rules} setRules={r => setPolicy({ ...policy, rate_limit_rules: r })} flash={flash} tr={tr} />
      <HotpatchConfigPanel targets={policy.hotpatch.targets} setTargets={t => setPolicy({ ...policy, hotpatch: { targets: t } })} flash={flash} tr={tr} />
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

function GeneralPolicyPanel({ policy, setPolicy, saving, setSaving, flash, lang, tr }: {
  policy: MonitorPolicy; setPolicy: (p: MonitorPolicy) => void; saving: boolean; setSaving: (v: boolean) => void
  flash: (msg: string) => void; lang: Lang; tr: (zh: string, en: string) => string
}) {
  const [sensitivePrefixes, setSensitivePrefixes] = useState(policy.sensitive_prefixes.join('\n'))
  const [execWhitelist, setExecWhitelist] = useState(policy.exec_whitelist_prefixes.join('\n'))
  const [monitoredServices, setMonitoredServices] = useState(policy.monitored_services.join('\n'))
  const [blockedPorts, setBlockedPorts] = useState(policy.blocked_ports.join(', '))
  const [thresholds, setThresholds] = useState({ ...policy.baseline_thresholds })

  const handleSave = async () => {
    setSaving(true)
    const body = {
      sensitive_prefixes: sensitivePrefixes.split('\n').map(s => s.trim()).filter(Boolean),
      exec_whitelist_prefixes: execWhitelist.split('\n').map(s => s.trim()).filter(Boolean),
      monitored_services: monitoredServices.split('\n').map(s => s.trim()).filter(Boolean),
      blocked_ports: blockedPorts.split(',').map(s => parseInt(s.trim(), 10)).filter(n => !isNaN(n)),
      baseline_thresholds: thresholds,
    }
    try {
      const r = await fetch('/api/v1/config', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
      if (r.ok) { const updated = await r.json() as MonitorPolicy; setPolicy(updated); flash(tr('通用策略已保存', 'General policy saved')) }
      else flash(tr('保存失败: ', 'Save failed: ') + r.statusText)
    } catch { flash(tr('保存失败: 网络错误', 'Save failed: network error')) }
    setSaving(false)
  }

  return (
    <div className="card">
      <div className="card-header"><h3>{tr('通用监控策略', 'General Monitoring Policy')}</h3></div>
      <div className="cfg-grid">
        <div className="cfg-field">
          <label>{tr('敏感文件前缀', 'Sensitive File Prefixes')}</label>
          <textarea rows={4} value={sensitivePrefixes} onChange={e => setSensitivePrefixes(e.target.value)} placeholder="/etc/shadow&#10;/etc/ssl&#10;/root/.ssh" />
          <span className="cfg-hint">{tr('每行一个路径前缀，匹配的文件访问将触发告警', 'One path prefix per line; matching file access triggers alerts')}</span>
        </div>
        <div className="cfg-field">
          <label>{tr('可执行白名单前缀', 'Exec Whitelist Prefixes')}</label>
          <textarea rows={4} value={execWhitelist} onChange={e => setExecWhitelist(e.target.value)} placeholder="/usr/bin&#10;/usr/sbin" />
          <span className="cfg-hint">{tr('允许的 execve 路径前缀，不在白名单内的将触发告警', 'Allowed execve path prefixes; non-whitelisted paths trigger alerts')}</span>
        </div>
        <div className="cfg-field">
          <label>{tr('监控服务', 'Monitored Services')}</label>
          <textarea rows={3} value={monitoredServices} onChange={e => setMonitoredServices(e.target.value)} placeholder="sshd.service&#10;nginx.service" />
          <span className="cfg-hint">{tr('systemd unit 名称，自动追踪其 PID', 'Systemd unit names; PIDs are tracked automatically')}</span>
        </div>
        <div className="cfg-field">
          <label>{tr('阻断端口', 'Blocked Ports')}</label>
          <input type="text" value={blockedPorts} onChange={e => setBlockedPorts(e.target.value)} placeholder="4444, 31337" />
          <span className="cfg-hint">{tr('逗号分隔端口号，匹配的连接将被阻断', 'Comma-separated port numbers; matching connections are blocked')}</span>
        </div>
      </div>

      <h4 className="cfg-section-title">{tr('基线阈值（每 30 秒窗口）', 'Baseline Thresholds (per 30s window)')}</h4>
      <div className="threshold-grid">
        {['file_io', 'process', 'privilege', 'network', 'hotpatch'].map(k => (
          <div key={k} className="threshold-item">
            <label>{mapKind(k, lang)}</label>
            <input type="number" min={0} value={thresholds[k] ?? 0} onChange={e => setThresholds({ ...thresholds, [k]: parseInt(e.target.value, 10) || 0 })} />
          </div>
        ))}
      </div>

      <button className="btn-primary" onClick={handleSave} disabled={saving}>
        {saving ? tr('保存中...', 'Saving...') : tr('保存通用策略', 'Save General Policy')}
      </button>
    </div>
  )
}

const emptyRule: RateLimitRule = { cidr: '', max_conn_per_sec: 100, action: 'log', enabled: true }

function RateLimitPanel({ rules, setRules, flash, tr }: {
  rules: RateLimitRule[]; setRules: (r: RateLimitRule[]) => void; flash: (msg: string) => void; tr: (zh: string, en: string) => string
}) {
  const [draft, setDraft] = useState<RateLimitRule>({ ...emptyRule })

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

  const handleToggle = async (index: number) => {
    const rule = { ...rules[index], enabled: !rules[index].enabled }
    try {
      const r = await fetch('/api/v1/config/rate-limit', { method: 'PUT', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ index, ...rule }) })
      if (r.ok) { setRules(await r.json()); flash(tr('规则已更新', 'Rule updated')) }
    } catch { flash(tr('更新失败', 'Update failed')) }
  }

  return (
    <div className="card">
      <div className="card-header">
        <h3>{tr('IP 限流规则', 'IP Rate Limiting Rules')}</h3>
        <span className="card-badge">{rules.length} {tr('条规则', 'rules')}</span>
      </div>
      <p className="card-desc">{tr(
        '配置基于 CIDR 的连接速率限制。规则由网络遥测代理在内核态实时评估，支持记录、阻断和限速三种动作。',
        'Define per-CIDR connection rate limits. Rules are evaluated by the network telemetry agent in kernel space at runtime, supporting log, block, and throttle actions.'
      )}</p>

      {rules.length > 0 && (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>CIDR</th>
                <th>{tr('最大连接/秒', 'Max Conn/s')}</th>
                <th>{tr('动作', 'Action')}</th>
                <th>{tr('状态', 'Status')}</th>
                <th>{tr('操作', 'Operations')}</th>
              </tr>
            </thead>
            <tbody>
              {rules.map((rule, i) => (
                <tr key={i} className={rule.enabled ? '' : 'row-disabled'}>
                  <td><code>{rule.cidr}</code></td>
                  <td>{rule.max_conn_per_sec}</td>
                  <td><span className={`action-tag action-${rule.action}`}>{rule.action}</span></td>
                  <td>
                    <button className={`toggle-btn ${rule.enabled ? 'on' : 'off'}`} onClick={() => handleToggle(i)}>
                      {rule.enabled ? tr('启用', 'ON') : tr('禁用', 'OFF')}
                    </button>
                  </td>
                  <td><button className="btn-danger-sm" onClick={() => handleDelete(i)}>{tr('删除', 'Delete')}</button></td>
                </tr>
              ))}
            </tbody>
          </table>
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
          <label className="check-label">
            <input type="checkbox" checked={draft.enabled} onChange={e => setDraft({ ...draft, enabled: e.target.checked })} />
            {tr('启用', 'Enabled')}
          </label>
          <button className="btn-primary" onClick={handleAdd}>{tr('添加', 'Add')}</button>
        </div>
      </div>
    </div>
  )
}

const emptyTarget: HotpatchTarget = { binary: '', symbol: '', pid: null }

function HotpatchConfigPanel({ targets, setTargets, flash, tr }: {
  targets: HotpatchTarget[]; setTargets: (t: HotpatchTarget[]) => void; flash: (msg: string) => void; tr: (zh: string, en: string) => string
}) {
  const [draft, setDraft] = useState<HotpatchTarget>({ ...emptyTarget })

  const handleAdd = async () => {
    if (!draft.binary.trim() || !draft.symbol.trim()) { flash(tr('二进制路径和符号名必填', 'Binary path and symbol name are required')); return }
    const payload = { binary: draft.binary.trim(), symbol: draft.symbol.trim(), pid: draft.pid || null }
    try {
      const r = await fetch('/api/v1/config/hotpatch', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) })
      if (r.ok) { setTargets(await r.json()); setDraft({ ...emptyTarget }); flash(tr('热补丁目标已添加', 'Hotpatch target added')) }
      else flash(tr('添加失败: ', 'Add failed: ') + r.statusText)
    } catch { flash(tr('添加失败: 网络错误', 'Add failed: network error')) }
  }

  const handleDelete = async (index: number) => {
    try {
      const r = await fetch(`/api/v1/config/hotpatch/${index}`, { method: 'DELETE' })
      if (r.ok) { setTargets(await r.json()); flash(tr('目标已删除', 'Target removed')) }
    } catch { flash(tr('删除失败', 'Delete failed')) }
  }

  return (
    <div className="card">
      <div className="card-header">
        <h3>{tr('热补丁目标配置', 'Hot-Patch Target Configuration')}</h3>
        <span className="card-badge">{targets.length} {tr('个目标', 'targets')}</span>
      </div>
      <p className="card-desc">{tr(
        '通过 uprobe/uretprobe 在运行时挂载到高危函数入口和出口，结合参数校验与返回值控制（bpf_override_return）实现不停机防护。动态符号解析器自动解析 ELF 符号表和 /proc/[pid]/maps 以克服 ASLR。',
        'Attach uprobe/uretprobe probes to vulnerable functions at runtime. The hot-patching agent validates arguments and can force error returns via bpf_override_return without restarting services. The dynamic symbol resolver automatically parses ELF symbol tables and /proc/[pid]/maps to bypass ASLR.'
      )}</p>

      {targets.length > 0 && (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>{tr('二进制文件', 'Binary')}</th>
                <th>{tr('符号', 'Symbol')}</th>
                <th>PID</th>
                <th>{tr('操作', 'Operations')}</th>
              </tr>
            </thead>
            <tbody>
              {targets.map((t, i) => (
                <tr key={i}>
                  <td><code>{t.binary}</code></td>
                  <td><code>{t.symbol}</code></td>
                  <td>{t.pid ?? tr('全部', 'all')}</td>
                  <td><button className="btn-danger-sm" onClick={() => handleDelete(i)}>{tr('删除', 'Delete')}</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <div className="add-form">
        <h4>{tr('新增目标', 'Add Target')}</h4>
        <div className="add-row">
          <input type="text" placeholder="/usr/sbin/nginx" value={draft.binary} onChange={e => setDraft({ ...draft, binary: e.target.value })} />
          <input type="text" placeholder="ngx_http_process_request" value={draft.symbol} onChange={e => setDraft({ ...draft, symbol: e.target.value })} />
          <input type="number" min={0} placeholder={tr('PID（可选）', 'PID (optional)')} value={draft.pid ?? ''} onChange={e => setDraft({ ...draft, pid: e.target.value ? parseInt(e.target.value, 10) : null })} />
          <button className="btn-primary" onClick={handleAdd}>{tr('添加', 'Add')}</button>
        </div>
      </div>
    </div>
  )
}

export default App
