import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import {
  mockSnapshot,
  featureMeta,
  tabDefs,
} from './app/constants'
import {
  AiConfigPanel,
  BaselinePanel,
  BlockedPortsPanel,
  HotpatchConfigPanel,
  RateLimitPanel,
} from './app/components/ConfigPanels'
import {
  AlertList,
  EventDetailModal,
  EventTable,
  FileEventDetailModal,
  HistoryPanel,
  ProcessDetailModal,
  ToggleListPanel,
} from './app/components/SharedPanels'
import type {
  AiAlertNotification,
  AiConfig,
  AlertRecord,
  ChatMessage,
  ChatRole,
  EventRecord,
  FileEventDetail,
  Lang,
  MonitorPolicy,
  ProcessDetail,
  Snapshot,
  Tab,
  UiChatMessage,
} from './app/types'
import { storedToEventRecord } from './app/types'
import {
  formatTimestamp,
  initialLang,
  mapAction,
  mapKind,
} from './app/utils'
import './App.css'

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
          {tab === 'process' && <ProcessTab snapshot={snapshot} lang={lang} tr={tr} onPidClick={openProcessDetail} />}
          {tab === 'network' && <NetworkTab snapshot={snapshot} lang={lang} tr={tr} />}
          {tab === 'hotpatch' && <HotpatchTab snapshot={snapshot} lang={lang} tr={tr} />}
          {tab === 'alerts' && <AlertsTab snapshot={snapshot} lang={lang} tr={tr} />}
          {tab === 'ai' && <AiTab lang={lang} tr={tr} />}
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
  const [selectedEvent, setSelectedEvent] = useState<EventRecord | null>(null)
  const [selectedAlert, setSelectedAlert] = useState<AlertRecord | null>(null)
  const [fileDetail, setFileDetail] = useState<FileEventDetail | null>(null)
  const [fileDetailLoading, setFileDetailLoading] = useState(false)
  const [eventsCollapsed, setEventsCollapsed] = useState(false)
  const [historyDetailEvent, setHistoryDetailEvent] = useState<EventRecord | null>(null)

  const fileEvents = snapshot.events.filter(e => e.kind === 'file_io')
  const fileAlerts = snapshot.alerts.filter(a => a.event.kind === 'file_io')
  const sensitiveAccess = fileEvents.filter(e => e.action === 'alert').length

  const fetchDetail = useCallback(async (event: EventRecord) => {
    setFileDetail(null)
    setFileDetailLoading(true)
    try {
      const params = new URLSearchParams({ path: event.detail })
      if (event.pid) params.set('pid', String(event.pid))
      const r = await fetch(`/api/v1/file-event/detail?${params}`)
      if (r.ok) setFileDetail((await r.json()) as FileEventDetail)
    } catch { /* ignore */ }
    setFileDetailLoading(false)
  }, [])

  const openEventDetail = useCallback((event: EventRecord) => {
    if (event.action !== 'enter' && event.action !== 'alert') return
    setSelectedEvent(event)
    setSelectedAlert(null)
    fetchDetail(event)
  }, [fetchDetail])

  const openAlertDetail = useCallback((alert: AlertRecord) => {
    setSelectedAlert(alert)
    setSelectedEvent(alert.event)
    fetchDetail(alert.event)
  }, [fetchDetail])

  const closeDetail = useCallback(() => {
    setSelectedEvent(null)
    setSelectedAlert(null)
    setFileDetail(null)
    setFileDetailLoading(false)
  }, [])

  return (
    <div className="tab-content">
      <div className="tab-intro">
        <p>{tr(
          '文件 I/O 代理通过 tracepoint/syscalls/sys_enter_openat 和 sys_exit_openat 挂载点，在内核态进行轻量级路径前缀匹配，仅将对敏感目标（如 /etc/shadow、SSL 证书、SSH 密钥等）的访问事件上报至用户态。点击事件行或告警项可查看详情。',
          'The File I/O Agent hooks into tracepoint/syscalls/sys_enter_openat and sys_exit_openat, performing lightweight path prefix matching in kernel space. Only access events targeting sensitive files (e.g., /etc/shadow, SSL certs, SSH keys) are forwarded to user space. Click an event row or alert to inspect it.'
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
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <span className="card-badge">{tr('点击行查看详情', 'Click row for details')}</span>
            <button
              className="btn-collapse"
              onClick={() => setEventsCollapsed(c => !c)}
              title={eventsCollapsed ? tr('展开', 'Expand') : tr('收起', 'Collapse')}
            >
              {eventsCollapsed ? '▶' : '▼'}
            </button>
          </div>
        </div>
        {!eventsCollapsed && (
          fileEvents.length > 0 ? (
            <div className="file-event-scroll">
              <FileEventTable events={fileEvents} lang={lang} tr={tr} onEventClick={openEventDetail} />
            </div>
          ) : (
            <div className="empty-state">{tr('暂无文件事件', 'No file events yet')}</div>
          )
        )}
      </div>

      {fileAlerts.length > 0 && (
        <div className="card">
          <div className="card-header">
            <h3>{tr('文件相关告警', 'File-related Alerts')}</h3>
            <span className="card-badge">{tr('点击告警查看详情', 'Click alert for details')}</span>
          </div>
          <div className="file-alert-scroll">
            <AlertList alerts={fileAlerts} lang={lang} onAlertClick={openAlertDetail} />
          </div>
        </div>
      )}

      <HistoryPanel kinds={['file_io']} lang={lang} tr={tr} onEventClick={e => setHistoryDetailEvent(storedToEventRecord(e))} />

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

      <FileEventDetailModal
        event={selectedEvent}
        alertRecord={selectedAlert}
        detail={fileDetail}
        loading={fileDetailLoading}
        lang={lang}
        tr={tr}
        onClose={closeDetail}
      />
      <EventDetailModal event={historyDetailEvent} lang={lang} tr={tr} onClose={() => setHistoryDetailEvent(null)} />
    </div>
  )
}

function FileEventTable({ events, lang, tr, onEventClick }: {
  events: EventRecord[]
  lang: Lang
  tr: (zh: string, en: string) => string
  onEventClick: (event: EventRecord) => void
}) {
  const isClickable = (e: EventRecord) => e.action === 'enter' || e.action === 'alert'
  return (
    <div className="table-wrap">
      <table>
        <thead>
          <tr>
            <th>{tr('时间', 'Time')}</th>
            <th>{tr('动作', 'Action')}</th>
            <th>{tr('服务', 'Service')}</th>
            <th>{tr('进程', 'Process')}</th>
            <th>PID</th>
            <th>UID</th>
            <th>{tr('文件路径', 'File Path')}</th>
          </tr>
        </thead>
        <tbody>
          {events.map((e, i) => (
            <tr
              key={`${e.timestamp_ns}-${i}`}
              className={`${e.action === 'blocked' ? 'row-blocked' : e.action === 'alert' ? 'row-alert' : e.action === 'rate_limited' ? 'row-rate-limited' : ''} ${isClickable(e) ? 'row-clickable' : ''}`}
              onClick={() => isClickable(e) && onEventClick(e)}
              title={isClickable(e) ? tr('点击查看事件详情', 'Click to inspect event') : undefined}
            >
              <td className="td-time">{formatTimestamp(e.timestamp_ns)}</td>
              <td><span className={`action-tag action-${e.action}`}>{mapAction(e.action, lang)}</span></td>
              <td>{e.service ? <span className="service-badge">{e.service}</span> : <span className="no-service">-</span>}</td>
              <td><code>{e.comm || '-'}</code></td>
              <td>{e.pid}</td>
              <td>{e.uid}</td>
              <td className="td-detail">{e.detail || '-'}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

// ── Process Tab ──

function ProcessTab({ snapshot, lang, tr, onPidClick }: {
  snapshot: Snapshot; lang: Lang; tr: (zh: string, en: string) => string
  onPidClick: (pid: number) => void
}) {
  const [detailEvent, setDetailEvent] = useState<EventRecord | null>(null)

  const processEvents = snapshot.events.filter(e => e.kind === 'process' || e.kind === 'privilege')
  const privEvents = snapshot.events.filter(e => e.kind === 'privilege')
  const processAlerts = snapshot.alerts.filter(a => a.event.kind === 'process' || a.event.kind === 'privilege')

  return (
    <div className="tab-content">
      <div className="tab-intro">
        <p>{tr(
          '进程与权限代理通过 tracepoint/syscalls/sys_enter_execve、setuid、setgid 挂载点，追踪进程树的生命周期，检测未经授权的特权提升行为。点击事件行可查看该进程的实时详情。',
          'The Process & Privilege Agent hooks into sys_enter_execve, setuid, and setgid to track process lifecycles and detect privilege escalations. Click any event row to inspect the live process details.'
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
          <span className="card-badge">{tr('点击行查看详情', 'Click row for details')}</span>
        </div>
        {processEvents.length > 0 ? (
          <EventTable events={processEvents} lang={lang} tr={tr} onRowClick={setDetailEvent} />
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
          <EventTable events={privEvents} lang={lang} tr={tr} onRowClick={setDetailEvent} />
        </div>
      )}

      <HistoryPanel kinds={['process', 'privilege']} lang={lang} tr={tr} onPidClick={onPidClick} onEventClick={e => setDetailEvent(storedToEventRecord(e))} />

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

      <EventDetailModal event={detailEvent} lang={lang} tr={tr} onClose={() => setDetailEvent(null)} />
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
  const [detailEvent, setDetailEvent] = useState<EventRecord | null>(null)

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
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <span className="card-badge">{tr('网络事件', 'Events')}: {(snapshot.counters.network ?? 0).toLocaleString()}</span>
            <span className="card-badge">{tr('点击行查看详情', 'Click row for details')}</span>
          </div>
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
                  <tr
                    key={`${e.timestamp_ns}-${i}`}
                    className={`${e.action === 'blocked' ? 'row-blocked' : e.action === 'rate_limited' ? 'row-rate-limited' : ''} row-clickable`}
                    onClick={() => setDetailEvent(e)}
                    title={tr('点击查看事件详情', 'Click to inspect event')}
                  >
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

      <HistoryPanel kinds={['network']} lang={lang} tr={tr} onEventClick={e => setDetailEvent(storedToEventRecord(e))} />

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

      <EventDetailModal event={detailEvent} lang={lang} tr={tr} onClose={() => setDetailEvent(null)} />
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
  const [detailEvent, setDetailEvent] = useState<EventRecord | null>(null)

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
          <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
            <span className="card-badge">{tr('点击行查看详情', 'Click row for details')}</span>
            <button className="btn-reload" onClick={handleReload} disabled={reloading}>
              {reloading ? tr('重载中...', 'Reloading...') : tr('重载探针', 'Reload Probes')}
            </button>
          </div>
        </div>
        {hotpatchEvents.length > 0 ? (
          <EventTable events={hotpatchEvents} lang={lang} tr={tr} onRowClick={setDetailEvent} />
        ) : (
          <div className="empty-state">{tr('暂无热补丁事件', 'No hotpatch events yet')}</div>
        )}
      </div>

      <HistoryPanel kinds={['hotpatch']} lang={lang} tr={tr} onEventClick={e => setDetailEvent(storedToEventRecord(e))} />

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

      <EventDetailModal event={detailEvent} lang={lang} tr={tr} onClose={() => setDetailEvent(null)} />
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

// ── AI Analysis Tab ──

let _aiMsgCounter = 0
function aiMsgId() { return `ai-${++_aiMsgCounter}-${Date.now()}` }

// ── Alert Panel (collapsible floating panel) ──────────────────────────────────
function AiAlertPanel({ alerts, onClear, tr }: {
  alerts: UiChatMessage[]
  onClear: () => void
  tr: (zh: string, en: string) => string
}) {
  const [collapsed, setCollapsed] = useState(false)
  const [minimized, setMinimized] = useState(false)
  const alertsEndRef = useRef<HTMLDivElement>(null)

  // Auto-scroll alert list when new alerts arrive (only when expanded)
  useEffect(() => {
    if (!collapsed && !minimized) {
      alertsEndRef.current?.scrollIntoView({ behavior: 'smooth' })
    }
  }, [alerts, collapsed, minimized])

  const unread = alerts.length
  const criticalCount = alerts.filter(a => a.level === 'critical').length
  const highCount = alerts.filter(a => a.level === 'high').length

  // Simple markdown-like rendering (same as AiChatBubble)
  const renderContent = (text: string) => {
    const parts = text.split(/(`[^`]+`|\*\*[^*]+\*\*)/g)
    return parts.map((part, i) => {
      if (part.startsWith('`') && part.endsWith('`')) {
        return <code key={i} className="ai-inline-code">{part.slice(1, -1)}</code>
      }
      if (part.startsWith('**') && part.endsWith('**')) {
        return <strong key={i}>{part.slice(2, -2)}</strong>
      }
      return <span key={i}>{part.split('\n').map((line, j, arr) => (
        <span key={j}>{line}{j < arr.length - 1 ? <br /> : null}</span>
      ))}</span>
    })
  }

  return (
    <div className={`ai-alert-panel ${minimized ? 'minimized' : ''} ${collapsed ? 'collapsed' : ''}`}>
      {/* Panel header — always visible */}
      <div className="ai-alert-panel-header">
        <div className="ai-alert-panel-title">
          <span className="ai-alert-panel-icon">🚨</span>
          {!collapsed && <span>{tr('实时告警', 'Live Alerts')}</span>}
          {!collapsed && criticalCount > 0 && (
            <span className="ai-alert-panel-badge critical">{criticalCount} {tr('严重', 'CRIT')}</span>
          )}
          {!collapsed && highCount > 0 && criticalCount === 0 && (
            <span className="ai-alert-panel-badge high">{highCount} {tr('高危', 'HIGH')}</span>
          )}
          {!collapsed && unread > 0 && criticalCount === 0 && highCount === 0 && (
            <span className="ai-alert-panel-badge high">{unread}</span>
          )}
          {collapsed && unread > 0 && (
            <span className={`ai-alert-panel-badge ${criticalCount > 0 ? 'critical' : 'high'}`}>
              {unread}
            </span>
          )}
        </div>
        <div className="ai-alert-panel-actions">
          {!collapsed && alerts.length > 0 && (
            <button className="ai-alert-panel-btn" onClick={onClear} title={tr('清空告警', 'Clear alerts')}>
              ✕
            </button>
          )}
          {!collapsed && (
            <button
              className="ai-alert-panel-btn"
              onClick={() => setMinimized(m => !m)}
              title={minimized ? tr('展开', 'Expand') : tr('最小化', 'Minimize')}
            >
              {minimized ? '▲' : '▼'}
            </button>
          )}
          <button
            className="ai-alert-panel-btn collapse-btn"
            onClick={() => setCollapsed(c => !c)}
            title={collapsed ? tr('展开面板', 'Expand panel') : tr('收起面板', 'Collapse panel')}
          >
            {collapsed ? '◀' : '▶'}
          </button>
        </div>
      </div>

      {/* Panel body — hidden when collapsed or minimized */}
      {!collapsed && !minimized && (
        <div className="ai-alert-panel-body">
          {alerts.length === 0 ? (
            <div className="ai-alert-panel-empty">
              {tr('暂无告警', 'No alerts yet')}
            </div>
          ) : (
            alerts.map(msg => (
              <div key={msg.id} className={`ai-alert-bubble ${msg.level === 'critical' ? 'critical' : 'high'}`}>
                <div className="ai-alert-header">
                  <span className="ai-alert-badge">{msg.level === 'critical' ? '🔴 CRITICAL' : '🟠 HIGH'}</span>
                  <span className="ai-alert-time">{new Date(msg.timestamp).toLocaleTimeString()}</span>
                </div>
                <div className="ai-alert-content">{renderContent(msg.content)}</div>
              </div>
            ))
          )}
          <div ref={alertsEndRef} />
        </div>
      )}
    </div>
  )
}

function AiTab({ lang, tr }: { lang: Lang; tr: (zh: string, en: string) => string }) {
  const [aiConfig, setAiConfig] = useState<AiConfig | null>(null)
  const [configLoading, setConfigLoading] = useState(true)
  // Chat messages (user + assistant only)
  const [messages, setMessages] = useState<UiChatMessage[]>([])
  // Alerts are kept separate so they never pollute the chat
  const [alerts, setAlerts] = useState<UiChatMessage[]>([])
  const [input, setInput] = useState('')
  const [sending, setSending] = useState(false)
  const [includeContext, setIncludeContext] = useState(true)
  const messagesEndRef = useRef<HTMLDivElement>(null)
  const inputRef = useRef<HTMLTextAreaElement>(null)
  const eventSourceRef = useRef<EventSource | null>(null)

  // Load AI config
  useEffect(() => {
    fetch('/api/v1/ai/config')
      .then(r => r.ok ? r.json() : null)
      .then((cfg: AiConfig | null) => { if (cfg) setAiConfig(cfg) })
      .catch(() => {})
      .finally(() => setConfigLoading(false))
  }, [])

  // Subscribe to AI alert event stream — alerts go into separate state
  useEffect(() => {
    const es = new EventSource('/api/v1/ai/events')
    eventSourceRef.current = es

    es.addEventListener('alert', (e: MessageEvent) => {
      try {
        const notification = JSON.parse(e.data) as AiAlertNotification
        const content = lang === 'zh'
          ? `🚨 **[${notification.level.toUpperCase()}]** ${notification.reason}\n进程: \`${notification.comm}\` (PID ${notification.pid}) · 类型: ${notification.event_kind} · 详情: ${notification.detail}`
          : `🚨 **[${notification.level.toUpperCase()}]** ${notification.reason}\nProcess: \`${notification.comm}\` (PID ${notification.pid}) · Kind: ${notification.event_kind} · Detail: ${notification.detail}`
        setAlerts(prev => [...prev, {
          id: aiMsgId(),
          role: 'alert',
          content,
          level: notification.level,
          timestamp: Date.now(),
        }])
      } catch { /* ignore parse errors */ }
    })

    es.onerror = () => {
      // EventSource auto-reconnects; no action needed
    }

    return () => { es.close(); eventSourceRef.current = null }
  }, [lang])

  // Auto-scroll chat to bottom when new messages arrive
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [messages])


  const sendMessage = async () => {
    const text = input.trim()
    if (!text || sending) return

    const userMsg: UiChatMessage = {
      id: aiMsgId(),
      role: 'user',
      content: text,
      timestamp: Date.now(),
    }
    setMessages(prev => [...prev, userMsg])
    setInput('')
    setSending(true)

    // Build conversation history
    const history: ChatMessage[] = messages
      .filter(m => m.role === 'user' || m.role === 'assistant')
      .map(m => ({ role: m.role as ChatRole, content: m.content }))
    history.push({ role: 'user', content: text })

    // Add a placeholder streaming message
    const assistantId = aiMsgId()
    setMessages(prev => [...prev, {
      id: assistantId,
      role: 'assistant',
      content: '',
      streaming: true,
      timestamp: Date.now(),
    }])

    try {
      const resp = await fetch('/api/v1/ai/chat', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ messages: history, include_context: includeContext }),
      })

      if (!resp.ok) {
        const errText = await resp.text()
        setMessages(prev => prev.map(m =>
          m.id === assistantId
            ? { ...m, content: `❌ ${errText}`, streaming: false }
            : m
        ))
        setSending(false)
        return
      }

      // Read SSE stream
      const reader = resp.body!.getReader()
      const decoder = new TextDecoder()
      let buffer = ''
      let accumulated = ''

      while (true) {
        const { done, value } = await reader.read()
        if (done) break

        buffer += decoder.decode(value, { stream: true })
        const lines = buffer.split('\n')
        buffer = lines.pop() ?? ''

        for (const line of lines) {
          const trimmed = line.trim()
          if (!trimmed || !trimmed.startsWith('data:')) continue
          const jsonStr = trimmed.slice(5).trim()
          try {
            const payload = JSON.parse(jsonStr) as { delta: string; done: boolean; error?: string }
            if (payload.error) {
              accumulated += `\n❌ ${payload.error}`
            } else {
              accumulated += payload.delta
            }
            setMessages(prev => prev.map(m =>
              m.id === assistantId
                ? { ...m, content: accumulated, streaming: !payload.done }
                : m
            ))
            if (payload.done) break
          } catch { /* skip malformed */ }
        }
      }
    } catch (err) {
      setMessages(prev => prev.map(m =>
        m.id === assistantId
          ? { ...m, content: `❌ ${tr('网络错误', 'Network error')}: ${err}`, streaming: false }
          : m
      ))
    }

    setSending(false)
    inputRef.current?.focus()
  }

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (e.key === 'Enter' && !e.shiftKey) {
      e.preventDefault()
      sendMessage()
    }
  }

  const clearHistory = () => {
    setMessages([])
  }

  if (configLoading) {
    return <div className="tab-content"><div className="empty-state">{tr('加载中...', 'Loading...')}</div></div>
  }

  const isEnabled = aiConfig?.enabled ?? false

  return (
    <div className="tab-content ai-tab">
      {/* Status bar */}
      <div className="ai-status-bar">
        <div className="ai-status-left">
          <span className={`ai-status-dot ${isEnabled ? 'enabled' : 'disabled'}`} />
          <span className="ai-status-label">
            {isEnabled
              ? tr(`AI 分析已启用 · ${aiConfig?.model ?? ''}`, `AI Analysis Enabled · ${aiConfig?.model ?? ''}`)
              : tr('AI 分析未启用 — 请在「系统配置」中开启', 'AI Analysis disabled — enable it in Config')}
          </span>
        </div>
        <div className="ai-status-right">
          <label className="ai-ctx-toggle">
            <input
              type="checkbox"
              checked={includeContext}
              onChange={e => setIncludeContext(e.target.checked)}
            />
            <span>{tr('携带系统上下文', 'Include system context')}</span>
          </label>
          {messages.length > 0 && (
            <button className="btn-ghost-sm" onClick={clearHistory}>
              {tr('清空对话', 'Clear')}
            </button>
          )}
        </div>
      </div>

      {/* Main area: chat + alert panel side by side */}
      <div className="ai-main-area">
        {/* Chat messages — pure conversation, no alerts */}
        <div className="ai-chat-body">
          {messages.length === 0 && (
            <div className="ai-welcome">
              <div className="ai-welcome-icon">🤖</div>
              <h3>{tr('GAIA AI 安全分析助手', 'GAIA AI Security Analyst')}</h3>
              <p>{tr(
                '你好！我是 GAIA 的 AI 安全分析助手。我可以帮你分析安全事件、解读告警、排查异常行为，并提供修复建议。',
                'Hello! I\'m GAIA\'s AI security analyst. I can help you analyze security events, interpret alerts, investigate anomalies, and suggest remediation steps.'
              )}</p>
              <div className="ai-suggestions">
                {[
                  [tr('分析最近的告警', 'Analyze recent alerts'), tr('分析最近的告警', 'Analyze recent alerts')],
                  [tr('有哪些高危进程？', 'Any high-risk processes?'), tr('有哪些高危进程？', 'Any high-risk processes?')],
                  [tr('解释热补丁触发事件', 'Explain hotpatch trigger events'), tr('解释热补丁触发事件', 'Explain hotpatch trigger events')],
                  [tr('当前系统安全状态如何？', 'What is the current security posture?'), tr('当前系统安全状态如何？', 'What is the current security posture?')],
                ].map(([label, prompt], i) => (
                  <button
                    key={i}
                    className="ai-suggestion-chip"
                    onClick={() => { setInput(prompt); inputRef.current?.focus() }}
                    disabled={!isEnabled}
                  >
                    {label}
                  </button>
                ))}
              </div>
            </div>
          )}

          {messages.map(msg => (
            <AiChatBubble key={msg.id} msg={msg} tr={tr} />
          ))}
          <div ref={messagesEndRef} />
        </div>

        {/* Collapsible alert panel — floats on the right */}
        <AiAlertPanel alerts={alerts} onClear={() => setAlerts([])} tr={tr} />
      </div>

      {/* Input area */}
      <div className="ai-input-area">
        <textarea
          ref={inputRef}
          className="ai-input"
          placeholder={isEnabled
            ? tr('输入问题，按 Enter 发送，Shift+Enter 换行...', 'Ask a question, Enter to send, Shift+Enter for newline...')
            : tr('请先在「系统配置」中启用 AI 分析功能', 'Enable AI Analysis in Config first')}
          value={input}
          onChange={e => setInput(e.target.value)}
          onKeyDown={handleKeyDown}
          disabled={!isEnabled || sending}
          rows={3}
        />
        <button
          className={`ai-send-btn ${sending ? 'loading' : ''}`}
          onClick={sendMessage}
          disabled={!isEnabled || sending || !input.trim()}
        >
          {sending ? '⏳' : '➤'}
        </button>
      </div>
    </div>
  )
}

function AiChatBubble({ msg }: { msg: UiChatMessage; tr?: (zh: string, en: string) => string }) {
  const isUser = msg.role === 'user'
  const isAlert = msg.role === 'alert'
  const isAssistant = msg.role === 'assistant'

  // Simple markdown-like rendering: bold, code, newlines
  const renderContent = (text: string) => {
    const parts = text.split(/(`[^`]+`|\*\*[^*]+\*\*)/g)
    return parts.map((part, i) => {
      if (part.startsWith('`') && part.endsWith('`')) {
        return <code key={i} className="ai-inline-code">{part.slice(1, -1)}</code>
      }
      if (part.startsWith('**') && part.endsWith('**')) {
        return <strong key={i}>{part.slice(2, -2)}</strong>
      }
      return <span key={i}>{part.split('\n').map((line, j, arr) => (
        <span key={j}>{line}{j < arr.length - 1 ? <br /> : null}</span>
      ))}</span>
    })
  }

  if (isAlert) {
    return (
      <div className={`ai-alert-bubble ${msg.level === 'critical' ? 'critical' : 'high'}`}>
        <div className="ai-alert-header">
          <span className="ai-alert-badge">{msg.level === 'critical' ? '🔴 CRITICAL' : '🟠 HIGH'}</span>
          <span className="ai-alert-time">{new Date(msg.timestamp).toLocaleTimeString()}</span>
        </div>
        <div className="ai-alert-content">{renderContent(msg.content)}</div>
      </div>
    )
  }

  return (
    <div className={`ai-bubble-row ${isUser ? 'user' : 'assistant'}`}>
      <div className={`ai-bubble ${isUser ? 'user' : 'assistant'} ${msg.streaming ? 'streaming' : ''}`}>
        {isAssistant && (
          <div className="ai-bubble-header">
            <span className="ai-bubble-role">🤖 GAIA AI</span>
            {msg.streaming && <span className="ai-typing-indicator"><span /><span /><span /></span>}
          </div>
        )}
        <div className="ai-bubble-content">
          {msg.content ? renderContent(msg.content) : (
            msg.streaming ? <span className="ai-typing-indicator"><span /><span /><span /></span> : null
          )}
        </div>
        <div className="ai-bubble-time">{new Date(msg.timestamp).toLocaleTimeString()}</div>
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
      <AiConfigPanel tr={tr} flash={flash} />
    </div>
  )
}

export default App
