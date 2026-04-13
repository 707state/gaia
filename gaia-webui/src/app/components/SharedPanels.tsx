import { useCallback, useEffect, useState } from 'react'
import type {
  AlertRecord,
  EventPage,
  EventRecord,
  FileEventDetail,
  Lang,
  ProcessDetail,
  StoredEvent,
  ToggleItem,
  TranslateFn,
} from '../types'
import { formatTimestamp, mapAction, mapKind, relativeTime } from '../utils'

// ── shared format helpers (used by multiple modals) ──

function fmtBytes(b: number) {
  if (b < 1024) return `${b} B`
  if (b < 1048576) return `${(b / 1024).toFixed(1)} KB`
  if (b < 1073741824) return `${(b / 1048576).toFixed(1)} MB`
  return `${(b / 1073741824).toFixed(2)} GB`
}

function fmtUnixSecs(secs: number) {
  if (!secs) return '-'
  return new Date(secs * 1000).toLocaleString()
}

function fmtUptime(secs: number) {
  const d = Math.floor(secs / 86400), h = Math.floor((secs % 86400) / 3600)
  const m = Math.floor((secs % 3600) / 60), s = Math.floor(secs % 60)
  return [d && `${d}d`, h && `${h}h`, m && `${m}m`, `${s}s`].filter(Boolean).join(' ')
}

// ── Shared helpers ──

function LangAwareKind({ kind, lang }: { kind: string; lang: Lang }) {
  return <span className={`kind-tag kind-${kind}`}>{mapKind(kind, lang)}</span>
}

function LangAwareAction({ action, lang }: { action: string; lang: Lang }) {
  return <span className={`action-tag action-${action}`}>{mapAction(action, lang)}</span>
}

export function EventTable({ events, lang, tr, onRowClick }: {
  events: EventRecord[]
  lang: Lang
  tr: TranslateFn
  onRowClick?: (e: EventRecord) => void
}) {
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
            <tr
              key={`${e.timestamp_ns}-${i}`}
              className={`${e.action === 'blocked' ? 'row-blocked' : e.action === 'alert' ? 'row-alert' : e.action === 'rate_limited' ? 'row-rate-limited' : ''} ${onRowClick ? 'row-clickable' : ''}`}
              onClick={() => onRowClick?.(e)}
              title={onRowClick ? tr('点击查看进程详情', 'Click to view process details') : undefined}
            >
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

export function AlertList({ alerts, lang, onAlertClick }: {
  alerts: AlertRecord[]
  lang: Lang
  onAlertClick?: (alert: AlertRecord) => void
}) {
  return (
    <div className="alert-list">
      {alerts.map((a, i) => (
        <div
          key={`${a.reason}-${i}`}
          className={`alert-item level-${a.level}${onAlertClick ? ' alert-item-clickable' : ''}`}
          onClick={() => onAlertClick?.(a)}
          title={onAlertClick ? (lang === 'zh' ? '点击查看详情' : 'Click to inspect') : undefined}
        >
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

export function ToggleListPanel({ title, desc, items, section, toggle, renderValue, addPlaceholder, onAdd, onDelete, tr }: {
  title: string
  desc: string
  items: ToggleItem[]
  section: string
  toggle: (section: string, index: number, enabled: boolean) => void
  renderValue: (item: ToggleItem) => string
  addPlaceholder: string
  onAdd: (value: string) => void
  onDelete: (index: number) => void
  tr: TranslateFn
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

export function ProcessDetailModal({ detail, loading, tr, onClose }: {
  detail: ProcessDetail | null
  loading: boolean
  tr: TranslateFn
  onClose: () => void
}) {
  if (!loading && !detail) return null

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
                  <div className="detail-item"><span className="detail-label">{tr('运行时间', 'Uptime')}</span><span className="detail-value">{fmtUptime(detail.uptime_secs)}</span></div>
                  <div className="detail-item"><span className="detail-label">OOM Score</span><span className="detail-value">{detail.oom_score}</span></div>
                </div>
              </section>

              <section className="detail-section">
                <h4>{tr('路径信息', 'Paths')}</h4>
                <div className="detail-paths">
                  <div className="path-row"><span className="detail-label">{tr('可执行文件', 'Executable')}</span><code>{detail.exe}</code></div>
                  <div className="path-row"><span className="detail-label">{tr('工作目录', 'CWD')}</span><code>{detail.cwd}</code></div>
                  <div className="path-row"><span className="detail-label">{tr('命令行', 'Cmdline')}</span><code className="cmdline">{detail.cmdline}</code></div>
                </div>
              </section>

              <section className="detail-section">
                <h4>{tr('内存使用', 'Memory')}</h4>
                <div className="detail-grid">
                  <div className="detail-item"><span className="detail-label">VmPeak</span><span className="detail-value">{fmtBytes(detail.mem.vm_peak_kb * 1024)}</span></div>
                  <div className="detail-item"><span className="detail-label">VmSize</span><span className="detail-value">{fmtBytes(detail.mem.vm_size_kb * 1024)}</span></div>
                  <div className="detail-item"><span className="detail-label">VmRSS</span><span className="detail-value">{fmtBytes(detail.mem.vm_rss_kb * 1024)}</span></div>
                  <div className="detail-item"><span className="detail-label">VmData</span><span className="detail-value">{fmtBytes(detail.mem.vm_data_kb * 1024)}</span></div>
                  <div className="detail-item"><span className="detail-label">VmStk</span><span className="detail-value">{fmtBytes(detail.mem.vm_stk_kb * 1024)}</span></div>
                  <div className="detail-item"><span className="detail-label">VmExe</span><span className="detail-value">{fmtBytes(detail.mem.vm_exe_kb * 1024)}</span></div>
                  <div className="detail-item"><span className="detail-label">VmLib</span><span className="detail-value">{fmtBytes(detail.mem.vm_lib_kb * 1024)}</span></div>
                  <div className="detail-item"><span className="detail-label">VmSwap</span><span className="detail-value">{fmtBytes(detail.mem.vm_swap_kb * 1024)}</span></div>
                </div>
              </section>

              <section className="detail-section">
                <h4>{tr('I/O 统计', 'I/O Stats')}</h4>
                <div className="detail-grid">
                  <div className="detail-item"><span className="detail-label">{tr('逻辑读', 'Logical Read')}</span><span className="detail-value">{fmtBytes(detail.io.rchar)}</span></div>
                  <div className="detail-item"><span className="detail-label">{tr('逻辑写', 'Logical Write')}</span><span className="detail-value">{fmtBytes(detail.io.wchar)}</span></div>
                  <div className="detail-item"><span className="detail-label">{tr('磁盘读', 'Disk Read')}</span><span className="detail-value">{fmtBytes(detail.io.read_bytes)}</span></div>
                  <div className="detail-item"><span className="detail-label">{tr('磁盘写', 'Disk Write')}</span><span className="detail-value">{fmtBytes(detail.io.write_bytes)}</span></div>
                  <div className="detail-item"><span className="detail-label">{tr('读系统调用', 'Read Syscalls')}</span><span className="detail-value">{detail.io.syscr.toLocaleString()}</span></div>
                  <div className="detail-item"><span className="detail-label">{tr('写系统调用', 'Write Syscalls')}</span><span className="detail-value">{detail.io.syscw.toLocaleString()}</span></div>
                </div>
              </section>

              <section className="detail-section">
                <h4>{tr('安全与调度', 'Security & Scheduling')}</h4>
                <div className="detail-grid">
                  <div className="detail-item"><span className="detail-label">CapEff</span><span className="detail-value" style={{ fontSize: 11, wordBreak: 'break-all' }}>{detail.cap_eff}</span></div>
                  <div className="detail-item"><span className="detail-label">Seccomp</span><span className="detail-value">{detail.seccomp}</span></div>
                  <div className="detail-item"><span className="detail-label">{tr('允许 CPU', 'CPUs Allowed')}</span><span className="detail-value">{detail.cpus_allowed_list}</span></div>
                  <div className="detail-item"><span className="detail-label">{tr('主动上下文切换', 'Vol. Ctx Switches')}</span><span className="detail-value">{detail.voluntary_ctxt_switches.toLocaleString()}</span></div>
                  <div className="detail-item"><span className="detail-label">{tr('被动上下文切换', 'Invol. Ctx Switches')}</span><span className="detail-value">{detail.nonvoluntary_ctxt_switches.toLocaleString()}</span></div>
                </div>
              </section>

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

export function FileEventDetailModal({ event, alertRecord, detail, loading, lang, tr, onClose }: {
  event: EventRecord | null
  alertRecord?: AlertRecord | null
  detail: FileEventDetail | null
  loading: boolean
  lang: Lang
  tr: TranslateFn
  onClose: () => void
}) {
  if (!event && !loading) return null

  const filePath = event?.detail || ''

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-panel" onClick={e => e.stopPropagation()}>
        <div className="modal-header">
          <h3>
            {alertRecord
              ? tr('文件告警详情', 'File Alert Detail')
              : tr('文件访问事件详情', 'File Access Event Detail')}
            {filePath ? ` — ${filePath}` : ''}
          </h3>
          <button className="modal-close" onClick={onClose}>✕</button>
        </div>
        <div className="modal-body">
          {loading && <div className="modal-loading">{tr('加载中...', 'Loading...')}</div>}

          {/* Alert context — shown only when opened from an alert */}
          {alertRecord && (
            <section className="detail-section">
              <h4>{tr('告警信息', 'Alert Info')}</h4>
              <div className="detail-grid">
                <div className="detail-item">
                  <span className="detail-label">{tr('级别', 'Level')}</span>
                  <span className="detail-value">
                    <span className={`level-badge level-${alertRecord.level}`}>{alertRecord.level.toUpperCase()}</span>
                  </span>
                </div>
                <div className="detail-item" style={{ gridColumn: '1 / -1' }}>
                  <span className="detail-label">{tr('告警原因', 'Reason')}</span>
                  <span className="detail-value" style={{ lineHeight: 1.5 }}>{alertRecord.reason}</span>
                </div>
              </div>
            </section>
          )}

          {/* Event properties */}
          {event && (
            <section className="detail-section">
              <h4>{tr('事件属性', 'Event Properties')}</h4>
              <div className="detail-grid">
                <div className="detail-item"><span className="detail-label">{tr('时间', 'Time')}</span><span className="detail-value">{formatTimestamp(event.timestamp_ns)}</span></div>
                <div className="detail-item"><span className="detail-label">{tr('类型', 'Kind')}</span><span className="detail-value"><LangAwareKind kind={event.kind} lang={lang} /></span></div>
                <div className="detail-item"><span className="detail-label">{tr('动作', 'Action')}</span><span className="detail-value"><LangAwareAction action={event.action} lang={lang} /></span></div>
                <div className="detail-item"><span className="detail-label">PID</span><span className="detail-value">{event.pid}</span></div>
                <div className="detail-item"><span className="detail-label">TGID</span><span className="detail-value">{event.tgid}</span></div>
                <div className="detail-item"><span className="detail-label">UID</span><span className="detail-value">{event.uid}</span></div>
                <div className="detail-item"><span className="detail-label">GID</span><span className="detail-value">{event.gid}</span></div>
                <div className="detail-item"><span className="detail-label">{tr('进程名', 'Process')}</span><span className="detail-value"><code>{event.comm || '-'}</code></span></div>
                {event.service && <div className="detail-item"><span className="detail-label">{tr('服务', 'Service')}</span><span className="detail-value"><span className="service-badge">{event.service}</span></span></div>}
                <div className="detail-item" style={{ gridColumn: '1 / -1' }}>
                  <span className="detail-label">{tr('文件路径', 'File Path')}</span>
                  <span className="detail-value"><code style={{ wordBreak: 'break-all' }}>{filePath || '-'}</code></span>
                </div>
              </div>
            </section>
          )}

          {!loading && detail && (
            <>
              <section className="detail-section">
                <h4>{tr('事件说明', 'Event Explanation')}</h4>
                <div className="detail-paths">
                  <div className="path-row">
                    <span className="detail-label">{tr('摘要', 'Summary')}</span>
                    <span style={{ lineHeight: 1.5 }}>{detail.summary}</span>
                  </div>
                  <div className="path-row" style={{ marginTop: 8 }}>
                    <span className="detail-label">{tr('行为说明', 'What it does')}</span>
                    <span style={{ lineHeight: 1.5 }}>{detail.action_meaning}</span>
                  </div>
                </div>
                <div className="detail-grid" style={{ marginTop: 12 }}>
                  <div className="detail-item">
                    <span className="detail-label">{tr('敏感路径', 'Sensitive Path')}</span>
                    <span className="detail-value">
                      {detail.is_sensitive
                        ? <span className="level-badge level-high">{tr('是', 'YES')}</span>
                        : <span style={{ color: 'var(--text-muted)' }}>{tr('否', 'NO')}</span>}
                    </span>
                  </div>
                  <div className="detail-item">
                    <span className="detail-label">{tr('当前已打开', 'Currently Open')}</span>
                    <span className="detail-value">
                      {detail.currently_open_by_pid
                        ? <span className="level-badge level-medium">{tr('是', 'YES')}</span>
                        : <span style={{ color: 'var(--text-muted)' }}>{tr('否', 'NO')}</span>}
                    </span>
                  </div>
                </div>
              </section>

              {detail.file_meta && (
                <section className="detail-section">
                  <h4>{tr('文件元信息', 'File Metadata')}</h4>
                  <div className="detail-grid">
                    <div className="detail-item"><span className="detail-label">{tr('类型', 'Type')}</span><span className="detail-value">{detail.file_meta.file_type}</span></div>
                    <div className="detail-item"><span className="detail-label">{tr('大小', 'Size')}</span><span className="detail-value">{fmtBytes(detail.file_meta.size_bytes)}</span></div>
                    <div className="detail-item"><span className="detail-label">{tr('权限', 'Permissions')}</span><span className="detail-value"><code>{detail.file_meta.permissions}</code></span></div>
                    <div className="detail-item"><span className="detail-label">{tr('所有者 UID', 'Owner UID')}</span><span className="detail-value">{detail.file_meta.owner_uid}</span></div>
                    <div className="detail-item"><span className="detail-label">{tr('所有者 GID', 'Owner GID')}</span><span className="detail-value">{detail.file_meta.owner_gid}</span></div>
                    <div className="detail-item"><span className="detail-label">Inode</span><span className="detail-value">{detail.file_meta.inode}</span></div>
                    <div className="detail-item"><span className="detail-label">{tr('硬链接数', 'Hard Links')}</span><span className="detail-value">{detail.file_meta.hard_links}</span></div>
                    <div className="detail-item"><span className="detail-label">{tr('修改时间', 'Modified')}</span><span className="detail-value">{fmtUnixSecs(detail.file_meta.modified_secs)}</span></div>
                    <div className="detail-item"><span className="detail-label">{tr('访问时间', 'Accessed')}</span><span className="detail-value">{fmtUnixSecs(detail.file_meta.accessed_secs)}</span></div>
                    <div className="detail-item"><span className="detail-label">{tr('状态变更时间', 'Changed')}</span><span className="detail-value">{fmtUnixSecs(detail.file_meta.created_secs)}</span></div>
                  </div>
                </section>
              )}

              {!detail.file_meta && (
                <section className="detail-section">
                  <h4>{tr('文件元信息', 'File Metadata')}</h4>
                  <div className="empty-state">{tr('文件不存在或无法访问', 'File does not exist or is not accessible')}</div>
                </section>
              )}
            </>
          )}
        </div>
      </div>
    </div>
  )
}

// ── Unified Event Detail Modal ──
// Handles file_io, process/privilege, and network events in one place.

export function EventDetailModal({ event, lang, tr, onClose }: {
  event: EventRecord | null
  lang: Lang
  tr: TranslateFn
  onClose: () => void
}) {
  const [procDetail, setProcDetail] = useState<ProcessDetail | null>(null)
  const [procLoading, setProcLoading] = useState(false)
  const [fileDetail, setFileDetail] = useState<FileEventDetail | null>(null)
  const [fileLoading, setFileLoading] = useState(false)

  // Fetch extra data whenever the event changes
  useEffect(() => {
    setProcDetail(null)
    setFileDetail(null)
    if (!event) return

    if (event.kind === 'process' || event.kind === 'privilege') {
      setProcLoading(true)
      fetch(`/api/v1/process/${event.pid}`)
        .then(r => r.ok ? r.json() : null)
        .then((d: ProcessDetail | null) => { setProcDetail(d); setProcLoading(false) })
        .catch(() => setProcLoading(false))
    }

    if (event.kind === 'file_io' && (event.action === 'enter' || event.action === 'alert') && event.detail) {
      setFileLoading(true)
      const p = new URLSearchParams({ path: event.detail })
      if (event.pid) p.set('pid', String(event.pid))
      fetch(`/api/v1/file-event/detail?${p}`)
        .then(r => r.ok ? r.json() : null)
        .then((d: FileEventDetail | null) => { setFileDetail(d); setFileLoading(false) })
        .catch(() => setFileLoading(false))
    }
  }, [event])

  if (!event) return null

  const title = event.kind === 'file_io'
    ? tr('文件事件详情', 'File Event Detail')
    : event.kind === 'network'
      ? tr('网络事件详情', 'Network Event Detail')
      : tr('进程事件详情', 'Process Event Detail')

  return (
    <div className="modal-overlay" onClick={onClose}>
      <div className="modal-panel" onClick={e => e.stopPropagation()}>
        <div className="modal-header">
          <h3>{title} — <code style={{ fontSize: 13 }}>{event.comm}</code> PID {event.pid}</h3>
          <button className="modal-close" onClick={onClose}>✕</button>
        </div>
        <div className="modal-body">

          {/* ── Common event properties ── */}
          <section className="detail-section">
            <h4>{tr('事件属性', 'Event Properties')}</h4>
            <div className="detail-grid">
              <div className="detail-item"><span className="detail-label">{tr('时间', 'Time')}</span><span className="detail-value">{formatTimestamp(event.timestamp_ns)}</span></div>
              <div className="detail-item"><span className="detail-label">{tr('类型', 'Kind')}</span><span className="detail-value"><LangAwareKind kind={event.kind} lang={lang} /></span></div>
              <div className="detail-item"><span className="detail-label">{tr('动作', 'Action')}</span><span className="detail-value"><LangAwareAction action={event.action} lang={lang} /></span></div>
              <div className="detail-item"><span className="detail-label">PID</span><span className="detail-value">{event.pid}</span></div>
              <div className="detail-item"><span className="detail-label">TGID</span><span className="detail-value">{event.tgid}</span></div>
              <div className="detail-item"><span className="detail-label">UID</span><span className="detail-value">{event.uid}</span></div>
              <div className="detail-item"><span className="detail-label">GID</span><span className="detail-value">{event.gid}</span></div>
              <div className="detail-item"><span className="detail-label">{tr('进程名', 'Process')}</span><span className="detail-value"><code>{event.comm || '-'}</code></span></div>
              {event.service && <div className="detail-item"><span className="detail-label">{tr('服务', 'Service')}</span><span className="detail-value"><span className="service-badge">{event.service}</span></span></div>}
              {event.detail && (
                <div className="detail-item" style={{ gridColumn: '1 / -1' }}>
                  <span className="detail-label">{tr('详情', 'Detail')}</span>
                  <span className="detail-value"><code style={{ wordBreak: 'break-all' }}>{event.detail}</code></span>
                </div>
              )}
            </div>
          </section>

          {/* ── Network-specific ── */}
          {event.kind === 'network' && event.network && (
            <section className="detail-section">
              <h4>{tr('网络信息', 'Network Info')}</h4>
              <div className="detail-grid">
                <div className="detail-item"><span className="detail-label">{tr('目标地址', 'Address')}</span><span className="detail-value"><code>{event.network.address}</code></span></div>
                <div className="detail-item"><span className="detail-label">{tr('端口', 'Port')}</span><span className="detail-value"><code>{event.network.port}</code></span></div>
                <div className="detail-item">
                  <span className="detail-label">{tr('状态', 'Status')}</span>
                  <span className="detail-value">
                    {event.action === 'blocked'
                      ? <span className="level-badge level-critical">{tr('已阻断', 'BLOCKED')}</span>
                      : event.action === 'rate_limited'
                        ? <span className="level-badge level-high">{tr('已限流', 'RATE LIMITED')}</span>
                        : <span style={{ color: 'var(--text-muted)' }}>{tr('已放行', 'allowed')}</span>}
                  </span>
                </div>
              </div>
            </section>
          )}

          {/* ── File-specific ── */}
          {event.kind === 'file_io' && (
            <section className="detail-section">
              <h4>{tr('文件信息', 'File Info')}</h4>
              {fileLoading && <div className="modal-loading">{tr('加载中...', 'Loading...')}</div>}
              {fileDetail && (
                <>
                  <div className="detail-paths" style={{ marginBottom: 12 }}>
                    <div className="path-row">
                      <span className="detail-label">{tr('说明', 'Explanation')}</span>
                      <span style={{ lineHeight: 1.5 }}>{fileDetail.action_meaning}</span>
                    </div>
                  </div>
                  <div className="detail-grid">
                    <div className="detail-item">
                      <span className="detail-label">{tr('敏感路径', 'Sensitive')}</span>
                      <span className="detail-value">
                        {fileDetail.is_sensitive
                          ? <span className="level-badge level-high">{tr('是', 'YES')}</span>
                          : <span style={{ color: 'var(--text-muted)' }}>{tr('否', 'NO')}</span>}
                      </span>
                    </div>
                    <div className="detail-item">
                      <span className="detail-label">{tr('当前已打开', 'Open Now')}</span>
                      <span className="detail-value">
                        {fileDetail.currently_open_by_pid
                          ? <span className="level-badge level-medium">{tr('是', 'YES')}</span>
                          : <span style={{ color: 'var(--text-muted)' }}>{tr('否', 'NO')}</span>}
                      </span>
                    </div>
                    {fileDetail.file_meta && <>
                      <div className="detail-item"><span className="detail-label">{tr('类型', 'Type')}</span><span className="detail-value">{fileDetail.file_meta.file_type}</span></div>
                      <div className="detail-item"><span className="detail-label">{tr('大小', 'Size')}</span><span className="detail-value">{fmtBytes(fileDetail.file_meta.size_bytes)}</span></div>
                      <div className="detail-item"><span className="detail-label">{tr('权限', 'Perms')}</span><span className="detail-value"><code>{fileDetail.file_meta.permissions}</code></span></div>
                      <div className="detail-item"><span className="detail-label">{tr('所有者', 'Owner')}</span><span className="detail-value">uid:{fileDetail.file_meta.owner_uid} gid:{fileDetail.file_meta.owner_gid}</span></div>
                      <div className="detail-item"><span className="detail-label">Inode</span><span className="detail-value">{fileDetail.file_meta.inode}</span></div>
                      <div className="detail-item"><span className="detail-label">{tr('修改时间', 'Modified')}</span><span className="detail-value">{fmtUnixSecs(fileDetail.file_meta.modified_secs)}</span></div>
                    </>}
                    {!fileDetail.file_meta && !fileLoading && (
                      <div className="detail-item" style={{ gridColumn: '1 / -1' }}>
                        <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>{tr('文件不存在或无法访问', 'File not found or inaccessible')}</span>
                      </div>
                    )}
                  </div>
                </>
              )}
            </section>
          )}

          {/* ── Process-specific ── */}
          {(event.kind === 'process' || event.kind === 'privilege') && (
            <section className="detail-section">
              <h4>{tr('进程详情', 'Process Details')}</h4>
              {procLoading && <div className="modal-loading">{tr('加载中...', 'Loading...')}</div>}
              {!procLoading && !procDetail && (
                <div className="empty-state" style={{ fontSize: 12 }}>{tr('进程已退出或无法访问', 'Process exited or inaccessible')}</div>
              )}
              {procDetail && (
                <div className="detail-grid">
                  <div className="detail-item"><span className="detail-label">{tr('进程名', 'Name')}</span><span className="detail-value">{procDetail.name}</span></div>
                  <div className="detail-item"><span className="detail-label">{tr('状态', 'State')}</span><span className="detail-value"><span className={`state-badge state-${procDetail.state.charAt(0).toLowerCase()}`}>{procDetail.state}</span></span></div>
                  <div className="detail-item"><span className="detail-label">PPID</span><span className="detail-value">{procDetail.ppid}</span></div>
                  <div className="detail-item"><span className="detail-label">UID/EUID</span><span className="detail-value">{procDetail.uid}/{procDetail.euid}</span></div>
                  <div className="detail-item"><span className="detail-label">{tr('线程', 'Threads')}</span><span className="detail-value">{procDetail.threads}</span></div>
                  <div className="detail-item"><span className="detail-label">{tr('运行时间', 'Uptime')}</span><span className="detail-value">{fmtUptime(procDetail.uptime_secs)}</span></div>
                  <div className="detail-item"><span className="detail-label">VmRSS</span><span className="detail-value">{fmtBytes(procDetail.mem.vm_rss_kb * 1024)}</span></div>
                  <div className="detail-item"><span className="detail-label">VmSize</span><span className="detail-value">{fmtBytes(procDetail.mem.vm_size_kb * 1024)}</span></div>
                  <div className="detail-item" style={{ gridColumn: '1 / -1' }}>
                    <span className="detail-label">{tr('命令行', 'Cmdline')}</span>
                    <span className="detail-value"><code className="cmdline">{procDetail.cmdline || procDetail.exe}</code></span>
                  </div>
                </div>
              )}
            </section>
          )}

        </div>
      </div>
    </div>
  )
}

// ── History Panel ──

export function HistoryPanel({ kinds, lang, tr, onPidClick, onEventClick }: {
  kinds: string[]
  lang: Lang
  tr: TranslateFn
  onPidClick?: (pid: number) => void
  onEventClick?: (e: StoredEvent) => void
}) {
  const [page, setPage] = useState(0)
  const [pageSize] = useState(50)
  const [kindFilter, setKindFilter] = useState<string>(kinds.length === 1 ? kinds[0] : '')
  const [sinceInput, setSinceInput] = useState('')
  const [untilInput, setUntilInput] = useState('')
  const [data, setData] = useState<EventPage | null>(null)
  const [loading, setLoading] = useState(false)
  const [collapsed, setCollapsed] = useState(false)

  const doFetch = useCallback(async (p: number) => {
    setLoading(true)
    try {
      const params = new URLSearchParams({ page: String(p), page_size: String(pageSize) })
      if (kindFilter) params.set('kind', kindFilter)
      if (sinceInput) params.set('since_ms', String(new Date(sinceInput).getTime()))
      if (untilInput) params.set('until_ms', String(new Date(untilInput).getTime()))
      const r = await fetch(`/api/v1/history/events?${params}`)
      if (r.ok) setData(await r.json() as EventPage)
    } catch { /* offline */ }
    setLoading(false)
  }, [kindFilter, sinceInput, untilInput, pageSize])

  useEffect(() => {
    if (!collapsed) doFetch(page)
  }, [page, collapsed, doFetch])

  const totalPages = data ? Math.ceil(Number(data.total) / pageSize) : 0
  const from = data ? page * pageSize + 1 : 0
  const to   = data ? Math.min((page + 1) * pageSize, Number(data.total)) : 0

  return (
    <div className="card">
      <div className="card-header">
        <h3>{tr('历史事件', 'Event History')}</h3>
        <div style={{ display: 'flex', gap: 8, alignItems: 'center' }}>
          {data && <span className="card-badge">{Number(data.total).toLocaleString()} {tr('条', 'total')}</span>}
          <button className="btn-collapse" onClick={() => setCollapsed(c => !c)}>
            {collapsed ? '▶' : '▼'}
          </button>
        </div>
      </div>

      {!collapsed && (
        <>
          <div className="history-filter-bar">
            {kinds.length > 1 && (
              <select value={kindFilter} onChange={e => setKindFilter(e.target.value)}>
                <option value="">{tr('全部类型', 'All kinds')}</option>
                {kinds.map(k => <option key={k} value={k}>{mapKind(k, lang)}</option>)}
              </select>
            )}
            <input type="datetime-local" value={sinceInput} onChange={e => setSinceInput(e.target.value)} title={tr('开始时间', 'Since')} />
            <span style={{ color: 'var(--text-muted)', fontSize: 12 }}>→</span>
            <input type="datetime-local" value={untilInput} onChange={e => setUntilInput(e.target.value)} title={tr('结束时间', 'Until')} />
            <button className="btn-primary" onClick={() => { setPage(0); doFetch(0) }} disabled={loading}>
              {loading ? tr('查询中…', 'Loading…') : tr('查询', 'Search')}
            </button>
          </div>

          {data && data.events.length > 0 ? (
            <div className="table-wrap" style={{ maxHeight: 400, overflowY: 'auto' }}>
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
                  </tr>
                </thead>
                <tbody>
                  {data.events.map((e: StoredEvent) => (
                    <tr
                      key={e.id}
                      className={`${e.action === 'blocked' ? 'row-blocked' : e.action === 'alert' ? 'row-alert' : e.action === 'rate_limited' ? 'row-rate-limited' : ''} ${(onEventClick || onPidClick) ? 'row-clickable' : ''}`}
                      onClick={() => onEventClick ? onEventClick(e) : onPidClick?.(e.pid)}
                      title={(onEventClick || onPidClick) ? tr('点击查看详情', 'Click to inspect') : undefined}
                    >
                      <td className="td-time">{formatTimestamp(e.ts_ms)}</td>
                      <td><span className={`kind-tag kind-${e.kind}`}>{mapKind(e.kind, lang)}</span></td>
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
          ) : (
            !loading && <div className="empty-state">{tr('暂无历史事件', 'No historical events')}</div>
          )}

          {data && totalPages > 1 && (
            <div className="history-pagination">
              <button onClick={() => setPage(p => Math.max(0, p - 1))} disabled={page === 0}>‹</button>
              <span>{tr(`第 ${page + 1}/${totalPages} 页 · ${from}–${to} / ${Number(data.total)} 条`, `Page ${page + 1}/${totalPages} · ${from}–${to} of ${Number(data.total)}`)}</span>
              <button onClick={() => setPage(p => Math.min(totalPages - 1, p + 1))} disabled={page >= totalPages - 1}>›</button>
            </div>
          )}
        </>
      )}
    </div>
  )
}
