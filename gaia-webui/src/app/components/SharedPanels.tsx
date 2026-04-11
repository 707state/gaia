import { useState } from 'react'
import type {
  AlertRecord,
  EventRecord,
  Lang,
  ProcessDetail,
  ToggleItem,
  TranslateFn,
} from '../types'
import { formatTimestamp, mapAction, mapKind, relativeTime } from '../utils'

export function EventTable({ events, lang, tr }: { events: EventRecord[]; lang: Lang; tr: TranslateFn }) {
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

export function AlertList({ alerts, lang }: { alerts: AlertRecord[]; lang: Lang }) {
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
