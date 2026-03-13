import { useCallback, useEffect, useMemo, useState } from 'react'
import './App.css'

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

type Tab = 'dashboard' | 'config'
type Lang = 'zh' | 'en'

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
  services: { 'sshd.service': [721], 'nginx.service': [1142, 1145, 1148] },
  events: [
    {
      timestamp_ns: Date.now() * 1e6,
      kind: 'network',
      action: 'blocked',
      pid: 1148,
      tgid: 1148,
      uid: 33,
      gid: 33,
      comm: 'nginx',
      detail: 'connect attempt matched blocked_ports policy',
      network: { port: 4444, address: '192.168.1.19' },
    },
    {
      timestamp_ns: Date.now() * 1e6,
      kind: 'file_io',
      action: 'alert',
      pid: 721,
      tgid: 721,
      uid: 0,
      gid: 0,
      comm: 'sshd',
      detail: '/etc/shadow',
    },
  ],
  alerts: [
    {
      level: 'critical',
      reason: 'blocked outbound/listen port hit active defense policy',
      event: {
        timestamp_ns: Date.now() * 1e6,
        kind: 'network',
        action: 'blocked',
        pid: 1148,
        tgid: 1148,
        uid: 33,
        gid: 33,
        comm: 'nginx',
        detail: 'connect attempt matched blocked_ports policy',
        network: { port: 4444, address: '192.168.1.19' },
      },
    },
  ],
}

const featureMeta = [
  ['file_io_agent', { zh: '文件 I/O 代理', en: 'File I/O Agent' }],
  ['process_agent', { zh: '进程与权限代理', en: 'Process & Privilege Agent' }],
  ['network_agent', { zh: '网络遥测代理', en: 'Network Telemetry Agent' }],
  ['hotpatch_agent', { zh: '热补丁代理', en: 'Hot-patching Agent' }],
  ['anomaly_engine', { zh: '异常检测引擎', en: 'Anomaly Detection Engine' }],
  ['symbol_resolver', { zh: '符号解析器', en: 'Symbol Resolver' }],
] as const

function initialLang(): Lang {
  const saved = localStorage.getItem('gaia_lang')
  if (saved === 'zh' || saved === 'en') return saved
  return navigator.language.toLowerCase().startsWith('zh') ? 'zh' : 'en'
}

function mapKind(kind: string, lang: Lang) {
  const m: Record<string, { zh: string; en: string }> = {
    file_io: { zh: '文件', en: 'File I/O' },
    process: { zh: '进程', en: 'Process' },
    privilege: { zh: '权限', en: 'Privilege' },
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

function App() {
  const [tab, setTab] = useState<Tab>('dashboard')
  const [lang, setLang] = useState<Lang>(initialLang)
  const [snapshot, setSnapshot] = useState<Snapshot>(mockSnapshot)
  const [live, setLive] = useState(false)

  const tr = useCallback((zh: string, en: string) => (lang === 'zh' ? zh : en), [lang])

  useEffect(() => {
    localStorage.setItem('gaia_lang', lang)
  }, [lang])

  useEffect(() => {
    let cancelled = false
    const pull = async () => {
      try {
        const r = await fetch('/api/v1/state')
        if (!r.ok) return
        const data = (await r.json()) as Snapshot
        if (!cancelled) {
          setSnapshot(data)
          setLive(true)
        }
      } catch {
        if (!cancelled) setLive(false)
      }
    }
    pull()
    const timer = window.setInterval(pull, 2000)
    return () => {
      cancelled = true
      window.clearInterval(timer)
    }
  }, [])

  const totalEvents = useMemo(
    () => Object.values(snapshot.counters).reduce((s, v) => s + v, 0),
    [snapshot.counters],
  )

  return (
    <main className="gaia">
      <section className="hero">
        <div>
          <div className="hero-head">
            <p className="badge">{tr('GAIA 安全平面', 'GAIA Security Plane')}</p>
            <button className="lang-switch" onClick={() => setLang((l) => (l === 'zh' ? 'en' : 'zh'))}>
              {lang === 'zh' ? 'EN' : '中文'}
            </button>
          </div>
          <h1>{tr('Linux 关键服务监控与主动防御', 'Linux Key Service Monitoring & Active Defense')}</h1>
          <p className="intro">
            {tr(
              'Rust + Aya eBPF 代理实时采集内核遥测，用户态控制器执行白名单校验、基线异常检测与运行时热补丁编排。',
              'Rust + Aya eBPF agents collect kernel telemetry in real time, while the user-space controller performs whitelist checks, baseline anomaly detection, and runtime hot-patch orchestration.',
            )}
          </p>
        </div>
        <div className="status-box">
          <p>{tr('控制器 API', 'Controller API')}</p>
          <strong>{live ? tr('实时数据', 'Live feed') : tr('模拟数据', 'Mock feed')}</strong>
          <span>{live ? tr('已连接 /api/v1/state', 'Connected to /api/v1/state') : tr('当前显示回退数据', 'Showing fallback data')}</span>
        </div>
      </section>

      <nav className="tab-bar">
        <button className={tab === 'dashboard' ? 'active' : ''} onClick={() => setTab('dashboard')}>
          {tr('看板', 'Dashboard')}
        </button>
        <button className={tab === 'config' ? 'active' : ''} onClick={() => setTab('config')}>
          {tr('配置', 'Configuration')}
        </button>
      </nav>

      {tab === 'dashboard' ? (
        <DashboardView snapshot={snapshot} totalEvents={totalEvents} lang={lang} tr={tr} />
      ) : (
        <ConfigView lang={lang} tr={tr} />
      )}
    </main>
  )
}

function DashboardView({
  snapshot,
  totalEvents,
  lang,
  tr,
}: {
  snapshot: Snapshot
  totalEvents: number
  lang: Lang
  tr: (zh: string, en: string) => string
}) {
  return (
    <>
      <section className="grid stats">
        <article>
          <p>{tr('事件总数', 'Total Events')}</p>
          <h2>{totalEvents}</h2>
        </article>
        <article>
          <p>{tr('告警数量', 'Open Alerts')}</p>
          <h2>{snapshot.alerts.length}</h2>
        </article>
        <article>
          <p>{tr('跟踪服务', 'Tracked Services')}</p>
          <h2>{Object.keys(snapshot.services).length}</h2>
        </article>
      </section>

      <section className="panel">
        <h3>{tr('代理状态', 'Agents Status')}</h3>
        <div className="feature-list">
          {featureMeta.map(([key, label]) => (
            <div key={key} className={`feature ${snapshot.features[key] ? 'ok' : 'down'}`}>
              <span>{label[lang]}</span>
              <strong>{snapshot.features[key] ? tr('运行中', 'ACTIVE') : tr('离线', 'DOWN')}</strong>
            </div>
          ))}
        </div>
      </section>

      <section className="grid two">
        <article className="panel">
          <h3>{tr('Systemd 跟踪', 'Systemd Tracker')}</h3>
          <div className="services">
            {Object.entries(snapshot.services).map(([svc, pids]) => (
              <div key={svc} className="service-row">
                <span>{svc}</span>
                <code>{pids.join(', ') || '-'}</code>
              </div>
            ))}
          </div>
        </article>
        <article className="panel">
          <h3>{tr('异常计数器', 'Anomaly Counters')}</h3>
          <div className="services">
            {Object.entries(snapshot.counters).map(([k, v]) => (
              <div key={k} className="service-row">
                <span>{mapKind(k, lang)}</span>
                <code>{v}</code>
              </div>
            ))}
          </div>
        </article>
      </section>

      <section className="panel">
        <h3>{tr('最新告警', 'Latest Alerts')}</h3>
        <div className="alerts">
          {snapshot.alerts.slice(0, 6).map((a, i) => (
            <div key={`${a.reason}-${i}`} className={`alert ${a.level}`}>
              <p>
                <strong>{a.level.toUpperCase()}</strong> - {a.reason}
              </p>
              <span>
                {mapKind(a.event.kind, lang)} / {mapAction(a.event.action, lang)} / pid {a.event.pid}
              </span>
            </div>
          ))}
        </div>
      </section>

      <section className="panel">
        <h3>{tr('事件流', 'Event Stream')}</h3>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>{tr('类型', 'Kind')}</th>
                <th>{tr('动作', 'Action')}</th>
                <th>{tr('进程', 'Process')}</th>
                <th>PID</th>
                <th>{tr('详情', 'Detail')}</th>
                <th>{tr('网络', 'Network')}</th>
              </tr>
            </thead>
            <tbody>
              {snapshot.events.slice(0, 12).map((e, i) => (
                <tr key={`${e.timestamp_ns}-${i}`}>
                  <td>{mapKind(e.kind, lang)}</td>
                  <td>{mapAction(e.action, lang)}</td>
                  <td>{e.comm || '-'}</td>
                  <td>{e.pid}</td>
                  <td>{e.detail || '-'}</td>
                  <td>{e.network ? `${e.network.address}:${e.network.port}` : '-'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </>
  )
}

function ConfigView({ lang, tr }: { lang: Lang; tr: (zh: string, en: string) => string }) {
  const [policy, setPolicy] = useState<MonitorPolicy | null>(null)
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)
  const [msg, setMsg] = useState('')

  const fetchConfig = useCallback(async () => {
    try {
      const r = await fetch('/api/v1/config')
      if (r.ok) setPolicy(await r.json())
    } catch {
      // offline
    }
    setLoading(false)
  }, [])

  useEffect(() => {
    fetchConfig()
  }, [fetchConfig])

  const flash = (text: string) => {
    setMsg(text)
    setTimeout(() => setMsg(''), 2500)
  }

  if (loading) return <p className="cfg-loading">{tr('加载配置中...', 'Loading configuration...')}</p>
  if (!policy) return <p className="cfg-loading">{tr('加载配置失败（后端离线？）', 'Unable to load configuration (backend offline?)')}</p>

  return (
    <div className="config-view">
      {msg && <div className="cfg-toast">{msg}</div>}

      <GeneralPolicyPanel
        policy={policy}
        setPolicy={setPolicy}
        saving={saving}
        setSaving={setSaving}
        flash={flash}
        lang={lang}
        tr={tr}
      />
      <RateLimitPanel
        rules={policy.rate_limit_rules}
        setRules={(rules) => setPolicy({ ...policy, rate_limit_rules: rules })}
        flash={flash}
        lang={lang}
        tr={tr}
      />
      <HotpatchPanel
        targets={policy.hotpatch.targets}
        setTargets={(targets) => setPolicy({ ...policy, hotpatch: { targets } })}
        flash={flash}
        lang={lang}
        tr={tr}
      />
    </div>
  )
}

function GeneralPolicyPanel({
  policy,
  setPolicy,
  saving,
  setSaving,
  flash,
  tr,
}: {
  policy: MonitorPolicy
  setPolicy: (p: MonitorPolicy) => void
  saving: boolean
  setSaving: (v: boolean) => void
  flash: (msg: string) => void
  lang: Lang
  tr: (zh: string, en: string) => string
}) {
  const [sensitivePrefixes, setSensitivePrefixes] = useState(policy.sensitive_prefixes.join('\n'))
  const [execWhitelist, setExecWhitelist] = useState(policy.exec_whitelist_prefixes.join('\n'))
  const [monitoredServices, setMonitoredServices] = useState(policy.monitored_services.join('\n'))
  const [blockedPorts, setBlockedPorts] = useState(policy.blocked_ports.join(', '))
  const [thresholds, setThresholds] = useState({ ...policy.baseline_thresholds })

  const handleSave = async () => {
    setSaving(true)
    const body = {
      sensitive_prefixes: sensitivePrefixes.split('\n').map((s) => s.trim()).filter(Boolean),
      exec_whitelist_prefixes: execWhitelist.split('\n').map((s) => s.trim()).filter(Boolean),
      monitored_services: monitoredServices.split('\n').map((s) => s.trim()).filter(Boolean),
      blocked_ports: blockedPorts
        .split(',')
        .map((s) => parseInt(s.trim(), 10))
        .filter((n) => !isNaN(n)),
      baseline_thresholds: thresholds,
    }
    try {
      const r = await fetch('/api/v1/config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      })
      if (r.ok) {
        const updated = (await r.json()) as MonitorPolicy
        setPolicy(updated)
        flash(tr('通用策略已保存', 'General policy saved'))
      } else {
        flash(tr('保存失败: ', 'Save failed: ') + r.statusText)
      }
    } catch {
      flash(tr('保存失败: 网络错误', 'Save failed: network error'))
    }
    setSaving(false)
  }

  return (
    <section className="panel cfg-panel">
      <h3>{tr('通用策略', 'General Policy')}</h3>
      <div className="cfg-grid">
        <div className="cfg-field">
          <label>{tr('敏感文件前缀', 'Sensitive File Prefixes')}</label>
          <textarea
            rows={4}
            value={sensitivePrefixes}
            onChange={(e) => setSensitivePrefixes(e.target.value)}
            placeholder="/etc/shadow&#10;/etc/ssl&#10;/root/.ssh"
          />
          <span className="cfg-hint">{tr('每行一个路径前缀', 'One path prefix per line')}</span>
        </div>
        <div className="cfg-field">
          <label>{tr('可执行白名单前缀', 'Exec Whitelist Prefixes')}</label>
          <textarea
            rows={4}
            value={execWhitelist}
            onChange={(e) => setExecWhitelist(e.target.value)}
            placeholder="/usr/bin&#10;/usr/sbin"
          />
          <span className="cfg-hint">{tr('允许的 execve 前缀，每行一个', 'Allowed execve path prefixes, one per line')}</span>
        </div>
        <div className="cfg-field">
          <label>{tr('监控服务', 'Monitored Services')}</label>
          <textarea
            rows={3}
            value={monitoredServices}
            onChange={(e) => setMonitoredServices(e.target.value)}
            placeholder="sshd.service&#10;nginx.service"
          />
          <span className="cfg-hint">{tr('systemd unit 名称，每行一个', 'Systemd unit names, one per line')}</span>
        </div>
        <div className="cfg-field">
          <label>{tr('阻断端口', 'Blocked Ports')}</label>
          <input
            type="text"
            value={blockedPorts}
            onChange={(e) => setBlockedPorts(e.target.value)}
            placeholder="4444, 31337"
          />
          <span className="cfg-hint">{tr('逗号分隔端口号', 'Comma-separated port numbers')}</span>
        </div>
      </div>

      <h4>{tr('基线阈值（每 30 秒窗口）', 'Baseline Thresholds (per 30s window)')}</h4>
      <div className="cfg-thresholds">
        {['file_io', 'process', 'privilege', 'network', 'hotpatch'].map((k) => (
          <div key={k} className="cfg-threshold-row">
            <label>{mapKind(k, 'en')}</label>
            <input
              type="number"
              min={0}
              value={thresholds[k] ?? 0}
              onChange={(e) =>
                setThresholds({ ...thresholds, [k]: parseInt(e.target.value, 10) || 0 })
              }
            />
          </div>
        ))}
      </div>

      <button className="cfg-save" onClick={handleSave} disabled={saving}>
        {saving ? tr('保存中...', 'Saving...') : tr('保存通用策略', 'Save General Policy')}
      </button>
    </section>
  )
}

const emptyRule: RateLimitRule = { cidr: '', max_conn_per_sec: 100, action: 'log', enabled: true }

function RateLimitPanel({
  rules,
  setRules,
  flash,
  tr,
}: {
  rules: RateLimitRule[]
  setRules: (r: RateLimitRule[]) => void
  flash: (msg: string) => void
  lang: Lang
  tr: (zh: string, en: string) => string
}) {
  const [draft, setDraft] = useState<RateLimitRule>({ ...emptyRule })

  const handleAdd = async () => {
    if (!draft.cidr.trim()) {
      flash(tr('CIDR 必填', 'CIDR is required'))
      return
    }
    try {
      const r = await fetch('/api/v1/config/rate-limit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ...draft, cidr: draft.cidr.trim() }),
      })
      if (r.ok) {
        setRules(await r.json())
        setDraft({ ...emptyRule })
        flash(tr('限流规则已添加', 'Rate limit rule added'))
      } else {
        flash(tr('添加失败: ', 'Add failed: ') + r.statusText)
      }
    } catch {
      flash(tr('添加失败: 网络错误', 'Add failed: network error'))
    }
  }

  const handleDelete = async (index: number) => {
    try {
      const r = await fetch(`/api/v1/config/rate-limit/${index}`, { method: 'DELETE' })
      if (r.ok) {
        setRules(await r.json())
        flash(tr('规则已删除', 'Rule deleted'))
      }
    } catch {
      flash(tr('删除失败', 'Delete failed'))
    }
  }

  const handleToggle = async (index: number) => {
    const rule = { ...rules[index], enabled: !rules[index].enabled }
    try {
      const r = await fetch('/api/v1/config/rate-limit', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ index, ...rule }),
      })
      if (r.ok) {
        setRules(await r.json())
        flash(tr('规则已更新', 'Rule updated'))
      }
    } catch {
      flash(tr('更新失败', 'Update failed'))
    }
  }

  return (
    <section className="panel cfg-panel">
      <h3>{tr('IP 限流', 'IP Rate Limiting')}</h3>
      <p className="cfg-desc">
        {tr(
          '配置基于 CIDR 的连接速率限制。规则由网络遥测代理在运行时评估。',
          'Define per-CIDR connection rate limits. Rules are evaluated by the network telemetry agent at runtime.',
        )}
      </p>

      {rules.length > 0 && (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>CIDR</th>
                <th>{tr('最大连接/秒', 'Max Conn/s')}</th>
                <th>{tr('动作', 'Action')}</th>
                <th>{tr('启用', 'Enabled')}</th>
                <th>{tr('操作', 'Operations')}</th>
              </tr>
            </thead>
            <tbody>
              {rules.map((rule, i) => (
                <tr key={i} className={rule.enabled ? '' : 'row-disabled'}>
                  <td>
                    <code>{rule.cidr}</code>
                  </td>
                  <td>{rule.max_conn_per_sec}</td>
                  <td>
                    <span className={`action-badge action-${rule.action}`}>{rule.action}</span>
                  </td>
                  <td>
                    <button className="btn-toggle" onClick={() => handleToggle(i)}>
                      {rule.enabled ? tr('开', 'ON') : tr('关', 'OFF')}
                    </button>
                  </td>
                  <td>
                    <button className="btn-danger" onClick={() => handleDelete(i)}>
                      {tr('删除', 'Delete')}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <div className="cfg-add-form">
        <h4>{tr('新增规则', 'Add Rule')}</h4>
        <div className="cfg-add-row">
          <input
            type="text"
            placeholder="10.0.0.0/8"
            value={draft.cidr}
            onChange={(e) => setDraft({ ...draft, cidr: e.target.value })}
          />
          <input
            type="number"
            min={1}
            placeholder="100"
            value={draft.max_conn_per_sec}
            onChange={(e) =>
              setDraft({ ...draft, max_conn_per_sec: parseInt(e.target.value, 10) || 1 })
            }
          />
          <select
            value={draft.action}
            onChange={(e) => setDraft({ ...draft, action: e.target.value as RateLimitRule['action'] })}
          >
            <option value="log">{tr('记录', 'Log')}</option>
            <option value="block">{tr('阻断', 'Block')}</option>
            <option value="throttle">{tr('限速', 'Throttle')}</option>
          </select>
          <label className="cfg-checkbox">
            <input
              type="checkbox"
              checked={draft.enabled}
              onChange={(e) => setDraft({ ...draft, enabled: e.target.checked })}
            />
            {tr('启用', 'Enabled')}
          </label>
          <button className="cfg-save" onClick={handleAdd}>
            {tr('添加', 'Add')}
          </button>
        </div>
      </div>
    </section>
  )
}

const emptyTarget: HotpatchTarget = { binary: '', symbol: '', pid: null }

function HotpatchPanel({
  targets,
  setTargets,
  flash,
  tr,
}: {
  targets: HotpatchTarget[]
  setTargets: (t: HotpatchTarget[]) => void
  flash: (msg: string) => void
  lang: Lang
  tr: (zh: string, en: string) => string
}) {
  const [draft, setDraft] = useState<HotpatchTarget>({ ...emptyTarget })

  const handleAdd = async () => {
    if (!draft.binary.trim() || !draft.symbol.trim()) {
      flash(tr('二进制路径和符号名必填', 'Binary path and symbol name are required'))
      return
    }
    const payload = {
      binary: draft.binary.trim(),
      symbol: draft.symbol.trim(),
      pid: draft.pid || null,
    }
    try {
      const r = await fetch('/api/v1/config/hotpatch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      })
      if (r.ok) {
        setTargets(await r.json())
        setDraft({ ...emptyTarget })
        flash(tr('热补丁目标已添加', 'Hotpatch target added'))
      } else {
        flash(tr('添加失败: ', 'Add failed: ') + r.statusText)
      }
    } catch {
      flash(tr('添加失败: 网络错误', 'Add failed: network error'))
    }
  }

  const handleDelete = async (index: number) => {
    try {
      const r = await fetch(`/api/v1/config/hotpatch/${index}`, { method: 'DELETE' })
      if (r.ok) {
        setTargets(await r.json())
        flash(tr('目标已删除', 'Target removed'))
      }
    } catch {
      flash(tr('删除失败', 'Delete failed'))
    }
  }

  return (
    <section className="panel cfg-panel">
      <h3>{tr('高危函数运行时热补丁', 'Hot-Patch Targets (Runtime Defense)')}</h3>
      <p className="cfg-desc">
        {tr(
          '通过 uprobe/uretprobe 在运行时挂载到高危函数入口和出口，结合参数校验与返回值控制（如 bpf_override_return）实现不停机防护。',
          'Attach uprobe/uretprobe probes to vulnerable functions at runtime. The hot-patching agent validates arguments and can force error returns via bpf_override_return without restarting services.',
        )}
      </p>

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
                  <td>
                    <code>{t.binary}</code>
                  </td>
                  <td>
                    <code>{t.symbol}</code>
                  </td>
                  <td>{t.pid ?? tr('全部', 'all')}</td>
                  <td>
                    <button className="btn-danger" onClick={() => handleDelete(i)}>
                      {tr('删除', 'Delete')}
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <div className="cfg-add-form">
        <h4>{tr('新增目标', 'Add Target')}</h4>
        <div className="cfg-add-row">
          <input
            type="text"
            placeholder="/usr/sbin/nginx"
            value={draft.binary}
            onChange={(e) => setDraft({ ...draft, binary: e.target.value })}
          />
          <input
            type="text"
            placeholder="ngx_http_process_request"
            value={draft.symbol}
            onChange={(e) => setDraft({ ...draft, symbol: e.target.value })}
          />
          <input
            type="number"
            min={0}
            placeholder={tr('PID（可选）', 'PID (optional)')}
            value={draft.pid ?? ''}
            onChange={(e) =>
              setDraft({ ...draft, pid: e.target.value ? parseInt(e.target.value, 10) : null })
            }
          />
          <button className="cfg-save" onClick={handleAdd}>
            {tr('添加', 'Add')}
          </button>
        </div>
      </div>
    </section>
  )
}

export default App
