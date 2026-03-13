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

// ── Mock data ──

const mockSnapshot: Snapshot = {
  features: {
    file_io_agent: true, process_agent: true, network_agent: true,
    hotpatch_agent: true, anomaly_engine: true, symbol_resolver: true,
  },
  counters: { file_io: 341, process: 88, privilege: 5, network: 152, hotpatch: 11 },
  services: { 'sshd.service': [721], 'nginx.service': [1142, 1145, 1148] },
  events: [
    {
      timestamp_ns: Date.now() * 1e6, kind: 'network', action: 'blocked',
      pid: 1148, tgid: 1148, uid: 33, gid: 33, comm: 'nginx',
      detail: 'connect attempt matched blocked_ports policy',
      network: { port: 4444, address: '192.168.1.19' },
    },
    {
      timestamp_ns: Date.now() * 1e6, kind: 'file_io', action: 'alert',
      pid: 721, tgid: 721, uid: 0, gid: 0, comm: 'sshd', detail: '/etc/shadow',
    },
  ],
  alerts: [
    {
      level: 'critical', reason: 'blocked outbound/listen port hit active defense policy',
      event: {
        timestamp_ns: Date.now() * 1e6, kind: 'network', action: 'blocked',
        pid: 1148, tgid: 1148, uid: 33, gid: 33, comm: 'nginx',
        detail: 'connect attempt matched blocked_ports policy',
        network: { port: 4444, address: '192.168.1.19' },
      },
    },
  ],
}

const featureMeta = [
  ['file_io_agent', 'File I/O Agent'],
  ['process_agent', 'Process & Privilege Agent'],
  ['network_agent', 'Network Telemetry Agent'],
  ['hotpatch_agent', 'Hot-patching Agent'],
  ['anomaly_engine', 'Anomaly Detection Engine'],
  ['symbol_resolver', 'Symbol Resolver'],
] as const

type Tab = 'dashboard' | 'config'

// ── App ──

function App() {
  const [tab, setTab] = useState<Tab>('dashboard')
  const [snapshot, setSnapshot] = useState<Snapshot>(mockSnapshot)
  const [live, setLive] = useState(false)

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

  return (
    <main className="gaia">
      <section className="hero">
        <div>
          <p className="badge">GAIA Security Plane</p>
          <h1>Linux Key Service Monitoring & Active Defense</h1>
          <p className="intro">
            Rust + Aya eBPF agents collect kernel telemetry in real time, while the user-space
            controller performs whitelist checks, baseline anomaly detection, and runtime hot-patch
            orchestration.
          </p>
        </div>
        <div className="status-box">
          <p>Controller API</p>
          <strong>{live ? 'Live feed' : 'Mock feed'}</strong>
          <span>{live ? 'Connected to /api/v1/state' : 'Showing fallback data'}</span>
        </div>
      </section>

      <nav className="tab-bar">
        <button className={tab === 'dashboard' ? 'active' : ''} onClick={() => setTab('dashboard')}>
          Dashboard
        </button>
        <button className={tab === 'config' ? 'active' : ''} onClick={() => setTab('config')}>
          Configuration
        </button>
      </nav>

      {tab === 'dashboard' ? (
        <DashboardView snapshot={snapshot} totalEvents={totalEvents} />
      ) : (
        <ConfigView />
      )}
    </main>
  )
}

// ── Dashboard ──

function DashboardView({ snapshot, totalEvents }: { snapshot: Snapshot; totalEvents: number }) {
  return (
    <>
      <section className="grid stats">
        <article><p>Total Events</p><h2>{totalEvents}</h2></article>
        <article><p>Open Alerts</p><h2>{snapshot.alerts.length}</h2></article>
        <article><p>Tracked Services</p><h2>{Object.keys(snapshot.services).length}</h2></article>
      </section>

      <section className="panel">
        <h3>Agents Status</h3>
        <div className="feature-list">
          {featureMeta.map(([key, label]) => (
            <div key={key} className={`feature ${snapshot.features[key] ? 'ok' : 'down'}`}>
              <span>{label}</span>
              <strong>{snapshot.features[key] ? 'ACTIVE' : 'DOWN'}</strong>
            </div>
          ))}
        </div>
      </section>

      <section className="grid two">
        <article className="panel">
          <h3>Systemd Tracker</h3>
          <div className="services">
            {Object.entries(snapshot.services).map(([svc, pids]) => (
              <div key={svc} className="service-row">
                <span>{svc}</span><code>{pids.join(', ') || '-'}</code>
              </div>
            ))}
          </div>
        </article>
        <article className="panel">
          <h3>Anomaly Counters</h3>
          <div className="services">
            {Object.entries(snapshot.counters).map(([k, v]) => (
              <div key={k} className="service-row">
                <span>{k}</span><code>{v}</code>
              </div>
            ))}
          </div>
        </article>
      </section>

      <section className="panel">
        <h3>Latest Alerts</h3>
        <div className="alerts">
          {snapshot.alerts.slice(0, 6).map((a, i) => (
            <div key={`${a.reason}-${i}`} className={`alert ${a.level}`}>
              <p><strong>{a.level.toUpperCase()}</strong> - {a.reason}</p>
              <span>{a.event.kind} / {a.event.action} / pid {a.event.pid}</span>
            </div>
          ))}
        </div>
      </section>

      <section className="panel">
        <h3>Event Stream</h3>
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>Kind</th><th>Action</th><th>Process</th>
                <th>PID</th><th>Detail</th><th>Network</th>
              </tr>
            </thead>
            <tbody>
              {snapshot.events.slice(0, 12).map((e, i) => (
                <tr key={`${e.timestamp_ns}-${i}`}>
                  <td>{e.kind}</td><td>{e.action}</td>
                  <td>{e.comm || '-'}</td><td>{e.pid}</td>
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

// ── Configuration View ──

function ConfigView() {
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

  const flash = (text: string) => { setMsg(text); setTimeout(() => setMsg(''), 2500) }

  if (loading) return <p className="cfg-loading">Loading configuration...</p>
  if (!policy) return <p className="cfg-loading">Unable to load configuration (backend offline?)</p>

  return (
    <div className="config-view">
      {msg && <div className="cfg-toast">{msg}</div>}

      <GeneralPolicyPanel
        policy={policy} setPolicy={setPolicy}
        saving={saving} setSaving={setSaving} flash={flash}
      />
      <RateLimitPanel
        rules={policy.rate_limit_rules}
        setRules={(rules) => setPolicy({ ...policy, rate_limit_rules: rules })}
        flash={flash}
      />
      <HotpatchPanel
        targets={policy.hotpatch.targets}
        setTargets={(targets) => setPolicy({ ...policy, hotpatch: { targets } })}
        flash={flash}
      />
    </div>
  )
}

// ── General Policy Panel ──

function GeneralPolicyPanel({
  policy, setPolicy, saving, setSaving, flash,
}: {
  policy: MonitorPolicy
  setPolicy: (p: MonitorPolicy) => void
  saving: boolean
  setSaving: (v: boolean) => void
  flash: (msg: string) => void
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
      const r = await fetch('/api/v1/config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      })
      if (r.ok) {
        const updated = await r.json() as MonitorPolicy
        setPolicy(updated)
        flash('General policy saved')
      } else {
        flash('Save failed: ' + r.statusText)
      }
    } catch { flash('Save failed: network error') }
    setSaving(false)
  }

  return (
    <section className="panel cfg-panel">
      <h3>General Policy</h3>
      <div className="cfg-grid">
        <div className="cfg-field">
          <label>Sensitive File Prefixes</label>
          <textarea rows={4} value={sensitivePrefixes}
            onChange={e => setSensitivePrefixes(e.target.value)}
            placeholder="/etc/shadow&#10;/etc/ssl&#10;/root/.ssh" />
          <span className="cfg-hint">One path prefix per line</span>
        </div>
        <div className="cfg-field">
          <label>Exec Whitelist Prefixes</label>
          <textarea rows={4} value={execWhitelist}
            onChange={e => setExecWhitelist(e.target.value)}
            placeholder="/usr/bin&#10;/usr/sbin" />
          <span className="cfg-hint">Allowed execve path prefixes, one per line</span>
        </div>
        <div className="cfg-field">
          <label>Monitored Services</label>
          <textarea rows={3} value={monitoredServices}
            onChange={e => setMonitoredServices(e.target.value)}
            placeholder="sshd.service&#10;nginx.service" />
          <span className="cfg-hint">Systemd unit names, one per line</span>
        </div>
        <div className="cfg-field">
          <label>Blocked Ports</label>
          <input type="text" value={blockedPorts}
            onChange={e => setBlockedPorts(e.target.value)}
            placeholder="4444, 31337" />
          <span className="cfg-hint">Comma-separated port numbers</span>
        </div>
      </div>

      <h4>Baseline Thresholds (per {'\u00A0'}30s window)</h4>
      <div className="cfg-thresholds">
        {['file_io', 'process', 'privilege', 'network', 'hotpatch'].map(k => (
          <div key={k} className="cfg-threshold-row">
            <label>{k}</label>
            <input type="number" min={0}
              value={thresholds[k] ?? 0}
              onChange={e => setThresholds({ ...thresholds, [k]: parseInt(e.target.value, 10) || 0 })}
            />
          </div>
        ))}
      </div>

      <button className="cfg-save" onClick={handleSave} disabled={saving}>
        {saving ? 'Saving...' : 'Save General Policy'}
      </button>
    </section>
  )
}

// ── Rate Limit Panel ──

const emptyRule: RateLimitRule = { cidr: '', max_conn_per_sec: 100, action: 'log', enabled: true }

function RateLimitPanel({
  rules, setRules, flash,
}: {
  rules: RateLimitRule[]
  setRules: (r: RateLimitRule[]) => void
  flash: (msg: string) => void
}) {
  const [draft, setDraft] = useState<RateLimitRule>({ ...emptyRule })

  const handleAdd = async () => {
    if (!draft.cidr.trim()) { flash('CIDR is required'); return }
    try {
      const r = await fetch('/api/v1/config/rate-limit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ...draft, cidr: draft.cidr.trim() }),
      })
      if (r.ok) { setRules(await r.json()); setDraft({ ...emptyRule }); flash('Rate limit rule added') }
      else flash('Add failed: ' + r.statusText)
    } catch { flash('Add failed: network error') }
  }

  const handleDelete = async (index: number) => {
    try {
      const r = await fetch(`/api/v1/config/rate-limit/${index}`, { method: 'DELETE' })
      if (r.ok) { setRules(await r.json()); flash('Rule deleted') }
    } catch { flash('Delete failed') }
  }

  const handleToggle = async (index: number) => {
    const rule = { ...rules[index], enabled: !rules[index].enabled }
    try {
      const r = await fetch('/api/v1/config/rate-limit', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ index, ...rule }),
      })
      if (r.ok) { setRules(await r.json()); flash('Rule updated') }
    } catch { flash('Update failed') }
  }

  return (
    <section className="panel cfg-panel">
      <h3>IP Rate Limiting</h3>
      <p className="cfg-desc">
        Define per-CIDR connection rate limits. Rules are evaluated by the network telemetry agent
        against incoming connections from tracked services.
      </p>

      {rules.length > 0 && (
        <div className="table-wrap">
          <table>
            <thead>
              <tr>
                <th>CIDR</th><th>Max Conn/s</th><th>Action</th>
                <th>Enabled</th><th>Operations</th>
              </tr>
            </thead>
            <tbody>
              {rules.map((rule, i) => (
                <tr key={i} className={rule.enabled ? '' : 'row-disabled'}>
                  <td><code>{rule.cidr}</code></td>
                  <td>{rule.max_conn_per_sec}</td>
                  <td><span className={`action-badge action-${rule.action}`}>{rule.action}</span></td>
                  <td>
                    <button className="btn-toggle" onClick={() => handleToggle(i)}>
                      {rule.enabled ? 'ON' : 'OFF'}
                    </button>
                  </td>
                  <td>
                    <button className="btn-danger" onClick={() => handleDelete(i)}>Delete</button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <div className="cfg-add-form">
        <h4>Add Rule</h4>
        <div className="cfg-add-row">
          <input type="text" placeholder="10.0.0.0/8" value={draft.cidr}
            onChange={e => setDraft({ ...draft, cidr: e.target.value })} />
          <input type="number" min={1} placeholder="100" value={draft.max_conn_per_sec}
            onChange={e => setDraft({ ...draft, max_conn_per_sec: parseInt(e.target.value, 10) || 1 })} />
          <select value={draft.action}
            onChange={e => setDraft({ ...draft, action: e.target.value as RateLimitRule['action'] })}>
            <option value="log">Log</option>
            <option value="block">Block</option>
            <option value="throttle">Throttle</option>
          </select>
          <label className="cfg-checkbox">
            <input type="checkbox" checked={draft.enabled}
              onChange={e => setDraft({ ...draft, enabled: e.target.checked })} />
            Enabled
          </label>
          <button className="cfg-save" onClick={handleAdd}>Add</button>
        </div>
      </div>
    </section>
  )
}

// ── Hotpatch Panel ──

const emptyTarget: HotpatchTarget = { binary: '', symbol: '', pid: null }

function HotpatchPanel({
  targets, setTargets, flash,
}: {
  targets: HotpatchTarget[]
  setTargets: (t: HotpatchTarget[]) => void
  flash: (msg: string) => void
}) {
  const [draft, setDraft] = useState<HotpatchTarget>({ ...emptyTarget })

  const handleAdd = async () => {
    if (!draft.binary.trim() || !draft.symbol.trim()) {
      flash('Binary path and symbol name are required'); return
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
      if (r.ok) { setTargets(await r.json()); setDraft({ ...emptyTarget }); flash('Hotpatch target added') }
      else flash('Add failed: ' + r.statusText)
    } catch { flash('Add failed: network error') }
  }

  const handleDelete = async (index: number) => {
    try {
      const r = await fetch(`/api/v1/config/hotpatch/${index}`, { method: 'DELETE' })
      if (r.ok) { setTargets(await r.json()); flash('Target removed') }
    } catch { flash('Delete failed') }
  }

  return (
    <section className="panel cfg-panel">
      <h3>Hot-Patch Targets (Runtime Defense)</h3>
      <p className="cfg-desc">
        Attach uprobe/uretprobe probes to vulnerable functions at runtime. The hot-patching agent
        validates arguments at function entry and can force error returns via <code>bpf_override_return</code> to
        neutralize exploits without restarting the service.
      </p>

      {targets.length > 0 && (
        <div className="table-wrap">
          <table>
            <thead>
              <tr><th>Binary</th><th>Symbol</th><th>PID</th><th>Operations</th></tr>
            </thead>
            <tbody>
              {targets.map((t, i) => (
                <tr key={i}>
                  <td><code>{t.binary}</code></td>
                  <td><code>{t.symbol}</code></td>
                  <td>{t.pid ?? 'all'}</td>
                  <td><button className="btn-danger" onClick={() => handleDelete(i)}>Delete</button></td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      <div className="cfg-add-form">
        <h4>Add Target</h4>
        <div className="cfg-add-row">
          <input type="text" placeholder="/usr/sbin/nginx" value={draft.binary}
            onChange={e => setDraft({ ...draft, binary: e.target.value })} />
          <input type="text" placeholder="ngx_http_process_request" value={draft.symbol}
            onChange={e => setDraft({ ...draft, symbol: e.target.value })} />
          <input type="number" min={0} placeholder="PID (optional)" value={draft.pid ?? ''}
            onChange={e => setDraft({ ...draft, pid: e.target.value ? parseInt(e.target.value, 10) : null })} />
          <button className="cfg-save" onClick={handleAdd}>Add</button>
        </div>
      </div>
    </section>
  )
}

export default App
