import { useEffect, useMemo, useState } from 'react'
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
  network?: {
    port: number
    address: string
  }
}

type AlertRecord = {
  level: string
  reason: string
  event: EventRecord
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
  services: Record<string, number[]>
  events: EventRecord[]
  alerts: AlertRecord[]
}

const mockSnapshot: Snapshot = {
  features: {
    file_io_agent: true,
    process_agent: true,
    network_agent: true,
    hotpatch_agent: true,
    anomaly_engine: true,
    symbol_resolver: true,
  },
  counters: {
    file_io: 341,
    process: 88,
    privilege: 5,
    network: 152,
    hotpatch: 11,
  },
  services: {
    'sshd.service': [721],
    'nginx.service': [1142, 1145, 1148],
  },
  events: [
    {
      timestamp_ns: Date.now() * 1_000_000,
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
      timestamp_ns: Date.now() * 1_000_000,
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
        timestamp_ns: Date.now() * 1_000_000,
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
  ['file_io_agent', 'File I/O Agent'],
  ['process_agent', 'Process & Privilege Agent'],
  ['network_agent', 'Network Telemetry Agent'],
  ['hotpatch_agent', 'Hot-patching Agent'],
  ['anomaly_engine', 'Anomaly Detection Engine'],
  ['symbol_resolver', 'Symbol Resolver'],
] as const

function App() {
  const [snapshot, setSnapshot] = useState<Snapshot>(mockSnapshot)
  const [live, setLive] = useState(false)

  useEffect(() => {
    let cancelled = false

    const pull = async () => {
      try {
        const response = await fetch('/api/v1/state')
        if (!response.ok) return
        const data = (await response.json()) as Snapshot
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
    () => Object.values(snapshot.counters).reduce((sum, value) => sum + value, 0),
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

      <section className="grid stats">
        <article>
          <p>Total Events</p>
          <h2>{totalEvents}</h2>
        </article>
        <article>
          <p>Open Alerts</p>
          <h2>{snapshot.alerts.length}</h2>
        </article>
        <article>
          <p>Tracked Services</p>
          <h2>{Object.keys(snapshot.services).length}</h2>
        </article>
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
            {Object.entries(snapshot.services).map(([service, pids]) => (
              <div key={service} className="service-row">
                <span>{service}</span>
                <code>{pids.join(', ') || '-'}</code>
              </div>
            ))}
          </div>
        </article>

        <article className="panel">
          <h3>Anomaly Counters</h3>
          <div className="services">
            {Object.entries(snapshot.counters).map(([kind, value]) => (
              <div key={kind} className="service-row">
                <span>{kind}</span>
                <code>{value}</code>
              </div>
            ))}
          </div>
        </article>
      </section>

      <section className="panel">
        <h3>Latest Alerts</h3>
        <div className="alerts">
          {snapshot.alerts.slice(0, 6).map((alert, idx) => (
            <div key={`${alert.reason}-${idx}`} className={`alert ${alert.level}`}>
              <p>
                <strong>{alert.level.toUpperCase()}</strong> - {alert.reason}
              </p>
              <span>
                {alert.event.kind} / {alert.event.action} / pid {alert.event.pid}
              </span>
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
                <th>Kind</th>
                <th>Action</th>
                <th>Process</th>
                <th>PID</th>
                <th>Detail</th>
                <th>Network</th>
              </tr>
            </thead>
            <tbody>
              {snapshot.events.slice(0, 12).map((event, idx) => (
                <tr key={`${event.timestamp_ns}-${idx}`}>
                  <td>{event.kind}</td>
                  <td>{event.action}</td>
                  <td>{event.comm || '-'}</td>
                  <td>{event.pid}</td>
                  <td>{event.detail || '-'}</td>
                  <td>
                    {event.network ? `${event.network.address}:${event.network.port}` : '-'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </main>
  )
}

export default App
