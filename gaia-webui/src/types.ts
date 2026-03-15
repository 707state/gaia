export type EventRecord = {
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

export type AlertRecord = { level: string; reason: string; event: EventRecord }

export type Snapshot = {
  features: {
    file_io_agent: boolean
    process_agent: boolean
    network_agent: boolean
    hotpatch_agent: boolean
    anomaly_engine: boolean
    symbol_resolver: boolean
    traffic_agent: boolean
  }
  counters: Record<string, number>
  services: Record<string, number[]>
  events: EventRecord[]
  alerts: AlertRecord[]
  total_events?: number
}

export type RateLimitRule = {
  cidr: string
  max_conn_per_sec: number
  action: 'log' | 'block' | 'throttle'
  enabled: boolean
}

export type HotpatchTarget = {
  binary: string
  symbol: string
  pid?: number | null
  block_mode: boolean
}

export type MonitorPolicy = {
  sensitive_prefixes: string[]
  monitored_services: string[]
  exec_whitelist_prefixes: string[]
  blocked_ports: number[]
  baseline_thresholds: Record<string, number>
  hotpatch: { targets: HotpatchTarget[] }
  rate_limit_rules: RateLimitRule[]
}

export type Lang = 'zh' | 'en'

export type ServiceTrafficSnapshot = {
  service: string
  pids: number[]
  bytes_sent: number
  bytes_recv: number
  packets_sent: number
  packets_recv: number
}

export type TrafficDataPoint = {
  timestamp_ms: number
  bytes_sent: number
  bytes_recv: number
  packets_sent: number
  packets_recv: number
}

export type TrafficResponse = {
  system_bytes_sent: number
  system_bytes_recv: number
  system_packets_sent: number
  system_packets_recv: number
  services: ServiceTrafficSnapshot[]
  history: TrafficDataPoint[]
}
