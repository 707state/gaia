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
  service?: string
}

export type AlertRecord = { level: string; reason: string; event: EventRecord }

export type NetIfTraffic = {
  name: string
  rx_bytes_per_sec: number
  tx_bytes_per_sec: number
  rx_packets_per_sec: number
  tx_packets_per_sec: number
}

export type TrafficSnapshot = {
  interfaces: NetIfTraffic[]
  total_rx_bytes_per_sec: number
  total_tx_bytes_per_sec: number
}

export type ServiceStatusInfo = {
  active_state: string
  sub_state: string
  state: string
  pids: number[]
}

export type Snapshot = {
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

export type ToggleItem = {
  value: string
  enabled: boolean
}

export type ProcessMemory = {
  vm_peak_kb: number
  vm_size_kb: number
  vm_rss_kb: number
  vm_swap_kb: number
  vm_data_kb: number
  vm_stk_kb: number
  vm_exe_kb: number
  vm_lib_kb: number
}

export type ProcessIo = {
  rchar: number
  wchar: number
  syscr: number
  syscw: number
  read_bytes: number
  write_bytes: number
}

export type FdEntry = { fd: number; target: string }

export type ProcessDetail = {
  pid: number
  name: string
  state: string
  ppid: number
  uid: number
  gid: number
  euid: number
  egid: number
  threads: number
  cmdline: string
  exe: string
  cwd: string
  uptime_secs: number
  mem: ProcessMemory
  io: ProcessIo
  fds: FdEntry[]
  voluntary_ctxt_switches: number
  nonvoluntary_ctxt_switches: number
  oom_score: number
  seccomp: string
  cap_eff: string
  environ: string[]
  cpus_allowed_list: string
}

export type TogglePort = {
  port: number
  enabled: boolean
}

export type RateLimitRule = {
  cidr: string
  max_conn_per_sec: number
  action: 'log' | 'block' | 'throttle'
  enabled: boolean
}

export type PatchAction = 'monitor' | 'override_return' | 'skip_call' | 'replace_function'

export type HotpatchTarget = {
  binary: string
  symbol: string
  pid?: number | null
  enabled: boolean
  patch_action: PatchAction
  override_return_value: number
  replace_lib?: string | null
  replace_symbol?: string | null
}

export type KernelLivepatchTarget = {
  old_func: string
  new_func_body: string
  func_ret: string
  func_args: string
  obj_name?: string | null
  enabled: boolean
}

export type LivepatchStatus = {
  name: string
  state: string
  enabled: boolean | null
  build_dir: string
}

export type MonitorPolicy = {
  sensitive_prefixes: ToggleItem[]
  monitored_services: ToggleItem[]
  exec_whitelist_prefixes: ToggleItem[]
  blocked_ports: TogglePort[]
  baseline_thresholds: Record<string, number>
  hotpatch: { targets: HotpatchTarget[]; kernel_livepatch: KernelLivepatchTarget[] }
  rate_limit_rules: RateLimitRule[]
}

export type Tab = 'overview' | 'file' | 'process' | 'network' | 'hotpatch' | 'alerts' | 'config' | 'ai'
export type Lang = 'zh' | 'en'

export type TranslateFn = (zh: string, en: string) => string

export type AiProvider = 'open_ai' | 'ollama' | 'custom'

export type AiConfig = {
  enabled: boolean
  provider: AiProvider
  base_url: string
  model: string
  api_key: string
  analysis_interval_hours: number
}

export type WechatBotStatus = {
  enabled: boolean
  logged_in: boolean
  needs_qr_scan: boolean
  qr_url?: string | null
  last_error?: string | null
  account_id?: string | null
  user_id?: string | null
  updated_at?: string | null
}

export type ChatRole = 'user' | 'assistant' | 'system'

export type ChatMessage = {
  role: ChatRole
  content: string
}

export type UiChatMessage = {
  id: string
  role: ChatRole | 'alert'
  content: string
  streaming?: boolean
  level?: string
  timestamp: number
}

export type FileMetadata = {
  path: string
  file_type: string
  size_bytes: number
  permissions: string
  owner_uid: number
  owner_gid: number
  inode: number
  hard_links: number
  modified_secs: number
  accessed_secs: number
  created_secs: number
}

export type FileEventDetail = {
  summary: string
  action_meaning: string
  is_sensitive: boolean
  file_meta: FileMetadata | null
  currently_open_by_pid: boolean
}

export type StoredEvent = {
  id: number
  ts_ms: number
  kind: string
  action: string
  pid: number
  tgid: number
  uid: number
  gid: number
  comm: string
  detail: string
  service?: string
  net_addr?: string
  net_port?: number
}

export type EventPage = {
  events: StoredEvent[]
  total: number
  page: number
  page_size: number
}

/** Adapt a StoredEvent (from history API) to the EventRecord shape used by modals. */
export function storedToEventRecord(e: StoredEvent): EventRecord {
  return {
    timestamp_ns: e.ts_ms,
    kind: e.kind,
    action: e.action,
    pid: e.pid,
    tgid: e.tgid,
    uid: e.uid,
    gid: e.gid,
    comm: e.comm,
    detail: e.detail,
    service: e.service,
    network: e.net_addr != null && e.net_port != null
      ? { address: e.net_addr, port: e.net_port }
      : undefined,
  }
}

export type AiAlertNotification = {
  timestamp: string
  level: string
  reason: string
  event_kind: string
  event_action: string
  pid: number
  comm: string
  detail: string
}
