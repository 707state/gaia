import type { Lang, Snapshot } from './types'

export function initialLang(): Lang {
  const saved = localStorage.getItem('gaia_lang')
  if (saved === 'zh' || saved === 'en') return saved
  return navigator.language.toLowerCase().startsWith('zh') ? 'zh' : 'en'
}

export function mapKind(kind: string, lang: Lang) {
  const m: Record<string, { zh: string; en: string }> = {
    file_io: { zh: '文件 I/O', en: 'File I/O' },
    process: { zh: '进程', en: 'Process' },
    privilege: { zh: '权限', en: 'Privilege' },
    network: { zh: '网络', en: 'Network' },
    hotpatch: { zh: '热补丁', en: 'Hotpatch' },
    unknown: { zh: '未知', en: 'Unknown' },
  }
  return (m[kind] ?? { zh: kind, en: kind })[lang]
}

export function mapAction(action: string, lang: Lang) {
  const m: Record<string, { zh: string; en: string }> = {
    enter: { zh: '进入', en: 'Enter' },
    exit: { zh: '退出', en: 'Exit' },
    alert: { zh: '告警', en: 'Alert' },
    blocked: { zh: '阻断', en: 'Blocked' },
    rate_limited: { zh: '限流', en: 'Rate Limited' },
    bind: { zh: '监听', en: 'Bind' },
    kill: { zh: '终止', en: 'Kill' },
    kill_request: { zh: '阻断(SIGKILL)', en: 'Kill (SIGKILL)' },
    unknown: { zh: '未知', en: 'Unknown' },
  }
  return (m[action] ?? { zh: action, en: action })[lang]
}

export function actionColor(action: string): string {
  const m: Record<string, string> = {
    alert: 'orange',
    blocked: 'red',
    rate_limited: 'purple',
    kill_request: 'magenta',
    kill: 'red',
    bind: 'gold',
    enter: 'green',
    exit: 'default',
  }
  return m[action] ?? 'default'
}

export function levelColor(level: string): string {
  const m: Record<string, string> = {
    critical: 'red',
    high: 'orange',
    medium: 'gold',
    low: 'blue',
  }
  return m[level] ?? 'default'
}

export function formatTs(ns: number): string {
  const ms = ns / 1e6
  const d = new Date(ms)
  return d.toLocaleTimeString(undefined, {
    hour12: false,
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
  })
}

export function kindColor(kind: string): string {
  const m: Record<string, string> = {
    file_io: '#1890ff',
    process: '#722ed1',
    privilege: '#f5222d',
    network: '#13c2c2',
    hotpatch: '#fa8c16',
  }
  return m[kind] ?? '#8c8c8c'
}

export const featureMeta: Array<[string, { zh: string; en: string }]> = [
  ['file_io_agent', { zh: '文件 I/O 代理', en: 'File I/O Agent' }],
  ['process_agent', { zh: '进程与权限代理', en: 'Process & Privilege Agent' }],
  ['network_agent', { zh: '网络遥测代理', en: 'Network Telemetry Agent' }],
  ['hotpatch_agent', { zh: '热补丁代理', en: 'Hot-patching Agent' }],
  ['anomaly_engine', { zh: '异常检测引擎', en: 'Anomaly Detection Engine' }],
  ['symbol_resolver', { zh: '符号解析器', en: 'Symbol Resolver' }],
  ['traffic_agent', { zh: '流量监控代理', en: 'Traffic Monitor Agent' }],
]

export const emptySnapshot: Snapshot = {
  features: {
    file_io_agent: false,
    process_agent: false,
    network_agent: false,
    hotpatch_agent: false,
    anomaly_engine: false,
    symbol_resolver: false,
    traffic_agent: false,
  },
  counters: {},
  services: {},
  events: [],
  alerts: [],
  total_events: 0,
}
