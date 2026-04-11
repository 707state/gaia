import type { Lang } from './types'

export function initialLang(): Lang {
  const saved = localStorage.getItem('gaia_lang')
  if (saved === 'zh' || saved === 'en') return saved
  return navigator.language.toLowerCase().startsWith('zh') ? 'zh' : 'en'
}

export function mapKind(kind: string, lang: Lang) {
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

export function mapAction(action: string, lang: Lang) {
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

export function formatTimestamp(ns: number) {
  const ms = ns / 1e6
  const d = new Date(ms)
  if (isNaN(d.getTime())) return '-'
  return d.toLocaleTimeString(undefined, { hour: '2-digit', minute: '2-digit', second: '2-digit' })
}

export function relativeTime(ns: number, lang: Lang) {
  const diff = Date.now() - ns / 1e6
  if (diff < 0 || isNaN(diff)) return '-'
  const secs = Math.floor(diff / 1000)
  if (secs < 60) return lang === 'zh' ? `${secs}秒前` : `${secs}s ago`
  const mins = Math.floor(secs / 60)
  if (mins < 60) return lang === 'zh' ? `${mins}分钟前` : `${mins}m ago`
  const hrs = Math.floor(mins / 60)
  return lang === 'zh' ? `${hrs}小时前` : `${hrs}h ago`
}
