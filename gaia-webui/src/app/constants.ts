import type { Snapshot, Tab } from './types'

export const mockSnapshot: Snapshot = {
  features: {
    file_io_agent: true,
    process_agent: true,
    network_agent: true,
    hotpatch_agent: true,
    anomaly_engine: true,
    symbol_resolver: true,
  },
  counters: { file_io: 341, process: 88, privilege: 5, network: 152, hotpatch: 11 },
  services: {
    'sshd.service': { active_state: 'active', sub_state: 'running', state: 'active (running)', pids: [721] },
    'nginx.service': { active_state: 'active', sub_state: 'running', state: 'active (running)', pids: [1142, 1145, 1148] },
    'redis.service': { active_state: 'active', sub_state: 'running', state: 'active (running)', pids: [2001] },
    'postgresql.service': { active_state: 'active', sub_state: 'running', state: 'active (running)', pids: [3010, 3011] },
  },
  events: [
    {
      timestamp_ns: Date.now() - 0,
      kind: 'network', action: 'blocked', pid: 1148, tgid: 1148, uid: 33, gid: 33,
      comm: 'nginx', detail: 'connect attempt matched blocked_ports policy',
      network: { port: 4444, address: '192.168.1.19' },
    },
    {
      timestamp_ns: Date.now() - 2000,
      kind: 'file_io', action: 'alert', pid: 721, tgid: 721, uid: 0, gid: 0,
      comm: 'sshd', detail: '/etc/shadow',
    },
    {
      timestamp_ns: Date.now() - 5000,
      kind: 'process', action: 'enter', pid: 5521, tgid: 5521, uid: 0, gid: 0,
      comm: 'bash', detail: '/usr/bin/curl',
    },
    {
      timestamp_ns: Date.now() - 8000,
      kind: 'privilege', action: 'alert', pid: 5521, tgid: 5521, uid: 1000, gid: 1000,
      comm: 'sudo', detail: 'setuid:0',
    },
    {
      timestamp_ns: Date.now() - 12000,
      kind: 'network', action: 'enter', pid: 1142, tgid: 1142, uid: 33, gid: 33,
      comm: 'nginx', detail: 'outbound connection',
      network: { port: 443, address: '93.184.216.34' },
    },
    {
      timestamp_ns: Date.now() - 15000,
      kind: 'file_io', action: 'enter', pid: 2001, tgid: 2001, uid: 999, gid: 999,
      comm: 'redis-server', detail: '/var/lib/redis/dump.rdb',
    },
    {
      timestamp_ns: Date.now() - 20000,
      kind: 'hotpatch', action: 'enter', pid: 1142, tgid: 1142, uid: 33, gid: 33,
      comm: 'nginx', detail: 'uprobe-entry',
    },
    {
      timestamp_ns: Date.now() - 25000,
      kind: 'network', action: 'rate_limited', pid: 9921, tgid: 9921, uid: 0, gid: 0,
      comm: 'scanner', detail: 'rate-limit:exceeded',
      network: { port: 80, address: '10.0.0.55' },
    },
    {
      timestamp_ns: Date.now() - 30000,
      kind: 'file_io', action: 'alert', pid: 3010, tgid: 3010, uid: 26, gid: 26,
      comm: 'postgres', detail: '/etc/ssl/private/server.key',
    },
    {
      timestamp_ns: Date.now() - 35000,
      kind: 'process', action: 'enter', pid: 7788, tgid: 7788, uid: 0, gid: 0,
      comm: 'cron', detail: '/usr/sbin/logrotate',
    },
  ],
  traffic: {
    interfaces: [
      { name: 'eth0', rx_bytes_per_sec: 125400, tx_bytes_per_sec: 48200, rx_packets_per_sec: 320, tx_packets_per_sec: 180 },
      { name: 'lo', rx_bytes_per_sec: 8500, tx_bytes_per_sec: 8500, rx_packets_per_sec: 42, tx_packets_per_sec: 42 },
    ],
    total_rx_bytes_per_sec: 125400,
    total_tx_bytes_per_sec: 48200,
  },
  alerts: [
    {
      level: 'critical',
      reason: 'Blocked outbound connection on port 4444 — active defense policy triggered',
      event: {
        timestamp_ns: Date.now(), kind: 'network', action: 'blocked',
        pid: 1148, tgid: 1148, uid: 33, gid: 33, comm: 'nginx',
        detail: 'connect attempt matched blocked_ports policy',
        network: { port: 4444, address: '192.168.1.19' },
      },
    },
    {
      level: 'high',
      reason: 'Sensitive file /etc/shadow accessed by sshd (pid 721)',
      event: {
        timestamp_ns: Date.now() - 2000, kind: 'file_io', action: 'alert',
        pid: 721, tgid: 721, uid: 0, gid: 0, comm: 'sshd', detail: '/etc/shadow',
      },
    },
    {
      level: 'high',
      reason: 'Privilege escalation: setuid:0 by sudo (pid 5521)',
      event: {
        timestamp_ns: Date.now() - 8000, kind: 'privilege', action: 'alert',
        pid: 5521, tgid: 5521, uid: 1000, gid: 1000, comm: 'sudo', detail: 'setuid:0',
      },
    },
    {
      level: 'high',
      reason: 'IP rate limit exceeded from 10.0.0.55',
      event: {
        timestamp_ns: Date.now() - 25000, kind: 'network', action: 'rate_limited',
        pid: 9921, tgid: 9921, uid: 0, gid: 0, comm: 'scanner', detail: 'rate-limit:exceeded',
        network: { port: 80, address: '10.0.0.55' },
      },
    },
    {
      level: 'medium',
      reason: 'Syscall rate exceeded for file_io: 65/s > 50/s',
      event: {
        timestamp_ns: Date.now() - 40000, kind: 'file_io', action: 'enter',
        pid: 1142, tgid: 1142, uid: 33, gid: 33, comm: 'nginx', detail: '/var/log/nginx/access.log',
      },
    },
  ],
}

export const featureMeta: [string, { zh: string; en: string; icon: string; desc_zh: string; desc_en: string }][] = [
  ['file_io_agent', { zh: '文件 I/O 代理', en: 'File I/O Agent', icon: '📁', desc_zh: '监控 openat 系统调用，检测敏感文件访问', desc_en: 'Monitors openat syscalls, detects sensitive file access' }],
  ['process_agent', { zh: '进程与权限代理', en: 'Process & Privilege Agent', icon: '⚙️', desc_zh: '追踪 execve/setuid/setgid，检测权限提升', desc_en: 'Tracks execve/setuid/setgid, detects privilege escalation' }],
  ['network_agent', { zh: '网络遥测代理', en: 'Network Telemetry Agent', icon: '🌐', desc_zh: '监控 connect/bind，检测异常外连与端口绑定', desc_en: 'Monitors connect/bind, detects abnormal outbound & port binding' }],
  ['hotpatch_agent', { zh: '热补丁代理', en: 'Hot-patching Agent', icon: '🔥', desc_zh: '通过 kprobe/uprobe 实现运行时函数热补丁', desc_en: 'Runtime function hot-patching via kprobe/uprobe' }],
  ['anomaly_engine', { zh: '异常检测引擎', en: 'Anomaly Detection Engine', icon: '🧠', desc_zh: '白名单规则校验 + 统计基线异常检测', desc_en: 'Whitelist rule checks + statistical baseline anomaly detection' }],
  ['symbol_resolver', { zh: '动态符号解析器', en: 'Symbol Resolver', icon: '🔍', desc_zh: '解析 ELF 符号表与 /proc/maps，克服 ASLR', desc_en: 'Parses ELF symbol tables & /proc/maps, bypasses ASLR' }],
]

export const tabDefs: { key: Tab; zh: string; en: string; icon: string }[] = [
  { key: 'overview', zh: '总览', en: 'Overview', icon: '📊' },
  { key: 'file', zh: '文件监控', en: 'File I/O', icon: '📁' },
  { key: 'process', zh: '进程监控', en: 'Process', icon: '⚙️' },
  { key: 'network', zh: '网络监控', en: 'Network', icon: '🌐' },
  { key: 'hotpatch', zh: '热补丁', en: 'Hotpatch', icon: '🔥' },
  { key: 'alerts', zh: '告警中心', en: 'Alerts', icon: '🚨' },
  { key: 'ai', zh: 'AI 分析', en: 'AI Analysis', icon: '🤖' },
  { key: 'config', zh: '系统配置', en: 'Config', icon: '⚡' },
]
