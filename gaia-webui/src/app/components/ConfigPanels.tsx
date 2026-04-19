import { useEffect, useState } from 'react'
import type {
  AiConfig,
  AiProvider,
  HotpatchTarget,
  KernelLivepatchTarget,
  Lang,
  LivepatchStatus,
  MonitorPolicy,
  PatchAction,
  RateLimitRule,
  TranslateFn,
} from '../types'
import { mapKind } from '../utils'

export function AiConfigPanel({ tr, flash }: { tr: TranslateFn; flash: (msg: string) => void }) {
  const [cfg, setCfg] = useState<AiConfig | null>(null)
  const [loading, setLoading] = useState(true)
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    fetch('/api/v1/ai/config')
      .then(r => r.ok ? r.json() : null)
      .then((c: AiConfig | null) => { if (c) setCfg(c) })
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [])

  const save = async (updates: Partial<AiConfig>) => {
    if (!cfg) return
    const next = { ...cfg, ...updates }
    setCfg(next)
    setSaving(true)
    try {
      const r = await fetch('/api/v1/ai/config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(updates),
      })
      if (r.ok) {
        const updated = await r.json() as AiConfig
        setCfg(updated)
        flash(tr('AI 配置已保存', 'AI config saved'))
      } else {
        flash(tr('保存失败', 'Save failed'))
      }
    } catch {
      flash(tr('保存失败: 网络错误', 'Save failed: network error'))
    }
    setSaving(false)
  }

  if (loading || !cfg) return null

  const providerLabels: Record<AiProvider, string> = {
    open_ai: 'OpenAI / Compatible',
    ollama: 'Ollama (Local)',
    custom: 'Custom',
  }

  return (
    <div className="card">
      <div className="card-header">
        <h3>🤖 {tr('AI 分析系统', 'AI Analysis System')}</h3>
        <div className="header-actions">
          <button
            className={`switch ${cfg.enabled ? 'on' : 'off'}`}
            onClick={() => save({ enabled: !cfg.enabled })}
            title={cfg.enabled ? tr('点击关闭 AI 分析', 'Click to disable AI') : tr('点击启用 AI 分析', 'Click to enable AI')}
          >
            <span className="switch-knob" />
          </button>
          <span className={`card-badge ${cfg.enabled ? '' : 'danger'}`}>
            {cfg.enabled ? tr('已启用', 'Enabled') : tr('已禁用', 'Disabled')}
          </span>
        </div>
      </div>
      <p className="card-desc">{tr(
        '集成 LLM 进行安全事件分析。启用后可在「AI 分析」标签页与 AI 交互，高危告警也会自动推送到 AI 聊天面板。',
        'Integrate an LLM for security event analysis. When enabled, interact with AI in the "AI Analysis" tab. High-severity alerts are automatically pushed to the AI chat panel.'
      )}</p>

      {cfg.enabled && (
        <div className="ai-config-form">
          <div className="config-row">
            <label>{tr('LLM 提供商', 'LLM Provider')}</label>
            <select value={cfg.provider} onChange={e => save({ provider: e.target.value as AiProvider })} disabled={saving}>
              {(Object.keys(providerLabels) as AiProvider[]).map(p => (
                <option key={p} value={p}>{providerLabels[p]}</option>
              ))}
            </select>
          </div>

          <div className="config-row">
            <label>{tr('模型名称', 'Model Name')}</label>
            <input
              type="text"
              value={cfg.model}
              placeholder={cfg.provider === 'ollama' ? 'llama3.2' : 'gpt-4o-mini'}
              onChange={e => setCfg({ ...cfg, model: e.target.value })}
              onBlur={e => save({ model: e.target.value })}
              disabled={saving}
            />
          </div>

          <div className="config-row">
            <label>{cfg.provider === 'ollama' ? tr('Ollama 地址', 'Ollama Base URL') : tr('API Base URL', 'API Base URL')}</label>
            <input
              type="text"
              value={cfg.base_url}
              placeholder={cfg.provider === 'ollama' ? 'http://localhost:11434' : 'https://api.openai.com'}
              onChange={e => setCfg({ ...cfg, base_url: e.target.value })}
              onBlur={e => save({ base_url: e.target.value })}
              disabled={saving}
            />
          </div>

          {cfg.provider !== 'ollama' && (
            <div className="config-row">
              <label>{tr('API Key', 'API Key')}</label>
              <input
                type="password"
                value={cfg.api_key}
                placeholder={tr('sk-... (留空则不发送)', 'sk-... (leave empty to skip)')}
                onChange={e => setCfg({ ...cfg, api_key: e.target.value })}
                onBlur={e => save({ api_key: e.target.value })}
                disabled={saving}
                autoComplete="off"
              />
            </div>
          )}

          <div className="ai-config-hint">
            {cfg.provider === 'ollama'
              ? tr('Ollama 本地模型无需 API Key，确保 Ollama 服务已启动并已拉取对应模型。', 'Ollama local models require no API key. Ensure Ollama is running and the model is pulled.')
              : tr('API Key 仅存储在服务端配置文件中，不会在前端明文显示。', 'API Key is stored only in the server-side config file and never shown in plaintext in the UI.')}
          </div>
        </div>
      )}
    </div>
  )
}

export function BlockedPortsPanel({ policy, setPolicy, toggle, flash, tr }: {
  policy: MonitorPolicy
  setPolicy: (p: MonitorPolicy) => void
  toggle: (section: string, index: number, enabled: boolean) => void
  flash: (msg: string) => void
  tr: TranslateFn
}) {
  const [draft, setDraft] = useState('')
  const ports = policy.blocked_ports
  const enabled = ports.filter(p => p.enabled).length

  const handleAdd = async () => {
    const port = parseInt(draft.trim(), 10)
    if (isNaN(port) || port < 1 || port > 65535) {
      flash(tr('请输入有效端口号 (1-65535)', 'Enter a valid port (1-65535)'))
      return
    }
    const body = { blocked_ports: [...ports, { port, enabled: true }] }
    try {
      const r = await fetch('/api/v1/config', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
      if (r.ok) { setPolicy(await r.json()); setDraft(''); flash(tr('已添加', 'Added')) }
    } catch {
      flash(tr('添加失败', 'Add failed'))
    }
  }

  const handleDelete = async (index: number) => {
    const items = ports.filter((_, i) => i !== index)
    const body = { blocked_ports: items }
    try {
      const r = await fetch('/api/v1/config', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) })
      if (r.ok) { setPolicy(await r.json()); flash(tr('已删除', 'Deleted')) }
    } catch {
      flash(tr('删除失败', 'Delete failed'))
    }
  }

  return (
    <div className="card">
      <div className="card-header">
        <h3>{tr('阻断端口', 'Blocked Ports')}</h3>
        <span className="card-badge">{enabled}/{ports.length} {tr('启用', 'enabled')}</span>
      </div>
      <p className="card-desc">{tr('匹配的连接将被阻断。禁用后该端口不再参与阻断规则。', 'Matching connections are blocked. Disabled ports are excluded from blocking rules.')}</p>

      {ports.length > 0 && (
        <div className="toggle-list">
          {ports.map((item, i) => (
            <div key={i} className={`toggle-row ${item.enabled ? '' : 'disabled'}`}>
              <button className={`switch ${item.enabled ? 'on' : 'off'}`} onClick={() => toggle('blocked_ports', i, !item.enabled)}>
                <span className="switch-knob" />
              </button>
              <code className="toggle-value">{item.port}</code>
              <button className="btn-danger-sm" onClick={() => handleDelete(i)}>{tr('删除', 'Delete')}</button>
            </div>
          ))}
        </div>
      )}

      <div className="add-form">
        <div className="add-row">
          <input type="number" min={1} max={65535} placeholder="4444" value={draft} onChange={e => setDraft(e.target.value)} onKeyDown={e => { if (e.key === 'Enter') handleAdd() }} />
          <button className="btn-primary" onClick={handleAdd}>{tr('添加', 'Add')}</button>
        </div>
      </div>
    </div>
  )
}

export function BaselinePanel({ policy, setPolicy, saving, setSaving, flash, lang, tr }: {
  policy: MonitorPolicy
  setPolicy: (p: MonitorPolicy) => void
  saving: boolean
  setSaving: (v: boolean) => void
  flash: (msg: string) => void
  lang: Lang
  tr: TranslateFn
}) {
  const [thresholds, setThresholds] = useState({ ...policy.baseline_thresholds })

  const handleSave = async () => {
    setSaving(true)
    try {
      const r = await fetch('/api/v1/config', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ baseline_thresholds: thresholds }) })
      if (r.ok) { setPolicy(await r.json()); flash(tr('基线阈值已保存', 'Baseline thresholds saved')) }
      else flash(tr('保存失败', 'Save failed'))
    } catch {
      flash(tr('保存失败', 'Save failed'))
    }
    setSaving(false)
  }

  return (
    <div className="card">
      <div className="card-header"><h3>{tr('基线阈值（每秒次数）', 'Baseline Thresholds (events/sec)')}</h3></div>
      <p className="card-desc">{tr('每秒事件数超过阈值时触发中危告警，10 秒冷却期内同类告警不重复触发。', 'Triggers a medium alert when events/sec exceed the threshold. Suppressed for 10s after each alert per kind.')}</p>
      <div className="threshold-grid">
        {['file_io', 'process', 'privilege', 'network', 'hotpatch'].map(k => (
          <div key={k} className="threshold-item">
            <label>{mapKind(k, lang)}</label>
            <input type="number" min={0} value={thresholds[k] ?? 0} onChange={e => setThresholds({ ...thresholds, [k]: parseInt(e.target.value, 10) || 0 })} />
          </div>
        ))}
      </div>
      <button className="btn-primary" onClick={handleSave} disabled={saving}>
        {saving ? tr('保存中...', 'Saving...') : tr('保存阈值', 'Save Thresholds')}
      </button>
    </div>
  )
}

const emptyRule: RateLimitRule = { cidr: '', max_conn_per_sec: 100, action: 'log', enabled: true }

export function RateLimitPanel({ rules, setRules, toggle, flash, tr }: {
  rules: RateLimitRule[]
  setRules: (r: RateLimitRule[]) => void
  toggle: (section: string, index: number, enabled: boolean) => void
  flash: (msg: string) => void
  tr: TranslateFn
}) {
  const [draft, setDraft] = useState<RateLimitRule>({ ...emptyRule })
  const enabled = rules.filter(r => r.enabled).length

  const handleAdd = async () => {
    if (!draft.cidr.trim()) { flash(tr('CIDR 必填', 'CIDR is required')); return }
    try {
      const r = await fetch('/api/v1/config/rate-limit', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ ...draft, cidr: draft.cidr.trim() }) })
      if (r.ok) { setRules(await r.json()); setDraft({ ...emptyRule }); flash(tr('限流规则已添加', 'Rate limit rule added')) }
      else flash(tr('添加失败: ', 'Add failed: ') + r.statusText)
    } catch {
      flash(tr('添加失败: 网络错误', 'Add failed: network error'))
    }
  }

  const handleDelete = async (index: number) => {
    try {
      const r = await fetch(`/api/v1/config/rate-limit/${index}`, { method: 'DELETE' })
      if (r.ok) { setRules(await r.json()); flash(tr('规则已删除', 'Rule deleted')) }
    } catch {
      flash(tr('删除失败', 'Delete failed'))
    }
  }

  return (
    <div className="card">
      <div className="card-header">
        <h3>{tr('IP 限流规则', 'IP Rate Limiting Rules')}</h3>
        <span className="card-badge">{enabled}/{rules.length} {tr('启用', 'enabled')}</span>
      </div>
      <p className="card-desc">{tr(
        '配置基于 CIDR 的连接速率限制。规则由网络遥测代理在内核态实时评估。',
        'Define per-CIDR connection rate limits. Rules are evaluated by the network telemetry agent in kernel space at runtime.'
      )}</p>

      {rules.length > 0 && (
        <div className="toggle-list">
          {rules.map((rule, i) => (
            <div key={i} className={`toggle-row ${rule.enabled ? '' : 'disabled'}`}>
              <button className={`switch ${rule.enabled ? 'on' : 'off'}`} onClick={() => toggle('rate_limit_rules', i, !rule.enabled)}>
                <span className="switch-knob" />
              </button>
              <div className="toggle-detail">
                <code>{rule.cidr}</code>
                <span className="toggle-meta">{rule.max_conn_per_sec} conn/s</span>
                <span className={`action-tag action-${rule.action}`}>{rule.action}</span>
              </div>
              <button className="btn-danger-sm" onClick={() => handleDelete(i)}>{tr('删除', 'Delete')}</button>
            </div>
          ))}
        </div>
      )}

      <div className="add-form">
        <h4>{tr('新增规则', 'Add Rule')}</h4>
        <div className="add-row">
          <input type="text" placeholder="10.0.0.0/8" value={draft.cidr} onChange={e => setDraft({ ...draft, cidr: e.target.value })} />
          <input type="number" min={1} placeholder="100" value={draft.max_conn_per_sec} onChange={e => setDraft({ ...draft, max_conn_per_sec: parseInt(e.target.value, 10) || 1 })} />
          <select value={draft.action} onChange={e => setDraft({ ...draft, action: e.target.value as RateLimitRule['action'] })}>
            <option value="log">{tr('记录', 'Log')}</option>
            <option value="block">{tr('阻断', 'Block')}</option>
            <option value="throttle">{tr('限速', 'Throttle')}</option>
          </select>
          <button className="btn-primary" onClick={handleAdd}>{tr('添加', 'Add')}</button>
        </div>
      </div>
    </div>
  )
}

const emptyTarget: HotpatchTarget = { binary: '', symbol: '', pid: null, enabled: true, patch_action: 'monitor', override_return_value: 0, replace_lib: null, replace_symbol: null }

const patchActionLabel = (action: PatchAction, tr: TranslateFn) => {
  switch (action) {
    case 'monitor': return tr('监控', 'Monitor')
    case 'override_return': return tr('替换返回值', 'Override Return')
    case 'skip_call': return tr('跳过调用', 'Skip Call')
    case 'replace_function': return tr('函数替换', 'Replace Function')
  }
}

const patchActionClass = (action: PatchAction) => {
  switch (action) {
    case 'monitor': return 'action-log'
    case 'override_return': return 'action-blocked'
    case 'skip_call': return 'action-alert'
    case 'replace_function': return 'action-replace'
  }
}

export function HotpatchConfigPanel({ targets, setTargets, toggle, flash, tr }: {
  targets: HotpatchTarget[]
  setTargets: (t: HotpatchTarget[]) => void
  toggle: (section: string, index: number, enabled: boolean) => void
  flash: (msg: string) => void
  tr: TranslateFn
}) {
  const [draft, setDraft] = useState<HotpatchTarget>({ ...emptyTarget })
  const [reloading, setReloading] = useState(false)
  const [uploading, setUploading] = useState(false)
  const [uploadedLib, setUploadedLib] = useState<string | null>(null)
  const enabled = targets.filter(t => t.enabled).length
  const overrides = targets.filter(t => t.enabled && t.patch_action !== 'monitor').length

  const handleUploadLib = async (file: File) => {
    setUploading(true)
    try {
      const form = new FormData()
      form.append('file', file)
      const r = await fetch('/api/v1/upload-lib', { method: 'POST', body: form })
      if (r.ok) {
        const data = await r.json() as { path: string; size: number; arch: string; name: string }
        setUploadedLib(data.path)
        setDraft(d => ({ ...d, replace_lib: data.path }))
        flash(tr(`库已上传: ${data.name} (${data.arch}, ${data.size} bytes)`, `Library uploaded: ${data.name} (${data.arch}, ${data.size} bytes)`))
      } else {
        flash(tr('上传失败: ', 'Upload failed: ') + await r.text())
      }
    } catch {
      flash(tr('上传失败: 网络错误', 'Upload failed: network error'))
    }
    setUploading(false)
  }

  const handleAdd = async () => {
    if (!draft.binary.trim() || !draft.symbol.trim()) { flash(tr('二进制路径和符号名必填', 'Binary path and symbol name are required')); return }
    if (draft.patch_action === 'replace_function' && !draft.replace_lib) {
      flash(tr('函数替换模式需要先上传动态链接库', 'Replace function mode requires uploading a shared library first'))
      return
    }
    if (draft.patch_action === 'replace_function' && !draft.pid) {
      flash(tr('函数替换模式需要指定 PID', 'Replace function mode requires a PID'))
      return
    }
    const payload: Record<string, unknown> = {
      binary: draft.binary.trim(),
      symbol: draft.symbol.trim(),
      pid: draft.pid || null,
      enabled: true,
      patch_action: draft.patch_action,
      override_return_value: draft.override_return_value,
    }
    if (draft.patch_action === 'replace_function') {
      payload.replace_lib = draft.replace_lib
      payload.replace_symbol = draft.replace_symbol?.trim() || null
    }
    try {
      const r = await fetch('/api/v1/config/hotpatch', { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(payload) })
      if (r.ok) { setTargets(await r.json()); setDraft({ ...emptyTarget }); setUploadedLib(null); flash(tr('热补丁目标已添加', 'Hotpatch target added')) }
      else flash(tr('添加失败: ', 'Add failed: ') + await r.text())
    } catch {
      flash(tr('添加失败: 网络错误', 'Add failed: network error'))
    }
  }

  const handleDelete = async (index: number) => {
    try {
      const r = await fetch(`/api/v1/config/hotpatch/${index}`, { method: 'DELETE' })
      if (r.ok) { setTargets(await r.json()); flash(tr('目标已删除', 'Target removed')) }
    } catch {
      flash(tr('删除失败', 'Delete failed'))
    }
  }

  const handleUpdateTarget = async (index: number, updates: Partial<HotpatchTarget>) => {
    const target = { ...targets[index], ...updates }
    try {
      const r = await fetch('/api/v1/config/hotpatch', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ index, ...target }),
      })
      if (r.ok) { setTargets(await r.json()); flash(tr('已更新', 'Updated')) }
    } catch {
      flash(tr('更新失败', 'Update failed'))
    }
  }

  const handleReload = async () => {
    setReloading(true)
    try {
      const r = await fetch('/api/v1/reload-hotpatch', { method: 'POST' })
      const data = await r.json() as { success: boolean; message: string; targets_count: number }
      flash(data.success
        ? tr(`探针重载成功，已处理 ${data.targets_count} 个目标`, `Reload succeeded: ${data.targets_count} target(s) processed`)
        : tr('重载失败: ', 'Reload failed: ') + data.message)
    } catch {
      flash(tr('重载失败: 网络错误', 'Reload failed: network error'))
    }
    setReloading(false)
  }

  return (
    <div className="card">
      <div className="card-header">
        <h3>{tr('热补丁 — 运行期函数替换', 'Hot-Patch — Runtime Function Replacement')}</h3>
        <div className="header-actions">
          <button className="btn-reload" onClick={handleReload} disabled={reloading || targets.length === 0}>
            {reloading ? tr('重载中...', 'Reloading...') : tr('重载探针', 'Reload Probes')}
          </button>
          <span className="card-badge">{enabled}/{targets.length} {tr('启用', 'enabled')}</span>
          {overrides > 0 && <span className="card-badge danger">{overrides} {tr('替换中', 'overriding')}</span>}
        </div>
      </div>
      <p className="card-desc">{tr(
        '通过 uprobe/uretprobe 在运行时挂载到目标函数。支持四种模式：监控（仅记录出入口）、替换返回值（通过 bpf_override_return 强制函数返回指定值）、跳过调用（语义同替换返回值）、函数替换（上传编译好的 .so 动态链接库，通过 ptrace 注入并用 trampoline 替换原函数实现，无需停机重启）。修改补丁动作后需点击"重载探针"生效。',
        'Attach uprobe/uretprobe to target functions at runtime. Four modes: Monitor (log entry/exit only), Override Return (force return value via bpf_override_return), Skip Call (same mechanism, marked as "skip"), Replace Function (upload a compiled .so, inject via ptrace and replace the original function with a trampoline — zero-downtime). Click "Reload Probes" after changing patch actions.'
      )}</p>

      {targets.length > 0 && (
        <div className="toggle-list">
          {targets.map((t, i) => (
            <div key={i} className={`toggle-row hotpatch-row ${t.enabled ? '' : 'disabled'}`}>
              <button className={`switch ${t.enabled ? 'on' : 'off'}`} onClick={() => toggle('hotpatch_targets', i, !t.enabled)}>
                <span className="switch-knob" />
              </button>
              <div className="toggle-detail hotpatch-detail">
                <div className="hotpatch-main">
                  <code>{t.binary}</code>
                  <span className="toggle-meta">{t.symbol}</span>
                  <span className="toggle-meta">PID: {t.pid ?? tr('全部', 'all')}</span>
                </div>
                <div className="hotpatch-action-row">
                  <select className="hotpatch-action-select" value={t.patch_action} onChange={e => handleUpdateTarget(i, { patch_action: e.target.value as PatchAction })} disabled={!t.enabled}>
                    <option value="monitor">{tr('监控', 'Monitor')}</option>
                    <option value="override_return">{tr('替换返回值', 'Override Return')}</option>
                    <option value="skip_call">{tr('跳过调用', 'Skip Call')}</option>
                    <option value="replace_function">{tr('函数替换', 'Replace Function')}</option>
                  </select>
                  {(t.patch_action === 'override_return' || t.patch_action === 'skip_call') && (
                    <div className="hotpatch-retval">
                      <label>{tr('返回值:', 'Return:')}</label>
                      <input
                        type="number"
                        className="hotpatch-retval-input"
                        value={t.override_return_value}
                        onChange={e => handleUpdateTarget(i, { override_return_value: parseInt(e.target.value, 10) || 0 })}
                        disabled={!t.enabled}
                        title={tr('常用值: 0=成功, -1=EPERM, -13=EACCES, -22=EINVAL', 'Common: 0=success, -1=EPERM, -13=EACCES, -22=EINVAL')}
                      />
                    </div>
                  )}
                  {t.patch_action === 'replace_function' && t.replace_lib && (
                    <span className="toggle-meta" title={t.replace_lib}>.so: {t.replace_lib.split('/').pop()}</span>
                  )}
                  {t.patch_action === 'replace_function' && t.replace_symbol && (
                    <span className="toggle-meta">→ {t.replace_symbol}</span>
                  )}
                  <span className={`action-tag ${patchActionClass(t.patch_action)}`}>
                    {patchActionLabel(t.patch_action, tr)}
                  </span>
                </div>
              </div>
              <button className="btn-danger-sm" onClick={() => handleDelete(i)}>{tr('删除', 'Delete')}</button>
            </div>
          ))}
        </div>
      )}

      <div className="add-form">
        <h4>{tr('新增目标', 'Add Target')}</h4>
        <div className="add-row">
          <input type="text" placeholder="/usr/sbin/nginx" value={draft.binary} onChange={e => setDraft({ ...draft, binary: e.target.value })} />
          <input type="text" placeholder="ngx_http_process_request" value={draft.symbol} onChange={e => setDraft({ ...draft, symbol: e.target.value })} />
          <input type="number" min={0} placeholder={tr('PID（可选）', 'PID (optional)')} value={draft.pid ?? ''} onChange={e => setDraft({ ...draft, pid: e.target.value ? parseInt(e.target.value, 10) : null })} />
          <select value={draft.patch_action} onChange={e => setDraft({ ...draft, patch_action: e.target.value as PatchAction })}>
            <option value="monitor">{tr('监控', 'Monitor')}</option>
            <option value="override_return">{tr('替换返回值', 'Override Return')}</option>
            <option value="skip_call">{tr('跳过调用', 'Skip Call')}</option>
            <option value="replace_function">{tr('函数替换', 'Replace Function')}</option>
          </select>
          {(draft.patch_action === 'override_return' || draft.patch_action === 'skip_call') && (
            <input type="number" placeholder={tr('返回值 (如 -1)', 'Return value (e.g. -1)')} value={draft.override_return_value} onChange={e => setDraft({ ...draft, override_return_value: parseInt(e.target.value, 10) || 0 })} />
          )}
          <button className="btn-primary" onClick={handleAdd}>{tr('添加', 'Add')}</button>
        </div>
        {draft.patch_action === 'replace_function' && (
          <div className="add-row" style={{ marginTop: 10 }}>
            <label className="btn-upload" style={{
              padding: '8px 16px', background: uploadedLib ? '#f0fdf4' : '#f8fafc',
              border: `1px solid ${uploadedLib ? '#bbf7d0' : '#e2e8f0'}`, borderRadius: 8,
              fontSize: '12.5px', cursor: 'pointer', display: 'inline-flex', alignItems: 'center', gap: 6,
            }}>
              {uploading ? tr('上传中...', 'Uploading...') : uploadedLib ? `✅ ${uploadedLib.split('/').pop()}` : tr('📁 上传 .so 动态链接库', '📁 Upload .so Library')}
              <input
                type="file"
                accept=".so,.so.*"
                style={{ display: 'none' }}
                onChange={e => { const f = e.target.files?.[0]; if (f) handleUploadLib(f); e.target.value = '' }}
                disabled={uploading}
              />
            </label>
            <input
              type="text"
              placeholder={tr('替换符号名（可选，默认同原符号）', 'Replace symbol (optional, defaults to original)')}
              value={draft.replace_symbol ?? ''}
              onChange={e => setDraft({ ...draft, replace_symbol: e.target.value || null })}
              style={{ minWidth: 240 }}
            />
          </div>
        )}
      </div>
    </div>
  )
}

const emptyKlpTarget: KernelLivepatchTarget = {
  old_func: '',
  new_func_body: '    return 0;',
  func_ret: 'static int',
  func_args: 'void',
  obj_name: null,
  enabled: true,
}

export function KernelLivepatchPanel({ targets, setTargets, flash, tr }: {
  targets: KernelLivepatchTarget[]
  setTargets: (t: KernelLivepatchTarget[]) => void
  flash: (msg: string) => void
  tr: TranslateFn
}) {
  const [draft, setDraft] = useState<KernelLivepatchTarget>({ ...emptyKlpTarget })
  const [status, setStatus] = useState<LivepatchStatus[]>([])
  const [reloading, setReloading] = useState(false)

  const fetchStatus = async () => {
    try {
      const r = await fetch('/api/v1/kernel-livepatch/status')
      if (r.ok) setStatus(await r.json())
    } catch { /* offline */ }
  }

  useEffect(() => { fetchStatus() }, [])

  const handleToggle = async (index: number, enabled: boolean) => {
    const updated = { ...targets[index], enabled }
    try {
      const r = await fetch(`/api/v1/config/kernel-livepatch/${index}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(updated),
      })
      if (r.ok) {
        setTargets(await r.json())
        flash(enabled ? tr('已启用', 'Enabled') : tr('已禁用', 'Disabled'))
      } else {
        flash(tr('切换失败', 'Toggle failed'))
      }
    } catch {
      flash(tr('切换失败: 网络错误', 'Toggle failed: network error'))
    }
  }

  const handleAdd = async () => {
    if (!draft.old_func.trim()) {
      flash(tr('内核函数名必填', 'Kernel function name is required'))
      return
    }
    if (!draft.new_func_body.trim()) {
      flash(tr('替换函数体必填', 'Replacement function body is required'))
      return
    }
    try {
      const r = await fetch('/api/v1/config/kernel-livepatch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ...draft, old_func: draft.old_func.trim() }),
      })
      if (r.ok) {
        setTargets(await r.json())
        setDraft({ ...emptyKlpTarget })
        flash(tr('内核补丁目标已添加', 'Kernel livepatch target added'))
      } else {
        flash(tr('添加失败: ', 'Add failed: ') + await r.text())
      }
    } catch {
      flash(tr('添加失败: 网络错误', 'Add failed: network error'))
    }
  }

  const handleDelete = async (index: number) => {
    try {
      const r = await fetch(`/api/v1/config/kernel-livepatch/${index}`, { method: 'DELETE' })
      if (r.ok) { setTargets(await r.json()); flash(tr('目标已删除', 'Target removed')) }
    } catch {
      flash(tr('删除失败', 'Delete failed'))
    }
  }

  const handleReload = async () => {
    setReloading(true)
    try {
      const r = await fetch('/api/v1/kernel-livepatch/reload', { method: 'POST' })
      const data = await r.json() as { success: boolean; message: string; module_name: string | null }
      flash(data.success
        ? tr(`内核补丁已应用: ${data.module_name ?? ''}`, `Kernel livepatch applied: ${data.module_name ?? ''}`)
        : tr('应用失败: ', 'Apply failed: ') + data.message)
      await fetchStatus()
    } catch {
      flash(tr('应用失败: 网络错误', 'Apply failed: network error'))
    }
    setReloading(false)
  }

  const enabled = targets.filter(t => t.enabled).length

  return (
    <div className="card">
      <div className="card-header">
        <h3>{tr('内核热补丁 (Kernel Livepatch)', 'Kernel Livepatch')}</h3>
        <div className="header-actions">
          <button className="btn-reload" onClick={handleReload} disabled={reloading || enabled === 0}>
            {reloading ? tr('应用中...', 'Applying...') : tr('应用补丁', 'Apply Patches')}
          </button>
          <span className="card-badge">{enabled}/{targets.length} {tr('启用', 'enabled')}</span>
        </div>
      </div>
      <p className="card-desc">{tr(
        '通过 Linux klp_patch API 在内核态替换函数，无需重启内核。需要 root 权限、CONFIG_LIVEPATCH=y 和 kernel-devel 头文件。补丁以 C 内核模块形式编译并通过 insmod 加载。',
        'Replace kernel functions via the Linux klp_patch API without rebooting. Requires root, CONFIG_LIVEPATCH=y, and kernel-devel headers. Patches are compiled as C kernel modules and loaded via insmod.'
      )}</p>

      {status.length > 0 && (
        <div className="toggle-list" style={{ marginBottom: 12 }}>
          <div style={{ fontSize: 12, color: 'var(--text-muted)', marginBottom: 6 }}>
            {tr('已加载模块', 'Loaded Modules')}
          </div>
          {status.map(s => (
            <div key={s.name} className="toggle-row">
              <code className="toggle-value">{s.name}</code>
              <span className={`action-tag ${s.enabled ? 'action-replace' : 'action-log'}`}>
                {s.enabled ? tr('已激活', 'active') : tr('已禁用', 'disabled')}
              </span>
              <span className="toggle-meta">{s.state}</span>
            </div>
          ))}
        </div>
      )}

      {targets.length > 0 && (
        <div className="toggle-list">
          {targets.map((t, i) => (
            <div key={i} className={`toggle-row hotpatch-row ${t.enabled ? '' : 'disabled'}`}>
              <button
                className={`switch ${t.enabled ? 'on' : 'off'}`}
                onClick={() => handleToggle(i, !t.enabled)}
                title={t.enabled ? tr('点击禁用', 'Click to disable') : tr('点击启用', 'Click to enable')}
              >
                <span className="switch-knob" />
              </button>
              <div className="toggle-detail hotpatch-detail" style={{ flex: 1 }}>
                <div className="hotpatch-main">
                  <code>{t.old_func}</code>
                  <span className="toggle-meta">{t.func_ret}({t.func_args})</span>
                  {t.obj_name && <span className="toggle-meta">mod: {t.obj_name}</span>}
                </div>
                <pre style={{ margin: '4px 0 0', fontSize: 11, color: 'var(--text-muted)', whiteSpace: 'pre-wrap', wordBreak: 'break-all', background: 'none' }}>
                  {t.new_func_body.trim().slice(0, 120)}{t.new_func_body.trim().length > 120 ? '…' : ''}
                </pre>
              </div>
              <button className="btn-danger-sm" onClick={() => handleDelete(i)}>{tr('删除', 'Delete')}</button>
            </div>
          ))}
        </div>
      )}

      <div className="add-form">
        <h4>{tr('新增内核补丁目标', 'Add Kernel Livepatch Target')}</h4>
        <div className="add-row" style={{ flexWrap: 'wrap', gap: 8 }}>
          <input
            type="text"
            placeholder={tr('内核函数名, 如 cmdline_proc_show', 'Kernel function, e.g. cmdline_proc_show')}
            value={draft.old_func}
            onChange={e => setDraft({ ...draft, old_func: e.target.value })}
            style={{ minWidth: 220 }}
          />
          <input
            type="text"
            placeholder={tr('返回类型, 如 static int', 'Return type, e.g. static int')}
            value={draft.func_ret}
            onChange={e => setDraft({ ...draft, func_ret: e.target.value })}
            style={{ minWidth: 150 }}
          />
          <input
            type="text"
            placeholder={tr('参数列表, 如 struct seq_file *m, void *v', 'Args, e.g. struct seq_file *m, void *v')}
            value={draft.func_args}
            onChange={e => setDraft({ ...draft, func_args: e.target.value })}
            style={{ minWidth: 260 }}
          />
          <input
            type="text"
            placeholder={tr('内核模块名（留空=vmlinux）', 'Kernel module (empty = vmlinux)')}
            value={draft.obj_name ?? ''}
            onChange={e => setDraft({ ...draft, obj_name: e.target.value || null })}
            style={{ minWidth: 160 }}
          />
        </div>
        <div style={{ marginTop: 8 }}>
          <label style={{ fontSize: 12, color: 'var(--text-muted)', display: 'block', marginBottom: 4 }}>
            {tr('替换函数体 (C 代码，函数体内容)', 'Replacement function body (C code inside { })')}
          </label>
          <textarea
            rows={5}
            style={{ width: '100%', fontFamily: 'monospace', fontSize: 12, padding: '8px 10px', borderRadius: 6, border: '1px solid var(--border)', background: 'var(--bg-input, #f8fafc)', resize: 'vertical', boxSizing: 'border-box' }}
            placeholder={'    seq_puts(m, "GAIA_PROTECTED\\n");\n    return 0;'}
            value={draft.new_func_body}
            onChange={e => setDraft({ ...draft, new_func_body: e.target.value })}
          />
        </div>
        <div style={{ marginTop: 8 }}>
          <button className="btn-primary" onClick={handleAdd}>{tr('添加目标', 'Add Target')}</button>
        </div>
      </div>
    </div>
  )
}
