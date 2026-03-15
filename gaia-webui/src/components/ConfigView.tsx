import { useEffect, useState } from 'react'
import {
  Card, Form, Input, Button, InputNumber, Select, Switch, Table, Tag,
  Space, Popconfirm, message, Spin, Typography, Divider, Alert, Collapse,
} from 'antd'
import {
  SaveOutlined, PlusOutlined, DeleteOutlined, SettingOutlined,
  SafetyCertificateOutlined, ThunderboltOutlined,
} from '@ant-design/icons'
import type { Lang, MonitorPolicy, RateLimitRule, HotpatchTarget } from '../types'
import { mapKind } from '../helpers'

const { TextArea } = Input
const { Text } = Typography

export default function ConfigView({
  lang,
  tr,
}: {
  lang: Lang
  tr: (zh: string, en: string) => string
}) {
  const [policy, setPolicy] = useState<MonitorPolicy | null>(null)
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    let cancelled = false
    const load = async () => {
      try {
        const r = await fetch('/api/v1/config')
        if (r.ok && !cancelled) setPolicy(await r.json())
      } catch { /* offline */ }
      if (!cancelled) setLoading(false)
    }
    load()
    return () => { cancelled = true }
  }, [])

  if (loading) return <Spin size="large" style={{ display: 'block', margin: '80px auto' }} />
  if (!policy) return (
    <Alert
      type="error"
      message={tr('加载配置失败', 'Failed to load configuration')}
      description={tr('后端可能离线', 'Backend may be offline')}
      showIcon
      style={{ margin: 20 }}
    />
  )

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      <GeneralPolicyPanel policy={policy} setPolicy={setPolicy} lang={lang} tr={tr} />
      <RateLimitPanel
        rules={policy.rate_limit_rules}
        setRules={(rules) => setPolicy({ ...policy, rate_limit_rules: rules })}
        lang={lang}
        tr={tr}
      />
      <HotpatchPanel
        targets={policy.hotpatch.targets}
        setTargets={(targets) => setPolicy({ ...policy, hotpatch: { targets } })}
        lang={lang}
        tr={tr}
      />
    </div>
  )
}

function GeneralPolicyPanel({
  policy, setPolicy, lang, tr,
}: {
  policy: MonitorPolicy
  setPolicy: (p: MonitorPolicy) => void
  lang: Lang
  tr: (zh: string, en: string) => string
}) {
  const [form] = Form.useForm()
  const [saving, setSaving] = useState(false)

  useEffect(() => {
    form.setFieldsValue({
      sensitive_prefixes: policy.sensitive_prefixes.join('\n'),
      exec_whitelist_prefixes: policy.exec_whitelist_prefixes.join('\n'),
      monitored_services: policy.monitored_services.join('\n'),
      blocked_ports: policy.blocked_ports.join(', '),
      ...Object.fromEntries(
        ['file_io', 'process', 'privilege', 'network', 'hotpatch'].map((k) => [
          `threshold_${k}`,
          policy.baseline_thresholds[k] ?? 0,
        ]),
      ),
    })
  }, [policy, form])

  const handleSave = async () => {
    setSaving(true)
    try {
      const vals = await form.validateFields()
      const body = {
        sensitive_prefixes: (vals.sensitive_prefixes as string).split('\n').map((s: string) => s.trim()).filter(Boolean),
        exec_whitelist_prefixes: (vals.exec_whitelist_prefixes as string).split('\n').map((s: string) => s.trim()).filter(Boolean),
        monitored_services: (vals.monitored_services as string).split('\n').map((s: string) => s.trim()).filter(Boolean),
        blocked_ports: (vals.blocked_ports as string).split(',').map((s: string) => parseInt(s.trim(), 10)).filter((n: number) => !isNaN(n)),
        baseline_thresholds: Object.fromEntries(
          ['file_io', 'process', 'privilege', 'network', 'hotpatch'].map((k) => [
            k,
            vals[`threshold_${k}`] ?? 0,
          ]),
        ),
      }
      const r = await fetch('/api/v1/config', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      })
      if (r.ok) {
        setPolicy(await r.json())
        message.success(tr('通用策略已保存', 'General policy saved'))
      } else {
        message.error(tr('保存失败', 'Save failed'))
      }
    } catch {
      message.error(tr('保存失败', 'Save failed'))
    }
    setSaving(false)
  }

  return (
    <Card
      title={<Space><SettingOutlined />{tr('通用监控策略', 'General Monitoring Policy')}</Space>}
      style={{ borderRadius: 12 }}
    >
      <Form form={form} layout="vertical">
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(300px, 1fr))', gap: 16 }}>
          <Form.Item name="sensitive_prefixes" label={tr('敏感文件前缀', 'Sensitive File Prefixes')}>
            <TextArea rows={4} placeholder="/etc/shadow&#10;/etc/ssl&#10;/root/.ssh" style={{ fontFamily: 'monospace' }} />
          </Form.Item>
          <Form.Item name="exec_whitelist_prefixes" label={tr('可执行白名单前缀', 'Exec Whitelist Prefixes')}>
            <TextArea rows={4} placeholder="/usr/bin&#10;/usr/sbin" style={{ fontFamily: 'monospace' }} />
          </Form.Item>
          <Form.Item name="monitored_services" label={tr('监控服务', 'Monitored Services')}>
            <TextArea rows={4} placeholder="sshd.service&#10;nginx.service" style={{ fontFamily: 'monospace' }} />
          </Form.Item>
          <Form.Item name="blocked_ports" label={tr('阻断端口', 'Blocked Ports')}>
            <Input placeholder="4444, 31337" style={{ fontFamily: 'monospace' }} />
          </Form.Item>
        </div>

        <Divider>{tr('基线阈值（每 30 秒窗口）', 'Baseline Thresholds (per 30s window)')}</Divider>
        <div style={{ display: 'flex', flexWrap: 'wrap', gap: 16 }}>
          {['file_io', 'process', 'privilege', 'network', 'hotpatch'].map((k) => (
            <Form.Item key={k} name={`threshold_${k}`} label={mapKind(k, lang)} style={{ minWidth: 140 }}>
              <InputNumber min={0} style={{ width: '100%' }} />
            </Form.Item>
          ))}
        </div>

        <Button type="primary" icon={<SaveOutlined />} onClick={handleSave} loading={saving}>
          {tr('保存通用策略', 'Save General Policy')}
        </Button>
      </Form>
    </Card>
  )
}

function RateLimitPanel({
  rules, setRules, tr,
}: {
  rules: RateLimitRule[]
  setRules: (r: RateLimitRule[]) => void
  lang: Lang
  tr: (zh: string, en: string) => string
}) {
  const [form] = Form.useForm()

  const handleAdd = async () => {
    try {
      const vals = await form.validateFields()
      const rule: RateLimitRule = {
        cidr: vals.cidr.trim(),
        max_conn_per_sec: vals.max_conn_per_sec,
        action: vals.action,
        enabled: vals.enabled ?? true,
      }
      const r = await fetch('/api/v1/config/rate-limit', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(rule),
      })
      if (r.ok) {
        setRules(await r.json())
        form.resetFields()
        message.success(tr('限流规则已添加', 'Rate limit rule added'))
      }
    } catch { /* validation */ }
  }

  const handleDelete = async (index: number) => {
    const r = await fetch(`/api/v1/config/rate-limit/${index}`, { method: 'DELETE' })
    if (r.ok) {
      setRules(await r.json())
      message.success(tr('规则已删除', 'Rule deleted'))
    }
  }

  const handleToggle = async (index: number) => {
    const rule = { ...rules[index], enabled: !rules[index].enabled }
    const r = await fetch('/api/v1/config/rate-limit', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ index, ...rule }),
    })
    if (r.ok) {
      setRules(await r.json())
    }
  }

  return (
    <Card
      title={<Space><SafetyCertificateOutlined />{tr('IP 限流规则', 'IP Rate Limiting')}</Space>}
      style={{ borderRadius: 12 }}
    >
      <Text type="secondary" style={{ display: 'block', marginBottom: 16 }}>
        {tr(
          '配置基于 CIDR 的连接速率限制。规则由网络遥测代理在内核中实时评估。',
          'Configure per-CIDR connection rate limits evaluated by the network agent in kernel.',
        )}
      </Text>

      <Table
        dataSource={rules.map((r, i) => ({ ...r, _idx: i }))}
        rowKey="_idx"
        size="small"
        pagination={false}
        locale={{ emptyText: tr('暂无限流规则', 'No rate limit rules') }}
        columns={[
          { title: 'CIDR', dataIndex: 'cidr', render: (v: string) => <Text code>{v}</Text> },
          { title: tr('最大连接/秒', 'Max Conn/s'), dataIndex: 'max_conn_per_sec', width: 120 },
          {
            title: tr('动作', 'Action'), dataIndex: 'action', width: 100,
            render: (v: string) => <Tag color={v === 'block' ? 'red' : v === 'throttle' ? 'gold' : 'blue'}>{v}</Tag>,
          },
          {
            title: tr('启用', 'Enabled'), dataIndex: 'enabled', width: 80,
            render: (v: boolean, _r: RateLimitRule & { _idx: number }) => (
              <Switch checked={v} size="small" onChange={() => handleToggle(_r._idx)} />
            ),
          },
          {
            title: tr('操作', 'Actions'), width: 80,
            render: (_: unknown, r: RateLimitRule & { _idx: number }) => (
              <Popconfirm title={tr('确认删除？', 'Confirm delete?')} onConfirm={() => handleDelete(r._idx)}>
                <Button type="text" danger icon={<DeleteOutlined />} size="small" />
              </Popconfirm>
            ),
          },
        ]}
      />

      <Collapse
        ghost
        style={{ marginTop: 12 }}
        items={[{
          key: 'add',
          label: <Space><PlusOutlined />{tr('新增规则', 'Add Rule')}</Space>,
          children: (
            <Form form={form} layout="inline" style={{ flexWrap: 'wrap', gap: 8 }}
              initialValues={{ max_conn_per_sec: 100, action: 'log', enabled: true }}
            >
              <Form.Item name="cidr" rules={[{ required: true, message: 'CIDR' }]}>
                <Input placeholder="10.0.0.0/8" style={{ width: 160, fontFamily: 'monospace' }} />
              </Form.Item>
              <Form.Item name="max_conn_per_sec">
                <InputNumber min={1} placeholder="100" style={{ width: 100 }} />
              </Form.Item>
              <Form.Item name="action">
                <Select style={{ width: 100 }} options={[
                  { value: 'log', label: tr('记录', 'Log') },
                  { value: 'block', label: tr('阻断', 'Block') },
                  { value: 'throttle', label: tr('限速', 'Throttle') },
                ]} />
              </Form.Item>
              <Form.Item name="enabled" valuePropName="checked">
                <Switch checkedChildren={tr('启用', 'ON')} unCheckedChildren={tr('关', 'OFF')} />
              </Form.Item>
              <Form.Item>
                <Button type="primary" icon={<PlusOutlined />} onClick={handleAdd}>
                  {tr('添加', 'Add')}
                </Button>
              </Form.Item>
            </Form>
          ),
        }]}
      />
    </Card>
  )
}

function HotpatchPanel({
  targets, setTargets, tr,
}: {
  targets: HotpatchTarget[]
  setTargets: (t: HotpatchTarget[]) => void
  lang: Lang
  tr: (zh: string, en: string) => string
}) {
  const [form] = Form.useForm()

  const handleAdd = async () => {
    try {
      const vals = await form.validateFields()
      const payload: HotpatchTarget = {
        binary: vals.binary.trim(),
        symbol: vals.symbol.trim(),
        pid: vals.pid || null,
        block_mode: vals.block_mode ?? false,
      }
      const r = await fetch('/api/v1/config/hotpatch', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(payload),
      })
      if (r.ok) {
        setTargets(await r.json())
        form.resetFields()
        message.success(tr('热补丁目标已添加', 'Hotpatch target added'))
      }
    } catch { /* validation */ }
  }

  const handleDelete = async (index: number) => {
    const r = await fetch(`/api/v1/config/hotpatch/${index}`, { method: 'DELETE' })
    if (r.ok) {
      setTargets(await r.json())
      message.success(tr('目标已删除', 'Target removed'))
    }
  }

  const handleToggleBlock = async (index: number) => {
    const target = { ...targets[index], block_mode: !targets[index].block_mode }
    const r = await fetch('/api/v1/config/hotpatch', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ index, ...target }),
    })
    if (r.ok) {
      setTargets(await r.json())
    }
  }

  return (
    <Card
      title={<Space><ThunderboltOutlined />{tr('高危函数运行时热补丁', 'Hot-Patch Targets')}</Space>}
      style={{ borderRadius: 12 }}
    >
      <Text type="secondary" style={{ display: 'block', marginBottom: 16 }}>
        {tr(
          '通过 uprobe/uretprobe 在运行时挂载到高危函数。开启阻断模式后将发送 SIGKILL。',
          'Attach uprobe/uretprobe to vulnerable functions. Block mode sends SIGKILL.',
        )}
      </Text>

      <Table
        dataSource={targets.map((t, i) => ({ ...t, _idx: i }))}
        rowKey="_idx"
        size="small"
        pagination={false}
        locale={{ emptyText: tr('暂无热补丁目标', 'No hotpatch targets') }}
        columns={[
          { title: tr('二进制文件', 'Binary'), dataIndex: 'binary', render: (v: string) => <Text code>{v}</Text> },
          { title: tr('符号', 'Symbol'), dataIndex: 'symbol', render: (v: string) => <Text code>{v}</Text> },
          { title: 'PID', dataIndex: 'pid', width: 80, render: (v: number | null) => v ?? tr('全部', 'all') },
          {
            title: tr('阻断模式', 'Block Mode'), dataIndex: 'block_mode', width: 120,
            render: (v: boolean, r: HotpatchTarget & { _idx: number }) => (
              <Switch
                checked={v}
                size="small"
                onChange={() => handleToggleBlock(r._idx)}
                checkedChildren={tr('阻断', 'BLOCK')}
                unCheckedChildren={tr('监控', 'MON')}
                style={v ? { background: '#ff4d4f' } : undefined}
              />
            ),
          },
          {
            title: tr('操作', 'Actions'), width: 80,
            render: (_: unknown, r: HotpatchTarget & { _idx: number }) => (
              <Popconfirm title={tr('确认删除？', 'Confirm delete?')} onConfirm={() => handleDelete(r._idx)}>
                <Button type="text" danger icon={<DeleteOutlined />} size="small" />
              </Popconfirm>
            ),
          },
        ]}
      />

      <Collapse
        ghost
        style={{ marginTop: 12 }}
        items={[{
          key: 'add',
          label: <Space><PlusOutlined />{tr('新增目标', 'Add Target')}</Space>,
          children: (
            <Form form={form} layout="inline" style={{ flexWrap: 'wrap', gap: 8 }}
              initialValues={{ block_mode: false }}
            >
              <Form.Item name="binary" rules={[{ required: true }]}>
                <Input placeholder="/usr/sbin/nginx" style={{ width: 200, fontFamily: 'monospace' }} />
              </Form.Item>
              <Form.Item name="symbol" rules={[{ required: true }]}>
                <Input placeholder="ngx_http_process_request" style={{ width: 220, fontFamily: 'monospace' }} />
              </Form.Item>
              <Form.Item name="pid">
                <InputNumber min={0} placeholder={tr('PID（可选）', 'PID (opt)')} style={{ width: 120 }} />
              </Form.Item>
              <Form.Item name="block_mode" valuePropName="checked">
                <Switch
                  checkedChildren={tr('阻断', 'BLOCK')}
                  unCheckedChildren={tr('监控', 'MON')}
                />
              </Form.Item>
              <Form.Item>
                <Button type="primary" icon={<PlusOutlined />} onClick={handleAdd}>
                  {tr('添加', 'Add')}
                </Button>
              </Form.Item>
            </Form>
          ),
        }]}
      />
    </Card>
  )
}
