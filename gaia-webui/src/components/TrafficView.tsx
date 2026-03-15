import { useEffect, useMemo, useState, useCallback, useRef } from 'react'
import {
  Card, Table, Tag, Space, Typography, Statistic, Row, Col, Empty, Spin,
} from 'antd'
import {
  ArrowUpOutlined, ArrowDownOutlined, SwapOutlined,
  CloudServerOutlined, LineChartOutlined, DatabaseOutlined,
} from '@ant-design/icons'
import type { Lang, TrafficResponse, ServiceTrafficSnapshot, TrafficDataPoint } from '../types'

const { Text } = Typography

function formatBytes(bytes: number): string {
  if (bytes <= 0) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(1024))
  const idx = Math.min(i, units.length - 1)
  const val = bytes / Math.pow(1024, idx)
  return `${val.toFixed(idx > 0 ? 1 : 0)} ${units[idx]}`
}

function formatRate(bytesPerInterval: number): string {
  const bps = bytesPerInterval / 2
  return `${formatBytes(bps)}/s`
}

// ── SVG Line Chart ──

function LineChart({
  data,
  width,
  height,
  tr,
}: {
  data: TrafficDataPoint[]
  width: number
  height: number
  tr: (zh: string, en: string) => string
}) {
  if (data.length < 2) {
    return (
      <div style={{ width, height, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
        <Text type="secondary">{tr('等待数据采集...', 'Waiting for data...')}</Text>
      </div>
    )
  }

  const pad = { top: 24, right: 20, bottom: 32, left: 65 }
  const cw = width - pad.left - pad.right
  const ch = height - pad.top - pad.bottom

  const maxSent = Math.max(...data.map((d) => d.bytes_sent))
  const maxRecv = Math.max(...data.map((d) => d.bytes_recv))
  const maxVal = Math.max(maxSent, maxRecv, 1)

  const x = (i: number) => pad.left + (i / (data.length - 1)) * cw
  const y = (v: number) => pad.top + ch - (v / maxVal) * ch

  const line = (key: 'bytes_sent' | 'bytes_recv') =>
    data.map((d, i) => `${i === 0 ? 'M' : 'L'}${x(i).toFixed(1)},${y(d[key]).toFixed(1)}`).join(' ')

  const area = (key: 'bytes_sent' | 'bytes_recv') => {
    const l = line(key)
    return `${l} L${x(data.length - 1).toFixed(1)},${(pad.top + ch).toFixed(1)} L${pad.left.toFixed(1)},${(pad.top + ch).toFixed(1)} Z`
  }

  const yTicks = [0, 0.25, 0.5, 0.75, 1].map((f) => ({ val: maxVal * f, py: y(maxVal * f) }))

  const xCount = Math.min(6, data.length)
  const xLabels = Array.from({ length: xCount }, (_, i) => {
    const idx = Math.round((i / (xCount - 1)) * (data.length - 1))
    const d = data[idx]
    return {
      px: x(idx),
      label: new Date(d.timestamp_ms).toLocaleTimeString(undefined, { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' }),
    }
  })

  return (
    <svg width={width} height={height} style={{ display: 'block' }}>
      {yTicks.map((t, i) => (
        <g key={i}>
          <line x1={pad.left} y1={t.py} x2={width - pad.right} y2={t.py} stroke="rgba(128,128,128,0.15)" strokeDasharray="4,4" />
          <text x={pad.left - 8} y={t.py + 4} textAnchor="end" fill="rgba(160,160,160,0.7)" fontSize={10}>{formatBytes(t.val)}</text>
        </g>
      ))}
      {xLabels.map((l, i) => (
        <text key={i} x={l.px} y={height - 8} textAnchor="middle" fill="rgba(160,160,160,0.7)" fontSize={10}>{l.label}</text>
      ))}
      <path d={area('bytes_sent')} fill="rgba(24,144,255,0.12)" />
      <path d={area('bytes_recv')} fill="rgba(82,196,26,0.12)" />
      <path d={line('bytes_sent')} fill="none" stroke="#1890ff" strokeWidth={2} strokeLinejoin="round" />
      <path d={line('bytes_recv')} fill="none" stroke="#52c41a" strokeWidth={2} strokeLinejoin="round" />
      {/* Latest value dots */}
      <circle cx={x(data.length - 1)} cy={y(data[data.length - 1].bytes_sent)} r={4} fill="#1890ff" />
      <circle cx={x(data.length - 1)} cy={y(data[data.length - 1].bytes_recv)} r={4} fill="#52c41a" />
      {/* Legend */}
      <rect x={pad.left + 8} y={4} width={10} height={10} rx={2} fill="#1890ff" />
      <text x={pad.left + 22} y={13} fill="rgba(200,200,200,0.85)" fontSize={11}>{tr('出站 Outbound', 'Outbound')}</text>
      <rect x={pad.left + 110} y={4} width={10} height={10} rx={2} fill="#52c41a" />
      <text x={pad.left + 124} y={13} fill="rgba(200,200,200,0.85)" fontSize={11}>{tr('入站 Inbound', 'Inbound')}</text>
    </svg>
  )
}

// ── Main Component ──

export default function TrafficView({
  lang,
  tr,
}: {
  lang: Lang
  tr: (zh: string, en: string) => string
}) {
  const [data, setData] = useState<TrafficResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const chartRef = useRef<HTMLDivElement>(null)
  const [chartWidth, setChartWidth] = useState(800)

  void lang

  const fetchTraffic = useCallback(async () => {
    try {
      const r = await fetch('/api/v1/traffic')
      if (r.ok) setData(await r.json() as TrafficResponse)
    } catch { /* offline */ }
    setLoading(false)
  }, [])

  useEffect(() => {
    fetchTraffic()
    const timer = window.setInterval(fetchTraffic, 2000)
    return () => window.clearInterval(timer)
  }, [fetchTraffic])

  useEffect(() => {
    const el = chartRef.current
    if (!el) return
    const obs = new ResizeObserver((entries) => {
      for (const e of entries) setChartWidth(e.contentRect.width)
    })
    obs.observe(el)
    return () => obs.disconnect()
  }, [])

  const rates = useMemo(() => {
    if (!data || data.history.length === 0) return { sendRate: 0, recvRate: 0, pktSend: 0, pktRecv: 0 }
    const recent = data.history.slice(-3)
    const n = recent.length || 1
    return {
      sendRate: recent.reduce((s, p) => s + p.bytes_sent, 0) / n,
      recvRate: recent.reduce((s, p) => s + p.bytes_recv, 0) / n,
      pktSend: recent.reduce((s, p) => s + p.packets_sent, 0) / n,
      pktRecv: recent.reduce((s, p) => s + p.packets_recv, 0) / n,
    }
  }, [data])

  if (loading) return <Spin size="large" style={{ display: 'block', margin: '80px auto' }} />

  if (!data) {
    return (
      <Card style={{ borderRadius: 12 }}>
        <Empty description={tr('无法获取流量数据', 'Unable to fetch traffic data')} image={Empty.PRESENTED_IMAGE_SIMPLE} />
      </Card>
    )
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* Rate cards */}
      <Row gutter={[16, 16]}>
        <Col xs={24} sm={12} lg={6}>
          <Card hoverable style={{ borderRadius: 12, background: '#e6f7ff', borderColor: '#91d5ff' }} styles={{ body: { padding: '20px 24px' } }}>
            <Statistic title={tr('出站速率', 'Outbound Rate')} value={formatRate(rates.sendRate)} prefix={<ArrowUpOutlined style={{ color: '#1890ff' }} />} />
          </Card>
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <Card hoverable style={{ borderRadius: 12, background: '#f6ffed', borderColor: '#b7eb8f' }} styles={{ body: { padding: '20px 24px' } }}>
            <Statistic title={tr('入站速率', 'Inbound Rate')} value={formatRate(rates.recvRate)} prefix={<ArrowDownOutlined style={{ color: '#52c41a' }} />} />
          </Card>
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <Card hoverable style={{ borderRadius: 12, background: '#fff7e6', borderColor: '#ffd591' }} styles={{ body: { padding: '20px 24px' } }}>
            <Statistic title={tr('系统总出站', 'Total Sent')} value={formatBytes(data.system_bytes_sent)} prefix={<DatabaseOutlined style={{ color: '#fa8c16' }} />} />
          </Card>
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <Card hoverable style={{ borderRadius: 12, background: '#f9f0ff', borderColor: '#d3adf7' }} styles={{ body: { padding: '20px 24px' } }}>
            <Statistic title={tr('系统总入站', 'Total Recv')} value={formatBytes(data.system_bytes_recv)} prefix={<DatabaseOutlined style={{ color: '#722ed1' }} />} />
          </Card>
        </Col>
      </Row>

      {/* System-wide line chart */}
      <Card
        title={<Space><LineChartOutlined />{tr('系统实时流量折线图', 'System Real-time Traffic Chart')}</Space>}
        style={{ borderRadius: 12 }}
      >
        <div ref={chartRef} style={{ width: '100%' }}>
          <LineChart data={data.history} width={chartWidth} height={300} tr={tr} />
        </div>
      </Card>

      {/* System-wide traffic table */}
      <Card
        title={<Space><SwapOutlined />{tr('系统流量明细（全端口）', 'System Traffic Detail (All Ports)')}</Space>}
        style={{ borderRadius: 12 }}
      >
        <Table<TrafficDataPoint>
          dataSource={[...data.history].reverse()}
          rowKey={(_, i) => `sys-${i}`}
          size="small"
          scroll={{ y: 360 }}
          pagination={{
            pageSize: 50,
            showSizeChanger: true,
            pageSizeOptions: ['20', '50', '100', '200'],
            size: 'small',
            showTotal: (total, range) => tr(`${range[0]}-${range[1]} / ${total}`, `${range[0]}-${range[1]} of ${total}`),
          }}
          columns={[
            {
              title: tr('时间', 'Time'), dataIndex: 'timestamp_ms', width: 110,
              render: (ms: number) => <Text code style={{ fontSize: 12 }}>{new Date(ms).toLocaleTimeString(undefined, { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' })}</Text>,
            },
            {
              title: <Space><ArrowUpOutlined style={{ color: '#1890ff' }} />{tr('出站', 'Sent')}</Space>,
              dataIndex: 'bytes_sent', width: 130,
              render: (v: number) => <Text style={{ color: v > 0 ? '#1890ff' : undefined }}>{v > 0 ? formatBytes(v) : '-'}</Text>,
              sorter: (a, b) => a.bytes_sent - b.bytes_sent,
            },
            {
              title: <Space><ArrowDownOutlined style={{ color: '#52c41a' }} />{tr('入站', 'Recv')}</Space>,
              dataIndex: 'bytes_recv', width: 130,
              render: (v: number) => <Text style={{ color: v > 0 ? '#52c41a' : undefined }}>{v > 0 ? formatBytes(v) : '-'}</Text>,
              sorter: (a, b) => a.bytes_recv - b.bytes_recv,
            },
            {
              title: tr('出站速率', 'Send Rate'), dataIndex: 'bytes_sent', width: 120,
              key: 'send_rate',
              render: (v: number) => <Text code style={{ fontSize: 12 }}>{v > 0 ? formatRate(v) : '-'}</Text>,
            },
            {
              title: tr('入站速率', 'Recv Rate'), dataIndex: 'bytes_recv', width: 120,
              key: 'recv_rate',
              render: (v: number) => <Text code style={{ fontSize: 12 }}>{v > 0 ? formatRate(v) : '-'}</Text>,
            },
            {
              title: tr('出站包', 'Pkts Out'), dataIndex: 'packets_sent', width: 90,
              render: (v: number) => v > 0 ? v.toLocaleString() : '-',
            },
            {
              title: tr('入站包', 'Pkts In'), dataIndex: 'packets_recv', width: 90,
              render: (v: number) => v > 0 ? v.toLocaleString() : '-',
            },
          ]}
        />
      </Card>

      {/* Per-service traffic */}
      <Card
        title={
          <Space>
            <CloudServerOutlined />
            {tr('Systemd 服务流量监控', 'Systemd Service Traffic')}
            {data.services.length > 0 && <Tag color="blue">{data.services.length} {tr('个服务', 'services')}</Tag>}
          </Space>
        }
        style={{ borderRadius: 12 }}
      >
        {data.services.length === 0 ? (
          <Empty description={tr('暂无跟踪服务 — 请在配置中添加监控服务', 'No tracked services — add in config')} image={Empty.PRESENTED_IMAGE_SIMPLE} />
        ) : (
          <Table<ServiceTrafficSnapshot>
            dataSource={data.services}
            rowKey="service"
            size="small"
            pagination={false}
            columns={[
              {
                title: tr('服务', 'Service'), dataIndex: 'service',
                render: (v: string) => <Text strong>{v}</Text>,
              },
              {
                title: 'PIDs', dataIndex: 'pids',
                render: (pids: number[]) => <Space size={4} wrap>{pids.map((p) => <Tag key={p} color="blue">PID {p}</Tag>)}</Space>,
              },
              {
                title: <Space><ArrowUpOutlined style={{ color: '#1890ff' }} />{tr('出站', 'Sent')}</Space>,
                dataIndex: 'bytes_sent',
                sorter: (a, b) => a.bytes_sent - b.bytes_sent,
                render: (v: number) => <Text code>{formatBytes(v)}</Text>,
              },
              {
                title: <Space><ArrowDownOutlined style={{ color: '#52c41a' }} />{tr('入站', 'Recv')}</Space>,
                dataIndex: 'bytes_recv',
                sorter: (a, b) => a.bytes_recv - b.bytes_recv,
                render: (v: number) => <Text code>{formatBytes(v)}</Text>,
              },
              {
                title: tr('出站包', 'Pkts Sent'), dataIndex: 'packets_sent',
                render: (v: number) => v.toLocaleString(),
              },
              {
                title: tr('入站包', 'Pkts Recv'), dataIndex: 'packets_recv',
                render: (v: number) => v.toLocaleString(),
              },
            ]}
          />
        )}
      </Card>
    </div>
  )
}
