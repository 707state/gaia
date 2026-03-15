import { useEffect, useMemo, useState, useCallback } from 'react'
import {
  Card, Table, Tag, Space, Typography, Statistic, Row, Col, Empty, Segmented, Spin,
} from 'antd'
import {
  ArrowUpOutlined, ArrowDownOutlined, SwapOutlined,
  CloudServerOutlined, ReloadOutlined,
} from '@ant-design/icons'
import type { Lang, TrafficResponse, ServiceTrafficSnapshot, TrafficDataPoint } from '../types'

const { Text, Title } = Typography

function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(1024))
  const val = bytes / Math.pow(1024, i)
  return `${val.toFixed(i > 0 ? 1 : 0)} ${units[i]}`
}

function formatRate(bytes: number): string {
  return `${formatBytes(bytes)}/s`
}

export default function TrafficView({
  lang,
  tr,
}: {
  lang: Lang
  tr: (zh: string, en: string) => string
}) {
  const [data, setData] = useState<TrafficResponse | null>(null)
  const [loading, setLoading] = useState(true)
  const [selectedService, setSelectedService] = useState<string>('all')

  void lang

  const fetchTraffic = useCallback(async () => {
    try {
      const r = await fetch('/api/v1/traffic')
      if (r.ok) {
        const resp = (await r.json()) as TrafficResponse
        setData(resp)
      }
    } catch { /* offline */ }
    setLoading(false)
  }, [])

  useEffect(() => {
    fetchTraffic()
    const timer = window.setInterval(fetchTraffic, 2000)
    return () => window.clearInterval(timer)
  }, [fetchTraffic])

  const serviceNames = useMemo(() => {
    if (!data) return []
    return data.services.map((s) => s.service)
  }, [data])

  const filteredHistory = useMemo(() => {
    if (!data) return []
    if (selectedService === 'all') return data.history
    return data.history.filter((p) => p.service === selectedService)
  }, [data, selectedService])

  // Aggregate recent rates (last 3 samples = ~6 seconds)
  const recentRates = useMemo(() => {
    if (!data || filteredHistory.length === 0) return { sendRate: 0, recvRate: 0, pktSend: 0, pktRecv: 0 }
    const recent = filteredHistory.slice(-3)
    const count = recent.length || 1
    const sendRate = recent.reduce((s, p) => s + p.bytes_sent, 0) / (count * 2)
    const recvRate = recent.reduce((s, p) => s + p.bytes_recv, 0) / (count * 2)
    const pktSend = recent.reduce((s, p) => s + p.packets_sent, 0) / (count * 2)
    const pktRecv = recent.reduce((s, p) => s + p.packets_recv, 0) / (count * 2)
    return { sendRate, recvRate, pktSend, pktRecv }
  }, [filteredHistory, data])

  // Build chart-like data for the sparkline table
  const historyByService = useMemo(() => {
    if (!data) return new Map<string, TrafficDataPoint[]>()
    const map = new Map<string, TrafficDataPoint[]>()
    for (const p of data.history) {
      const arr = map.get(p.service) || []
      arr.push(p)
      map.set(p.service, arr)
    }
    return map
  }, [data])

  if (loading) return <Spin size="large" style={{ display: 'block', margin: '80px auto' }} />

  if (!data || data.services.length === 0) {
    return (
      <Card style={{ borderRadius: 12 }}>
        <Empty
          description={tr('暂无流量数据 — 请确保有监控服务正在运行', 'No traffic data — ensure monitored services are running')}
          image={Empty.PRESENTED_IMAGE_SIMPLE}
        />
      </Card>
    )
  }

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* Rate overview cards */}
      <Row gutter={[16, 16]}>
        <Col xs={24} sm={12} lg={6}>
          <Card hoverable style={{ borderRadius: 12, background: '#e6f7ff', borderColor: '#91d5ff' }} styles={{ body: { padding: '20px 24px' } }}>
            <Statistic
              title={tr('出站速率', 'Outbound Rate')}
              value={formatRate(recentRates.sendRate)}
              prefix={<ArrowUpOutlined style={{ color: '#1890ff' }} />}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <Card hoverable style={{ borderRadius: 12, background: '#f6ffed', borderColor: '#b7eb8f' }} styles={{ body: { padding: '20px 24px' } }}>
            <Statistic
              title={tr('入站速率', 'Inbound Rate')}
              value={formatRate(recentRates.recvRate)}
              prefix={<ArrowDownOutlined style={{ color: '#52c41a' }} />}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <Card hoverable style={{ borderRadius: 12, background: '#fff7e6', borderColor: '#ffd591' }} styles={{ body: { padding: '20px 24px' } }}>
            <Statistic
              title={tr('出站包速率', 'Outbound Pkt/s')}
              value={recentRates.pktSend.toFixed(1)}
              suffix="pkt/s"
              prefix={<SwapOutlined style={{ color: '#fa8c16' }} />}
            />
          </Card>
        </Col>
        <Col xs={24} sm={12} lg={6}>
          <Card hoverable style={{ borderRadius: 12, background: '#f9f0ff', borderColor: '#d3adf7' }} styles={{ body: { padding: '20px 24px' } }}>
            <Statistic
              title={tr('入站包速率', 'Inbound Pkt/s')}
              value={recentRates.pktRecv.toFixed(1)}
              suffix="pkt/s"
              prefix={<SwapOutlined style={{ color: '#722ed1' }} />}
            />
          </Card>
        </Col>
      </Row>

      {/* Service filter */}
      {serviceNames.length > 1 && (
        <Segmented
          value={selectedService}
          onChange={(v) => setSelectedService(v as string)}
          options={[
            { value: 'all', label: tr('全部服务', 'All Services') },
            ...serviceNames.map((s) => ({ value: s, label: s })),
          ]}
        />
      )}

      {/* Per-service traffic totals */}
      <Card
        title={<Space><CloudServerOutlined />{tr('服务流量统计', 'Service Traffic Stats')}</Space>}
        style={{ borderRadius: 12 }}
      >
        <Table<ServiceTrafficSnapshot>
          dataSource={data.services}
          rowKey="service"
          size="small"
          pagination={false}
          columns={[
            {
              title: tr('服务', 'Service'),
              dataIndex: 'service',
              render: (v: string) => <Text strong>{v}</Text>,
            },
            {
              title: 'PIDs',
              dataIndex: 'pids',
              render: (pids: number[]) => (
                <Space size={4}>
                  {pids.map((p) => <Tag key={p} color="blue">PID {p}</Tag>)}
                </Space>
              ),
            },
            {
              title: <Space><ArrowUpOutlined />{tr('出站', 'Sent')}</Space>,
              dataIndex: 'bytes_sent',
              sorter: (a, b) => a.bytes_sent - b.bytes_sent,
              render: (v: number) => <Text code>{formatBytes(v)}</Text>,
            },
            {
              title: <Space><ArrowDownOutlined />{tr('入站', 'Recv')}</Space>,
              dataIndex: 'bytes_recv',
              sorter: (a, b) => a.bytes_recv - b.bytes_recv,
              render: (v: number) => <Text code>{formatBytes(v)}</Text>,
            },
            {
              title: tr('出站包', 'Pkts Sent'),
              dataIndex: 'packets_sent',
              render: (v: number) => v.toLocaleString(),
            },
            {
              title: tr('入站包', 'Pkts Recv'),
              dataIndex: 'packets_recv',
              render: (v: number) => v.toLocaleString(),
            },
          ]}
        />
      </Card>

      {/* Real-time traffic history */}
      <Card
        title={
          <Space>
            <ReloadOutlined spin />
            {tr('实时流量数据', 'Real-time Traffic Data')}
            <Tag color="blue">{filteredHistory.length} {tr('条记录', 'records')}</Tag>
          </Space>
        }
        style={{ borderRadius: 12 }}
      >
        <Table<TrafficDataPoint>
          dataSource={[...filteredHistory].reverse().slice(0, 200)}
          rowKey={(r, i) => `${r.timestamp_ms}-${r.service}-${i}`}
          size="small"
          scroll={{ y: 400 }}
          pagination={false}
          columns={[
            {
              title: tr('时间', 'Time'),
              dataIndex: 'timestamp_ms',
              width: 100,
              render: (ms: number) => (
                <Text code style={{ fontSize: 12 }}>
                  {new Date(ms).toLocaleTimeString(undefined, { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' })}
                </Text>
              ),
            },
            {
              title: tr('服务', 'Service'),
              dataIndex: 'service',
              width: 160,
              render: (v: string) => <Tag>{v}</Tag>,
            },
            {
              title: <Space><ArrowUpOutlined style={{ color: '#1890ff' }} />{tr('出站', 'Sent')}</Space>,
              dataIndex: 'bytes_sent',
              width: 120,
              render: (v: number) => (
                <Text style={{ color: v > 0 ? '#1890ff' : undefined }}>
                  {v > 0 ? formatBytes(v) : '-'}
                </Text>
              ),
            },
            {
              title: <Space><ArrowDownOutlined style={{ color: '#52c41a' }} />{tr('入站', 'Recv')}</Space>,
              dataIndex: 'bytes_recv',
              width: 120,
              render: (v: number) => (
                <Text style={{ color: v > 0 ? '#52c41a' : undefined }}>
                  {v > 0 ? formatBytes(v) : '-'}
                </Text>
              ),
            },
            {
              title: tr('出站包', 'Pkts Out'),
              dataIndex: 'packets_sent',
              width: 90,
              render: (v: number) => v > 0 ? v : '-',
            },
            {
              title: tr('入站包', 'Pkts In'),
              dataIndex: 'packets_recv',
              width: 90,
              render: (v: number) => v > 0 ? v : '-',
            },
          ]}
        />
      </Card>

      {/* Mini sparkline per service */}
      {serviceNames.length > 0 && (
        <Card
          title={<Space><SwapOutlined />{tr('各服务流量趋势', 'Per-Service Traffic Trend')}</Space>}
          style={{ borderRadius: 12 }}
        >
          <Row gutter={[16, 16]}>
            {serviceNames.map((svc) => {
              const points = historyByService.get(svc) || []
              const last30 = points.slice(-30)
              const maxVal = Math.max(...last30.map((p) => p.bytes_sent + p.bytes_recv), 1)
              return (
                <Col xs={24} lg={12} key={svc}>
                  <Card size="small" style={{ borderRadius: 8 }}>
                    <Title level={5} style={{ marginBottom: 8 }}>{svc}</Title>
                    <div style={{ display: 'flex', alignItems: 'flex-end', gap: 2, height: 60 }}>
                      {last30.map((p, i) => {
                        const total = p.bytes_sent + p.bytes_recv
                        const h = Math.max(2, (total / maxVal) * 56)
                        const sentRatio = total > 0 ? p.bytes_sent / total : 0.5
                        return (
                          <div
                            key={i}
                            title={`${new Date(p.timestamp_ms).toLocaleTimeString()} | Out: ${formatBytes(p.bytes_sent)} | In: ${formatBytes(p.bytes_recv)}`}
                            style={{
                              flex: 1,
                              height: h,
                              borderRadius: 2,
                              background: `linear-gradient(to top, #1890ff ${sentRatio * 100}%, #52c41a ${sentRatio * 100}%)`,
                              minWidth: 3,
                            }}
                          />
                        )
                      })}
                    </div>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginTop: 6 }}>
                      <Text type="secondary" style={{ fontSize: 11 }}>
                        <span style={{ color: '#1890ff' }}>&#9632;</span> {tr('出站', 'Out')}
                        {' '}
                        <span style={{ color: '#52c41a' }}>&#9632;</span> {tr('入站', 'In')}
                      </Text>
                      <Text type="secondary" style={{ fontSize: 11 }}>
                        {tr('最近 30 个采样点', 'Last 30 samples')}
                      </Text>
                    </div>
                  </Card>
                </Col>
              )
            })}
          </Row>
        </Card>
      )}
    </div>
  )
}
