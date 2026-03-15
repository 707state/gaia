import { useMemo } from 'react'
import {
  Card,
  Col,
  Row,
  Statistic,
  Tag,
  Badge,
  Progress,
  Timeline,
  Typography,
  Space,
  Tooltip,
  Empty,
} from 'antd'
import {
  AlertOutlined,
  CheckCircleOutlined,
  CloseCircleOutlined,
  CloudServerOutlined,
  FileProtectOutlined,
  FundOutlined,
  SafetyCertificateOutlined,
  ThunderboltOutlined,
} from '@ant-design/icons'
import type { Snapshot, Lang } from '../types'
import {
  mapKind,
  mapAction,
  actionColor,
  levelColor,
  formatTs,
  kindColor,
  featureMeta,
} from '../helpers'

const { Text } = Typography

export default function DashboardView({
  snapshot,
  totalEvents,
  lang,
  tr,
}: {
  snapshot: Snapshot
  totalEvents: number
  lang: Lang
  tr: (zh: string, en: string) => string
}) {
  const criticalAlerts = useMemo(
    () => snapshot.alerts.filter((a) => a.level === 'critical').length,
    [snapshot.alerts],
  )
  const highAlerts = useMemo(
    () => snapshot.alerts.filter((a) => a.level === 'high').length,
    [snapshot.alerts],
  )
  const maxCount = Math.max(...Object.values(snapshot.counters), 1)

  const statCards = [
    {
      title: tr('事件总数', 'Total Events'),
      value: totalEvents,
      icon: <FundOutlined style={{ fontSize: 24, color: '#1890ff' }} />,
      color: '#e6f7ff',
      borderColor: '#91d5ff',
    },
    {
      title: tr('严重告警', 'Critical Alerts'),
      value: criticalAlerts,
      icon: <AlertOutlined style={{ fontSize: 24, color: '#ff4d4f' }} />,
      color: '#fff2f0',
      borderColor: '#ffccc7',
    },
    {
      title: tr('高危告警', 'High Alerts'),
      value: highAlerts,
      icon: <ThunderboltOutlined style={{ fontSize: 24, color: '#fa8c16' }} />,
      color: '#fff7e6',
      borderColor: '#ffd591',
    },
    {
      title: tr('跟踪服务', 'Tracked Services'),
      value: Object.keys(snapshot.services).length,
      icon: <CloudServerOutlined style={{ fontSize: 24, color: '#52c41a' }} />,
      color: '#f6ffed',
      borderColor: '#b7eb8f',
    },
  ]

  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 20 }}>
      {/* Stat Cards */}
      <Row gutter={[16, 16]}>
        {statCards.map((s) => (
          <Col xs={24} sm={12} lg={6} key={s.title}>
            <Card
              hoverable
              style={{
                borderRadius: 12,
                background: s.color,
                borderColor: s.borderColor,
              }}
              styles={{ body: { padding: '20px 24px' } }}
            >
              <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'flex-start' }}>
                <Statistic title={s.title} value={s.value} />
                {s.icon}
              </div>
            </Card>
          </Col>
        ))}
      </Row>

      {/* Agent Status */}
      <Card
        title={
          <Space>
            <SafetyCertificateOutlined />
            {tr('代理状态', 'Agent Status')}
          </Space>
        }
        style={{ borderRadius: 12 }}
      >
        <Row gutter={[12, 12]}>
          {featureMeta.map(([key, label]) => {
            const active = snapshot.features[key as keyof typeof snapshot.features]
            return (
              <Col xs={24} sm={12} md={8} key={key}>
                <Card
                  size="small"
                  style={{
                    borderRadius: 8,
                    borderLeft: `3px solid ${active ? '#52c41a' : '#ff4d4f'}`,
                    background: active ? '#f6ffed' : '#fff2f0',
                  }}
                >
                  <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center' }}>
                    <Text>{label[lang]}</Text>
                    <Badge
                      status={active ? 'success' : 'error'}
                      text={
                        active ? (
                          <Text type="success" style={{ fontSize: 12 }}>
                            <CheckCircleOutlined /> {tr('运行中', 'ACTIVE')}
                          </Text>
                        ) : (
                          <Text type="danger" style={{ fontSize: 12 }}>
                            <CloseCircleOutlined /> {tr('离线', 'DOWN')}
                          </Text>
                        )
                      }
                    />
                  </div>
                </Card>
              </Col>
            )
          })}
        </Row>
      </Card>

      <Row gutter={[16, 16]}>
        {/* Systemd Tracker */}
        <Col xs={24} lg={12}>
          <Card
            title={
              <Space>
                <CloudServerOutlined />
                {tr('Systemd 服务跟踪', 'Systemd Tracker')}
              </Space>
            }
            style={{ borderRadius: 12, height: '100%' }}
          >
            {Object.entries(snapshot.services).length === 0 ? (
              <Empty description={tr('暂无跟踪服务', 'No services tracked')} image={Empty.PRESENTED_IMAGE_SIMPLE} />
            ) : (
              <div style={{ display: 'flex', flexDirection: 'column', gap: 10 }}>
                {Object.entries(snapshot.services).map(([svc, pids]) => (
                  <div
                    key={svc}
                    style={{
                      display: 'flex',
                      justifyContent: 'space-between',
                      alignItems: 'center',
                      padding: '8px 12px',
                      background: '#fafafa',
                      borderRadius: 8,
                    }}
                  >
                    <Text strong style={{ fontSize: 13 }}>
                      <FileProtectOutlined style={{ marginRight: 6 }} />
                      {svc}
                    </Text>
                    <Space size={4}>
                      {pids.length > 0
                        ? pids.map((pid) => (
                            <Tag key={pid} color="blue">
                              PID {pid}
                            </Tag>
                          ))
                        : <Text type="secondary">-</Text>}
                    </Space>
                  </div>
                ))}
              </div>
            )}
          </Card>
        </Col>

        {/* Event Distribution */}
        <Col xs={24} lg={12}>
          <Card
            title={
              <Space>
                <FundOutlined />
                {tr('事件类型分布', 'Event Distribution')}
              </Space>
            }
            style={{ borderRadius: 12, height: '100%' }}
          >
            <div style={{ display: 'flex', flexDirection: 'column', gap: 14 }}>
              {Object.entries(snapshot.counters).map(([k, v]) => (
                <div key={k}>
                  <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 4 }}>
                    <Text style={{ fontSize: 13 }}>{mapKind(k, lang)}</Text>
                    <Text strong style={{ fontSize: 13 }}>
                      {v.toLocaleString()}
                    </Text>
                  </div>
                  <Tooltip title={`${v} / ${maxCount}`}>
                    <Progress
                      percent={Math.round((v / maxCount) * 100)}
                      showInfo={false}
                      strokeColor={kindColor(k)}
                      trailColor="#f0f0f0"
                      size="small"
                    />
                  </Tooltip>
                </div>
              ))}
            </div>
          </Card>
        </Col>
      </Row>

      {/* Latest Alerts */}
      <Card
        title={
          <Space>
            <AlertOutlined style={{ color: '#ff4d4f' }} />
            {tr('最新告警', 'Latest Alerts')}
            {snapshot.alerts.length > 0 && (
              <Tag color="red">{snapshot.alerts.length}</Tag>
            )}
          </Space>
        }
        style={{ borderRadius: 12 }}
      >
        {snapshot.alerts.length === 0 ? (
          <Empty
            description={tr('暂无告警 — 系统运行正常', 'No alerts — system healthy')}
            image={Empty.PRESENTED_IMAGE_SIMPLE}
          />
        ) : (
          <Timeline
            items={snapshot.alerts.slice(0, 20).map((a, i) => ({
              key: i,
              color: a.level === 'critical' ? 'red' : a.level === 'high' ? 'orange' : 'gold',
              children: (
                <div>
                  <div style={{ display: 'flex', alignItems: 'center', gap: 8, flexWrap: 'wrap', marginBottom: 4 }}>
                    <Tag color={levelColor(a.level)} style={{ margin: 0 }}>
                      {a.level.toUpperCase()}
                    </Tag>
                    <Text style={{ fontSize: 13 }}>{a.reason}</Text>
                  </div>
                  <Space size={6} wrap>
                    <Tag>{mapKind(a.event.kind, lang)}</Tag>
                    <Tag color={actionColor(a.event.action)}>
                      {mapAction(a.event.action, lang)}
                    </Tag>
                    <Text type="secondary" style={{ fontSize: 12 }}>
                      PID {a.event.pid}
                    </Text>
                    <Text code style={{ fontSize: 12 }}>
                      {a.event.comm}
                    </Text>
                    {a.event.network && (
                      <Text code style={{ fontSize: 12 }}>
                        {a.event.network.address}:{a.event.network.port}
                      </Text>
                    )}
                    <Text type="secondary" style={{ fontSize: 11 }}>
                      {formatTs(a.event.timestamp_ns)}
                    </Text>
                  </Space>
                </div>
              ),
            }))}
          />
        )}
      </Card>
    </div>
  )
}
