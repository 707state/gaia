import { useMemo, useState } from 'react'
import { Card, Table, Tag, Select, Space, Input, Typography } from 'antd'
import { SearchOutlined, UnorderedListOutlined } from '@ant-design/icons'
import type { Snapshot, Lang } from '../types'
import { mapKind, mapAction, actionColor, formatTs } from '../helpers'
import type { ColumnsType } from 'antd/es/table'
import type { EventRecord } from '../types'

const { Text } = Typography

export default function EventsView({
  snapshot,
  lang,
  tr,
}: {
  snapshot: Snapshot
  lang: Lang
  tr: (zh: string, en: string) => string
}) {
  const [kindFilter, setKindFilter] = useState<string>('all')
  const [actionFilter, setActionFilter] = useState<string>('all')
  const [searchText, setSearchText] = useState('')
  const [pageSize, setPageSize] = useState(50)

  const filtered = useMemo(() => {
    return snapshot.events.filter((e) => {
      if (kindFilter !== 'all' && e.kind !== kindFilter) return false
      if (actionFilter !== 'all' && e.action !== actionFilter) return false
      if (searchText) {
        const s = searchText.toLowerCase()
        if (
          !e.comm.toLowerCase().includes(s) &&
          !e.detail.toLowerCase().includes(s) &&
          !String(e.pid).includes(s) &&
          !(e.network?.address ?? '').toLowerCase().includes(s)
        )
          return false
      }
      return true
    })
  }, [snapshot.events, kindFilter, actionFilter, searchText])

  const kinds = useMemo(
    () => ['all', ...Array.from(new Set(snapshot.events.map((e) => e.kind)))],
    [snapshot.events],
  )
  const actions = useMemo(
    () => ['all', ...Array.from(new Set(snapshot.events.map((e) => e.action)))],
    [snapshot.events],
  )

  const columns: ColumnsType<EventRecord> = [
    {
      title: tr('时间', 'Time'),
      dataIndex: 'timestamp_ns',
      key: 'time',
      width: 100,
      render: (ns: number) => (
        <Text code style={{ fontSize: 12 }}>
          {formatTs(ns)}
        </Text>
      ),
      sorter: (a, b) => a.timestamp_ns - b.timestamp_ns,
      defaultSortOrder: 'descend',
    },
    {
      title: tr('类型', 'Kind'),
      dataIndex: 'kind',
      key: 'kind',
      width: 100,
      render: (kind: string) => <Tag>{mapKind(kind, lang)}</Tag>,
    },
    {
      title: tr('动作', 'Action'),
      dataIndex: 'action',
      key: 'action',
      width: 120,
      render: (action: string) => (
        <Tag color={actionColor(action)}>{mapAction(action, lang)}</Tag>
      ),
    },
    {
      title: tr('进程', 'Process'),
      dataIndex: 'comm',
      key: 'comm',
      width: 110,
      render: (comm: string) => <Text code>{comm || '-'}</Text>,
    },
    {
      title: 'PID',
      dataIndex: 'pid',
      key: 'pid',
      width: 80,
      sorter: (a, b) => a.pid - b.pid,
    },
    {
      title: 'UID',
      dataIndex: 'uid',
      key: 'uid',
      width: 70,
    },
    {
      title: tr('详情', 'Detail'),
      dataIndex: 'detail',
      key: 'detail',
      ellipsis: { showTitle: true },
      render: (detail: string) => (
        <Text
          code
          style={{ fontSize: 12, maxWidth: 260, display: 'inline-block' }}
          ellipsis={{ tooltip: detail }}
        >
          {detail || '-'}
        </Text>
      ),
    },
    {
      title: tr('网络', 'Network'),
      key: 'network',
      width: 160,
      render: (_: unknown, record: EventRecord) =>
        record.network ? (
          <Text code style={{ fontSize: 12 }}>
            {record.network.address}:{record.network.port}
          </Text>
        ) : (
          <Text type="secondary">-</Text>
        ),
    },
  ]

  return (
    <Card
      title={
        <Space>
          <UnorderedListOutlined />
          {tr('事件流', 'Event Stream')}
          <Tag color="blue">{filtered.length}</Tag>
        </Space>
      }
      style={{ borderRadius: 12 }}
      extra={
        <Space wrap>
          <Input
            placeholder={tr('搜索进程/详情/PID...', 'Search process/detail/PID...')}
            prefix={<SearchOutlined />}
            value={searchText}
            onChange={(e) => setSearchText(e.target.value)}
            allowClear
            style={{ width: 220 }}
          />
          <Select
            value={kindFilter}
            onChange={setKindFilter}
            style={{ width: 130 }}
            options={kinds.map((k) => ({
              value: k,
              label: k === 'all' ? tr('全部类型', 'All Kinds') : mapKind(k, lang),
            }))}
          />
          <Select
            value={actionFilter}
            onChange={setActionFilter}
            style={{ width: 130 }}
            options={actions.map((a) => ({
              value: a,
              label: a === 'all' ? tr('全部动作', 'All Actions') : mapAction(a, lang),
            }))}
          />
        </Space>
      }
    >
      <Table<EventRecord>
        columns={columns}
        dataSource={filtered}
        rowKey={(record, index) => `${record.timestamp_ns}-${record.pid}-${index}`}
        size="small"
        scroll={{ x: 900, y: 600 }}
        pagination={{
          pageSize,
          showSizeChanger: true,
          pageSizeOptions: ['20', '50', '100', '200', '500'],
          onShowSizeChange: (_, size) => setPageSize(size),
          showTotal: (total, range) =>
            tr(
              `第 ${range[0]}-${range[1]} 条，共 ${total} 条`,
              `${range[0]}-${range[1]} of ${total} events`,
            ),
          size: 'small',
        }}
        rowClassName={(record) =>
          record.action === 'alert' ||
          record.action === 'blocked' ||
          record.action === 'kill_request'
            ? 'gaia-row-highlight'
            : ''
        }
      />
    </Card>
  )
}
