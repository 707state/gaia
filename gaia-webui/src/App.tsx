import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  ConfigProvider, Layout, Menu, Badge, Tag, Typography, Space, Switch, theme,
} from 'antd'
import {
  DashboardOutlined,
  UnorderedListOutlined,
  SettingOutlined,
  GlobalOutlined,
  SafetyCertificateOutlined,
  SwapOutlined,
} from '@ant-design/icons'
import type { Lang, Snapshot } from './types'
import { initialLang, emptySnapshot } from './helpers'
import DashboardView from './components/DashboardView'
import EventsView from './components/EventsView'
import ConfigView from './components/ConfigView'
import TrafficView from './components/TrafficView'

const { Header, Sider, Content } = Layout
const { Text, Title } = Typography

type Tab = 'dashboard' | 'events' | 'traffic' | 'config'

function App() {
  const [tab, setTab] = useState<Tab>('dashboard')
  const [lang, setLang] = useState<Lang>(initialLang)
  const [snapshot, setSnapshot] = useState<Snapshot>(emptySnapshot)
  const [live, setLive] = useState(false)
  const [collapsed, setCollapsed] = useState(false)
  const [darkMode, setDarkMode] = useState(true)

  const tr = useCallback((zh: string, en: string) => (lang === 'zh' ? zh : en), [lang])

  useEffect(() => {
    localStorage.setItem('gaia_lang', lang)
  }, [lang])

  useEffect(() => {
    let cancelled = false
    const pull = async () => {
      try {
        const r = await fetch('/api/v1/state')
        if (!r.ok) return
        const data = (await r.json()) as Snapshot
        if (!cancelled) {
          setSnapshot(data)
          setLive(true)
        }
      } catch {
        if (!cancelled) setLive(false)
      }
    }
    pull()
    const timer = window.setInterval(pull, 2000)
    return () => {
      cancelled = true
      window.clearInterval(timer)
    }
  }, [])

  const totalEvents = useMemo(
    () => Object.values(snapshot.counters).reduce((s, v) => s + v, 0),
    [snapshot.counters],
  )

  const criticalAlerts = useMemo(
    () => snapshot.alerts.filter((a) => a.level === 'critical').length,
    [snapshot.alerts],
  )

  const menuItems = [
    {
      key: 'dashboard',
      icon: <DashboardOutlined />,
      label: tr('仪表盘', 'Dashboard'),
    },
    {
      key: 'events',
      icon: <Badge count={snapshot.events.length} size="small" offset={[6, 0]}>
        <UnorderedListOutlined style={{ fontSize: 16 }} />
      </Badge>,
      label: tr('事件流', 'Events'),
    },
    {
      key: 'traffic',
      icon: <SwapOutlined />,
      label: tr('流量监控', 'Traffic'),
    },
    {
      key: 'config',
      icon: <SettingOutlined />,
      label: tr('配置', 'Config'),
    },
  ]

  const themeConfig = darkMode
    ? {
        algorithm: theme.darkAlgorithm,
        token: {
          colorPrimary: '#1890ff',
          borderRadius: 8,
          colorBgContainer: '#141414',
          colorBgLayout: '#0a0a0a',
        },
      }
    : {
        algorithm: theme.defaultAlgorithm,
        token: {
          colorPrimary: '#1890ff',
          borderRadius: 8,
        },
      }

  return (
    <ConfigProvider theme={themeConfig}>
      <Layout style={{ minHeight: '100vh' }}>
        <Sider
          collapsible
          collapsed={collapsed}
          onCollapse={setCollapsed}
          breakpoint="lg"
          style={{
            overflow: 'auto',
            height: '100vh',
            position: 'fixed',
            left: 0,
            top: 0,
            bottom: 0,
            zIndex: 10,
          }}
        >
          <div style={{
            padding: collapsed ? '16px 8px' : '16px',
            textAlign: 'center',
            borderBottom: '1px solid rgba(255,255,255,0.08)',
          }}>
            <SafetyCertificateOutlined style={{ fontSize: collapsed ? 24 : 28, color: '#1890ff' }} />
            {!collapsed && (
              <Title level={5} style={{ margin: '8px 0 0', color: '#fff', whiteSpace: 'nowrap' }}>
                GAIA XDP
              </Title>
            )}
          </div>
          <Menu
            theme="dark"
            mode="inline"
            selectedKeys={[tab]}
            onClick={({ key }) => setTab(key as Tab)}
            items={menuItems}
            style={{ borderRight: 0 }}
          />
          {!collapsed && (
            <div style={{
              position: 'absolute',
              bottom: 48,
              left: 0,
              right: 0,
              padding: '12px 16px',
              display: 'flex',
              flexDirection: 'column',
              gap: 10,
            }}>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <Text style={{ color: 'rgba(255,255,255,0.65)', fontSize: 12 }}>
                  <GlobalOutlined /> {tr('语言', 'Lang')}
                </Text>
                <Switch
                  checkedChildren="中文"
                  unCheckedChildren="EN"
                  checked={lang === 'zh'}
                  onChange={(v) => setLang(v ? 'zh' : 'en')}
                  size="small"
                />
              </div>
              <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
                <Text style={{ color: 'rgba(255,255,255,0.65)', fontSize: 12 }}>
                  {tr('主题', 'Theme')}
                </Text>
                <Switch
                  checkedChildren={tr('暗', 'Dark')}
                  unCheckedChildren={tr('亮', 'Light')}
                  checked={darkMode}
                  onChange={setDarkMode}
                  size="small"
                />
              </div>
            </div>
          )}
        </Sider>

        <Layout style={{ marginLeft: collapsed ? 80 : 200, transition: 'margin-left 0.2s' }}>
          <Header style={{
            padding: '0 24px',
            display: 'flex',
            alignItems: 'center',
            justifyContent: 'space-between',
            background: darkMode ? '#141414' : '#fff',
            borderBottom: `1px solid ${darkMode ? '#303030' : '#f0f0f0'}`,
            position: 'sticky',
            top: 0,
            zIndex: 5,
          }}>
            <Space size={12}>
              <Title level={4} style={{ margin: 0 }}>
                {tr('Linux 关键服务监控与主动防御', 'Linux Service Monitoring & Active Defense')}
              </Title>
            </Space>
            <Space size={12}>
              {criticalAlerts > 0 && (
                <Tag color="error" icon={<SafetyCertificateOutlined />}>
                  {criticalAlerts} {tr('严重告警', 'Critical')}
                </Tag>
              )}
              <Tag color={live ? 'success' : 'default'}>
                <Badge status={live ? 'processing' : 'default'} />
                {' '}{live ? tr('实时连接', 'Live') : tr('离线', 'Offline')}
              </Tag>
            </Space>
          </Header>

          <Content style={{ margin: 20, minHeight: 280 }}>
            {tab === 'dashboard' && (
              <DashboardView snapshot={snapshot} totalEvents={totalEvents} lang={lang} tr={tr} />
            )}
            {tab === 'events' && (
              <EventsView snapshot={snapshot} lang={lang} tr={tr} />
            )}
            {tab === 'traffic' && (
              <TrafficView lang={lang} tr={tr} />
            )}
            {tab === 'config' && (
              <ConfigView lang={lang} tr={tr} />
            )}
          </Content>
        </Layout>
      </Layout>
    </ConfigProvider>
  )
}

export default App
