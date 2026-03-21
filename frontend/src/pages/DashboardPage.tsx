import { useQuery } from '@tanstack/react-query'
import { useChartTheme } from '../lib/chartTheme'
import { dashboardAPI } from '../services/api'
import { safeArray, safeObj, safeNum } from '../lib/safe'
import {
  AlertTriangle,
  ShieldAlert,
  ShieldCheck,
  Activity,
  TrendingUp,
  Package,
} from 'lucide-react'
import {
  BarChart,
  Bar,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  PieChart,
  Pie,
  Cell,
  Area,
  AreaChart,
} from 'recharts'
import SeverityBadge from '../components/common/SeverityBadge'

const SEVERITY_COLORS = {
  critical: '#dc2626',
  high: '#ea580c',
  medium: '#d97706',
  low: '#2563eb',
  info: '#6b7280',
}

export default function DashboardPage() {
  const chart = useChartTheme()
  const { data, isLoading, error } = useQuery({
    queryKey: ['dashboard'],
    queryFn: () => dashboardAPI.stats().then((r) => r.data),
  })

  if (isLoading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="animate-pulse text-content-muted">Loading dashboard...</div>
      </div>
    )
  }

  if (error || !data) {
    return (
      <div className="space-y-6">
        <div>
          <h1 className="text-2xl font-bold text-content-primary">Security Dashboard</h1>
          <p className="text-content-muted mt-1">Overview of your application security posture</p>
        </div>
        <div className="card text-center py-12 text-content-muted">
          {error ? 'Failed to load dashboard data. Please check your backend connection.' : 'No data available yet. Import some scans to get started.'}
        </div>
      </div>
    )
  }

  const severityData = Object.entries(safeObj(data.findings_by_severity)).map(([name, value]) => ({
    name: name.charAt(0).toUpperCase() + name.slice(1),
    value: value as number,
    color: SEVERITY_COLORS[name as keyof typeof SEVERITY_COLORS] || '#6b7280',
  }))

  const scannerData = Object.entries(safeObj(data.findings_by_scanner)).map(([name, value]) => ({
    name,
    count: value as number,
  }))

  return (
    <div className="space-y-6">
      {/* Page Header */}
      <div>
        <h1 className="text-2xl font-bold text-content-primary">Security Dashboard</h1>
        <p className="text-content-muted mt-1">Overview of your application security posture</p>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <StatCard
          title="Total Findings"
          value={data.total_findings}
          icon={Activity}
          color="text-foxnode-400"
          bgColor="bg-foxnode-500/10"
        />
        <StatCard
          title="Critical"
          value={data.critical_findings}
          icon={ShieldAlert}
          color="text-red-400"
          bgColor="bg-red-500/10"
        />
        <StatCard
          title="High"
          value={data.high_findings}
          icon={AlertTriangle}
          color="text-orange-400"
          bgColor="bg-orange-500/10"
        />
        <StatCard
          title="Products"
          value={data.total_products}
          icon={Package}
          color="text-green-400"
          bgColor="bg-green-500/10"
        />
      </div>

      {/* Charts Row */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Severity Distribution */}
        <div className="card">
          <h3 className="text-lg font-semibold text-content-primary mb-4">Findings by Severity</h3>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <PieChart>
                <Pie
                  data={severityData}
                  cx="50%"
                  cy="50%"
                  innerRadius={60}
                  outerRadius={100}
                  paddingAngle={3}
                  dataKey="value"
                >
                  {severityData.map((entry, index) => (
                    <Cell key={index} fill={entry.color} />
                  ))}
                </Pie>
                <Tooltip
                  contentStyle={{
                    backgroundColor: chart.tooltipStyle.backgroundColor,
                    border: chart.tooltipStyle.border,
                    borderRadius: '8px',
                    color: '#f3f4f6',
                  }}
                />
              </PieChart>
            </ResponsiveContainer>
          </div>
          <div className="flex flex-wrap gap-4 mt-2 justify-center">
            {severityData.map((item) => (
              <div key={item.name} className="flex items-center gap-2">
                <div className="w-3 h-3 rounded-full" style={{ backgroundColor: item.color }} />
                <span className="text-sm text-content-tertiary">
                  {item.name}: {item.value}
                </span>
              </div>
            ))}
          </div>
        </div>

        {/* Findings by Scanner */}
        <div className="card">
          <h3 className="text-lg font-semibold text-content-primary mb-4">Findings by Scanner</h3>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={scannerData} layout="vertical">
                <CartesianGrid strokeDasharray="3 3" stroke={chart.gridStroke} />
                <XAxis type="number" stroke={chart.axisStroke} />
                <YAxis type="category" dataKey="name" stroke={chart.axisStroke} width={100} tick={{ fontSize: 12 }} />
                <Tooltip
                  contentStyle={{
                    backgroundColor: chart.tooltipStyle.backgroundColor,
                    border: chart.tooltipStyle.border,
                    borderRadius: '8px',
                    color: '#f3f4f6',
                  }}
                />
                <Bar dataKey="count" fill="#0c8ee9" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Top Vulnerable Products */}
      {safeArray(data.top_vulnerable_products).length > 0 && (
        <div className="card">
          <h3 className="text-lg font-semibold text-content-primary mb-4">Top Vulnerable Products</h3>
          <div className="space-y-3">
            {safeArray(data.top_vulnerable_products).map((product: any, i: number) => (
              <div key={i} className="flex items-center justify-between p-3 bg-surface-tertiary/50 rounded-lg">
                <span className="text-content-secondary font-medium">{product.name}</span>
                <span className="text-sm text-red-400 font-mono">{product.count} findings</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Recent Findings */}
      <div className="card">
        <h3 className="text-lg font-semibold text-content-primary mb-4">Recent Findings</h3>
        {safeArray(data.recent_findings).length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-border">
                  <th className="text-left py-3 px-4 text-xs font-medium text-content-muted uppercase">Severity</th>
                  <th className="text-left py-3 px-4 text-xs font-medium text-content-muted uppercase">Title</th>
                  <th className="text-left py-3 px-4 text-xs font-medium text-content-muted uppercase">Scanner</th>
                  <th className="text-left py-3 px-4 text-xs font-medium text-content-muted uppercase">Status</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border/50">
                {safeArray(data.recent_findings).map((finding: any) => (
                  <tr key={finding.id} className="hover:bg-surface-tertiary/30 transition-colors">
                    <td className="py-3 px-4">
                      <SeverityBadge severity={finding.severity} />
                    </td>
                    <td className="py-3 px-4 text-sm text-content-secondary max-w-md truncate">{finding.title}</td>
                    <td className="py-3 px-4 text-sm text-content-tertiary">{finding.scanner || '-'}</td>
                    <td className="py-3 px-4">
                      <span className="text-xs text-content-tertiary capitalize">{finding.status}</span>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="text-center py-12 text-content-muted">
            <ShieldCheck className="w-12 h-12 mx-auto mb-3 opacity-50" />
            <p>No findings yet. Import a scan to get started.</p>
          </div>
        )}
      </div>
    </div>
  )
}

function StatCard({
  title,
  value,
  icon: Icon,
  color,
  bgColor,
}: {
  title: string
  value: number
  icon: any
  color: string
  bgColor: string
}) {
  return (
    <div className="card-hover flex items-center gap-4">
      <div className={`w-12 h-12 ${bgColor} rounded-xl flex items-center justify-center`}>
        <Icon className={`w-6 h-6 ${color}`} />
      </div>
      <div>
        <p className="text-sm text-content-muted">{title}</p>
        <p className="text-2xl font-bold text-content-primary">{(value ?? 0).toLocaleString()}</p>
      </div>
    </div>
  )
}
