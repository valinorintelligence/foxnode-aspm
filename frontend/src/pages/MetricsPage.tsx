import { useState, useEffect } from 'react'
import { useChartTheme } from '../lib/chartTheme'
import { safeArray, safeObj } from '../lib/safe'
import { metricsAPI } from '../services/api'
import {
  Activity,
  TrendingUp,
  TrendingDown,
  Clock,
  Users,
  ScanLine,
  Target,
  AlertTriangle,
  CheckCircle,
  ArrowUpRight,
  ArrowDownRight,
  Minus,
  Shield,
  Zap,
} from 'lucide-react'
import {
  AreaChart,
  Area,
  BarChart,
  Bar,
  LineChart,
  Line,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
  Legend,
} from 'recharts'

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#f59e0b',
  low: '#3b82f6',
}

const RISK_LEVEL_STYLES: Record<string, { bg: string; border: string; text: string; badge: string }> = {
  critical: { bg: 'bg-red-500/5', border: 'border-red-500/20', text: 'text-red-400', badge: 'bg-red-500/20 text-red-300' },
  high: { bg: 'bg-orange-500/5', border: 'border-orange-500/20', text: 'text-orange-400', badge: 'bg-orange-500/20 text-orange-300' },
  medium: { bg: 'bg-yellow-500/5', border: 'border-yellow-500/20', text: 'text-yellow-400', badge: 'bg-yellow-500/20 text-yellow-300' },
  low: { bg: 'bg-blue-500/5', border: 'border-blue-500/20', text: 'text-blue-400', badge: 'bg-blue-500/20 text-blue-300' },
  info: { bg: 'bg-gray-500/5', border: 'border-gray-500/20', text: 'text-content-tertiary', badge: 'bg-gray-500/20 text-content-secondary' },
}

export default function MetricsPage() {
  const chart = useChartTheme()
  const DARK_TOOLTIP = {
    contentStyle: { backgroundColor: chart.tooltipStyle.backgroundColor, border: chart.tooltipStyle.border, borderRadius: '8px', color: chart.tooltipStyle.color },
    labelStyle: { color: chart.textColor },
  }
  const [loading, setLoading] = useState(true)
  const [execSummary, setExecSummary] = useState<any>(null)
  const [kpi, setKpi] = useState<any>(null)
  const [mttr, setMttr] = useState<any>(null)
  const [aging, setAging] = useState<any>(null)
  const [burndown, setBurndown] = useState<any>(null)
  const [velocity, setVelocity] = useState<any>(null)
  const [scannerEff, setScannerEff] = useState<any>(null)
  const [trends, setTrends] = useState<any>(null)
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    const fetchData = async () => {
      setLoading(true)
      setError(null)
      try {
        const [execRes, kpiRes, mttrRes, agingRes, burndownRes, velocityRes, scannerRes, trendsRes] =
          await Promise.allSettled([
            metricsAPI.executiveSummary(),
            metricsAPI.kpi(),
            metricsAPI.mttr(),
            metricsAPI.aging(),
            metricsAPI.burndown(),
            metricsAPI.velocity(),
            metricsAPI.scannerEffectiveness(),
            metricsAPI.trends(90),
          ])

        if (execRes.status === 'fulfilled') setExecSummary(execRes.value.data)
        if (kpiRes.status === 'fulfilled') setKpi(kpiRes.value.data)
        if (mttrRes.status === 'fulfilled') setMttr(mttrRes.value.data)
        if (agingRes.status === 'fulfilled') setAging(agingRes.value.data)
        if (burndownRes.status === 'fulfilled') setBurndown(burndownRes.value.data)
        if (velocityRes.status === 'fulfilled') setVelocity(velocityRes.value.data)
        if (scannerRes.status === 'fulfilled') setScannerEff(scannerRes.value.data)
        if (trendsRes.status === 'fulfilled') setTrends(trendsRes.value.data)
      } catch (err) {
        setError('Failed to load metrics data')
      } finally {
        setLoading(false)
      }
    }
    fetchData()
  }, [])

  const trendIcon = (trend: string) => {
    if (trend === 'improving' || trend === 'decreasing') return <ArrowDownRight className="w-4 h-4 text-green-400" />
    if (trend === 'worsening' || trend === 'increasing') return <ArrowUpRight className="w-4 h-4 text-red-400" />
    return <Minus className="w-4 h-4 text-content-tertiary" />
  }

  if (loading) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="flex flex-col items-center gap-3">
          <div className="w-8 h-8 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
          <span className="text-content-muted text-sm">Loading security metrics...</span>
        </div>
      </div>
    )
  }

  if (error) {
    return (
      <div className="flex items-center justify-center h-64">
        <div className="text-center">
          <AlertTriangle className="w-8 h-8 text-red-400 mx-auto mb-2" />
          <p className="text-content-tertiary">{error}</p>
        </div>
      </div>
    )
  }

  const riskLevel = execSummary?.overall_risk_level || 'medium'
  const riskStyle = RISK_LEVEL_STYLES[riskLevel] || RISK_LEVEL_STYLES.medium

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center gap-3">
        <div className="p-2 bg-gradient-to-br from-blue-500/20 to-cyan-500/20 rounded-xl">
          <Activity className="w-6 h-6 text-blue-400" />
        </div>
        <div>
          <h1 className="text-2xl font-bold text-content-primary">Security Metrics & KPIs</h1>
          <p className="text-content-tertiary text-sm">Track security performance with real-time analytics</p>
        </div>
      </div>

      {/* Executive Summary */}
      <div className={`rounded-xl p-6 border ${riskStyle.bg} ${riskStyle.border}`}>
        <div className="flex items-start justify-between mb-4">
          <div>
            <h2 className="text-lg font-semibold text-content-primary flex items-center gap-2">
              <Shield className="w-5 h-5 text-blue-400" />
              Executive Summary
            </h2>
            <div className="flex items-center gap-2 mt-1">
              <span className="text-sm text-content-tertiary">Risk trend:</span>
              <span className="flex items-center gap-1 text-sm font-medium capitalize">
                {trendIcon(execSummary?.risk_trend || 'stable')}
                <span className={
                  (execSummary?.risk_trend === 'improving' || execSummary?.risk_trend === 'decreasing') ? 'text-green-400' :
                  (execSummary?.risk_trend === 'worsening' || execSummary?.risk_trend === 'increasing') ? 'text-red-400' :
                  'text-content-tertiary'
                }>
                  {execSummary?.risk_trend || 'stable'}
                </span>
              </span>
            </div>
          </div>
          <div className="text-right">
            <span className={`inline-block px-3 py-1 rounded-full text-sm font-bold uppercase ${riskStyle.badge}`}>
              {riskLevel}
            </span>
            <div className="text-xs text-content-muted mt-1">Overall Risk Level</div>
          </div>
        </div>

        {/* Key Metrics Row */}
        {execSummary?.key_metrics && (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mb-4">
            {Object.entries(safeObj(execSummary.key_metrics)).slice(0, 4).map(([key, value]: [string, any]) => (
              <div key={key} className="bg-surface-tertiary/40 rounded-lg p-3">
                <div className="text-xs text-content-muted capitalize">{key.replace(/_/g, ' ')}</div>
                <div className="text-lg font-bold text-content-primary">{value}</div>
              </div>
            ))}
          </div>
        )}

        {/* Highlights */}
        {safeArray(execSummary?.highlights).length > 0 && (
          <div className="mb-3">
            <h4 className="text-xs font-semibold text-content-tertiary uppercase mb-2">Highlights</h4>
            <div className="flex flex-wrap gap-2">
              {safeArray(execSummary.highlights).map((h: string, i: number) => (
                <span key={i} className="text-xs bg-surface-tertiary/60 text-content-secondary px-3 py-1 rounded-full border border-border-secondary/50">
                  {h}
                </span>
              ))}
            </div>
          </div>
        )}

        {/* Action Items */}
        {safeArray(execSummary?.action_items).length > 0 && (
          <div>
            <h4 className="text-xs font-semibold text-content-tertiary uppercase mb-2">Action Items</h4>
            <ul className="space-y-1">
              {safeArray(execSummary.action_items).map((item: string, i: number) => (
                <li key={i} className="flex items-start gap-2 text-sm text-content-secondary">
                  <Zap className="w-3 h-3 text-amber-400 mt-1 flex-shrink-0" />
                  {item}
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>

      {/* KPI Cards */}
      {kpi && (
        <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-5 gap-4">
          {[
            { label: 'Open Findings', value: kpi.total_open ?? kpi.key_metrics?.total_open ?? 0, icon: AlertTriangle, color: 'text-red-400', iconBg: 'bg-red-500/10' },
            { label: 'Critical Open', value: kpi.critical_open ?? kpi.key_metrics?.critical_open ?? 0, icon: Target, color: 'text-orange-400', iconBg: 'bg-orange-500/10' },
            { label: 'MTTR (Critical)', value: kpi.mttr_critical ?? kpi.key_metrics?.mttr_critical ?? 'N/A', icon: Clock, color: 'text-yellow-400', iconBg: 'bg-yellow-500/10' },
            { label: 'SLA Compliance', value: kpi.sla_compliance_rate ?? kpi.key_metrics?.sla_compliance_rate ?? 'N/A', icon: CheckCircle, color: 'text-green-400', iconBg: 'bg-green-500/10' },
            { label: 'Resolution Rate', value: kpi.resolution_rate ?? 'N/A', icon: TrendingUp, color: 'text-blue-400', iconBg: 'bg-blue-500/10' },
          ].map((m) => (
            <div key={m.label} className="bg-surface-tertiary/50 border border-border-secondary/50 rounded-xl p-4">
              <div className="flex items-center gap-2 mb-2">
                <div className={`p-1.5 rounded-lg ${m.iconBg}`}>
                  <m.icon className={`w-4 h-4 ${m.color}`} />
                </div>
                <span className="text-xs text-content-tertiary">{m.label}</span>
              </div>
              <div className="text-2xl font-bold text-content-primary">{m.value}</div>
            </div>
          ))}
        </div>
      )}

      {/* MTTR Section */}
      {mttr && (
        <div className="bg-surface-tertiary/50 border border-border-secondary/50 rounded-xl p-5">
          <h3 className="text-sm font-semibold text-content-primary mb-4 flex items-center gap-2">
            <Clock className="w-4 h-4 text-yellow-400" />
            Mean Time to Remediate
          </h3>

          {/* Overall MTTR */}
          <div className="flex items-center gap-6 mb-5">
            <div className="bg-surface-secondary/50 rounded-xl p-4 text-center min-w-[140px]">
              <div className="text-3xl font-bold text-content-primary">{mttr.overall_hours ?? mttr.overall ?? 'N/A'}</div>
              <div className="text-xs text-content-muted mt-1">Overall Hours</div>
            </div>
            <div className="flex-1 grid grid-cols-2 md:grid-cols-4 gap-3">
              {(['critical', 'high', 'medium', 'low'] as const).map((sev) => {
                const hours = mttr.by_severity?.[sev] ?? 0
                return (
                  <div key={sev} className="bg-surface-secondary/30 border border-border-secondary/30 rounded-lg p-3">
                    <div className="flex items-center gap-1.5 mb-1">
                      <div className="w-2 h-2 rounded-full" style={{ backgroundColor: SEVERITY_COLORS[sev] }} />
                      <span className="text-xs text-content-tertiary capitalize">{sev}</span>
                    </div>
                    <div className="text-lg font-bold text-content-primary">{hours}h</div>
                  </div>
                )
              })}
            </div>
          </div>

          {/* MTTR Trend Sparkline */}
          {safeArray(mttr.trend_data).length > 0 && (
            <div>
              <h4 className="text-xs text-content-muted mb-2">30-Day MTTR Trend</h4>
              <ResponsiveContainer width="100%" height={100}>
                <AreaChart data={safeArray(mttr.trend_data)}>
                  <CartesianGrid strokeDasharray="3 3" stroke={chart.gridStroke} />
                  <XAxis dataKey="date" tick={{ fill: '#6b7280', fontSize: 10 }} />
                  <YAxis tick={{ fill: '#6b7280', fontSize: 10 }} />
                  <Tooltip {...DARK_TOOLTIP} />
                  <Area type="monotone" dataKey="hours" stroke="#f59e0b" fill="#f59e0b" fillOpacity={0.1} />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          )}

          {/* MTTR Bar Chart */}
          <div className="mt-4">
            <ResponsiveContainer width="100%" height={220}>
              <BarChart data={[
                { severity: 'Critical', hours: mttr.by_severity?.critical ?? 24 },
                { severity: 'High', hours: mttr.by_severity?.high ?? 72 },
                { severity: 'Medium', hours: mttr.by_severity?.medium ?? 168 },
                { severity: 'Low', hours: mttr.by_severity?.low ?? 720 },
              ]}>
                <CartesianGrid strokeDasharray="3 3" stroke={chart.gridStroke} />
                <XAxis dataKey="severity" tick={{ fill: '#9ca3af', fontSize: 12 }} />
                <YAxis tick={{ fill: '#9ca3af', fontSize: 12 }} />
                <Tooltip {...DARK_TOOLTIP} />
                <Bar dataKey="hours" fill="#8b5cf6" radius={[4, 4, 0, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Finding Aging Analysis */}
        {aging ? (
          <div className="bg-surface-tertiary/50 border border-border-secondary/50 rounded-xl p-5">
            <h3 className="text-sm font-semibold text-content-primary mb-4 flex items-center gap-2">
              <Clock className="w-4 h-4 text-orange-400" />
              Finding Aging Analysis
            </h3>
            <ResponsiveContainer width="100%" height={260}>
              <BarChart
                layout="vertical"
                data={Array.isArray(aging.buckets)
                  ? aging.buckets
                  : typeof aging.buckets === 'object' && aging.buckets
                    ? Object.entries(aging.buckets).map(([bucket, counts]: [string, any]) => ({ bucket, ...safeObj(counts) }))
                    : []}

              >
                <CartesianGrid strokeDasharray="3 3" stroke={chart.gridStroke} />
                <XAxis type="number" tick={{ fill: '#9ca3af', fontSize: 11 }} />
                <YAxis dataKey="bucket" type="category" tick={{ fill: '#9ca3af', fontSize: 11 }} width={60} />
                <Tooltip {...DARK_TOOLTIP} />
                <Legend wrapperStyle={{ fontSize: '11px', color: '#9ca3af' }} />
                <Bar dataKey="critical" stackId="a" fill="#ef4444" name="Critical" />
                <Bar dataKey="high" stackId="a" fill="#f97316" name="High" />
                <Bar dataKey="medium" stackId="a" fill="#f59e0b" name="Medium" />
                <Bar dataKey="low" stackId="a" fill="#3b82f6" name="Low" radius={[0, 4, 4, 0]} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        ) : (
          <div className="bg-surface-tertiary/50 border border-border-secondary/50 rounded-xl p-5 flex items-center justify-center h-64">
            <p className="text-content-muted text-sm">No aging data available</p>
          </div>
        )}

        {/* Risk Burndown */}
        {burndown ? (
          <div className="bg-surface-tertiary/50 border border-border-secondary/50 rounded-xl p-5">
            <h3 className="text-sm font-semibold text-content-primary mb-4 flex items-center justify-between">
              <span className="flex items-center gap-2">
                <TrendingDown className="w-4 h-4 text-green-400" />
                Risk Burndown (30 Days)
              </span>
              {burndown.trend_direction && (
                <span className={`text-xs px-2 py-0.5 rounded-full ${
                  burndown.trend_direction === 'decreasing' ? 'bg-green-500/10 text-green-400' :
                  burndown.trend_direction === 'increasing' ? 'bg-red-500/10 text-red-400' :
                  'bg-gray-500/10 text-content-tertiary'
                }`}>
                  {burndown.trend_direction === 'decreasing' ? 'Improving' :
                   burndown.trend_direction === 'increasing' ? 'Worsening' : 'Stable'}
                </span>
              )}
            </h3>
            <ResponsiveContainer width="100%" height={240}>
              <AreaChart data={safeArray(burndown.data_points ?? burndown)}>
                <CartesianGrid strokeDasharray="3 3" stroke={chart.gridStroke} />
                <XAxis dataKey="date" tick={{ fill: '#9ca3af', fontSize: 11 }} />
                <YAxis tick={{ fill: '#9ca3af', fontSize: 11 }} />
                <Tooltip {...DARK_TOOLTIP} />
                <Area type="monotone" dataKey="value" stroke="#10b981" fill="#10b981" fillOpacity={0.1} name="Risk Score" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        ) : (
          <div className="bg-surface-tertiary/50 border border-border-secondary/50 rounded-xl p-5 flex items-center justify-center h-64">
            <p className="text-content-muted text-sm">No burndown data available</p>
          </div>
        )}
      </div>

      {/* Team Velocity */}
      {velocity ? (
        <div className="bg-surface-tertiary/50 border border-border-secondary/50 rounded-xl p-5">
          <h3 className="text-sm font-semibold text-content-primary mb-4 flex items-center gap-2">
            <Users className="w-4 h-4 text-purple-400" />
            Team Velocity
          </h3>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            {/* Top Resolvers */}
            <div>
              <h4 className="text-xs text-content-muted uppercase mb-3">Top Resolvers</h4>
              <div className="space-y-2">
                {safeArray(velocity.top_resolvers).slice(0, 5).map((user: any, i: number) => (
                  <div key={i} className="flex items-center gap-3 bg-surface-secondary/30 rounded-lg p-2.5">
                    <div className="w-8 h-8 bg-purple-500/20 rounded-full flex items-center justify-center text-sm font-bold text-purple-400">
                      {i + 1}
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-medium text-content-primary truncate">{user.name || user.username}</p>
                      <p className="text-xs text-content-muted">{user.resolved || user.count} resolved</p>
                    </div>
                  </div>
                ))}
                {safeArray(velocity.top_resolvers).length === 0 && (
                  <p className="text-xs text-content-muted">No resolver data</p>
                )}
              </div>
            </div>

            {/* Weekly Resolution Chart */}
            <div className="lg:col-span-2">
              <div className="flex items-center justify-between mb-3">
                <h4 className="text-xs text-content-muted uppercase">Weekly Resolutions</h4>
                {velocity.resolution_rate != null && (
                  <span className="text-xs font-medium text-green-400 bg-green-500/10 px-2 py-0.5 rounded-full">
                    {typeof velocity.resolution_rate === 'number' ? `${velocity.resolution_rate.toFixed(1)}%` : velocity.resolution_rate} resolution rate
                  </span>
                )}
              </div>
              {safeArray(velocity.weekly_data).length > 0 ? (
                <ResponsiveContainer width="100%" height={200}>
                  <BarChart data={safeArray(velocity.weekly_data)}>
                    <CartesianGrid strokeDasharray="3 3" stroke={chart.gridStroke} />
                    <XAxis dataKey="week" tick={{ fill: '#9ca3af', fontSize: 11 }} />
                    <YAxis tick={{ fill: '#9ca3af', fontSize: 11 }} />
                    <Tooltip {...DARK_TOOLTIP} />
                    <Bar dataKey="resolved" fill="#8b5cf6" radius={[4, 4, 0, 0]} name="Resolved" />
                    <Bar dataKey="new" fill="#ef4444" radius={[4, 4, 0, 0]} name="New" />
                  </BarChart>
                </ResponsiveContainer>
              ) : (
                <div className="flex items-center justify-center h-[200px] text-content-muted text-sm">
                  No weekly data available
                </div>
              )}
            </div>
          </div>
        </div>
      ) : (
        <div className="bg-surface-tertiary/50 border border-border-secondary/50 rounded-xl p-5 flex items-center justify-center h-48">
          <p className="text-content-muted text-sm">No velocity data available</p>
        </div>
      )}

      {/* Scanner Effectiveness */}
      {scannerEff ? (
        <div className="bg-surface-tertiary/50 border border-border-secondary/50 rounded-xl p-5">
          <h3 className="text-sm font-semibold text-content-primary mb-4 flex items-center gap-2">
            <ScanLine className="w-4 h-4 text-cyan-400" />
            Scanner Effectiveness
          </h3>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border-secondary/50">
                  <th className="text-left text-xs text-content-tertiary font-medium pb-3 pr-4">Scanner</th>
                  <th className="text-right text-xs text-content-tertiary font-medium pb-3 px-3">Total</th>
                  <th className="text-right text-xs text-content-tertiary font-medium pb-3 px-3">Unique</th>
                  <th className="text-right text-xs text-content-tertiary font-medium pb-3 px-3">Duplicates</th>
                  <th className="text-right text-xs text-content-tertiary font-medium pb-3 px-3">FP Rate</th>
                  <th className="text-left text-xs text-content-tertiary font-medium pb-3 pl-3">Severity Distribution</th>
                </tr>
              </thead>
              <tbody>
                {safeArray(scannerEff.scanners ?? scannerEff).map((scanner: any, i: number) => {
                  const name = scanner.name ?? scanner.scanner ?? `Scanner ${i + 1}`
                  const total = scanner.total_findings ?? scanner.total ?? 0
                  const unique = scanner.unique_findings ?? scanner.unique ?? 0
                  const duplicates = scanner.duplicate_findings ?? scanner.duplicates ?? (total - unique)
                  const fpRate = scanner.false_positive_rate ?? scanner.fp_rate ?? 0
                  const sevDist = scanner.severity_distribution ?? scanner.severities ?? {}

                  return (
                    <tr key={i} className="border-b border-border-secondary/20 hover:bg-border-secondary/10">
                      <td className="py-3 pr-4 text-content-primary font-medium">{name}</td>
                      <td className="py-3 px-3 text-right text-content-secondary font-mono">{total}</td>
                      <td className="py-3 px-3 text-right text-content-secondary font-mono">{unique}</td>
                      <td className="py-3 px-3 text-right text-content-secondary font-mono">{duplicates}</td>
                      <td className="py-3 px-3 text-right">
                        <span className={`font-mono ${fpRate > 20 ? 'text-red-400' : fpRate > 10 ? 'text-yellow-400' : 'text-green-400'}`}>
                          {typeof fpRate === 'number' ? `${fpRate.toFixed(1)}%` : fpRate}
                        </span>
                      </td>
                      <td className="py-3 pl-3">
                        <div className="flex items-center gap-1">
                          {Object.entries(safeObj(sevDist)).map(([sev, count]: [string, any]) => (
                            <span
                              key={sev}
                              className="text-[10px] px-1.5 py-0.5 rounded font-mono"
                              style={{
                                backgroundColor: `${SEVERITY_COLORS[sev] || '#6b7280'}20`,
                                color: SEVERITY_COLORS[sev] || '#9ca3af',
                              }}
                            >
                              {sev[0]?.toUpperCase()}: {count}
                            </span>
                          ))}
                          {Object.keys(sevDist).length === 0 && (
                            <span className="text-xs text-content-muted">-</span>
                          )}
                        </div>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
            {(!scannerEff.scanners && Object.keys(scannerEff).length === 0) && (
              <p className="text-center text-content-muted text-sm py-6">No scanner data available</p>
            )}
          </div>
        </div>
      ) : (
        <div className="bg-surface-tertiary/50 border border-border-secondary/50 rounded-xl p-5 flex items-center justify-center h-48">
          <p className="text-content-muted text-sm">No scanner effectiveness data available</p>
        </div>
      )}

      {/* Vulnerability Trends */}
      {trends ? (
        <div className="bg-surface-tertiary/50 border border-border-secondary/50 rounded-xl p-5">
          <h3 className="text-sm font-semibold text-content-primary mb-4 flex items-center gap-2">
            <TrendingUp className="w-4 h-4 text-blue-400" />
            Vulnerability Trends (90 Days)
          </h3>
          <ResponsiveContainer width="100%" height={280}>
            <LineChart data={safeArray(trends.data_points ?? trends.trend_data)}>
              <CartesianGrid strokeDasharray="3 3" stroke={chart.gridStroke} />
              <XAxis dataKey="date" tick={{ fill: '#9ca3af', fontSize: 11 }} />
              <YAxis tick={{ fill: '#9ca3af', fontSize: 11 }} />
              <Tooltip {...DARK_TOOLTIP} />
              <Legend wrapperStyle={{ fontSize: '12px', color: '#9ca3af' }} />
              <Line type="monotone" dataKey="new" stroke="#ef4444" strokeWidth={2} dot={false} name="New Findings" />
              <Line type="monotone" dataKey="resolved" stroke="#10b981" strokeWidth={2} dot={false} name="Resolved" />
            </LineChart>
          </ResponsiveContainer>
        </div>
      ) : (
        <div className="bg-surface-tertiary/50 border border-border-secondary/50 rounded-xl p-5 flex items-center justify-center h-48">
          <p className="text-content-muted text-sm">No trend data available</p>
        </div>
      )}
    </div>
  )
}
