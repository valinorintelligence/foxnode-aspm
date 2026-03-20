import { useQuery } from '@tanstack/react-query'
import { useChartTheme } from '../lib/chartTheme'
import { scorecardAPI } from '../services/api'
import {
  Award,
  TrendingUp,
  TrendingDown,
  Minus,
  Trophy,
  Star,
  ArrowUp,
  ArrowDown,
} from 'lucide-react'
import {
  AreaChart,
  Area,
  XAxis,
  YAxis,
  CartesianGrid,
  Tooltip,
  ResponsiveContainer,
} from 'recharts'
import clsx from 'clsx'

const GRADE_COLORS: Record<string, { text: string; bg: string; border: string; glow: string }> = {
  A: { text: 'text-green-400', bg: 'bg-green-500/10', border: 'border-green-500/30', glow: '#10b981' },
  B: { text: 'text-blue-400', bg: 'bg-blue-500/10', border: 'border-blue-500/30', glow: '#3b82f6' },
  C: { text: 'text-yellow-400', bg: 'bg-yellow-500/10', border: 'border-yellow-500/30', glow: '#f59e0b' },
  D: { text: 'text-orange-400', bg: 'bg-orange-500/10', border: 'border-orange-500/30', glow: '#ea580c' },
  F: { text: 'text-red-400', bg: 'bg-red-500/10', border: 'border-red-500/30', glow: '#ef4444' },
}

const TREND_ICONS: Record<string, { icon: any; color: string; label: string }> = {
  improving: { icon: TrendingUp, color: 'text-green-400', label: 'Improving' },
  declining: { icon: TrendingDown, color: 'text-red-400', label: 'Declining' },
  stable: { icon: Minus, color: 'text-content-tertiary', label: 'Stable' },
}

export default function ScorecardPage() {
  const chart = useChartTheme()
  const { data: overview, isLoading } = useQuery({
    queryKey: ['scorecard-overview'],
    queryFn: () => scorecardAPI.overview().then((r) => r.data),
  })

  const { data: trends } = useQuery({
    queryKey: ['scorecard-trends'],
    queryFn: () => scorecardAPI.trends().then((r) => r.data),
  })

  if (isLoading) {
    return <div className="flex items-center justify-center h-64 text-content-muted">Loading scorecard...</div>
  }

  // Handle both object-style {score, grade, trend} and flat-style {org_score, org_grade, org_trend}
  const orgScore = typeof overview?.org_score === 'object'
    ? overview.org_score
    : { score: overview?.org_score || 0, grade: overview?.org_grade || 'F', trend: overview?.org_trend || 'stable' }
  const orgGrade = GRADE_COLORS[orgScore.grade] || GRADE_COLORS.F
  const orgTrend = TREND_ICONS[orgScore.trend] || TREND_ICONS.stable
  const OrgTrendIcon = orgTrend.icon

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <div className="flex items-center gap-3 mb-1">
          <div className="w-10 h-10 bg-amber-500/10 rounded-xl flex items-center justify-center">
            <Award className="w-5 h-5 text-amber-400" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-content-primary">Security Scorecard</h1>
            <p className="text-content-muted text-sm">Track security posture with letter grades and trends</p>
          </div>
        </div>
      </div>

      {/* Org-wide Score Hero */}
      <div className="card relative overflow-hidden">
        <div className="absolute top-0 right-0 w-64 h-64 opacity-5" style={{ background: `radial-gradient(circle, ${orgGrade.glow}, transparent 70%)` }} />
        <div className="flex items-center justify-between">
          <div>
            <p className="text-sm text-content-muted mb-1">Organization Security Score</p>
            <div className="flex items-end gap-4">
              <div className={clsx('text-7xl font-black', orgGrade.text)}>{orgScore.grade}</div>
              <div className="mb-2">
                <p className="text-3xl font-bold text-content-primary">{orgScore.score}<span className="text-lg text-content-muted">/100</span></p>
                <div className={clsx('flex items-center gap-1 mt-1', orgTrend.color)}>
                  <OrgTrendIcon className="w-4 h-4" />
                  <span className="text-sm font-medium">{orgTrend.label}</span>
                </div>
              </div>
            </div>
          </div>
          <div className="text-right space-y-1">
            {overview?.breakdown && Object.entries(overview.breakdown).map(([key, val]: [string, any]) => (
              <div key={key} className="flex items-center gap-3 justify-end">
                <span className="text-xs text-content-muted capitalize">{key.replace(/_/g, ' ')}</span>
                <div className="w-24 h-1.5 bg-surface-tertiary rounded-full overflow-hidden">
                  <div className="h-full bg-foxnode-500 rounded-full" style={{ width: `${Math.min(val, 100)}%` }} />
                </div>
                <span className="text-xs text-content-tertiary font-mono w-8 text-right">{val}%</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Score Trend Chart */}
      {trends?.data_points?.length > 0 && (
        <div className="card">
          <h3 className="text-lg font-semibold text-content-primary mb-4">Score Trend — Last 30 Days</h3>
          <div className="h-64">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={trends.data_points}>
                <CartesianGrid strokeDasharray="3 3" stroke={chart.gridStroke} />
                <XAxis dataKey="date" stroke={chart.axisStroke} tick={{ fontSize: 11 }} />
                <YAxis domain={[0, 100]} stroke={chart.axisStroke} tick={{ fontSize: 11 }} />
                <Tooltip
                  contentStyle={{ backgroundColor: chart.tooltipStyle.backgroundColor, border: chart.tooltipStyle.border, borderRadius: chart.tooltipStyle.borderRadius, color: chart.tooltipStyle.color }}
                />
                <defs>
                  <linearGradient id="scoreGrad" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="5%" stopColor="#0c8ee9" stopOpacity={0.3} />
                    <stop offset="95%" stopColor="#0c8ee9" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <Area type="monotone" dataKey="score" stroke="#0c8ee9" strokeWidth={2} fill="url(#scoreGrad)" />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>
      )}

      {/* Product Leaderboard */}
      <div className="card p-0 overflow-hidden">
        <div className="p-6 border-b border-border">
          <div className="flex items-center gap-2">
            <Trophy className="w-5 h-5 text-amber-400" />
            <h3 className="text-lg font-semibold text-content-primary">Product Leaderboard</h3>
          </div>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="bg-surface-tertiary/50">
                <th className="text-left py-3 px-4 text-xs font-medium text-content-muted uppercase w-12">Rank</th>
                <th className="text-left py-3 px-4 text-xs font-medium text-content-muted uppercase">Product</th>
                <th className="text-center py-3 px-4 text-xs font-medium text-content-muted uppercase">Grade</th>
                <th className="text-left py-3 px-4 text-xs font-medium text-content-muted uppercase">Score</th>
                <th className="text-left py-3 px-4 text-xs font-medium text-content-muted uppercase">Trend</th>
                <th className="text-left py-3 px-4 text-xs font-medium text-content-muted uppercase">Open Findings</th>
                <th className="text-left py-3 px-4 text-xs font-medium text-content-muted uppercase">Recommendations</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-border/50">
              {overview?.leaderboard?.map((product: any, index: number) => {
                const grade = GRADE_COLORS[product.grade] || GRADE_COLORS.F
                const trend = TREND_ICONS[product.trend] || TREND_ICONS.stable
                const TIcon = trend.icon
                return (
                  <tr key={product.product_id} className="hover:bg-surface-tertiary/30 transition-colors">
                    <td className="py-3 px-4">
                      {index < 3 ? (
                        <div className={clsx(
                          'w-7 h-7 rounded-full flex items-center justify-center text-xs font-bold',
                          index === 0 ? 'bg-amber-500/20 text-amber-400' :
                          index === 1 ? 'bg-gray-400/20 text-content-secondary' :
                          'bg-orange-600/20 text-orange-400'
                        )}>
                          {index === 0 ? <Star className="w-3.5 h-3.5" /> : index + 1}
                        </div>
                      ) : (
                        <span className="text-sm text-content-muted pl-2">{index + 1}</span>
                      )}
                    </td>
                    <td className="py-3 px-4">
                      <p className="text-sm font-medium text-content-secondary">{product.product_name}</p>
                    </td>
                    <td className="py-3 px-4 text-center">
                      <span className={clsx('text-2xl font-black', grade.text)}>{product.grade}</span>
                    </td>
                    <td className="py-3 px-4">
                      <div className="flex items-center gap-2">
                        <div className="w-20 h-2 bg-surface-tertiary rounded-full overflow-hidden">
                          <div
                            className="h-full rounded-full"
                            style={{
                              width: `${product.score}%`,
                              backgroundColor: grade.glow,
                            }}
                          />
                        </div>
                        <span className="text-xs text-content-tertiary font-mono">{product.score}</span>
                      </div>
                    </td>
                    <td className="py-3 px-4">
                      <span className={clsx('flex items-center gap-1 text-xs', trend.color)}>
                        <TIcon className="w-3.5 h-3.5" />
                        {trend.label}
                      </span>
                    </td>
                    <td className="py-3 px-4">
                      <span className="text-sm text-content-tertiary">{product.open_findings || 0}</span>
                    </td>
                    <td className="py-3 px-4">
                      {product.recommendations?.[0] && (
                        <p className="text-xs text-content-muted max-w-xs truncate">{product.recommendations[0]}</p>
                      )}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
