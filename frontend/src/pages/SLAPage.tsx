import { useQuery } from '@tanstack/react-query'
import { slaAPI } from '../services/api'
import {
  Timer,
  AlertTriangle,
  CheckCircle,
  XCircle,
  Flame,
  Clock,
  Shield,
  TrendingUp,
} from 'lucide-react'
import SeverityBadge from '../components/common/SeverityBadge'
import clsx from 'clsx'

const RISK_COLORS: Record<string, string> = {
  critical: 'bg-red-500',
  high: 'bg-orange-500',
  medium: 'bg-yellow-500',
  low: 'bg-blue-500',
  none: 'bg-surface-tertiary',
}

const RISK_BG: Record<string, string> = {
  critical: 'bg-red-500/20 text-red-300',
  high: 'bg-orange-500/20 text-orange-300',
  medium: 'bg-yellow-500/20 text-yellow-300',
  low: 'bg-blue-500/20 text-blue-300',
  none: 'bg-surface-tertiary/50 text-content-muted',
}

export default function SLAPage() {
  const { data: status, isLoading } = useQuery({
    queryKey: ['sla-status'],
    queryFn: () => slaAPI.status().then((r) => r.data),
  })

  const { data: heatmap } = useQuery({
    queryKey: ['sla-heatmap'],
    queryFn: () => slaAPI.heatmap().then((r) => r.data),
  })

  const { data: breaches } = useQuery({
    queryKey: ['sla-breaches'],
    queryFn: () => slaAPI.breaches().then((r) => r.data),
  })

  const { data: config } = useQuery({
    queryKey: ['sla-config'],
    queryFn: () => slaAPI.config().then((r) => r.data),
  })

  if (isLoading) {
    return <div className="flex items-center justify-center h-64 text-content-muted">Loading SLA data...</div>
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <div className="flex items-center gap-3 mb-1">
          <div className="w-10 h-10 bg-rose-500/10 rounded-xl flex items-center justify-center">
            <Timer className="w-5 h-5 text-rose-400" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-content-primary">SLA Tracker & Risk Heatmap</h1>
            <p className="text-content-muted text-sm">Monitor remediation timelines and identify risk concentration</p>
          </div>
        </div>
      </div>

      {/* SLA Summary Cards */}
      <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
        <div className="card-hover">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-green-500/10 rounded-xl flex items-center justify-center">
              <CheckCircle className="w-5 h-5 text-green-400" />
            </div>
            <div>
              <p className="text-xs text-content-muted">Within SLA</p>
              <p className="text-2xl font-bold text-green-400">{status?.in_sla || 0}</p>
            </div>
          </div>
        </div>
        <div className="card-hover">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-red-500/10 rounded-xl flex items-center justify-center">
              <XCircle className="w-5 h-5 text-red-400" />
            </div>
            <div>
              <p className="text-xs text-content-muted">SLA Breached</p>
              <p className="text-2xl font-bold text-red-400">{status?.breached || 0}</p>
            </div>
          </div>
        </div>
        <div className="card-hover">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-amber-500/10 rounded-xl flex items-center justify-center">
              <Flame className="w-5 h-5 text-amber-400" />
            </div>
            <div>
              <p className="text-xs text-content-muted">Breach Rate</p>
              <p className="text-2xl font-bold text-amber-400">{status?.breach_rate || 0}%</p>
            </div>
          </div>
        </div>
        <div className="card-hover">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 bg-blue-500/10 rounded-xl flex items-center justify-center">
              <Clock className="w-5 h-5 text-blue-400" />
            </div>
            <div>
              <p className="text-xs text-content-muted">Avg Time to Fix</p>
              <p className="text-2xl font-bold text-blue-400">{status?.avg_time_to_remediate_days || 0}<span className="text-sm text-content-muted">d</span></p>
            </div>
          </div>
        </div>
      </div>

      {/* SLA Targets */}
      {config && (
        <div className="card">
          <h3 className="text-sm font-semibold text-content-tertiary uppercase mb-3">SLA Targets</h3>
          <div className="flex flex-wrap gap-4">
            {Object.entries(config.targets || {}).map(([sev, hours]: [string, any]) => (
              <div key={sev} className="flex items-center gap-2 px-3 py-2 bg-surface-tertiary/50 rounded-lg">
                <SeverityBadge severity={sev} />
                <span className="text-xs text-content-tertiary">
                  {hours < 24 ? `${hours}h` : hours < 168 ? `${Math.round(hours / 24)}d` : `${Math.round(hours / 168)}w`}
                </span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Risk Heatmap */}
      {heatmap && (Array.isArray(heatmap) ? heatmap.length > 0 : heatmap?.matrix?.length > 0) && (
        <div className="card">
          <div className="flex items-center gap-2 mb-4">
            <Shield className="w-5 h-5 text-foxnode-400" />
            <h3 className="text-lg font-semibold text-content-primary">Risk Heatmap</h3>
            <span className="text-xs text-content-muted">Products × Severity</span>
          </div>

          <div className="overflow-x-auto">
            {(() => {
              // Transform flat array [{product_id, product_name, severity, count, breached_count, risk_level}]
              // into matrix rows [{product_id, product_name, cells: {severity: {count, breached_count, risk_level}}}]
              const rawData = Array.isArray(heatmap) ? heatmap : heatmap?.matrix || []
              const productMap: Record<number, any> = {}
              rawData.forEach((item: any) => {
                if (!productMap[item.product_id]) {
                  productMap[item.product_id] = { product_id: item.product_id, product_name: item.product_name, cells: {} }
                }
                productMap[item.product_id].cells[item.severity] = {
                  count: item.count, breached_count: item.breached_count, risk_level: item.risk_level
                }
              })
              const matrixRows = Object.values(productMap)

              return (
                <table className="w-full">
                  <thead>
                    <tr>
                      <th className="text-left py-2 px-3 text-xs font-medium text-content-muted uppercase w-48">Product</th>
                      {['critical', 'high', 'medium', 'low', 'info'].map((sev) => (
                        <th key={sev} className="text-center py-2 px-3 text-xs font-medium text-content-muted uppercase">{sev}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border/30">
                    {matrixRows.map((row: any) => (
                      <tr key={row.product_id} className="hover:bg-surface-tertiary/20">
                        <td className="py-2 px-3 text-sm text-content-secondary font-medium">{row.product_name}</td>
                        {['critical', 'high', 'medium', 'low', 'info'].map((sev) => {
                          const cell = row.cells?.[sev] || { count: 0, breached_count: 0, risk_level: 'none' }
                          return (
                            <td key={sev} className="py-2 px-3 text-center">
                              {cell.count > 0 ? (
                                <div className="inline-flex flex-col items-center">
                                  <span className={clsx(
                                    'inline-flex items-center justify-center w-10 h-10 rounded-lg text-sm font-bold',
                                    RISK_BG[cell.risk_level] || RISK_BG.none,
                                  )}>
                                    {cell.count}
                                  </span>
                                  {cell.breached_count > 0 && (
                                    <span className="text-[10px] text-red-400 mt-0.5 flex items-center gap-0.5">
                                      <Flame className="w-2.5 h-2.5" />{cell.breached_count}
                                    </span>
                                  )}
                                </div>
                              ) : (
                                <span className="text-content-muted">—</span>
                              )}
                            </td>
                          )
                        })}
                      </tr>
                    ))}
                  </tbody>
                </table>
              )
            })()}
          </div>

          {/* Legend */}
          <div className="flex items-center gap-4 mt-4 pt-4 border-t border-border">
            <span className="text-xs text-content-muted">Risk Level:</span>
            {['critical', 'high', 'medium', 'low'].map((level) => (
              <span key={level} className="flex items-center gap-1.5 text-xs">
                <div className={clsx('w-3 h-3 rounded', RISK_COLORS[level])} />
                <span className="text-content-tertiary capitalize">{level}</span>
              </span>
            ))}
            <span className="flex items-center gap-1.5 text-xs ml-4">
              <Flame className="w-3 h-3 text-red-400" />
              <span className="text-content-tertiary">= SLA Breached</span>
            </span>
          </div>
        </div>
      )}

      {/* SLA Breached Findings */}
      {(() => {
        const breachList = Array.isArray(breaches) ? breaches : breaches?.findings || []
        return breachList.length > 0 ? (
        <div className="card p-0 overflow-hidden">
          <div className="p-6 border-b border-border">
            <div className="flex items-center gap-2">
              <AlertTriangle className="w-5 h-5 text-red-400" />
              <h3 className="text-lg font-semibold text-content-primary">SLA Breached Findings</h3>
              <span className="text-xs text-red-400 bg-red-500/10 border border-red-500/30 px-2 py-0.5 rounded-full">
                {breachList.length} breaches
              </span>
            </div>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="bg-surface-tertiary/50">
                  <th className="text-left py-3 px-4 text-xs font-medium text-content-muted uppercase">Severity</th>
                  <th className="text-left py-3 px-4 text-xs font-medium text-content-muted uppercase">Title</th>
                  <th className="text-left py-3 px-4 text-xs font-medium text-content-muted uppercase">Product</th>
                  <th className="text-left py-3 px-4 text-xs font-medium text-content-muted uppercase">SLA Target</th>
                  <th className="text-left py-3 px-4 text-xs font-medium text-content-muted uppercase">Elapsed</th>
                  <th className="text-left py-3 px-4 text-xs font-medium text-content-muted uppercase">Overdue By</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border/50">
                {breachList.map((b: any) => {
                  const overdue = Math.max(0, b.elapsed_hours - b.sla_target_hours)
                  return (
                    <tr key={b.finding_id} className="hover:bg-surface-tertiary/30 transition-colors">
                      <td className="py-3 px-4"><SeverityBadge severity={b.severity} /></td>
                      <td className="py-3 px-4 text-sm text-content-secondary max-w-xs truncate">{b.title}</td>
                      <td className="py-3 px-4 text-sm text-content-tertiary">{b.product_name}</td>
                      <td className="py-3 px-4 text-xs text-content-muted font-mono">
                        {b.sla_target_hours < 24 ? `${b.sla_target_hours}h` : `${Math.round(b.sla_target_hours / 24)}d`}
                      </td>
                      <td className="py-3 px-4 text-xs text-content-tertiary font-mono">
                        {Math.round(b.elapsed_hours / 24)}d {Math.round(b.elapsed_hours % 24)}h
                      </td>
                      <td className="py-3 px-4">
                        <span className="text-xs text-red-400 font-mono font-bold">
                          +{overdue < 24 ? `${Math.round(overdue)}h` : `${Math.round(overdue / 24)}d`}
                        </span>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </div>
        ) : null
      })()}
    </div>
  )
}
