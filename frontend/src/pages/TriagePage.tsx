import { useState } from 'react'
import { useQuery, useMutation } from '@tanstack/react-query'
import { triageAPI, productsAPI } from '../services/api'
import {
  Brain,
  Zap,
  AlertTriangle,
  CheckCircle,
  Clock,
  Eye,
  Filter,
  TrendingUp,
  XCircle,
  ArrowRight,
} from 'lucide-react'
import SeverityBadge from '../components/common/SeverityBadge'
import clsx from 'clsx'

const PRIORITY_CONFIG: Record<string, { color: string; bg: string; icon: any; label: string }> = {
  immediate: { color: 'text-red-400', bg: 'bg-red-500/10 border-red-500/30', icon: Zap, label: 'Immediate' },
  next_sprint: { color: 'text-orange-400', bg: 'bg-orange-500/10 border-orange-500/30', icon: Clock, label: 'Next Sprint' },
  backlog: { color: 'text-blue-400', bg: 'bg-blue-500/10 border-blue-500/30', icon: ArrowRight, label: 'Backlog' },
  monitor: { color: 'text-gray-400', bg: 'bg-gray-500/10 border-gray-500/30', icon: Eye, label: 'Monitor' },
}

export default function TriagePage() {
  const [selectedProduct, setSelectedProduct] = useState<string>('')

  const { data: products } = useQuery({
    queryKey: ['products'],
    queryFn: () => productsAPI.list().then((r) => r.data),
  })

  const { data: summary, isLoading: summaryLoading } = useQuery({
    queryKey: ['triage-summary', selectedProduct],
    queryFn: () => triageAPI.summary(Number(selectedProduct)).then((r) => r.data),
    enabled: !!selectedProduct,
  })

  const bulkMutation = useMutation({
    mutationFn: (productId: number) => triageAPI.bulkAnalyze(productId),
  })

  const bulkResults = bulkMutation.data?.data

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <div className="flex items-center gap-3 mb-1">
            <div className="w-10 h-10 bg-purple-500/10 rounded-xl flex items-center justify-center">
              <Brain className="w-5 h-5 text-purple-400" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-white">AI Finding Triage</h1>
              <p className="text-gray-500 text-sm">Intelligent prioritization and false positive detection</p>
            </div>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <select
            className="input"
            value={selectedProduct}
            onChange={(e) => setSelectedProduct(e.target.value)}
          >
            <option value="">Select product...</option>
            {products?.map((p: any) => (
              <option key={p.id} value={p.id}>{p.name}</option>
            ))}
          </select>
          <button
            onClick={() => selectedProduct && bulkMutation.mutate(Number(selectedProduct))}
            disabled={!selectedProduct || bulkMutation.isPending}
            className="btn-primary flex items-center gap-2"
          >
            <Brain className="w-4 h-4" />
            {bulkMutation.isPending ? 'Analyzing...' : 'Run Triage'}
          </button>
        </div>
      </div>

      {/* Summary Cards */}
      {summary && (
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          {Object.entries(PRIORITY_CONFIG).map(([key, config]) => {
            const count = summary.priority_counts?.[key] || 0
            const Icon = config.icon
            return (
              <div key={key} className="card-hover">
                <div className="flex items-center gap-3">
                  <div className={clsx('w-10 h-10 rounded-xl flex items-center justify-center', config.bg, 'border')}>
                    <Icon className={clsx('w-5 h-5', config.color)} />
                  </div>
                  <div>
                    <p className="text-xs text-gray-500">{config.label}</p>
                    <p className="text-2xl font-bold text-white">{count}</p>
                  </div>
                </div>
              </div>
            )
          })}
        </div>
      )}

      {/* False Positive Candidates */}
      {summary?.false_positive_candidates?.length > 0 && (
        <div className="card">
          <div className="flex items-center gap-2 mb-4">
            <XCircle className="w-5 h-5 text-yellow-400" />
            <h3 className="text-lg font-semibold text-white">Likely False Positives</h3>
            <span className="text-xs text-yellow-400 bg-yellow-500/10 border border-yellow-500/30 px-2 py-0.5 rounded-full">
              {summary.false_positive_candidates.length} detected
            </span>
          </div>
          <div className="space-y-2">
            {summary.false_positive_candidates.slice(0, 8).map((fp: any) => (
              <div key={fp.finding_id} className="flex items-center justify-between p-3 bg-gray-800/50 rounded-lg">
                <div className="flex items-center gap-3">
                  <SeverityBadge severity={fp.severity} />
                  <div>
                    <p className="text-sm text-gray-200">{fp.title}</p>
                    <p className="text-xs text-gray-500">{fp.reasoning}</p>
                  </div>
                </div>
                <div className="text-right">
                  <span className="text-xs text-yellow-400 font-mono">
                    {Math.round(fp.false_positive_likelihood * 100)}% likely FP
                  </span>
                </div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Grouped Findings */}
      {summary?.grouped_findings?.length > 0 && (
        <div className="card">
          <div className="flex items-center gap-2 mb-4">
            <Filter className="w-5 h-5 text-blue-400" />
            <h3 className="text-lg font-semibold text-white">Auto-Grouped Findings</h3>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
            {summary.grouped_findings.map((group: any, i: number) => (
              <div key={i} className="p-4 bg-gray-800/50 rounded-lg border border-gray-700/50">
                <div className="flex items-center justify-between mb-2">
                  <h4 className="text-sm font-semibold text-white">{group.group_key}</h4>
                  <span className="text-xs text-foxnode-400 font-mono">{group.count} findings</span>
                </div>
                <p className="text-xs text-gray-500">{group.description}</p>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Bulk Analysis Results */}
      {bulkResults?.results?.length > 0 && (
        <div className="card p-0 overflow-hidden">
          <div className="p-6 border-b border-gray-800">
            <div className="flex items-center gap-2">
              <TrendingUp className="w-5 h-5 text-green-400" />
              <h3 className="text-lg font-semibold text-white">Triage Results</h3>
              <span className="text-xs text-gray-500">Sorted by priority score</span>
            </div>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="bg-gray-800/50">
                  <th className="text-left py-3 px-4 text-xs font-medium text-gray-500 uppercase">Score</th>
                  <th className="text-left py-3 px-4 text-xs font-medium text-gray-500 uppercase">Priority</th>
                  <th className="text-left py-3 px-4 text-xs font-medium text-gray-500 uppercase">Severity</th>
                  <th className="text-left py-3 px-4 text-xs font-medium text-gray-500 uppercase">Title</th>
                  <th className="text-left py-3 px-4 text-xs font-medium text-gray-500 uppercase">FP Likelihood</th>
                  <th className="text-left py-3 px-4 text-xs font-medium text-gray-500 uppercase">Reasoning</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800/50">
                {bulkResults.results.map((result: any) => {
                  const priorityConf = PRIORITY_CONFIG[result.priority] || PRIORITY_CONFIG.monitor
                  const PIcon = priorityConf.icon
                  return (
                    <tr key={result.finding_id} className="hover:bg-gray-800/30 transition-colors">
                      <td className="py-3 px-4">
                        <div className="flex items-center gap-2">
                          <div
                            className="w-8 h-8 rounded-full flex items-center justify-center text-xs font-bold"
                            style={{
                              background: `conic-gradient(${result.score >= 70 ? '#ef4444' : result.score >= 40 ? '#f59e0b' : '#10b981'} ${result.score}%, #1f2937 0)`,
                            }}
                          >
                            <div className="w-6 h-6 rounded-full bg-gray-900 flex items-center justify-center text-white text-[10px]">
                              {result.score}
                            </div>
                          </div>
                        </div>
                      </td>
                      <td className="py-3 px-4">
                        <span className={clsx('inline-flex items-center gap-1.5 text-xs font-medium px-2 py-1 rounded border', priorityConf.bg, priorityConf.color)}>
                          <PIcon className="w-3 h-3" />
                          {priorityConf.label}
                        </span>
                      </td>
                      <td className="py-3 px-4">
                        <SeverityBadge severity={result.severity} />
                      </td>
                      <td className="py-3 px-4">
                        <p className="text-sm text-gray-200 max-w-xs truncate">{result.title}</p>
                      </td>
                      <td className="py-3 px-4">
                        <div className="flex items-center gap-2">
                          <div className="w-16 h-1.5 bg-gray-800 rounded-full overflow-hidden">
                            <div
                              className={clsx('h-full rounded-full', result.false_positive_likelihood > 0.6 ? 'bg-yellow-400' : 'bg-gray-600')}
                              style={{ width: `${result.false_positive_likelihood * 100}%` }}
                            />
                          </div>
                          <span className="text-xs text-gray-500">{Math.round(result.false_positive_likelihood * 100)}%</span>
                        </div>
                      </td>
                      <td className="py-3 px-4">
                        <p className="text-xs text-gray-500 max-w-xs truncate">{result.reasoning?.[0]}</p>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Empty State */}
      {!selectedProduct && !bulkResults && (
        <div className="card text-center py-16">
          <Brain className="w-16 h-16 mx-auto mb-4 text-purple-500/30" />
          <h3 className="text-lg font-medium text-gray-300 mb-2">Select a Product to Begin</h3>
          <p className="text-gray-500 max-w-md mx-auto">
            The AI triage engine analyzes your findings using pattern matching, severity weighting,
            and contextual scoring to prioritize what matters most.
          </p>
        </div>
      )}
    </div>
  )
}
