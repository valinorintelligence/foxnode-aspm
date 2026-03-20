import { useState, useEffect } from 'react'
import { useQuery } from '@tanstack/react-query'
import { attackPathAPI, productsAPI } from '../services/api'
import {
  Network, AlertTriangle, Shield, Target, ArrowRight, Zap, Globe,
  Server, Database, Lock, Loader2, TrendingUp, Activity
} from 'lucide-react'

const riskColors: Record<string, { bg: string; text: string; border: string }> = {
  critical: { bg: 'bg-red-500/10', text: 'text-red-400', border: 'border-red-500/30' },
  high: { bg: 'bg-orange-500/10', text: 'text-orange-400', border: 'border-orange-500/30' },
  medium: { bg: 'bg-yellow-500/10', text: 'text-yellow-400', border: 'border-yellow-500/30' },
  low: { bg: 'bg-green-500/10', text: 'text-green-400', border: 'border-green-500/30' },
}

const nodeTypeColors: Record<string, { bg: string; text: string; ring: string }> = {
  entry_point: { bg: 'bg-red-500/20', text: 'text-red-400', ring: 'ring-red-500/40' },
  weakness: { bg: 'bg-yellow-500/20', text: 'text-yellow-400', ring: 'ring-yellow-500/40' },
  data_store: { bg: 'bg-blue-500/20', text: 'text-blue-400', ring: 'ring-blue-500/40' },
  external: { bg: 'bg-purple-500/20', text: 'text-purple-400', ring: 'ring-purple-500/40' },
  vulnerability: { bg: 'bg-orange-500/20', text: 'text-orange-400', ring: 'ring-orange-500/40' },
  service: { bg: 'bg-cyan-500/20', text: 'text-cyan-400', ring: 'ring-cyan-500/40' },
  target: { bg: 'bg-pink-500/20', text: 'text-pink-400', ring: 'ring-pink-500/40' },
}

function getRiskLevel(score: number): string {
  if (score >= 80) return 'critical'
  if (score >= 60) return 'high'
  if (score >= 40) return 'medium'
  return 'low'
}

function getNodeIcon(type: string) {
  const icons: Record<string, any> = {
    entry_point: Globe,
    vulnerability: AlertTriangle,
    weakness: AlertTriangle,
    data_store: Database,
    service: Server,
    external: Globe,
    target: Target,
  }
  return icons[type] || Shield
}

function severityCount(items: any[], severity: string): number {
  return items.filter((i: any) => i.severity === severity).length
}

export default function AttackPathPage() {
  const [selectedProduct, setSelectedProduct] = useState<number | null>(null)
  const [selectedPath, setSelectedPath] = useState<any>(null)

  const { data: products } = useQuery({
    queryKey: ['products'],
    queryFn: () => productsAPI.list(),
  })

  const { data: overview, isLoading: overviewLoading } = useQuery({
    queryKey: ['attack-paths-overview'],
    queryFn: () => attackPathAPI.overview(),
  })

  const { data: paths, isLoading: pathsLoading } = useQuery({
    queryKey: ['attack-paths', selectedProduct],
    queryFn: () => attackPathAPI.product(selectedProduct!),
    enabled: !!selectedProduct,
  })

  const { data: surface, isLoading: surfaceLoading } = useQuery({
    queryKey: ['attack-surface', selectedProduct],
    queryFn: () => attackPathAPI.surface(selectedProduct!),
    enabled: !!selectedProduct,
  })

  const { data: graph, isLoading: graphLoading } = useQuery({
    queryKey: ['attack-graph', selectedProduct],
    queryFn: () => attackPathAPI.graph(selectedProduct!),
    enabled: !!selectedProduct,
  })

  // Reset selected path when product changes
  useEffect(() => {
    setSelectedPath(null)
  }, [selectedProduct])

  const attackPaths = paths?.data?.attack_paths || paths?.data || []
  const surfaceData = surface?.data || null
  const graphData = graph?.data || null
  const overviewData = overview?.data || null

  // Compute average risk score from overview product_breakdown
  const avgRiskScore = overviewData?.product_breakdown?.length
    ? Math.round(
        overviewData.product_breakdown.reduce(
          (sum: number, p: any) => sum + (p.highest_risk_score || 0),
          0
        ) / overviewData.product_breakdown.length
      )
    : 0

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-gradient-to-br from-red-500/20 to-orange-500/20 rounded-xl">
            <Network className="w-6 h-6 text-red-400" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-white">Attack Path Analysis</h1>
            <p className="text-gray-400 text-sm">
              Discover attack chains and visualize your attack surface
            </p>
          </div>
        </div>
        <select
          className="bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white focus:outline-none focus:ring-2 focus:ring-red-500/50"
          value={selectedProduct || ''}
          onChange={(e) =>
            setSelectedProduct(e.target.value ? Number(e.target.value) : null)
          }
        >
          <option value="">Select product...</option>
          {products?.data?.map((p: any) => (
            <option key={p.id} value={p.id}>
              {p.name}
            </option>
          ))}
        </select>
      </div>

      {/* Overview Stats (always shown) */}
      {overviewLoading ? (
        <div className="flex items-center justify-center py-8">
          <Loader2 className="w-6 h-6 text-gray-400 animate-spin" />
          <span className="ml-2 text-gray-400 text-sm">Loading overview...</span>
        </div>
      ) : overviewData ? (
        <div className="grid grid-cols-4 gap-4">
          {[
            {
              label: 'Total Attack Paths',
              value: overviewData.total_attack_paths || 0,
              color: 'text-red-400',
              icon: Network,
              gradient: 'from-red-500/10 to-red-500/5',
            },
            {
              label: 'Critical Paths',
              value: overviewData.critical_paths || 0,
              color: 'text-orange-400',
              icon: Zap,
              gradient: 'from-orange-500/10 to-orange-500/5',
            },
            {
              label: 'High-Risk Products',
              value: overviewData.products_at_risk || 0,
              color: 'text-yellow-400',
              icon: Target,
              gradient: 'from-yellow-500/10 to-yellow-500/5',
            },
            {
              label: 'Average Risk Score',
              value: avgRiskScore,
              color: 'text-blue-400',
              icon: TrendingUp,
              gradient: 'from-blue-500/10 to-blue-500/5',
            },
          ].map((s) => (
            <div
              key={s.label}
              className={`bg-gradient-to-br ${s.gradient} border border-gray-700/50 rounded-xl p-4`}
            >
              <div className="flex items-center gap-2 mb-2">
                <s.icon className={`w-4 h-4 ${s.color}`} />
                <span className="text-xs text-gray-400">{s.label}</span>
              </div>
              <div className={`text-2xl font-bold text-white`}>{s.value}</div>
            </div>
          ))}
        </div>
      ) : null}

      {/* Product Not Selected - Overview Details */}
      {!selectedProduct ? (
        <div className="space-y-4">
          {overviewData?.product_breakdown?.length > 0 ? (
            <div className="bg-gray-800/50 border border-gray-700/50 rounded-xl p-6">
              <h3 className="text-sm font-semibold text-white mb-4 flex items-center gap-2">
                <Activity className="w-4 h-4 text-red-400" />
                Products with Attack Paths
              </h3>
              <div className="space-y-3">
                {overviewData.product_breakdown.map((p: any) => {
                  const risk = getRiskLevel(p.highest_risk_score || 0)
                  const colors = riskColors[risk]
                  return (
                    <button
                      key={p.product_id}
                      onClick={() => setSelectedProduct(p.product_id)}
                      className="w-full text-left bg-gray-900/50 border border-gray-700/50 rounded-lg p-4 hover:border-gray-600 transition-all"
                    >
                      <div className="flex items-center justify-between">
                        <div>
                          <h4 className="text-sm font-semibold text-white">
                            {p.product_name}
                          </h4>
                          <p className="text-xs text-gray-400 mt-1">
                            {p.attack_path_count} attack path{p.attack_path_count !== 1 ? 's' : ''} discovered
                            {' '}&middot;{' '}
                            Top chain: {p.top_path}
                          </p>
                        </div>
                        <div className="flex items-center gap-3">
                          {p.critical_paths > 0 && (
                            <span className="text-xs px-2 py-0.5 rounded-full bg-red-500/10 text-red-400">
                              {p.critical_paths} critical
                            </span>
                          )}
                          <span
                            className={`text-xs px-2 py-1 rounded-full ${colors.bg} ${colors.text} font-semibold`}
                          >
                            {p.highest_risk_score}/100
                          </span>
                          <ArrowRight className="w-4 h-4 text-gray-500" />
                        </div>
                      </div>
                    </button>
                  )
                })}
              </div>
            </div>
          ) : (
            <div className="bg-gray-800/50 border border-gray-700/50 rounded-xl p-12 text-center">
              <Network className="w-12 h-12 text-gray-600 mx-auto mb-4" />
              <h3 className="text-lg font-medium text-gray-400">Select a Product</h3>
              <p className="text-sm text-gray-500 mt-1">
                Choose a product to discover attack paths and visualize your attack surface
              </p>
            </div>
          )}
        </div>
      ) : (
        /* Product Selected - Full Analysis */
        <div className="space-y-6">
          {/* Loading state */}
          {(pathsLoading || surfaceLoading) && (
            <div className="flex items-center justify-center py-8">
              <Loader2 className="w-6 h-6 text-gray-400 animate-spin" />
              <span className="ml-2 text-gray-400 text-sm">Analyzing attack paths...</span>
            </div>
          )}

          {/* Attack Paths Section */}
          {!pathsLoading && (
            <div className="grid grid-cols-12 gap-6">
              {/* Attack Path Cards */}
              <div className="col-span-4 space-y-3">
                <h3 className="text-sm font-semibold text-white flex items-center gap-2">
                  <Zap className="w-4 h-4 text-orange-400" />
                  Discovered Attack Chains
                </h3>
                {attackPaths.length === 0 ? (
                  <div className="bg-gray-800/50 border border-gray-700/50 rounded-xl p-6 text-center">
                    <Shield className="w-8 h-8 text-green-400 mx-auto mb-2" />
                    <p className="text-sm text-gray-400">No attack chains discovered</p>
                  </div>
                ) : (
                  attackPaths.map((path: any, i: number) => {
                    const risk = getRiskLevel(path.risk_score || 50)
                    const colors = riskColors[risk]
                    const isSelected = selectedPath?.id === path.id || selectedPath?.name === path.name
                    return (
                      <button
                        key={path.id || i}
                        onClick={() => setSelectedPath(path)}
                        className={`w-full text-left border rounded-xl p-4 transition-all ${
                          isSelected
                            ? `${colors.bg} ${colors.border}`
                            : 'bg-gray-800/50 border-gray-700/50 hover:border-gray-600'
                        }`}
                      >
                        <div className="flex items-center justify-between mb-2">
                          <h4 className="text-sm font-semibold text-white truncate pr-2">
                            {path.name}
                          </h4>
                          <span
                            className={`text-xs px-2 py-0.5 rounded-full whitespace-nowrap ${colors.bg} ${colors.text} font-semibold`}
                          >
                            {path.risk_score}/100
                          </span>
                        </div>
                        <p className="text-xs text-gray-400 line-clamp-2 mb-2">
                          {path.description}
                        </p>

                        {/* Likelihood & Impact badges */}
                        <div className="flex items-center gap-2 mb-2">
                          {path.likelihood && (
                            <span className="text-[10px] px-1.5 py-0.5 rounded bg-gray-700/50 text-gray-300">
                              Likelihood: {path.likelihood}
                            </span>
                          )}
                          {path.impact && (
                            <span className="text-[10px] px-1.5 py-0.5 rounded bg-gray-700/50 text-gray-300">
                              Impact: {path.impact}
                            </span>
                          )}
                        </div>

                        {/* Node chain preview with arrows */}
                        <div className="flex items-center flex-wrap gap-0.5">
                          {(path.nodes || []).slice(0, 5).map((node: any, ni: number) => (
                            <div key={ni} className="flex items-center">
                              <div
                                className={`w-6 h-6 ${colors.bg} rounded-full flex items-center justify-center`}
                              >
                                <span className={`text-[10px] font-bold ${colors.text}`}>
                                  {ni + 1}
                                </span>
                              </div>
                              {ni < Math.min((path.nodes || []).length, 5) - 1 && (
                                <ArrowRight className="w-3 h-3 text-gray-600 mx-0.5" />
                              )}
                            </div>
                          ))}
                        </div>

                        {/* Mitigation priority badge */}
                        {path.mitigation_priority && (
                          <div className="mt-2">
                            <span
                              className={`text-[10px] px-2 py-0.5 rounded-full font-medium ${
                                path.mitigation_priority === 'immediate'
                                  ? 'bg-red-500/15 text-red-400'
                                  : path.mitigation_priority === 'next_sprint'
                                  ? 'bg-orange-500/15 text-orange-400'
                                  : 'bg-blue-500/15 text-blue-400'
                              }`}
                            >
                              {path.mitigation_priority === 'immediate'
                                ? 'Immediate'
                                : path.mitigation_priority === 'next_sprint'
                                ? 'Next Sprint'
                                : path.mitigation_priority}
                            </span>
                          </div>
                        )}
                      </button>
                    )
                  })
                )}
              </div>

              {/* Attack Path Detail / Visualization */}
              <div className="col-span-8">
                {selectedPath ? (
                  <div className="bg-gray-800/50 border border-gray-700/50 rounded-xl p-6">
                    <div className="flex items-center justify-between mb-6">
                      <div>
                        <h3 className="text-lg font-semibold text-white">
                          {selectedPath.name}
                        </h3>
                        <p className="text-sm text-gray-400 mt-1">
                          {selectedPath.description}
                        </p>
                      </div>
                      <div className="text-right">
                        <div
                          className={`text-2xl font-bold ${
                            riskColors[getRiskLevel(selectedPath.risk_score || 50)].text
                          }`}
                        >
                          {selectedPath.risk_score}/100
                        </div>
                        <div className="text-xs text-gray-500">Risk Score</div>
                      </div>
                    </div>

                    {/* Info badges */}
                    <div className="flex items-center gap-3 mb-6">
                      {selectedPath.likelihood && (
                        <span className="text-xs px-2 py-1 rounded-lg bg-gray-700/50 text-gray-300 border border-gray-600/50">
                          Likelihood: <span className="font-semibold text-white">{selectedPath.likelihood}</span>
                        </span>
                      )}
                      {selectedPath.impact && (
                        <span className="text-xs px-2 py-1 rounded-lg bg-gray-700/50 text-gray-300 border border-gray-600/50">
                          Impact: <span className="font-semibold text-white">{selectedPath.impact}</span>
                        </span>
                      )}
                      {selectedPath.mitigation_priority && (
                        <span
                          className={`text-xs px-2 py-1 rounded-lg border ${
                            selectedPath.mitigation_priority === 'immediate'
                              ? 'bg-red-500/10 border-red-500/30 text-red-400'
                              : 'bg-orange-500/10 border-orange-500/30 text-orange-400'
                          }`}
                        >
                          Priority:{' '}
                          <span className="font-semibold">
                            {selectedPath.mitigation_priority === 'immediate'
                              ? 'Immediate'
                              : selectedPath.mitigation_priority === 'next_sprint'
                              ? 'Next Sprint'
                              : selectedPath.mitigation_priority}
                          </span>
                        </span>
                      )}
                    </div>

                    {/* Chain Visualization */}
                    <div className="relative">
                      {(selectedPath.nodes || []).map(
                        (node: any, i: number, arr: any[]) => {
                          const NodeIcon = getNodeIcon(node.type || 'vulnerability')
                          const isLast = i === arr.length - 1
                          return (
                            <div
                              key={node.finding_id || i}
                              className="flex items-start gap-4 mb-6 last:mb-0"
                            >
                              <div className="flex flex-col items-center">
                                <div
                                  className={`w-10 h-10 rounded-xl flex items-center justify-center ${
                                    i === 0
                                      ? 'bg-green-500/20'
                                      : isLast
                                      ? 'bg-red-500/20'
                                      : 'bg-yellow-500/20'
                                  }`}
                                >
                                  <NodeIcon
                                    className={`w-5 h-5 ${
                                      i === 0
                                        ? 'text-green-400'
                                        : isLast
                                        ? 'text-red-400'
                                        : 'text-yellow-400'
                                    }`}
                                  />
                                </div>
                                {!isLast && (
                                  <div className="w-px h-8 bg-gray-700 mt-2" />
                                )}
                              </div>
                              <div className="flex-1 bg-gray-900/50 rounded-lg p-3 border border-gray-700/50">
                                <div className="flex items-center justify-between">
                                  <h4 className="text-sm font-medium text-white">
                                    {typeof node === 'string'
                                      ? node
                                      : node.title || node.name}
                                  </h4>
                                  {node.severity && (
                                    <span
                                      className={`text-xs px-2 py-0.5 rounded-full ${
                                        riskColors[node.severity]?.bg || ''
                                      } ${
                                        riskColors[node.severity]?.text ||
                                        'text-gray-400'
                                      }`}
                                    >
                                      {node.severity}
                                    </span>
                                  )}
                                </div>
                                {node.description && (
                                  <p className="text-xs text-gray-400 mt-1">
                                    {node.description}
                                  </p>
                                )}
                                {node.cwe && (
                                  <span className="text-xs text-gray-500 mt-1 block">
                                    CWE-{node.cwe}
                                  </span>
                                )}
                              </div>
                            </div>
                          )
                        }
                      )}
                    </div>

                    {/* Mitigation box */}
                    {selectedPath.mitigation_priority && (
                      <div className="mt-6 p-4 bg-blue-500/5 border border-blue-500/20 rounded-lg">
                        <h4 className="text-sm font-semibold text-blue-400 mb-2 flex items-center gap-2">
                          <Lock className="w-4 h-4" /> Mitigation Priority
                        </h4>
                        <p className="text-sm text-gray-300">
                          {selectedPath.mitigation_priority === 'immediate'
                            ? 'This attack chain should be addressed immediately. The combination of vulnerabilities presents a critical risk to the system.'
                            : selectedPath.mitigation_priority === 'next_sprint'
                            ? 'Schedule remediation in the next sprint. These vulnerabilities form a significant attack chain that should be prioritized.'
                            : `Priority: ${selectedPath.mitigation_priority}`}
                        </p>
                      </div>
                    )}
                  </div>
                ) : (
                  <div className="bg-gray-800/50 border border-gray-700/50 rounded-xl p-12 flex flex-col items-center justify-center h-full">
                    <Network className="w-12 h-12 text-gray-600 mb-4" />
                    <h3 className="text-lg font-medium text-gray-400">
                      Select an Attack Path
                    </h3>
                    <p className="text-sm text-gray-500 mt-1">
                      Click on an attack path to see the full chain visualization
                    </p>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Attack Surface Section */}
          {!surfaceLoading && surfaceData && (
            <div>
              <h3 className="text-sm font-semibold text-white mb-3 flex items-center gap-2">
                <Target className="w-4 h-4 text-yellow-400" />
                Attack Surface
              </h3>
              <div className="grid grid-cols-4 gap-4">
                {[
                  {
                    label: 'Entry Points',
                    subtitle: 'DAST findings',
                    items: surfaceData.entry_points || [],
                    count: surfaceData.summary?.entry_point_count || (surfaceData.entry_points || []).length,
                    icon: Globe,
                    color: 'text-red-400',
                    bg: 'from-red-500/10 to-red-500/5',
                  },
                  {
                    label: 'Internal Weaknesses',
                    subtitle: 'SAST findings',
                    items: surfaceData.internal_weaknesses || [],
                    count: surfaceData.summary?.internal_weakness_count || (surfaceData.internal_weaknesses || []).length,
                    icon: AlertTriangle,
                    color: 'text-yellow-400',
                    bg: 'from-yellow-500/10 to-yellow-500/5',
                  },
                  {
                    label: 'Data Stores',
                    subtitle: 'Database related',
                    items: surfaceData.data_stores || [],
                    count: surfaceData.summary?.data_store_count || (surfaceData.data_stores || []).length,
                    icon: Database,
                    color: 'text-blue-400',
                    bg: 'from-blue-500/10 to-blue-500/5',
                  },
                  {
                    label: 'External Services',
                    subtitle: 'SSRF / API risks',
                    items: surfaceData.external_services || [],
                    count: surfaceData.summary?.external_service_count || (surfaceData.external_services || []).length,
                    icon: Server,
                    color: 'text-purple-400',
                    bg: 'from-purple-500/10 to-purple-500/5',
                  },
                ].map((cat) => (
                  <div
                    key={cat.label}
                    className={`bg-gradient-to-br ${cat.bg} border border-gray-700/50 rounded-xl p-4`}
                  >
                    <div className="flex items-center gap-2 mb-3">
                      <cat.icon className={`w-4 h-4 ${cat.color}`} />
                      <div>
                        <span className="text-xs font-semibold text-white">{cat.label}</span>
                        <span className="text-[10px] text-gray-500 block">{cat.subtitle}</span>
                      </div>
                    </div>
                    <div className="text-2xl font-bold text-white mb-3">{cat.count}</div>
                    {/* Severity breakdown */}
                    <div className="space-y-1">
                      {['critical', 'high', 'medium', 'low'].map((sev) => {
                        const count = severityCount(cat.items, sev)
                        if (count === 0) return null
                        const sevColors = riskColors[sev]
                        return (
                          <div key={sev} className="flex items-center justify-between">
                            <span className={`text-[10px] capitalize ${sevColors.text}`}>
                              {sev}
                            </span>
                            <span className={`text-[10px] font-semibold ${sevColors.text}`}>
                              {count}
                            </span>
                          </div>
                        )
                      })}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Risk Graph Visualization */}
          {!graphLoading && graphData && graphData.nodes?.length > 0 && (
            <div>
              <h3 className="text-sm font-semibold text-white mb-3 flex items-center gap-2">
                <Network className="w-4 h-4 text-cyan-400" />
                Risk Graph
                <span className="text-xs text-gray-500 font-normal ml-2">
                  {graphData.nodes.length} nodes &middot; {graphData.edges?.length || 0} edges
                </span>
              </h3>
              <div className="bg-gray-800/50 border border-gray-700/50 rounded-xl p-6 overflow-hidden">
                {/* CSS-based graph layout */}
                <div className="relative" style={{ minHeight: '320px' }}>
                  {/* Render edges as SVG lines */}
                  <svg
                    className="absolute inset-0 w-full h-full pointer-events-none"
                    style={{ zIndex: 0 }}
                  >
                    {(graphData.edges || []).map((edge: any, ei: number) => {
                      const sourceIdx = graphData.nodes.findIndex(
                        (n: any) => n.id === edge.source
                      )
                      const targetIdx = graphData.nodes.findIndex(
                        (n: any) => n.id === edge.target
                      )
                      if (sourceIdx === -1 || targetIdx === -1) return null

                      const cols = Math.min(graphData.nodes.length, 6)
                      const sRow = Math.floor(sourceIdx / cols)
                      const sCol = sourceIdx % cols
                      const tRow = Math.floor(targetIdx / cols)
                      const tCol = targetIdx % cols

                      const cellW = 100 / cols
                      const rowH = 100

                      const x1 = sCol * cellW + cellW / 2
                      const y1 = sRow * rowH + 40
                      const x2 = tCol * cellW + cellW / 2
                      const y2 = tRow * rowH + 40

                      return (
                        <line
                          key={ei}
                          x1={`${x1}%`}
                          y1={y1}
                          x2={`${x2}%`}
                          y2={y2}
                          stroke="rgba(107, 114, 128, 0.4)"
                          strokeWidth="1.5"
                          strokeDasharray="4 4"
                        />
                      )
                    })}
                  </svg>

                  {/* Render nodes */}
                  <div
                    className="relative grid gap-4"
                    style={{
                      gridTemplateColumns: `repeat(${Math.min(
                        graphData.nodes.length,
                        6
                      )}, 1fr)`,
                      zIndex: 1,
                    }}
                  >
                    {graphData.nodes.map((node: any) => {
                      const severity = node.severity || 'medium'
                      const nodeType = node.type || severity
                      const typeColors =
                        nodeTypeColors[nodeType] ||
                        nodeTypeColors['vulnerability'] ||
                        { bg: 'bg-gray-500/20', text: 'text-gray-400', ring: 'ring-gray-500/40' }
                      const sevColors = riskColors[severity] || riskColors['medium']

                      return (
                        <div
                          key={node.id}
                          className="flex flex-col items-center text-center"
                        >
                          <div
                            className={`w-12 h-12 rounded-full ${typeColors.bg} ring-2 ${typeColors.ring} flex items-center justify-center mb-2`}
                          >
                            <span className={`text-xs font-bold ${typeColors.text}`}>
                              {node.cwe ? `${node.cwe}` : node.id}
                            </span>
                          </div>
                          <p className="text-[10px] text-gray-300 leading-tight max-w-[120px] truncate">
                            {node.label}
                          </p>
                          <span
                            className={`text-[9px] mt-1 px-1.5 py-0.5 rounded-full ${sevColors.bg} ${sevColors.text}`}
                          >
                            {severity}
                          </span>
                        </div>
                      )
                    })}
                  </div>
                </div>

                {/* Legend */}
                <div className="mt-4 pt-4 border-t border-gray-700/50 flex items-center gap-4 flex-wrap">
                  <span className="text-[10px] text-gray-500 font-medium">Node Types:</span>
                  {[
                    { label: 'Entry Point', color: 'bg-red-400' },
                    { label: 'Weakness', color: 'bg-yellow-400' },
                    { label: 'Data Store', color: 'bg-blue-400' },
                    { label: 'External', color: 'bg-purple-400' },
                  ].map((leg) => (
                    <div key={leg.label} className="flex items-center gap-1.5">
                      <div className={`w-2.5 h-2.5 rounded-full ${leg.color}`} />
                      <span className="text-[10px] text-gray-400">{leg.label}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
