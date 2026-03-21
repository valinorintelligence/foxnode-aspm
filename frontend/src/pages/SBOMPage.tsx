import { useState, useEffect } from 'react'
import { useChartTheme } from '../lib/chartTheme'
import { safeArray, safeObj } from '../lib/safe'
import { sbomAPI, productsAPI } from '../services/api'
import {
  Package, AlertTriangle, Scale, Shield, Box, Layers, FileCode,
  Search, Bug, ShieldAlert, Skull, Activity, ChevronDown,
} from 'lucide-react'
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer, Legend } from 'recharts'

type TabId = 'components' | 'vulnerabilities' | 'licenses' | 'supply-chain' | 'summary'

const LICENSE_COLORS: Record<string, string> = {
  MIT: '#10b981',
  'Apache-2.0': '#3b82f6',
  GPL: '#ef4444',
  BSD: '#f59e0b',
  Other: '#8b5cf6',
}

const SEVERITY_BADGE: Record<string, string> = {
  critical: 'bg-red-500/10 text-red-400',
  high: 'bg-orange-500/10 text-orange-400',
  medium: 'bg-yellow-500/10 text-yellow-400',
  low: 'bg-green-500/10 text-green-400',
}

function getRiskColor(score: number) {
  if (score >= 80) return 'text-red-400'
  if (score >= 60) return 'text-orange-400'
  if (score >= 40) return 'text-yellow-400'
  return 'text-green-400'
}

function getRiskBg(score: number) {
  if (score >= 80) return 'bg-red-500/10 border-red-500/30'
  if (score >= 60) return 'bg-orange-500/10 border-orange-500/30'
  if (score >= 40) return 'bg-yellow-500/10 border-yellow-500/30'
  return 'bg-green-500/10 border-green-500/30'
}

export default function SBOMPage() {
  const [selectedProduct, setSelectedProduct] = useState<number | null>(null)
  const chart = useChartTheme()
  const [activeTab, setActiveTab] = useState<TabId>('components')
  const [searchTerm, setSearchTerm] = useState('')

  const [products, setProducts] = useState<any[]>([])
  const [overview, setOverview] = useState<any>(null)
  const [components, setComponents] = useState<any[]>([])
  const [vulns, setVulns] = useState<any[]>([])
  const [licenses, setLicenses] = useState<any>(null)
  const [supplyChain, setSupplyChain] = useState<any[]>([])
  const [summary, setSummary] = useState<any>(null)

  const [loading, setLoading] = useState(false)
  const [error, setError] = useState<string | null>(null)

  // Load products and overview on mount
  useEffect(() => {
    productsAPI.list().then((res) => setProducts(safeArray(res.data))).catch(() => {})
    sbomAPI.overview().then((res) => setOverview(res.data)).catch(() => {})
  }, [])

  // Load product-specific data when product or tab changes
  useEffect(() => {
    if (!selectedProduct) {
      setComponents([])
      setVulns([])
      setLicenses(null)
      setSupplyChain([])
      setSummary(null)
      return
    }

    setLoading(true)
    setError(null)

    const load = async () => {
      try {
        if (activeTab === 'components') {
          const res = await sbomAPI.components(selectedProduct)
          setComponents(safeArray(res.data?.components ?? res.data))
        } else if (activeTab === 'vulnerabilities') {
          const res = await sbomAPI.vulnerabilities(selectedProduct)
          setVulns(safeArray(res.data?.vulnerabilities ?? res.data))
        } else if (activeTab === 'licenses') {
          const res = await sbomAPI.licenses(selectedProduct)
          setLicenses(res.data)
        } else if (activeTab === 'supply-chain') {
          const res = await sbomAPI.supplyChainRisks(selectedProduct)
          setSupplyChain(safeArray(res.data?.risks ?? res.data))
        } else if (activeTab === 'summary') {
          const res = await sbomAPI.product(selectedProduct)
          setSummary(res.data)
        }
      } catch (err: any) {
        setError(err?.response?.data?.detail || 'Failed to load data')
      } finally {
        setLoading(false)
      }
    }

    load()
  }, [selectedProduct, activeTab])

  const tabs: { id: TabId; label: string; icon: any }[] = [
    { id: 'components', label: 'Components', icon: Box },
    { id: 'vulnerabilities', label: 'Vulnerabilities', icon: Bug },
    { id: 'licenses', label: 'Licenses', icon: Scale },
    { id: 'supply-chain', label: 'Supply Chain Risks', icon: ShieldAlert },
    { id: 'summary', label: 'Summary', icon: Activity },
  ]

  // Build license pie chart data
  const licensePieData = (() => {
    if (!licenses) return []
    const dist = licenses.distribution || licenses
    if (typeof dist !== 'object') return []
    return Object.entries(dist).map(([name, val]: [string, any]) => ({
      name,
      value: typeof val === 'number' ? val : val?.count || 0,
    }))
  })()

  const getLicenseColor = (name: string) => {
    if (name.includes('MIT')) return LICENSE_COLORS.MIT
    if (name.includes('Apache')) return LICENSE_COLORS['Apache-2.0']
    if (name.includes('GPL') || name.includes('AGPL')) return LICENSE_COLORS.GPL
    if (name.includes('BSD')) return LICENSE_COLORS.BSD
    return LICENSE_COLORS.Other
  }

  // Build component type donut data for summary
  const componentTypeData = (() => {
    if (!components.length && !summary?.component_breakdown) return []
    if (summary?.component_breakdown) {
      return Object.entries(safeObj(summary.component_breakdown)).map(([name, value]: [string, any]) => ({
        name,
        value: typeof value === 'number' ? value : 0,
      }))
    }
    const counts: Record<string, number> = {}
    components.forEach((c: any) => {
      const t = c.type || 'library'
      counts[t] = (counts[t] || 0) + 1
    })
    return Object.entries(counts).map(([name, value]) => ({ name, value }))
  })()

  const TYPE_COLORS = ['#3b82f6', '#10b981', '#f59e0b', '#ef4444', '#8b5cf6', '#ec4899']

  const filteredComponents = components.filter(
    (c: any) => !searchTerm || c.name?.toLowerCase().includes(searchTerm.toLowerCase())
  )

  const overallScore = summary?.risk_score ?? summary?.overall_score ?? overview?.supply_chain_risk_score ?? null

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-gradient-to-br from-amber-500/20 to-orange-500/20 rounded-xl">
            <Package className="w-6 h-6 text-amber-400" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-content-primary">SBOM &amp; Supply Chain</h1>
            <p className="text-content-tertiary text-sm">Software Bill of Materials and dependency risk analysis</p>
          </div>
        </div>
        <div className="relative">
          <select
            className="bg-surface-tertiary border border-border-secondary rounded-lg px-4 py-2 text-sm text-content-primary appearance-none pr-8 min-w-[200px]"
            value={selectedProduct || ''}
            onChange={(e) => {
              setSelectedProduct(e.target.value ? Number(e.target.value) : null)
              setActiveTab('components')
              setSearchTerm('')
            }}
          >
            <option value="">Select product...</option>
            {products.map((p: any) => (
              <option key={p.id} value={p.id}>{p.name}</option>
            ))}
          </select>
          <ChevronDown className="absolute right-2 top-1/2 -translate-y-1/2 w-4 h-4 text-content-tertiary pointer-events-none" />
        </div>
      </div>

      {/* Overview Stats (org-wide, always visible) */}
      {!selectedProduct && overview && (
        <div className="grid grid-cols-4 gap-4">
          {[
            { label: 'Total Components', value: overview.total_components || 0, icon: Box, color: 'text-blue-400' },
            { label: 'Known Vulnerabilities', value: overview.vulnerable_count || overview.known_vulnerabilities || 0, icon: AlertTriangle, color: 'text-red-400' },
            { label: 'License Risks', value: overview.license_risks || 0, icon: Scale, color: 'text-yellow-400' },
            { label: 'Supply Chain Risk Score', value: overview.supply_chain_risk_score ?? overview.supply_chain_risks ?? 'N/A', icon: Shield, color: 'text-orange-400' },
          ].map((s) => (
            <div key={s.label} className="bg-surface-tertiary/50 border border-border-secondary/50 rounded-xl p-5">
              <div className="flex items-center gap-2 mb-2">
                <s.icon className={`w-4 h-4 ${s.color}`} />
                <span className="text-xs text-content-tertiary uppercase tracking-wide">{s.label}</span>
              </div>
              <div className="text-3xl font-bold text-content-primary">{s.value}</div>
            </div>
          ))}
        </div>
      )}

      {!selectedProduct && (
        <div className="bg-surface-tertiary/50 border border-border-secondary/50 rounded-xl p-12 text-center">
          <Package className="w-12 h-12 text-content-muted mx-auto mb-3" />
          <h3 className="text-lg font-medium text-content-tertiary">Select a Product</h3>
          <p className="text-sm text-content-muted mt-1">Choose a product to view its Software Bill of Materials and dependency analysis</p>
        </div>
      )}

      {/* Product selected: Tabs + Content */}
      {selectedProduct && (
        <>
          {/* Tab Navigation - underline style */}
          <div className="border-b border-border-secondary">
            <div className="flex gap-6">
              {tabs.map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => { setActiveTab(tab.id); setSearchTerm('') }}
                  className={`flex items-center gap-2 pb-3 px-1 text-sm font-medium transition-colors border-b-2 ${
                    activeTab === tab.id
                      ? 'border-blue-500 text-blue-400'
                      : 'border-transparent text-content-tertiary hover:text-content-primary'
                  }`}
                >
                  <tab.icon className="w-4 h-4" />
                  {tab.label}
                </button>
              ))}
            </div>
          </div>

          {/* Loading / Error states */}
          {loading && (
            <div className="flex items-center justify-center py-12">
              <div className="animate-spin rounded-full h-8 w-8 border-b-2 border-blue-500" />
              <span className="ml-3 text-content-tertiary text-sm">Loading...</span>
            </div>
          )}

          {error && !loading && (
            <div className="bg-red-500/10 border border-red-500/30 rounded-xl p-4 text-sm text-red-400">
              {error}
            </div>
          )}

          {/* Components Tab */}
          {!loading && !error && activeTab === 'components' && (
            <div className="space-y-4">
              <div className="relative max-w-md">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-content-muted" />
                <input
                  type="text"
                  placeholder="Search components..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="w-full bg-surface-tertiary border border-border-secondary rounded-lg pl-10 pr-4 py-2 text-sm text-content-primary placeholder-content-muted"
                />
              </div>

              {filteredComponents.length === 0 ? (
                <div className="bg-surface-tertiary/50 border border-border-secondary/50 rounded-xl p-8 text-center text-content-muted text-sm">
                  No components found.
                </div>
              ) : (
                <div className="bg-surface-tertiary/50 border border-border-secondary/50 rounded-xl overflow-hidden">
                  <table className="w-full">
                    <thead>
                      <tr className="border-b border-border-secondary/50">
                        <th className="text-left px-4 py-3 text-xs font-medium text-content-tertiary uppercase tracking-wide">Component</th>
                        <th className="text-left px-4 py-3 text-xs font-medium text-content-tertiary uppercase tracking-wide">Version</th>
                        <th className="text-left px-4 py-3 text-xs font-medium text-content-tertiary uppercase tracking-wide">Type</th>
                        <th className="text-left px-4 py-3 text-xs font-medium text-content-tertiary uppercase tracking-wide">Ecosystem</th>
                        <th className="text-left px-4 py-3 text-xs font-medium text-content-tertiary uppercase tracking-wide">License</th>
                        <th className="text-left px-4 py-3 text-xs font-medium text-content-tertiary uppercase tracking-wide">Risk</th>
                      </tr>
                    </thead>
                    <tbody>
                      {filteredComponents.slice(0, 50).map((c: any, i: number) => (
                        <tr key={i} className="border-b border-border/50 hover:bg-surface-tertiary/30">
                          <td className="px-4 py-3 text-sm text-content-primary flex items-center gap-2">
                            <FileCode className="w-4 h-4 text-content-muted flex-shrink-0" />
                            {c.name}
                          </td>
                          <td className="px-4 py-3 text-sm text-content-tertiary font-mono">{c.version || '-'}</td>
                          <td className="px-4 py-3">
                            <span className="text-xs px-2 py-0.5 bg-border-secondary/50 rounded text-content-secondary">
                              {c.type || 'library'}
                            </span>
                          </td>
                          <td className="px-4 py-3 text-sm text-content-tertiary">{c.ecosystem || c.language || '-'}</td>
                          <td className="px-4 py-3 text-sm text-content-tertiary">{c.license || 'Unknown'}</td>
                          <td className="px-4 py-3">
                            <span className={`text-xs px-2 py-0.5 rounded-full ${SEVERITY_BADGE[c.risk_level || 'low'] || SEVERITY_BADGE.low}`}>
                              {c.risk_level || 'low'}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}

          {/* Vulnerabilities Tab */}
          {!loading && !error && activeTab === 'vulnerabilities' && (
            <div className="space-y-3">
              {vulns.length === 0 ? (
                <div className="bg-surface-tertiary/50 border border-border-secondary/50 rounded-xl p-8 text-center text-content-muted text-sm">
                  No known vulnerabilities found.
                </div>
              ) : (
                <div className="bg-surface-tertiary/50 border border-border-secondary/50 rounded-xl overflow-hidden">
                  <table className="w-full">
                    <thead>
                      <tr className="border-b border-border-secondary/50">
                        <th className="text-left px-4 py-3 text-xs font-medium text-content-tertiary uppercase tracking-wide">CVE ID</th>
                        <th className="text-left px-4 py-3 text-xs font-medium text-content-tertiary uppercase tracking-wide">Component</th>
                        <th className="text-left px-4 py-3 text-xs font-medium text-content-tertiary uppercase tracking-wide">Severity</th>
                        <th className="text-left px-4 py-3 text-xs font-medium text-content-tertiary uppercase tracking-wide">Description</th>
                        <th className="text-left px-4 py-3 text-xs font-medium text-content-tertiary uppercase tracking-wide">Fix Version</th>
                      </tr>
                    </thead>
                    <tbody>
                      {vulns.map((v: any, i: number) => (
                        <tr key={i} className="border-b border-border/50 hover:bg-surface-tertiary/30">
                          <td className="px-4 py-3 text-sm text-blue-400 font-mono">{v.vulnerability_id || v.cve_id || '-'}</td>
                          <td className="px-4 py-3 text-sm text-content-primary">
                            {v.component_name}{v.component_version ? ` ${v.component_version}` : ''}
                          </td>
                          <td className="px-4 py-3">
                            <span className={`text-xs px-2 py-0.5 rounded-full ${SEVERITY_BADGE[v.severity] || SEVERITY_BADGE.medium}`}>
                              {v.severity}
                            </span>
                          </td>
                          <td className="px-4 py-3 text-xs text-content-tertiary max-w-xs truncate">{v.description || '-'}</td>
                          <td className="px-4 py-3 text-sm text-green-400 font-mono">{v.fixed_version || '-'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}

          {/* Licenses Tab */}
          {!loading && !error && activeTab === 'licenses' && (
            <div className="space-y-6">
              {licensePieData.length > 0 ? (
                <div className="grid grid-cols-2 gap-6">
                  {/* Pie Chart */}
                  <div className="bg-surface-tertiary/50 border border-border-secondary/50 rounded-xl p-6">
                    <h3 className="text-sm font-semibold text-content-primary mb-4">License Distribution</h3>
                    <ResponsiveContainer width="100%" height={300}>
                      <PieChart>
                        <Pie
                          data={licensePieData}
                          cx="50%"
                          cy="50%"
                          innerRadius={60}
                          outerRadius={100}
                          paddingAngle={3}
                          dataKey="value"
                          nameKey="name"
                        >
                          {licensePieData.map((entry, index) => (
                            <Cell key={index} fill={getLicenseColor(entry.name)} />
                          ))}
                        </Pie>
                        <Tooltip
                          contentStyle={{ backgroundColor: chart.tooltipStyle.backgroundColor, border: chart.tooltipStyle.border, borderRadius: '8px' }}
                          itemStyle={{ color: '#e5e7eb' }}
                        />
                        <Legend
                          wrapperStyle={{ color: '#9ca3af', fontSize: '12px' }}
                        />
                      </PieChart>
                    </ResponsiveContainer>
                  </div>

                  {/* Copyleft / Risky Licenses */}
                  <div className="bg-surface-tertiary/50 border border-border-secondary/50 rounded-xl p-6">
                    <h3 className="text-sm font-semibold text-content-primary mb-4">Copyleft &amp; Risky Licenses</h3>
                    <div className="space-y-3">
                      {licensePieData
                        .filter((l) => ['GPL', 'AGPL', 'LGPL', 'SSPL', 'EUPL'].some((r) => l.name.toUpperCase().includes(r)))
                        .map((l, i) => (
                          <div key={i} className="flex items-center justify-between bg-red-500/5 border border-red-500/20 rounded-lg p-3">
                            <div className="flex items-center gap-2">
                              <AlertTriangle className="w-4 h-4 text-red-400" />
                              <span className="text-sm text-content-primary">{l.name}</span>
                            </div>
                            <span className="text-xs text-red-400 font-medium">{l.value} components</span>
                          </div>
                        ))}
                      {licensePieData
                        .filter((l) => !['GPL', 'AGPL', 'LGPL', 'SSPL', 'EUPL'].some((r) => l.name.toUpperCase().includes(r)))
                        .map((l, i) => (
                          <div key={i} className="flex items-center justify-between bg-surface-secondary/50 border border-border-secondary/50 rounded-lg p-3">
                            <span className="text-sm text-content-secondary">{l.name}</span>
                            <span className="text-xs text-content-muted">{l.value} components</span>
                          </div>
                        ))}
                      {licensePieData.length === 0 && (
                        <p className="text-sm text-content-muted">No license data available.</p>
                      )}
                    </div>
                  </div>
                </div>
              ) : (
                <div className="bg-surface-tertiary/50 border border-border-secondary/50 rounded-xl p-8 text-center text-content-muted text-sm">
                  No license data available.
                </div>
              )}
            </div>
          )}

          {/* Supply Chain Risks Tab */}
          {!loading && !error && activeTab === 'supply-chain' && (
            <div className="space-y-4">
              {supplyChain.length === 0 ? (
                <div className="bg-surface-tertiary/50 border border-border-secondary/50 rounded-xl p-8 text-center text-content-muted text-sm">
                  No supply chain risks detected.
                </div>
              ) : (
                <div className="grid grid-cols-2 gap-4">
                  {supplyChain.map((r: any, i: number) => {
                    const sev = r.severity || r.risk_level || 'medium'
                    return (
                      <div key={i} className={`border rounded-xl p-5 ${getRiskBg(
                        sev === 'critical' ? 90 : sev === 'high' ? 70 : sev === 'medium' ? 50 : 20
                      )}`}>
                        <div className="flex items-center justify-between mb-3">
                          <div className="flex items-center gap-2">
                            {r.risk_type?.toLowerCase().includes('malicious') ? (
                              <Skull className="w-5 h-5 text-red-400" />
                            ) : r.risk_type?.toLowerCase().includes('typosquat') ? (
                              <Search className="w-5 h-5 text-orange-400" />
                            ) : (
                              <ShieldAlert className="w-5 h-5 text-yellow-400" />
                            )}
                            <h4 className="text-sm font-semibold text-content-primary">{r.risk_type || r.type || 'Unknown Risk'}</h4>
                          </div>
                          <span className={`text-xs px-2 py-0.5 rounded-full ${SEVERITY_BADGE[sev] || SEVERITY_BADGE.medium}`}>
                            {sev}
                          </span>
                        </div>
                        <p className="text-xs text-content-secondary leading-relaxed">{r.description}</p>
                        {r.affected_components && r.affected_components.length > 0 && (
                          <p className="text-xs text-content-muted mt-2">
                            Affected: {r.affected_components.join(', ')}
                          </p>
                        )}
                      </div>
                    )
                  })}
                </div>
              )}
            </div>
          )}

          {/* Summary Tab */}
          {!loading && !error && activeTab === 'summary' && (
            <div className="space-y-6">
              <div className="grid grid-cols-3 gap-6">
                {/* Risk Score Card */}
                <div className="bg-surface-tertiary/50 border border-border-secondary/50 rounded-xl p-6 flex flex-col items-center justify-center">
                  <h3 className="text-sm font-semibold text-content-tertiary mb-4">Overall Risk Score</h3>
                  {overallScore !== null ? (
                    <>
                      <div className={`text-5xl font-bold ${getRiskColor(overallScore)}`}>
                        {overallScore}
                      </div>
                      <div className="text-xs text-content-muted mt-2">out of 100</div>
                      <div className="w-full mt-4 bg-border-secondary rounded-full h-2">
                        <div
                          className={`h-2 rounded-full transition-all ${
                            overallScore >= 80 ? 'bg-red-500' :
                            overallScore >= 60 ? 'bg-orange-500' :
                            overallScore >= 40 ? 'bg-yellow-500' : 'bg-green-500'
                          }`}
                          style={{ width: `${Math.min(overallScore, 100)}%` }}
                        />
                      </div>
                    </>
                  ) : (
                    <div className="text-content-muted text-sm">No score available</div>
                  )}
                </div>

                {/* Component Breakdown Donut */}
                <div className="bg-surface-tertiary/50 border border-border-secondary/50 rounded-xl p-6">
                  <h3 className="text-sm font-semibold text-content-tertiary mb-4">Component Breakdown by Type</h3>
                  {componentTypeData.length > 0 ? (
                    <ResponsiveContainer width="100%" height={220}>
                      <PieChart>
                        <Pie
                          data={componentTypeData}
                          cx="50%"
                          cy="50%"
                          innerRadius={50}
                          outerRadius={80}
                          paddingAngle={3}
                          dataKey="value"
                          nameKey="name"
                        >
                          {componentTypeData.map((_entry, index) => (
                            <Cell key={index} fill={TYPE_COLORS[index % TYPE_COLORS.length]} />
                          ))}
                        </Pie>
                        <Tooltip
                          contentStyle={{ backgroundColor: chart.tooltipStyle.backgroundColor, border: chart.tooltipStyle.border, borderRadius: '8px' }}
                          itemStyle={{ color: '#e5e7eb' }}
                        />
                        <Legend
                          wrapperStyle={{ color: '#9ca3af', fontSize: '11px' }}
                        />
                      </PieChart>
                    </ResponsiveContainer>
                  ) : (
                    <div className="flex items-center justify-center h-[220px] text-content-muted text-sm">
                      No component data
                    </div>
                  )}
                </div>

                {/* Vulnerability Correlation Stats */}
                <div className="bg-surface-tertiary/50 border border-border-secondary/50 rounded-xl p-6">
                  <h3 className="text-sm font-semibold text-content-tertiary mb-4">Vulnerability Correlation</h3>
                  <div className="space-y-4">
                    {[
                      { label: 'Total Components', value: summary?.total_components ?? components.length, icon: Layers },
                      { label: 'Vulnerable Components', value: summary?.vulnerable_count ?? summary?.vulnerable_components ?? 0, icon: AlertTriangle },
                      { label: 'Critical CVEs', value: summary?.critical_cves ?? summary?.critical_vulnerabilities ?? 0, icon: Skull },
                      { label: 'License Violations', value: summary?.license_violations ?? summary?.license_risks ?? 0, icon: Scale },
                      { label: 'Supply Chain Alerts', value: summary?.supply_chain_alerts ?? summary?.supply_chain_risks ?? 0, icon: Shield },
                    ].map((item) => (
                      <div key={item.label} className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <item.icon className="w-4 h-4 text-content-muted" />
                          <span className="text-xs text-content-tertiary">{item.label}</span>
                        </div>
                        <span className="text-sm font-bold text-content-primary">{item.value}</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>
            </div>
          )}
        </>
      )}
    </div>
  )
}
