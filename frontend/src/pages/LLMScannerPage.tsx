import { useState } from 'react'
import { useQuery, useMutation } from '@tanstack/react-query'
import { llmScannerAPI, productsAPI } from '../services/api'
import {
  ShieldAlert, Scan, Code, AlertTriangle, Loader2, CheckCircle, XCircle,
  Info, Cpu, BarChart3, ChevronRight, FileWarning, Bug, Eye,
} from 'lucide-react'
import toast from 'react-hot-toast'

const LANGUAGES = ['python', 'javascript', 'typescript', 'java', 'go'] as const

const RISK_COLORS: Record<string, string> = {
  critical: '#ef4444',
  high: '#f97316',
  medium: '#f59e0b',
  low: '#10b981',
  none: '#6b7280',
}

const SEV_BADGE: Record<string, string> = {
  critical: 'bg-red-500/20 text-red-400 border border-red-500/40',
  high: 'bg-orange-500/20 text-orange-400 border border-orange-500/40',
  medium: 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/40',
  low: 'bg-emerald-500/20 text-emerald-400 border border-emerald-500/40',
  info: 'bg-blue-500/20 text-blue-400 border border-blue-500/40',
}

const OWASP_LLM_CATEGORIES = [
  { id: 'LLM01', name: 'Prompt Injection', color: '#ef4444' },
  { id: 'LLM02', name: 'Insecure Output Handling', color: '#f43f5e' },
  { id: 'LLM03', name: 'Training Data Poisoning', color: '#f97316' },
  { id: 'LLM04', name: 'Model Denial of Service', color: '#fb923c' },
  { id: 'LLM05', name: 'Supply Chain Vulnerabilities', color: '#f59e0b' },
  { id: 'LLM06', name: 'Sensitive Information Disclosure', color: '#eab308' },
  { id: 'LLM07', name: 'Insecure Plugin Design', color: '#d4b106' },
  { id: 'LLM08', name: 'Excessive Agency', color: '#a3e635' },
  { id: 'LLM09', name: 'Overreliance', color: '#84cc16' },
  { id: 'LLM10', name: 'Model Theft', color: '#facc15' },
]

type TabId = 'scanner' | 'product' | 'overview'

export default function LLMScannerPage() {
  const [activeTab, setActiveTab] = useState<TabId>('scanner')
  const [code, setCode] = useState('')
  const [language, setLanguage] = useState<string>('python')
  const [scanResults, setScanResults] = useState<any>(null)
  const [selectedProduct, setSelectedProduct] = useState<number | null>(null)

  const { data: products } = useQuery({
    queryKey: ['products'],
    queryFn: () => productsAPI.list(),
  })

  const scanMutation = useMutation({
    mutationFn: () => llmScannerAPI.scan(code, language),
    onSuccess: (res) => {
      setScanResults(res.data)
      const count = res.data.vulnerabilities?.length || 0
      toast.success(`Scan complete: ${count} AI/ML vulnerabilit${count === 1 ? 'y' : 'ies'} found`)
    },
    onError: () => toast.error('Scan failed. Please try again.'),
  })

  const { data: assessment, isLoading: assessmentLoading } = useQuery({
    queryKey: ['llm-assessment', selectedProduct],
    queryFn: () => llmScannerAPI.product(selectedProduct!),
    enabled: !!selectedProduct && activeTab === 'product',
  })

  const { data: owaspLlm, isLoading: owaspLoading } = useQuery({
    queryKey: ['owasp-llm', selectedProduct],
    queryFn: () => llmScannerAPI.owaspLlm(selectedProduct!),
    enabled: !!selectedProduct && activeTab === 'product',
  })

  const analyzeMutation = useMutation({
    mutationFn: (productId: number) => llmScannerAPI.analyzeFindings(productId),
    onSuccess: () => toast.success('AI pattern analysis complete'),
    onError: () => toast.error('Analysis failed'),
  })

  const { data: overview } = useQuery({
    queryKey: ['llm-overview'],
    queryFn: () => llmScannerAPI.overview(),
    enabled: activeTab === 'overview',
  })

  const tabs: { id: TabId; label: string; icon: typeof Code }[] = [
    { id: 'scanner', label: 'Code Scanner', icon: Code },
    { id: 'product', label: 'Product Analysis', icon: ShieldAlert },
    { id: 'overview', label: 'Overview', icon: BarChart3 },
  ]

  const riskLevelBadge = (level: string) => {
    const l = (level || 'none').toLowerCase()
    const color = RISK_COLORS[l] || RISK_COLORS.none
    return (
      <span
        className="text-xs font-semibold px-2.5 py-0.5 rounded-full border"
        style={{ color, borderColor: color + '66', backgroundColor: color + '1a' }}
      >
        {l.charAt(0).toUpperCase() + l.slice(1)}
      </span>
    )
  }

  const severityCounts = (vulns: any[]) => {
    const counts: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0 }
    vulns.forEach((v) => {
      const s = (v.severity || 'low').toLowerCase()
      if (counts[s] !== undefined) counts[s]++
    })
    return counts
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center gap-3">
        <div className="p-2.5 bg-gradient-to-br from-violet-500/20 to-cyan-500/20 rounded-xl">
          <ShieldAlert className="w-6 h-6 text-violet-400" />
        </div>
        <div>
          <h1 className="text-2xl font-bold text-content-primary">AI/LLM Security Scanner</h1>
          <p className="text-content-tertiary text-sm">Detect vulnerabilities in AI/ML code and LLM integrations</p>
        </div>
      </div>

      {/* Tab Navigation */}
      <div className="border-b border-border-secondary">
        <div className="flex gap-6">
          {tabs.map((tab) => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-2 pb-3 px-1 text-sm font-medium transition-colors border-b-2 ${
                activeTab === tab.id
                  ? 'border-violet-500 text-content-primary'
                  : 'border-transparent text-content-tertiary hover:text-content-secondary'
              }`}
            >
              <tab.icon className="w-4 h-4" />
              {tab.label}
            </button>
          ))}
        </div>
      </div>

      {/* TAB 1: Code Scanner */}
      {activeTab === 'scanner' && (
        <div className="space-y-6">
          <div className="bg-surface-tertiary border border-border-secondary rounded-xl p-5">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-sm font-semibold text-content-primary flex items-center gap-2">
                <Code className="w-4 h-4 text-violet-400" />
                Paste AI/ML Code to Scan
              </h3>
              <select
                value={language}
                onChange={(e) => setLanguage(e.target.value)}
                className="bg-surface-secondary border border-border-secondary rounded-lg px-3 py-1.5 text-sm text-content-primary focus:outline-none focus:border-violet-500/50"
              >
                {LANGUAGES.map((l) => (
                  <option key={l} value={l}>{l.charAt(0).toUpperCase() + l.slice(1)}</option>
                ))}
              </select>
            </div>
            <textarea
              value={code}
              onChange={(e) => setCode(e.target.value)}
              placeholder="Paste your AI/ML code here..."
              className="w-full h-[360px] bg-surface-secondary border border-border-secondary rounded-lg p-4 text-sm text-content-secondary font-mono resize-none focus:outline-none focus:border-violet-500/50 placeholder-content-muted"
            />
            <button
              onClick={() => scanMutation.mutate()}
              disabled={!code.trim() || scanMutation.isPending}
              className="mt-4 px-5 py-2.5 bg-gradient-to-r from-violet-600 to-blue-600 text-content-primary rounded-lg text-sm font-medium hover:from-violet-500 hover:to-blue-500 disabled:opacity-50 disabled:cursor-not-allowed flex items-center gap-2 transition-all"
            >
              {scanMutation.isPending ? (
                <Loader2 className="w-4 h-4 animate-spin" />
              ) : (
                <Scan className="w-4 h-4" />
              )}
              Scan Code
            </button>
          </div>

          {/* Scan Results */}
          {scanResults && (
            <div className="space-y-4">
              {/* Summary Bar */}
              {scanResults.vulnerabilities && scanResults.vulnerabilities.length > 0 && (
                <div className="bg-surface-tertiary border border-border-secondary rounded-xl p-4">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <FileWarning className="w-5 h-5 text-red-400" />
                      <span className="text-content-primary font-semibold text-sm">
                        {scanResults.vulnerabilities.length} Vulnerabilit{scanResults.vulnerabilities.length === 1 ? 'y' : 'ies'} Found
                      </span>
                    </div>
                    <div className="flex items-center gap-3">
                      {Object.entries(severityCounts(scanResults.vulnerabilities)).map(([sev, count]) => (
                        count > 0 && (
                          <span key={sev} className={`text-xs px-2.5 py-1 rounded-full font-medium ${SEV_BADGE[sev] || ''}`}>
                            {count} {sev}
                          </span>
                        )
                      ))}
                    </div>
                  </div>
                </div>
              )}

              {scanResults.vulnerabilities && scanResults.vulnerabilities.length > 0 ? (
                <div className="grid gap-4">
                  {scanResults.vulnerabilities.map((v: any, i: number) => (
                    <div key={i} className="bg-surface-tertiary border border-border-secondary rounded-xl p-5">
                      <div className="flex items-start justify-between mb-3">
                        <div className="flex items-center gap-3">
                          <Bug className="w-5 h-5 text-red-400 shrink-0" />
                          <div>
                            <h4 className="text-content-primary font-semibold text-sm">
                              {v.vulnerability_type || v.category || v.type || 'Unknown Vulnerability'}
                            </h4>
                            {v.description && (
                              <p className="text-content-tertiary text-xs mt-1 leading-relaxed">{v.description}</p>
                            )}
                          </div>
                        </div>
                        <div className="flex items-center gap-2 shrink-0">
                          {v.owasp_category && (
                            <span className="text-xs font-mono font-bold px-2 py-0.5 rounded bg-violet-500/20 text-violet-300 border border-violet-500/40">
                              {v.owasp_category}
                            </span>
                          )}
                          {v.cwe_id && (
                            <span className="text-xs font-mono px-2 py-0.5 rounded bg-border-secondary text-content-secondary border border-border-secondary">
                              CWE-{v.cwe_id}
                            </span>
                          )}
                          <span className={`text-xs px-2.5 py-0.5 rounded-full font-medium ${SEV_BADGE[(v.severity || 'low').toLowerCase()] || SEV_BADGE.info}`}>
                            {v.severity}
                          </span>
                        </div>
                      </div>

                      {/* Affected Code Snippet */}
                      {(v.affected_code || v.code_snippet || v.line_number) && (
                        <div className="mt-3 bg-surface-secondary border border-border-secondary rounded-lg p-3 font-mono text-xs">
                          {v.line_number && (
                            <span className="text-content-muted mr-2">Line {v.line_number}:</span>
                          )}
                          <span className="text-red-300">{v.affected_code || v.code_snippet}</span>
                        </div>
                      )}

                      {/* Recommendation */}
                      {v.recommendation && (
                        <div className="mt-3 flex items-start gap-2 bg-emerald-500/5 border border-emerald-500/20 rounded-lg p-3">
                          <CheckCircle className="w-4 h-4 text-emerald-400 shrink-0 mt-0.5" />
                          <div>
                            <span className="text-xs font-semibold text-emerald-400">Recommendation</span>
                            <p className="text-xs text-content-secondary mt-0.5">{v.recommendation}</p>
                          </div>
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              ) : (
                <div className="bg-surface-tertiary border border-emerald-500/30 rounded-xl p-10 text-center">
                  <CheckCircle className="w-12 h-12 text-emerald-400 mx-auto mb-3" />
                  <h3 className="text-lg font-medium text-content-primary">No AI Vulnerabilities Found</h3>
                  <p className="text-sm text-content-tertiary mt-1">The scanned code appears safe from AI-specific security issues.</p>
                </div>
              )}
            </div>
          )}

          {!scanResults && !scanMutation.isPending && (
            <div className="bg-surface-tertiary/50 border border-border-secondary/50 rounded-xl p-10 text-center">
              <Scan className="w-12 h-12 text-content-muted mx-auto mb-3" />
              <h3 className="text-lg font-medium text-content-tertiary">Ready to Scan</h3>
              <p className="text-sm text-content-muted mt-1">Paste your AI/ML code above and click Scan Code to detect vulnerabilities</p>
            </div>
          )}
        </div>
      )}

      {/* TAB 2: Product Analysis */}
      {activeTab === 'product' && (
        <div className="space-y-6">
          <div className="flex items-center gap-4">
            <select
              className="bg-surface-tertiary border border-border-secondary rounded-lg px-4 py-2.5 text-sm text-content-primary focus:outline-none focus:border-violet-500/50 min-w-[240px]"
              value={selectedProduct || ''}
              onChange={(e) => setSelectedProduct(e.target.value ? Number(e.target.value) : null)}
            >
              <option value="">Select a product...</option>
              {products?.data?.map((p: any) => (
                <option key={p.id} value={p.id}>{p.name}</option>
              ))}
            </select>
            {selectedProduct && (
              <button
                onClick={() => analyzeMutation.mutate(selectedProduct)}
                disabled={analyzeMutation.isPending}
                className="px-4 py-2.5 bg-violet-600 hover:bg-violet-500 text-white rounded-lg text-sm font-medium flex items-center gap-2 disabled:opacity-50 transition-colors"
              >
                {analyzeMutation.isPending ? (
                  <Loader2 className="w-4 h-4 animate-spin" />
                ) : (
                  <Scan className="w-4 h-4" />
                )}
                Analyze Findings
              </button>
            )}
          </div>

          {!selectedProduct && (
            <div className="bg-surface-tertiary/50 border border-border-secondary/50 rounded-xl p-12 text-center">
              <Info className="w-12 h-12 text-content-muted mx-auto mb-3" />
              <h3 className="text-lg font-medium text-content-tertiary">Select a Product</h3>
              <p className="text-sm text-content-muted mt-1">Choose a product to view its AI risk assessment and OWASP LLM Top 10 mapping</p>
            </div>
          )}

          {selectedProduct && (assessmentLoading || owaspLoading) && (
            <div className="flex items-center justify-center py-16">
              <Loader2 className="w-8 h-8 text-violet-400 animate-spin" />
            </div>
          )}

          {/* AI Risk Assessment */}
          {selectedProduct && assessment?.data && !assessmentLoading && (
            <div className="space-y-4">
              <h3 className="text-lg font-semibold text-content-primary flex items-center gap-2">
                <ShieldAlert className="w-5 h-5 text-violet-400" />
                AI Risk Assessment
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
                {/* AI Exposure Level */}
                <div className="bg-surface-tertiary border border-border-secondary rounded-xl p-4">
                  <div className="text-xs text-content-tertiary mb-2">AI Exposure Level</div>
                  <div className="flex items-center gap-2">
                    {riskLevelBadge(assessment.data.ai_exposure_level || assessment.data.risk_level || 'medium')}
                  </div>
                </div>
                {/* Prompt Injection Risk */}
                <div className="bg-surface-tertiary border border-border-secondary rounded-xl p-4">
                  <div className="text-xs text-content-tertiary mb-2">Prompt Injection Risk</div>
                  <div className="flex items-center gap-2">
                    {riskLevelBadge(assessment.data.prompt_injection_risk || 'low')}
                  </div>
                </div>
                {/* Data Poisoning Risk */}
                <div className="bg-surface-tertiary border border-border-secondary rounded-xl p-4">
                  <div className="text-xs text-content-tertiary mb-2">Data Poisoning Risk</div>
                  <div className="flex items-center gap-2">
                    {riskLevelBadge(assessment.data.data_poisoning_risk || 'low')}
                  </div>
                </div>
                {/* Model Supply Chain Risk */}
                <div className="bg-surface-tertiary border border-border-secondary rounded-xl p-4">
                  <div className="text-xs text-content-tertiary mb-2">Model Supply Chain Risk</div>
                  <div className="flex items-center gap-2">
                    {riskLevelBadge(assessment.data.model_supply_chain_risk || 'low')}
                  </div>
                </div>
              </div>

              {/* Recommendations */}
              {assessment.data.recommendations && assessment.data.recommendations.length > 0 && (
                <div className="bg-surface-tertiary border border-border-secondary rounded-xl p-5">
                  <h4 className="text-sm font-semibold text-content-primary mb-3 flex items-center gap-2">
                    <CheckCircle className="w-4 h-4 text-emerald-400" />
                    Recommendations
                  </h4>
                  <div className="space-y-2">
                    {assessment.data.recommendations.map((rec: string, i: number) => (
                      <div key={i} className="flex items-start gap-2 text-sm text-content-secondary">
                        <ChevronRight className="w-4 h-4 text-violet-400 shrink-0 mt-0.5" />
                        <span>{rec}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* OWASP LLM Top 10 Mapping */}
          {selectedProduct && owaspLlm?.data && !owaspLoading && (
            <div className="space-y-4">
              <h3 className="text-lg font-semibold text-content-primary flex items-center gap-2">
                <AlertTriangle className="w-5 h-5 text-yellow-400" />
                OWASP LLM Top 10 Mapping
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-3">
                {OWASP_LLM_CATEGORIES.map((cat, idx) => {
                  const mappings = owaspLlm.data.categories || owaspLlm.data.mappings || []
                  const match = mappings.find((m: any) => m.id === cat.id || m.category_id === cat.id) || {}
                  const riskLevel = (match.risk_level || match.status || 'none').toLowerCase()
                  const findingCount = match.finding_count || 0
                  const rColor = RISK_COLORS[riskLevel] || RISK_COLORS.none

                  return (
                    <div
                      key={cat.id}
                      className="bg-surface-tertiary border border-border-secondary rounded-xl p-4 hover:border-border-secondary transition-colors"
                    >
                      <div className="flex items-center justify-between mb-2">
                        <span
                          className="text-xs font-mono font-bold px-2 py-0.5 rounded"
                          style={{ color: cat.color, backgroundColor: cat.color + '1a', border: `1px solid ${cat.color}44` }}
                        >
                          {cat.id}
                        </span>
                        <span
                          className="text-[10px] font-semibold px-2 py-0.5 rounded-full"
                          style={{ color: rColor, backgroundColor: rColor + '1a', border: `1px solid ${rColor}44` }}
                        >
                          {riskLevel === 'none' ? 'None' : riskLevel.charAt(0).toUpperCase() + riskLevel.slice(1)}
                        </span>
                      </div>
                      <h4 className="text-xs font-medium text-content-primary mb-1 leading-snug">{cat.name}</h4>
                      <div className="flex items-center justify-between mt-2">
                        <span className="text-[10px] text-content-muted">{findingCount} finding{findingCount !== 1 ? 's' : ''}</span>
                        {findingCount === 0 ? (
                          <CheckCircle className="w-3.5 h-3.5 text-emerald-400" />
                        ) : (
                          <XCircle className="w-3.5 h-3.5" style={{ color: rColor }} />
                        )}
                      </div>
                      {match.description && (
                        <p className="text-[10px] text-content-muted mt-2 leading-relaxed line-clamp-2">{match.description}</p>
                      )}
                    </div>
                  )
                })}
              </div>
            </div>
          )}
        </div>
      )}

      {/* TAB 3: Overview (org-wide) */}
      {activeTab === 'overview' && (
        <div className="space-y-6">
          {!overview?.data ? (
            <div className="flex items-center justify-center py-16">
              <Loader2 className="w-8 h-8 text-violet-400 animate-spin" />
            </div>
          ) : (
            <>
              {/* Stats Cards */}
              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div className="bg-surface-tertiary border border-border-secondary rounded-xl p-5">
                  <div className="flex items-center gap-2 mb-2">
                    <Cpu className="w-4 h-4 text-violet-400" />
                    <span className="text-xs text-content-tertiary">Products with AI Risk</span>
                  </div>
                  <div className="text-3xl font-bold text-content-primary">
                    {overview.data.products_with_ai_risk ?? overview.data.ai_component_count ?? 0}
                  </div>
                </div>
                <div className="bg-surface-tertiary border border-border-secondary rounded-xl p-5">
                  <div className="flex items-center gap-2 mb-2">
                    <Bug className="w-4 h-4 text-red-400" />
                    <span className="text-xs text-content-tertiary">Total AI Vulnerabilities</span>
                  </div>
                  <div className="text-3xl font-bold text-red-400">
                    {overview.data.total_ai_vulnerabilities ?? overview.data.prompt_injection_count ?? 0}
                  </div>
                </div>
                <div className="bg-surface-tertiary border border-border-secondary rounded-xl p-5">
                  <div className="flex items-center gap-2 mb-2">
                    <AlertTriangle className="w-4 h-4 text-orange-400" />
                    <span className="text-xs text-content-tertiary">Critical AI Findings</span>
                  </div>
                  <div className="text-3xl font-bold text-orange-400">
                    {overview.data.critical_ai_findings ?? 0}
                  </div>
                </div>
              </div>

              {/* Overall Risk Level */}
              {overview.data.overall_risk_level && (
                <div className="bg-surface-tertiary border border-border-secondary rounded-xl p-5 flex items-center justify-between">
                  <div className="flex items-center gap-3">
                    <Eye className="w-5 h-5 text-violet-400" />
                    <span className="text-sm font-medium text-content-primary">Organization AI Risk Level</span>
                  </div>
                  {riskLevelBadge(overview.data.overall_risk_level)}
                </div>
              )}

              {/* Per-Product Risk Summary */}
              {overview.data.products && overview.data.products.length > 0 && (
                <div className="bg-surface-tertiary border border-border-secondary rounded-xl overflow-hidden">
                  <div className="p-4 border-b border-border-secondary">
                    <h3 className="text-sm font-semibold text-content-primary flex items-center gap-2">
                      <BarChart3 className="w-4 h-4 text-violet-400" />
                      Per-Product AI Risk Summary
                    </h3>
                  </div>
                  <div className="overflow-x-auto">
                    <table className="w-full text-sm">
                      <thead>
                        <tr className="text-left text-xs text-content-tertiary border-b border-border-secondary">
                          <th className="px-4 py-3 font-medium">Product</th>
                          <th className="px-4 py-3 font-medium">AI Risk Level</th>
                          <th className="px-4 py-3 font-medium">AI Vulnerabilities</th>
                          <th className="px-4 py-3 font-medium">Prompt Injection</th>
                          <th className="px-4 py-3 font-medium">OWASP Coverage</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-border-secondary/50">
                        {overview.data.products.map((p: any, i: number) => (
                          <tr key={i} className="hover:bg-border-secondary/20 transition-colors">
                            <td className="px-4 py-3 text-content-primary font-medium">{p.name || p.product_name || `Product ${p.id}`}</td>
                            <td className="px-4 py-3">{riskLevelBadge(p.risk_level || p.ai_risk_level || 'none')}</td>
                            <td className="px-4 py-3 text-content-secondary">{p.ai_vulnerability_count ?? p.vulnerability_count ?? 0}</td>
                            <td className="px-4 py-3 text-content-secondary">{p.prompt_injection_count ?? 0}</td>
                            <td className="px-4 py-3 text-content-secondary">{p.owasp_coverage || 'N/A'}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              )}

              {/* Empty state for products list */}
              {(!overview.data.products || overview.data.products.length === 0) && (
                <div className="bg-surface-tertiary/50 border border-border-secondary/50 rounded-xl p-10 text-center">
                  <Info className="w-10 h-10 text-content-muted mx-auto mb-3" />
                  <h3 className="text-base font-medium text-content-tertiary">No Product AI Data Yet</h3>
                  <p className="text-sm text-content-muted mt-1">Run AI analysis on your products to populate the overview</p>
                </div>
              )}
            </>
          )}
        </div>
      )}
    </div>
  )
}
