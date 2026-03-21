import { useState } from 'react'
import { useQuery, useMutation } from '@tanstack/react-query'
import { safeArray } from '../lib/safe'
import { copilotAPI, productsAPI, findingsAPI } from '../services/api'
import {
  Wand2,
  FileWarning,
  ChevronRight,
  Copy,
  Check,
  Loader2,
  Zap,
  BookOpen,
  Clock,
  Shield,
  AlertTriangle,
  ExternalLink,
  X,
  ListOrdered,
  Code,
  BarChart3,
  Target,
} from 'lucide-react'
import toast from 'react-hot-toast'

const SEVERITY_COLORS: Record<string, { text: string; bg: string; border: string; hex: string }> = {
  critical: { text: 'text-red-400', bg: 'bg-red-500/10', border: 'border-red-500/30', hex: '#ef4444' },
  high: { text: 'text-orange-400', bg: 'bg-orange-500/10', border: 'border-orange-500/30', hex: '#f97316' },
  medium: { text: 'text-yellow-400', bg: 'bg-yellow-500/10', border: 'border-yellow-500/30', hex: '#f59e0b' },
  low: { text: 'text-blue-400', bg: 'bg-blue-500/10', border: 'border-blue-500/30', hex: '#3b82f6' },
  info: { text: 'text-content-tertiary', bg: 'bg-gray-500/10', border: 'border-gray-500/30', hex: '#6b7280' },
}

function SeverityBadge({ severity }: { severity: string }) {
  const s = SEVERITY_COLORS[severity?.toLowerCase()] || SEVERITY_COLORS.info
  return (
    <span className={`text-xs font-medium px-2 py-0.5 rounded-full ${s.text} ${s.bg} border ${s.border} capitalize`}>
      {severity}
    </span>
  )
}

export default function CopilotPage() {
  const [selectedFinding, setSelectedFinding] = useState<number | null>(null)
  const [selectedProduct, setSelectedProduct] = useState<number | null>(null)
  const [copiedBlock, setCopiedBlock] = useState<string | null>(null)
  const [showBulkModal, setShowBulkModal] = useState(false)

  // Data fetching
  const { data: products } = useQuery({
    queryKey: ['products'],
    queryFn: () => productsAPI.list().then((r) => r.data),
  })

  const { data: findings } = useQuery({
    queryKey: ['copilot-findings', selectedProduct],
    queryFn: () => findingsAPI.list({ product_id: selectedProduct, limit: 100 }).then((r) => r.data),
    enabled: !!selectedProduct,
  })

  const remediateMutation = useMutation({
    mutationFn: (findingId: number) => copilotAPI.remediate(findingId),
    onSuccess: () => {
      toast.success('Remediation guidance generated')
    },
    onError: () => toast.error('Failed to generate remediation'),
  })

  const bulkMutation = useMutation({
    mutationFn: (productId: number) => copilotAPI.bulkRemediate(productId),
    onSuccess: (res) => {
      setShowBulkModal(true)
      toast.success(`Generated ${res.data?.results?.length || 0} bulk remediations`)
    },
    onError: () => toast.error('Bulk remediation failed'),
  })

  const remediation = remediateMutation.data?.data

  const handleFindingClick = (findingId: number) => {
    setSelectedFinding(findingId)
    remediateMutation.mutate(findingId)
  }

  const copyCode = (code: string, block: string) => {
    navigator.clipboard.writeText(code)
    setCopiedBlock(block)
    setTimeout(() => setCopiedBlock(null), 2000)
  }

  const selectedFindingData = safeArray(findings).find((f: any) => f.id === selectedFinding)
  const bulkResults = bulkMutation.data?.data?.results

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2.5 bg-gradient-to-br from-purple-500/20 to-pink-500/20 rounded-xl border border-purple-500/20">
            <Wand2 className="w-6 h-6 text-purple-400" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-content-primary">AI Remediation Copilot</h1>
            <p className="text-content-tertiary text-sm">Get AI-powered fix recommendations with code examples</p>
          </div>
        </div>
      </div>

      {/* Two-panel layout */}
      <div className="grid grid-cols-12 gap-6" style={{ minHeight: '70vh' }}>
        {/* LEFT PANEL - Sidebar */}
        <div className="col-span-4 flex flex-col gap-4">
          {/* Product Selector */}
          <div className="bg-surface-tertiary/50 border border-border-secondary/50 rounded-xl p-4">
            <h3 className="text-sm font-semibold text-content-primary mb-3 flex items-center gap-2">
              <Target className="w-4 h-4 text-purple-400" />
              Select Product
            </h3>
            <select
              className="w-full bg-surface-secondary border border-border-secondary rounded-lg px-3 py-2.5 text-sm text-content-primary focus:border-purple-500 focus:ring-1 focus:ring-purple-500 outline-none transition-colors"
              value={selectedProduct || ''}
              onChange={(e) => {
                setSelectedProduct(Number(e.target.value))
                setSelectedFinding(null)
              }}
            >
              <option value="">Choose a product...</option>
              {safeArray(products).map((p: any) => (
                <option key={p.id} value={p.id}>{p.name}</option>
              ))}
            </select>
          </div>

          {/* Finding List */}
          {safeArray(findings).length > 0 && (
            <div className="bg-surface-tertiary/50 border border-border-secondary/50 rounded-xl p-4 flex-1 flex flex-col min-h-0">
              <h3 className="text-sm font-semibold text-content-primary mb-3 flex items-center gap-2">
                <FileWarning className="w-4 h-4 text-orange-400" />
                Findings ({safeArray(findings).length})
              </h3>
              <div className="flex-1 overflow-y-auto space-y-2 pr-1 scrollbar-thin">
                {safeArray(findings).map((f: any) => (
                  <button
                    key={f.id}
                    onClick={() => handleFindingClick(f.id)}
                    className={`w-full text-left p-3 rounded-lg border transition-all duration-200 ${
                      selectedFinding === f.id
                        ? 'bg-purple-500/10 border-purple-500/30 shadow-lg shadow-purple-500/5'
                        : 'bg-surface-secondary/50 border-border-secondary/30 hover:border-border-secondary hover:bg-surface-secondary/80'
                    }`}
                  >
                    <div className="flex items-start gap-2">
                      <div className="min-w-0 flex-1">
                        <p className="text-sm text-content-primary truncate font-medium">{f.title}</p>
                        <div className="flex items-center gap-2 mt-1.5">
                          <SeverityBadge severity={f.severity} />
                          {f.cwe_id && <span className="text-xs text-content-muted">CWE-{f.cwe_id}</span>}
                        </div>
                        {f.file_path && (
                          <p className="text-xs text-content-muted mt-1 truncate font-mono">{f.file_path}</p>
                        )}
                      </div>
                      <ChevronRight className={`w-4 h-4 shrink-0 mt-0.5 transition-colors ${
                        selectedFinding === f.id ? 'text-purple-400' : 'text-content-muted'
                      }`} />
                    </div>
                  </button>
                ))}
              </div>
            </div>
          )}

          {/* Bulk Remediate Button */}
          {selectedProduct && (
            <button
              onClick={() => bulkMutation.mutate(selectedProduct)}
              disabled={bulkMutation.isPending}
              className="w-full px-4 py-3 bg-gradient-to-r from-purple-600 to-pink-600 text-content-primary rounded-xl text-sm font-semibold hover:from-purple-500 hover:to-pink-500 transition-all duration-200 disabled:opacity-50 flex items-center justify-center gap-2 shadow-lg shadow-purple-500/20"
            >
              {bulkMutation.isPending ? (
                <Loader2 className="w-4 h-4 animate-spin" />
              ) : (
                <Wand2 className="w-4 h-4" />
              )}
              Bulk Remediate
            </button>
          )}
        </div>

        {/* RIGHT PANEL - Main Content */}
        <div className="col-span-8">
          {remediateMutation.isPending ? (
            /* Loading state */
            <div className="bg-surface-tertiary/50 border border-border-secondary/50 rounded-xl p-16 flex flex-col items-center justify-center h-full">
              <div className="relative">
                <Loader2 className="w-14 h-14 text-purple-400 animate-spin" />
                <Wand2 className="w-6 h-6 text-pink-400 absolute -top-1 -right-1 animate-pulse" />
              </div>
              <p className="text-content-tertiary mt-4 text-sm">Analyzing finding and generating remediation guidance...</p>
            </div>
          ) : remediation && selectedFindingData ? (
            /* Remediation content */
            <div className="space-y-4 animate-in fade-in duration-300">
              {/* Finding Header */}
              <div className="bg-surface-tertiary/50 border border-border-secondary/50 rounded-xl p-5">
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <h2 className="text-lg font-bold text-content-primary">{selectedFindingData.title}</h2>
                    <div className="flex items-center gap-3 mt-2 flex-wrap">
                      <SeverityBadge severity={selectedFindingData.severity} />
                      {(selectedFindingData.cwe_id || remediation.cwe_id) && (
                        <span className="text-xs font-mono text-content-tertiary bg-surface-secondary/80 px-2 py-1 rounded-md border border-border-secondary/50">
                          CWE-{selectedFindingData.cwe_id || remediation.cwe_id}
                        </span>
                      )}
                      {(selectedFindingData.file_path || remediation.file_path) && (
                        <span className="text-xs font-mono text-content-muted flex items-center gap-1">
                          <Code className="w-3 h-3" />
                          {selectedFindingData.file_path || remediation.file_path}
                        </span>
                      )}
                    </div>
                  </div>
                </div>
              </div>

              {/* Risk Explanation */}
              {(remediation.risk_explanation || remediation.explanation) && (
                <div className="bg-surface-tertiary/50 border border-border-secondary/50 rounded-xl p-5">
                  <h3 className="text-base font-semibold text-content-primary mb-3 flex items-center gap-2">
                    <AlertTriangle className="w-5 h-5 text-red-400" />
                    Risk Explanation
                  </h3>
                  <p className="text-content-secondary text-sm leading-relaxed">
                    {remediation.risk_explanation || remediation.explanation}
                  </p>
                </div>
              )}

              {/* Impact Analysis */}
              {remediation.impact_analysis && (
                <div className="bg-surface-tertiary/50 border border-border-secondary/50 rounded-xl p-5">
                  <h3 className="text-base font-semibold text-content-primary mb-3 flex items-center gap-2">
                    <BarChart3 className="w-5 h-5 text-orange-400" />
                    Impact Analysis
                  </h3>
                  <div className="p-3 bg-orange-500/5 border border-orange-500/20 rounded-lg">
                    <p className="text-sm text-orange-200/90 leading-relaxed">{remediation.impact_analysis}</p>
                  </div>
                </div>
              )}

              {/* Remediation Steps */}
              {safeArray(remediation.remediation_steps).length > 0 && (
                <div className="bg-surface-tertiary/50 border border-border-secondary/50 rounded-xl p-5">
                  <h3 className="text-base font-semibold text-content-primary mb-4 flex items-center gap-2">
                    <ListOrdered className="w-5 h-5 text-yellow-400" />
                    Remediation Steps
                  </h3>
                  <ol className="space-y-3">
                    {safeArray(remediation.remediation_steps).map((step: string, i: number) => (
                      <li key={i} className="flex items-start gap-3">
                        <span className="w-7 h-7 bg-purple-500/20 text-purple-400 rounded-full flex items-center justify-center text-xs font-bold shrink-0 mt-0.5 border border-purple-500/20">
                          {i + 1}
                        </span>
                        <span className="text-sm text-content-secondary leading-relaxed pt-1">{step}</span>
                      </li>
                    ))}
                  </ol>
                </div>
              )}

              {/* Code Examples */}
              {(remediation.code_example_vulnerable || remediation.code_example_fixed) && (
                <div className="bg-surface-tertiary/50 border border-border-secondary/50 rounded-xl p-5">
                  <h3 className="text-base font-semibold text-content-primary mb-4 flex items-center gap-2">
                    <Code className="w-5 h-5 text-green-400" />
                    Code Examples
                    {remediation.language && (
                      <span className="ml-2 text-xs font-mono text-content-tertiary bg-surface-secondary/80 px-2 py-1 rounded-md border border-border-secondary/50">
                        {remediation.language}
                      </span>
                    )}
                  </h3>
                  <div className="grid grid-cols-1 gap-4">
                    {/* Vulnerable Code */}
                    {remediation.code_example_vulnerable && (
                      <div className="border-l-4 border-red-500 rounded-r-xl bg-surface-secondary/50">
                        <div className="flex items-center justify-between px-4 py-2 border-b border-border-secondary/30">
                          <span className="text-sm font-semibold text-red-400 flex items-center gap-2">
                            <AlertTriangle className="w-4 h-4" />
                            Vulnerable Code
                          </span>
                          <button
                            onClick={() => copyCode(remediation.code_example_vulnerable, 'vulnerable')}
                            className="text-content-muted hover:text-content-primary transition-colors p-1 rounded"
                            title="Copy code"
                          >
                            {copiedBlock === 'vulnerable' ? (
                              <Check className="w-4 h-4 text-green-400" />
                            ) : (
                              <Copy className="w-4 h-4" />
                            )}
                          </button>
                        </div>
                        <pre className="bg-surface-primary rounded-br-xl p-4 text-sm text-content-secondary overflow-x-auto font-mono">
                          <code>{remediation.code_example_vulnerable}</code>
                        </pre>
                      </div>
                    )}

                    {/* Fixed Code */}
                    {remediation.code_example_fixed && (
                      <div className="border-l-4 border-green-500 rounded-r-xl bg-surface-secondary/50">
                        <div className="flex items-center justify-between px-4 py-2 border-b border-border-secondary/30">
                          <span className="text-sm font-semibold text-green-400 flex items-center gap-2">
                            <Shield className="w-4 h-4" />
                            Fixed Code
                          </span>
                          <button
                            onClick={() => copyCode(remediation.code_example_fixed, 'fixed')}
                            className="text-content-muted hover:text-content-primary transition-colors p-1 rounded"
                            title="Copy code"
                          >
                            {copiedBlock === 'fixed' ? (
                              <Check className="w-4 h-4 text-green-400" />
                            ) : (
                              <Copy className="w-4 h-4" />
                            )}
                          </button>
                        </div>
                        <pre className="bg-surface-primary rounded-br-xl p-4 text-sm text-content-secondary overflow-x-auto font-mono">
                          <code>{remediation.code_example_fixed}</code>
                        </pre>
                      </div>
                    )}
                  </div>
                </div>
              )}

              {/* References */}
              {safeArray(remediation.references).length > 0 && (
                <div className="bg-surface-tertiary/50 border border-border-secondary/50 rounded-xl p-5">
                  <h3 className="text-base font-semibold text-content-primary mb-3 flex items-center gap-2">
                    <BookOpen className="w-5 h-5 text-blue-400" />
                    References
                  </h3>
                  <div className="space-y-2">
                    {safeArray(remediation.references).map((ref: any, i: number) => (
                      <a
                        key={i}
                        href={typeof ref === 'string' ? ref : ref.url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="flex items-center gap-2 text-sm text-blue-400 hover:text-blue-300 transition-colors group"
                      >
                        <ExternalLink className="w-3.5 h-3.5 shrink-0 group-hover:translate-x-0.5 transition-transform" />
                        <span className="truncate">{typeof ref === 'string' ? ref : ref.title || ref.url}</span>
                      </a>
                    ))}
                  </div>
                </div>
              )}

              {/* Metadata */}
              <div className="bg-surface-tertiary/50 border border-border-secondary/50 rounded-xl p-5">
                <h3 className="text-base font-semibold text-content-primary mb-3 flex items-center gap-2">
                  <Zap className="w-5 h-5 text-purple-400" />
                  Metadata
                </h3>
                <div className="grid grid-cols-2 sm:grid-cols-4 gap-4">
                  {remediation.priority_reasoning && (
                    <div>
                      <p className="text-xs text-content-muted mb-1">Priority Reasoning</p>
                      <p className="text-sm text-content-secondary">{remediation.priority_reasoning}</p>
                    </div>
                  )}
                  {remediation.estimated_effort && (
                    <div>
                      <p className="text-xs text-content-muted mb-1">Estimated Effort</p>
                      <p className="text-sm text-content-secondary flex items-center gap-1">
                        <Clock className="w-3.5 h-3.5 text-yellow-400" />
                        {typeof remediation.estimated_effort === 'number'
                          ? `${remediation.estimated_effort} hours`
                          : remediation.estimated_effort}
                      </p>
                    </div>
                  )}
                  {remediation.owasp_category && (
                    <div>
                      <p className="text-xs text-content-muted mb-1">OWASP Category</p>
                      <p className="text-sm text-content-secondary">{remediation.owasp_category}</p>
                    </div>
                  )}
                  {remediation.confidence && (
                    <div>
                      <p className="text-xs text-content-muted mb-1">Confidence</p>
                      <p className="text-sm text-content-secondary capitalize">{remediation.confidence}</p>
                    </div>
                  )}
                </div>
              </div>
            </div>
          ) : (
            /* Empty state */
            <div className="bg-surface-tertiary/50 border border-border-secondary/50 rounded-xl flex flex-col items-center justify-center h-full min-h-[400px]">
              <div className="p-4 bg-border-secondary/20 rounded-2xl mb-4">
                <Wand2 className="w-14 h-14 text-content-muted" />
              </div>
              <h3 className="text-lg font-medium text-content-tertiary">Select a Finding</h3>
              <p className="text-content-muted text-sm mt-1 max-w-sm text-center">
                Select a finding to get AI-powered remediation guidance
              </p>
            </div>
          )}
        </div>
      </div>

      {/* Bulk Remediation Modal */}
      {showBulkModal && safeArray(bulkResults).length > 0 && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="bg-surface-secondary border border-border-secondary rounded-2xl shadow-2xl w-full max-w-4xl max-h-[80vh] flex flex-col mx-4">
            {/* Modal Header */}
            <div className="flex items-center justify-between p-5 border-b border-border-secondary/50">
              <div className="flex items-center gap-3">
                <div className="p-2 bg-purple-500/10 rounded-lg">
                  <Wand2 className="w-5 h-5 text-purple-400" />
                </div>
                <div>
                  <h2 className="text-lg font-bold text-content-primary">Bulk Remediation Results</h2>
                  <p className="text-sm text-content-tertiary">{safeArray(bulkResults).length} findings analyzed</p>
                </div>
              </div>
              <button
                onClick={() => setShowBulkModal(false)}
                className="p-2 text-content-tertiary hover:text-content-primary hover:bg-surface-tertiary rounded-lg transition-colors"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Modal Body */}
            <div className="flex-1 overflow-y-auto p-5">
              <table className="w-full">
                <thead>
                  <tr className="text-left text-xs text-content-muted uppercase tracking-wider">
                    <th className="pb-3 pr-4">Finding</th>
                    <th className="pb-3 pr-4">Severity</th>
                    <th className="pb-3 pr-4">Priority</th>
                    <th className="pb-3 pr-4">Effort</th>
                    <th className="pb-3">Confidence</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-border">
                  {safeArray(bulkResults).map((r: any, i: number) => (
                    <tr key={i} className="hover:bg-surface-tertiary/50 transition-colors">
                      <td className="py-3 pr-4">
                        <p className="text-sm text-content-primary font-medium truncate max-w-[250px]">
                          {r.title || r.finding_title || `Finding #${r.finding_id || i + 1}`}
                        </p>
                        {r.cwe_id && (
                          <span className="text-xs text-content-muted font-mono">CWE-{r.cwe_id}</span>
                        )}
                      </td>
                      <td className="py-3 pr-4">
                        <SeverityBadge severity={r.severity || 'info'} />
                      </td>
                      <td className="py-3 pr-4">
                        <span className="text-sm text-content-secondary capitalize">
                          {r.priority || r.recommended_priority || r.priority_reasoning || '-'}
                        </span>
                      </td>
                      <td className="py-3 pr-4">
                        <span className="text-sm text-content-secondary flex items-center gap-1">
                          <Clock className="w-3.5 h-3.5 text-yellow-400" />
                          {r.estimated_effort
                            ? typeof r.estimated_effort === 'number'
                              ? `${r.estimated_effort}h`
                              : r.estimated_effort
                            : '-'}
                        </span>
                      </td>
                      <td className="py-3">
                        <span className="text-sm text-content-tertiary capitalize">{r.confidence || '-'}</span>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Modal Footer */}
            <div className="flex items-center justify-end gap-3 p-5 border-t border-border-secondary/50">
              <button
                onClick={() => setShowBulkModal(false)}
                className="px-4 py-2 text-sm text-content-tertiary hover:text-content-primary bg-surface-tertiary hover:bg-border-secondary rounded-lg transition-colors border border-border-secondary"
              >
                Close
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
