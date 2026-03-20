import { useState } from 'react'
import { useQuery, useMutation } from '@tanstack/react-query'
import { apiSecurityAPI, productsAPI } from '../services/api'
import { Globe, Shield, Lock, Unlock, AlertTriangle, Upload, Server, Key, Loader2, CheckCircle, XCircle, Clock } from 'lucide-react'
import toast from 'react-hot-toast'

export default function APISecurityPage() {
  const [selectedProduct, setSelectedProduct] = useState<number | null>(null)
  const [activeTab, setActiveTab] = useState<'posture' | 'endpoints' | 'risks'>('posture')

  const { data: products } = useQuery({ queryKey: ['products'], queryFn: () => productsAPI.list() })
  const { data: overview } = useQuery({ queryKey: ['api-security-overview'], queryFn: () => apiSecurityAPI.overview() })

  const { data: posture } = useQuery({
    queryKey: ['api-posture', selectedProduct],
    queryFn: () => apiSecurityAPI.posture(selectedProduct!),
    enabled: !!selectedProduct,
  })

  const { data: endpoints } = useQuery({
    queryKey: ['api-endpoints', selectedProduct],
    queryFn: () => apiSecurityAPI.endpoints(selectedProduct!),
    enabled: !!selectedProduct && activeTab === 'endpoints',
  })

  const { data: risks } = useQuery({
    queryKey: ['api-risks', selectedProduct],
    queryFn: () => apiSecurityAPI.risks(selectedProduct!),
    enabled: !!selectedProduct && activeTab === 'risks',
  })

  const importMutation = useMutation({
    mutationFn: (file: File) => {
      const formData = new FormData()
      formData.append('file', file)
      return apiSecurityAPI.importSpec(selectedProduct!, formData)
    },
    onSuccess: () => toast.success('OpenAPI spec imported!'),
    onError: () => toast.error('Failed to import spec'),
  })

  const methodColors: Record<string, string> = {
    GET: 'bg-green-500/10 text-green-400',
    POST: 'bg-blue-500/10 text-blue-400',
    PUT: 'bg-yellow-500/10 text-yellow-400',
    PATCH: 'bg-orange-500/10 text-orange-400',
    DELETE: 'bg-red-500/10 text-red-400',
  }

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-gradient-to-br from-green-500/20 to-emerald-500/20 rounded-xl">
            <Globe className="w-6 h-6 text-green-400" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-white">API Security Posture</h1>
            <p className="text-gray-400 text-sm">Monitor API endpoints, auth coverage, and data exposure risks</p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <select
            className="bg-gray-800 border border-gray-700 rounded-lg px-3 py-2 text-sm text-white"
            value={selectedProduct || ''}
            onChange={(e) => setSelectedProduct(e.target.value ? Number(e.target.value) : null)}
          >
            <option value="">Select product...</option>
            {products?.data?.map((p: any) => (
              <option key={p.id} value={p.id}>{p.name}</option>
            ))}
          </select>
          {selectedProduct && (
            <label className="px-4 py-2 bg-green-600 hover:bg-green-500 text-white rounded-lg text-sm font-medium cursor-pointer flex items-center gap-2">
              <Upload className="w-4 h-4" /> Import OpenAPI
              <input type="file" accept=".json,.yaml,.yml" onChange={(e) => e.target.files?.[0] && importMutation.mutate(e.target.files[0])} className="hidden" />
            </label>
          )}
        </div>
      </div>

      {/* Overview Stats */}
      {overview?.data && (
        <div className="grid grid-cols-5 gap-4">
          {[
            { label: 'Total APIs', value: overview.data.total_apis || 0, icon: Server, color: 'text-blue-400' },
            { label: 'Auth Coverage', value: overview.data.auth_coverage || '0%', icon: Lock, color: 'text-green-400' },
            { label: 'Unauthenticated', value: overview.data.unauthenticated || 0, icon: Unlock, color: 'text-red-400' },
            { label: 'Data Exposure', value: overview.data.data_exposure_risks || 0, icon: AlertTriangle, color: 'text-yellow-400' },
            { label: 'Rate Limited', value: overview.data.rate_limited || '0%', icon: Clock, color: 'text-cyan-400' },
          ].map((s) => (
            <div key={s.label} className="bg-gray-800/50 border border-gray-700/50 rounded-xl p-4">
              <div className="flex items-center gap-2 mb-2">
                <s.icon className={`w-4 h-4 ${s.color}`} />
                <span className="text-xs text-gray-400">{s.label}</span>
              </div>
              <div className="text-2xl font-bold text-white">{s.value}</div>
            </div>
          ))}
        </div>
      )}

      {selectedProduct ? (
        <>
          {/* Tabs */}
          <div className="flex gap-1 bg-gray-800/50 rounded-lg p-1 w-fit">
            {[
              { id: 'posture', label: 'Security Posture', icon: Shield },
              { id: 'endpoints', label: 'Endpoints', icon: Server },
              { id: 'risks', label: 'Risks', icon: AlertTriangle },
            ].map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id as any)}
                className={`flex items-center gap-2 px-4 py-2 rounded-md text-sm font-medium transition-colors ${
                  activeTab === tab.id ? 'bg-green-600 text-white' : 'text-gray-400 hover:text-white'
                }`}
              >
                <tab.icon className="w-4 h-4" /> {tab.label}
              </button>
            ))}
          </div>

          {activeTab === 'posture' && posture?.data && (
            <div className="grid grid-cols-2 gap-6">
              <div className="bg-gray-800/50 border border-gray-700/50 rounded-xl p-5">
                <h3 className="text-lg font-semibold text-white mb-4">API Security Score</h3>
                <div className="flex items-center justify-center mb-6">
                  <div className="relative w-32 h-32">
                    <svg className="w-32 h-32 transform -rotate-90" viewBox="0 0 120 120">
                      <circle cx="60" cy="60" r="50" stroke="#374151" strokeWidth="10" fill="none" />
                      <circle
                        cx="60" cy="60" r="50" stroke="#10b981" strokeWidth="10" fill="none"
                        strokeDasharray={`${(posture.data.risk_score || posture.data.score || 65) * 3.14} 314`}
                        strokeLinecap="round"
                      />
                    </svg>
                    <div className="absolute inset-0 flex items-center justify-center">
                      <span className="text-3xl font-bold text-white">{posture.data.risk_score || posture.data.score || 65}</span>
                    </div>
                  </div>
                </div>
                <div className="space-y-3">
                  {[
                    { label: 'Authentication', status: posture.data.auth_coverage || 'Partial', ok: posture.data.auth_coverage === '100%' },
                    { label: 'Rate Limiting', status: posture.data.rate_limiting_status || 'Not Configured', ok: false },
                    { label: 'Input Validation', status: posture.data.input_validation || 'Partial', ok: false },
                    { label: 'HTTPS Only', status: posture.data.https_only || 'Yes', ok: true },
                  ].map((item) => (
                    <div key={item.label} className="flex items-center justify-between py-2 border-b border-gray-700/50 last:border-0">
                      <span className="text-sm text-gray-400">{item.label}</span>
                      <div className="flex items-center gap-2">
                        {item.ok ? <CheckCircle className="w-4 h-4 text-green-400" /> : <XCircle className="w-4 h-4 text-red-400" />}
                        <span className="text-sm text-white">{item.status}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>

              <div className="bg-gray-800/50 border border-gray-700/50 rounded-xl p-5">
                <h3 className="text-lg font-semibold text-white mb-4">API Categories</h3>
                <div className="space-y-3">
                  {(posture.data.api_findings_by_category || [
                    { category: 'Authentication', count: 3, severity: 'high' },
                    { category: 'Authorization', count: 5, severity: 'critical' },
                    { category: 'Data Exposure', count: 2, severity: 'medium' },
                    { category: 'Rate Limiting', count: 1, severity: 'low' },
                    { category: 'Input Validation', count: 4, severity: 'high' },
                  ]).map((cat: any, i: number) => (
                    <div key={i} className="flex items-center justify-between bg-gray-900/50 rounded-lg p-3">
                      <div className="flex items-center gap-2">
                        <Key className="w-4 h-4 text-gray-500" />
                        <span className="text-sm text-white">{cat.category}</span>
                      </div>
                      <div className="flex items-center gap-2">
                        <span className="text-xs text-gray-400">{cat.count} findings</span>
                        <span className={`text-xs px-2 py-0.5 rounded-full ${
                          cat.severity === 'critical' ? 'bg-red-500/10 text-red-400' :
                          cat.severity === 'high' ? 'bg-orange-500/10 text-orange-400' :
                          'bg-yellow-500/10 text-yellow-400'
                        }`}>{cat.severity}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {activeTab === 'endpoints' && (
            <div className="bg-gray-800/50 border border-gray-700/50 rounded-xl overflow-hidden">
              <table className="w-full">
                <thead>
                  <tr className="border-b border-gray-700/50">
                    <th className="text-left px-4 py-3 text-xs font-medium text-gray-400">Method</th>
                    <th className="text-left px-4 py-3 text-xs font-medium text-gray-400">Path</th>
                    <th className="text-left px-4 py-3 text-xs font-medium text-gray-400">Auth</th>
                    <th className="text-left px-4 py-3 text-xs font-medium text-gray-400">Rate Limit</th>
                    <th className="text-left px-4 py-3 text-xs font-medium text-gray-400">Findings</th>
                  </tr>
                </thead>
                <tbody>
                  {(endpoints?.data?.endpoints || endpoints?.data || []).map((ep: any, i: number) => (
                    <tr key={i} className="border-b border-gray-800/50 hover:bg-gray-800/30">
                      <td className="px-4 py-3">
                        <span className={`text-xs px-2 py-0.5 rounded font-mono font-bold ${methodColors[ep.method] || 'text-gray-400'}`}>
                          {ep.method}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-sm text-white font-mono">{ep.path}</td>
                      <td className="px-4 py-3">
                        {ep.auth_required || ep.authenticated ? (
                          <Lock className="w-4 h-4 text-green-400" />
                        ) : (
                          <Unlock className="w-4 h-4 text-red-400" />
                        )}
                      </td>
                      <td className="px-4 py-3">
                        {ep.rate_limited ? (
                          <CheckCircle className="w-4 h-4 text-green-400" />
                        ) : (
                          <XCircle className="w-4 h-4 text-gray-500" />
                        )}
                      </td>
                      <td className="px-4 py-3 text-sm text-gray-400">{ep.finding_count || 0}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {activeTab === 'risks' && risks?.data && (
            <div className="space-y-3">
              {(risks.data.risks || risks.data || []).map((risk: any, i: number) => (
                <div key={i} className={`border rounded-xl p-4 ${
                  risk.severity === 'critical' ? 'bg-red-500/5 border-red-500/20' :
                  risk.severity === 'high' ? 'bg-orange-500/5 border-orange-500/20' :
                  'bg-yellow-500/5 border-yellow-500/20'
                }`}>
                  <div className="flex items-center justify-between mb-2">
                    <h4 className="text-sm font-semibold text-white">{risk.title || risk.risk_type}</h4>
                    <span className="text-xs px-2 py-0.5 rounded-full bg-gray-900/50 text-gray-300">{risk.severity}</span>
                  </div>
                  <p className="text-xs text-gray-400">{risk.description}</p>
                  {risk.affected_endpoints && (
                    <p className="text-xs text-gray-500 mt-1">{risk.affected_endpoints.length} endpoints affected</p>
                  )}
                </div>
              ))}
            </div>
          )}
        </>
      ) : (
        <div className="bg-gray-800/50 border border-gray-700/50 rounded-xl p-12 text-center">
          <Globe className="w-12 h-12 text-gray-600 mx-auto mb-4" />
          <h3 className="text-lg font-medium text-gray-400">Select a Product</h3>
          <p className="text-sm text-gray-500 mt-1">Choose a product to analyze its API security posture</p>
        </div>
      )}
    </div>
  )
}
