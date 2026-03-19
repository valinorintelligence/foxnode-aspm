import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { findingsAPI } from '../services/api'
import { Search, Filter, ChevronDown, FileCode, AlertTriangle, Eye } from 'lucide-react'
import SeverityBadge from '../components/common/SeverityBadge'

export default function FindingsPage() {
  const [filters, setFilters] = useState<any>({ limit: 50 })
  const [search, setSearch] = useState('')
  const queryClient = useQueryClient()
  const navigate = useNavigate()

  const { data: findings, isLoading } = useQuery({
    queryKey: ['findings', filters, search],
    queryFn: () =>
      findingsAPI.list({ ...filters, search: search || undefined }).then((r) => r.data),
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: number; data: any }) => findingsAPI.update(id, data),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['findings'] }),
  })

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Findings</h1>
          <p className="text-gray-500 mt-1">Vulnerability findings across all products</p>
        </div>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap gap-3">
        <div className="relative flex-1 max-w-md">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
          <input
            type="text"
            placeholder="Search findings..."
            className="input w-full pl-10"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
        <select
          className="input"
          value={filters.severity || ''}
          onChange={(e) => setFilters({ ...filters, severity: e.target.value || undefined })}
        >
          <option value="">All Severities</option>
          <option value="critical">Critical</option>
          <option value="high">High</option>
          <option value="medium">Medium</option>
          <option value="low">Low</option>
          <option value="info">Info</option>
        </select>
        <select
          className="input"
          value={filters.status || ''}
          onChange={(e) => setFilters({ ...filters, status: e.target.value || undefined })}
        >
          <option value="">All Statuses</option>
          <option value="active">Active</option>
          <option value="verified">Verified</option>
          <option value="mitigated">Mitigated</option>
          <option value="false_positive">False Positive</option>
          <option value="risk_accepted">Risk Accepted</option>
        </select>
      </div>

      {/* Table */}
      {isLoading ? (
        <div className="text-gray-500 text-center py-12">Loading findings...</div>
      ) : (
        <div className="card p-0 overflow-hidden">
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="bg-gray-800/50">
                  <th className="text-left py-3 px-4 text-xs font-medium text-gray-500 uppercase">Severity</th>
                  <th className="text-left py-3 px-4 text-xs font-medium text-gray-500 uppercase">Title</th>
                  <th className="text-left py-3 px-4 text-xs font-medium text-gray-500 uppercase">Scanner</th>
                  <th className="text-left py-3 px-4 text-xs font-medium text-gray-500 uppercase">File</th>
                  <th className="text-left py-3 px-4 text-xs font-medium text-gray-500 uppercase">CVE</th>
                  <th className="text-left py-3 px-4 text-xs font-medium text-gray-500 uppercase">Status</th>
                  <th className="text-left py-3 px-4 text-xs font-medium text-gray-500 uppercase">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800/50">
                {findings?.length === 0 ? (
                  <tr>
                    <td colSpan={7} className="py-12 text-center">
                      <AlertTriangle className="w-10 h-10 mx-auto mb-3 text-gray-600" />
                      <p className="text-gray-500">No findings match your filters</p>
                    </td>
                  </tr>
                ) : (
                  findings?.map((finding: any) => (
                    <tr key={finding.id} className="hover:bg-gray-800/30 transition-colors">
                      <td className="py-3 px-4">
                        <SeverityBadge severity={finding.severity} />
                      </td>
                      <td className="py-3 px-4">
                        <div className="max-w-sm">
                          <p className="text-sm text-gray-200 font-medium truncate">{finding.title}</p>
                          {finding.component && (
                            <p className="text-xs text-gray-500 mt-0.5">
                              {finding.component}
                              {finding.component_version && `@${finding.component_version}`}
                            </p>
                          )}
                        </div>
                      </td>
                      <td className="py-3 px-4 text-sm text-gray-400">{finding.scanner || '-'}</td>
                      <td className="py-3 px-4">
                        {finding.file_path ? (
                          <div className="flex items-center gap-1.5">
                            <FileCode className="w-3.5 h-3.5 text-gray-600 shrink-0" />
                            <span className="text-xs text-gray-400 font-mono truncate max-w-[200px]">
                              {finding.file_path}
                              {finding.line_number && `:${finding.line_number}`}
                            </span>
                          </div>
                        ) : (
                          <span className="text-gray-600">-</span>
                        )}
                      </td>
                      <td className="py-3 px-4">
                        {finding.cve ? (
                          <span className="text-xs text-foxnode-400 font-mono">{finding.cve}</span>
                        ) : (
                          <span className="text-gray-600">-</span>
                        )}
                      </td>
                      <td className="py-3 px-4">
                        <select
                          className="bg-transparent text-xs text-gray-400 border border-gray-700 rounded px-2 py-1 focus:outline-none focus:ring-1 focus:ring-foxnode-500"
                          value={finding.status}
                          onChange={(e) =>
                            updateMutation.mutate({ id: finding.id, data: { status: e.target.value } })
                          }
                        >
                          <option value="active">Active</option>
                          <option value="verified">Verified</option>
                          <option value="mitigated">Mitigated</option>
                          <option value="false_positive">False Positive</option>
                          <option value="risk_accepted">Risk Accepted</option>
                        </select>
                      </td>
                      <td className="py-3 px-4">
                        <button
                          onClick={() => navigate(`/findings/${finding.id}`)}
                          className="p-1.5 text-gray-500 hover:text-foxnode-400 transition-colors"
                          title="View details"
                        >
                          <Eye className="w-4 h-4" />
                        </button>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}
