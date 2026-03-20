import { useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { findingsAPI, jiraAPI } from '../services/api'
import {
  ArrowLeft,
  FileCode,
  ExternalLink,
  Shield,
  AlertTriangle,
  Bug,
  Link2,
  Clock,
} from 'lucide-react'
import SeverityBadge from '../components/common/SeverityBadge'
import toast from 'react-hot-toast'
import clsx from 'clsx'

export default function FindingDetailPage() {
  const { id } = useParams()
  const navigate = useNavigate()
  const queryClient = useQueryClient()
  const [jiraProjectKey, setJiraProjectKey] = useState('SEC')

  const { data: finding, isLoading } = useQuery({
    queryKey: ['finding', id],
    queryFn: () => findingsAPI.get(Number(id)).then((r) => r.data),
    enabled: !!id,
  })

  const updateMutation = useMutation({
    mutationFn: (data: any) => findingsAPI.update(Number(id), data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['finding', id] })
      queryClient.invalidateQueries({ queryKey: ['findings'] })
      toast.success('Finding updated')
    },
  })

  const jiraMutation = useMutation({
    mutationFn: () => jiraAPI.createIssue(Number(id), { project_key: jiraProjectKey }),
    onSuccess: (res) => {
      toast.success(`Jira issue ${res.data.jira_key} created!`)
    },
    onError: (err: any) => toast.error(err.response?.data?.detail || 'Failed to create Jira issue'),
  })

  if (isLoading) {
    return <div className="text-content-muted text-center py-12">Loading finding...</div>
  }

  if (!finding) {
    return <div className="text-content-muted text-center py-12">Finding not found</div>
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-start gap-4">
        <button
          onClick={() => navigate('/findings')}
          className="p-2 text-content-tertiary hover:text-content-secondary hover:bg-surface-tertiary rounded-lg transition-colors mt-0.5"
        >
          <ArrowLeft className="w-5 h-5" />
        </button>
        <div className="flex-1">
          <div className="flex items-center gap-3 mb-2">
            <SeverityBadge severity={finding.severity} />
            <span className="text-xs text-content-muted capitalize px-2 py-0.5 bg-surface-tertiary rounded">{finding.status}</span>
          </div>
          <h1 className="text-xl font-bold text-content-primary">{finding.title}</h1>
          <div className="flex items-center gap-4 mt-2 text-xs text-content-muted">
            {finding.scanner && (
              <span className="flex items-center gap-1.5">
                <Shield className="w-3.5 h-3.5" /> {finding.scanner}
              </span>
            )}
            {finding.cve && (
              <span className="flex items-center gap-1.5 text-foxnode-400">
                <Bug className="w-3.5 h-3.5" /> {finding.cve}
              </span>
            )}
            <span className="flex items-center gap-1.5">
              <Clock className="w-3.5 h-3.5" /> Found {finding.date_found ? new Date(finding.date_found).toLocaleDateString() : '—'}
            </span>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Main Content */}
        <div className="lg:col-span-2 space-y-6">
          {/* Description */}
          {finding.description && (
            <div className="card">
              <h3 className="text-sm font-semibold text-content-tertiary uppercase mb-3">Description</h3>
              <p className="text-sm text-content-secondary whitespace-pre-wrap leading-relaxed">{finding.description}</p>
            </div>
          )}

          {/* File Location */}
          {finding.file_path && (
            <div className="card">
              <h3 className="text-sm font-semibold text-content-tertiary uppercase mb-3">Location</h3>
              <div className="flex items-center gap-2 p-3 bg-surface-tertiary/50 rounded-lg font-mono text-sm">
                <FileCode className="w-4 h-4 text-content-muted shrink-0" />
                <span className="text-content-secondary">{finding.file_path}</span>
                {finding.line_number && (
                  <span className="text-foxnode-400">:{finding.line_number}</span>
                )}
              </div>
            </div>
          )}

          {/* Mitigation */}
          {finding.mitigation && (
            <div className="card">
              <h3 className="text-sm font-semibold text-content-tertiary uppercase mb-3">Recommended Mitigation</h3>
              <p className="text-sm text-content-secondary whitespace-pre-wrap leading-relaxed">{finding.mitigation}</p>
            </div>
          )}
        </div>

        {/* Sidebar */}
        <div className="space-y-6">
          {/* Status / Actions */}
          <div className="card space-y-4">
            <h3 className="text-sm font-semibold text-content-tertiary uppercase">Actions</h3>
            <div>
              <label className="block text-xs text-content-muted mb-1">Status</label>
              <select
                className="input w-full"
                value={finding.status}
                onChange={(e) => updateMutation.mutate({ status: e.target.value })}
              >
                <option value="active">Active</option>
                <option value="verified">Verified</option>
                <option value="mitigated">Mitigated</option>
                <option value="false_positive">False Positive</option>
                <option value="risk_accepted">Risk Accepted</option>
              </select>
            </div>
            <div>
              <label className="block text-xs text-content-muted mb-1">Severity</label>
              <select
                className="input w-full"
                value={finding.severity}
                onChange={(e) => updateMutation.mutate({ severity: e.target.value })}
              >
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
                <option value="info">Info</option>
              </select>
            </div>
          </div>

          {/* Details */}
          <div className="card space-y-3">
            <h3 className="text-sm font-semibold text-content-tertiary uppercase">Details</h3>
            {finding.cvss_score != null && (
              <DetailRow label="CVSS Score" value={String(finding.cvss_score)} />
            )}
            {finding.cwe && <DetailRow label="CWE" value={`CWE-${finding.cwe}`} />}
            {finding.component && (
              <DetailRow
                label="Component"
                value={`${finding.component}${finding.component_version ? `@${finding.component_version}` : ''}`}
              />
            )}
            {finding.tool_type && <DetailRow label="Tool Type" value={finding.tool_type} />}
            <DetailRow label="Duplicate" value={finding.is_duplicate ? 'Yes' : 'No'} />
            <DetailRow label="Product ID" value={String(finding.product_id)} />
          </div>

          {/* Jira Integration */}
          <div className="card space-y-3">
            <h3 className="text-sm font-semibold text-content-tertiary uppercase flex items-center gap-2">
              <Link2 className="w-4 h-4" /> Jira
            </h3>
            <div>
              <label className="block text-xs text-content-muted mb-1">Project Key</label>
              <input
                className="input w-full"
                value={jiraProjectKey}
                onChange={(e) => setJiraProjectKey(e.target.value)}
                placeholder="SEC"
              />
            </div>
            <button
              onClick={() => jiraMutation.mutate()}
              disabled={jiraMutation.isPending}
              className="btn-primary w-full flex items-center justify-center gap-2"
            >
              <ExternalLink className="w-4 h-4" />
              {jiraMutation.isPending ? 'Creating...' : 'Create Jira Issue'}
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

function DetailRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center justify-between py-1.5">
      <span className="text-xs text-content-muted">{label}</span>
      <span className="text-xs text-content-secondary font-mono">{value}</span>
    </div>
  )
}
