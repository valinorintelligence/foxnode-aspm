import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { complianceAPI } from '../services/api'
import {
  ClipboardCheck,
  Shield,
  AlertTriangle,
  CheckCircle,
  XCircle,
  ChevronRight,
  BarChart3,
} from 'lucide-react'
import clsx from 'clsx'

const FRAMEWORK_ICONS: Record<string, string> = {
  owasp_top_10: '🛡️',
  cis_benchmarks: '📋',
  pci_dss: '💳',
  soc2: '🔐',
  iso_27001: '🌐',
}

export default function CompliancePage() {
  const [selectedFramework, setSelectedFramework] = useState<string | null>(null)

  const { data: overview, isLoading } = useQuery({
    queryKey: ['compliance-overview'],
    queryFn: () => complianceAPI.overview().then((r) => r.data),
  })

  const { data: frameworks } = useQuery({
    queryKey: ['compliance-frameworks'],
    queryFn: () => complianceAPI.frameworks().then((r) => r.data),
  })

  const { data: report } = useQuery({
    queryKey: ['compliance-report', selectedFramework],
    queryFn: () => complianceAPI.report(selectedFramework!).then((r) => r.data),
    enabled: !!selectedFramework,
  })

  const { data: gaps } = useQuery({
    queryKey: ['compliance-gaps', selectedFramework],
    queryFn: () => complianceAPI.gaps(selectedFramework!).then((r) => r.data),
    enabled: !!selectedFramework,
  })

  if (isLoading) {
    return <div className="flex items-center justify-center h-64 text-gray-500">Loading compliance data...</div>
  }

  return (
    <div className="space-y-6">
      {/* Header */}
      <div>
        <div className="flex items-center gap-3 mb-1">
          <div className="w-10 h-10 bg-emerald-500/10 rounded-xl flex items-center justify-center">
            <ClipboardCheck className="w-5 h-5 text-emerald-400" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-white">Compliance Mapping</h1>
            <p className="text-gray-500 text-sm">Map findings to OWASP, PCI-DSS, SOC 2, CIS, and ISO 27001</p>
          </div>
        </div>
      </div>

      {/* Framework Overview Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-5 gap-4">
        {overview?.frameworks?.map((fw: any) => {
          const isSelected = selectedFramework === fw.framework_id
          const pct = fw.compliance_percentage || 0
          const color = pct >= 80 ? '#10b981' : pct >= 60 ? '#f59e0b' : '#ef4444'
          return (
            <button
              key={fw.framework_id}
              onClick={() => setSelectedFramework(fw.framework_id)}
              className={clsx(
                'card-hover text-left transition-all',
                isSelected && 'ring-2 ring-foxnode-500 border-foxnode-500/50',
              )}
            >
              <div className="flex items-center justify-between mb-3">
                <span className="text-2xl">{FRAMEWORK_ICONS[fw.framework_id] || '📑'}</span>
                <ChevronRight className={clsx('w-4 h-4 transition-transform', isSelected ? 'text-foxnode-400 rotate-90' : 'text-gray-600')} />
              </div>
              <h3 className="text-sm font-semibold text-white mb-1">{fw.framework_name}</h3>

              {/* Circular Progress */}
              <div className="flex items-center gap-3 mt-3">
                <svg width="48" height="48" viewBox="0 0 48 48">
                  <circle cx="24" cy="24" r="20" fill="none" stroke="#1f2937" strokeWidth="4" />
                  <circle
                    cx="24" cy="24" r="20" fill="none" stroke={color} strokeWidth="4"
                    strokeDasharray={`${pct * 1.256} 125.6`}
                    strokeLinecap="round"
                    transform="rotate(-90 24 24)"
                  />
                  <text x="24" y="28" textAnchor="middle" fill="white" fontSize="12" fontWeight="700">{pct}%</text>
                </svg>
                <div>
                  <p className="text-xs text-gray-500">{fw.passing_controls}/{fw.total_controls} controls</p>
                  <p className="text-xs" style={{ color }}>{fw.failing_controls} failing</p>
                </div>
              </div>
            </button>
          )
        })}
      </div>

      {/* Detailed Report */}
      {selectedFramework && report && (
        <div className="space-y-6">
          {/* Framework Detail Header */}
          <div className="card">
            <div className="flex items-center justify-between mb-4">
              <div>
                <h3 className="text-lg font-semibold text-white">{report.framework_name}</h3>
                <p className="text-sm text-gray-500">{report.description}</p>
              </div>
              <div className="text-right">
                <p className="text-3xl font-bold text-white">{report.compliance_percentage}%</p>
                <p className="text-xs text-gray-500">compliance rate</p>
              </div>
            </div>

            {/* Progress Bar */}
            <div className="w-full h-3 bg-gray-800 rounded-full overflow-hidden">
              <div className="h-full flex">
                <div className="bg-green-500 h-full" style={{ width: `${(report.passing_controls / report.total_controls) * 100}%` }} />
                <div className="bg-red-500 h-full" style={{ width: `${(report.failing_controls / report.total_controls) * 100}%` }} />
                <div className="bg-gray-600 h-full" style={{ width: `${((report.total_controls - report.passing_controls - report.failing_controls) / report.total_controls) * 100}%` }} />
              </div>
            </div>
            <div className="flex gap-6 mt-3">
              <span className="flex items-center gap-1.5 text-xs text-green-400">
                <CheckCircle className="w-3.5 h-3.5" /> {report.passing_controls} Passing
              </span>
              <span className="flex items-center gap-1.5 text-xs text-red-400">
                <XCircle className="w-3.5 h-3.5" /> {report.failing_controls} Failing
              </span>
              <span className="flex items-center gap-1.5 text-xs text-gray-500">
                <AlertTriangle className="w-3.5 h-3.5" /> {report.total_controls - report.passing_controls - report.failing_controls} No Coverage
              </span>
            </div>
          </div>

          {/* Controls List */}
          {report.controls && (
            <div className="card p-0 overflow-hidden">
              <div className="p-6 border-b border-gray-800">
                <h3 className="text-lg font-semibold text-white">Controls</h3>
              </div>
              <div className="divide-y divide-gray-800/50">
                {report.controls.map((control: any) => (
                  <div key={control.id} className="flex items-center justify-between p-4 hover:bg-gray-800/30 transition-colors">
                    <div className="flex items-center gap-3 flex-1">
                      {control.status === 'passing' ? (
                        <CheckCircle className="w-5 h-5 text-green-400 shrink-0" />
                      ) : control.status === 'failing' ? (
                        <XCircle className="w-5 h-5 text-red-400 shrink-0" />
                      ) : (
                        <AlertTriangle className="w-5 h-5 text-gray-500 shrink-0" />
                      )}
                      <div>
                        <p className="text-sm text-gray-200">
                          <span className="text-foxnode-400 font-mono mr-2">{control.id}</span>
                          {control.name}
                        </p>
                        {control.description && (
                          <p className="text-xs text-gray-500 mt-0.5 max-w-2xl">{control.description}</p>
                        )}
                      </div>
                    </div>
                    <div className="text-right shrink-0 ml-4">
                      {control.finding_count > 0 && (
                        <span className="text-xs text-red-400 font-mono">{control.finding_count} findings</span>
                      )}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Gap Analysis */}
          {gaps?.gaps?.length > 0 && (
            <div className="card">
              <div className="flex items-center gap-2 mb-4">
                <BarChart3 className="w-5 h-5 text-amber-400" />
                <h3 className="text-lg font-semibold text-white">Gap Analysis</h3>
              </div>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {gaps.gaps.map((gap: any, i: number) => (
                  <div key={i} className="p-4 bg-amber-500/5 border border-amber-800/30 rounded-lg">
                    <div className="flex items-start gap-3">
                      <AlertTriangle className="w-4 h-4 text-amber-400 mt-0.5 shrink-0" />
                      <div>
                        <p className="text-sm text-amber-200 font-medium">{gap.control_id}: {gap.control_name}</p>
                        <p className="text-xs text-gray-500 mt-1">{gap.recommendation}</p>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Empty State */}
      {!selectedFramework && (
        <div className="card text-center py-12">
          <Shield className="w-12 h-12 mx-auto mb-3 text-emerald-500/30" />
          <h3 className="text-lg font-medium text-gray-300 mb-1">Select a Framework</h3>
          <p className="text-gray-500">Click on a compliance framework above to see the detailed report and gap analysis</p>
        </div>
      )}
    </div>
  )
}
