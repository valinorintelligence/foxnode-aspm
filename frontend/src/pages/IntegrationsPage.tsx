import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { integrationsAPI } from '../services/api'
import { Plus, Plug, Trash2, CheckCircle, Zap, Cloud, Shield, Search as SearchIcon, Bug, Key, Server, Bell } from 'lucide-react'
import toast from 'react-hot-toast'
import clsx from 'clsx'

const TYPE_ICONS: Record<string, any> = {
  sast: Shield,
  dast: Bug,
  sca: SearchIcon,
  container: Server,
  cloud: Cloud,
  infrastructure: Server,
  secret_detection: Key,
  iac: Shield,
  issue_tracker: Plug,
  notification: Bell,
}

const TYPE_COLORS: Record<string, string> = {
  sast: 'text-purple-400 bg-purple-500/10',
  dast: 'text-red-400 bg-red-500/10',
  sca: 'text-blue-400 bg-blue-500/10',
  container: 'text-cyan-400 bg-cyan-500/10',
  cloud: 'text-sky-400 bg-sky-500/10',
  infrastructure: 'text-orange-400 bg-orange-500/10',
  secret_detection: 'text-yellow-400 bg-yellow-500/10',
  iac: 'text-green-400 bg-green-500/10',
  issue_tracker: 'text-indigo-400 bg-indigo-500/10',
  notification: 'text-pink-400 bg-pink-500/10',
}

export default function IntegrationsPage() {
  const [showAdd, setShowAdd] = useState(false)
  const queryClient = useQueryClient()

  const { data: tools } = useQuery({
    queryKey: ['supported-tools'],
    queryFn: () => integrationsAPI.supportedTools().then((r) => r.data),
  })

  const { data: active } = useQuery({
    queryKey: ['integrations'],
    queryFn: () => integrationsAPI.list().then((r) => r.data),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: number) => integrationsAPI.delete(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['integrations'] })
      toast.success('Integration removed')
    },
  })

  const createMutation = useMutation({
    mutationFn: (data: any) => integrationsAPI.create(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['integrations'] })
      toast.success('Integration added')
    },
  })

  const activeToolNames = new Set(active?.map((a: any) => a.tool_name) || [])

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">Integrations</h1>
        <p className="text-gray-500 mt-1">Connect your security tools and services</p>
      </div>

      {/* Active Integrations */}
      {active?.length > 0 && (
        <div>
          <h2 className="text-lg font-semibold text-white mb-3">Active Integrations</h2>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {active.map((integration: any) => {
              const Icon = TYPE_ICONS[integration.integration_type] || Plug
              const colors = TYPE_COLORS[integration.integration_type] || 'text-gray-400 bg-gray-500/10'
              return (
                <div key={integration.id} className="card-hover group">
                  <div className="flex items-start justify-between">
                    <div className="flex items-center gap-3">
                      <div className={clsx('w-10 h-10 rounded-lg flex items-center justify-center', colors)}>
                        <Icon className="w-5 h-5" />
                      </div>
                      <div>
                        <h3 className="font-medium text-white">{integration.name}</h3>
                        <div className="flex items-center gap-2 mt-0.5">
                          <CheckCircle className="w-3.5 h-3.5 text-green-400" />
                          <span className="text-xs text-green-400">Connected</span>
                        </div>
                      </div>
                    </div>
                    <button
                      onClick={() => deleteMutation.mutate(integration.id)}
                      className="opacity-0 group-hover:opacity-100 p-1.5 text-gray-500 hover:text-red-400 transition-all"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      )}

      {/* Available Tools */}
      <div>
        <h2 className="text-lg font-semibold text-white mb-3">Available Tools</h2>
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 gap-3">
          {tools?.map((tool: any) => {
            const Icon = TYPE_ICONS[tool.type] || Plug
            const colors = TYPE_COLORS[tool.type] || 'text-gray-400 bg-gray-500/10'
            const isActive = activeToolNames.has(tool.name)

            return (
              <div
                key={tool.name}
                className={clsx(
                  'card-hover flex items-center gap-3 p-4',
                  isActive && 'border-green-800/50',
                )}
              >
                <div className={clsx('w-9 h-9 rounded-lg flex items-center justify-center shrink-0', colors)}>
                  <Icon className="w-4.5 h-4.5" />
                </div>
                <div className="flex-1 min-w-0">
                  <h3 className="text-sm font-medium text-white truncate">{tool.name}</h3>
                  <p className="text-xs text-gray-500 truncate">{tool.description}</p>
                </div>
                {isActive ? (
                  <CheckCircle className="w-4 h-4 text-green-400 shrink-0" />
                ) : (
                  <button
                    onClick={() =>
                      createMutation.mutate({
                        name: tool.name,
                        tool_name: tool.name,
                        integration_type: tool.type,
                        description: tool.description,
                      })
                    }
                    className="text-xs text-foxnode-400 hover:text-foxnode-300 font-medium shrink-0"
                  >
                    Connect
                  </button>
                )}
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}
