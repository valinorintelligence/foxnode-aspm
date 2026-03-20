import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { engagementsAPI, productsAPI } from '../services/api'
import { Plus, Calendar, Clock, CheckCircle, XCircle, Play } from 'lucide-react'
import toast from 'react-hot-toast'
import clsx from 'clsx'

const STATUS_CONFIG: Record<string, { icon: any; color: string; bg: string }> = {
  not_started: { icon: Clock, color: 'text-content-tertiary', bg: 'bg-gray-500/10' },
  in_progress: { icon: Play, color: 'text-blue-400', bg: 'bg-blue-500/10' },
  completed: { icon: CheckCircle, color: 'text-green-400', bg: 'bg-green-500/10' },
  cancelled: { icon: XCircle, color: 'text-red-400', bg: 'bg-red-500/10' },
}

export default function EngagementsPage() {
  const [showCreate, setShowCreate] = useState(false)
  const queryClient = useQueryClient()

  const { data: engagements, isLoading } = useQuery({
    queryKey: ['engagements'],
    queryFn: () => engagementsAPI.list().then((r) => r.data),
  })

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-content-primary">Engagements</h1>
          <p className="text-content-muted mt-1">Manage security testing engagements and assessments</p>
        </div>
        <button onClick={() => setShowCreate(true)} className="btn-primary flex items-center gap-2">
          <Plus className="w-4 h-4" />
          New Engagement
        </button>
      </div>

      {isLoading ? (
        <div className="text-content-muted text-center py-12">Loading engagements...</div>
      ) : engagements?.length === 0 ? (
        <div className="card text-center py-16">
          <Calendar className="w-12 h-12 mx-auto mb-3 text-content-muted" />
          <h3 className="text-lg font-medium text-content-secondary mb-1">No Engagements Yet</h3>
          <p className="text-content-muted mb-4">Create your first security testing engagement</p>
          <button onClick={() => setShowCreate(true)} className="btn-primary">
            Create Engagement
          </button>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {(Array.isArray(engagements) ? engagements : []).map((eng: any) => {
            const statusConfig = STATUS_CONFIG[eng.status] || STATUS_CONFIG.not_started
            const StatusIcon = statusConfig.icon
            return (
              <div key={eng.id} className="card-hover">
                <div className="flex items-start justify-between mb-3">
                  <div className="flex items-center gap-3">
                    <div className={clsx('w-10 h-10 rounded-lg flex items-center justify-center', statusConfig.bg)}>
                      <StatusIcon className={clsx('w-5 h-5', statusConfig.color)} />
                    </div>
                    <div>
                      <h3 className="font-semibold text-content-primary">{eng.name}</h3>
                      <p className="text-xs text-content-muted capitalize">{eng.engagement_type}</p>
                    </div>
                  </div>
                  <span className={clsx('text-xs font-medium capitalize px-2 py-1 rounded', statusConfig.bg, statusConfig.color)}>
                    {eng.status?.replace('_', ' ')}
                  </span>
                </div>

                {eng.description && (
                  <p className="text-sm text-content-tertiary mb-3 line-clamp-2">{eng.description}</p>
                )}

                <div className="flex items-center justify-between mt-4 pt-3 border-t border-border">
                  <span className="text-xs text-content-muted">
                    Product ID: {eng.product_id}
                  </span>
                  <span className="text-xs text-content-muted">
                    {eng.created_at ? new Date(eng.created_at).toLocaleDateString() : '—'}
                  </span>
                </div>
              </div>
            )
          })}
        </div>
      )}

      {showCreate && <CreateEngagementModal onClose={() => setShowCreate(false)} />}
    </div>
  )
}

function CreateEngagementModal({ onClose }: { onClose: () => void }) {
  const [form, setForm] = useState({
    name: '',
    description: '',
    engagement_type: 'CI/CD',
    product_id: '',
    target_start: '',
    target_end: '',
  })
  const queryClient = useQueryClient()

  const { data: products } = useQuery({
    queryKey: ['products'],
    queryFn: () => productsAPI.list().then((r) => r.data),
  })

  const mutation = useMutation({
    mutationFn: (data: any) => engagementsAPI.create(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['engagements'] })
      toast.success('Engagement created')
      onClose()
    },
    onError: (err: any) => toast.error(err.response?.data?.detail || 'Failed to create'),
  })

  return (
    <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50 p-4">
      <div className="card w-full max-w-lg">
        <h2 className="text-xl font-semibold text-content-primary mb-6">New Engagement</h2>
        <form
          onSubmit={(e) => {
            e.preventDefault()
            mutation.mutate({
              ...form,
              product_id: parseInt(form.product_id),
              target_start: form.target_start || undefined,
              target_end: form.target_end || undefined,
            })
          }}
          className="space-y-4"
        >
          <div>
            <label className="block text-sm font-medium text-content-tertiary mb-1">Name</label>
            <input className="input w-full" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} required />
          </div>
          <div>
            <label className="block text-sm font-medium text-content-tertiary mb-1">Description</label>
            <textarea className="input w-full" rows={3} value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-content-tertiary mb-1">Product</label>
              <select className="input w-full" value={form.product_id} onChange={(e) => setForm({ ...form, product_id: e.target.value })} required>
                <option value="">Select product...</option>
                {products?.map((p: any) => (
                  <option key={p.id} value={p.id}>{p.name}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-content-tertiary mb-1">Type</label>
              <select className="input w-full" value={form.engagement_type} onChange={(e) => setForm({ ...form, engagement_type: e.target.value })}>
                <option value="CI/CD">CI/CD</option>
                <option value="Penetration Test">Penetration Test</option>
                <option value="Bug Bounty">Bug Bounty</option>
                <option value="Security Audit">Security Audit</option>
                <option value="Compliance">Compliance</option>
              </select>
            </div>
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-content-tertiary mb-1">Start Date</label>
              <input type="date" className="input w-full" value={form.target_start} onChange={(e) => setForm({ ...form, target_start: e.target.value })} />
            </div>
            <div>
              <label className="block text-sm font-medium text-content-tertiary mb-1">End Date</label>
              <input type="date" className="input w-full" value={form.target_end} onChange={(e) => setForm({ ...form, target_end: e.target.value })} />
            </div>
          </div>
          <div className="flex gap-3 pt-2">
            <button type="submit" disabled={mutation.isPending} className="btn-primary flex-1">
              {mutation.isPending ? 'Creating...' : 'Create Engagement'}
            </button>
            <button type="button" onClick={onClose} className="btn-secondary">Cancel</button>
          </div>
        </form>
      </div>
    </div>
  )
}
