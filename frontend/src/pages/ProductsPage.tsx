import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { productsAPI } from '../services/api'
import { Plus, Search, Package, Trash2, ExternalLink } from 'lucide-react'
import toast from 'react-hot-toast'

export default function ProductsPage() {
  const [search, setSearch] = useState('')
  const [showCreate, setShowCreate] = useState(false)
  const queryClient = useQueryClient()

  const { data: products, isLoading } = useQuery({
    queryKey: ['products', search],
    queryFn: () => productsAPI.list({ search: search || undefined }).then((r) => r.data),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: number) => productsAPI.delete(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['products'] })
      toast.success('Product deleted')
    },
  })

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white">Products</h1>
          <p className="text-gray-500 mt-1">Manage your applications and services</p>
        </div>
        <button onClick={() => setShowCreate(true)} className="btn-primary flex items-center gap-2">
          <Plus className="w-4 h-4" />
          Add Product
        </button>
      </div>

      {/* Search */}
      <div className="relative max-w-md">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-gray-500" />
        <input
          type="text"
          placeholder="Search products..."
          className="input w-full pl-10"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
        />
      </div>

      {/* Products Grid */}
      {isLoading ? (
        <div className="text-gray-500 text-center py-12">Loading...</div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
          {products?.map((product: any) => (
            <div key={product.id} className="card-hover group">
              <div className="flex items-start justify-between mb-3">
                <div className="flex items-center gap-3">
                  <div className="w-10 h-10 bg-foxnode-600/10 rounded-lg flex items-center justify-center">
                    <Package className="w-5 h-5 text-foxnode-400" />
                  </div>
                  <div>
                    <h3 className="font-semibold text-white">{product.name}</h3>
                    <p className="text-xs text-gray-500 capitalize">{product.product_type.replace('_', ' ')}</p>
                  </div>
                </div>
                <button
                  onClick={() => deleteMutation.mutate(product.id)}
                  className="opacity-0 group-hover:opacity-100 p-1.5 text-gray-500 hover:text-red-400 transition-all"
                >
                  <Trash2 className="w-4 h-4" />
                </button>
              </div>

              {product.description && (
                <p className="text-sm text-gray-400 mb-3 line-clamp-2">{product.description}</p>
              )}

              {/* Finding counts */}
              <div className="flex gap-2 mt-3">
                {product.finding_counts?.critical > 0 && (
                  <span className="badge-critical">{product.finding_counts.critical}C</span>
                )}
                {product.finding_counts?.high > 0 && (
                  <span className="badge-high">{product.finding_counts.high}H</span>
                )}
                {product.finding_counts?.medium > 0 && (
                  <span className="badge-medium">{product.finding_counts.medium}M</span>
                )}
                {product.finding_counts?.low > 0 && (
                  <span className="badge-low">{product.finding_counts.low}L</span>
                )}
              </div>

              <div className="flex items-center justify-between mt-4 pt-3 border-t border-gray-800">
                <span className="text-xs text-gray-500">
                  {product.team || 'No team assigned'}
                </span>
                {product.repo_url && (
                  <ExternalLink className="w-3.5 h-3.5 text-gray-600" />
                )}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Create Modal */}
      {showCreate && <CreateProductModal onClose={() => setShowCreate(false)} />}
    </div>
  )
}

function CreateProductModal({ onClose }: { onClose: () => void }) {
  const [form, setForm] = useState({
    name: '',
    description: '',
    product_type: 'web_application',
    business_criticality: 'medium',
    team: '',
    repo_url: '',
  })
  const queryClient = useQueryClient()

  const mutation = useMutation({
    mutationFn: (data: any) => productsAPI.create(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['products'] })
      toast.success('Product created')
      onClose()
    },
    onError: (err: any) => toast.error(err.response?.data?.detail || 'Failed to create'),
  })

  return (
    <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50 p-4">
      <div className="card w-full max-w-lg">
        <h2 className="text-xl font-semibold text-white mb-6">Add Product</h2>
        <form
          onSubmit={(e) => {
            e.preventDefault()
            mutation.mutate(form)
          }}
          className="space-y-4"
        >
          <div>
            <label className="block text-sm font-medium text-gray-400 mb-1">Name</label>
            <input
              className="input w-full"
              value={form.name}
              onChange={(e) => setForm({ ...form, name: e.target.value })}
              required
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-400 mb-1">Description</label>
            <textarea
              className="input w-full"
              rows={3}
              value={form.description}
              onChange={(e) => setForm({ ...form, description: e.target.value })}
            />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-400 mb-1">Type</label>
              <select
                className="input w-full"
                value={form.product_type}
                onChange={(e) => setForm({ ...form, product_type: e.target.value })}
              >
                <option value="web_application">Web Application</option>
                <option value="api">API</option>
                <option value="mobile">Mobile</option>
                <option value="infrastructure">Infrastructure</option>
                <option value="cloud">Cloud</option>
                <option value="container">Container</option>
                <option value="source_code">Source Code</option>
              </select>
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-400 mb-1">Criticality</label>
              <select
                className="input w-full"
                value={form.business_criticality}
                onChange={(e) => setForm({ ...form, business_criticality: e.target.value })}
              >
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
            </div>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-400 mb-1">Team</label>
            <input
              className="input w-full"
              value={form.team}
              onChange={(e) => setForm({ ...form, team: e.target.value })}
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-400 mb-1">Repository URL</label>
            <input
              className="input w-full"
              value={form.repo_url}
              onChange={(e) => setForm({ ...form, repo_url: e.target.value })}
            />
          </div>
          <div className="flex gap-3 pt-2">
            <button type="submit" disabled={mutation.isPending} className="btn-primary flex-1">
              {mutation.isPending ? 'Creating...' : 'Create Product'}
            </button>
            <button type="button" onClick={onClose} className="btn-secondary">
              Cancel
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}
