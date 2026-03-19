import { useState, useRef } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { scansAPI, productsAPI } from '../services/api'
import { Upload, FileUp, CheckCircle, XCircle, Clock, AlertTriangle } from 'lucide-react'
import toast from 'react-hot-toast'
import clsx from 'clsx'

export default function ScanImportPage() {
  const [selectedScanner, setSelectedScanner] = useState('')
  const [selectedProduct, setSelectedProduct] = useState('')
  const [file, setFile] = useState<File | null>(null)
  const [dragOver, setDragOver] = useState(false)
  const fileRef = useRef<HTMLInputElement>(null)
  const queryClient = useQueryClient()

  const { data: parsers } = useQuery({
    queryKey: ['parsers'],
    queryFn: () => scansAPI.parsers().then((r) => r.data),
  })

  const { data: products } = useQuery({
    queryKey: ['products'],
    queryFn: () => productsAPI.list().then((r) => r.data),
  })

  const { data: history } = useQuery({
    queryKey: ['scan-history'],
    queryFn: () => scansAPI.history().then((r) => r.data),
  })

  const importMutation = useMutation({
    mutationFn: (formData: FormData) => scansAPI.import(formData),
    onSuccess: (res) => {
      const data = res.data
      queryClient.invalidateQueries({ queryKey: ['scan-history'] })
      queryClient.invalidateQueries({ queryKey: ['findings'] })
      queryClient.invalidateQueries({ queryKey: ['dashboard'] })
      toast.success(
        `Imported ${data.findings_created} findings (${data.findings_duplicates} duplicates)`,
      )
      setFile(null)
      setSelectedScanner('')
    },
    onError: (err: any) => toast.error(err.response?.data?.detail || 'Import failed'),
  })

  const handleImport = () => {
    if (!file || !selectedScanner || !selectedProduct) {
      toast.error('Please select a scanner, product, and file')
      return
    }
    const formData = new FormData()
    formData.append('file', file)
    formData.append('scanner', selectedScanner)
    formData.append('product_id', selectedProduct)
    importMutation.mutate(formData)
  }

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault()
    setDragOver(false)
    const droppedFile = e.dataTransfer.files[0]
    if (droppedFile) setFile(droppedFile)
  }

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-white">Import Scans</h1>
        <p className="text-gray-500 mt-1">Upload security scan results from your tools</p>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
        {/* Import Form */}
        <div className="lg:col-span-2 space-y-4">
          <div className="card">
            <h3 className="text-lg font-semibold text-white mb-4">Upload Scan Report</h3>

            <div className="grid grid-cols-2 gap-4 mb-4">
              <div>
                <label className="block text-sm font-medium text-gray-400 mb-1">Scanner</label>
                <select
                  className="input w-full"
                  value={selectedScanner}
                  onChange={(e) => setSelectedScanner(e.target.value)}
                >
                  <option value="">Select scanner...</option>
                  {parsers?.map((p: any) => (
                    <option key={p.name} value={p.name}>
                      {p.name} ({p.scan_type})
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label className="block text-sm font-medium text-gray-400 mb-1">Product</label>
                <select
                  className="input w-full"
                  value={selectedProduct}
                  onChange={(e) => setSelectedProduct(e.target.value)}
                >
                  <option value="">Select product...</option>
                  {products?.map((p: any) => (
                    <option key={p.id} value={p.id}>
                      {p.name}
                    </option>
                  ))}
                </select>
              </div>
            </div>

            {/* Drop Zone */}
            <div
              className={clsx(
                'border-2 border-dashed rounded-xl p-8 text-center transition-all cursor-pointer',
                dragOver
                  ? 'border-foxnode-500 bg-foxnode-500/5'
                  : file
                  ? 'border-green-700 bg-green-500/5'
                  : 'border-gray-700 hover:border-gray-600',
              )}
              onClick={() => fileRef.current?.click()}
              onDragOver={(e) => {
                e.preventDefault()
                setDragOver(true)
              }}
              onDragLeave={() => setDragOver(false)}
              onDrop={handleDrop}
            >
              <input
                ref={fileRef}
                type="file"
                className="hidden"
                accept=".json,.csv,.xml,.jsonl,.sarif"
                onChange={(e) => setFile(e.target.files?.[0] || null)}
              />
              {file ? (
                <div className="flex items-center justify-center gap-3">
                  <FileUp className="w-8 h-8 text-green-400" />
                  <div>
                    <p className="text-green-400 font-medium">{file.name}</p>
                    <p className="text-xs text-gray-500 mt-1">
                      {(file.size / 1024).toFixed(1)} KB
                    </p>
                  </div>
                </div>
              ) : (
                <>
                  <Upload className="w-10 h-10 text-gray-600 mx-auto mb-3" />
                  <p className="text-gray-400">Drop your scan report here or click to browse</p>
                  <p className="text-xs text-gray-600 mt-2">
                    Supports JSON, CSV, XML, JSONL, SARIF formats
                  </p>
                </>
              )}
            </div>

            <button
              onClick={handleImport}
              disabled={!file || !selectedScanner || !selectedProduct || importMutation.isPending}
              className="btn-primary w-full mt-4 py-2.5 disabled:opacity-40"
            >
              {importMutation.isPending ? 'Importing...' : 'Import Scan Results'}
            </button>
          </div>
        </div>

        {/* Supported Parsers */}
        <div className="card h-fit">
          <h3 className="text-lg font-semibold text-white mb-4">Supported Scanners</h3>
          <div className="space-y-2">
            {parsers?.map((p: any) => (
              <div
                key={p.name}
                className="flex items-center justify-between p-2.5 bg-gray-800/50 rounded-lg"
              >
                <span className="text-sm text-gray-300">{p.name}</span>
                <span className="text-xs text-gray-500 font-mono">{p.scan_type}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {/* Import History */}
      {history?.length > 0 && (
        <div className="card">
          <h3 className="text-lg font-semibold text-white mb-4">Import History</h3>
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-gray-800">
                  <th className="text-left py-3 px-4 text-xs font-medium text-gray-500 uppercase">Status</th>
                  <th className="text-left py-3 px-4 text-xs font-medium text-gray-500 uppercase">File</th>
                  <th className="text-left py-3 px-4 text-xs font-medium text-gray-500 uppercase">Scanner</th>
                  <th className="text-left py-3 px-4 text-xs font-medium text-gray-500 uppercase">Created</th>
                  <th className="text-left py-3 px-4 text-xs font-medium text-gray-500 uppercase">Duplicates</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-gray-800/50">
                {history.map((scan: any) => (
                  <tr key={scan.id} className="hover:bg-gray-800/30">
                    <td className="py-3 px-4">
                      {scan.status === 'completed' ? (
                        <div className="flex items-center gap-1.5 text-green-400">
                          <CheckCircle className="w-4 h-4" />
                          <span className="text-xs">{scan.findings_created} findings</span>
                        </div>
                      ) : scan.status === 'failed' ? (
                        <div className="flex items-center gap-1.5 text-red-400">
                          <XCircle className="w-4 h-4" />
                          <span className="text-xs">Failed</span>
                        </div>
                      ) : (
                        <div className="flex items-center gap-1.5 text-yellow-400">
                          <Clock className="w-4 h-4" />
                          <span className="text-xs">Processing</span>
                        </div>
                      )}
                    </td>
                    <td className="py-3 px-4 text-sm text-gray-300 font-mono">{scan.filename}</td>
                    <td className="py-3 px-4 text-sm text-gray-400">{scan.scanner}</td>
                    <td className="py-3 px-4 text-xs text-gray-500">
                      {new Date(scan.created_at).toLocaleString()}
                    </td>
                    <td className="py-3 px-4 text-xs text-gray-500">{scan.findings_duplicates}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}
    </div>
  )
}
