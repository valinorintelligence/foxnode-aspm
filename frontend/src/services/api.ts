import axios from 'axios'

const api = axios.create({
  baseURL: '/api/v1',
  headers: { 'Content-Type': 'application/json' },
})

api.interceptors.request.use((config) => {
  const token = localStorage.getItem('foxnode_token')
  if (token) {
    config.headers.Authorization = `Bearer ${token}`
  }
  return config
})

api.interceptors.response.use(
  (response) => response,
  (error) => {
    if (error.response?.status === 401) {
      localStorage.removeItem('foxnode_token')
      window.location.href = '/login'
    }
    return Promise.reject(error)
  },
)

export default api

// Auth
export const authAPI = {
  login: (data: { username: string; password: string }) => api.post('/auth/login', data),
  register: (data: any) => api.post('/auth/register', data),
  me: () => api.get('/auth/me'),
}

// Dashboard
export const dashboardAPI = {
  stats: () => api.get('/dashboard/stats'),
}

// Products
export const productsAPI = {
  list: (params?: any) => api.get('/products', { params }),
  get: (id: number) => api.get(`/products/${id}`),
  create: (data: any) => api.post('/products', data),
  delete: (id: number) => api.delete(`/products/${id}`),
}

// Findings
export const findingsAPI = {
  list: (params?: any) => api.get('/findings', { params }),
  get: (id: number) => api.get(`/findings/${id}`),
  create: (data: any) => api.post('/findings', data),
  update: (id: number, data: any) => api.patch(`/findings/${id}`, data),
  summary: (params?: any) => api.get('/findings/stats/summary', { params }),
}

// Engagements
export const engagementsAPI = {
  list: (params?: any) => api.get('/engagements', { params }),
  create: (data: any) => api.post('/engagements', data),
}

// Integrations
export const integrationsAPI = {
  list: () => api.get('/integrations'),
  supportedTools: () => api.get('/integrations/supported-tools'),
  create: (data: any) => api.post('/integrations', data),
  delete: (id: number) => api.delete(`/integrations/${id}`),
}

// Scans
export const scansAPI = {
  parsers: () => api.get('/scans/parsers'),
  import: (formData: FormData) => api.post('/scans/import', formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
  }),
  history: (params?: any) => api.get('/scans/history', { params }),
}

// Users
export const usersAPI = {
  list: () => api.get('/users'),
  get: (id: number) => api.get(`/users/${id}`),
  update: (id: number, data: any) => api.patch(`/users/${id}`, data),
  delete: (id: number) => api.delete(`/users/${id}`),
}

// Jira
export const jiraAPI = {
  status: () => api.get('/jira/status'),
  createIssue: (findingId: number, data?: any) => api.post(`/jira/create-issue/${findingId}`, data || {}),
  syncStatus: (findingId: number, jiraKey: string) => api.post(`/jira/sync/${findingId}`, { jira_key: jiraKey }),
}

// Notifications
export const notificationsAPI = {
  getSettings: () => api.get('/notifications/settings'),
  configure: (data: any) => api.post('/notifications/configure', data),
  testSlack: (webhookUrl?: string) => api.post('/notifications/test-slack', { webhook_url: webhookUrl }),
}

// AI Triage
export const triageAPI = {
  analyze: (findingId: number) => api.post(`/triage/analyze/${findingId}`),
  bulkAnalyze: (productId: number) => api.post('/triage/bulk-analyze', { product_id: productId }),
  summary: (productId: number) => api.get(`/triage/summary/${productId}`),
}

// Security Scorecard
export const scorecardAPI = {
  product: (productId: number) => api.get(`/scorecard/product/${productId}`),
  overview: () => api.get('/scorecard/overview'),
  trends: () => api.get('/scorecard/trends'),
}

// Compliance
export const complianceAPI = {
  frameworks: () => api.get('/compliance/frameworks'),
  report: (frameworkId: string, productId?: number) =>
    api.get(`/compliance/report/${frameworkId}`, { params: productId ? { product_id: productId } : {} }),
  overview: () => api.get('/compliance/overview'),
  gaps: (frameworkId: string) => api.get(`/compliance/gaps/${frameworkId}`),
}

// SLA & Risk Heatmap
export const slaAPI = {
  status: () => api.get('/sla/status'),
  product: (productId: number) => api.get(`/sla/product/${productId}`),
  breaches: () => api.get('/sla/breaches'),
  heatmap: () => api.get('/sla/heatmap'),
  config: () => api.get('/sla/config'),
  updateConfig: (data: any) => api.post('/sla/config', data),
}
