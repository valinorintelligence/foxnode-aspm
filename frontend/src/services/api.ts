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

// Security Metrics & KPIs
export const metricsAPI = {
  kpi: () => api.get('/metrics/kpi'),
  mttr: () => api.get('/metrics/mttr'),
  aging: () => api.get('/metrics/aging'),
  burndown: () => api.get('/metrics/burndown'),
  velocity: () => api.get('/metrics/velocity'),
  scannerEffectiveness: () => api.get('/metrics/scanner-effectiveness'),
  trends: (days?: number) => api.get('/metrics/trends', { params: days ? { days } : {} }),
  executiveSummary: () => api.get('/metrics/executive-summary'),
}

// Attack Path Analysis
export const attackPathAPI = {
  product: (productId: number) => api.get(`/attack-paths/product/${productId}`),
  surface: (productId: number) => api.get(`/attack-paths/surface/${productId}`),
  graph: (productId: number) => api.get(`/attack-paths/graph/${productId}`),
  overview: () => api.get('/attack-paths/overview'),
}

// API Security
export const apiSecurityAPI = {
  posture: (productId: number) => api.get(`/api-security/posture/${productId}`),
  endpoints: (productId: number) => api.get(`/api-security/endpoints/${productId}`),
  risks: (productId: number) => api.get(`/api-security/risks/${productId}`),
  overview: () => api.get('/api-security/overview'),
  importSpec: (productId: number, data: any) => api.post(`/api-security/import-spec/${productId}`, data),
}

// AI Security Agent
export const securityAgentAPI = {
  analyze: (productId: number) => api.post(`/agent/analyze/${productId}`),
  chat: (message: string, productId?: number) => api.post('/agent/chat', { message, product_id: productId }),
  report: (productId: number) => api.get(`/agent/report/${productId}`),
  attackChains: (productId: number) => api.get(`/agent/attack-chains/${productId}`),
}

// SBOM & Supply Chain
export const sbomAPI = {
  product: (productId: number) => api.get(`/sbom/product/${productId}`),
  components: (productId: number) => api.get(`/sbom/components/${productId}`),
  vulnerabilities: (productId: number) => api.get(`/sbom/vulnerabilities/${productId}`),
  licenses: (productId: number) => api.get(`/sbom/licenses/${productId}`),
  supplyChainRisks: (productId: number) => api.get(`/sbom/supply-chain-risks/${productId}`),
  overview: () => api.get('/sbom/overview'),
  upload: (productId: number, formData: FormData) => api.post(`/sbom/upload/${productId}`, formData, {
    headers: { 'Content-Type': 'multipart/form-data' },
  }),
}

// AI Remediation Copilot
export const copilotAPI = {
  remediate: (findingId: number) => api.post(`/copilot/remediate/${findingId}`),
  bulkRemediate: (productId: number, severityFilter?: string) => api.post('/copilot/bulk-remediate', { product_id: productId, severity_filter: severityFilter }),
  developerSummary: (findingId: number) => api.get(`/copilot/developer-summary/${findingId}`),
  stats: () => api.get('/copilot/stats'),
}

// LLM Vulnerability Scanner
export const llmScannerAPI = {
  scan: (code: string, language: string) => api.post('/llm-scanner/scan', { code, language }),
  product: (productId: number) => api.get(`/llm-scanner/product/${productId}`),
  owaspLlm: (productId: number) => api.get(`/llm-scanner/owasp-llm/${productId}`),
  analyzeFindings: (productId: number) => api.post(`/llm-scanner/analyze-findings/${productId}`),
  overview: () => api.get('/llm-scanner/overview'),
}
