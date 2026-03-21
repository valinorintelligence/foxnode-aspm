import type { AxiosInstance } from 'axios'
import MockAdapter from 'axios-mock-adapter'
import * as mock from './mockData'

let mockInstance: MockAdapter | null = null

export function activateDemoMode(apiInstance: AxiosInstance) {
  if (mockInstance) return // already active

  mockInstance = new MockAdapter(apiInstance, { delayResponse: 200, onNoMatch: 'passthrough' })

  // Auth
  mockInstance.onGet('/auth/me').reply(200, mock.authMe)
  mockInstance.onPost('/auth/login').reply(200, { access_token: 'demo-token', token_type: 'bearer' })

  // Dashboard
  mockInstance.onGet('/dashboard/stats').reply(200, mock.dashboardStats)

  // Products
  mockInstance.onGet('/products').reply(200, mock.products)
  mockInstance.onGet(/\/products\/\d+/).reply(200, mock.products?.[0] || {})
  mockInstance.onPost('/products').reply(201, { id: 99, name: 'Demo Product', description: 'Demo', product_type: 'web_application', business_criticality: 'medium', created_at: new Date().toISOString(), finding_counts: {} })

  // Findings
  mockInstance.onGet('/findings').reply(200, mock.findings)
  mockInstance.onGet(/\/findings\/\d+/).reply(200, mock.findingDetail)
  mockInstance.onGet('/findings/stats/summary').reply(200, mock.findingsSummary || { total: 164, by_severity: { critical: 12, high: 88, medium: 46, low: 17, info: 1 } })
  mockInstance.onPatch(/\/findings\/\d+/).reply(200, mock.findingDetail)

  // Engagements
  mockInstance.onGet('/engagements').reply(200, mock.engagements)
  mockInstance.onPost('/engagements').reply(201, { id: 99, name: 'Demo Engagement', status: 'in_progress', created_at: new Date().toISOString() })

  // Integrations
  mockInstance.onGet('/integrations').reply(200, mock.integrations || [])
  mockInstance.onGet('/integrations/supported-tools').reply(200, mock.supportedTools)
  mockInstance.onPost('/integrations').reply(201, { id: 99, tool: 'demo-tool', status: 'connected' })
  mockInstance.onDelete(/\/integrations\/\d+/).reply(204)

  // Scans
  mockInstance.onGet('/scans/parsers').reply(200, mock.scanParsers)
  mockInstance.onGet('/scans/history').reply(200, mock.scanHistory)
  mockInstance.onPost('/scans/import').reply(200, { message: 'Demo: Scan imported successfully', findings_count: 23 })

  // Users
  mockInstance.onGet('/users').reply(200, mock.users || [mock.authMe])
  mockInstance.onGet(/\/users\/\d+/).reply(200, mock.authMe)
  mockInstance.onPatch(/\/users\/\d+/).reply(200, mock.authMe)

  // Scorecard
  mockInstance.onGet('/scorecard/overview').reply(200, mock.scorecardOverview)
  mockInstance.onGet('/scorecard/trends').reply(200, mock.scorecardTrends)
  mockInstance.onGet(/\/scorecard\/product\/\d+/).reply(200, mock.scorecardProduct)

  // AI Triage
  mockInstance.onPost(/\/triage\/analyze\/\d+/).reply(200, {
    finding_id: 1, priority: 'high', confidence: 0.92,
    reasoning: 'This finding represents a genuine security risk based on the code pattern analysis.',
    false_positive_probability: 0.08, recommended_action: 'Fix in next sprint'
  })
  mockInstance.onPost('/triage/bulk-analyze').reply(200, { analyzed: 15, results: [] })
  mockInstance.onGet(/\/triage\/summary\/\d+/).reply(200, mock.triageSummary)

  // Compliance
  mockInstance.onGet('/compliance/frameworks').reply(200, mock.complianceFrameworks)
  mockInstance.onGet('/compliance/overview').reply(200, mock.complianceOverview)
  mockInstance.onGet(/\/compliance\/report\//).reply(200, {
    framework_id: 'owasp-top10-2021', framework_name: 'OWASP Top 10',
    compliance_percentage: 20.0, controls: (mock.complianceFrameworks as any)?.[0] ? [] : [],
    total_controls: 10, passing_controls: 2, failing_controls: 8
  })
  mockInstance.onGet(/\/compliance\/gaps\//).reply(200, {
    framework_id: 'owasp-top10-2021', gaps: [
      { control: 'A01:2021 - Broken Access Control', severity: 'critical', finding_count: 15, description: 'Multiple access control issues detected' },
      { control: 'A03:2021 - Injection', severity: 'critical', finding_count: 12, description: 'SQL and command injection vulnerabilities found' },
      { control: 'A07:2021 - Identification and Authentication Failures', severity: 'high', finding_count: 8, description: 'Authentication weaknesses detected' },
    ]
  })

  // SLA
  mockInstance.onGet('/sla/status').reply(200, mock.slaStatus)
  mockInstance.onGet('/sla/breaches').reply(200, mock.slaBreaches || [])
  mockInstance.onGet('/sla/heatmap').reply(200, mock.slaHeatmap)
  mockInstance.onGet('/sla/config').reply(200, mock.slaConfig)
  mockInstance.onPost('/sla/config').reply(200, mock.slaConfig)
  mockInstance.onGet(/\/sla\/product\/\d+/).reply(200, mock.slaProduct)

  // Metrics
  mockInstance.onGet('/metrics/kpi').reply(200, mock.metricsKpi)
  mockInstance.onGet('/metrics/mttr').reply(200, mock.metricsMttr)
  mockInstance.onGet('/metrics/aging').reply(200, mock.metricsAging)
  mockInstance.onGet('/metrics/burndown').reply(200, mock.metricsBurndown)
  mockInstance.onGet('/metrics/velocity').reply(200, mock.metricsVelocity)
  mockInstance.onGet('/metrics/scanner-effectiveness').reply(200, mock.metricsScannerEffectiveness)
  mockInstance.onGet('/metrics/trends').reply(200, mock.metricsTrends)
  mockInstance.onGet('/metrics/executive-summary').reply(200, mock.metricsExecutiveSummary)

  // Attack Paths
  mockInstance.onGet('/attack-paths/overview').reply(200, mock.attackPathsOverview)
  mockInstance.onGet(/\/attack-paths\/product\/\d+/).reply(200, mock.attackPathsProduct)
  mockInstance.onGet(/\/attack-paths\/surface\/\d+/).reply(200, mock.attackPathsSurface)
  mockInstance.onGet(/\/attack-paths\/graph\/\d+/).reply(200, mock.attackPathsGraph)

  // AI Security Agent
  mockInstance.onPost(/\/agent\/analyze\/\d+/).reply(200, {
    status: 'completed', product_id: 1,
    summary: 'Analysis complete. Found 3 critical attack chains and 5 high-risk vulnerabilities.',
    risk_score: 78.5
  })
  mockInstance.onPost('/agent/chat').reply(200, {
    response: 'Based on the security analysis of your application, the most critical findings are related to SQL injection (CWE-89) and broken authentication (CWE-287). I recommend prioritizing the 7 critical findings first, starting with the command injection vulnerability in the payment processing module.',
    metrics: { findings_analyzed: 164, critical_count: 12, risk_score: 78.5 }
  })
  mockInstance.onGet(/\/agent\/report\/\d+/).reply(200, mock.agentReport)
  mockInstance.onGet(/\/agent\/attack-chains\/\d+/).reply(200, mock.agentAttackChains || [])

  // SBOM
  mockInstance.onGet('/sbom/overview').reply(200, mock.sbomOverview)
  mockInstance.onGet(/\/sbom\/product\/\d+/).reply(200, mock.sbomProduct)
  mockInstance.onGet(/\/sbom\/components\/\d+/).reply(200, mock.sbomComponents)
  mockInstance.onGet(/\/sbom\/vulnerabilities\/\d+/).reply(200, mock.sbomVulnerabilities)
  mockInstance.onGet(/\/sbom\/licenses\/\d+/).reply(200, mock.sbomLicenses)
  mockInstance.onGet(/\/sbom\/supply-chain-risks\/\d+/).reply(200, mock.sbomSupplyChainRisks)

  // AI Copilot
  mockInstance.onPost(/\/copilot\/remediate\/\d+/).reply(200, {
    finding_id: 1, remediation: {
      description: 'Replace subprocess call with safer alternative using shlex.quote()',
      code_before: 'subprocess.call(f"process {user_input}")',
      code_after: 'subprocess.call(["process", shlex.quote(user_input)])',
      language: 'python', confidence: 0.95
    }
  })
  mockInstance.onPost('/copilot/bulk-remediate').reply(200, { remediated: 5, results: [] })
  mockInstance.onGet(/\/copilot\/developer-summary\/\d+/).reply(200, {
    finding_id: 1, title: 'Command Injection in subprocess call',
    severity: 'high', summary: 'User-controlled input passed to subprocess without sanitization.',
    fix_suggestion: 'Use shlex.quote() or parameterized command execution.',
    code_example: 'subprocess.call(["cmd", shlex.quote(user_input)])',
    references: ['https://owasp.org/www-community/attacks/Command_Injection']
  })
  mockInstance.onGet('/copilot/stats').reply(200, mock.copilotStats)

  // LLM Scanner
  mockInstance.onPost('/llm-scanner/scan').reply(200, {
    vulnerabilities: [
      { title: 'Prompt Injection Risk', severity: 'high', category: 'LLM01', description: 'User input directly concatenated into LLM prompt', line: 42 },
      { title: 'Sensitive Data Exposure', severity: 'medium', category: 'LLM06', description: 'PII may leak through model responses', line: 78 },
    ]
  })
  mockInstance.onGet('/llm-scanner/overview').reply(200, mock.llmScannerOverview)
  mockInstance.onGet(/\/llm-scanner\/product\/\d+/).reply(200, mock.llmScannerProduct)
  mockInstance.onGet(/\/llm-scanner\/owasp-llm\/\d+/).reply(200, mock.llmScannerOwaspLlm)
  mockInstance.onPost(/\/llm-scanner\/analyze-findings\/\d+/).reply(200, { analyzed: 10, llm_risks: 3 })

  // Jira
  mockInstance.onGet('/jira/status').reply(200, mock.jiraStatus || { connected: false })
  mockInstance.onPost(/\/jira\/create-issue\/\d+/).reply(200, { jira_key: 'FOX-123', url: 'https://jira.example.com/FOX-123' })

  // Notifications
  mockInstance.onGet('/notifications/settings').reply(200, mock.notificationSettings || { slack_enabled: false, email_enabled: false })
  mockInstance.onPost('/notifications/configure').reply(200, { status: 'configured' })
  mockInstance.onPost('/notifications/test-slack').reply(200, { status: 'sent' })

  // API Security
  mockInstance.onGet('/api-security/overview').reply(200, {
    total_endpoints: 45, vulnerable_endpoints: 12,
    risk_distribution: { critical: 3, high: 5, medium: 4, low: 8 },
    top_risks: ['Broken Authentication', 'Excessive Data Exposure', 'Injection']
  })
  mockInstance.onGet(/\/api-security\/posture\/\d+/).reply(200, {
    product_id: 1, total_endpoints: 15, authenticated: 12, unauthenticated: 3,
    risk_score: 65.0, issues: []
  })
  mockInstance.onGet(/\/api-security\/endpoints\/\d+/).reply(200, [])
  mockInstance.onGet(/\/api-security\/risks\/\d+/).reply(200, [])
}

export function deactivateDemoMode() {
  if (mockInstance) {
    mockInstance.restore()
    mockInstance = null
  }
}
