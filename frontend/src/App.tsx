import { useEffect } from 'react'
import { Routes, Route, Navigate } from 'react-router-dom'
import { useAuthStore } from './store/authStore'
import Layout from './components/layout/Layout'
import LoginPage from './pages/LoginPage'
import DashboardPage from './pages/DashboardPage'
import ProductsPage from './pages/ProductsPage'
import FindingsPage from './pages/FindingsPage'
import FindingDetailPage from './pages/FindingDetailPage'
import EngagementsPage from './pages/EngagementsPage'
import IntegrationsPage from './pages/IntegrationsPage'
import ScanImportPage from './pages/ScanImportPage'
import SettingsPage from './pages/SettingsPage'
import TriagePage from './pages/TriagePage'
import ScorecardPage from './pages/ScorecardPage'
import CompliancePage from './pages/CompliancePage'
import SLAPage from './pages/SLAPage'
import MetricsPage from './pages/MetricsPage'
import AttackPathPage from './pages/AttackPathPage'
import SecurityAgentPage from './pages/SecurityAgentPage'
import SBOMPage from './pages/SBOMPage'
import CopilotPage from './pages/CopilotPage'
import LLMScannerPage from './pages/LLMScannerPage'

function ProtectedRoute({ children }: { children: React.ReactNode }) {
  const { isAuthenticated } = useAuthStore()
  if (!isAuthenticated) return <Navigate to="/login" replace />
  return <>{children}</>
}

export default function App() {
  const { isAuthenticated, loadUser } = useAuthStore()

  useEffect(() => {
    if (isAuthenticated) loadUser()
  }, [])

  return (
    <Routes>
      <Route path="/login" element={isAuthenticated ? <Navigate to="/" replace /> : <LoginPage />} />
      <Route path="/" element={<ProtectedRoute><Layout /></ProtectedRoute>}>
        <Route index element={<DashboardPage />} />
        <Route path="products" element={<ProductsPage />} />
        <Route path="findings" element={<FindingsPage />} />
        <Route path="findings/:id" element={<FindingDetailPage />} />
        <Route path="engagements" element={<EngagementsPage />} />
        <Route path="integrations" element={<IntegrationsPage />} />
        <Route path="scans/import" element={<ScanImportPage />} />
        <Route path="triage" element={<TriagePage />} />
        <Route path="scorecard" element={<ScorecardPage />} />
        <Route path="compliance" element={<CompliancePage />} />
        <Route path="sla" element={<SLAPage />} />
        <Route path="metrics" element={<MetricsPage />} />
        <Route path="attack-paths" element={<AttackPathPage />} />
        <Route path="security-agent" element={<SecurityAgentPage />} />
        <Route path="sbom" element={<SBOMPage />} />
        <Route path="copilot" element={<CopilotPage />} />
        <Route path="llm-scanner" element={<LLMScannerPage />} />
        <Route path="settings" element={<SettingsPage />} />
      </Route>
    </Routes>
  )
}
