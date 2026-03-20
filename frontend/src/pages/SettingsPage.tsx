import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { usersAPI, jiraAPI, notificationsAPI } from '../services/api'
import { useAuthStore } from '../store/authStore'
import {
  Settings,
  Users,
  Bell,
  Link2,
  Shield,
  Trash2,
  CheckCircle,
  XCircle,
  Send,
  Save,
} from 'lucide-react'
import toast from 'react-hot-toast'
import clsx from 'clsx'

type Tab = 'general' | 'users' | 'jira' | 'notifications'

export default function SettingsPage() {
  const [activeTab, setActiveTab] = useState<Tab>('general')

  const tabs = [
    { id: 'general' as Tab, label: 'General', icon: Settings },
    { id: 'users' as Tab, label: 'User Management', icon: Users },
    { id: 'jira' as Tab, label: 'Jira Integration', icon: Link2 },
    { id: 'notifications' as Tab, label: 'Notifications', icon: Bell },
  ]

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-content-primary">Settings</h1>
        <p className="text-content-muted mt-1">Configure your FoxNode platform</p>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 bg-surface-secondary border border-border rounded-xl p-1">
        {tabs.map((tab) => (
          <button
            key={tab.id}
            onClick={() => setActiveTab(tab.id)}
            className={clsx(
              'flex items-center gap-2 px-4 py-2.5 rounded-lg text-sm font-medium transition-all flex-1',
              activeTab === tab.id
                ? 'bg-foxnode-600/15 text-foxnode-400 border border-foxnode-500/20'
                : 'text-content-tertiary hover:text-content-secondary hover:bg-surface-tertiary/50',
            )}
          >
            <tab.icon className="w-4 h-4" />
            {tab.label}
          </button>
        ))}
      </div>

      {/* Tab Content */}
      {activeTab === 'general' && <GeneralSettings />}
      {activeTab === 'users' && <UserManagement />}
      {activeTab === 'jira' && <JiraSettings />}
      {activeTab === 'notifications' && <NotificationSettings />}
    </div>
  )
}

function GeneralSettings() {
  return (
    <div className="card space-y-6">
      <h3 className="text-lg font-semibold text-content-primary">General Settings</h3>
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        <div>
          <label className="block text-sm font-medium text-content-tertiary mb-1">Platform Name</label>
          <input className="input w-full" defaultValue="FoxNode" />
        </div>
        <div>
          <label className="block text-sm font-medium text-content-tertiary mb-1">Default Severity Threshold</label>
          <select className="input w-full" defaultValue="medium">
            <option value="critical">Critical Only</option>
            <option value="high">High and Above</option>
            <option value="medium">Medium and Above</option>
            <option value="low">All Severities</option>
          </select>
        </div>
        <div>
          <label className="block text-sm font-medium text-content-tertiary mb-1">Auto-deduplicate Findings</label>
          <select className="input w-full" defaultValue="true">
            <option value="true">Enabled</option>
            <option value="false">Disabled</option>
          </select>
        </div>
        <div>
          <label className="block text-sm font-medium text-content-tertiary mb-1">Risk Score Algorithm</label>
          <select className="input w-full" defaultValue="cvss_weighted">
            <option value="cvss_weighted">CVSS Weighted</option>
            <option value="severity_count">Severity Count Based</option>
            <option value="custom">Custom Formula</option>
          </select>
        </div>
      </div>
      <div className="flex justify-end pt-4 border-t border-border">
        <button className="btn-primary flex items-center gap-2">
          <Save className="w-4 h-4" />
          Save Settings
        </button>
      </div>
    </div>
  )
}

function UserManagement() {
  const { user: currentUser } = useAuthStore()
  const queryClient = useQueryClient()

  const { data: users, isLoading } = useQuery({
    queryKey: ['users'],
    queryFn: () => usersAPI.list().then((r) => r.data),
  })

  const updateMutation = useMutation({
    mutationFn: ({ id, data }: { id: number; data: any }) => usersAPI.update(id, data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] })
      toast.success('User updated')
    },
    onError: (err: any) => toast.error(err.response?.data?.detail || 'Failed to update'),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: number) => usersAPI.delete(id),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['users'] })
      toast.success('User deactivated')
    },
  })

  if (isLoading) return <div className="text-content-muted text-center py-12">Loading users...</div>

  return (
    <div className="card p-0 overflow-hidden">
      <div className="p-6 border-b border-border">
        <h3 className="text-lg font-semibold text-content-primary">User Management</h3>
        <p className="text-sm text-content-muted mt-1">Manage users and their roles</p>
      </div>
      <div className="overflow-x-auto">
        <table className="w-full">
          <thead>
            <tr className="bg-surface-tertiary/50">
              <th className="text-left py-3 px-4 text-xs font-medium text-content-muted uppercase">User</th>
              <th className="text-left py-3 px-4 text-xs font-medium text-content-muted uppercase">Email</th>
              <th className="text-left py-3 px-4 text-xs font-medium text-content-muted uppercase">Role</th>
              <th className="text-left py-3 px-4 text-xs font-medium text-content-muted uppercase">Status</th>
              <th className="text-left py-3 px-4 text-xs font-medium text-content-muted uppercase">Joined</th>
              <th className="text-left py-3 px-4 text-xs font-medium text-content-muted uppercase">Actions</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-border/50">
            {users?.map((u: any) => (
              <tr key={u.id} className="hover:bg-surface-tertiary/30 transition-colors">
                <td className="py-3 px-4">
                  <div className="flex items-center gap-3">
                    <div className="w-8 h-8 bg-foxnode-600/20 text-foxnode-400 rounded-full flex items-center justify-center text-sm font-medium">
                      {(u.full_name || u.username).charAt(0).toUpperCase()}
                    </div>
                    <div>
                      <p className="text-sm font-medium text-content-secondary">{u.full_name || u.username}</p>
                      <p className="text-xs text-content-muted">@{u.username}</p>
                    </div>
                  </div>
                </td>
                <td className="py-3 px-4 text-sm text-content-tertiary">{u.email}</td>
                <td className="py-3 px-4">
                  <select
                    className="bg-transparent text-xs text-content-tertiary border border-border-secondary rounded px-2 py-1 focus:outline-none focus:ring-1 focus:ring-foxnode-500"
                    value={u.role}
                    disabled={u.id === currentUser?.id}
                    onChange={(e) => updateMutation.mutate({ id: u.id, data: { role: e.target.value } })}
                  >
                    <option value="admin">Admin</option>
                    <option value="manager">Manager</option>
                    <option value="analyst">Analyst</option>
                    <option value="viewer">Viewer</option>
                  </select>
                </td>
                <td className="py-3 px-4">
                  {u.is_active ? (
                    <span className="flex items-center gap-1.5 text-green-400 text-xs">
                      <CheckCircle className="w-3.5 h-3.5" /> Active
                    </span>
                  ) : (
                    <span className="flex items-center gap-1.5 text-red-400 text-xs">
                      <XCircle className="w-3.5 h-3.5" /> Inactive
                    </span>
                  )}
                </td>
                <td className="py-3 px-4 text-xs text-content-muted">
                  {new Date(u.created_at).toLocaleDateString()}
                </td>
                <td className="py-3 px-4">
                  {u.id !== currentUser?.id && u.is_active && (
                    <button
                      onClick={() => deleteMutation.mutate(u.id)}
                      className="p-1.5 text-content-muted hover:text-red-400 transition-colors"
                      title="Deactivate user"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  )}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function JiraSettings() {
  const { data: status, isLoading } = useQuery({
    queryKey: ['jira-status'],
    queryFn: () => jiraAPI.status().then((r) => r.data),
  })

  return (
    <div className="space-y-6">
      {/* Connection Status */}
      <div className="card">
        <h3 className="text-lg font-semibold text-content-primary mb-4">Jira Connection</h3>
        {isLoading ? (
          <p className="text-content-muted">Checking connection...</p>
        ) : status?.connected ? (
          <div className="flex items-center gap-3 p-4 bg-green-500/5 border border-green-800/50 rounded-lg">
            <CheckCircle className="w-6 h-6 text-green-400" />
            <div>
              <p className="text-green-400 font-medium">Connected to Jira</p>
              <p className="text-xs text-content-muted mt-0.5">
                {status.server_title} &bull; v{status.version} &bull; {status.base_url}
              </p>
            </div>
          </div>
        ) : (
          <div className="flex items-center gap-3 p-4 bg-red-500/5 border border-red-800/50 rounded-lg">
            <XCircle className="w-6 h-6 text-red-400" />
            <div>
              <p className="text-red-400 font-medium">Not Connected</p>
              <p className="text-xs text-content-muted mt-0.5">{status?.error || 'Configure Jira credentials in environment variables'}</p>
            </div>
          </div>
        )}
      </div>

      {/* Configuration */}
      <div className="card space-y-4">
        <h3 className="text-lg font-semibold text-content-primary">Configuration</h3>
        <p className="text-sm text-content-muted">Set these environment variables to enable Jira integration:</p>
        <div className="space-y-3">
          {['JIRA_URL', 'JIRA_USERNAME', 'JIRA_API_TOKEN'].map((envVar) => (
            <div key={envVar} className="flex items-center gap-3 p-3 bg-surface-tertiary/50 rounded-lg">
              <code className="text-sm text-foxnode-400 font-mono">{envVar}</code>
              <span className="text-xs text-content-muted">
                {envVar === 'JIRA_URL' && 'Your Jira instance URL (e.g., https://company.atlassian.net)'}
                {envVar === 'JIRA_USERNAME' && 'Jira account email'}
                {envVar === 'JIRA_API_TOKEN' && 'Jira API token (generate from Atlassian account settings)'}
              </span>
            </div>
          ))}
        </div>
        <div className="p-4 bg-surface-tertiary/30 border border-border-secondary rounded-lg">
          <h4 className="text-sm font-medium text-content-secondary mb-2">How it works</h4>
          <ul className="text-xs text-content-muted space-y-1.5 list-disc list-inside">
            <li>Create Jira issues directly from any finding with one click</li>
            <li>Severity maps to Jira priority (Critical → Highest, High → High, etc.)</li>
            <li>Labels auto-added: security, severity level, scanner name, CVE ID</li>
            <li>Sync Jira issue status back to findings</li>
          </ul>
        </div>
      </div>
    </div>
  )
}

function NotificationSettings() {
  const queryClient = useQueryClient()
  const [webhookUrl, setWebhookUrl] = useState('')

  const { data: settings, isLoading } = useQuery({
    queryKey: ['notification-settings'],
    queryFn: () => notificationsAPI.getSettings().then((r) => r.data),
  })

  const configureMutation = useMutation({
    mutationFn: (data: any) => notificationsAPI.configure(data),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['notification-settings'] })
      toast.success('Notification settings saved')
    },
  })

  const testMutation = useMutation({
    mutationFn: () => notificationsAPI.testSlack(webhookUrl || settings?.slack_webhook_url),
    onSuccess: () => toast.success('Test notification sent!'),
    onError: (err: any) => toast.error(err.response?.data?.detail || 'Failed to send test'),
  })

  return (
    <div className="space-y-6">
      {/* Slack Config */}
      <div className="card space-y-4">
        <div className="flex items-center justify-between">
          <h3 className="text-lg font-semibold text-content-primary">Slack Notifications</h3>
          {settings?.slack_configured ? (
            <span className="flex items-center gap-1.5 text-green-400 text-xs">
              <CheckCircle className="w-3.5 h-3.5" /> Configured
            </span>
          ) : (
            <span className="flex items-center gap-1.5 text-yellow-400 text-xs">
              <XCircle className="w-3.5 h-3.5" /> Not Configured
            </span>
          )}
        </div>

        <div>
          <label className="block text-sm font-medium text-content-tertiary mb-1">Slack Webhook URL</label>
          <div className="flex gap-2">
            <input
              className="input flex-1"
              type="url"
              placeholder="https://hooks.slack.com/services/..."
              value={webhookUrl || settings?.slack_webhook_url || ''}
              onChange={(e) => setWebhookUrl(e.target.value)}
            />
            <button
              onClick={() => configureMutation.mutate({ slack_webhook_url: webhookUrl })}
              disabled={!webhookUrl}
              className="btn-primary"
            >
              <Save className="w-4 h-4" />
            </button>
            <button
              onClick={() => testMutation.mutate()}
              disabled={testMutation.isPending}
              className="btn-secondary flex items-center gap-2"
            >
              <Send className="w-4 h-4" />
              Test
            </button>
          </div>
        </div>
      </div>

      {/* Notification Preferences */}
      <div className="card space-y-4">
        <h3 className="text-lg font-semibold text-content-primary">Notification Preferences</h3>
        <div className="space-y-3">
          <label className="flex items-center justify-between p-3 bg-surface-tertiary/50 rounded-lg cursor-pointer">
            <div>
              <p className="text-sm text-content-secondary">New findings detected</p>
              <p className="text-xs text-content-muted">Get notified when new vulnerabilities are found</p>
            </div>
            <input
              type="checkbox"
              className="w-4 h-4 rounded border-border-secondary text-foxnode-500 focus:ring-foxnode-500 bg-surface-tertiary"
              defaultChecked={settings?.notify_on_new_findings ?? true}
              onChange={(e) => configureMutation.mutate({ notify_on_new_findings: e.target.checked })}
            />
          </label>
          <label className="flex items-center justify-between p-3 bg-surface-tertiary/50 rounded-lg cursor-pointer">
            <div>
              <p className="text-sm text-content-secondary">Scan import completed</p>
              <p className="text-xs text-content-muted">Get notified when a scan import finishes</p>
            </div>
            <input
              type="checkbox"
              className="w-4 h-4 rounded border-border-secondary text-foxnode-500 focus:ring-foxnode-500 bg-surface-tertiary"
              defaultChecked={settings?.notify_on_scan_complete ?? true}
              onChange={(e) => configureMutation.mutate({ notify_on_scan_complete: e.target.checked })}
            />
          </label>
        </div>

        <div>
          <label className="block text-sm font-medium text-content-tertiary mb-1">Minimum Severity for Alerts</label>
          <select
            className="input"
            defaultValue={settings?.minimum_severity || 'high'}
            onChange={(e) => configureMutation.mutate({ minimum_severity: e.target.value })}
          >
            <option value="critical">Critical Only</option>
            <option value="high">High and Above</option>
            <option value="medium">Medium and Above</option>
            <option value="low">All Severities</option>
          </select>
        </div>
      </div>
    </div>
  )
}
