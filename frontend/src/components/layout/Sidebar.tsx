import { NavLink } from 'react-router-dom'
import {
  LayoutDashboard,
  Package,
  AlertTriangle,
  Plug,
  Upload,
  Calendar,
  Settings,
  Brain,
  Award,
  ClipboardCheck,
  Timer,
  Activity,
  Network,
  Bot,
  Boxes,
  Wand2,
  ShieldAlert,
} from 'lucide-react'
import clsx from 'clsx'
import { useThemeStore } from '../../store/themeStore'

const navItems = [
  { to: '/', icon: LayoutDashboard, label: 'Dashboard', end: true },
  { to: '/products', icon: Package, label: 'Products' },
  { to: '/findings', icon: AlertTriangle, label: 'Findings' },
  { to: '/engagements', icon: Calendar, label: 'Engagements' },
  { to: '/integrations', icon: Plug, label: 'Integrations' },
  { to: '/scans/import', icon: Upload, label: 'Import Scans' },
  { to: '/triage', icon: Brain, label: 'AI Triage' },
  { to: '/scorecard', icon: Award, label: 'Scorecard' },
  { to: '/compliance', icon: ClipboardCheck, label: 'Compliance' },
  { to: '/sla', icon: Timer, label: 'SLA Tracker' },
  { to: '/metrics', icon: Activity, label: 'Metrics & KPIs' },
  { to: '/attack-paths', icon: Network, label: 'Attack Paths' },
  { to: '/security-agent', icon: Bot, label: 'AI Agent' },
  { to: '/sbom', icon: Boxes, label: 'SBOM' },
  { to: '/copilot', icon: Wand2, label: 'AI Copilot' },
  { to: '/llm-scanner', icon: ShieldAlert, label: 'LLM Scanner' },
]

export default function Sidebar() {
  const { theme } = useThemeStore()

  return (
    <aside className="w-64 bg-surface-secondary border-r border-border flex flex-col">
      {/* Logo */}
      <div className="h-16 flex items-center px-5 border-b border-border">
        <img
          src={theme === 'dark' ? '/logo-dark.svg' : '/logo-light.svg'}
          alt="FoxNode"
          className="h-8"
        />
      </div>

      {/* Navigation */}
      <nav className="flex-1 py-4 px-3 space-y-1">
        {navItems.map((item) => (
          <NavLink
            key={item.to}
            to={item.to}
            end={item.end}
            className={({ isActive }) =>
              clsx(
                'flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all duration-150',
                isActive
                  ? 'bg-foxnode-600/15 text-foxnode-400 border border-foxnode-500/20'
                  : 'text-content-tertiary hover:text-content-secondary hover:bg-surface-tertiary',
              )
            }
          >
            <item.icon className="w-5 h-5 shrink-0" />
            {item.label}
          </NavLink>
        ))}
      </nav>

      {/* Settings Link */}
      <div className="px-3 pb-2">
        <NavLink
          to="/settings"
          className={({ isActive }) =>
            clsx(
              'flex items-center gap-3 px-3 py-2.5 rounded-lg text-sm font-medium transition-all duration-150',
              isActive
                ? 'bg-foxnode-600/15 text-foxnode-400 border border-foxnode-500/20'
                : 'text-content-tertiary hover:text-content-secondary hover:bg-surface-tertiary',
            )
          }
        >
          <Settings className="w-5 h-5 shrink-0" />
          Settings
        </NavLink>
      </div>

      {/* Footer */}
      <div className="p-4 border-t border-border">
        <div className="text-xs text-content-muted text-center">
          FoxNode v1.0.0
        </div>
      </div>
    </aside>
  )
}
