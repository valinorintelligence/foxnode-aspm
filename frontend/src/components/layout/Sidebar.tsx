import { NavLink } from 'react-router-dom'
import {
  LayoutDashboard,
  Package,
  AlertTriangle,
  Plug,
  Upload,
  Shield,
  Calendar,
  Settings,
  Brain,
  Award,
  ClipboardCheck,
  Timer,
} from 'lucide-react'
import clsx from 'clsx'

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
]

export default function Sidebar() {
  return (
    <aside className="w-64 bg-gray-900 border-r border-gray-800 flex flex-col">
      {/* Logo */}
      <div className="h-16 flex items-center gap-3 px-6 border-b border-gray-800">
        <div className="w-8 h-8 bg-foxnode-600 rounded-lg flex items-center justify-center">
          <Shield className="w-5 h-5 text-white" />
        </div>
        <div>
          <h1 className="text-lg font-bold text-white tracking-tight">Foxnode</h1>
          <p className="text-[10px] text-gray-500 uppercase tracking-widest -mt-1">ASPM Platform</p>
        </div>
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
                  : 'text-gray-400 hover:text-gray-200 hover:bg-gray-800/50',
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
                : 'text-gray-400 hover:text-gray-200 hover:bg-gray-800/50',
            )
          }
        >
          <Settings className="w-5 h-5 shrink-0" />
          Settings
        </NavLink>
      </div>

      {/* Footer */}
      <div className="p-4 border-t border-gray-800">
        <div className="text-xs text-gray-600 text-center">
          Foxnode ASPM v1.0.0
        </div>
      </div>
    </aside>
  )
}
