import { useAuthStore } from '../../store/authStore'
import { useThemeStore } from '../../store/themeStore'
import { LogOut, User, Bell, Sun, Moon } from 'lucide-react'

export default function Header() {
  const { user, logout } = useAuthStore()
  const { theme, toggleTheme } = useThemeStore()

  return (
    <header className="h-16 bg-surface-secondary border-b border-border flex items-center justify-between px-6">
      <div>
        <h2 className="text-sm text-content-tertiary">Application Security Posture Management</h2>
      </div>

      <div className="flex items-center gap-4">
        {/* Theme Toggle */}
        <button
          onClick={toggleTheme}
          className="p-2 text-content-tertiary hover:text-content-secondary hover:bg-surface-tertiary rounded-lg transition-colors"
          title={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
        >
          {theme === 'dark' ? <Sun className="w-5 h-5" /> : <Moon className="w-5 h-5" />}
        </button>

        {/* Notifications */}
        <button className="relative p-2 text-content-tertiary hover:text-content-secondary hover:bg-surface-tertiary rounded-lg transition-colors">
          <Bell className="w-5 h-5" />
          <span className="absolute top-1.5 right-1.5 w-2 h-2 bg-red-500 rounded-full" />
        </button>

        {/* User Menu */}
        <div className="flex items-center gap-3 pl-4 border-l border-border">
          <div className="w-8 h-8 bg-foxnode-600/20 text-foxnode-400 rounded-full flex items-center justify-center">
            <User className="w-4 h-4" />
          </div>
          <div className="text-sm">
            <div className="font-medium text-content-secondary">{user?.full_name || user?.username}</div>
            <div className="text-xs text-content-muted capitalize">{user?.role}</div>
          </div>
          <button
            onClick={logout}
            className="p-2 text-content-muted hover:text-red-400 hover:bg-surface-tertiary rounded-lg transition-colors ml-2"
            title="Logout"
          >
            <LogOut className="w-4 h-4" />
          </button>
        </div>
      </div>
    </header>
  )
}
