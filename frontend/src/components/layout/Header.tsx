import { useAuthStore } from '../../store/authStore'
import { LogOut, User, Bell } from 'lucide-react'

export default function Header() {
  const { user, logout } = useAuthStore()

  return (
    <header className="h-16 bg-gray-900 border-b border-gray-800 flex items-center justify-between px-6">
      <div>
        <h2 className="text-sm text-gray-400">Application Security Posture Management</h2>
      </div>

      <div className="flex items-center gap-4">
        {/* Notifications */}
        <button className="relative p-2 text-gray-400 hover:text-gray-200 hover:bg-gray-800 rounded-lg transition-colors">
          <Bell className="w-5 h-5" />
          <span className="absolute top-1.5 right-1.5 w-2 h-2 bg-red-500 rounded-full" />
        </button>

        {/* User Menu */}
        <div className="flex items-center gap-3 pl-4 border-l border-gray-800">
          <div className="w-8 h-8 bg-foxnode-600/20 text-foxnode-400 rounded-full flex items-center justify-center">
            <User className="w-4 h-4" />
          </div>
          <div className="text-sm">
            <div className="font-medium text-gray-200">{user?.full_name || user?.username}</div>
            <div className="text-xs text-gray-500 capitalize">{user?.role}</div>
          </div>
          <button
            onClick={logout}
            className="p-2 text-gray-500 hover:text-red-400 hover:bg-gray-800 rounded-lg transition-colors ml-2"
            title="Logout"
          >
            <LogOut className="w-4 h-4" />
          </button>
        </div>
      </div>
    </header>
  )
}
