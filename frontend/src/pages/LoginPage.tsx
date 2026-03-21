import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useAuthStore } from '../store/authStore'
import { useThemeStore } from '../store/themeStore'
import { Eye, EyeOff, Play } from 'lucide-react'
import toast from 'react-hot-toast'

export default function LoginPage() {
  const [isRegister, setIsRegister] = useState(false)
  const [showPassword, setShowPassword] = useState(false)
  const [form, setForm] = useState({ username: '', password: '', email: '', full_name: '' })
  const [loading, setLoading] = useState(false)
  const { login, register, demoLogin } = useAuthStore()
  const { theme } = useThemeStore()
  const navigate = useNavigate()

  const handleDemoLogin = () => {
    demoLogin()
    toast.success('Welcome to FoxNode Demo!')
    navigate('/')
  }

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault()
    setLoading(true)
    try {
      if (isRegister) {
        await register({ ...form, role: 'analyst' })
        toast.success('Account created! Please sign in.')
        setIsRegister(false)
      } else {
        await login(form.username, form.password)
        navigate('/')
      }
    } catch (err: any) {
      toast.error(err.response?.data?.detail || 'Something went wrong')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-surface-primary flex items-center justify-center p-4">
      <div className="w-full max-w-md">
        {/* Logo */}
        <div className="flex flex-col items-center mb-8">
          <img
            src={theme === 'dark' ? '/logo-dark.svg' : '/logo-light.svg'}
            alt="FoxNode"
            className="h-12 mb-3"
          />
          <p className="text-content-muted mt-1">Application Security Posture Management</p>
        </div>

        {/* Form */}
        <div className="card">
          <h2 className="text-xl font-semibold text-content-primary mb-6">
            {isRegister ? 'Create Account' : 'Sign In'}
          </h2>

          <form onSubmit={handleSubmit} className="space-y-4">
            {isRegister && (
              <>
                <div>
                  <label className="block text-sm font-medium text-content-tertiary mb-1">Full Name</label>
                  <input
                    type="text"
                    className="input w-full"
                    value={form.full_name}
                    onChange={(e) => setForm({ ...form, full_name: e.target.value })}
                  />
                </div>
                <div>
                  <label className="block text-sm font-medium text-content-tertiary mb-1">Email</label>
                  <input
                    type="email"
                    className="input w-full"
                    value={form.email}
                    onChange={(e) => setForm({ ...form, email: e.target.value })}
                    required
                  />
                </div>
              </>
            )}

            <div>
              <label className="block text-sm font-medium text-content-tertiary mb-1">Username</label>
              <input
                type="text"
                className="input w-full"
                value={form.username}
                onChange={(e) => setForm({ ...form, username: e.target.value })}
                required
              />
            </div>

            <div>
              <label className="block text-sm font-medium text-content-tertiary mb-1">Password</label>
              <div className="relative">
                <input
                  type={showPassword ? 'text' : 'password'}
                  className="input w-full pr-10"
                  value={form.password}
                  onChange={(e) => setForm({ ...form, password: e.target.value })}
                  required
                />
                <button
                  type="button"
                  onClick={() => setShowPassword(!showPassword)}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-content-muted hover:text-content-secondary"
                >
                  {showPassword ? <EyeOff className="w-4 h-4" /> : <Eye className="w-4 h-4" />}
                </button>
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="btn-primary w-full py-2.5 disabled:opacity-50"
            >
              {loading ? 'Please wait...' : isRegister ? 'Create Account' : 'Sign In'}
            </button>
          </form>

          <div className="mt-6 text-center">
            <button
              onClick={() => setIsRegister(!isRegister)}
              className="text-sm text-foxnode-400 hover:text-foxnode-300 transition-colors"
            >
              {isRegister ? 'Already have an account? Sign in' : "Don't have an account? Register"}
            </button>
          </div>
        </div>

        {/* Demo Mode */}
        <div className="mt-4">
          <button
            onClick={handleDemoLogin}
            className="w-full flex items-center justify-center gap-2 py-2.5 px-4 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white font-medium transition-colors"
          >
            <Play className="w-4 h-4" />
            Try Live Demo
          </button>
          <p className="text-center text-xs text-content-muted mt-2">
            No account needed — explore all features with sample data
          </p>
        </div>
      </div>
    </div>
  )
}
