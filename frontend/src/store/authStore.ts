import { create } from 'zustand'
import api, { authAPI } from '../services/api'
import { activateDemoMode, deactivateDemoMode } from '../services/mockApi'

interface User {
  id: number
  email: string
  username: string
  full_name: string | null
  role: string
}

interface AuthState {
  user: User | null
  token: string | null
  isAuthenticated: boolean
  isLoading: boolean
  login: (username: string, password: string) => Promise<void>
  demoLogin: () => void
  register: (data: any) => Promise<void>
  logout: () => void
  loadUser: () => Promise<void>
}

export const useAuthStore = create<AuthState>((set) => ({
  user: null,
  token: localStorage.getItem('foxnode_token'),
  isAuthenticated: !!localStorage.getItem('foxnode_token'),
  isLoading: false,

  login: async (username, password) => {
    const res = await authAPI.login({ username, password })
    const token = res.data.access_token
    localStorage.setItem('foxnode_token', token)
    set({ token, isAuthenticated: true })

    const userRes = await authAPI.me()
    set({ user: userRes.data })
  },

  demoLogin: () => {
    localStorage.setItem('foxnode_demo', 'true')
    localStorage.setItem('foxnode_token', 'demo-token')
    activateDemoMode(api)
    set({
      token: 'demo-token',
      isAuthenticated: true,
      user: {
        id: 1,
        email: 'demo@foxnode.io',
        username: 'demo',
        full_name: 'Demo User',
        role: 'analyst',
      },
    })
  },

  register: async (data) => {
    await authAPI.register(data)
  },

  logout: () => {
    const wasDemo = localStorage.getItem('foxnode_demo') === 'true'
    localStorage.removeItem('foxnode_token')
    localStorage.removeItem('foxnode_demo')
    if (wasDemo) deactivateDemoMode()
    set({ user: null, token: null, isAuthenticated: false })
  },

  loadUser: async () => {
    try {
      set({ isLoading: true })
      const res = await authAPI.me()
      set({ user: res.data, isAuthenticated: true })
    } catch {
      localStorage.removeItem('foxnode_token')
      set({ user: null, isAuthenticated: false })
    } finally {
      set({ isLoading: false })
    }
  },
}))
