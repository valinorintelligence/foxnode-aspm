import { create } from 'zustand'
import { authAPI } from '../services/api'

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

  register: async (data) => {
    await authAPI.register(data)
  },

  logout: () => {
    localStorage.removeItem('foxnode_token')
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
