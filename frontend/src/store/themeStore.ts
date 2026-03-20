import { create } from 'zustand'

type Theme = 'light' | 'dark'

interface ThemeState {
  theme: Theme
  setTheme: (theme: Theme) => void
  toggleTheme: () => void
}

function applyTheme(theme: Theme) {
  const html = document.documentElement
  if (theme === 'dark') {
    html.classList.add('dark')
  } else {
    html.classList.remove('dark')
  }
}

const stored = (localStorage.getItem('foxnode_theme') as Theme) || 'dark'
applyTheme(stored)

export const useThemeStore = create<ThemeState>((set, get) => ({
  theme: stored,

  setTheme: (theme) => {
    localStorage.setItem('foxnode_theme', theme)
    applyTheme(theme)
    set({ theme })
  },

  toggleTheme: () => {
    const next = get().theme === 'dark' ? 'light' : 'dark'
    localStorage.setItem('foxnode_theme', next)
    applyTheme(next)
    set({ theme: next })
  },
}))
