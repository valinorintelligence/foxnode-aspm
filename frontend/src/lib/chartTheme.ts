import { useThemeStore } from '../store/themeStore'

export function useChartTheme() {
  const theme = useThemeStore((s) => s.theme)
  const isDark = theme === 'dark'

  return {
    tooltipStyle: {
      backgroundColor: isDark ? '#1f2937' : '#ffffff',
      border: `1px solid ${isDark ? '#374151' : '#e2e8f0'}`,
      borderRadius: '8px',
      color: isDark ? '#f3f4f6' : '#334155',
    },
    gridStroke: isDark ? '#374151' : '#e2e8f0',
    axisStroke: isDark ? '#6b7280' : '#94a3b8',
    textColor: isDark ? '#9ca3af' : '#64748b',
    cardBg: isDark ? '#111827' : '#ffffff',
    isDark,
  }
}
