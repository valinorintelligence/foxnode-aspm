import clsx from 'clsx'

const badgeClasses: Record<string, string> = {
  critical: 'badge-critical',
  high: 'badge-high',
  medium: 'badge-medium',
  low: 'badge-low',
  info: 'badge-info',
}

export default function SeverityBadge({ severity }: { severity: string }) {
  return (
    <span className={clsx(badgeClasses[severity] || 'badge-info')}>
      {severity.charAt(0).toUpperCase() + severity.slice(1)}
    </span>
  )
}
