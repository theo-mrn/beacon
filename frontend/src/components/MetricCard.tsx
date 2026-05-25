import { clsx } from 'clsx'

interface Props {
  label: string
  value: number | string
  sub?: string
  trend?: { value: string; up: boolean }
  color?: 'default' | 'danger' | 'warning' | 'accent'
}

export function MetricCard({ label, value, sub, trend, color = 'default' }: Props) {
  const valueColor = {
    default: 'text-foreground',
    danger: 'text-danger',
    warning: 'text-warning',
    accent: 'text-accent',
  }[color]

  return (
    <div className="bg-surface rounded-xl px-5 py-4 flex flex-col gap-1 border border-border">
      <span className="text-sm text-foreground-muted">{label}</span>
      <div className="flex items-end gap-3 mt-1">
        <span className={clsx('text-3xl font-bold tracking-tight', valueColor)}>{value}</span>
        {trend && (
          <span className={clsx('text-sm font-medium mb-0.5', trend.up ? 'text-accent' : 'text-danger')}>
            {trend.up ? '↗' : '↘'} {trend.value}
          </span>
        )}
      </div>
      {sub && <div className="text-xs text-foreground-muted">{sub}</div>}
    </div>
  )
}
