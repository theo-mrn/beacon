import { Check, Flag, Wrench, MessageSquare } from 'lucide-react'
import { RiskBadge } from '../components/RiskBadge'
import type { ExposedEndpoint } from '../lib/types'
import { clsx } from 'clsx'

interface Props {
  endpoints: ExposedEndpoint[]
  refresh: () => void
}

const REVIEW_CONFIG = {
  ACCEPTED: { label: 'Accepted', icon: Check, color: 'text-accent', bg: 'bg-accent/10 border-accent/30' },
  FALSE_POSITIVE: { label: 'False Positive', icon: Flag, color: 'text-foreground-muted', bg: 'bg-surface-2 border-border' },
  TO_FIX: { label: 'To Fix', icon: Wrench, color: 'text-warning', bg: 'bg-warning/10 border-warning/30' },
}

export function Reviews({ endpoints, refresh }: Props) {
  const reviewed = endpoints.filter(e => e.review_status)
  const toFix = reviewed.filter(e => e.review_status === 'TO_FIX')
  const accepted = reviewed.filter(e => e.review_status === 'ACCEPTED')
  const fp = reviewed.filter(e => e.review_status === 'FALSE_POSITIVE')

  const del = async (ep: ExposedEndpoint) => {
    const key = `${ep.namespace}/${ep.source_kind}/${ep.name}/${ep.hostname || ep.external_ip}`
    await fetch(`/api/review?key=${encodeURIComponent(key)}`, { method: 'DELETE' })
    refresh()
  }

  const groups = [
    { label: 'To Fix', items: toFix, config: REVIEW_CONFIG.TO_FIX },
    { label: 'Accepted', items: accepted, config: REVIEW_CONFIG.ACCEPTED },
    { label: 'False Positive', items: fp, config: REVIEW_CONFIG.FALSE_POSITIVE },
  ]

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-bold">Reviews</h1>
        <p className="text-sm text-foreground-muted mt-0.5">{reviewed.length} reviewed endpoints</p>
      </div>

      {/* Summary */}
      <div className="grid grid-cols-3 gap-4">
        {groups.map(({ label, items, config }) => {
          const Icon = config.icon
          return (
            <div key={label} className={clsx('card border flex items-center gap-4', config.bg)}>
              <div className={clsx('p-2.5 rounded-xl bg-black/20', config.color)}>
                <Icon size={18} />
              </div>
              <div>
                <div className="text-2xl font-bold font-mono">{items.length}</div>
                <div className={clsx('text-xs font-medium', config.color)}>{label}</div>
              </div>
            </div>
          )
        })}
      </div>

      {/* Lists */}
      {groups.map(({ label, items, config }) => {
        if (!items.length) return null
        const Icon = config.icon
        return (
          <div key={label} className="card p-0 overflow-hidden">
            <div className="px-5 py-4 border-b border-border flex items-center gap-2">
              <Icon size={14} className={config.color} />
              <span className="text-sm font-semibold">{label}</span>
              <span className="text-xs text-foreground-muted ml-1">({items.length})</span>
            </div>
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border text-xs text-foreground-muted">
                  <th className="text-left px-5 py-3 font-medium">Endpoint</th>
                  <th className="text-left py-3 pr-4 font-medium">Namespace</th>
                  <th className="text-left py-3 pr-4 font-medium">Risk</th>
                  <th className="text-left py-3 pr-4 font-medium">Comment</th>
                  <th className="py-3 pr-4" />
                </tr>
              </thead>
              <tbody>
                {items.map((ep, i) => (
                  <tr key={i} className="table-row">
                    <td className="px-5 py-3 font-mono text-xs text-foreground">
                      {ep.hostname || ep.external_ip || ep.name}
                    </td>
                    <td className="py-3 pr-4 text-xs text-foreground-muted">{ep.namespace}</td>
                    <td className="py-3 pr-4"><RiskBadge risk={ep.risk} /></td>
                    <td className="py-3 pr-4 text-xs text-foreground-muted max-w-[240px]">
                      {ep.review_comment ? (
                        <span className="flex items-center gap-1.5">
                          <MessageSquare size={11} />{ep.review_comment}
                        </span>
                      ) : '—'}
                    </td>
                    <td className="py-3 pr-4">
                      <button
                        onClick={() => del(ep)}
                        className="text-xs text-foreground-muted hover:text-danger transition-colors"
                      >
                        Remove
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )
      })}

      {!reviewed.length && (
        <div className="card text-center py-12">
          <MessageSquare size={32} className="mx-auto text-foreground-muted/30 mb-3" />
          <div className="text-sm text-foreground-muted">No reviews yet</div>
          <div className="text-xs text-foreground-muted/60 mt-1">Go to Endpoints and mark items for review</div>
        </div>
      )}
    </div>
  )
}
