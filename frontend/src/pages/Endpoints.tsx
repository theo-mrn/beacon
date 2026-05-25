import { useState } from 'react'
import { Search, ExternalLink, Lock, LockOpen, ChevronDown, ChevronRight, X, Check, Flag, Wrench } from 'lucide-react'
import { RiskBadge } from '../components/RiskBadge'
import type { ExposedEndpoint, ReviewStatus } from '../lib/types'
import { clsx } from 'clsx'

interface Props {
  endpoints: ExposedEndpoint[]
  refresh: () => void
  onNavigateCVE?: (ns: string) => void
}

type FilterRisk = 'ALL' | 'HIGH' | 'MEDIUM' | 'LOW'
type FilterReview = 'ALL' | 'NONE' | 'ACCEPTED' | 'FALSE_POSITIVE' | 'TO_FIX'

const REVIEW_LABELS: Record<string, { label: string; color: string }> = {
  ACCEPTED: { label: 'Accepted', color: 'text-accent' },
  FALSE_POSITIVE: { label: 'False Positive', color: 'text-foreground-muted' },
  TO_FIX: { label: 'To Fix', color: 'text-warning' },
}

function ReviewModal({ ep, onClose, onSave }: { ep: ExposedEndpoint; onClose: () => void; onSave: () => void }) {
  const [status, setStatus] = useState<ReviewStatus>(ep.review_status || '')
  const [comment, setComment] = useState(ep.review_comment || '')
  const [saving, setSaving] = useState(false)

  const key = `${ep.namespace}/${ep.source_kind}/${ep.name}/${ep.hostname || ep.external_ip}`

  const save = async () => {
    if (!status) return
    setSaving(true)
    await fetch('/api/review', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ key, status, comment }),
    })
    setSaving(false)
    onSave()
    onClose()
  }

  const del = async () => {
    setSaving(true)
    await fetch(`/api/review?key=${encodeURIComponent(key)}`, { method: 'DELETE' })
    setSaving(false)
    onSave()
    onClose()
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center">
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={onClose} />
      <div className="relative bg-surface border border-border rounded-2xl p-6 w-full max-w-md shadow-2xl">
        <div className="flex items-center justify-between mb-4">
          <div>
            <div className="text-sm font-semibold">{ep.name}</div>
            <div className="text-xs text-foreground-muted font-mono">{ep.namespace}</div>
          </div>
          <button onClick={onClose} className="btn-ghost p-1.5"><X size={16} /></button>
        </div>

        <div className="space-y-2 mb-4">
          {[
            { value: 'ACCEPTED', label: 'Accepted', icon: Check, color: 'border-accent/40 bg-accent/10 text-accent' },
            { value: 'FALSE_POSITIVE', label: 'False Positive', icon: Flag, color: 'border-foreground-muted/30 bg-surface-2 text-foreground-muted' },
            { value: 'TO_FIX', label: 'To Fix', icon: Wrench, color: 'border-warning/40 bg-warning/10 text-warning' },
          ].map(({ value, label, icon: Icon, color }) => (
            <button
              key={value}
              onClick={() => setStatus(value as ReviewStatus)}
              className={clsx(
                'w-full flex items-center gap-3 px-4 py-3 rounded-xl border text-sm font-medium transition-all duration-150',
                status === value ? color : 'border-border bg-surface-2/50 text-foreground-muted hover:text-foreground hover:border-border/80'
              )}
            >
              <Icon size={15} />
              {label}
            </button>
          ))}
        </div>

        <textarea
          value={comment}
          onChange={e => setComment(e.target.value)}
          placeholder="Add a comment (optional)..."
          rows={3}
          className="w-full bg-surface-2 border border-border rounded-xl px-3 py-2.5 text-sm text-foreground placeholder:text-foreground-muted resize-none outline-none focus:border-foreground-muted/50 transition-colors"
        />

        <div className="flex items-center gap-2 mt-4">
          <button onClick={save} disabled={!status || saving} className="btn-primary flex-1 justify-center">
            {saving ? 'Saving…' : 'Save Review'}
          </button>
          {ep.review_status && (
            <button onClick={del} className="px-3 py-2 rounded-lg border border-danger/30 text-danger text-sm hover:bg-danger/10 transition-colors">
              Remove
            </button>
          )}
        </div>
      </div>
    </div>
  )
}

function EndpointRow({ ep, refresh, onNavigateCVE }: { ep: ExposedEndpoint; refresh: () => void; onNavigateCVE?: (ns: string) => void }) {
  const [expanded, setExpanded] = useState(false)
  const [reviewing, setReviewing] = useState(false)
  const dismissed = ep.review_status === 'ACCEPTED' || ep.review_status === 'FALSE_POSITIVE'

  const url = ep.hostname
    ? `${ep.tls ? 'https' : 'http'}://${ep.hostname}`
    : ep.external_ip && ep.ports?.[0]
    ? `${ep.tls ? 'https' : 'http'}://${ep.external_ip}:${ep.ports[0].port}`
    : null

  return (
    <>
      {reviewing && <ReviewModal ep={ep} onClose={() => setReviewing(false)} onSave={refresh} />}
      <tr
        className={clsx(
          'table-row cursor-pointer',
          dismissed && 'opacity-40'
        )}
        onClick={() => setExpanded(v => !v)}
      >
        <td className="py-3 px-4 w-4">
          {expanded ? <ChevronDown size={14} className="text-foreground-muted" /> : <ChevronRight size={14} className="text-foreground-muted" />}
        </td>
        <td className="py-3 pr-4">
          <div className="flex items-center gap-2">
            {ep.tls ? <Lock size={12} className="text-accent shrink-0" /> : <LockOpen size={12} className="text-foreground-muted shrink-0" />}
            <span className="font-mono text-xs text-foreground truncate max-w-[200px]">
              {ep.hostname || ep.external_ip || '—'}
            </span>
            {ep.status === 'NEW' && (
              <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-foreground-muted/15 text-foreground border border-foreground-muted/30">NEW</span>
            )}
            {ep.status === 'MODIFIED' && (
              <span className="px-1.5 py-0.5 rounded text-[10px] font-semibold bg-warning/15 text-warning border border-warning/30">MOD</span>
            )}
          </div>
        </td>
        <td className="py-3 pr-4 text-xs text-foreground-muted">{ep.namespace}</td>
        <td className="py-3 pr-4 text-xs text-foreground-muted">{ep.source_kind}</td>
        <td className="py-3 pr-4">{!dismissed && <RiskBadge risk={ep.risk} />}</td>
        <td className="py-3 pr-4 text-xs text-foreground-muted font-mono">
          {ep.ports?.map(p => p.port).join(', ') || '—'}
        </td>
        <td className="py-3 pr-4">
          {ep.review_status && (
            <span className={clsx('text-xs font-medium', REVIEW_LABELS[ep.review_status]?.color)}>
              {REVIEW_LABELS[ep.review_status]?.label}
            </span>
          )}
        </td>
        <td className="py-3 pr-4" onClick={e => e.stopPropagation()}>
          <button onClick={() => setReviewing(true)} className="btn-ghost text-xs px-2 py-1">Review</button>
          {url && (
            <a href={url} target="_blank" rel="noreferrer" className="btn-ghost text-xs px-2 py-1 ml-1" onClick={e => e.stopPropagation()}>
              <ExternalLink size={12} />
            </a>
          )}
        </td>
      </tr>
      {expanded && (
        <tr className="bg-surface-2/30">
          <td colSpan={8} className="px-8 py-3">
            <div className="grid grid-cols-4 gap-6 items-center text-xs w-full">
              {ep.risk_reasons?.length > 0 && (
                <div className="min-w-0">
                  <div className="text-foreground-muted font-medium mb-1">Risk Reasons</div>
                  <ul className="space-y-0.5">
                    {ep.risk_reasons.map((r, i) => <li key={i} className="text-foreground">• {r}</li>)}
                  </ul>
                </div>
              )}
              {ep.pods?.length > 0 && (
                <div>
                  <div className="text-foreground-muted font-medium mb-1">Pods ({ep.pods.length})</div>
                  <div className="space-y-0.5">
                    {ep.pods.slice(0, 3).map((p: any, i) => (
                      <div key={i} className="flex items-center gap-1.5">
                        <span className={clsx('w-1.5 h-1.5 rounded-full shrink-0', (p.Status || p.status) === 'Running' ? 'bg-accent' : 'bg-warning')} />
                        <span className="font-mono text-foreground">{p.Name || p.name}</span>
                      </div>
                    ))}
                    {ep.pods.length > 3 && <div className="text-foreground-muted">+{ep.pods.length - 3} more</div>}
                  </div>
                </div>
              )}
              {(ep.cve_critical > 0 || ep.cve_high > 0) ? (
                <div>
                  <div className="text-foreground-muted font-medium mb-1">CVEs</div>
                  {ep.cve_critical > 0 && <div className="text-danger">{ep.cve_critical} CRITICAL</div>}
                  {ep.cve_high > 0 && <div className="text-warning">{ep.cve_high} HIGH</div>}
                </div>
              ) : <div />}
              {(ep.cve_critical > 0 || ep.cve_high > 0) && onNavigateCVE ? (
                <div className="flex items-center">
                  <button
                    onClick={e => { e.stopPropagation(); onNavigateCVE(ep.namespace) }}
                    className="btn-ghost text-xs px-2 py-1"
                  >
                    Voir tout →
                  </button>
                </div>
              ) : <div />}
              {ep.review_comment && (
                <div className="min-w-0">
                  <div className="text-foreground-muted font-medium mb-1">Comment</div>
                  <div className="text-foreground">{ep.review_comment}</div>
                </div>
              )}
            </div>
          </td>
        </tr>
      )}
    </>
  )
}

export function Endpoints({ endpoints, refresh, initialSearch, onNavigateCVE }: Props & { initialSearch?: string }) {
  const [search, setSearch] = useState(initialSearch || '')
  const [riskFilter, setRiskFilter] = useState<FilterRisk>('ALL')
  const [reviewFilter, setReviewFilter] = useState<FilterReview>('ALL')

  const filtered = endpoints.filter(ep => {
    if (riskFilter !== 'ALL' && ep.risk !== riskFilter) return false
    if (reviewFilter === 'NONE' && ep.review_status) return false
    if (reviewFilter !== 'ALL' && reviewFilter !== 'NONE' && ep.review_status !== reviewFilter) return false
    if (search) {
      const q = search.toLowerCase()
      return (
        ep.hostname?.includes(q) ||
        ep.external_ip?.includes(q) ||
        ep.namespace?.includes(q) ||
        ep.name?.includes(q)
      )
    }
    return true
  })

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold">Endpoints</h1>
          <p className="text-sm text-foreground-muted mt-0.5">{filtered.length} of {endpoints.length} endpoints</p>
        </div>
      </div>

      {/* Filters */}
      <div className="flex items-center gap-3 flex-wrap">
        <div className="relative">
          <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-foreground-muted" />
          <input
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Search endpoints..."
            className="bg-surface border border-border rounded-lg pl-9 pr-4 py-2 text-sm text-foreground placeholder:text-foreground-muted outline-none focus:border-foreground-muted/50 w-64 transition-colors"
          />
        </div>
        <div className="flex items-center gap-1">
          {(['ALL', 'HIGH', 'MEDIUM', 'LOW'] as FilterRisk[]).map(r => (
            <button
              key={r}
              onClick={() => setRiskFilter(r)}
              className={clsx(
                'px-3 py-1.5 rounded-lg text-xs font-medium transition-all duration-150',
                riskFilter === r
                  ? r === 'HIGH' ? 'bg-danger/20 text-danger border border-danger/40'
                    : r === 'MEDIUM' ? 'bg-warning/20 text-warning border border-warning/40'
                    : r === 'LOW' ? 'bg-accent/20 text-accent border border-accent/40'
                    : 'bg-surface-2 text-foreground border border-border'
                  : 'text-foreground-muted hover:text-foreground hover:bg-surface-2'
              )}
            >
              {r}
            </button>
          ))}
        </div>
        <div className="flex items-center gap-1">
          {(['ALL', 'NONE', 'TO_FIX', 'ACCEPTED', 'FALSE_POSITIVE'] as FilterReview[]).map(r => (
            <button
              key={r}
              onClick={() => setReviewFilter(r)}
              className={clsx(
                'px-3 py-1.5 rounded-lg text-xs font-medium transition-all duration-150',
                reviewFilter === r ? 'bg-surface-2 text-foreground border border-border' : 'text-foreground-muted hover:text-foreground hover:bg-surface-2'
              )}
            >
              {r === 'NONE' ? 'Unreviewed' : r === 'FALSE_POSITIVE' ? 'False Positive' : r === 'TO_FIX' ? 'To Fix' : r}
            </button>
          ))}
        </div>
      </div>

      {/* Table */}
      <div className="card p-0 overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border text-xs text-foreground-muted">
              <th className="w-4 px-4 py-3" />
              <th className="text-left px-0 py-3 pr-4 font-medium">Host / IP</th>
              <th className="text-left py-3 pr-4 font-medium">Namespace</th>
              <th className="text-left py-3 pr-4 font-medium">Type</th>
              <th className="text-left py-3 pr-4 font-medium">Risk</th>
              <th className="text-left py-3 pr-4 font-medium">Ports</th>
              <th className="text-left py-3 pr-4 font-medium">Review</th>
              <th className="text-left py-3 pr-4 font-medium">Actions</th>
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 ? (
              <tr><td colSpan={8} className="text-center py-12 text-foreground-muted text-sm">No endpoints match your filters</td></tr>
            ) : (
              filtered.map((ep, i) => <EndpointRow key={i} ep={ep} refresh={refresh} onNavigateCVE={onNavigateCVE} />)
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
