import { RefreshCw, Server, ShieldCheck, AlertTriangle } from 'lucide-react'
import type { LynisStats } from '../lib/types'
import { clsx } from 'clsx'

interface Props {
  stats: LynisStats | null
  loading: boolean
  refresh: () => void
}

const indexColor = (index: number) => {
  if (index >= 80) return 'text-success'
  if (index >= 60) return 'text-warning'
  return 'text-danger'
}

const indexBg = (index: number) => {
  if (index >= 80) return 'bg-success/10'
  if (index >= 60) return 'bg-warning/10'
  return 'bg-danger/10'
}

export function Lynis({ stats, loading, refresh }: Props) {
  if (loading) return <div className="flex items-center justify-center h-64 text-foreground-muted text-sm">Loading Lynis data…</div>
  if (!stats || !stats.nodes?.length) return (
    <div className="flex flex-col items-center justify-center h-64 gap-3 text-foreground-muted">
      <ShieldCheck size={32} className="opacity-30" />
      <p className="text-sm">Aucun résultat Lynis disponible</p>
      <p className="text-xs">Le CronJob tourne chaque dimanche à 3h</p>
    </div>
  )

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold">Lynis — Hardening Audit</h1>
          <p className="text-sm text-foreground-muted mt-0.5">
            {stats.nodes.length} node{stats.nodes.length > 1 ? 's' : ''} audité{stats.nodes.length > 1 ? 's' : ''}
            {stats.last_updated && ` · Mis à jour ${new Date(stats.last_updated).toLocaleDateString()}`}
          </p>
        </div>
        <button onClick={refresh} className="btn-ghost"><RefreshCw size={14} />Refresh</button>
      </div>

      {/* Score par node */}
      <div className="grid grid-cols-2 gap-4">
        {stats.nodes.map((node, i) => (
          <div key={i} className="card p-0 overflow-hidden">
            <div className="px-5 py-4 border-b border-border flex items-center gap-3">
              <Server size={14} className="text-accent" />
              <div className="font-semibold text-sm">{node.hostname}</div>
              <div className={clsx('ml-auto text-2xl font-black', indexColor(node.hardening_index))}>
                {node.hardening_index}/100
              </div>
            </div>

            {/* Barre de progression */}
            <div className="px-5 py-3 border-b border-border">
              <div className="w-full h-2 bg-surface-2 rounded-full overflow-hidden">
                <div
                  className={clsx('h-full rounded-full transition-all', indexBg(node.hardening_index), 'border', node.hardening_index >= 80 ? 'border-success bg-success/30' : node.hardening_index >= 60 ? 'border-warning bg-warning/30' : 'border-danger bg-danger/30')}
                  style={{ width: `${node.hardening_index}%` }}
                />
              </div>
              <div className="flex justify-between text-[10px] text-foreground-muted mt-1">
                <span>{node.tests.performed} tests</span>
                <span>{node.tests.warnings} warnings</span>
              </div>
            </div>

            {/* Warnings */}
            {node.warnings?.length > 0 && (
              <div className="px-5 py-3 border-b border-border">
                <div className="flex items-center gap-1.5 mb-2">
                  <AlertTriangle size={12} className="text-warning" />
                  <span className="text-[11px] font-semibold text-warning">Warnings ({node.warnings.length})</span>
                </div>
                <ul className="space-y-1">
                  {node.warnings.slice(0, 5).map((w, j) => (
                    <li key={j} className="text-[10px] text-foreground-muted flex gap-1.5">
                      <span className="text-warning shrink-0">•</span>
                      <span>{w}</span>
                    </li>
                  ))}
                  {node.warnings.length > 5 && (
                    <li className="text-[10px] text-foreground-muted">+{node.warnings.length - 5} autres…</li>
                  )}
                </ul>
              </div>
            )}

            {/* Suggestions */}
            {node.suggestions?.length > 0 && (
              <div className="px-5 py-3">
                <div className="flex items-center gap-1.5 mb-2">
                  <ShieldCheck size={12} className="text-accent" />
                  <span className="text-[11px] font-semibold text-accent">Suggestions ({node.suggestions.length})</span>
                </div>
                <ul className="space-y-1">
                  {node.suggestions.slice(0, 5).map((s, j) => (
                    <li key={j} className="text-[10px] text-foreground-muted flex gap-1.5">
                      <span className="text-accent shrink-0">→</span>
                      <span>{s}</span>
                    </li>
                  ))}
                  {node.suggestions.length > 5 && (
                    <li className="text-[10px] text-foreground-muted">+{node.suggestions.length - 5} autres…</li>
                  )}
                </ul>
              </div>
            )}
          </div>
        ))}
      </div>
    </div>
  )
}
