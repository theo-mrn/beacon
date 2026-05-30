import { RefreshCw, Zap, ShieldCheck, Maximize2, X } from 'lucide-react'
import { useState } from 'react'
import { MetricCard } from '../components/MetricCard'
import type { FalcoStats } from '../lib/types'
import { PieChart, Pie, Cell, Tooltip, ResponsiveContainer } from 'recharts'

interface Props {
  stats: FalcoStats | null
  loading: boolean
  refresh: () => void
}

const PRIORITY_COLOR: Record<string, string> = {
  'Notice':    '#64748b',
  'Warning':   '#EAB308',
  'Error':     '#F97316',
  'Critical':  '#EF4444',
  'Emergency': '#DC2626',
  'Alert':     '#DC2626',
}

function priorityColor(p: string): string {
  return PRIORITY_COLOR[p] ?? '#64748b'
}

const PriorityTooltip = ({ active, payload }: any) => {
  if (!active || !payload?.length) return null
  const d = payload[0]?.payload
  return (
    <div className="bg-surface-2 border border-border rounded-lg px-3 py-2 text-xs shadow-lg">
      <div style={{ color: priorityColor(d?.priority) }} className="font-semibold">{d?.priority}</div>
      <div className="font-mono text-foreground mt-0.5">{d?.count} events</div>
    </div>
  )
}

export function Falco({ stats, loading, refresh }: Props) {
  if (loading) return (
    <div className="flex items-center justify-center h-64 text-foreground-muted text-sm">
      Loading Falco data…
    </div>
  )
  if (!stats) return (
    <div className="flex flex-col items-center justify-center h-64 gap-3 text-foreground-muted">
      <Zap size={32} className="opacity-30" />
      <p className="text-sm">Falco not available — check Loki connection</p>
    </div>
  )

  const topRules = (stats.top_rules ?? []).slice(0, 6)
  const maxCount = topRules[0]?.count ?? 1

  const prioData = (stats.by_priority ?? []).map(p => ({
    priority: p.priority,
    count: p.count,
  }))

  const nodeData = (stats.node_stats ?? []).map(n => ({
    name: n.hostname,
    value: n.event_count,
  }))
  const maxNode = Math.max(...nodeData.map(d => d.value), 1)

  const alertEvents = (stats.recent_events ?? []).filter(e =>
    ['warning', 'error', 'critical', 'emergency', 'alert'].includes(e.priority?.toLowerCase())
  ).slice(0, 10)

  const [selectedEvent, setSelectedEvent] = useState<typeof alertEvents[0] | null>(null)

  return (
    <div className="space-y-6">

      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold">Falco</h1>
          <p className="text-sm text-foreground-muted mt-0.5">Runtime security — syscall monitoring (6h)</p>
        </div>
        <button onClick={refresh} className="btn-ghost"><RefreshCw size={14} />Refresh</button>
      </div>

      {/* Métriques */}
      <div className="grid grid-cols-4 gap-3">
        <MetricCard label="Total events" value={stats.total_events} />
        <MetricCard label="Critical / Emergency" value={stats.critical} color="danger" />
        <MetricCard label="Warning / Error" value={stats.warning} color="warning" />
        <MetricCard label="Règles distinctes" value={topRules.length} />
      </div>

      {/* Ligne principale */}
      <div className="grid grid-cols-3 gap-4">

        {/* Top règles — barres CSS, pas recharts */}
        <div className="col-span-2 card p-0 overflow-hidden">
          <div className="px-5 py-4 border-b border-border">
            <div className="text-sm font-semibold">Top règles déclenchées</div>
            <div className="text-xs text-foreground-muted mt-0.5">6 dernières heures</div>
          </div>
          <div className="px-5 py-4 space-y-4">
            {!topRules.length ? (
              <div className="text-xs text-foreground-muted text-center py-8">Aucun event</div>
            ) : topRules.map((r, i) => (
              <div key={i}>
                <div className="flex items-center justify-between mb-1.5">
                  <span className="text-[11px] text-foreground truncate pr-4">{r.rule}</span>
                  <span className="text-[11px] font-mono tabular-nums text-foreground-muted shrink-0">{r.count}</span>
                </div>
                <div className="h-1.5 bg-surface-2 rounded-full overflow-hidden">
                  <div
                    className="h-full rounded-full transition-all"
                    style={{
                      width: `${Math.round((r.count / maxCount) * 100)}%`,
                      backgroundColor: priorityColor(r.priority),
                      opacity: 0.7,
                    }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Colonne droite : pie + nodes */}
        <div className="flex flex-col gap-4">

          {/* Pie priorities */}
          <div className="card p-0 overflow-hidden">
            <div className="px-5 py-4 border-b border-border">
              <div className="text-sm font-semibold">Par priorité</div>
            </div>
            <div className="flex items-center gap-4 px-4 py-4">
              <ResponsiveContainer width={80} height={80}>
                <PieChart>
                  <Pie data={prioData} dataKey="count" cx="50%" cy="50%" innerRadius={22} outerRadius={38} strokeWidth={0}>
                    {prioData.map((entry, i) => (
                      <Cell key={i} fill={priorityColor(entry.priority)} />
                    ))}
                  </Pie>
                  <Tooltip content={<PriorityTooltip />} />
                </PieChart>
              </ResponsiveContainer>
              <div className="flex flex-col gap-1.5 flex-1 min-w-0">
                {prioData.map((p, i) => (
                  <div key={i} className="flex items-center gap-2">
                    <div className="w-2 h-2 rounded-full shrink-0" style={{ backgroundColor: priorityColor(p.priority) }} />
                    <span className="text-[11px] text-foreground-muted flex-1">{p.priority}</span>
                    <span className="text-[11px] font-mono tabular-nums">{p.count}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Nodes */}
          {nodeData.length > 0 && (
            <div className="card p-0 overflow-hidden">
              <div className="px-5 py-4 border-b border-border">
                <div className="text-sm font-semibold">Par node</div>
              </div>
              <div className="px-5 py-4 space-y-3">
                {nodeData.map((n, i) => (
                  <div key={i}>
                    <div className="flex items-center justify-between mb-1">
                      <span className="text-[11px] font-mono text-foreground-muted">{n.name}</span>
                      <span className="text-[11px] font-mono tabular-nums">{n.value}</span>
                    </div>
                    <div className="h-1.5 bg-surface-2 rounded-full overflow-hidden">
                      <div
                        className="h-full bg-foreground-muted/40 rounded-full"
                        style={{ width: `${Math.round((n.value / maxNode) * 100)}%` }}
                      />
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Feed Warning+ */}
      <div className="card p-0 overflow-hidden">
        <div className="px-5 py-4 border-b border-border flex items-center justify-between">
          <div>
            <div className="text-sm font-semibold">Events Warning+</div>
            <div className="text-xs text-foreground-muted mt-0.5">Notice exclus</div>
          </div>
          {alertEvents.length === 0 && (
            <div className="flex items-center gap-1.5 text-xs text-foreground-muted">
              <ShieldCheck size={13} />
              Aucun event Warning+ sur 6h
            </div>
          )}
        </div>
        {alertEvents.length > 0 ? (
          <div className="divide-y divide-border/50 max-h-72 overflow-y-auto">
            {alertEvents.map((e, i) => (
              <div key={i} className="px-5 py-3 flex items-start gap-3 hover:bg-surface-2/30 transition-colors group cursor-pointer" onClick={() => setSelectedEvent(e)}>
                <div className="w-1.5 h-1.5 rounded-full mt-1.5 shrink-0" style={{ backgroundColor: priorityColor(e.priority) }} />
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="text-[11px] font-medium">{e.rule}</span>
                    <span className="text-[10px] font-mono text-foreground-muted">{e.hostname}</span>
                  </div>
                  <div className="text-[10px] text-foreground-muted mt-0.5 truncate">{e.output}</div>
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  <span className="text-[10px] text-foreground-muted font-mono">
                    {e.timestamp ? new Date(e.timestamp).toLocaleTimeString() : ''}
                  </span>
                  <button
                    onClick={() => setSelectedEvent(e)}
                    className="opacity-0 group-hover:opacity-100 transition-opacity p-1 rounded hover:bg-surface-2"
                  >
                    <Maximize2 size={11} className="text-foreground-muted" />
                  </button>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="px-5 py-6 text-xs text-foreground-muted text-center">
            Events Notice filtrés — connexions K8S API normales.
          </div>
        )}
      </div>

      {/* Modal event complet */}
      {selectedEvent && (
        <div className="fixed inset-0 z-50 flex items-center justify-center p-6" onClick={() => setSelectedEvent(null)}>
          <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" />
          <div
            className="relative bg-surface border border-border rounded-xl w-full max-w-2xl shadow-2xl"
            onClick={e => e.stopPropagation()}
          >
            <div className="flex items-start justify-between px-5 py-4 border-b border-border">
              <div>
                <div className="flex items-center gap-2">
                  <div className="w-2 h-2 rounded-full shrink-0" style={{ backgroundColor: priorityColor(selectedEvent.priority) }} />
                  <span className="text-sm font-semibold">{selectedEvent.rule}</span>
                </div>
                <div className="flex items-center gap-3 mt-1">
                  <span className="text-[11px] font-mono text-foreground-muted">{selectedEvent.hostname}</span>
                  <span className="text-[11px]" style={{ color: priorityColor(selectedEvent.priority) }}>{selectedEvent.priority}</span>
                  {selectedEvent.timestamp && (
                    <span className="text-[11px] text-foreground-muted">{new Date(selectedEvent.timestamp).toLocaleString()}</span>
                  )}
                </div>
              </div>
              <button onClick={() => setSelectedEvent(null)} className="p-1.5 rounded hover:bg-surface-2 transition-colors">
                <X size={14} className="text-foreground-muted" />
              </button>
            </div>
            <div className="px-5 py-4">
              <div className="text-[10px] text-foreground-muted mb-2 uppercase tracking-wider">Output</div>
              <pre className="text-[11px] font-mono text-foreground bg-surface-2 rounded-lg p-4 overflow-x-auto whitespace-pre-wrap break-all leading-relaxed">
                {selectedEvent.output}
              </pre>
            </div>
            {selectedEvent.tags?.length > 0 && (
              <div className="px-5 pb-4">
                <div className="text-[10px] text-foreground-muted mb-2 uppercase tracking-wider">Tags</div>
                <div className="flex flex-wrap gap-1.5">
                  {selectedEvent.tags.map((t, i) => (
                    <span key={i} className="text-[10px] font-mono px-2 py-0.5 rounded bg-surface-2 text-foreground-muted border border-border">{t}</span>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      )}

    </div>
  )
}
