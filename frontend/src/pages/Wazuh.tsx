import { RefreshCw, ExternalLink } from 'lucide-react'
import { MetricCard } from '../components/MetricCard'
import type { WazuhStats } from '../lib/types'
import { clsx } from 'clsx'

const LEVEL_COLOR = (level: number) => {
  if (level >= 12) return 'text-danger'
  if (level >= 7) return 'text-warning'
  return 'text-foreground-muted'
}

interface Props {
  stats: WazuhStats | null
  loading: boolean
  refresh: () => void
}

export function Wazuh({ stats, loading, refresh }: Props) {
  if (loading) return <div className="flex items-center justify-center h-64 text-foreground-muted text-sm">Loading Wazuh data…</div>
  if (!stats) return <div className="flex items-center justify-center h-64 text-foreground-muted text-sm">Wazuh not available</div>

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold">Wazuh Alerts</h1>
          <p className="text-sm text-foreground-muted mt-0.5">Last 24 hours — {stats.total} total alerts</p>
        </div>
        <button onClick={refresh} className="btn-ghost"><RefreshCw size={14} />Refresh</button>
      </div>

      {/* Bento grid */}
      <div className="grid grid-cols-3 gap-3">
        <MetricCard label="Total Alerts" value={stats.total} />
        <MetricCard label="Critical (level ≥12)" value={stats.critical} color="danger" />
        <MetricCard label="High (level ≥7)" value={stats.high} color="warning" />
      </div>

      <div className="grid grid-cols-3 gap-3">
        {/* Machines sous attaque — 2 cols */}
        <div className="col-span-2 card p-0 overflow-hidden">
          <div className="px-5 py-4 border-b border-border">
            <div className="text-sm font-semibold">Machines sous attaque</div>
            <div className="text-xs text-foreground-muted mt-0.5">Nœuds K8s ciblés — les services à droite pourraient être atteints par pivot</div>
          </div>
          <div className="divide-y divide-border/50">
            {!stats.correlations?.length ? (
              <div className="px-5 py-8 text-xs text-foreground-muted text-center">Aucune corrélation détectée</div>
            ) : stats.correlations.map((c, i) => (
              <div key={i} className="grid grid-cols-2 divide-x divide-border/50">
                {/* Left: node + attackers */}
                <div className="px-5 py-4 space-y-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <div className={clsx('w-1.5 h-1.5 rounded-full animate-pulse', c.alert_count >= 100 ? 'bg-danger' : 'bg-warning')} />
                      <span className="text-sm font-semibold">{c.node_name || c.node_ip}</span>
                      <span className="font-mono text-xs text-foreground-muted">{c.node_ip}</span>
                    </div>
                    <span className={clsx('text-xs font-bold px-2 py-0.5 rounded-md', c.alert_count >= 100 ? 'bg-danger/10 text-danger' : 'bg-warning/10 text-warning')}>
                      {c.alert_count}× / 24h
                    </span>
                  </div>
                  <div className="space-y-1.5">
                    {c.top_src_ips?.slice(0, 4).map((ip, k) => (
                      <div key={k} className="flex items-center gap-2 text-xs">
                        <span className="font-mono text-foreground flex-1">{ip.ip}</span>
                        <span className="text-foreground-muted">{ip.country || '—'}</span>
                        <span className={clsx('font-bold tabular-nums w-8 text-right', c.alert_count >= 100 ? 'text-danger' : 'text-warning')}>{ip.count}</span>
                      </div>
                    ))}
                  </div>
                </div>
                {/* Right: services at risk */}
                <div className="px-5 py-4 space-y-3">
                  <div className="text-xs text-foreground-muted font-medium">Services exposés <span className="text-foreground-muted/50">(risque de pivot)</span></div>
                  {c.endpoints?.length > 0 ? (
                    <div className="space-y-1.5">
                      {c.endpoints.map((ep, j) => (
                        <div key={j} className="flex items-center gap-2 text-xs">
                          <span className={clsx('w-1.5 h-1.5 rounded-full shrink-0', ep.risk === 'HIGH' ? 'bg-danger' : ep.risk === 'MEDIUM' ? 'bg-warning' : 'bg-accent')} />
                          <span className="font-mono text-foreground flex-1">{ep.ns}/{ep.name}</span>
                          {ep.url && <a href={ep.url} target="_blank" rel="noreferrer" className="text-foreground-muted hover:text-foreground"><ExternalLink size={10} /></a>}
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="text-xs text-foreground-muted">Aucun service public exposé</div>
                  )}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Top IPs — 1 col */}
        <div className="card p-0 overflow-hidden">
          <div className="px-5 py-4 border-b border-border">
            <div className="text-sm font-semibold">Top Attacking IPs</div>
            <div className="text-xs text-foreground-muted mt-0.5">Global · 24h</div>
          </div>
          <div className="px-5 py-4 space-y-3">
            {stats.top_src_ips?.slice(0, 8).map((ip, i) => {
              const pct = Math.round((ip.count / (stats.top_src_ips[0]?.count || 1)) * 100)
              return (
                <div key={i} className="space-y-1">
                  <div className="flex items-center justify-between text-xs">
                    <span className="font-mono text-foreground">{ip.ip}</span>
                    <div className="flex items-center gap-2">
                      <span className="text-foreground-muted">{ip.country || '—'}</span>
                      <span className="font-semibold text-danger tabular-nums">{ip.count}</span>
                    </div>
                  </div>
                  <div className="h-1 bg-surface-2 rounded-full overflow-hidden">
                    <div className="h-full bg-danger/60 rounded-full" style={{ width: `${pct}%` }} />
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      </div>

      {/* Recent alerts — full width */}
      <div className="card p-0 overflow-hidden">
        <div className="px-5 py-4 border-b border-border">
          <div className="text-sm font-semibold">Alertes récentes</div>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-border text-xs text-foreground-muted">
                <th className="text-left px-5 py-3 font-medium">Level</th>
                <th className="text-left py-3 pr-4 font-medium">Règle</th>
                <th className="text-left py-3 pr-4 font-medium">Agent</th>
                <th className="text-left py-3 pr-4 font-medium">Source IP</th>
                <th className="text-left py-3 pr-4 font-medium">Pays</th>
                <th className="text-left py-3 pr-4 font-medium">MITRE</th>
                <th className="text-left py-3 pr-4 font-medium">Heure</th>
              </tr>
            </thead>
            <tbody>
              {stats.recent_alerts?.slice(0, 20).map((a, i) => (
                <tr key={i} className="border-b border-border/40 last:border-0 hover:bg-surface-2/40 transition-colors">
                  <td className="px-5 py-2.5">
                    <span className={clsx('font-mono text-xs font-bold', LEVEL_COLOR(a.rule_level))}>{a.rule_level}</span>
                  </td>
                  <td className="py-2.5 pr-4 text-xs text-foreground max-w-[200px] truncate">{a.rule_desc || a.rule_id}</td>
                  <td className="py-2.5 pr-4 text-xs text-foreground-muted">{a.agent_name}</td>
                  <td className="py-2.5 pr-4 font-mono text-xs text-foreground">{a.src_ip || '—'}</td>
                  <td className="py-2.5 pr-4 text-xs text-foreground-muted">{a.country || '—'}</td>
                  <td className="py-2.5 pr-4 text-xs text-foreground-muted">{a.mitre_tactics?.slice(0, 1).join('') || '—'}</td>
                  <td className="py-2.5 pr-4 text-xs text-foreground-muted font-mono">
                    {a.timestamp ? new Date(a.timestamp).toLocaleTimeString() : '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}
