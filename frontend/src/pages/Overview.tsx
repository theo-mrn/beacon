import { MetricCard } from '../components/MetricCard'
import { RiskBadge } from '../components/RiskBadge'
import { PieChart, Pie, Cell, BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer } from 'recharts'
import type { ExposedEndpoint, WazuhStats } from '../lib/types'

interface Props {
  endpoints: ExposedEndpoint[]
  wazuh: WazuhStats | null
  onNavigate: (v: 'endpoints' | 'wazuh') => void
}

const CustomTooltip = ({ active, payload, label }: any) => {
  if (!active || !payload?.length) return null
  return (
    <div className="bg-surface-2 border border-border rounded-lg px-3 py-2 text-xs">
      <div className="text-foreground-muted mb-1">{label}</div>
      {payload.map((p: any) => (
        <div key={p.name} style={{ color: p.fill ?? p.color }} className="font-mono font-semibold">{p.value}</div>
      ))}
    </div>
  )
}

export function Overview({ endpoints, wazuh, onNavigate }: Props) {
  const high = endpoints.filter(e => e.risk === 'HIGH').length
  const medium = endpoints.filter(e => e.risk === 'MEDIUM').length
  const low = endpoints.filter(e => e.risk === 'LOW').length
  const newEps = endpoints.filter(e => e.status === 'NEW').length

  const riskData = [
    { name: 'HIGH', value: high, color: '#EF4444' },
    { name: 'MEDIUM', value: medium, color: '#F59E0B' },
    { name: 'LOW', value: low, color: '#22C55E' },
  ].filter(d => d.value > 0)

  const nsMap: Record<string, number> = {}
  endpoints.forEach(e => {
    const ns = e.namespace || 'default'
    nsMap[ns] = (nsMap[ns] ?? 0) + 1
  })
  const nsData = Object.entries(nsMap)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 6)
    .map(([name, value]) => ({ name, value }))

  const topRisk = [...endpoints].filter(e => e.risk === 'HIGH').slice(0, 5)

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-xl font-bold">Overview</h1>
        <p className="text-sm text-foreground-muted mt-0.5">Attack surface at a glance</p>
      </div>

      {/* Bento top row */}
      <div className="grid grid-cols-4 gap-3">
        <MetricCard label="Total Endpoints" value={endpoints.length} sub={newEps > 0 ? `${newEps} new` : undefined} />
        <MetricCard label="High Risk" value={high} color="danger" sub="Action immédiate" />
        <MetricCard label="Medium Risk" value={medium} color="warning" sub="À surveiller" />
        <MetricCard label="Low Risk" value={low} color="accent" sub="Sous contrôle" />
      </div>

      {/* Charts row */}
      <div className="grid grid-cols-2 gap-4">
        {/* Donut risk */}
        <div className="card flex flex-col">
          <div className="text-sm font-semibold mb-1">Risk Distribution</div>
          <div className="text-xs text-foreground-muted mb-4">Répartition par niveau de risque</div>
          {riskData.length === 0 ? (
            <div className="flex-1 flex items-center justify-center text-xs text-foreground-muted">Aucun endpoint à risque</div>
          ) : (
            <div className="flex items-center gap-6">
              <ResponsiveContainer width={160} height={160}>
                <PieChart>
                  <Pie data={riskData} cx="50%" cy="50%" innerRadius={45} outerRadius={70} dataKey="value" strokeWidth={0}>
                    {riskData.map(d => <Cell key={d.name} fill={d.color} fillOpacity={0.9} />)}
                  </Pie>
                  <Tooltip content={<CustomTooltip />} />
                </PieChart>
              </ResponsiveContainer>
              <div className="space-y-3">
                {riskData.map(d => (
                  <div key={d.name} className="flex items-center gap-2.5">
                    <span className="w-2.5 h-2.5 rounded-full shrink-0" style={{ background: d.color }} />
                    <span className="text-xs text-foreground-muted w-14">{d.name}</span>
                    <span className="text-sm font-bold tabular-nums" style={{ color: d.color }}>{d.value}</span>
                  </div>
                ))}
                <div className="pt-1 border-t border-border text-xs text-foreground-muted">
                  {endpoints.length} total
                </div>
              </div>
            </div>
          )}
        </div>

        {/* By namespace */}
        <div className="card">
          <div className="text-sm font-semibold mb-1">By Namespace</div>
          <div className="text-xs text-foreground-muted mb-4">Exposition par namespace</div>
          <ResponsiveContainer width="100%" height={160}>
            <BarChart data={nsData} barSize={20} layout="vertical" margin={{ left: 0, right: 8 }}>
              <XAxis type="number" tick={{ fontSize: 10, fill: '#888' }} axisLine={false} tickLine={false} />
              <YAxis type="category" dataKey="name" tick={{ fontSize: 11, fill: '#888' }} axisLine={false} tickLine={false} width={80} />
              <Tooltip content={<CustomTooltip />} cursor={{ fill: 'rgba(255,255,255,0.03)' }} />
              <Bar dataKey="value" fill="#475569" fillOpacity={0.9} radius={[0, 4, 4, 0]} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Second bento row — Wazuh + top risk */}
      <div className={wazuh ? 'grid grid-cols-3 gap-4' : 'grid grid-cols-1 gap-4'}>
        {/* Top HIGH endpoints */}
        {topRisk.length > 0 && (
          <div className={`card ${wazuh ? 'col-span-2' : ''} p-0 overflow-hidden`}>
            <div className="flex items-center justify-between px-5 py-4 border-b border-border">
              <div>
                <div className="text-sm font-semibold">High Risk Endpoints</div>
                <div className="text-xs text-foreground-muted">Nécessitent une action immédiate</div>
              </div>
              <button onClick={() => onNavigate('endpoints')} className="btn-ghost text-xs">Voir tout</button>
            </div>
            <table className="w-full text-sm">
              <thead>
                <tr className="text-xs text-foreground-muted border-b border-border">
                  <th className="text-left px-5 py-2.5 font-medium">Endpoint</th>
                  <th className="text-left py-2.5 pr-4 font-medium">Namespace</th>
                  <th className="text-left py-2.5 pr-4 font-medium">Risk</th>
                  <th className="text-left py-2.5 pr-4 font-medium">Raisons</th>
                </tr>
              </thead>
              <tbody>
                {topRisk.map((ep, i) => (
                  <tr key={i} className="border-b border-border/40 last:border-0 hover:bg-surface-2/40 transition-colors">
                    <td className="px-5 py-2.5 font-mono text-xs text-foreground">{ep.hostname || ep.external_ip || ep.name || '—'}</td>
                    <td className="py-2.5 pr-4 text-xs text-foreground-muted">{ep.namespace}</td>
                    <td className="py-2.5 pr-4"><RiskBadge risk={ep.risk} /></td>
                    <td className="py-2.5 pr-4 text-xs text-foreground-muted">{ep.risk_reasons?.slice(0, 1).join(', ') || '—'}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        {/* Wazuh summary */}
        {wazuh && (
          <div className="card space-y-4">
            <div className="flex items-center justify-between">
              <div>
                <div className="text-sm font-semibold">Wazuh</div>
                <div className="text-xs text-foreground-muted">Dernières 24h</div>
              </div>
              <button onClick={() => onNavigate('wazuh')} className="btn-ghost text-xs">Détails</button>
            </div>
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-xs text-foreground-muted">Total alertes</span>
                <span className="text-sm font-bold tabular-nums">{wazuh.total}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-xs text-foreground-muted">Critical (≥12)</span>
                <span className="text-sm font-bold text-danger tabular-nums">{wazuh.critical}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-xs text-foreground-muted">High (≥7)</span>
                <span className="text-sm font-bold text-warning tabular-nums">{wazuh.high}</span>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-xs text-foreground-muted">Nœuds sous attaque</span>
                <span className="text-sm font-bold tabular-nums">{wazuh.correlations?.length ?? 0}</span>
              </div>
            </div>
            {wazuh.top_src_ips?.length > 0 && (
              <div className="pt-3 border-t border-border space-y-2">
                <div className="text-xs text-foreground-muted font-medium">Top attaquants</div>
                {wazuh.top_src_ips.slice(0, 3).map((ip, i) => {
                  const pct = Math.round((ip.count / (wazuh.top_src_ips[0]?.count || 1)) * 100)
                  return (
                    <div key={i} className="space-y-0.5">
                      <div className="flex items-center justify-between text-xs">
                        <span className="font-mono text-foreground">{ip.ip}</span>
                        <span className="text-danger font-semibold">{ip.count}</span>
                      </div>
                      <div className="h-1 bg-surface-2 rounded-full overflow-hidden">
                        <div className="h-full bg-danger/60 rounded-full" style={{ width: `${pct}%` }} />
                      </div>
                    </div>
                  )
                })}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
