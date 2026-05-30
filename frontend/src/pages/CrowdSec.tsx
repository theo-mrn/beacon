import { RefreshCw, Shield, ShieldCheck, TrendingUp } from 'lucide-react'
import { MetricCard } from '../components/MetricCard'
import type { CrowdSecStats } from '../lib/types'
import {
  BarChart, Bar, XAxis, YAxis, Tooltip, ResponsiveContainer, Cell
} from 'recharts'

interface Props {
  stats: CrowdSecStats | null
  loading: boolean
  refresh: () => void
}

// Badge coloré selon le type de scénario
function scenarioColor(scenario: string): string {
  const s = scenario.toLowerCase()
  if (s.includes('bruteforce') || s.includes('brute')) return '#EF4444'
  if (s.includes('exploit') || s.includes('cve')) return '#F97316'
  if (s.includes('scan') || s.includes('probe')) return '#EAB308'
  if (s.includes('crawl')) return '#A855F7'
  if (s.includes('ssh')) return '#3B82F6'
  return '#64748B'
}

function scenarioLabel(scenario: string): string {
  const s = scenario.toLowerCase()
  if (s.includes('bruteforce') || s.includes('brute')) return 'Brute Force'
  if (s.includes('exploit') || s.includes('cve')) return 'Exploit'
  if (s.includes('scan') || s.includes('probe')) return 'Scan'
  if (s.includes('crawl')) return 'Crawl'
  if (s.includes('ssh')) return 'SSH'
  if (s.includes('http')) return 'HTTP'
  return scenario.split(':')[1] ?? scenario
}

const CustomTooltip = ({ active, payload, label }: any) => {
  if (!active || !payload?.length) return null
  return (
    <div className="bg-surface-2 border border-border rounded-lg px-3 py-2 text-xs shadow-lg">
      <div className="text-foreground-muted mb-1 truncate max-w-[160px]">{label}</div>
      <div className="font-mono font-bold" style={{ color: payload[0]?.fill }}>
        {payload[0]?.value?.toLocaleString()} décisions
      </div>
    </div>
  )
}

export function CrowdSec({ stats, loading, refresh }: Props) {
  if (loading) return (
    <div className="flex items-center justify-center h-64 text-foreground-muted text-sm">
      Loading CrowdSec data…
    </div>
  )
  if (!stats) return (
    <div className="flex flex-col items-center justify-center h-64 gap-3 text-foreground-muted">
      <Shield size={32} className="opacity-30" />
      <p className="text-sm">CrowdSec not available — check CROWDSEC_API_KEY</p>
    </div>
  )

  // Préparer les données du bar chart scénarios
  const scenarioData = (stats.top_scenarios ?? []).map(s => ({
    name: scenarioLabel(s.scenario),
    full: s.scenario,
    value: s.count,
    color: scenarioColor(s.scenario),
  }))


  return (
    <div className="space-y-6">

      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold">CrowdSec</h1>
          <p className="text-sm text-foreground-muted mt-0.5">Protection réseau — IPS actif</p>
        </div>
        <button onClick={refresh} className="btn-ghost"><RefreshCw size={14} />Refresh</button>
      </div>

      {/* Métriques */}
      <div className="grid grid-cols-4 gap-3">
        <MetricCard label="Détections locales" value={stats.local_decisions} color="danger" />
        <MetricCard label="Alertes 24h" value={stats.alerts_last_24h} color="warning" />
        <MetricCard label="Threat intel" value={stats.community_decisions.toLocaleString()} />
        <MetricCard label="Scénarios" value={stats.top_scenarios?.length ?? 0} />
      </div>

      {/* Zone principale : chart scénarios + alertes récentes */}
      <div className="grid grid-cols-3 gap-4">

        {/* Bar chart scénarios — 2 cols */}
        <div className="col-span-2 card p-0 overflow-hidden">
          <div className="px-5 py-4 border-b border-border flex items-center gap-2">
            <TrendingUp size={14} className="text-accent" />
            <div>
              <div className="text-sm font-semibold">Répartition par scénario</div>
              <div className="text-xs text-foreground-muted mt-0.5">Nombre de décisions par type d'attaque</div>
            </div>
          </div>
          <div className="px-4 py-5">
            {!scenarioData.length ? (
              <div className="flex items-center justify-center h-40 text-xs text-foreground-muted">Aucun scénario</div>
            ) : (
              <ResponsiveContainer width="100%" height={200}>
                <BarChart data={scenarioData} layout="vertical" barSize={16} margin={{ left: 8, right: 32, top: 0, bottom: 0 }}>
                  <XAxis type="number" tick={{ fontSize: 10, fill: '#64748b' }} axisLine={false} tickLine={false} tickFormatter={v => v.toLocaleString()} />
                  <YAxis type="category" dataKey="name" tick={{ fontSize: 11, fill: '#94a3b8', fontFamily: 'monospace' }} axisLine={false} tickLine={false} width={72} />
                  <Tooltip content={<CustomTooltip />} cursor={{ fill: 'rgba(255,255,255,0.03)' }} />
                  <Bar dataKey="value" radius={[0, 4, 4, 0]}>
                    {scenarioData.map((entry, i) => (
                      <Cell key={i} fill={entry.color} fillOpacity={0.8} />
                    ))}
                  </Bar>
                </BarChart>
              </ResponsiveContainer>
            )}
          </div>
        </div>

        {/* Alertes récentes — 1 col */}
        <div className="card p-0 overflow-hidden">
          <div className="px-5 py-4 border-b border-border">
            <div className="text-sm font-semibold">Alertes récentes</div>
            <div className="text-xs text-foreground-muted mt-0.5">Dernières 24h</div>
          </div>
          <div className="divide-y divide-border/50 overflow-y-auto max-h-64">
            {!stats.recent_alerts?.length ? (
              <div className="px-5 py-8 text-xs text-foreground-muted text-center">
                <ShieldCheck size={20} className="mx-auto mb-2 text-accent opacity-50" />
                Aucune alerte
              </div>
            ) : stats.recent_alerts.slice(0, 8).map((a, i) => (
              <div key={i} className="px-4 py-2.5">
                <div className="flex items-start justify-between gap-2">
                  <div
                    className="w-1.5 h-1.5 rounded-full mt-1.5 shrink-0"
                    style={{ backgroundColor: scenarioColor(a.scenario) }}
                  />
                  <div className="flex-1 min-w-0">
                    <div className="text-[11px] font-mono truncate">{a.source_ip}</div>
                    <div className="text-[10px] text-foreground-muted truncate">{scenarioLabel(a.scenario)}</div>
                  </div>
                  <div className="text-[10px] text-foreground-muted shrink-0">
                    {a.events_count}ev
                  </div>
                </div>
              </div>
            ))}
          </div>
        </div>

      </div>


    </div>
  )
}
