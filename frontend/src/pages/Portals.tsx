import { useMemo, useState } from 'react'
import { ExternalLink, Lock, LockOpen, Search } from 'lucide-react'
import { RiskBadge } from '../components/RiskBadge'
import { usePortals } from '../hooks/usePortals'
import { clsx } from 'clsx'

export function Portals({ initialSearch }: { initialSearch?: string }) {
  const { portals, loading } = usePortals()
  const [search, setSearch] = useState(initialSearch || '')
  const [nsFilter, setNsFilter] = useState('ALL')

  const namespaces = useMemo(() => ['ALL', ...Array.from(new Set(portals.map(p => p.namespace))).sort()], [portals])

  const filtered = useMemo(() => portals.filter(p => {
    if (nsFilter !== 'ALL' && p.namespace !== nsFilter) return false
    if (search) {
      const q = search.toLowerCase()
      return p.hostname.toLowerCase().includes(q) || p.name.toLowerCase().includes(q) || p.namespace.toLowerCase().includes(q)
    }
    return true
  }), [portals, nsFilter, search])

  if (loading) return <div className="flex items-center justify-center h-64 text-foreground-muted text-sm">Chargement…</div>

  return (
    <div className="space-y-4">
      <div>
        <h1 className="text-xl font-bold">Portails</h1>
        <p className="text-sm text-foreground-muted mt-0.5">{filtered.length} portails accessibles</p>
      </div>

      <div className="flex items-center gap-3 flex-wrap">
        <div className="relative">
          <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-foreground-muted" />
          <input
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="Rechercher…"
            className="bg-surface border border-border rounded-lg pl-9 pr-4 py-2 text-sm text-foreground placeholder:text-foreground-muted outline-none focus:border-foreground-muted/50 w-64 transition-colors"
          />
        </div>
        <select
          value={nsFilter}
          onChange={e => setNsFilter(e.target.value)}
          className="bg-surface border border-border rounded-lg px-3 py-2 text-xs text-foreground outline-none focus:border-foreground-muted/50 transition-colors"
        >
          {namespaces.map(ns => <option key={ns} value={ns}>{ns === 'ALL' ? 'Tous les namespaces' : ns}</option>)}
        </select>
      </div>

      <div className="card p-0 overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border text-xs text-foreground-muted uppercase tracking-wide">
              <th className="text-left px-4 py-3 font-medium">Host</th>
              <th className="text-left py-3 pr-4 font-medium">Namespace</th>
              <th className="text-left py-3 pr-4 font-medium">Nom</th>
              <th className="text-left py-3 pr-4 font-medium">Risk</th>
              <th className="text-left py-3 pr-4 font-medium">TLS</th>
              <th className="py-3 pr-4" />
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 ? (
              <tr><td colSpan={6} className="text-center py-12 text-foreground-muted text-sm">Aucun portail trouvé</td></tr>
            ) : (
              filtered.map((p, i) => (
                <tr key={i} className="border-b border-border/40 last:border-0 hover:bg-surface-2/40 transition-colors">
                  <td className="px-4 py-3 font-mono text-xs text-foreground">{p.hostname || '—'}</td>
                  <td className="py-3 pr-4 text-xs text-foreground-muted">{p.namespace}</td>
                  <td className="py-3 pr-4 text-xs text-foreground-muted">{p.name}</td>
                  <td className="py-3 pr-4"><RiskBadge risk={p.risk as 'HIGH' | 'MEDIUM' | 'LOW'} /></td>
                  <td className="py-3 pr-4">
                    {p.tls
                      ? <Lock size={13} className="text-accent" />
                      : <LockOpen size={13} className="text-foreground-muted" />}
                  </td>
                  <td className="py-3 pr-4">
                    {p.url && (
                      <a href={p.url} target="_blank" rel="noreferrer"
                        className={clsx('btn-ghost text-xs px-2 py-1 flex items-center gap-1 w-fit')}>
                        <ExternalLink size={12} /> Ouvrir
                      </a>
                    )}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}
