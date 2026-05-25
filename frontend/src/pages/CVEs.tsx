import { useState, useMemo } from 'react'

const cveLink = (id: string) => `https://nvd.nist.gov/vuln/detail/${id}`
import { ExternalLink, Search, ChevronLeft, ChevronRight } from 'lucide-react'
import { useCVEs } from '../hooks/useCVEs'
import { clsx } from 'clsx'

const SEV_STYLE: Record<string, string> = {
  CRITICAL: 'bg-danger/15 text-danger border border-danger/30',
  HIGH: 'bg-warning/15 text-warning border border-warning/30',
  MEDIUM: 'bg-accent/15 text-accent border border-accent/30',
  LOW: 'bg-foreground-muted/10 text-foreground-muted border border-foreground-muted/20',
}

const SEV_ORDER: Record<string, number> = { CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3 }
const PAGE_SIZE = 50

export function CVEs({ initialSearch, initialNs, initialApp }: { initialSearch?: string; initialNs?: string; initialApp?: string }) {
  const { cves, loading } = useCVEs()
  const [search, setSearch] = useState(initialSearch || '')
  const [sevFilter, setSevFilter] = useState('ALL')
  const [nsFilter, setNsFilter] = useState(initialNs || 'ALL')
  const [appFilter, setAppFilter] = useState(initialApp || 'ALL')
  const [page, setPage] = useState(0)

  const namespaces = useMemo(() => ['ALL', ...Array.from(new Set(cves.map(c => c.namespace))).sort()], [cves])
  const apps = useMemo(() => ['ALL', ...Array.from(new Set(cves.filter(c => nsFilter === 'ALL' || c.namespace === nsFilter).map(c => c.app))).sort()], [cves, nsFilter])

  const counts = useMemo(() => ({
    CRITICAL: cves.filter(c => c.severity === 'CRITICAL').length,
    HIGH: cves.filter(c => c.severity === 'HIGH').length,
    MEDIUM: cves.filter(c => c.severity === 'MEDIUM').length,
  }), [cves])

  const filtered = useMemo(() => cves
    .filter(c => {
      if (sevFilter !== 'ALL' && c.severity !== sevFilter) return false
      if (nsFilter !== 'ALL' && c.namespace !== nsFilter) return false
      if (appFilter !== 'ALL' && c.app !== appFilter) return false
      if (search) {
        const q = search.toLowerCase()
        return c.id.toLowerCase().includes(q) || c.title.toLowerCase().includes(q) ||
          c.package.toLowerCase().includes(q) || c.app.toLowerCase().includes(q) ||
          c.namespace.toLowerCase().includes(q)
      }
      return true
    })
    .sort((a, b) => (SEV_ORDER[a.severity] ?? 9) - (SEV_ORDER[b.severity] ?? 9) || b.score - a.score),
    [cves, sevFilter, nsFilter, appFilter, search]
  )

  const totalPages = Math.ceil(filtered.length / PAGE_SIZE)
  const pageItems = filtered.slice(page * PAGE_SIZE, (page + 1) * PAGE_SIZE)

  const handleFilter = (s: string) => { setSevFilter(s); setPage(0) }
  const handleNs = (s: string) => { setNsFilter(s); setAppFilter('ALL'); setPage(0) }
  const handleApp = (s: string) => { setAppFilter(s); setPage(0) }
  const handleSearch = (v: string) => { setSearch(v); setPage(0) }

  if (loading) return <div className="flex items-center justify-center h-64 text-foreground-muted text-sm">Chargement…</div>

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold">CVEs</h1>
          <p className="text-sm text-foreground-muted mt-0.5">
            {counts.CRITICAL} critical · {counts.HIGH} high · {filtered.length} résultats sur {cves.length}
          </p>
        </div>
      </div>

      <div className="flex items-center gap-3 flex-wrap">
        <div className="relative">
          <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-foreground-muted" />
          <input
            value={search}
            onChange={e => handleSearch(e.target.value)}
            placeholder="CVE ID, package, app…"
            className="bg-surface border border-border rounded-lg pl-9 pr-4 py-2 text-sm text-foreground placeholder:text-foreground-muted outline-none focus:border-foreground-muted/50 w-64 transition-colors"
          />
        </div>
        <select
          value={nsFilter}
          onChange={e => handleNs(e.target.value)}
          className="bg-surface border border-border rounded-lg px-3 py-2 text-xs text-foreground outline-none focus:border-foreground-muted/50 transition-colors"
        >
          {namespaces.map(ns => <option key={ns} value={ns}>{ns === 'ALL' ? 'Tous les namespaces' : ns}</option>)}
        </select>
        <select
          value={appFilter}
          onChange={e => handleApp(e.target.value)}
          className="bg-surface border border-border rounded-lg px-3 py-2 text-xs text-foreground outline-none focus:border-foreground-muted/50 transition-colors"
        >
          {apps.map(a => <option key={a} value={a}>{a === 'ALL' ? 'Toutes les apps' : a}</option>)}
        </select>
        <div className="flex items-center gap-1">
          {(['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const).map(s => (
            <button
              key={s}
              onClick={() => handleFilter(s)}
              className={clsx(
                'px-3 py-1.5 rounded-lg text-xs font-medium transition-all duration-150',
                sevFilter === s
                  ? s === 'CRITICAL' ? 'bg-danger/20 text-danger border border-danger/40'
                    : s === 'HIGH' ? 'bg-warning/20 text-warning border border-warning/40'
                    : s === 'MEDIUM' ? 'bg-accent/20 text-accent border border-accent/40'
                    : 'bg-surface-2 text-foreground border border-border'
                  : 'text-foreground-muted hover:text-foreground hover:bg-surface-2'
              )}
            >
              {s}
            </button>
          ))}
        </div>
      </div>

      <div className="card p-0 overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-border text-xs text-foreground-muted uppercase tracking-wide">
              <th className="text-left px-4 py-3 font-medium">Sévérité</th>
              <th className="text-left py-3 pr-4 font-medium">Score</th>
              <th className="text-left py-3 pr-4 font-medium">CVE</th>
              <th className="text-left py-3 pr-4 font-medium">Titre / App</th>
              <th className="text-left py-3 pr-4 font-medium">Package</th>
              <th className="text-left py-3 pr-4 font-medium">Namespace</th>
              <th className="text-left py-3 pr-4 font-medium">Fix</th>
            </tr>
          </thead>
          <tbody>
            {pageItems.length === 0 ? (
              <tr><td colSpan={7} className="text-center py-12 text-foreground-muted text-sm">Aucun CVE trouvé</td></tr>
            ) : (
              pageItems.map((c, i) => (
                <tr key={i} className="border-b border-border/40 last:border-0 hover:bg-surface-2/40 transition-colors">
                  <td className="px-4 py-3">
                    <span className={clsx('inline-flex items-center px-2 py-0.5 rounded-md text-xs font-semibold', SEV_STYLE[c.severity] ?? SEV_STYLE.LOW)}>
                      {c.severity}
                    </span>
                  </td>
                  <td className="py-3 pr-4">
                    {c.score > 0
                      ? <span className={clsx('text-sm font-bold', c.score >= 9 ? 'text-danger' : c.score >= 7 ? 'text-warning' : 'text-foreground-muted')}>{c.score.toFixed(1)}</span>
                      : <span className="text-xs text-foreground-muted">—</span>}
                  </td>
                  <td className="py-3 pr-4">
                    <a href={cveLink(c.id)} target="_blank" rel="noreferrer"
                      className="font-mono text-xs text-accent hover:underline flex items-center gap-1">
                      {c.id} <ExternalLink size={10} />
                    </a>
                  </td>
                  <td className="py-3 pr-4 max-w-xs">
                    <div className="text-xs text-foreground leading-snug line-clamp-2">{c.title}</div>
                    <div className="text-xs text-foreground-muted mt-0.5">{c.app} · {c.container}</div>
                  </td>
                  <td className="py-3 pr-4">
                    <div className="font-mono text-xs text-foreground">{c.package}</div>
                    <div className="font-mono text-xs text-foreground-muted">{c.installed_version}</div>
                  </td>
                  <td className="py-3 pr-4 text-xs text-foreground-muted">{c.namespace}</td>
                  <td className="py-3 pr-4">
                    {c.fixed_version
                      ? <span className="inline-flex items-center px-2 py-0.5 rounded-md text-xs font-medium bg-accent/15 text-accent border border-accent/30">{c.fixed_version}</span>
                      : <span className="text-xs text-foreground-muted">—</span>}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>

        {totalPages > 1 && (
          <div className="flex items-center justify-between px-4 py-3 border-t border-border">
            <span className="text-xs text-foreground-muted">
              Page {page + 1} / {totalPages} · {filtered.length} résultats
            </span>
            <div className="flex items-center gap-1">
              <button
                onClick={() => setPage(p => Math.max(0, p - 1))}
                disabled={page === 0}
                className="btn-ghost px-2 py-1 disabled:opacity-30"
              >
                <ChevronLeft size={14} />
              </button>
              <button
                onClick={() => setPage(p => Math.min(totalPages - 1, p + 1))}
                disabled={page >= totalPages - 1}
                className="btn-ghost px-2 py-1 disabled:opacity-30"
              >
                <ChevronRight size={14} />
              </button>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
