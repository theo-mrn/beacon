import { useState, useEffect, useRef, useMemo } from 'react'
import { Search, X, ExternalLink, Bug, Globe, Shield, FileCheck } from 'lucide-react'
import { clsx } from 'clsx'
import type { ExposedEndpoint } from '../lib/types'
import type { Portal } from '../hooks/usePortals'
import type { View } from './Sidebar'

interface Result {
  id: string
  type: 'cve' | 'endpoint' | 'portal' | 'nav'
  label: string
  sub?: string
  badge?: string
  badgeColor?: string
  url?: string
  view?: View
  query?: string
}

interface Props {
  open: boolean
  onClose: () => void
  onNavigate: (view: View, query?: string) => void
  endpoints: ExposedEndpoint[]
  portals: Portal[]
}

const NAV_ITEMS = [
  { id: 'overview', label: 'Overview', icon: Shield },
  { id: 'endpoints', label: 'Endpoints', icon: Globe },
  { id: 'portals', label: 'Portails', icon: ExternalLink },
  { id: 'cves', label: 'CVEs', icon: Bug },
  { id: 'wazuh', label: 'Wazuh Alerts', icon: Shield },
  { id: 'reviews', label: 'Reviews', icon: FileCheck },
]

const TYPE_ICON: Record<string, React.ElementType> = {
  cve: Bug,
  endpoint: Globe,
  portal: ExternalLink,
  nav: Shield,
}

const TYPE_LABEL: Record<string, string> = {
  cve: 'CVE',
  endpoint: 'Endpoint',
  portal: 'Portail',
  nav: 'Navigation',
}

type CVERow = { id: string; severity: string; title: string; primary_link: string; package?: string }
let _cveCache: CVERow[] | null = null
let _cveFetch: Promise<CVERow[]> | null = null
function getCVEs(): Promise<CVERow[]> {
  if (_cveCache) return Promise.resolve(_cveCache)
  if (_cveFetch) return _cveFetch
  _cveFetch = window.fetch('/api/cves').then(r => r.json()).then(d => { _cveCache = d ?? []; return _cveCache! }).catch(() => [])
  return _cveFetch
}

export function CommandPalette({ open, onClose, onNavigate, endpoints, portals }: Props) {
  const [query, setQuery] = useState('')
  const [selected, setSelected] = useState(0)
  const [cveResults, setCveResults] = useState<CVERow[]>([])
  const inputRef = useRef<HTMLInputElement>(null)
  const listRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    if (open) { setTimeout(() => inputRef.current?.focus(), 50); setQuery(''); setSelected(0); setCveResults([]) }
  }, [open])

  // Preload CVEs when palette opens
  useEffect(() => { if (open) getCVEs() }, [open])

  // Filter CVEs on query change
  useEffect(() => {
    const q = query.trim().toLowerCase()
    if (!q) { setCveResults([]); return }
    getCVEs().then(all => {
      const exact: CVERow[] = []
      const partial: CVERow[] = []
      const seen = new Set<string>()
      for (const c of all) {
        if (seen.has(c.id)) continue
        seen.add(c.id)
        if (c.id.toLowerCase() === q) exact.unshift(c)
        else if (c.id.toLowerCase().includes(q)) exact.push(c)
        else if (c.title?.toLowerCase().includes(q)) partial.push(c)
      }
      setCveResults([...exact, ...partial].slice(0, 8))
    })
  }, [query])

  const results = useMemo((): Result[] => {
    const q = query.trim().toLowerCase()
    if (!q) return NAV_ITEMS.map(n => ({ id: n.id, type: 'nav' as const, label: n.label, view: n.id as View }))

    const out: Result[] = []

    // CVEs from async fetch
    cveResults.forEach(c => out.push({
        id: c.id,
        type: 'cve',
        label: c.id,
        sub: c.title || c.package,
        badge: c.severity,
        badgeColor: c.severity === 'CRITICAL' ? 'text-danger' : c.severity === 'HIGH' ? 'text-warning' : 'text-foreground-muted',
        view: 'cves',
        query: c.id,
        url: `https://nvd.nist.gov/vuln/detail/${c.id}`,
      }))

    // Endpoints
    endpoints
      .filter(e => e.hostname?.toLowerCase().includes(q) || e.name?.toLowerCase().includes(q) || e.namespace?.toLowerCase().includes(q) || e.external_ip?.toLowerCase().includes(q))
      .slice(0, 5)
      .forEach(e => out.push({
        id: `ep-${e.namespace}-${e.name}`,
        type: 'endpoint',
        label: e.hostname || e.external_ip || e.name,
        sub: `${e.namespace} · ${e.source_kind}`,
        badge: e.risk,
        badgeColor: e.risk === 'HIGH' ? 'text-danger' : e.risk === 'MEDIUM' ? 'text-warning' : 'text-accent',
        view: 'endpoints',
        query: e.hostname || e.name,
      }))

    // Portals
    portals
      .filter(p => p.hostname.toLowerCase().includes(q) || p.name.toLowerCase().includes(q) || p.namespace.toLowerCase().includes(q))
      .slice(0, 4)
      .forEach(p => out.push({
        id: `portal-${p.namespace}-${p.name}`,
        type: 'portal',
        label: p.hostname || p.name,
        sub: p.namespace,
        badge: p.risk,
        badgeColor: p.risk === 'HIGH' ? 'text-danger' : p.risk === 'MEDIUM' ? 'text-warning' : 'text-accent',
        view: 'portals',
        url: p.url,
      }))

    // Nav
    NAV_ITEMS
      .filter(n => n.label.toLowerCase().includes(q))
      .forEach(n => out.push({ id: n.id, type: 'nav', label: n.label, view: n.id as View }))

    return out
  }, [query, cveResults, endpoints, portals])

  useEffect(() => { setSelected(0) }, [results])

  useEffect(() => {
    if (!open) return
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'ArrowDown') { e.preventDefault(); setSelected(s => Math.min(s + 1, results.length - 1)) }
      if (e.key === 'ArrowUp') { e.preventDefault(); setSelected(s => Math.max(s - 1, 0)) }
      if (e.key === 'Enter') { e.preventDefault(); select(results[selected]) }
      if (e.key === 'Escape') onClose()
    }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [open, results, selected])

  const select = (r: Result) => {
    if (!r) return
    if (r.url && r.type === 'portal') { window.open(r.url, '_blank'); onClose(); return }
    onNavigate(r.view!, r.query)
    onClose()
  }

  if (!open) return null

  const grouped = results.reduce<Record<string, Result[]>>((acc, r) => {
    acc[r.type] = acc[r.type] || []
    acc[r.type].push(r)
    return acc
  }, {})

  const order = ['nav', 'cve', 'endpoint', 'portal']
  let globalIdx = 0

  return (
    <div className="fixed inset-0 z-50 flex items-start justify-center pt-20">
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={onClose} />
      <div className="relative bg-surface border border-border rounded-2xl w-full max-w-xl shadow-2xl overflow-hidden">
        {/* Input */}
        <div className="flex items-center gap-3 px-4 py-3.5 border-b border-border">
          <Search size={15} className="text-foreground-muted shrink-0" />
          <input
            ref={inputRef}
            value={query}
            onChange={e => setQuery(e.target.value)}
            placeholder="Rechercher une CVE, un endpoint, un portail…"
            className="flex-1 bg-transparent text-sm text-foreground placeholder:text-foreground-muted outline-none"
          />
          {query && <button onClick={() => setQuery('')} className="text-foreground-muted hover:text-foreground"><X size={14} /></button>}
          <kbd className="px-1.5 py-0.5 rounded text-[10px] bg-surface-2 border border-border font-mono text-foreground-muted">esc</kbd>
        </div>

        {/* Results */}
        <div ref={listRef} className="max-h-96 overflow-y-auto p-2">
          {results.length === 0 && (
            <div className="text-center py-8 text-xs text-foreground-muted">Aucun résultat</div>
          )}
          {order.map(type => {
            const items = grouped[type]
            if (!items?.length) return null
            return (
              <div key={type} className="mb-1">
                <div className="px-3 py-1.5 text-[10px] uppercase tracking-wider text-foreground-muted/60 font-medium">
                  {TYPE_LABEL[type]}
                </div>
                {items.map(r => {
                  const idx = globalIdx++
                  const Icon = TYPE_ICON[r.type]
                  return (
                    <button
                      key={r.id}
                      onClick={() => select(r)}
                      onMouseEnter={() => setSelected(idx)}
                      className={clsx(
                        'w-full flex items-center gap-3 px-3 py-2.5 rounded-lg text-left transition-colors',
                        selected === idx ? 'bg-surface-2' : 'hover:bg-surface-2/60'
                      )}
                    >
                      <Icon size={14} className="text-foreground-muted shrink-0" />
                      <div className="flex-1 min-w-0">
                        <div className="text-sm text-foreground font-mono truncate">{r.label}</div>
                        {r.sub && <div className="text-xs text-foreground-muted truncate">{r.sub}</div>}
                      </div>
                      {r.badge && <span className={clsx('text-xs font-semibold shrink-0', r.badgeColor)}>{r.badge}</span>}
                      {r.url && <ExternalLink size={11} className="text-foreground-muted shrink-0" />}
                    </button>
                  )
                })}
              </div>
            )
          })}
        </div>

        <div className="px-4 py-2 border-t border-border flex items-center gap-4 text-[10px] text-foreground-muted">
          <span><kbd className="font-mono">↑↓</kbd> naviguer</span>
          <span><kbd className="font-mono">↵</kbd> ouvrir</span>
          <span><kbd className="font-mono">esc</kbd> fermer</span>
        </div>
      </div>
    </div>
  )
}
