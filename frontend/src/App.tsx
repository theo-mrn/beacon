import { useState, useEffect } from 'react'
import { Sidebar, type View } from './components/Sidebar'
import { CommandPalette } from './components/CommandPalette'
import { Overview } from './pages/Overview'
import { Endpoints } from './pages/Endpoints'
import { Portals } from './pages/Portals'
import { CVEs } from './pages/CVEs'
import { Wazuh } from './pages/Wazuh'
import { Reviews } from './pages/Reviews'
import { Topology } from './pages/Topology'
import { useEndpoints } from './hooks/useEndpoints'
import { useWazuh } from './hooks/useWazuh'
import { useCVEs } from './hooks/useCVEs'
import { usePortals } from './hooks/usePortals'
import './index.css'

export default function App() {
  const [view, setView] = useState<View>('overview')
  const [searchOpen, setSearchOpen] = useState(false)
  const [searchQuery, setSearchQuery] = useState<string | undefined>(undefined)
  const [cveFilter, setCveFilter] = useState<{ ns: string; app: string } | undefined>(undefined)

  const { endpoints, loading: epLoading, refresh } = useEndpoints()
  const { stats: wazuh, loading: wzLoading, refresh: wzRefresh } = useWazuh()
  useCVEs()
  const { portals } = usePortals()

  const counts = {
    high: endpoints.filter(e => e.risk === 'HIGH').length,
    medium: endpoints.filter(e => e.risk === 'MEDIUM').length,
    low: endpoints.filter(e => e.risk === 'LOW').length,
  }

  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === 'k') { e.preventDefault(); setSearchOpen(true) }
    }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [])

  const handleNavigate = (v: View, query?: string) => {
    setView(v)
    setSearchQuery(query)
  }

  return (
    <div className="flex min-h-screen bg-background">
      <Sidebar view={view} onChange={v => { setView(v); setSearchQuery(undefined) }} counts={counts} liveCount={endpoints.length} onSearch={() => setSearchOpen(true)} />

      <CommandPalette
        open={searchOpen}
        onClose={() => setSearchOpen(false)}
        onNavigate={handleNavigate}
        endpoints={endpoints}
        portals={portals}
      />

      <main className="ml-56 flex-1 p-8 min-h-screen">
        {epLoading ? (
          <div className="flex items-center justify-center h-64 text-foreground-muted text-sm">Loading…</div>
        ) : (
          <>
            {view === 'overview' && <Overview endpoints={endpoints} wazuh={wazuh} onNavigate={setView} />}
            {view === 'endpoints' && <Endpoints endpoints={endpoints} refresh={refresh} initialSearch={searchQuery} onNavigateCVE={(ns) => { setCveFilter({ ns, app: 'ALL' }); setView('cves') }} />}
            {view === 'portals' && <Portals initialSearch={searchQuery} />}
            {view === 'cves' && <CVEs initialSearch={searchQuery} initialNs={cveFilter?.ns} initialApp={cveFilter?.app} />}
            {view === 'wazuh' && <Wazuh stats={wazuh} loading={wzLoading} refresh={wzRefresh} />}
            {view === 'reviews' && <Reviews endpoints={endpoints} refresh={refresh} />}
            {view === 'topology' && <Topology endpoints={endpoints} />}
          </>
        )}
      </main>
    </div>
  )
}
