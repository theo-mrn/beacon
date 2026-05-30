import { useState, useEffect } from 'react'
import { Sidebar, type View } from './components/Sidebar'
import { CommandPalette } from './components/CommandPalette'
import { Overview } from './pages/Overview'
import { Endpoints } from './pages/Endpoints'
import { Portals } from './pages/Portals'
import { CVEs } from './pages/CVEs'
import { CrowdSec } from './pages/CrowdSec'
import { Falco } from './pages/Falco'
import { Lynis } from './pages/Lynis'
import { Reviews } from './pages/Reviews'
import { Topology } from './pages/Topology'
import { useEndpoints } from './hooks/useEndpoints'
import { useCrowdSec } from './hooks/useCrowdSec'
import { useFalco } from './hooks/useFalco'
import { useLynis } from './hooks/useLynis'
import { useCVEs } from './hooks/useCVEs'
import { usePortals } from './hooks/usePortals'
import './index.css'

export default function App() {
  const [view, setView] = useState<View>('overview')
  const [searchOpen, setSearchOpen] = useState(false)
  const [searchQuery, setSearchQuery] = useState<string | undefined>(undefined)
  const [cveFilter, setCveFilter] = useState<{ ns: string; app: string } | undefined>(undefined)

  const { endpoints, loading: epLoading, refresh } = useEndpoints()
  const { stats: crowdsec, loading: csLoading, refresh: csRefresh } = useCrowdSec()
  const { stats: falco, loading: falcoLoading, refresh: falcoRefresh } = useFalco()
  const { stats: lynis, loading: lynisLoading, refresh: lynisRefresh } = useLynis()
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

      <main className="ml-56 flex-1 p-8 min-h-screen min-w-0 overflow-x-hidden">
        {epLoading ? (
          <div className="flex items-center justify-center h-64 text-foreground-muted text-sm">Loading…</div>
        ) : (
          <>
            {view === 'overview'  && <Overview endpoints={endpoints} wazuh={null} onNavigate={setView} />}
            {view === 'endpoints' && <Endpoints endpoints={endpoints} refresh={refresh} initialSearch={searchQuery} onNavigateCVE={(ns) => { setCveFilter({ ns, app: 'ALL' }); setView('cves') }} />}
            {view === 'portals'   && <Portals initialSearch={searchQuery} />}
            {view === 'cves'      && <CVEs initialSearch={searchQuery} initialNs={cveFilter?.ns} initialApp={cveFilter?.app} />}
            {view === 'crowdsec'  && <CrowdSec stats={crowdsec} loading={csLoading} refresh={csRefresh} />}
            {view === 'falco'     && <Falco stats={falco} loading={falcoLoading} refresh={falcoRefresh} />}
            {view === 'lynis'     && <Lynis stats={lynis} loading={lynisLoading} refresh={lynisRefresh} />}
            {view === 'reviews'   && <Reviews endpoints={endpoints} refresh={refresh} />}
            {view === 'topology'  && <Topology endpoints={endpoints} />}
          </>
        )}
      </main>
    </div>
  )
}
