import { LayoutDashboard, Globe, Shield, CheckSquare, Radar, ExternalLink, Bug, Search } from 'lucide-react'
import { clsx } from 'clsx'

export type View = 'overview' | 'endpoints' | 'portals' | 'cves' | 'wazuh' | 'reviews'

const nav = [
  { id: 'overview', label: 'Overview', icon: LayoutDashboard },
  { id: 'endpoints', label: 'Endpoints', icon: Globe },
  { id: 'portals', label: 'Portails', icon: ExternalLink },
  { id: 'cves', label: 'CVEs', icon: Bug },
  { id: 'wazuh', label: 'Wazuh Alerts', icon: Shield },
  { id: 'reviews', label: 'Reviews', icon: CheckSquare },
] as const

interface Props {
  view: View
  onChange: (v: View) => void
  counts?: { high: number; medium: number; low: number }
  liveCount: number
  onSearch: () => void
}

export function Sidebar({ view, onChange, counts, onSearch }: Props) {
  return (
    <aside className="fixed left-0 top-0 h-screen w-56 bg-sidebar border-r border-border flex flex-col z-20">
      {/* Logo */}
      <div className="px-4 py-5 border-b border-border">
        <div className="flex items-center gap-2.5">
          <div className="p-1.5 rounded-lg bg-accent/10 text-accent">
            <Radar size={18} />
          </div>
          <div>
            <div className="text-sm font-bold tracking-tight">Beacon</div>
            <div className="text-[10px] text-foreground-muted">K8s Surface Scanner</div>
          </div>
        </div>
      </div>

      {/* Search bar */}
      <div className="px-3 py-3 border-b border-border">
        <button
          onClick={onSearch}
          className="w-full flex items-center gap-2 px-3 py-2 rounded-lg bg-surface-2 border border-border text-foreground-muted text-xs hover:border-foreground-muted/40 transition-colors"
        >
          <Search size={13} />
          <span className="flex-1 text-left">Search</span>
          <kbd className="px-1.5 py-0.5 rounded text-[10px] bg-surface border border-border font-mono">⌘K</kbd>
        </button>
      </div>

      {/* Nav */}
      <nav className="flex-1 p-3 flex flex-col gap-1">
        {nav.map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            onClick={() => onChange(id as View)}
            className={clsx('nav-item text-left w-full', view === id && 'active')}
          >
            <Icon size={16} />
            {label}
          </button>
        ))}
      </nav>

    </aside>
  )
}
