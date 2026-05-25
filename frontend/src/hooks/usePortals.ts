import { useState, useEffect } from 'react'

export interface Portal {
  name: string
  namespace: string
  hostname: string
  url: string
  tls: boolean
  risk: string
}

let _cache: Portal[] | null = null

export function usePortals() {
  const [portals, setPortals] = useState<Portal[]>(_cache ?? [])
  const [loading, setLoading] = useState(_cache === null)

  useEffect(() => {
    if (_cache) { setPortals(_cache); setLoading(false); return }
    window.fetch('/api/portals')
      .then(r => r.json())
      .then(d => { _cache = d ?? []; setPortals(_cache!) })
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [])

  return { portals, loading }
}
