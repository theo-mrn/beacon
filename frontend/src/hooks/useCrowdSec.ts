import { useState, useEffect } from 'react'
import type { CrowdSecStats } from '../lib/types'

export function useCrowdSec() {
  const [stats, setStats] = useState<CrowdSecStats | null>(null)
  const [loading, setLoading] = useState(true)

  const fetch = async () => {
    try {
      const r = await window.fetch('/api/crowdsec')
      const data = await r.json()
      setStats(data)
    } catch {
      // ignore
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => {
    fetch()
    const id = setInterval(fetch, 30_000)
    return () => clearInterval(id)
  }, [])

  return { stats, loading, refresh: fetch }
}
