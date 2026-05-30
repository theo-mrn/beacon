import { useState, useEffect } from 'react'
import type { LynisStats } from '../lib/types'

export function useLynis() {
  const [stats, setStats] = useState<LynisStats | null>(null)
  const [loading, setLoading] = useState(true)

  const fetch = async () => {
    try {
      const r = await window.fetch('/api/lynis')
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
    const id = setInterval(fetch, 3_600_000) // 1h — lynis tourne 1x/semaine
    return () => clearInterval(id)
  }, [])

  return { stats, loading, refresh: fetch }
}
