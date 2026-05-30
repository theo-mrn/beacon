import { useState, useEffect } from 'react'
import type { FalcoStats } from '../lib/types'

export function useFalco() {
  const [stats, setStats] = useState<FalcoStats | null>(null)
  const [loading, setLoading] = useState(true)

  const fetch = async () => {
    try {
      const r = await window.fetch('/api/falco')
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
    const id = setInterval(fetch, 60_000)
    return () => clearInterval(id)
  }, [])

  return { stats, loading, refresh: fetch }
}
