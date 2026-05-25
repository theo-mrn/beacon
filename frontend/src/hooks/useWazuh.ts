import { useState, useEffect } from 'react'
import type { WazuhStats } from '../lib/types'

export function useWazuh() {
  const [stats, setStats] = useState<WazuhStats | null>(null)
  const [loading, setLoading] = useState(true)

  const fetch = async () => {
    try {
      const r = await window.fetch('/api/wazuh')
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
