import { useState, useEffect } from 'react'

export interface CVEDetail {
  id: string
  severity: string
  score: number
  package: string
  installed_version: string
  fixed_version: string
  title: string
  primary_link: string
  published_date: string
  namespace: string
  app: string
  container: string
}

let _cache: CVEDetail[] | null = null
let _promise: Promise<CVEDetail[]> | null = null

function fetchCVEs(): Promise<CVEDetail[]> {
  if (_cache) return Promise.resolve(_cache)
  if (_promise) return _promise
  _promise = window.fetch('/api/cves')
    .then(r => r.json())
    .then(d => { _cache = d ?? []; return _cache! })
    .catch(() => [])
  return _promise
}

export function useCVEs() {
  const [cves, setCVEs] = useState<CVEDetail[]>(_cache ?? [])
  const [loading, setLoading] = useState(_cache === null)

  useEffect(() => {
    if (_cache) { setCVEs(_cache); setLoading(false); return }
    fetchCVEs().then(d => { setCVEs(d); setLoading(false) })
  }, [])

  return { cves, loading }
}
