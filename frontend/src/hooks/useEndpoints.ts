import { useState, useEffect, useCallback } from 'react'
import type { ExposedEndpoint } from '../lib/types'

export function useEndpoints() {
  const [endpoints, setEndpoints] = useState<ExposedEndpoint[]>([])
  const [loading, setLoading] = useState(true)

  const fetch = useCallback(async () => {
    try {
      const r = await window.fetch('/api/endpoints')
      const data = await r.json()
      const mapped = (data ?? []).map((e: Record<string, unknown>) => ({
        namespace: e.Namespace,
        name: e.ObjectName,
        source_kind: e.SourceKind,
        hostname: e.Hostname,
        external_ip: e.ExternalIP,
        ports: e.Ports,
        tls: e.TLS,
        services: e.Services,
        pods: e.Pods,
        risk: e.Risk,
        risk_reasons: e.RiskReasons,
        status: e.Status,
        cve_critical: e.CVECritical,
        cve_high: e.CVEHigh,
        trivy_url: e.TrivyURL,
        review_status: e.ReviewStatus,
        review_comment: e.ReviewComment,
      }))
      setEndpoints(mapped)
    } catch {
      // silently retry via SSE
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    fetch()
    const es = new EventSource('/sse')
    es.onmessage = () => fetch()
    return () => es.close()
  }, [fetch])

  return { endpoints, loading, refresh: fetch }
}
