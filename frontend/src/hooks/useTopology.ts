import { useState, useEffect } from 'react'
import type { ExposedEndpoint } from '../lib/types'

export interface IngressController {
  name: string
  namespace: string
  kind: string
  pod_name: string
  ready: boolean
}

interface TopologyData {
  controllers: IngressController[]
  endpoints: ExposedEndpoint[]
}

export function useTopology() {
  const [data, setData] = useState<TopologyData>({ controllers: [], endpoints: [] })
  const [loading, setLoading] = useState(true)

  useEffect(() => {
    fetch('/api/topology')
      .then(r => r.ok ? r.json() : Promise.reject(r.status))
      .then(d => {
        setData({
          controllers: (d.controllers ?? []).map((c: any) => ({
          name: c.Name || c.name,
          namespace: c.Namespace || c.namespace,
          kind: c.Kind || c.kind,
          pod_name: c.PodName || c.pod_name,
          ready: c.Ready ?? c.ready ?? false,
        })),
          endpoints: (d.endpoints ?? []).map((e: any) => ({
            namespace: e.Namespace, name: e.ObjectName, source_kind: e.SourceKind,
            hostname: e.Hostname, external_ip: e.ExternalIP, ports: e.Ports,
            tls: e.TLS, risk: e.Risk, risk_reasons: e.RiskReasons,
            services: e.Services, pods: e.Pods,
            cve_critical: e.CVECritical, cve_high: e.CVEHigh,
            status: e.Status, review_status: e.ReviewStatus, review_comment: e.ReviewComment,
            trivy_url: e.TrivyURL,
          })),
        })
      })
      .catch(() => {})
      .finally(() => setLoading(false))
  }, [])

  return { ...data, loading }
}
