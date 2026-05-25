import { useMemo, useState } from 'react'
import {
  ReactFlow,
  Background,
  Controls,
  MiniMap,
  Handle,
  Position,
  type NodeProps,
} from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import dagre from 'dagre'
import { Lock, LockOpen, Box, Cpu, Router } from 'lucide-react'
import type { ExposedEndpoint } from '../lib/types'
import { useTopology } from '../hooks/useTopology'
import { clsx } from 'clsx'

const NODE_W = 220
const NODE_H = 90

function layoutGraph(nodes: any[], edges: any[]) {
  try {
    const g = new dagre.graphlib.Graph()
    g.setGraph({ rankdir: 'LR', nodesep: 50, ranksep: 100, marginx: 40, marginy: 40 })
    g.setDefaultEdgeLabel(() => ({}))
    nodes.forEach(n => g.setNode(n.id, { width: NODE_W, height: NODE_H }))
    edges.forEach(e => g.setEdge(e.source, e.target))
    dagre.layout(g)
    return nodes.map(n => {
      const pos = g.node(n.id)
      if (!pos) return n
      return { ...n, position: { x: pos.x - NODE_W / 2, y: pos.y - NODE_H / 2 } }
    })
  } catch {
    return nodes
  }
}

// ── Node components ──────────────────────────────────────────────────────────

function IngressNode({ data }: NodeProps) {
  const d = data as any
  const riskColor =
    d.risk === 'HIGH' ? 'border-danger/60 bg-danger/10' :
    d.risk === 'MEDIUM' ? 'border-warning/60 bg-warning/10' :
    'border-accent/40 bg-accent/5'
  const riskText =
    d.risk === 'HIGH' ? 'text-danger' :
    d.risk === 'MEDIUM' ? 'text-warning' : 'text-accent'

  return (
    <div className={clsx('rounded-xl border px-4 py-3 w-[220px] bg-surface shadow-lg', riskColor)}>
      <Handle type="target" position={Position.Left} style={{ background: '#475569', width: 8, height: 8 }} />
      <Handle type="source" position={Position.Right} style={{ background: '#475569', width: 8, height: 8 }} />
      <div className="text-[9px] uppercase tracking-widest text-foreground-muted/50 mb-1">{d.source_kind || 'Ingress'}</div>
      <div className="flex items-center gap-2 mb-1">
        {d.tls ? <Lock size={11} className="text-accent shrink-0" /> : <LockOpen size={11} className="text-foreground-muted shrink-0" />}
        <span className="text-xs font-bold text-foreground truncate">{d.label}</span>
      </div>
      <div className="text-[10px] text-foreground-muted font-mono truncate mb-2">{d.namespace}</div>
      <div className="flex items-center gap-1 flex-wrap">
        <span className={clsx('text-[10px] font-semibold px-1.5 py-0.5 rounded border', riskColor, riskText)}>{d.risk}</span>
        {d.cve_critical > 0 && (
          <span className="text-[10px] font-semibold px-1.5 py-0.5 rounded border border-danger/40 bg-danger/10 text-danger">{d.cve_critical} CRIT</span>
        )}
        {d.cve_high > 0 && (
          <span className="text-[10px] font-semibold px-1.5 py-0.5 rounded border border-warning/40 bg-warning/10 text-warning">{d.cve_high} HIGH</span>
        )}
      </div>
    </div>
  )
}

function ServiceNode({ data }: NodeProps) {
  const d = data as any
  return (
    <div className="rounded-xl border border-border bg-surface px-4 py-3 w-[220px] shadow-lg">
      <Handle type="target" position={Position.Left} style={{ background: '#475569', width: 8, height: 8 }} />
      <Handle type="source" position={Position.Right} style={{ background: '#475569', width: 8, height: 8 }} />
      <div className="text-[9px] uppercase tracking-widest text-foreground-muted/50 mb-1">Service</div>
      <div className="flex items-center gap-2 mb-1">
        <Box size={11} className="text-foreground-muted shrink-0" />
        <span className="text-xs font-bold text-foreground truncate">{d.label}</span>
      </div>
      <div className="text-[10px] text-foreground-muted font-mono truncate">{d.namespace}</div>
      {d.port && <div className="text-[10px] text-foreground-muted mt-0.5">port {d.port}</div>}
    </div>
  )
}

function PodNode({ data }: NodeProps) {
  const d = data as any
  const running = (d.status || '') === 'Running'
  return (
    <div className="rounded-xl border border-border bg-surface px-4 py-3 w-[220px] shadow-lg">
      <Handle type="target" position={Position.Left} style={{ background: '#475569', width: 8, height: 8 }} />
      <div className="text-[9px] uppercase tracking-widest text-foreground-muted/50 mb-1">Pod</div>
      <div className="flex items-center gap-2 mb-1">
        <span className={clsx('w-2 h-2 rounded-full shrink-0', running ? 'bg-accent' : 'bg-warning')} />
        <Cpu size={11} className="text-foreground-muted shrink-0" />
        <span className="text-xs font-mono text-foreground truncate">{d.label}</span>
      </div>
      <div className="text-[10px] text-foreground-muted">{running ? 'Running' : d.status || 'Unknown'}</div>
    </div>
  )
}

function ControllerNode({ data }: NodeProps) {
  const d = data as any
  return (
    <div className="rounded-xl border border-accent/40 bg-accent/5 px-4 py-3 w-[220px] shadow-lg">
      <Handle type="source" position={Position.Right} style={{ background: '#475569', width: 8, height: 8 }} />
      <div className="text-[9px] uppercase tracking-widest text-foreground-muted/50 mb-1">Ingress Controller</div>
      <div className="flex items-center gap-2 mb-1">
        <Router size={11} className="text-accent shrink-0" />
        <span className="text-xs font-bold text-foreground truncate">{d.label}</span>
      </div>
      <div className="text-[10px] text-foreground-muted font-mono truncate">{d.namespace}</div>
      <div className="flex items-center gap-1.5 mt-1.5">
        <span className={clsx('w-1.5 h-1.5 rounded-full', d.ready ? 'bg-accent' : 'bg-warning')} />
        <span className="text-[10px] text-foreground-muted">{d.ready ? 'Ready' : 'Not ready'}</span>
      </div>
    </div>
  )
}

const nodeTypes = { ingress: IngressNode, service: ServiceNode, pod: PodNode, controller: ControllerNode }

// ── Graph builder ─────────────────────────────────────────────────────────────

export function Topology({ endpoints: propEndpoints }: { endpoints?: ExposedEndpoint[] }) {
  const { controllers, endpoints: fetchedEndpoints, loading } = useTopology()
  const endpoints = fetchedEndpoints.length > 0 ? fetchedEndpoints : (propEndpoints ?? [])
  const namespaces = useMemo(() => ['ALL', ...Array.from(new Set(endpoints.map(e => e.namespace))).sort()], [endpoints])
  const [nsFilter, setNsFilter] = useState('ALL')

  const filtered = useMemo(() =>
    nsFilter === 'ALL' ? endpoints : endpoints.filter(e => e.namespace === nsFilter),
    [endpoints, nsFilter]
  )

  const { nodes, edges } = useMemo(() => {
    const rawNodes: any[] = []
    const edges: any[] = []
    const seenNodes = new Set<string>()
    const seenEdges = new Set<string>()

    const addNode = (id: string, type: string, data: any, extra?: any) => {
      if (!seenNodes.has(id)) {
        seenNodes.add(id)
        rawNodes.push({ id, type, position: { x: 0, y: 0 }, data, width: NODE_W, height: NODE_H, ...extra })
      }
    }

    const addEdge = (source: string, target: string, animated = false, color = '#475569') => {
      const id = `${source}→${target}`
      if (!seenEdges.has(id)) {
        seenEdges.add(id)
        edges.push({ id, source, target, animated, style: { stroke: color, strokeWidth: 1.5 } })
      }
    }

    // Un seul nœud par kind de controller
    const ctrlByKind = new Map<string, typeof controllers[0]>()
    for (const ctrl of controllers) {
      if (!ctrlByKind.has(ctrl.kind)) ctrlByKind.set(ctrl.kind, ctrl)
    }
    for (const ctrl of ctrlByKind.values()) {
      const ctrlId = `controller:${ctrl.kind}`
      addNode(ctrlId, 'controller', {
        label: ctrl.kind,
        namespace: ctrl.namespace,
        ready: ctrl.ready,
      })
    }

    for (const ep of filtered) {
      const ingressId = `ingress:${ep.namespace}/${ep.name}`

      addNode(ingressId, 'ingress', {
        label: ep.hostname || ep.external_ip || ep.name,
        namespace: ep.namespace,
        source_kind: ep.source_kind,
        risk: ep.risk,
        tls: ep.tls,
        cve_critical: ep.cve_critical,
        cve_high: ep.cve_high,
      })

      const edgeColor = ep.risk === 'HIGH' ? '#EF4444' : ep.risk === 'MEDIUM' ? '#F59E0B' : '#475569'
      const animated = ep.risk === 'HIGH'

      // Connecte au premier controller disponible
      if (ctrlByKind.size > 0) {
        const ctrl = ctrlByKind.values().next().value!
        const ctrlId = `controller:${ctrl.kind}`
        addEdge(ctrlId, ingressId, animated, edgeColor === '#475569' ? '#6b7280' : edgeColor)
      }

      const services = ep.services?.filter((s: any) => s.name || s.Name) ?? []
      const pods = ep.pods ?? []

      if (services.length > 0) {
        for (const svc of services) {
          const svcName = (svc as any).Name || svc.name
          const svcNs = (svc as any).Namespace || svc.namespace || ep.namespace
          const svcPort = (svc as any).Port || svc.port
          const svcId = `service:${svcNs}/${svcName}`
          addNode(svcId, 'service', { label: svcName, namespace: svcNs, port: svcPort })
          addEdge(ingressId, svcId, animated, edgeColor)
          for (const pod of pods) {
            const podName = (pod as any).Name || pod.name
            const podStatus = (pod as any).Status || pod.status
            const podId = `pod:${ep.namespace}/${podName}`
            addNode(podId, 'pod', { label: podName, status: podStatus })
            addEdge(svcId, podId, false, '#475569')
          }
        }
      } else {
        for (const pod of pods) {
          const podName = (pod as any).Name || pod.name
          const podStatus = (pod as any).Status || pod.status
          const podId = `pod:${ep.namespace}/${podName}`
          addNode(podId, 'pod', { label: podName, status: podStatus })
          addEdge(ingressId, podId, animated, edgeColor)
        }
      }
    }

    const nodes = layoutGraph(rawNodes, edges)
    return { nodes, edges }
  }, [filtered, controllers])

  if (loading && endpoints.length === 0) return <div className="flex items-center justify-center h-64 text-foreground-muted text-sm">Loading…</div>

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-bold">Topology</h1>
          <p className="text-sm text-foreground-muted mt-0.5">Attack surface graph — Controller → Ingress → Service → Pod</p>
        </div>
      </div>

      <div className="flex items-center gap-3 flex-wrap">
        <select
          value={nsFilter}
          onChange={e => setNsFilter(e.target.value)}
          className="bg-surface border border-border rounded-lg px-3 py-2 text-xs text-foreground outline-none focus:border-foreground-muted/50 transition-colors"
        >
          {namespaces.map(ns => <option key={ns} value={ns}>{ns === 'ALL' ? 'Tous les namespaces' : ns}</option>)}
        </select>
      </div>

      <div className="card p-0 overflow-hidden" style={{ height: 'calc(100vh - 200px)' }}>
        <ReactFlow
          nodes={nodes}
          edges={edges}
          nodeTypes={nodeTypes}
          fitView
          fitViewOptions={{ padding: 0.15 }}
          minZoom={0.1}
          maxZoom={2}
          proOptions={{ hideAttribution: true }}
        >
          <Background color="#2a2a2a" gap={20} />
          <Controls style={{ background: 'var(--surface)', border: '1px solid var(--border)' }} />
          <MiniMap
            nodeColor={n => {
              if (n.type === 'ingress') {
                const r = (n.data as any).risk
                return r === 'HIGH' ? '#EF4444' : r === 'MEDIUM' ? '#F59E0B' : '#22C55E'
              }
              if (n.type === 'group') return 'transparent'
              return '#475569'
            }}
            style={{ background: '#111', border: '1px solid #222' }}
          />
        </ReactFlow>
      </div>
    </div>
  )
}
