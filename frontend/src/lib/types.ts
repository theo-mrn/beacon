export type RiskLevel = 'HIGH' | 'MEDIUM' | 'LOW'
export type ReviewStatus = 'ACCEPTED' | 'FALSE_POSITIVE' | 'TO_FIX' | ''

export interface ExposedPort {
  port: number
  protocol: string
  node_port?: number
}

export interface PodRef {
  name: string
  status: string
}

export interface ServiceRef {
  namespace: string
  name: string
  port: number
}

export interface ExposedEndpoint {
  source_kind: string
  namespace: string
  name: string
  hostname: string
  external_ip: string
  ports: ExposedPort[]
  tls: boolean
  risk: RiskLevel
  risk_reasons: string[]
  status: string
  pods: PodRef[]
  services: ServiceRef[]
  cve_critical: number
  cve_high: number
  trivy_url: string
  review_status: ReviewStatus
  review_comment: string
}

// ── CrowdSec ──────────────────────────────────────────────────────────────────

export interface SrcIPCount {
  ip: string
  country: string
  count: number
  scenario: string
}

export interface ScenarioCount {
  scenario: string
  count: number
}

export interface EndpointRef {
  ns: string
  name: string
  url: string
  risk: RiskLevel
}

export interface CrowdSecCorrelation {
  node_ip: string
  node_name: string
  decision_count: number
  top_src_ips: SrcIPCount[]
  endpoints: EndpointRef[]
}

export interface CrowdSecDecision {
  id: number
  value: string
  type: string
  scenario: string
  origin: string
  scope: string
  duration: string
}

export interface CrowdSecAlert {
  id: number
  created_at: string
  scenario: string
  source_ip: string
  country: string
  events_count: number
}

export interface CrowdSecStats {
  active_decisions: number
  local_decisions: number
  community_decisions: number
  alerts_last_24h: number
  top_src_ips: SrcIPCount[]
  top_scenarios: ScenarioCount[]
  recent_alerts: CrowdSecAlert[]
  recent_decisions: CrowdSecDecision[]
  correlations: CrowdSecCorrelation[]
}

// ── Falco ─────────────────────────────────────────────────────────────────────

export interface FalcoEvent {
  timestamp: string
  priority: string
  rule: string
  hostname: string
  source: string
  output: string
  tags: string[]
}

export interface FalcoRuleCount {
  rule: string
  count: number
  priority: string
}

export interface FalcoPriorityCount {
  priority: string
  count: number
}

export interface FalcoNodeStat {
  hostname: string
  event_count: number
  top_rules: string[]
  namespaces: string[]
}

export interface FalcoStats {
  total_events: number
  critical: number
  warning: number
  top_rules: FalcoRuleCount[]
  by_priority: FalcoPriorityCount[]
  recent_events: FalcoEvent[]
  node_stats: FalcoNodeStat[]
}

// ── Lynis ─────────────────────────────────────────────────────────────────────

export interface LynisNodeResult {
  hostname: string
  scanned_at: string
  hardening_index: number
  warnings: string[]
  suggestions: string[]
  tests: {
    performed: number
    passed: number
    failed: number
    warnings: number
  }
}

export interface LynisStats {
  nodes: LynisNodeResult[]
  last_updated: string
}
