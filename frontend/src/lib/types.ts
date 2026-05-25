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

export interface SrcIPCount {
  ip: string
  country: string
  count: number
}

export interface AgentSummary {
  agent_id: string
  agent_name: string
  agent_ip: string
  total: number
  critical: number
  high: number
  top_src_ips: SrcIPCount[]
}

export interface EndpointRef {
  ns: string
  name: string
  url: string
  risk: RiskLevel
}

export interface Correlation {
  node_ip: string
  node_name: string
  alert_count: number
  top_src_ips: SrcIPCount[]
  endpoints: EndpointRef[]
}

export interface WazuhAlert {
  id: string
  timestamp: string
  agent_id: string
  agent_name: string
  agent_ip: string
  rule_id: string
  rule_level: number
  rule_desc: string
  src_ip: string
  country: string
  mitre_tactics: string[]
  mitre_techniques: string[]
}

export interface WazuhStats {
  total: number
  critical: number
  high: number
  agents: AgentSummary[]
  top_src_ips: SrcIPCount[]
  recent_alerts: WazuhAlert[]
  correlations: Correlation[]
}
