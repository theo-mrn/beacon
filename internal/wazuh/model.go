package wazuh

import "time"

// Alert est une alerte Wazuh extraite d'Elasticsearch.
type Alert struct {
	ID        string    `json:"id"`
	Timestamp time.Time `json:"timestamp"`

	// Agent (nœud K8s)
	AgentID   string `json:"agent_id"`
	AgentName string `json:"agent_name"`
	AgentIP   string `json:"agent_ip"`

	// Règle
	RuleID    string `json:"rule_id"`
	RuleLevel int    `json:"rule_level"`
	RuleDesc  string `json:"rule_desc"`
	Groups    []string `json:"groups"`

	// Source de l'attaque
	SrcIP   string `json:"src_ip"`
	SrcUser string `json:"src_user"`

	// Géolocalisation
	Country string  `json:"country"`
	Region  string  `json:"region"`
	Lat     float64 `json:"lat"`
	Lon     float64 `json:"lon"`

	// MITRE
	MitreTactics   []string `json:"mitre_tactics"`
	MitreTechniques []string `json:"mitre_techniques"`

	FullLog string `json:"full_log"`
}

// AgentSummary agrège les alertes par nœud.
type AgentSummary struct {
	AgentID   string `json:"agent_id"`
	AgentName string `json:"agent_name"`
	AgentIP   string `json:"agent_ip"`
	Total     int    `json:"total"`
	Critical  int    `json:"critical"` // level >= 12
	High      int    `json:"high"`     // level >= 7
	TopSrcIPs []SrcIPCount `json:"top_src_ips"`
}

type SrcIPCount struct {
	IP      string `json:"ip"`
	Country string `json:"country"`
	Count   int    `json:"count"`
}

// EndpointRef est un résumé d'endpoint pour l'affichage dans une corrélation.
type EndpointRef struct {
	NS   string `json:"ns"`
	Name string `json:"name"`
	URL  string `json:"url"`
	Risk string `json:"risk"`
}

// Correlation regroupe par nœud tous les endpoints exposés sur ce nœud + les alertes reçues.
type Correlation struct {
	NodeIP     string        `json:"node_ip"`
	NodeName   string        `json:"node_name"`
	AlertCount int           `json:"alert_count"`
	TopSrcIPs  []SrcIPCount  `json:"top_src_ips"`
	Endpoints  []EndpointRef `json:"endpoints"`
}

// Stats globales Wazuh sur la fenêtre de temps.
type Stats struct {
	Total        int           `json:"total"`
	Critical     int           `json:"critical"`
	High         int           `json:"high"`
	Agents       []AgentSummary `json:"agents"`
	TopSrcIPs    []SrcIPCount  `json:"top_src_ips"`
	RecentAlerts []Alert       `json:"recent_alerts"`
	Correlations []Correlation `json:"correlations"`
}
