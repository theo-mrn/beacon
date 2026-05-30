package crowdsec

import "time"

// Decision représente une décision CrowdSec (IP bannie).
type Decision struct {
	ID        int       `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	Value     string    `json:"value"`   // IP ou range
	Type      string    `json:"type"`    // ban, captcha...
	Scenario  string    `json:"scenario"`
	Origin    string    `json:"origin"`  // crowdsec, cscli, console
	Scope     string    `json:"scope"`   // Ip, Range
	Duration  string    `json:"duration"`
	Simulated bool      `json:"simulated"`
}

// Alert représente une alerte CrowdSec.
type Alert struct {
	ID        int       `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	Scenario  string    `json:"scenario"`
	SourceIP  string    `json:"source_ip"`
	Country   string    `json:"country"`
	EventsCount int     `json:"events_count"`
	Simulated bool      `json:"simulated"`
}

// SrcIPCount agrège les décisions par IP source.
type SrcIPCount struct {
	IP       string `json:"ip"`
	Country  string `json:"country"`
	Count    int    `json:"count"`
	Scenario string `json:"scenario"`
}

// ScenarioCount agrège les décisions par scénario.
type ScenarioCount struct {
	Scenario string `json:"scenario"`
	Count    int    `json:"count"`
}

// EndpointRef est un résumé d'endpoint pour la corrélation.
type EndpointRef struct {
	NS   string `json:"ns"`
	Name string `json:"name"`
	URL  string `json:"url"`
	Risk string `json:"risk"`
}

// Correlation regroupe par node les endpoints exposés + décisions CrowdSec.
type Correlation struct {
	NodeIP        string        `json:"node_ip"`
	NodeName      string        `json:"node_name"`
	DecisionCount int           `json:"decision_count"`
	TopSrcIPs     []SrcIPCount  `json:"top_src_ips"`
	Endpoints     []EndpointRef `json:"endpoints"`
}

// Stats agrège toutes les données CrowdSec.
type Stats struct {
	ActiveDecisions  int             `json:"active_decisions"`
	AlertsLast24h    int             `json:"alerts_last_24h"`
	TopSrcIPs        []SrcIPCount    `json:"top_src_ips"`
	TopScenarios     []ScenarioCount `json:"top_scenarios"`
	RecentAlerts     []Alert         `json:"recent_alerts"`
	RecentDecisions  []Decision      `json:"recent_decisions"`
	Correlations     []Correlation   `json:"correlations"`
}

// EndpointInfo est passé par le server pour la corrélation.
type EndpointInfo struct {
	Namespace  string
	Name       string
	URL        string
	Risk       string
	ExternalIP string
}
