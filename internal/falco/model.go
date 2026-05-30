package falco

import "time"

// Event représente un événement Falco stocké dans Loki.
type Event struct {
	Timestamp time.Time `json:"timestamp"`
	Priority  string    `json:"priority"`  // Notice, Warning, Error, Critical, Emergency
	Rule      string    `json:"rule"`
	Hostname  string    `json:"hostname"`
	Source    string    `json:"source"`
	Output    string    `json:"output"`
	Tags      []string  `json:"tags"`
}

// RuleCount agrège les events par règle.
type RuleCount struct {
	Rule     string `json:"rule"`
	Count    int    `json:"count"`
	Priority string `json:"priority"`
}

// PriorityCount agrège les events par priorité.
type PriorityCount struct {
	Priority string `json:"priority"`
	Count    int    `json:"count"`
}

// NamespaceCount agrège les events par namespace K8s.
type NamespaceCount struct {
	Namespace string `json:"namespace"`
	Count     int    `json:"count"`
}

// NodeCorrelation regroupe les events Falco par hostname × endpoints.
type NodeCorrelation struct {
	Hostname    string   `json:"hostname"`
	EventCount  int      `json:"event_count"`
	TopRules    []string `json:"top_rules"`
	Namespaces  []string `json:"namespaces"`
}

// Stats agrège toutes les données Falco sur la fenêtre de temps.
type Stats struct {
	TotalEvents    int              `json:"total_events"`
	Critical       int              `json:"critical"`
	Warning        int              `json:"warning"`
	TopRules       []RuleCount      `json:"top_rules"`
	ByPriority     []PriorityCount  `json:"by_priority"`
	RecentEvents   []Event          `json:"recent_events"`
	NodeStats      []NodeCorrelation `json:"node_stats"`
}
