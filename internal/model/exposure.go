package model

import "time"

type RiskLevel string

const (
	RiskLow    RiskLevel = "LOW"
	RiskMedium RiskLevel = "MEDIUM"
	RiskHigh   RiskLevel = "HIGH"
)

type ExposureType string

const (
	ExposureNodePort     ExposureType = "NodePort"
	ExposureLoadBalancer ExposureType = "LoadBalancer"
	ExposureIngress      ExposureType = "Ingress"
	ExposureIngressRoute ExposureType = "IngressRoute"
)

type ExposedPort struct {
	Port     int32
	Protocol string
	NodePort int32
}

// ServiceRef est un pointeur vers un Service K8s ciblé par un Ingress/IngressRoute.
type ServiceRef struct {
	Namespace string
	Name      string
	Port      int32
}

// PodInfo est un résumé d'un Pod derrière un Service.
type PodInfo struct {
	Name   string
	Status string // Running, Pending, CrashLoopBackOff…
}

// CVEDetail décrit une vulnérabilité individuelle issue d'un VulnerabilityReport Trivy.
type CVEDetail struct {
	ID               string  `json:"id"`
	Severity         string  `json:"severity"`
	Score            float64 `json:"score"`
	Package          string  `json:"package"`
	InstalledVersion string  `json:"installed_version"`
	FixedVersion     string  `json:"fixed_version"`
	Title            string  `json:"title"`
	PrimaryLink      string  `json:"primary_link"`
	PublishedDate    string  `json:"published_date"`
	Namespace        string  `json:"namespace"`
	App              string  `json:"app"`
	Container        string  `json:"container"`
}

// ExposedEndpoint représente un FQDN ou une IP exposée avec sa chaîne complète.
type ExposedEndpoint struct {
	// Identification
	Namespace  string
	ObjectName string       // nom de l'Ingress/IngressRoute/Service
	SourceKind ExposureType // d'où vient cet endpoint

	// Ce qui est exposé
	Hostname   string // ex: monsite.fr  (vide si LoadBalancer pur)
	ExternalIP string // ex: 217.65.146.24 (vide si Ingress pur)
	Ports      []ExposedPort
	TLS        bool

	// Chaîne de liaison
	Services []ServiceRef
	Pods     []PodInfo

	// Scoring
	Risk        RiskLevel
	RiskReasons []string

	// Tracking temporel
	DetectedAt time.Time
	FirstSeen  time.Time
	Status     string // "NEW", "MODIFIED", "" (connu)

	// Corrélation Trivy (optionnel — vide si Trivy non installé)
	CVECritical int
	CVEHigh     int
	TrivyURL    string // lien vers le dashboard Trivy

	// Annotation manuelle (false positive / accepté / à corriger)
	ReviewStatus  string // "ACCEPTED", "FALSE_POSITIVE", "TO_FIX", or ""
	ReviewComment string
}
