package scorer

import (
	_ "embed"
	"fmt"
	"os"
	"strings"

	"github.com/theo-mrn/beacon/internal/model"
	"gopkg.in/yaml.v3"
)

//go:embed scoring.yaml
var defaultConfig []byte

// ExternalConfigPath est le chemin lu en priorité (monté via ConfigMap en prod).
const ExternalConfigPath = "/etc/beacon/scoring.yaml"

// ── Config structs ────────────────────────────────────────────────────────────

type PortRule struct {
	Port int32  `yaml:"port"`
	Name string `yaml:"name"`
	Risk string `yaml:"risk"`
}

type WebhookConfig struct {
	Slack   string `yaml:"slack"`
	Teams   string `yaml:"teams"`
	Discord string `yaml:"discord"`
	Generic string `yaml:"generic"`
}

type CVEScoringConfig struct {
	CriticalCountHigh int `yaml:"critical_count_high"`
	HighCountMedium   int `yaml:"high_count_medium"`
	HighCountHigh     int `yaml:"high_count_high"`
}

type Config struct {
	Ports            []PortRule        `yaml:"ports"`
	ExposureDefaults map[string]string `yaml:"exposure_defaults"`
	Webhooks         WebhookConfig     `yaml:"webhooks"`
	PortalExclude    []string          `yaml:"portal_exclude"`
	CVEScoring       CVEScoringConfig  `yaml:"cve_scoring"`
	NoTLSPenalty     bool              `yaml:"no_tls_penalty"`
}

// ── Scorer ────────────────────────────────────────────────────────────────────

type Scorer struct {
	portRules     map[int32]PortRule
	typeDefaults  map[string]model.RiskLevel
	webhooks      WebhookConfig
	portalExclude []string
	cveScoring    CVEScoringConfig
	noTLSPenalty  bool
}

func (s *Scorer) Webhooks() WebhookConfig { return s.webhooks }

func (s *Scorer) IsPortalVisible(hostname string) bool {
	for _, pattern := range s.portalExclude {
		if strings.Contains(hostname, pattern) {
			return false
		}
	}
	return true
}

// Default est le scorer chargé depuis le fichier externe si présent, sinon l'embarqué.
var Default = mustLoadAuto()

func mustLoadAuto() *Scorer {
	if data, err := os.ReadFile(ExternalConfigPath); err == nil {
		if s, err := Load(data); err == nil {
			fmt.Printf("scorer: config chargée depuis %s\n", ExternalConfigPath)
			return s
		} else {
			fmt.Printf("scorer: %s invalide (%v), fallback embarqué\n", ExternalConfigPath, err)
		}
	}
	return mustLoad(defaultConfig)
}

func mustLoad(data []byte) *Scorer {
	s, err := Load(data)
	if err != nil {
		panic(fmt.Sprintf("scorer: invalid scoring.yaml: %v", err))
	}
	return s
}

// Load parse un YAML de config et retourne un Scorer.
func Load(data []byte) (*Scorer, error) {
	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	portRules := make(map[int32]PortRule, len(cfg.Ports))
	for _, r := range cfg.Ports {
		portRules[r.Port] = r
	}

	typeDefaults := make(map[string]model.RiskLevel, len(cfg.ExposureDefaults))
	for k, v := range cfg.ExposureDefaults {
		typeDefaults[k] = toRisk(v)
	}

	// Valeurs par défaut pour CVE scoring si non configurées
	cve := cfg.CVEScoring
	if cve.CriticalCountHigh == 0 {
		cve.CriticalCountHigh = 1
	}
	if cve.HighCountMedium == 0 {
		cve.HighCountMedium = 3
	}
	if cve.HighCountHigh == 0 {
		cve.HighCountHigh = 10
	}

	return &Scorer{
		portRules:     portRules,
		typeDefaults:  typeDefaults,
		webhooks:      cfg.Webhooks,
		portalExclude: cfg.PortalExclude,
		cveScoring:    cve,
		noTLSPenalty:  cfg.NoTLSPenalty,
	}, nil
}

// ScoreReasons contient le niveau de risque final et les raisons qui l'expliquent.
type ScoreReasons struct {
	Level   model.RiskLevel
	Reasons []string
}

// Score calcule le niveau de risque d'un endpoint — multi-facteurs.
func (s *Scorer) Score(ep *model.ExposedEndpoint) model.RiskLevel {
	return s.ScoreWithReasons(ep).Level
}

// ScoreWithReasons retourne le score ET les raisons détaillées.
func (s *Scorer) ScoreWithReasons(ep *model.ExposedEndpoint) ScoreReasons {
	risk := model.RiskLow
	var reasons []string

	// 1. Score de base selon le type d'exposition
	if def, ok := s.typeDefaults[string(ep.SourceKind)]; ok {
		risk = maxRisk(risk, def)
	}

	// 2. Port sensible exposé directement
	for _, p := range ep.Ports {
		if rule, ok := s.portRules[p.Port]; ok {
			r := toRisk(rule.Risk)
			if riskOrder(r) > riskOrder(risk) {
				risk = r
				reasons = append(reasons, fmt.Sprintf("Port sensible exposé : %s (%d)", rule.Name, p.Port))
			}
		}
	}

	// 3. Port sensible + pas de TLS → CRITICAL immédiat
	hasSensitivePort := false
	for _, p := range ep.Ports {
		if _, ok := s.portRules[p.Port]; ok {
			hasSensitivePort = true
			break
		}
	}
	if hasSensitivePort && !ep.TLS {
		risk = model.RiskHigh
		reasons = append(reasons, "Port sensible sans TLS")
	}

	// 4. Base de données/service interne exposé via Ingress (accès web direct)
	if ep.SourceKind == model.ExposureIngress || ep.SourceKind == model.ExposureIngressRoute {
		for _, p := range ep.Ports {
			if _, ok := s.portRules[p.Port]; ok {
				risk = model.RiskHigh
				reasons = append(reasons, "Service interne exposé via Ingress web")
				break
			}
		}
	}

	// 5. CVE scoring
	if ep.CVECritical >= s.cveScoring.CriticalCountHigh {
		if riskOrder(model.RiskHigh) > riskOrder(risk) {
			reasons = append(reasons, fmt.Sprintf("%d CVE CRITICAL", ep.CVECritical))
		}
		risk = maxRisk(risk, model.RiskHigh)
	}
	if ep.CVEHigh >= s.cveScoring.HighCountHigh {
		if riskOrder(model.RiskHigh) > riskOrder(risk) {
			reasons = append(reasons, fmt.Sprintf("%d CVE HIGH", ep.CVEHigh))
		}
		risk = maxRisk(risk, model.RiskHigh)
	} else if ep.CVEHigh >= s.cveScoring.HighCountMedium {
		if riskOrder(model.RiskMedium) > riskOrder(risk) {
			reasons = append(reasons, fmt.Sprintf("%d CVE HIGH", ep.CVEHigh))
		}
		risk = maxRisk(risk, model.RiskMedium)
	}

	// 6. Pas de TLS sur Ingress/IngressRoute → +1 niveau
	if s.noTLSPenalty && !ep.TLS {
		if ep.SourceKind == model.ExposureIngress || ep.SourceKind == model.ExposureIngressRoute {
			upgraded := upgradeRisk(risk)
			if riskOrder(upgraded) > riskOrder(risk) {
				reasons = append(reasons, "Pas de TLS")
				risk = upgraded
			}
		}
	}

	// 7. Service sans aucun pod running → zombie
	if len(ep.Pods) > 0 {
		running := 0
		for _, p := range ep.Pods {
			if p.Status == "Running" {
				running++
			}
		}
		if running == 0 {
			risk = maxRisk(risk, model.RiskMedium)
			reasons = append(reasons, "Aucun pod running (service zombie)")
		}
	}

	// 8. NodePort exposé directement (sans proxy/WAF)
	if ep.SourceKind == model.ExposureNodePort {
		risk = maxRisk(risk, model.RiskMedium)
		reasons = append(reasons, "NodePort exposé directement sans proxy")
	}

	return ScoreReasons{Level: risk, Reasons: reasons}
}

func maxRisk(a, b model.RiskLevel) model.RiskLevel {
	if riskOrder(a) >= riskOrder(b) {
		return a
	}
	return b
}

func upgradeRisk(r model.RiskLevel) model.RiskLevel {
	switch r {
	case model.RiskLow:
		return model.RiskMedium
	case model.RiskMedium:
		return model.RiskHigh
	default:
		return model.RiskHigh
	}
}

func riskOrder(r model.RiskLevel) int {
	switch r {
	case model.RiskHigh:
		return 2
	case model.RiskMedium:
		return 1
	default:
		return 0
	}
}

// PortName retourne le nom d'un port sensible, ou "".
func (s *Scorer) PortName(port int32) string {
	if rule, ok := s.portRules[port]; ok {
		return rule.Name
	}
	return ""
}

// Rules expose la config chargée (utile pour affichage).
func (s *Scorer) Rules() Config {
	ports := make([]PortRule, 0, len(s.portRules))
	for _, r := range s.portRules {
		ports = append(ports, r)
	}
	return Config{Ports: ports}
}

// ── Helpers package-level (compatibilité avec server.go) ─────────────────────

func Score(ep *model.ExposedEndpoint) model.RiskLevel {
	return Default.Score(ep)
}

func SensitivePortName(port int32) string {
	return Default.PortName(port)
}

func toRisk(s string) model.RiskLevel {
	switch s {
	case "HIGH":
		return model.RiskHigh
	case "MEDIUM":
		return model.RiskMedium
	default:
		return model.RiskLow
	}
}
