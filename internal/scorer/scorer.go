package scorer

import (
	_ "embed"
	"fmt"
	"os"

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

type Config struct {
	Ports            []PortRule        `yaml:"ports"`
	ExposureDefaults map[string]string `yaml:"exposure_defaults"`
	Webhooks         WebhookConfig     `yaml:"webhooks"`
}

// ── Scorer ────────────────────────────────────────────────────────────────────

type Scorer struct {
	portRules    map[int32]PortRule
	typeDefaults map[string]model.RiskLevel
	webhooks     WebhookConfig
}

func (s *Scorer) Webhooks() WebhookConfig { return s.webhooks }

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

	return &Scorer{portRules: portRules, typeDefaults: typeDefaults, webhooks: cfg.Webhooks}, nil
}

// Score calcule le niveau de risque d'un endpoint.
func (s *Scorer) Score(ep *model.ExposedEndpoint) model.RiskLevel {
	for _, p := range ep.Ports {
		if rule, ok := s.portRules[p.Port]; ok {
			return toRisk(rule.Risk)
		}
	}
	if def, ok := s.typeDefaults[string(ep.SourceKind)]; ok {
		return def
	}
	return model.RiskLow
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
