package notify

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/theo-mrn/beacon/internal/model"
)

type WebhookConfig struct {
	Slack   string
	Teams   string
	Discord string
	Generic string
}

type Notifier struct {
	cfg     WebhookConfig
	client  *http.Client
	enabled bool
}

func New(cfg WebhookConfig) *Notifier {
	enabled := cfg.Slack != "" || cfg.Teams != "" || cfg.Discord != "" || cfg.Generic != ""
	return &Notifier{
		cfg:     cfg,
		client:  &http.Client{Timeout: 10 * time.Second},
		enabled: enabled,
	}
}

func (n *Notifier) Enabled() bool { return n.enabled }

// NotifyHigh envoie une alerte pour un endpoint HIGH nouvellement détecté.
func (n *Notifier) NotifyHigh(ep model.ExposedEndpoint) {
	if !n.enabled {
		return
	}

	dest := ep.Hostname
	if dest == "" {
		dest = ep.ExternalIP
	}

	var ports []string
	for _, p := range ep.Ports {
		ports = append(ports, fmt.Sprintf("%d/%s", p.Port, p.Protocol))
	}
	portsStr := strings.Join(ports, ", ")

	if n.cfg.Slack != "" {
		go n.sendSlack(ep, dest, portsStr)
	}
	if n.cfg.Teams != "" {
		go n.sendTeams(ep, dest, portsStr)
	}
	if n.cfg.Discord != "" {
		go n.sendDiscord(ep, dest, portsStr)
	}
	if n.cfg.Generic != "" {
		go n.sendGeneric(ep, dest, portsStr)
	}
}

// ── Slack ─────────────────────────────────────────────────────────────────────

func (n *Notifier) sendSlack(ep model.ExposedEndpoint, dest, ports string) {
	payload := map[string]interface{}{
		"text": fmt.Sprintf("🚨 *Beacon — Nouveau service HIGH détecté*"),
		"attachments": []map[string]interface{}{
			{
				"color": "#EF4444",
				"fields": []map[string]string{
					{"title": "Service", "value": fmt.Sprintf("%s/%s", ep.Namespace, ep.ObjectName), "short": "true"},
					{"title": "Type", "value": string(ep.SourceKind), "short": "true"},
					{"title": "Destination", "value": dest, "short": "true"},
					{"title": "Ports", "value": ports, "short": "true"},
				},
				"footer": "Beacon KubeSurfaceScanner",
				"ts":     time.Now().Unix(),
			},
		},
	}
	n.post(n.cfg.Slack, payload)
}

// ── Teams ─────────────────────────────────────────────────────────────────────

func (n *Notifier) sendTeams(ep model.ExposedEndpoint, dest, ports string) {
	payload := map[string]interface{}{
		"@type":      "MessageCard",
		"@context":   "http://schema.org/extensions",
		"themeColor": "EF4444",
		"summary":    "Beacon — Nouveau service HIGH",
		"sections": []map[string]interface{}{
			{
				"activityTitle":    "🚨 Beacon — Nouveau service HIGH détecté",
				"activitySubtitle": fmt.Sprintf("Namespace: %s", ep.Namespace),
				"facts": []map[string]string{
					{"name": "Service", "value": ep.ObjectName},
					{"name": "Type", "value": string(ep.SourceKind)},
					{"name": "Destination", "value": dest},
					{"name": "Ports", "value": ports},
				},
			},
		},
	}
	n.post(n.cfg.Teams, payload)
}

// ── Discord ───────────────────────────────────────────────────────────────────

func (n *Notifier) sendDiscord(ep model.ExposedEndpoint, dest, ports string) {
	payload := map[string]interface{}{
		"embeds": []map[string]interface{}{
			{
				"title":       "🚨 Beacon — Nouveau service HIGH détecté",
				"color":       15672132, // #EF4444 en décimal
				"description": fmt.Sprintf("**%s/%s** vient d'être exposé", ep.Namespace, ep.ObjectName),
				"fields": []map[string]interface{}{
					{"name": "Type", "value": string(ep.SourceKind), "inline": true},
					{"name": "Destination", "value": dest, "inline": true},
					{"name": "Ports", "value": ports, "inline": false},
				},
				"footer": map[string]string{"text": "Beacon KubeSurfaceScanner"},
				"timestamp": time.Now().UTC().Format(time.RFC3339),
			},
		},
	}
	n.post(n.cfg.Discord, payload)
}

// ── Generic JSON ──────────────────────────────────────────────────────────────

func (n *Notifier) sendGeneric(ep model.ExposedEndpoint, dest, ports string) {
	payload := map[string]interface{}{
		"event":       "high_exposure_detected",
		"namespace":   ep.Namespace,
		"service":     ep.ObjectName,
		"type":        string(ep.SourceKind),
		"destination": dest,
		"ports":       ports,
		"risk":        string(ep.Risk),
		"timestamp":   time.Now().UTC().Format(time.RFC3339),
	}
	n.post(n.cfg.Generic, payload)
}

// ── HTTP helper ───────────────────────────────────────────────────────────────

func (n *Notifier) post(url string, payload interface{}) {
	b, err := json.Marshal(payload)
	if err != nil {
		fmt.Printf("[notify] marshal error: %v\n", err)
		return
	}
	resp, err := n.client.Post(url, "application/json", bytes.NewReader(b))
	if err != nil {
		fmt.Printf("[notify] post error: %v\n", err)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		fmt.Printf("[notify] unexpected status %d for %s\n", resp.StatusCode, url)
	}
}
