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

// NotifyHigh envoie une alerte pour un endpoint HIGH nouveau ou modifié.
func (n *Notifier) NotifyHigh(ep model.ExposedEndpoint) {
	if !n.enabled {
		return
	}
	dest, portsStr, reasonsStr := epStrings(ep)
	statusLabel := "Nouveau"
	if ep.Status == "MODIFIED" {
		statusLabel = "Modifié"
	}
	if n.cfg.Slack != "" {
		go n.sendSlack(ep, dest, portsStr, reasonsStr, statusLabel)
	}
	if n.cfg.Teams != "" {
		go n.sendTeams(ep, dest, portsStr, reasonsStr, statusLabel)
	}
	if n.cfg.Discord != "" {
		go n.sendDiscord(ep, dest, portsStr, reasonsStr, statusLabel)
	}
	if n.cfg.Generic != "" {
		go n.sendGeneric(ep, dest, portsStr, reasonsStr, statusLabel)
	}
}

// NotifyDigest envoie un résumé périodique (ex: quotidien).
func (n *Notifier) NotifyDigest(newCount, modCount, highCount int, topNew []model.ExposedEndpoint) {
	if !n.enabled {
		return
	}
	if n.cfg.Slack != "" {
		go n.sendSlackDigest(newCount, modCount, highCount, topNew)
	}
	if n.cfg.Discord != "" {
		go n.sendDiscordDigest(newCount, modCount, highCount, topNew)
	}
	if n.cfg.Teams != "" {
		go n.sendTeamsDigest(newCount, modCount, highCount, topNew)
	}
	if n.cfg.Generic != "" {
		go n.sendGenericDigest(newCount, modCount, highCount, topNew)
	}
}

// ── helpers ───────────────────────────────────────────────────────────────────

func epStrings(ep model.ExposedEndpoint) (dest, portsStr, reasonsStr string) {
	dest = ep.Hostname
	if dest == "" {
		dest = ep.ExternalIP
	}
	var ports []string
	for _, p := range ep.Ports {
		ports = append(ports, fmt.Sprintf("%d/%s", p.Port, p.Protocol))
	}
	portsStr = strings.Join(ports, ", ")
	if len(ep.RiskReasons) > 0 {
		reasonsStr = "• " + strings.Join(ep.RiskReasons, "\n• ")
	}
	return
}

func digestLines(topNew []model.ExposedEndpoint) string {
	var lines []string
	for _, ep := range topNew {
		dest := ep.Hostname
		if dest == "" {
			dest = ep.ExternalIP
		}
		lines = append(lines, fmt.Sprintf("• `%s/%s` — %s (%s)", ep.Namespace, ep.ObjectName, dest, ep.Risk))
	}
	return strings.Join(lines, "\n")
}

// ── Slack ─────────────────────────────────────────────────────────────────────

func (n *Notifier) sendSlack(ep model.ExposedEndpoint, dest, ports, reasons, statusLabel string) {
	icon := "🚨"
	if ep.Status == "MODIFIED" {
		icon = "⚠️"
	}
	fields := []map[string]string{
		{"title": "Service", "value": fmt.Sprintf("%s/%s", ep.Namespace, ep.ObjectName), "short": "true"},
		{"title": "Statut", "value": statusLabel, "short": "true"},
		{"title": "Type", "value": string(ep.SourceKind), "short": "true"},
		{"title": "Destination", "value": dest, "short": "true"},
		{"title": "Ports", "value": ports, "short": "true"},
	}
	if reasons != "" {
		fields = append(fields, map[string]string{"title": "Raisons", "value": reasons, "short": "false"})
	}
	payload := map[string]interface{}{
		"text": fmt.Sprintf("%s *Beacon — Service HIGH %s*", icon, statusLabel),
		"attachments": []map[string]interface{}{
			{
				"color":  "#EF4444",
				"fields": fields,
				"footer": "Beacon KubeSurfaceScanner",
				"ts":     time.Now().Unix(),
			},
		},
	}
	n.post(n.cfg.Slack, payload)
}

func (n *Notifier) sendSlackDigest(newCount, modCount, highCount int, topNew []model.ExposedEndpoint) {
	text := fmt.Sprintf("📊 *Beacon — Digest quotidien*\n• %d nouveaux endpoints\n• %d modifiés\n• %d HIGH au total",
		newCount, modCount, highCount)
	var attachments []map[string]interface{}
	if len(topNew) > 0 {
		attachments = append(attachments, map[string]interface{}{
			"color": "#EF4444",
			"title": "Nouveaux endpoints HIGH",
			"text":  digestLines(topNew),
		})
	}
	payload := map[string]interface{}{"text": text, "attachments": attachments}
	n.post(n.cfg.Slack, payload)
}

// ── Teams ─────────────────────────────────────────────────────────────────────

func (n *Notifier) sendTeams(ep model.ExposedEndpoint, dest, ports, reasons, statusLabel string) {
	facts := []map[string]string{
		{"name": "Service", "value": ep.ObjectName},
		{"name": "Statut", "value": statusLabel},
		{"name": "Type", "value": string(ep.SourceKind)},
		{"name": "Destination", "value": dest},
		{"name": "Ports", "value": ports},
	}
	if reasons != "" {
		facts = append(facts, map[string]string{"name": "Raisons", "value": reasons})
	}
	icon := "🚨"
	if ep.Status == "MODIFIED" {
		icon = "⚠️"
	}
	payload := map[string]interface{}{
		"@type":      "MessageCard",
		"@context":   "http://schema.org/extensions",
		"themeColor": "EF4444",
		"summary":    fmt.Sprintf("Beacon — Service HIGH %s", statusLabel),
		"sections": []map[string]interface{}{
			{
				"activityTitle":    fmt.Sprintf("%s Beacon — Service HIGH %s", icon, statusLabel),
				"activitySubtitle": fmt.Sprintf("Namespace: %s", ep.Namespace),
				"facts":            facts,
			},
		},
	}
	n.post(n.cfg.Teams, payload)
}

func (n *Notifier) sendTeamsDigest(newCount, modCount, highCount int, topNew []model.ExposedEndpoint) {
	payload := map[string]interface{}{
		"@type":      "MessageCard",
		"@context":   "http://schema.org/extensions",
		"themeColor": "6366F1",
		"summary":    "Beacon — Digest quotidien",
		"sections": []map[string]interface{}{
			{
				"activityTitle": "📊 Beacon — Digest quotidien",
				"facts": []map[string]string{
					{"name": "Nouveaux endpoints", "value": fmt.Sprintf("%d", newCount)},
					{"name": "Modifiés", "value": fmt.Sprintf("%d", modCount)},
					{"name": "Total HIGH", "value": fmt.Sprintf("%d", highCount)},
					{"name": "Nouveaux HIGH", "value": digestLines(topNew)},
				},
			},
		},
	}
	n.post(n.cfg.Teams, payload)
}

// ── Discord ───────────────────────────────────────────────────────────────────

func (n *Notifier) sendDiscord(ep model.ExposedEndpoint, dest, ports, reasons, statusLabel string) {
	color := 15672132 // rouge #EF4444
	if ep.Status == "MODIFIED" {
		color = 16027660 // orange #F4A50C
	}
	fields := []map[string]interface{}{
		{"name": "Statut", "value": statusLabel, "inline": true},
		{"name": "Type", "value": string(ep.SourceKind), "inline": true},
		{"name": "Destination", "value": dest, "inline": true},
		{"name": "Ports", "value": ports, "inline": false},
	}
	if reasons != "" {
		fields = append(fields, map[string]interface{}{"name": "Raisons", "value": reasons, "inline": false})
	}
	payload := map[string]interface{}{
		"embeds": []map[string]interface{}{
			{
				"title":       fmt.Sprintf("🚨 %s/%s — Service HIGH %s", ep.Namespace, ep.ObjectName, statusLabel),
				"color":       color,
				"fields":      fields,
				"footer":      map[string]string{"text": "Beacon KubeSurfaceScanner"},
				"timestamp":   time.Now().UTC().Format(time.RFC3339),
			},
		},
	}
	n.post(n.cfg.Discord, payload)
}

func (n *Notifier) sendDiscordDigest(newCount, modCount, highCount int, topNew []model.ExposedEndpoint) {
	desc := fmt.Sprintf("**%d** nouveaux • **%d** modifiés • **%d** HIGH au total", newCount, modCount, highCount)
	fields := []map[string]interface{}{}
	if len(topNew) > 0 {
		fields = append(fields, map[string]interface{}{
			"name":   "Nouveaux endpoints HIGH",
			"value":  digestLines(topNew),
			"inline": false,
		})
	}
	payload := map[string]interface{}{
		"embeds": []map[string]interface{}{
			{
				"title":       "📊 Beacon — Digest quotidien",
				"color":       6382178, // indigo #6166E2
				"description": desc,
				"fields":      fields,
				"footer":      map[string]string{"text": "Beacon KubeSurfaceScanner"},
				"timestamp":   time.Now().UTC().Format(time.RFC3339),
			},
		},
	}
	n.post(n.cfg.Discord, payload)
}

// ── Generic JSON ──────────────────────────────────────────────────────────────

func (n *Notifier) sendGeneric(ep model.ExposedEndpoint, dest, ports, reasons, statusLabel string) {
	payload := map[string]interface{}{
		"event":       "high_exposure_detected",
		"status":      statusLabel,
		"namespace":   ep.Namespace,
		"service":     ep.ObjectName,
		"type":        string(ep.SourceKind),
		"destination": dest,
		"ports":       ports,
		"risk":        string(ep.Risk),
		"reasons":     ep.RiskReasons,
		"timestamp":   time.Now().UTC().Format(time.RFC3339),
	}
	n.post(n.cfg.Generic, payload)
}

func (n *Notifier) sendGenericDigest(newCount, modCount, highCount int, topNew []model.ExposedEndpoint) {
	var top []map[string]string
	for _, ep := range topNew {
		dest := ep.Hostname
		if dest == "" {
			dest = ep.ExternalIP
		}
		top = append(top, map[string]string{
			"namespace": ep.Namespace,
			"service":   ep.ObjectName,
			"dest":      dest,
			"risk":      string(ep.Risk),
		})
	}
	payload := map[string]interface{}{
		"event":      "daily_digest",
		"new_count":  newCount,
		"mod_count":  modCount,
		"high_count": highCount,
		"top_new":    top,
		"timestamp":  time.Now().UTC().Format(time.RFC3339),
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
