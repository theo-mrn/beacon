package crowdsec

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"sort"
	"sync"
	"time"
)

// Client interroge l'API LAPI CrowdSec locale.
type Client struct {
	lapiURL string
	apiKey  string
	http    *http.Client

	mu      sync.RWMutex
	stats   Stats
	Updates chan struct{}
}

func NewClient(lapiURL, apiKey string) *Client {
	return &Client{
		lapiURL: lapiURL,
		apiKey:  apiKey,
		http:    &http.Client{Timeout: 10 * time.Second},
		Updates: make(chan struct{}, 1),
	}
}

// NewClientFromEnv crée un client depuis les variables d'environnement.
func NewClientFromEnv() *Client {
	url := os.Getenv("CROWDSEC_LAPI_URL")
	if url == "" {
		url = "http://crowdsec-service.crowdsec.svc.cluster.local:8080"
	}
	key := os.Getenv("CROWDSEC_API_KEY")
	return NewClient(url, key)
}

func (c *Client) Enabled() bool {
	return c.apiKey != ""
}

// Start lance le polling toutes les 2 minutes.
func (c *Client) Start(ctx context.Context) {
	if !c.Enabled() {
		fmt.Println("[crowdsec] désactivé — CROWDSEC_API_KEY non défini")
		return
	}
	go func() {
		c.poll(ctx)
		ticker := time.NewTicker(2 * time.Minute)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				c.poll(ctx)
			}
		}
	}()
}

func (c *Client) Stats() Stats {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.stats
}

// Correlate croise les décisions CrowdSec avec les endpoints exposés.
func (c *Client) Correlate(endpoints []EndpointInfo) []Correlation {
	c.mu.RLock()
	stats := c.stats
	c.mu.RUnlock()

	// Index des IPs bannies
	bannedIPs := map[string]int{}
	for _, d := range stats.RecentDecisions {
		bannedIPs[d.Value]++
	}

	// Regroupe les endpoints par ExternalIP
	type nodeData struct {
		endpoints []EndpointInfo
		banned    int
	}
	byIP := map[string]*nodeData{}
	for _, ep := range endpoints {
		if ep.ExternalIP == "" {
			continue
		}
		nd, exists := byIP[ep.ExternalIP]
		if !exists {
			nd = &nodeData{banned: bannedIPs[ep.ExternalIP]}
			byIP[ep.ExternalIP] = nd
		}
		nd.endpoints = append(nd.endpoints, ep)
	}

	var corrs []Correlation
	for nodeIP, nd := range byIP {
		var refs []EndpointRef
		for _, ep := range nd.endpoints {
			refs = append(refs, EndpointRef{
				NS:   ep.Namespace,
				Name: ep.Name,
				URL:  ep.URL,
				Risk: ep.Risk,
			})
		}
		sort.Slice(refs, func(i, j int) bool {
			if refs[i].Risk != refs[j].Risk {
				return refs[i].Risk == "HIGH"
			}
			return refs[i].Name < refs[j].Name
		})

		// Top IPs src ayant ciblé ce node
		var topIPs []SrcIPCount
		for _, src := range stats.TopSrcIPs {
			topIPs = append(topIPs, src)
			if len(topIPs) >= 5 {
				break
			}
		}

		corrs = append(corrs, Correlation{
			NodeIP:        nodeIP,
			DecisionCount: nd.banned,
			TopSrcIPs:     topIPs,
			Endpoints:     refs,
		})
	}
	sort.Slice(corrs, func(i, j int) bool {
		return corrs[i].DecisionCount > corrs[j].DecisionCount
	})
	return corrs
}

func (c *Client) notify() {
	select {
	case c.Updates <- struct{}{}:
	default:
	}
}

func (c *Client) poll(ctx context.Context) {
	decisions, err := c.fetchDecisions(ctx)
	if err != nil {
		fmt.Printf("[crowdsec] decisions error: %v\n", err)
		return
	}
	alerts, err := c.fetchAlerts(ctx)
	if err != nil {
		fmt.Printf("[crowdsec] alerts error: %v\n", err)
	}

	stats := buildStats(decisions, alerts)
	c.mu.Lock()
	c.stats = stats
	c.mu.Unlock()
	c.notify()
	fmt.Printf("[crowdsec] %d décisions actives, %d alertes (24h)\n", stats.ActiveDecisions, stats.AlertsLast24h)
}

func (c *Client) get(ctx context.Context, path string, out interface{}) error {
	req, err := http.NewRequestWithContext(ctx, "GET", c.lapiURL+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("X-Api-Key", c.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("status %d", resp.StatusCode)
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

func (c *Client) fetchDecisions(ctx context.Context) ([]Decision, error) {
	var raw []struct {
		ID        int    `json:"id"`
		Value     string `json:"value"`
		Type      string `json:"type"`
		Scenario  string `json:"scenario"`
		Origin    string `json:"origin"`
		Scope     string `json:"scope"`
		Duration  string `json:"duration"`
		Simulated bool   `json:"simulated"`
	}
	if err := c.get(ctx, "/v1/decisions", &raw); err != nil {
		return nil, err
	}
	var decisions []Decision
	for _, r := range raw {
		decisions = append(decisions, Decision{
			ID:        r.ID,
			CreatedAt: time.Now(),
			Value:     r.Value,
			Type:      r.Type,
			Scenario:  r.Scenario,
			Origin:    r.Origin,
			Scope:     r.Scope,
			Duration:  r.Duration,
			Simulated: r.Simulated,
		})
	}
	return decisions, nil
}

func (c *Client) fetchAlerts(ctx context.Context) ([]Alert, error) {
	since := time.Now().Add(-24 * time.Hour).Format(time.RFC3339)
	var raw []struct {
		ID          int    `json:"id"`
		Scenario    string `json:"scenario"`
		EventsCount int    `json:"events_count"`
		Simulated   bool   `json:"simulated"`
		CreatedAt   string `json:"created_at"`
		Source      struct {
			IP        string `json:"ip"`
			Cn        string `json:"cn"`
		} `json:"source"`
	}
	if err := c.get(ctx, "/v1/alerts?since="+since+"&limit=100", &raw); err != nil {
		return nil, err
	}
	var alerts []Alert
	for _, r := range raw {
		t, _ := time.Parse(time.RFC3339, r.CreatedAt)
		alerts = append(alerts, Alert{
			ID:          r.ID,
			CreatedAt:   t,
			Scenario:    r.Scenario,
			SourceIP:    r.Source.IP,
			Country:     r.Source.Cn,
			EventsCount: r.EventsCount,
			Simulated:   r.Simulated,
		})
	}
	return alerts, nil
}

func buildStats(decisions []Decision, alerts []Alert) Stats {
	st := Stats{
		ActiveDecisions: len(decisions),
		AlertsLast24h:   len(alerts),
	}

	// Top 10 décisions récentes
	st.RecentDecisions = decisions
	if len(st.RecentDecisions) > 20 {
		st.RecentDecisions = st.RecentDecisions[:20]
	}

	// Top 10 alertes récentes
	st.RecentAlerts = alerts
	if len(st.RecentAlerts) > 20 {
		st.RecentAlerts = st.RecentAlerts[:20]
	}

	// Top IPs
	ipMap := map[string]*SrcIPCount{}
	for _, d := range decisions {
		s, ok := ipMap[d.Value]
		if !ok {
			s = &SrcIPCount{IP: d.Value, Scenario: d.Scenario}
			ipMap[d.Value] = s
		}
		s.Count++
	}
	for _, s := range ipMap {
		st.TopSrcIPs = append(st.TopSrcIPs, *s)
	}
	sort.Slice(st.TopSrcIPs, func(i, j int) bool {
		return st.TopSrcIPs[i].Count > st.TopSrcIPs[j].Count
	})
	if len(st.TopSrcIPs) > 10 {
		st.TopSrcIPs = st.TopSrcIPs[:10]
	}

	// Top scénarios
	scenMap := map[string]int{}
	for _, d := range decisions {
		scenMap[d.Scenario]++
	}
	for scen, count := range scenMap {
		st.TopScenarios = append(st.TopScenarios, ScenarioCount{Scenario: scen, Count: count})
	}
	sort.Slice(st.TopScenarios, func(i, j int) bool {
		return st.TopScenarios[i].Count > st.TopScenarios[j].Count
	})
	if len(st.TopScenarios) > 10 {
		st.TopScenarios = st.TopScenarios[:10]
	}

	return st
}
