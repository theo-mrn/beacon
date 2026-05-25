package wazuh

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"sync"
	"time"
)

type Client struct {
	url      string
	user     string
	password string
	http     *http.Client

	mu      sync.RWMutex
	stats   Stats
	Updates chan struct{}
}

func NewClient(url, user, password string) *Client {
	return &Client{
		url:  url,
		user: user,
		password: password,
		http: &http.Client{
			Timeout: 15 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			},
		},
		Updates: make(chan struct{}, 1),
	}
}

// Start lance le polling toutes les 5 minutes.
func (c *Client) Start(ctx context.Context) {
	go func() {
		c.poll(ctx)
		ticker := time.NewTicker(5 * time.Minute)
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

// Correlate calcule les corrélations entre endpoints exposés et alertes Wazuh.
func (c *Client) Correlate(endpoints []EndpointInfo) []Correlation {
	c.mu.RLock()
	stats := c.stats
	c.mu.RUnlock()

	// Index AgentSummary par IP
	byIP := map[string]AgentSummary{}
	for _, ag := range stats.Agents {
		if ag.AgentIP != "" {
			byIP[ag.AgentIP] = ag
		}
	}

	// Déduplique les endpoints par ExternalIP pour éviter N corrélations pour 1 nœud
	// On regroupe tous les endpoints sur la même IP dans une seule corrélation
	type nodeCorr struct {
		endpoints []EndpointInfo
		ag        AgentSummary
	}
	byNodeIP := map[string]*nodeCorr{}
	for _, ep := range endpoints {
		if ep.ExternalIP == "" {
			continue
		}
		ag, ok := byIP[ep.ExternalIP]
		if !ok || ag.Total == 0 {
			continue
		}
		nc, exists := byNodeIP[ep.ExternalIP]
		if !exists {
			nc = &nodeCorr{ag: ag}
			byNodeIP[ep.ExternalIP] = nc
		}
		nc.endpoints = append(nc.endpoints, ep)
	}

	// Ajouter aussi les nœuds sous attaque sans endpoints exposés
	for _, ag := range stats.Agents {
		if ag.AgentIP == "" || ag.Total == 0 {
			continue
		}
		if _, already := byNodeIP[ag.AgentIP]; !already {
			byNodeIP[ag.AgentIP] = &nodeCorr{ag: ag}
		}
	}

	var corrs []Correlation
	for nodeIP, nc := range byNodeIP {
		var refs []EndpointRef
		for _, ep := range nc.endpoints {
			refs = append(refs, EndpointRef{
				NS:   ep.Namespace,
				Name: ep.Name,
				URL:  ep.URL,
				Risk: ep.Risk,
			})
		}
		// Trie les endpoints : HIGH d'abord
		sort.Slice(refs, func(i, j int) bool {
			if refs[i].Risk != refs[j].Risk {
				return refs[i].Risk == "HIGH"
			}
			return refs[i].Name < refs[j].Name
		})
		corrs = append(corrs, Correlation{
			NodeIP:     nodeIP,
			NodeName:   nc.ag.AgentName,
			AlertCount: nc.ag.Total,
			TopSrcIPs:  nc.ag.TopSrcIPs,
			Endpoints:  refs,
		})
	}
	sort.Slice(corrs, func(i, j int) bool {
		return corrs[i].AlertCount > corrs[j].AlertCount
	})
	return corrs
}

// EndpointInfo est un résumé d'endpoint passé pour la corrélation.
type EndpointInfo struct {
	Namespace  string
	Name       string
	URL        string
	Risk       string
	ExternalIP string
}

func (c *Client) notify() {
	select {
	case c.Updates <- struct{}{}:
	default:
	}
}

func (c *Client) poll(ctx context.Context) {
	alerts, err := c.fetchAlerts(ctx, 24*time.Hour, 500)
	if err != nil {
		fmt.Printf("[wazuh] poll error: %v\n", err)
		// Essayer le port-forward local comme fallback
		if c.url != "https://localhost:9200" {
			orig := c.url
			c.url = "https://localhost:9200"
			alerts, err = c.fetchAlerts(ctx, 24*time.Hour, 500)
			if err != nil {
				fmt.Printf("[wazuh] fallback localhost error: %v\n", err)
				c.url = orig
				return
			}
			fmt.Println("[wazuh] utilisation du fallback localhost:9200")
		} else {
			return
		}
	}
	stats := buildStats(alerts)
	c.mu.Lock()
	c.stats = stats
	c.mu.Unlock()
	c.notify()
	fmt.Printf("[wazuh] %d alertes (24h) — %d critical, %d high\n", stats.Total, stats.Critical, stats.High)
}

// fetchAlerts requête Elasticsearch pour les alertes Wazuh des dernières `window`.
func (c *Client) fetchAlerts(ctx context.Context, window time.Duration, size int) ([]Alert, error) {
	since := time.Now().UTC().Add(-window).Format(time.RFC3339)

	query := map[string]interface{}{
		"size": size,
		"sort": []map[string]interface{}{
			{"@timestamp": map[string]string{"order": "desc"}},
		},
		"query": map[string]interface{}{
			"bool": map[string]interface{}{
				"filter": []map[string]interface{}{
					{
						"range": map[string]interface{}{
							"@timestamp": map[string]string{"gte": since},
						},
					},
				},
			},
		},
		"_source": []string{
			"@timestamp", "agent", "rule", "data",
			"GeoLocation", "full_log",
		},
	}

	body, _ := json.Marshal(query)
	req, err := http.NewRequestWithContext(ctx, "POST",
		c.url+"/wazuh-alerts-4.x-*/_search", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(c.user, c.password)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var result struct {
		Hits struct {
			Hits []struct {
				ID     string                 `json:"_id"`
				Source map[string]interface{} `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	var alerts []Alert
	for _, h := range result.Hits.Hits {
		a := parseAlert(h.ID, h.Source)
		alerts = append(alerts, a)
	}
	return alerts, nil
}

func parseAlert(id string, s map[string]interface{}) Alert {
	a := Alert{ID: id}

	if ts, ok := s["@timestamp"].(string); ok {
		a.Timestamp, _ = time.Parse(time.RFC3339, ts)
	}
	if agent, ok := s["agent"].(map[string]interface{}); ok {
		a.AgentID, _ = agent["id"].(string)
		a.AgentName, _ = agent["name"].(string)
		a.AgentIP, _ = agent["ip"].(string)
	}
	if rule, ok := s["rule"].(map[string]interface{}); ok {
		a.RuleID, _ = rule["id"].(string)
		a.RuleDesc, _ = rule["description"].(string)
		if lvl, ok := rule["level"].(float64); ok {
			a.RuleLevel = int(lvl)
		}
		if grps, ok := rule["groups"].([]interface{}); ok {
			for _, g := range grps {
				if gs, ok := g.(string); ok {
					a.Groups = append(a.Groups, gs)
				}
			}
		}
		if mitre, ok := rule["mitre"].(map[string]interface{}); ok {
			if tactics, ok := mitre["tactic"].([]interface{}); ok {
				for _, t := range tactics {
					if ts, ok := t.(string); ok {
						a.MitreTactics = append(a.MitreTactics, ts)
					}
				}
			}
			if techs, ok := mitre["technique"].([]interface{}); ok {
				for _, t := range techs {
					if ts, ok := t.(string); ok {
						a.MitreTechniques = append(a.MitreTechniques, ts)
					}
				}
			}
		}
	}
	if data, ok := s["data"].(map[string]interface{}); ok {
		a.SrcIP, _ = data["srcip"].(string)
		a.SrcUser, _ = data["srcuser"].(string)
	}
	if geo, ok := s["GeoLocation"].(map[string]interface{}); ok {
		a.Country, _ = geo["country_name"].(string)
		a.Region, _ = geo["region_name"].(string)
		if loc, ok := geo["location"].(map[string]interface{}); ok {
			a.Lat, _ = loc["lat"].(float64)
			a.Lon, _ = loc["lon"].(float64)
		}
	}
	a.FullLog, _ = s["full_log"].(string)
	return a
}

func buildStats(alerts []Alert) Stats {
	st := Stats{
		Total:        len(alerts),
		RecentAlerts: alerts,
	}
	if len(st.RecentAlerts) > 50 {
		st.RecentAlerts = st.RecentAlerts[:50]
	}

	agentMap := map[string]*AgentSummary{}
	srcIPMap := map[string]*SrcIPCount{}

	for _, a := range alerts {
		if a.RuleLevel >= 12 {
			st.Critical++
		} else if a.RuleLevel >= 7 {
			st.High++
		}

		// Par agent
		ag, ok := agentMap[a.AgentID]
		if !ok {
			ag = &AgentSummary{
				AgentID:   a.AgentID,
				AgentName: a.AgentName,
				AgentIP:   a.AgentIP,
			}
			agentMap[a.AgentID] = ag
		}
		ag.Total++
		if a.RuleLevel >= 12 {
			ag.Critical++
		} else if a.RuleLevel >= 7 {
			ag.High++
		}

		// IPs sources globales
		if a.SrcIP != "" {
			src, ok := srcIPMap[a.SrcIP]
			if !ok {
				src = &SrcIPCount{IP: a.SrcIP, Country: a.Country}
				srcIPMap[a.SrcIP] = src
			}
			src.Count++
		}
	}

	// Top 10 IPs sources
	for _, s := range srcIPMap {
		st.TopSrcIPs = append(st.TopSrcIPs, *s)
	}
	sort.Slice(st.TopSrcIPs, func(i, j int) bool {
		return st.TopSrcIPs[i].Count > st.TopSrcIPs[j].Count
	})
	if len(st.TopSrcIPs) > 10 {
		st.TopSrcIPs = st.TopSrcIPs[:10]
	}

	// Agents triés par total décroissant
	for _, ag := range agentMap {
		// Top IPs par agent
		agSrcMap := map[string]*SrcIPCount{}
		for _, a := range alerts {
			if a.AgentID != ag.AgentID || a.SrcIP == "" {
				continue
			}
			s, ok := agSrcMap[a.SrcIP]
			if !ok {
				s = &SrcIPCount{IP: a.SrcIP, Country: a.Country}
				agSrcMap[a.SrcIP] = s
			}
			s.Count++
		}
		for _, s := range agSrcMap {
			ag.TopSrcIPs = append(ag.TopSrcIPs, *s)
		}
		sort.Slice(ag.TopSrcIPs, func(i, j int) bool {
			return ag.TopSrcIPs[i].Count > ag.TopSrcIPs[j].Count
		})
		if len(ag.TopSrcIPs) > 5 {
			ag.TopSrcIPs = ag.TopSrcIPs[:5]
		}
		st.Agents = append(st.Agents, *ag)
	}
	sort.Slice(st.Agents, func(i, j int) bool {
		return st.Agents[i].Total > st.Agents[j].Total
	})

	return st
}
