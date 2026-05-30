package falco

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"sort"
	"strings"
	"sync"
	"time"
)

// Client interroge Loki pour récupérer les events Falco.
type Client struct {
	lokiURL string
	http    *http.Client

	mu      sync.RWMutex
	stats   Stats
	Updates chan struct{}
}

func NewClient(lokiURL string) *Client {
	return &Client{
		lokiURL: lokiURL,
		http:    &http.Client{Timeout: 15 * time.Second},
		Updates: make(chan struct{}, 1),
	}
}

func NewClientFromEnv() *Client {
	u := os.Getenv("LOKI_URL")
	if u == "" {
		u = "http://loki.monitoring.svc.cluster.local:3100"
	}
	return NewClient(u)
}

// Start lance le polling toutes les minutes.
func (c *Client) Start(ctx context.Context) {
	go func() {
		c.poll(ctx)
		ticker := time.NewTicker(1 * time.Minute)
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

func (c *Client) notify() {
	select {
	case c.Updates <- struct{}{}:
	default:
	}
}

func (c *Client) poll(ctx context.Context) {
	events, err := c.fetchEvents(ctx, 6*time.Hour, 500)
	if err != nil {
		fmt.Printf("[falco] loki error: %v\n", err)
		return
	}
	stats := buildStats(events)
	c.mu.Lock()
	c.stats = stats
	c.mu.Unlock()
	c.notify()
	fmt.Printf("[falco] %d events (6h) — %d critical, %d warning\n", stats.TotalEvents, stats.Critical, stats.Warning)
}

func (c *Client) fetchEvents(ctx context.Context, window time.Duration, limit int) ([]Event, error) {
	start := time.Now().Add(-window).UnixNano()
	end := time.Now().UnixNano()

	// Query Loki : label priority présent = event Falco
	query := `{priority=~".+"}`

	params := url.Values{}
	params.Set("query", query)
	params.Set("start", fmt.Sprintf("%d", start))
	params.Set("end", fmt.Sprintf("%d", end))
	params.Set("limit", fmt.Sprintf("%d", limit))
	params.Set("direction", "backward")

	req, err := http.NewRequestWithContext(ctx, "GET",
		c.lokiURL+"/loki/api/v1/query_range?"+params.Encode(), nil)
	if err != nil {
		return nil, err
	}

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("loki status %d", resp.StatusCode)
	}

	var result struct {
		Data struct {
			Result []struct {
				Stream map[string]string `json:"stream"`
				Values [][2]string       `json:"values"`
			} `json:"result"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	var events []Event
	for _, stream := range result.Data.Result {
		priority := stream.Stream["priority"]
		rule := stream.Stream["rule"]
		hostname := stream.Stream["hostname"]
		source := stream.Stream["source"]
		tagsStr := stream.Stream["tags"]

		var tags []string
		for _, t := range strings.Split(tagsStr, ",") {
			t = strings.TrimSpace(t)
			if t != "" {
				tags = append(tags, t)
			}
		}

		for _, v := range stream.Values {
			// v[0] = timestamp nanoseconds string, v[1] = log line
			var ts time.Time
			var nsec int64
			fmt.Sscanf(v[0], "%d", &nsec)
			if nsec > 0 {
				ts = time.Unix(0, nsec)
			}

			events = append(events, Event{
				Timestamp: ts,
				Priority:  priority,
				Rule:      rule,
				Hostname:  hostname,
				Source:    source,
				Output:    v[1],
				Tags:      tags,
			})
		}
	}

	// Trier par timestamp décroissant
	sort.Slice(events, func(i, j int) bool {
		return events[i].Timestamp.After(events[j].Timestamp)
	})

	return events, nil
}

func buildStats(events []Event) Stats {
	st := Stats{TotalEvents: len(events)}

	ruleMap := map[string]*RuleCount{}
	prioMap := map[string]int{}

	for _, e := range events {
		p := strings.ToLower(e.Priority)
		switch p {
		case "critical", "emergency", "alert":
			st.Critical++
		case "warning", "error":
			st.Warning++
		}

		prioMap[e.Priority]++

		rc, ok := ruleMap[e.Rule]
		if !ok {
			rc = &RuleCount{Rule: e.Rule, Priority: e.Priority}
			ruleMap[e.Rule] = rc
		}
		rc.Count++
	}

	for _, rc := range ruleMap {
		st.TopRules = append(st.TopRules, *rc)
	}
	sort.Slice(st.TopRules, func(i, j int) bool {
		return st.TopRules[i].Count > st.TopRules[j].Count
	})
	if len(st.TopRules) > 10 {
		st.TopRules = st.TopRules[:10]
	}

	for prio, count := range prioMap {
		st.ByPriority = append(st.ByPriority, PriorityCount{Priority: prio, Count: count})
	}
	sort.Slice(st.ByPriority, func(i, j int) bool {
		return st.ByPriority[i].Count > st.ByPriority[j].Count
	})

	st.RecentEvents = events
	if len(st.RecentEvents) > 50 {
		st.RecentEvents = st.RecentEvents[:50]
	}

	// Stats par node
	nodeMap := map[string]*NodeCorrelation{}
	nodeRules := map[string]map[string]int{}
	for _, e := range events {
		if e.Hostname == "" {
			continue
		}
		nc, ok := nodeMap[e.Hostname]
		if !ok {
			nc = &NodeCorrelation{Hostname: e.Hostname}
			nodeMap[e.Hostname] = nc
			nodeRules[e.Hostname] = map[string]int{}
		}
		nc.EventCount++
		nodeRules[e.Hostname][e.Rule]++
	}
	for host, nc := range nodeMap {
		type ruleC struct {
			rule  string
			count int
		}
		var rules []ruleC
		for r, c := range nodeRules[host] {
			rules = append(rules, ruleC{r, c})
		}
		sort.Slice(rules, func(i, j int) bool { return rules[i].count > rules[j].count })
		for i, r := range rules {
			if i >= 3 {
				break
			}
			nc.TopRules = append(nc.TopRules, r.rule)
		}
		st.NodeStats = append(st.NodeStats, *nc)
	}
	sort.Slice(st.NodeStats, func(i, j int) bool {
		return st.NodeStats[i].EventCount > st.NodeStats[j].EventCount
	})

	return st
}
