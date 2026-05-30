package lynis

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// NodeResult représente le résultat d'un audit Lynis sur un node.
type NodeResult struct {
	Hostname      string    `json:"hostname"`
	ScannedAt     time.Time `json:"scanned_at"`
	HardeningIndex int      `json:"hardening_index"` // 0-100
	Warnings      []string  `json:"warnings"`
	Suggestions   []string  `json:"suggestions"`
	Tests         struct {
		Performed int `json:"performed"`
		Passed    int `json:"passed"`
		Failed    int `json:"failed"`
		Warnings  int `json:"warnings"`
	} `json:"tests"`
}

// Stats agrège les résultats Lynis de tous les nodes.
type Stats struct {
	Nodes       []NodeResult `json:"nodes"`
	LastUpdated time.Time    `json:"last_updated"`
}

// Client lit les résultats Lynis depuis Loki ou un fichier local.
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

// Start lance le polling toutes les heures (Lynis tourne 1x/semaine).
func (c *Client) Start(ctx context.Context) {
	go func() {
		c.poll(ctx)
		ticker := time.NewTicker(1 * time.Hour)
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
	nodes, err := c.fetchFromLoki(ctx)
	if err != nil {
		fmt.Printf("[lynis] loki error: %v — fallback fichier local\n", err)
		nodes = c.fetchFromFile()
	}
	if len(nodes) == 0 {
		fmt.Println("[lynis] aucun résultat disponible")
		return
	}

	stats := Stats{Nodes: nodes, LastUpdated: time.Now()}
	c.mu.Lock()
	c.stats = stats
	c.mu.Unlock()
	c.notify()

	for _, n := range nodes {
		fmt.Printf("[lynis] %s — hardening index: %d/100, %d warnings\n",
			n.Hostname, n.HardeningIndex, len(n.Warnings))
	}
}

// fetchFromLoki récupère les logs Lynis depuis Loki.
func (c *Client) fetchFromLoki(ctx context.Context) ([]NodeResult, error) {
	start := time.Now().Add(-7 * 24 * time.Hour).UnixNano()
	end := time.Now().UnixNano()

	query := `{app="lynis"}`
	reqURL := fmt.Sprintf("%s/loki/api/v1/query_range?query=%s&start=%d&end=%d&limit=1000&direction=backward",
		c.lokiURL, query, start, end)

	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
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

	// Regroupe tous les logs par node
	nodeLogMap := map[string][]string{}
	for _, stream := range result.Data.Result {
		host := stream.Stream["node"]
		if host == "" {
			host = stream.Stream["hostname"]
		}
		if host == "" {
			host = "unknown"
		}
		for _, v := range stream.Values {
			nodeLogMap[host] = append(nodeLogMap[host], v[1])
		}
	}

	var nodes []NodeResult
	for host, lines := range nodeLogMap {
		node := parseLynisOutput(host, lines)
		nodes = append(nodes, node)
	}
	sort.Slice(nodes, func(i, j int) bool {
		return nodes[i].HardeningIndex < nodes[j].HardeningIndex
	})
	return nodes, nil
}

// fetchFromFile lit les résultats Lynis depuis les fichiers locaux (fallback).
func (c *Client) fetchFromFile() []NodeResult {
	paths := []string{
		"/var/log/kube-bench-master.txt",
		"/var/log/lynis-report.dat",
	}
	for _, p := range paths {
		if data, err := os.ReadFile(p); err == nil {
			lines := strings.Split(string(data), "\n")
			node := parseLynisOutput("local", lines)
			if node.HardeningIndex > 0 {
				return []NodeResult{node}
			}
		}
	}
	return nil
}

var (
	reHardeningIndex = regexp.MustCompile(`Hardening index\s*[:\-]\s*(\d+)`)
	reWarning        = regexp.MustCompile(`^\s*\[WARNING\]\s*(.+)$`)
	reSuggestion     = regexp.MustCompile(`^\s*\[SUGGESTION\]\s*(.+)$`)
	reTests          = regexp.MustCompile(`Tests performed:\s*(\d+)`)
	reWarningCount   = regexp.MustCompile(`Warnings\s*:\s*(\d+)`)
)

func parseLynisOutput(hostname string, lines []string) NodeResult {
	node := NodeResult{
		Hostname:  hostname,
		ScannedAt: time.Now(),
	}

	for _, line := range lines {
		if m := reHardeningIndex.FindStringSubmatch(line); len(m) > 1 {
			node.HardeningIndex, _ = strconv.Atoi(m[1])
		}
		if m := reWarning.FindStringSubmatch(line); len(m) > 1 {
			node.Warnings = append(node.Warnings, strings.TrimSpace(m[1]))
		}
		if m := reSuggestion.FindStringSubmatch(line); len(m) > 1 {
			node.Suggestions = append(node.Suggestions, strings.TrimSpace(m[1]))
		}
		if m := reTests.FindStringSubmatch(line); len(m) > 1 {
			node.Tests.Performed, _ = strconv.Atoi(m[1])
		}
		if m := reWarningCount.FindStringSubmatch(line); len(m) > 1 {
			node.Tests.Warnings, _ = strconv.Atoi(m[1])
		}
	}

	// Déduplique warnings et suggestions
	node.Warnings = dedup(node.Warnings)
	node.Suggestions = dedup(node.Suggestions)
	if len(node.Warnings) > 10 {
		node.Warnings = node.Warnings[:10]
	}
	if len(node.Suggestions) > 10 {
		node.Suggestions = node.Suggestions[:10]
	}

	return node
}

func dedup(ss []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range ss {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// ParseFile est une fonction utilitaire pour parser un fichier Lynis directement.
func ParseFile(path string) (*NodeResult, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	hostname := strings.TrimSuffix(strings.TrimPrefix(path, "/var/log/lynis-"), ".txt")
	node := parseLynisOutput(hostname, lines)
	return &node, nil
}
