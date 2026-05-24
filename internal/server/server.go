package server

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/theo-mrn/beacon/internal/model"
	"github.com/theo-mrn/beacon/internal/scorer"
	"github.com/theo-mrn/beacon/internal/watcher"
)

//go:embed templates/*.html
var templateFS embed.FS

type Server struct {
	watcher   *watcher.KubeWatcher
	tmpl      *template.Template
	clients   map[chan string]struct{}
	clientsMu sync.Mutex
}

func New(w *watcher.KubeWatcher) (*Server, error) {
	tmpl, err := template.ParseFS(templateFS, "templates/*.html")
	if err != nil {
		return nil, err
	}
	return &Server{
		watcher: w,
		tmpl:    tmpl,
		clients: make(map[chan string]struct{}),
	}, nil
}

func (s *Server) Start(ctx context.Context, addr string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", s.handleIndex)
	mux.HandleFunc("/stream", s.handleSSE)
	mux.HandleFunc("/api/endpoints", s.handleAPI)

	srv := &http.Server{Addr: addr, Handler: mux}
	go func() { <-ctx.Done(); srv.Shutdown(context.Background()) }()
	go s.broadcastLoop(ctx)

	fmt.Printf("dashboard: http://localhost%s\n", addr)
	srv.ListenAndServe()
}

// ── Handlers ──────────────────────────────────────────────────────────────────

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	eps := s.snapshot()
	p := buildPayloadData(eps)

	var buf bytes.Buffer
	s.tmpl.ExecuteTemplate(&buf, "index.html", map[string]template.HTML{
		"HeaderStats": template.HTML(p.Header),
		"TableRows":   template.HTML(p.Table),
		"NsGroups":    template.HTML(p.Ns),
	})
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(buf.Bytes())
}

func (s *Server) handleSSE(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("Access-Control-Allow-Origin", "*")

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "streaming not supported", http.StatusInternalServerError)
		return
	}

	ch := make(chan string, 4)
	s.clientsMu.Lock()
	s.clients[ch] = struct{}{}
	s.clientsMu.Unlock()
	defer func() {
		s.clientsMu.Lock()
		delete(s.clients, ch)
		s.clientsMu.Unlock()
	}()

	if msg := s.buildSSEPayload(); msg != "" {
		fmt.Fprintf(w, "event: update\ndata: %s\n\n", msg)
		flusher.Flush()
	}

	for {
		select {
		case <-r.Context().Done():
			return
		case msg, ok := <-ch:
			if !ok {
				return
			}
			fmt.Fprintf(w, "event: update\ndata: %s\n\n", msg)
			flusher.Flush()
		}
	}
}

func (s *Server) handleAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.snapshot())
}

// ── Broadcast ─────────────────────────────────────────────────────────────────

func (s *Server) broadcastLoop(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.watcher.Updates:
			drain(s.watcher.Updates, 500*time.Millisecond)
			msg := s.buildSSEPayload()
			if msg == "" {
				continue
			}
			s.clientsMu.Lock()
			for ch := range s.clients {
				select {
				case ch <- msg:
				default:
				}
			}
			s.clientsMu.Unlock()
		}
	}
}

func drain(ch <-chan struct{}, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	for {
		select {
		case <-ch:
			t.Reset(d)
		case <-t.C:
			return
		}
	}
}

// ── Payload ───────────────────────────────────────────────────────────────────

type payloadData struct {
	Header     string
	Table      string
	Ns         string
	Namespaces []string
	HighCount  int
	Counts     map[string]int
}

func (s *Server) buildSSEPayload() string {
	eps := s.snapshot()
	p := buildPayloadData(eps)

	out := map[string]interface{}{
		"header":     p.Header,
		"table":      p.Table,
		"ns":         p.Ns,
		"namespaces": p.Namespaces,
		"high_count": p.HighCount,
		"counts":     p.Counts,
	}
	b, err := json.Marshal(out)
	if err != nil {
		return ""
	}
	return string(b)
}

func buildPayloadData(eps []model.ExposedEndpoint) payloadData {
	high, med, low := 0, 0, 0
	nsSet := map[string]bool{}
	for _, ep := range eps {
		switch ep.Risk {
		case model.RiskHigh:
			high++
		case model.RiskMedium:
			med++
		default:
			low++
		}
		nsSet[ep.Namespace] = true
	}

	namespaces := make([]string, 0, len(nsSet))
	for ns := range nsSet {
		namespaces = append(namespaces, ns)
	}
	sort.Strings(namespaces)

	return payloadData{
		Header:     renderHeaderStats(high, med, low),
		Table:      renderTableRows(eps),
		Ns:         renderNsGroups(eps, namespaces),
		Counts:     map[string]int{"HIGH": high, "MEDIUM": med, "LOW": low},
		Namespaces: namespaces,
		HighCount:  high,
	}
}

func (s *Server) snapshot() []model.ExposedEndpoint {
	eps := s.watcher.Snapshot()
	for i := range eps {
		eps[i].Risk = scorer.Score(&eps[i])
	}
	sort.Slice(eps, func(i, j int) bool {
		ri, rj := riskOrder(eps[i].Risk), riskOrder(eps[j].Risk)
		if ri != rj {
			return ri > rj
		}
		return epKey(eps[i]) < epKey(eps[j])
	})
	return eps
}

// ── Renderers ─────────────────────────────────────────────────────────────────

func renderHeaderStats(high, med, low int) string {
	total := high + med + low
	score, scoreClass := clusterScore(high, med, low, total)
	return fmt.Sprintf(`
<div class="flex items-center gap-1.5">
  <span class="text-xs font-semibold text-slate-500">Score</span>
  <span class="text-sm font-bold px-2.5 py-0.5 rounded-full %s">%s</span>
</div>
<div class="w-px h-4 bg-slate-200"></div>
<div class="flex items-center gap-1.5">
  <span class="w-2 h-2 rounded-full bg-red-500"></span>
  <span class="text-sm font-semibold text-slate-900">%d</span>
  <span class="text-xs text-slate-400">HIGH</span>
</div>
<div class="flex items-center gap-1.5">
  <span class="w-2 h-2 rounded-full bg-amber-400"></span>
  <span class="text-sm font-semibold text-slate-900">%d</span>
  <span class="text-xs text-slate-400">MED</span>
</div>
<div class="flex items-center gap-1.5">
  <span class="w-2 h-2 rounded-full bg-emerald-500"></span>
  <span class="text-sm font-semibold text-slate-900">%d</span>
  <span class="text-xs text-slate-400">LOW</span>
</div>
<div class="w-px h-4 bg-slate-200"></div>
<span class="text-xs text-slate-400">%d endpoints</span>`,
		scoreClass, score, high, med, low, total)
}

func clusterScore(high, med, low, total int) (string, string) {
	if total == 0 {
		return "—", "bg-slate-100 text-slate-500"
	}
	if high == 0 && med == 0 {
		return "A", "bg-emerald-100 text-emerald-700"
	}
	if high == 0 && med <= 2 {
		return "B", "bg-blue-100 text-blue-700"
	}
	if high == 0 {
		return "C", "bg-amber-100 text-amber-700"
	}
	if high <= 2 {
		return "D", "bg-orange-100 text-orange-700"
	}
	return "F", "bg-red-100 text-red-700"
}

func renderTableRows(eps []model.ExposedEndpoint) string {
	if len(eps) == 0 {
		return `<tr><td colspan="6" class="text-center py-16 text-slate-400 text-sm">Aucun endpoint exposé détecté</td></tr>`
	}
	var sb strings.Builder
	for _, ep := range eps {
		sb.WriteString(renderTableRow(ep))
	}
	return sb.String()
}

func cveBadgeHTML(ep model.ExposedEndpoint) string {
	if ep.CVECritical == 0 && ep.CVEHigh == 0 {
		return ""
	}
	label := ""
	if ep.CVECritical > 0 {
		label += fmt.Sprintf("%d CRIT", ep.CVECritical)
	}
	if ep.CVEHigh > 0 {
		if label != "" {
			label += " · "
		}
		label += fmt.Sprintf("%d HIGH", ep.CVEHigh)
	}
	if ep.TrivyURL != "" {
		return fmt.Sprintf(
			`<a href="%s" target="_blank" rel="noopener" title="Voir dans Trivy"
        class="inline-flex items-center gap-1 text-xs font-semibold px-2 py-0.5 rounded-full bg-purple-100 text-purple-700 border border-purple-200 hover:bg-purple-200 transition-colors cursor-pointer">
        <svg class="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
          <path stroke-linecap="round" stroke-linejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z"/>
        </svg>CVE %s ↗</a>`, ep.TrivyURL, label)
	}
	return fmt.Sprintf(
		`<span class="inline-flex items-center gap-1 text-xs font-semibold px-2 py-0.5 rounded-full bg-purple-100 text-purple-700 border border-purple-200">
        <svg class="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
          <path stroke-linecap="round" stroke-linejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z"/>
        </svg>CVE %s</span>`, label)
}

func statusBadgeHTML(status string) string {
	switch status {
	case "NEW":
		return `<span class="text-xs font-semibold px-2 py-0.5 rounded-full bg-blue-100 text-blue-700 border border-blue-200">NEW</span>`
	case "MODIFIED":
		return `<span class="text-xs font-semibold px-2 py-0.5 rounded-full bg-orange-100 text-orange-700 border border-orange-200">MODIFIED</span>`
	default:
		return ""
	}
}

func renderTableRow(ep model.ExposedEndpoint) string {
	riskDot, riskBadge, riskText := riskClasses(ep.Risk)

	url := epURL(ep)
	urlHTML := `<span class="text-slate-400 text-xs">—</span>`
	if url != "" {
		urlHTML = fmt.Sprintf(
			`<a href="%s" target="_blank" rel="noopener"
        class="text-blue-600 hover:text-blue-800 hover:underline text-sm font-medium transition-colors cursor-pointer">%s
        <svg class="inline w-3 h-3 ml-0.5 opacity-50" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2.5">
          <path stroke-linecap="round" stroke-linejoin="round" d="M13.5 6H5.25A2.25 2.25 0 003 8.25v10.5A2.25 2.25 0 005.25 21h10.5A2.25 2.25 0 0018 18.75V10.5m-10.5 6L21 3m0 0h-5.25M21 3v5.25"/>
        </svg></a>`, url, url)
	}

	portsHTML := renderPortTags(ep.Ports)

	podsHTML := `<span class="text-slate-400 text-xs">—</span>`
	if len(ep.Pods) > 0 {
		running := 0
		for _, p := range ep.Pods {
			if p.Status == "Running" {
				running++
			}
		}
		color := "text-slate-600"
		if running < len(ep.Pods) {
			color = "text-amber-600"
		}
		podsHTML = fmt.Sprintf(`<span class="text-xs font-medium %s">%d / %d</span><span class="text-slate-400 text-xs ml-1">running</span>`, color, running, len(ep.Pods))
	}

	return fmt.Sprintf(`
<tr class="tr-row border-b border-slate-100 last:border-0" data-risk="%s" data-ns="%s">
  <td class="px-4 py-3">
    <div class="flex flex-col gap-1">
      <span class="inline-flex items-center gap-1.5 text-xs font-semibold px-2 py-1 rounded-full %s">
        <span class="w-1.5 h-1.5 rounded-full %s"></span>%s
      </span>
      %s
    </div>
  </td>
  <td class="px-4 py-3 text-xs font-mono text-slate-600">%s</td>
  <td class="px-4 py-3">
    <span class="text-xs font-medium bg-slate-100 text-slate-600 px-2 py-0.5 rounded-full">%s</span>
  </td>
  <td class="px-4 py-3">%s</td>
  <td class="px-4 py-3"><div class="flex flex-wrap gap-1">%s</div></td>
  <td class="px-4 py-3">%s</td>
</tr>`,
		ep.Risk, ep.Namespace,
		riskBadge, riskDot, riskText,
		statusBadgeHTML(ep.Status),
		ep.SourceKind,
		ep.Namespace,
		urlHTML,
		portsHTML,
		podsHTML,
	)
}

func renderNsGroups(eps []model.ExposedEndpoint, namespaces []string) string {
	// Group by namespace
	byNs := map[string][]model.ExposedEndpoint{}
	for _, ep := range eps {
		byNs[ep.Namespace] = append(byNs[ep.Namespace], ep)
	}

	var sb strings.Builder
	for _, ns := range namespaces {
		nsEps := byNs[ns]
		high, med, low := 0, 0, 0
		for _, ep := range nsEps {
			switch ep.Risk {
			case model.RiskHigh:
				high++
			case model.RiskMedium:
				med++
			default:
				low++
			}
		}

		// Namespace header badge
		nsBadge := fmt.Sprintf(`<span class="text-xs font-medium bg-slate-100 text-slate-600 px-2.5 py-1 rounded-full">%s</span>`, ns)
		summaryBadges := ""
		if high > 0 {
			summaryBadges += fmt.Sprintf(`<span class="text-xs font-semibold px-2 py-0.5 rounded-full bg-red-100 text-red-700">%d HIGH</span>`, high)
		}
		if med > 0 {
			summaryBadges += fmt.Sprintf(` <span class="text-xs font-semibold px-2 py-0.5 rounded-full bg-amber-100 text-amber-700">%d MED</span>`, med)
		}
		if low > 0 {
			summaryBadges += fmt.Sprintf(` <span class="text-xs font-semibold px-2 py-0.5 rounded-full bg-emerald-100 text-emerald-700">%d LOW</span>`, low)
		}

		var cardsHTML strings.Builder
		for _, ep := range nsEps {
			cardsHTML.WriteString(renderNsCard(ep))
		}

		sb.WriteString(fmt.Sprintf(`
<div data-nsgroup="%s" class="bg-white rounded-xl border border-slate-200 overflow-hidden">
  <div class="flex items-center gap-3 px-4 py-3 border-b border-slate-100 bg-slate-50">
    %s
    <div class="flex items-center gap-1.5">%s</div>
    <span class="ml-auto text-xs text-slate-400">%d endpoint%s</span>
  </div>
  <div class="divide-y divide-slate-100">%s</div>
</div>`, ns, nsBadge, summaryBadges, len(nsEps), pluralS(len(nsEps)), cardsHTML.String()))
	}
	return sb.String()
}

func renderNsCard(ep model.ExposedEndpoint) string {
	riskDot, riskBadge, riskText := riskClasses(ep.Risk)
	url := epURL(ep)

	urlHTML := `<span class="text-slate-400 text-xs font-mono">—</span>`
	if url != "" {
		urlHTML = fmt.Sprintf(
			`<a href="%s" target="_blank" rel="noopener"
        class="text-blue-600 hover:text-blue-800 hover:underline text-sm font-medium transition-colors cursor-pointer font-mono">%s</a>`,
			url, url)
	}

	// Services
	var svcsHTML strings.Builder
	for _, svc := range ep.Services {
		if svc.Name == "" {
			continue
		}
		svcsHTML.WriteString(fmt.Sprintf(
			`<span class="text-xs font-mono text-slate-500 bg-slate-50 border border-slate-200 px-2 py-0.5 rounded">%s:%d</span> `,
			svc.Name, svc.Port,
		))
	}

	// Pods
	podsHTML := ""
	if len(ep.Pods) > 0 {
		running := 0
		for _, p := range ep.Pods {
			if p.Status == "Running" {
				running++
			}
		}
		col := "text-emerald-600"
		if running < len(ep.Pods) {
			col = "text-amber-600"
		}
		podsHTML = fmt.Sprintf(`<div class="flex items-center gap-1 mt-1">
      <svg class="w-3 h-3 text-slate-400" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
        <path stroke-linecap="round" stroke-linejoin="round" d="M21 7.5l-9-5.25L3 7.5m18 0l-9 5.25m9-5.25v9l-9 5.25M3 7.5l9 5.25M3 7.5v9l9 5.25m0-9v9"/>
      </svg>
      <span class="text-xs %s font-medium">%d/%d pods running</span>
    </div>`, col, running, len(ep.Pods))
	}

	tlsTag := ""
	if ep.TLS {
		tlsTag = `<span class="text-xs font-medium bg-emerald-50 text-emerald-700 border border-emerald-200 px-2 py-0.5 rounded-full">TLS</span>`
	}

	return fmt.Sprintf(`
<div class="px-4 py-3 hover:bg-slate-50 transition-colors" data-risk="%s">
  <div class="flex items-start justify-between gap-4">
    <div class="flex items-center gap-2.5 flex-wrap">
      <span class="inline-flex items-center gap-1.5 text-xs font-semibold px-2 py-1 rounded-full %s">
        <span class="w-1.5 h-1.5 rounded-full %s"></span>%s
      </span>
      <span class="text-xs font-mono text-slate-500 bg-slate-100 px-2 py-0.5 rounded">%s</span>
      %s
      %s
    </div>
    <div class="flex-shrink-0">%s</div>
  </div>
  <div class="mt-2 pl-1">%s</div>
  <div class="mt-1.5 pl-1 flex flex-wrap gap-1">%s</div>
  %s
</div>`,
		ep.Risk,
		riskBadge, riskDot, riskText,
		ep.SourceKind,
		tlsTag,
		statusBadgeHTML(ep.Status),
		cveBadgeHTML(ep),
		urlHTML,
		renderPortTags(ep.Ports),
		svcsHTML.String(),
		podsHTML,
	)
}

func renderPortTags(ports []model.ExposedPort) string {
	var sb strings.Builder
	for _, p := range ports {
		sensitive := scorer.SensitivePortName(p.Port)
		if sensitive != "" {
			sb.WriteString(fmt.Sprintf(
				`<span class="inline-flex items-center gap-1 text-xs font-mono px-2 py-0.5 rounded border bg-red-50 border-red-200 text-red-700">%d/%s <span class="font-sans font-semibold">! %s</span></span> `,
				p.Port, p.Protocol, sensitive,
			))
		} else {
			extra := ""
			if p.NodePort != 0 {
				extra = fmt.Sprintf(` <span class="text-slate-400">→%d</span>`, p.NodePort)
			}
			sb.WriteString(fmt.Sprintf(
				`<span class="text-xs font-mono px-2 py-0.5 rounded border bg-slate-50 border-slate-200 text-slate-600">%d/%s%s</span> `,
				p.Port, p.Protocol, extra,
			))
		}
	}
	return sb.String()
}

// ── Helpers ───────────────────────────────────────────────────────────────────

func epURL(ep model.ExposedEndpoint) string {
	scheme := "http"
	if ep.TLS {
		scheme = "https"
	}
	if ep.Hostname != "" {
		return fmt.Sprintf("%s://%s", scheme, ep.Hostname)
	}
	if ep.ExternalIP != "" {
		for _, p := range ep.Ports {
			return fmt.Sprintf("%s://%s:%d", scheme, ep.ExternalIP, p.Port)
		}
	}
	return ""
}

func riskClasses(r model.RiskLevel) (dot, badge, text string) {
	switch r {
	case model.RiskHigh:
		return "bg-red-500", "bg-red-100 text-red-700", "HIGH"
	case model.RiskMedium:
		return "bg-amber-400", "bg-amber-100 text-amber-700", "MEDIUM"
	default:
		return "bg-emerald-500", "bg-emerald-100 text-emerald-700", "LOW"
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

func epKey(ep model.ExposedEndpoint) string {
	if ep.Hostname != "" {
		return ep.Hostname
	}
	return ep.ExternalIP
}

func pluralS(n int) string {
	if n > 1 {
		return "s"
	}
	return ""
}
