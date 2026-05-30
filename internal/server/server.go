package server

import (
	"bytes"
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/theo-mrn/beacon/internal/crowdsec"
	"github.com/theo-mrn/beacon/internal/falco"
	"github.com/theo-mrn/beacon/internal/lynis"
	"github.com/theo-mrn/beacon/internal/model"
	"github.com/theo-mrn/beacon/internal/scorer"
	"github.com/theo-mrn/beacon/internal/store"
	"github.com/theo-mrn/beacon/internal/watcher"
)

//go:embed templates/*.html
var templateFS embed.FS

//go:embed static
var staticFS embed.FS

type Server struct {
	watcher   *watcher.KubeWatcher
	store     *store.Store
	crowdsec  *crowdsec.Client
	falco     *falco.Client
	lynis     *lynis.Client
	tmpl      *template.Template
	clients   map[chan string]struct{}
	clientsMu sync.Mutex
}

func New(w *watcher.KubeWatcher, st *store.Store, cs *crowdsec.Client, fc *falco.Client, ly *lynis.Client) (*Server, error) {
	tmpl, err := template.ParseFS(templateFS, "templates/*.html")
	if err != nil {
		return nil, err
	}
	return &Server{
		watcher:  w,
		store:    st,
		crowdsec: cs,
		falco:    fc,
		lynis:    ly,
		tmpl:     tmpl,
		clients:  make(map[chan string]struct{}),
	}, nil
}

func (s *Server) Start(ctx context.Context, addr string) {
	mux := http.NewServeMux()

	// React SPA — served at /app/
	sub, _ := fs.Sub(staticFS, "static")
	staticHandler := http.FileServer(http.FS(sub))
	mux.Handle("/app/", http.StripPrefix("/app", staticHandler))

	// Legacy HTML routes
	mux.HandleFunc("/old", s.handleIndex)
	mux.HandleFunc("/cves", s.handleCVEPage)
	mux.HandleFunc("/portal", s.handlePortal)

	// SSE — both paths for compat
	mux.HandleFunc("/stream", s.handleSSE)
	mux.HandleFunc("/sse", s.handleSSE)

	// APIs
	mux.HandleFunc("/api/endpoints", s.handleAPI)
	mux.HandleFunc("/api/cves", s.handleCVEs)
	mux.HandleFunc("/api/portals", s.handlePortalsAPI)
	mux.HandleFunc("/api/review", s.handleReview)
	mux.HandleFunc("/api/reviews", s.handleReviews)
	mux.HandleFunc("/api/crowdsec", s.handleCrowdSec)
	mux.HandleFunc("/api/falco", s.handleFalco)
	mux.HandleFunc("/api/lynis", s.handleLynis)
	mux.HandleFunc("/api/topology", s.handleTopology)

	// Root redirect to React app
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/app/", http.StatusFound)
			return
		}
		http.NotFound(w, r)
	})

	srv := &http.Server{Addr: addr, Handler: mux}
	go func() { <-ctx.Done(); srv.Shutdown(context.Background()) }()
	go s.broadcastLoop(ctx)

	fmt.Printf("dashboard: http://localhost%s\n", addr)
	srv.ListenAndServe()
}

// ── Handlers ──────────────────────────────────────────────────────────────────

func (s *Server) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	eps := s.snapshot()
	p := buildPayloadData(eps)

	var buf bytes.Buffer
	s.tmpl.ExecuteTemplate(&buf, "index.html", map[string]template.HTML{
		"HeaderStats": template.HTML(p.Header),
		"TableRows":   template.HTML(p.Table),
		"NsGroups":    template.HTML(p.Ns),
		"PortalCards": template.HTML(p.Portal),
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

func (s *Server) handleCVEs(w http.ResponseWriter, r *http.Request) {
	ns := r.URL.Query().Get("ns")
	app := r.URL.Query().Get("app")
	w.Header().Set("Content-Type", "application/json")
	if ns == "" || app == "" {
		json.NewEncoder(w).Encode(s.watcher.AllCVEDetails())
		return
	}
	cves := s.watcher.CVEsForApp(ns, app)
	if cves == nil {
		cves = []model.CVEDetail{}
	}
	json.NewEncoder(w).Encode(cves)
}

func (s *Server) handlePortalsAPI(w http.ResponseWriter, r *http.Request) {
	type PortalEntry struct {
		Name      string `json:"name"`
		Namespace string `json:"namespace"`
		Hostname  string `json:"hostname"`
		URL       string `json:"url"`
		TLS       bool   `json:"tls"`
		Risk      string `json:"risk"`
	}
	eps := s.snapshot()
	var out []PortalEntry
	for _, ep := range eps {
		isIngress := ep.SourceKind == model.ExposureIngress || ep.SourceKind == model.ExposureIngressRoute
		if !isIngress && ep.Hostname == "" {
			continue
		}
		if ep.Hostname != "" && !scorer.Default.IsPortalVisible(ep.Hostname) {
			continue
		}
		out = append(out, PortalEntry{
			Name:      ep.ObjectName,
			Namespace: ep.Namespace,
			Hostname:  epHost(ep),
			URL:       epURL(ep),
			TLS:       ep.TLS,
			Risk:      string(ep.Risk),
		})
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(out)
}

func (s *Server) handleCrowdSec(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	stats := s.crowdsec.Stats()

	eps := s.snapshot()
	var infos []crowdsec.EndpointInfo
	for _, ep := range eps {
		if ep.ExternalIP == "" {
			continue
		}
		infos = append(infos, crowdsec.EndpointInfo{
			Namespace:  ep.Namespace,
			Name:       ep.ObjectName,
			URL:        epURL(ep),
			Risk:       string(ep.Risk),
			ExternalIP: ep.ExternalIP,
		})
	}
	stats.Correlations = s.crowdsec.Correlate(infos)
	json.NewEncoder(w).Encode(stats)
}

func (s *Server) handleFalco(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.falco.Stats())
}

func (s *Server) handleLynis(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(s.lynis.Stats())
}

func (s *Server) handleReview(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodDelete {
		key := r.URL.Query().Get("key")
		if key == "" {
			http.Error(w, "missing key", http.StatusBadRequest)
			return
		}
		if err := s.store.DeleteReview(key); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	var req struct {
		Key     string `json:"key"`
		Status  string `json:"status"`
		Comment string `json:"comment"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "bad json", http.StatusBadRequest)
		return
	}
	if req.Key == "" || req.Status == "" {
		http.Error(w, "key and status required", http.StatusBadRequest)
		return
	}
	if err := s.store.SetReview(req.Key, store.ReviewStatus(req.Status), req.Comment); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleReviews(w http.ResponseWriter, r *http.Request) {
	reviews, err := s.store.GetAllReviews()
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(reviews)
}

func (s *Server) handleCVEPage(w http.ResponseWriter, r *http.Request) {
	var buf bytes.Buffer
	s.tmpl.ExecuteTemplate(&buf, "cves.html", nil)
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(buf.Bytes())
}

func (s *Server) handlePortal(w http.ResponseWriter, r *http.Request) {
	eps := s.snapshot()

	// Sort alphabetically by URL for the portal
	sort.Slice(eps, func(i, j int) bool {
		return epKey(eps[i]) < epKey(eps[j])
	})

	nsCount := map[string]int{}
	for _, ep := range eps {
		nsCount[ep.Namespace]++
	}
	nsSorted := make([]string, 0, len(nsCount))
	for ns := range nsCount {
		nsSorted = append(nsSorted, ns)
	}
	sort.Strings(nsSorted)

	var nsButtons strings.Builder
	for _, ns := range nsSorted {
		nsButtons.WriteString(fmt.Sprintf(
			`<button onclick="filterNs('%s')" data-ns="%s"
        class="ns-btn w-full text-left px-4 py-2 text-sm text-slate-600 hover:bg-slate-50 transition-colors flex items-center justify-between">
        %s<span class="text-xs font-semibold text-slate-400">%d</span>
      </button>`, ns, ns, ns, nsCount[ns]))
	}

	var cards strings.Builder
	for _, ep := range eps {
		cards.WriteString(renderPortalCard(ep))
	}

	var buf bytes.Buffer
	s.tmpl.ExecuteTemplate(&buf, "portal.html", map[string]template.HTML{
		"Total":     template.HTML(fmt.Sprintf("%d", len(eps))),
		"NsButtons": template.HTML(nsButtons.String()),
		"Cards":     template.HTML(cards.String()),
	})
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Write(buf.Bytes())
}

func renderPortalCard(ep model.ExposedEndpoint) string {
	url := epURL(ep)
	_, riskBadge, riskText := riskClasses(ep.Risk)

	scheme := "http"
	if ep.TLS {
		scheme = "https"
	}

	schemeTag := fmt.Sprintf(`<span class="text-xs font-mono font-semibold text-slate-400">%s</span>`, scheme)
	if ep.TLS {
		schemeTag = `<span class="text-xs font-mono font-semibold text-emerald-600">https</span>`
	}

	displayURL := url
	if displayURL == "" {
		displayURL = ep.ObjectName
	}

	// Favicon letter
	letter := string([]rune(ep.ObjectName)[0:1])

	searchData := strings.ToLower(ep.ObjectName + " " + ep.Namespace + " " + url + " " + string(ep.SourceKind))

	inner := fmt.Sprintf(`
    <div class="flex items-start gap-3 mb-3">
      <div class="w-9 h-9 rounded-lg bg-indigo-50 border border-indigo-100 flex items-center justify-center flex-shrink-0">
        <span class="text-sm font-bold text-indigo-600 uppercase">%s</span>
      </div>
      <div class="flex-1 min-w-0">
        <p class="text-sm font-semibold text-slate-900 truncate">%s</p>
        <p class="text-xs text-slate-400 mt-0.5">%s · %s</p>
      </div>
    </div>
    <div class="flex items-center gap-1.5 mb-3">
      %s
      <span class="text-xs text-slate-500 truncate font-mono">%s</span>
    </div>
    <div class="flex items-center justify-between">
      <span class="inline-flex items-center gap-1 text-xs font-semibold px-2 py-0.5 rounded-full %s">%s</span>
      %s
    </div>`,
		letter,
		ep.ObjectName,
		ep.Namespace, ep.SourceKind,
		schemeTag,
		displayURL,
		riskBadge, riskText,
		cveBadgeHTML(ep),
	)

	if url != "" {
		return fmt.Sprintf(`
<a href="%s" target="_blank" rel="noopener"
  class="service-card card-link block bg-white rounded-xl border border-slate-200 p-4 cursor-pointer"
  data-ns="%s" data-search="%s">%s</a>`, url, ep.Namespace, searchData, inner)
	}
	return fmt.Sprintf(`
<div class="service-card bg-white rounded-xl border border-slate-200 p-4 opacity-60"
  data-ns="%s" data-search="%s">%s</div>`, ep.Namespace, searchData, inner)
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
	Header      string
	Table       string
	Ns          string
	Portal      string
	Namespaces  []string
	HighCount   int
	Counts      map[string]int
}

func (s *Server) buildSSEPayload() string {
	eps := s.snapshot()
	p := buildPayloadData(eps)

	out := map[string]interface{}{
		"header":     p.Header,
		"table":      p.Table,
		"ns":         p.Ns,
		"portal":     p.Portal,
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
		Portal:     renderPortalCards(eps),
		Counts:     map[string]int{"HIGH": high, "MEDIUM": med, "LOW": low},
		Namespaces: namespaces,
		HighCount:  high,
	}
}

func (s *Server) snapshot() []model.ExposedEndpoint {
	eps := s.watcher.Snapshot()
	reviews, _ := s.store.GetAllReviews()
	for i := range eps {
		sr := scorer.Default.ScoreWithReasons(&eps[i])
		eps[i].Risk = sr.Level
		eps[i].RiskReasons = sr.Reasons
		key := endpointStoreKey(eps[i])
		if rv, ok := reviews[key]; ok {
			eps[i].ReviewStatus = string(rv.Status)
			eps[i].ReviewComment = rv.Comment
		}
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

func endpointStoreKey(ep model.ExposedEndpoint) string {
	host := ep.Hostname
	if host == "" {
		host = ep.ExternalIP
	}
	return fmt.Sprintf("%s/%s/%s/%s", ep.Namespace, string(ep.SourceKind), ep.ObjectName, host)
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
	// Trouve le nom d'app depuis les services (premier service = app principale)
	app := ep.ObjectName
	if len(ep.Services) > 0 && ep.Services[0].Name != "" {
		app = ep.Services[0].Name
	}
	return fmt.Sprintf(
		`<button onclick="showCVEs('%s','%s','%s')" title="Voir les CVEs"
		class="inline-flex items-center gap-1 text-xs font-semibold px-2 py-0.5 rounded-full bg-purple-100 text-purple-700 border border-purple-200 hover:bg-purple-200 transition-colors cursor-pointer">
		<svg class="w-3 h-3" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
		  <path stroke-linecap="round" stroke-linejoin="round" d="M12 9v3.75m-9.303 3.376c-.866 1.5.217 3.374 1.948 3.374h14.71c1.73 0 2.813-1.874 1.948-3.374L13.949 3.378c-.866-1.5-3.032-1.5-3.898 0L2.697 16.126zM12 15.75h.007v.008H12v-.008z"/>
		</svg>CVE %s</button>`,
		ep.Namespace, app, label, label)
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

	key := endpointStoreKey(ep)
	reviewHTML := reviewBadgeHTML(ep.ReviewStatus, key, ep.ReviewComment)

	// Faux positif ou Accepté → on efface le badge de risque, ligne atténuée
	dismissed := ep.ReviewStatus == "ACCEPTED" || ep.ReviewStatus == "FALSE_POSITIVE"

	rowClass := ""
	if dismissed {
		rowClass = " opacity-40"
	}

	riskCell := ""
	if dismissed {
		// Pas de badge risque, juste le badge review
		riskCell = reviewHTML
	} else {
		toFixExtra := ""
		if ep.ReviewStatus == "TO_FIX" {
			toFixExtra = `<div class="mt-0.5">` + reviewHTML + `</div>`
		}
		// Badge risque normal + tooltip raisons + badge status (NEW/MODIFIED)
		riskCell = fmt.Sprintf(`
    <div class="flex flex-col gap-1">
      <span class="beacon-tooltip inline-flex items-center gap-1.5 text-xs font-semibold px-2 py-1 rounded-full %s">
        <span class="w-1.5 h-1.5 rounded-full %s"></span>%s%s
      </span>
      %s%s
    </div>`,
			riskBadge, riskDot, riskText, reasonsTooltip(ep.RiskReasons),
			statusBadgeHTML(ep.Status),
			toFixExtra,
		)
	}

	// Colonne review : si déjà dans riskCell (dismissed ou TO_FIX), juste le bouton crayon
	reviewCol := reviewHTML
	if dismissed || ep.ReviewStatus == "TO_FIX" {
		// Déjà affiché dans riskCell, colonne review = bouton edit discret
		safeKey := strings.ReplaceAll(endpointStoreKey(ep), "'", "\\'")
		safeComment := strings.ReplaceAll(ep.ReviewComment, "'", "\\'")
		safeComment = strings.ReplaceAll(safeComment, "\n", " ")
		reviewCol = fmt.Sprintf(
			`<button onclick="openReviewModal('%s','%s','%s')" title="Modifier"
			class="text-slate-300 hover:text-slate-500 transition-colors cursor-pointer">
			<svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
			  <path stroke-linecap="round" stroke-linejoin="round" d="M16.862 4.487l1.687-1.688a1.875 1.875 0 112.652 2.652L10.582 16.07a4.5 4.5 0 01-1.897 1.13L6 18l.8-2.685a4.5 4.5 0 011.13-1.897l8.932-8.931zm0 0L19.5 7.125"/>
			</svg></button>`, safeKey, ep.ReviewStatus, safeComment)
	}

	return fmt.Sprintf(`
<tr class="tr-row border-b border-slate-100 last:border-0%s" data-risk="%s" data-ns="%s" data-review="%s">
  <td class="px-4 py-3">%s</td>
  <td class="px-4 py-3 text-xs font-mono text-slate-600">%s</td>
  <td class="px-4 py-3">
    <span class="text-xs font-medium bg-slate-100 text-slate-600 px-2 py-0.5 rounded-full">%s</span>
  </td>
  <td class="px-4 py-3">%s</td>
  <td class="px-4 py-3"><div class="flex flex-wrap gap-1">%s</div></td>
  <td class="px-4 py-3">%s</td>
  <td class="px-4 py-3">%s</td>
</tr>`,
		rowClass,
		ep.Risk, ep.Namespace, ep.ReviewStatus,
		riskCell,
		ep.SourceKind,
		ep.Namespace,
		urlHTML,
		portsHTML,
		podsHTML,
		reviewCol,
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
<div data-nsgroup="%s" class="bg-white rounded-xl border border-slate-200 overflow-hidden shadow-sm">
  <div class="flex items-center gap-3 px-5 py-3 bg-slate-50 border-b border-slate-200">
    %s
    <div class="flex items-center gap-1.5">%s</div>
    <span class="ml-auto text-xs text-slate-400 font-medium">%d endpoint%s</span>
  </div>
  <div>%s</div>
</div>`, ns, nsBadge, summaryBadges, len(nsEps), pluralS(len(nsEps)), cardsHTML.String()))
	}
	return sb.String()
}

func renderNsCard(ep model.ExposedEndpoint) string {
	_, riskBadge, riskText := riskClasses(ep.Risk)
	url := epURL(ep)

	urlHTML := `<span class="text-slate-400 text-xs">—</span>`
	if url != "" {
		urlHTML = fmt.Sprintf(`<a href="%s" target="_blank" rel="noopener" class="text-indigo-600 hover:text-indigo-800 hover:underline font-mono text-sm font-medium">%s ↗</a>`, url, url)
	}

	// Services
	var svcsHTML strings.Builder
	for _, svc := range ep.Services {
		if svc.Name == "" {
			continue
		}
		svcsHTML.WriteString(fmt.Sprintf(`<span class="text-xs font-mono text-slate-500 bg-slate-100 px-2 py-0.5 rounded">%s:%d</span>`, svc.Name, svc.Port))
	}

	// Pods
	podsStr := ""
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
		podsStr = fmt.Sprintf(`<span class="text-xs font-medium %s">%d/%d pods</span>`, col, running, len(ep.Pods))
	}

	tlsStr := ""
	if ep.TLS {
		tlsStr = `<span class="text-xs font-semibold text-emerald-600 bg-emerald-50 border border-emerald-200 px-2 py-0.5 rounded-full">TLS</span>`
	}

	cve := cveBadgeHTML(ep)
	status := statusBadgeHTML(ep.Status)

	return fmt.Sprintf(`
<div class="px-5 py-4 hover:bg-slate-50/60 transition-colors border-b border-slate-100 last:border-0" data-risk="%s">
  <div class="flex items-center justify-between gap-4">
    <div class="flex items-center gap-2 flex-wrap min-w-0">
      <span class="inline-flex items-center gap-1.5 text-xs font-semibold px-2.5 py-1 rounded-full %s">%s</span>
      <span class="text-xs font-mono text-slate-400 bg-slate-100 px-2 py-0.5 rounded">%s</span>
      %s%s%s
    </div>
    <div class="flex items-center gap-2 flex-shrink-0">%s%s</div>
  </div>
  <div class="mt-2 flex items-center gap-3 flex-wrap">
    %s
    <div class="flex gap-1 flex-wrap">%s</div>
  </div>
</div>`,
		ep.Risk,
		riskBadge, riskText,
		ep.SourceKind,
		tlsStr, status, cve,
		urlHTML, podsStr,
		renderPortTags(ep.Ports),
		svcsHTML.String(),
	)
}

func renderPortalCards(eps []model.ExposedEndpoint) string {
	// Sort alphabetically
	sorted := make([]model.ExposedEndpoint, len(eps))
	copy(sorted, eps)
	sort.Slice(sorted, func(i, j int) bool {
		return sorted[i].ObjectName < sorted[j].ObjectName
	})
	var sb strings.Builder
	for _, ep := range sorted {
		// Portail : Ingress/IngressRoute (toujours web) OU endpoint avec hostname
		isIngress := ep.SourceKind == model.ExposureIngress || ep.SourceKind == model.ExposureIngressRoute
		if !isIngress && ep.Hostname == "" {
			continue
		}
		if ep.Hostname != "" && !scorer.Default.IsPortalVisible(ep.Hostname) {
			continue
		}
		url := epURL(ep)
		host := epHost(ep)
		title := ep.Hostname
		if title == "" {
			title = ep.ObjectName
		} else if i := strings.Index(title, "."); i > 0 {
			title = title[:i]
		}
		letter := strings.ToUpper(string([]rune(title)[0:1]))
		tlsClass := "text-slate-400"
		scheme := "http"
		if ep.TLS {
			scheme = "https"
			tlsClass = "text-emerald-500"
		}
		search := strings.ToLower(title + " " + host + " " + ep.Namespace + " " + ep.ObjectName)
		sb.WriteString(fmt.Sprintf(`
<a href="%s" target="_blank" rel="noopener"
  class="portal-card block bg-white rounded-xl border border-slate-200 p-4 hover:shadow-md hover:-translate-y-px transition-all duration-150 cursor-pointer"
  data-ns="%s" data-search="%s">
  <div class="flex items-start gap-3 mb-3">
    <div class="w-9 h-9 rounded-lg bg-indigo-50 border border-indigo-100 flex items-center justify-center flex-shrink-0">
      <span class="text-sm font-bold text-indigo-600">%s</span>
    </div>
    <div class="flex-1 min-w-0">
      <p class="text-sm font-semibold text-slate-900 truncate">%s</p>
      <p class="text-xs text-slate-400 mt-0.5">%s</p>
    </div>
  </div>
  <p class="text-xs font-mono truncate"><span class="font-semibold %s">%s://</span><span class="text-slate-500">%s</span></p>
</a>`, url, ep.Namespace, search, letter, title, ep.Namespace, tlsClass, scheme, host))
	}
	return sb.String()
}


func epHost(ep model.ExposedEndpoint) string {
	if ep.Hostname != "" {
		return ep.Hostname
	}
	if ep.ExternalIP != "" && len(ep.Ports) > 0 {
		return fmt.Sprintf("%s:%d", ep.ExternalIP, ep.Ports[0].Port)
	}
	return ""
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

func reviewBadgeHTML(status, key, comment string) string {
	safeKey := strings.ReplaceAll(key, "'", "\\'")
	safeComment := strings.ReplaceAll(comment, "'", "\\'")
	safeComment = strings.ReplaceAll(safeComment, "\n", " ")
	if status == "" {
		return fmt.Sprintf(
			`<button onclick="openReviewModal('%s','','%s')" title="Annoter"
			class="text-slate-300 hover:text-slate-500 transition-colors cursor-pointer">
			<svg class="w-4 h-4" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
			  <path stroke-linecap="round" stroke-linejoin="round" d="M16.862 4.487l1.687-1.688a1.875 1.875 0 112.652 2.652L10.582 16.07a4.5 4.5 0 01-1.897 1.13L6 18l.8-2.685a4.5 4.5 0 011.13-1.897l8.932-8.931zm0 0L19.5 7.125"/>
			</svg></button>`, safeKey, safeComment)
	}
	label, cls := reviewLabel(status)
	tooltipHTML := ""
	if comment != "" {
		tooltipHTML = fmt.Sprintf(`<span class="tt">%s</span>`, comment)
	}
	return fmt.Sprintf(
		`<span class="beacon-tooltip"><button onclick="openReviewModal('%s','%s','%s')"
		class="inline-flex items-center gap-1 text-xs font-semibold px-2 py-0.5 rounded-full border cursor-pointer %s">%s</button>%s</span>`,
		safeKey, status, safeComment, cls, label, tooltipHTML)
}

type topologyResponse struct {
	Controllers []watcher.IngressController `json:"controllers"`
	Endpoints   []model.ExposedEndpoint     `json:"endpoints"`
}

func (s *Server) handleTopology(w http.ResponseWriter, r *http.Request) {
	controllers := s.watcher.DetectIngressControllers(r.Context())
	endpoints := s.watcher.Snapshot()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(topologyResponse{
		Controllers: controllers,
		Endpoints:   endpoints,
	})
}

func reviewLabel(status string) (string, string) {
	switch status {
	case "ACCEPTED":
		return "✓ Accepté", "bg-emerald-50 text-emerald-700 border-emerald-200"
	case "FALSE_POSITIVE":
		return "↩ Faux positif", "bg-blue-50 text-blue-700 border-blue-200"
	case "TO_FIX":
		return "⚠ À corriger", "bg-orange-50 text-orange-700 border-orange-200"
	default:
		return status, "bg-slate-100 text-slate-600 border-slate-200"
	}
}

func reasonsTooltip(reasons []string) string {
	if len(reasons) == 0 {
		return ""
	}
	var lines string
	for _, r := range reasons {
		lines += `<div>⚠ ` + r + `</div>`
	}
	return fmt.Sprintf(`<span class="tt" style="white-space:normal;min-width:180px;text-align:left">%s</span>`, lines)
}

func pluralS(n int) string {
	if n > 1 {
		return "s"
	}
	return ""
}
