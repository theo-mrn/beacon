package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sort"
	"strings"
	"syscall"
	"time"

	"github.com/theo-mrn/beacon/internal/model"
	"github.com/theo-mrn/beacon/internal/notify"
	"github.com/theo-mrn/beacon/internal/scorer"
	"github.com/theo-mrn/beacon/internal/server"
	"github.com/theo-mrn/beacon/internal/store"
	"github.com/theo-mrn/beacon/internal/watcher"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

const (
	reset  = "\033[0m"
	bold   = "\033[1m"
	dim    = "\033[2m"
	red    = "\033[31m"
	yellow = "\033[33m"
	green  = "\033[32m"
	cyan   = "\033[36m"
	white  = "\033[37m"
)

func buildConfig() (*rest.Config, error) {
	// In-cluster d'abord (quand on tourne comme Pod)
	if cfg, err := rest.InClusterConfig(); err == nil {
		fmt.Println("mode: in-cluster")
		return cfg, nil
	}
	// Fallback local
	kubeconfig := os.Getenv("KUBECONFIG")
	if kubeconfig == "" {
		home, _ := os.UserHomeDir()
		kubeconfig = home + "/.kube/config"
	}
	fmt.Printf("mode: kubeconfig (%s)\n", kubeconfig)
	return clientcmd.BuildConfigFromFlags("", kubeconfig)
}

func main() {
	cfg, err := buildConfig()
	if err != nil {
		fmt.Fprintf(os.Stderr, "kubeconfig: %v\n", err)
		os.Exit(1)
	}

	client, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "k8s client: %v\n", err)
		os.Exit(1)
	}
	dynClient, err := dynamic.NewForConfig(cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "dynamic client: %v\n", err)
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	// Notifier webhook — actif seulement si configuré dans scoring.yaml
	wh := scorer.Default.Webhooks()
	notifier := notify.New(notify.WebhookConfig{
		Slack:   wh.Slack,
		Teams:   wh.Teams,
		Discord: wh.Discord,
		Generic: wh.Generic,
	})
	if notifier.Enabled() {
		fmt.Println("notify: webhooks activés")
	}

	dbPath := "/var/lib/beacon/beacon.db"
	if p := os.Getenv("BEACON_DB"); p != "" {
		dbPath = p
	}
	st, err := store.Open(dbPath)
	if err != nil {
		// En local sans /var/lib/beacon, fallback sur un fichier temporaire
		st, err = store.Open("beacon.db")
		if err != nil {
			fmt.Fprintf(os.Stderr, "store: %v\n", err)
			os.Exit(1)
		}
	}
	defer st.Close()

	trivyURL := os.Getenv("TRIVY_DASHBOARD_URL")

	w := watcher.New(client, dynClient, notifier, st, trivyURL)
	w.Start(ctx)

	srv, err := server.New(w)
	if err != nil {
		fmt.Fprintf(os.Stderr, "server: %v\n", err)
		os.Exit(1)
	}
	go srv.Start(ctx, ":8080")

	printBanner()
	fmt.Printf("%sEn écoute... premier scan dans 3s (Ctrl+C pour quitter)%s\n", dim, reset)
	time.Sleep(3 * time.Second)

	// Premier affichage immédiat puis refresh à chaque update
	render(w)

	for {
		select {
		case <-ctx.Done():
			fmt.Println("\nArrêt de beacon.")
			return
		case <-w.Updates:
			// Debounce : attendre 500ms que les events se stabilisent
			drain(w.Updates, 500*time.Millisecond)
			render(w)
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

func render(w *watcher.KubeWatcher) {
	endpoints := w.Snapshot()
	for i := range endpoints {
		endpoints[i].Risk = scorer.Score(&endpoints[i])
	}

	// Trier : HIGH en premier, puis par hostname/IP
	sort.Slice(endpoints, func(i, j int) bool {
		ri, rj := riskOrder(endpoints[i].Risk), riskOrder(endpoints[j].Risk)
		if ri != rj {
			return ri > rj
		}
		return endpointKey(endpoints[i]) < endpointKey(endpoints[j])
	})

	fmt.Print("\033[H\033[2J") // clear screen
	printBanner()
	fmt.Printf("%s  %d endpoints exposés  —  %s%s\n\n",
		dim, len(endpoints), time.Now().Format("15:04:05"), reset)

	if len(endpoints) == 0 {
		fmt.Printf("  %sAucun endpoint exposé détecté.%s\n", dim, reset)
		return
	}

	for _, ep := range endpoints {
		printEndpoint(ep)
	}
}

func printEndpoint(ep model.ExposedEndpoint) {
	rc, icon := riskStyle(ep.Risk)

	// ── Ligne principale ─────────────────────────────────────────────────────
	dest := ep.Hostname
	if dest == "" {
		dest = ep.ExternalIP
	}
	if dest == "" {
		dest = "<pending>"
	}

	scheme := "http"
	if ep.TLS {
		scheme = "https"
	}

	var url string
	if ep.Hostname != "" {
		url = fmt.Sprintf("%s://%s", scheme, ep.Hostname)
	} else if ep.ExternalIP != "" {
		for _, p := range ep.Ports {
			url = fmt.Sprintf("%s://%s:%d", scheme, ep.ExternalIP, p.Port)
			break
		}
	}

	portStr := formatPorts(ep.Ports)

	statusTag := ""
	switch ep.Status {
	case "NEW":
		statusTag = fmt.Sprintf(" %s[NEW]%s", "\033[34m", reset)
	case "MODIFIED":
		statusTag = fmt.Sprintf(" %s[MODIFIED]%s", "\033[33m", reset)
	}

	fmt.Printf("%s%s %s%-14s%s %s%-10s%s  %s%-20s%s  %s%s%s%s\n",
		rc, icon, reset,
		ep.SourceKind, reset,
		rc, ep.Risk, reset,
		dim, ep.Namespace, reset,
		bold, url, statusTag, reset,
	)

	// ── Ports ────────────────────────────────────────────────────────────────
	fmt.Printf("  %s│%s  ports: %s\n", dim, reset, portStr)

	// ── Services ciblés ──────────────────────────────────────────────────────
	if len(ep.Services) > 0 {
		for si, sref := range ep.Services {
			prefix := "├─"
			if si == len(ep.Services)-1 && len(ep.Pods) == 0 {
				prefix = "└─"
			}
			fmt.Printf("  %s│%s  %s Service: %s/%s:%d%s\n",
				dim, reset, dim, sref.Namespace, sref.Name, sref.Port, reset)
			_ = prefix
		}
	}

	// ── Pods ─────────────────────────────────────────────────────────────────
	if len(ep.Pods) > 0 {
		fmt.Printf("  %s│%s  Pods (%d):\n", dim, reset, len(ep.Pods))
		for _, pod := range ep.Pods {
			statusColor := green
			if pod.Status != "Running" {
				statusColor = yellow
			}
			fmt.Printf("  %s│%s    %s• %s%s %s(%s)%s\n",
				dim, reset, dim, reset,
				pod.Name,
				statusColor, pod.Status, reset,
			)
		}
	}

	// ── CVE Trivy ─────────────────────────────────────────────────────────────
	if ep.CVECritical > 0 || ep.CVEHigh > 0 {
		cveStr := ""
		if ep.CVECritical > 0 {
			cveStr += fmt.Sprintf("%s%d CRITICAL%s", red, ep.CVECritical, reset)
		}
		if ep.CVEHigh > 0 {
			if cveStr != "" {
				cveStr += "  "
			}
			cveStr += fmt.Sprintf("%s%d HIGH%s", yellow, ep.CVEHigh, reset)
		}
		link := ""
		if ep.TrivyURL != "" {
			link = fmt.Sprintf("  %s→ %s%s", dim, ep.TrivyURL, reset)
		}
		fmt.Printf("  %s│%s  %sCVE:%s %s%s\n", dim, reset, "\033[35m", reset, cveStr, link)
	}

	fmt.Printf("  %s└──────────────────────────────────────────────%s\n\n", dim, reset)
}

func formatPorts(ports []model.ExposedPort) string {
	var parts []string
	for _, p := range ports {
		s := fmt.Sprintf("%d/%s", p.Port, p.Protocol)
		if p.NodePort != 0 {
			s += fmt.Sprintf(" (node:%d)", p.NodePort)
		}
		if name := scorer.SensitivePortName(p.Port); name != "" {
			s += fmt.Sprintf(" %s[!%s]%s", red, name, reset)
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, "  ")
}

func riskStyle(r model.RiskLevel) (color, icon string) {
	switch r {
	case model.RiskHigh:
		return red, "✖"
	case model.RiskMedium:
		return yellow, "⚠"
	default:
		return green, "✔"
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

func endpointKey(ep model.ExposedEndpoint) string {
	if ep.Hostname != "" {
		return ep.Hostname
	}
	return ep.ExternalIP
}

func printBanner() {
	fmt.Printf("%s%s", bold, cyan)
	fmt.Println("╔══════════════════════════════════════════════════════╗")
	fmt.Println("║          BEACON — KubeSurfaceScanner v0.1            ║")
	fmt.Println("╚══════════════════════════════════════════════════════╝")
	fmt.Printf("%s", reset)
}
