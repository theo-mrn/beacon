package watcher

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/theo-mrn/beacon/internal/model"
	"github.com/theo-mrn/beacon/internal/notify"
	"github.com/theo-mrn/beacon/internal/scorer"
	"github.com/theo-mrn/beacon/internal/store"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

var hostRe = regexp.MustCompile("Host\\(`([^`]+)`\\)")

var ingressRouteGVR = schema.GroupVersionResource{
	Group:    "traefik.io",
	Version:  "v1alpha1",
	Resource: "ingressroutes",
}

var vulnerabilityReportGVR = schema.GroupVersionResource{
	Group:    "aquasecurity.github.io",
	Version:  "v1alpha1",
	Resource: "vulnerabilityreports",
}

// CVESummary résume les vulnérabilités critiques/hautes d'un Pod.
type CVESummary struct {
	Critical int
	High     int
}

type KubeWatcher struct {
	client    kubernetes.Interface
	dynClient dynamic.Interface
	notifier  *notify.Notifier
	store     *store.Store
	trivyURL  string // URL du dashboard Trivy (optionnel)

	mu        sync.RWMutex
	services  map[string]*svcEntry
	ingresses map[string]*ingEntry
	routes    map[string]*routeEntry
	pods      map[string][]model.PodInfo
	cves      map[string]CVESummary // key: ns/podName
	seen      map[string]bool
	trivyAvailable bool

	Updates chan struct{}
}

type svcEntry struct {
	exposed *model.ExposedEndpoint
}

type ingEntry struct {
	exposed *model.ExposedEndpoint
}

type routeEntry struct {
	exposed *model.ExposedEndpoint
}

func New(client kubernetes.Interface, dynClient dynamic.Interface, notifier *notify.Notifier, st *store.Store, trivyURL string) *KubeWatcher {
	return &KubeWatcher{
		client:    client,
		dynClient: dynClient,
		notifier:  notifier,
		store:     st,
		trivyURL:  trivyURL,
		services:  make(map[string]*svcEntry),
		ingresses: make(map[string]*ingEntry),
		routes:    make(map[string]*routeEntry),
		pods:      make(map[string][]model.PodInfo),
		cves:      make(map[string]CVESummary),
		seen:      make(map[string]bool),
		Updates:   make(chan struct{}, 1),
	}
}

// track persiste l'endpoint dans SQLite et enrichit son Status / FirstSeen.
func (w *KubeWatcher) track(key string, ep *model.ExposedEndpoint) {
	if w.store == nil {
		return
	}
	var ports []int32
	for _, p := range ep.Ports {
		ports = append(ports, p.Port)
	}
	fp := store.Fingerprint(string(ep.SourceKind), ep.ExternalIP, ep.Hostname, ports)
	status, rec, err := w.store.Observe(key, fp)
	if err != nil {
		fmt.Printf("[store] observe error: %v\n", err)
		return
	}
	ep.FirstSeen = rec.FirstSeen
	ep.Status = string(status)
}

// maybeNotify envoie une alerte webhook si l'endpoint est HIGH et nouveau.
func (w *KubeWatcher) maybeNotify(key string, ep *model.ExposedEndpoint) {
	if w.notifier == nil || !w.notifier.Enabled() {
		return
	}
	ep.Risk = scorer.Score(ep)
	if ep.Risk == model.RiskHigh && !w.seen[key] {
		w.seen[key] = true
		w.notifier.NotifyHigh(*ep)
	}
}

func (w *KubeWatcher) Start(ctx context.Context) {
	go w.watchServices(ctx)
	go w.watchIngresses(ctx)
	go w.watchIngressRoutes(ctx)
	go w.watchPods(ctx)
	go w.startTrivyIfAvailable(ctx)
}

func (w *KubeWatcher) startTrivyIfAvailable(ctx context.Context) {
	// Vérifie si la CRD VulnerabilityReport existe dans le cluster
	_, err := w.dynClient.Resource(vulnerabilityReportGVR).Namespace("").List(ctx, metav1.ListOptions{Limit: 1})
	if err != nil {
		fmt.Println("[trivy] VulnerabilityReport CRD non disponible — corrélation désactivée")
		return
	}
	fmt.Println("[trivy] VulnerabilityReport détecté — corrélation activée")
	w.mu.Lock()
	w.trivyAvailable = true
	w.mu.Unlock()
	w.watchVulnerabilityReports(ctx)
}

func (w *KubeWatcher) TrivyAvailable() bool {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.trivyAvailable
}

func (w *KubeWatcher) notify() {
	select {
	case w.Updates <- struct{}{}:
	default:
	}
}

// Snapshot construit la liste des endpoints exposés avec leur chaîne complète.
// enrichCVE ajoute les compteurs CVE Trivy à un endpoint en croisant avec ses Pods.
func (w *KubeWatcher) enrichCVE(ep *model.ExposedEndpoint) {
	if !w.trivyAvailable {
		return
	}
	for _, pod := range ep.Pods {
		key := ep.Namespace + "/" + pod.Name
		if cve, ok := w.cves[key]; ok {
			ep.CVECritical += cve.Critical
			ep.CVEHigh += cve.High
		}
	}
	if (ep.CVECritical > 0 || ep.CVEHigh > 0) && w.trivyURL != "" {
		ep.TrivyURL = w.trivyURL
	}
}

func (w *KubeWatcher) Snapshot() []model.ExposedEndpoint {
	w.mu.RLock()
	defer w.mu.RUnlock()

	var out []model.ExposedEndpoint

	for _, e := range w.services {
		ep := *e.exposed
		ep.Pods = w.resolvePodsForService(ep.Namespace, ep.ObjectName)
		w.enrichCVE(&ep)
		out = append(out, ep)
	}
	for _, e := range w.ingresses {
		ep := *e.exposed
		ep.Pods = w.resolvePodsForServices(ep.Services)
		w.enrichCVE(&ep)
		out = append(out, ep)
	}
	for _, e := range w.routes {
		ep := *e.exposed
		ep.Pods = w.resolvePodsForServices(ep.Services)
		w.enrichCVE(&ep)
		out = append(out, ep)
	}

	return out
}

func (w *KubeWatcher) resolvePodsForService(ns, svcName string) []model.PodInfo {
	key := ns + "/" + svcName
	if pods, ok := w.pods[key]; ok {
		return pods
	}
	return nil
}

func (w *KubeWatcher) resolvePodsForServices(refs []model.ServiceRef) []model.PodInfo {
	seen := map[string]bool{}
	var out []model.PodInfo
	for _, ref := range refs {
		for _, p := range w.resolvePodsForService(ref.Namespace, ref.Name) {
			if !seen[p.Name] {
				seen[p.Name] = true
				out = append(out, p)
			}
		}
	}
	return out
}

// ── Services ────────────────────────────────────────────────────────────────

func (w *KubeWatcher) watchServices(ctx context.Context) {
	for {
		if err := w.runServiceWatch(ctx); err != nil && ctx.Err() == nil {
			fmt.Printf("[watcher] service: %v — retry 5s\n", err)
			time.Sleep(5 * time.Second)
		} else {
			return
		}
	}
}

func (w *KubeWatcher) runServiceWatch(ctx context.Context) error {
	wc, err := w.client.CoreV1().Services("").Watch(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	defer wc.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case ev, ok := <-wc.ResultChan():
			if !ok {
				return fmt.Errorf("channel closed")
			}
			svc, ok := ev.Object.(*corev1.Service)
			if !ok {
				continue
			}
			w.mu.Lock()
			w.handleService(ev.Type, svc)
			w.mu.Unlock()
			w.notify()
		}
	}
}

func (w *KubeWatcher) handleService(t watch.EventType, svc *corev1.Service) {
	key := svc.Namespace + "/" + svc.Name

	if t == watch.Deleted {
		delete(w.services, key)
		return
	}

	typ := svc.Spec.Type
	if typ != corev1.ServiceTypeNodePort && typ != corev1.ServiceTypeLoadBalancer {
		return
	}

	expType := model.ExposureNodePort
	if typ == corev1.ServiceTypeLoadBalancer {
		expType = model.ExposureLoadBalancer
	}

	var ports []model.ExposedPort
	for _, p := range svc.Spec.Ports {
		ports = append(ports, model.ExposedPort{
			Port:     p.Port,
			Protocol: string(p.Protocol),
			NodePort: p.NodePort,
		})
	}

	var externalIP string
	if len(svc.Status.LoadBalancer.Ingress) > 0 {
		externalIP = svc.Status.LoadBalancer.Ingress[0].IP
		if externalIP == "" {
			externalIP = svc.Status.LoadBalancer.Ingress[0].Hostname
		}
	}

	entry := &model.ExposedEndpoint{
		Namespace:  svc.Namespace,
		ObjectName: svc.Name,
		SourceKind: expType,
		ExternalIP: externalIP,
		Ports:      ports,
		DetectedAt: time.Now(),
	}
	w.track(key, entry)
	w.services[key] = &svcEntry{exposed: entry}
	w.maybeNotify(key, entry)
}

// ── Ingress natif ───────────────────────────────────────────────────────────

func (w *KubeWatcher) watchIngresses(ctx context.Context) {
	for {
		if err := w.runIngressWatch(ctx); err != nil && ctx.Err() == nil {
			fmt.Printf("[watcher] ingress: %v — retry 5s\n", err)
			time.Sleep(5 * time.Second)
		} else {
			return
		}
	}
}

func (w *KubeWatcher) runIngressWatch(ctx context.Context) error {
	wc, err := w.client.NetworkingV1().Ingresses("").Watch(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	defer wc.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case ev, ok := <-wc.ResultChan():
			if !ok {
				return fmt.Errorf("channel closed")
			}
			ing, ok := ev.Object.(*networkingv1.Ingress)
			if !ok {
				continue
			}
			w.mu.Lock()
			w.handleIngress(ev.Type, ing)
			w.mu.Unlock()
			w.notify()
		}
	}
}

func (w *KubeWatcher) handleIngress(t watch.EventType, ing *networkingv1.Ingress) {
	key := "ingress/" + ing.Namespace + "/" + ing.Name

	if t == watch.Deleted {
		delete(w.ingresses, key)
		return
	}

	tls := len(ing.Spec.TLS) > 0
	port := int32(80)
	if tls {
		port = 443
	}

	var svcs []model.ServiceRef
	for _, rule := range ing.Spec.Rules {
		if rule.HTTP == nil {
			continue
		}
		for _, path := range rule.HTTP.Paths {
			if path.Backend.Service != nil {
				svcs = append(svcs, model.ServiceRef{
					Namespace: ing.Namespace,
					Name:      path.Backend.Service.Name,
					Port:      int32(path.Backend.Service.Port.Number),
				})
			}
		}
	}

	for _, rule := range ing.Spec.Rules {
		epKey := key + "/" + rule.Host
		entry := &model.ExposedEndpoint{
			Namespace:  ing.Namespace,
			ObjectName: ing.Name,
			SourceKind: model.ExposureIngress,
			Hostname:   rule.Host,
			TLS:        tls,
			Ports:      []model.ExposedPort{{Port: port, Protocol: "TCP"}},
			Services:   svcs,
			DetectedAt: time.Now(),
		}
		w.track(epKey, entry)
		w.ingresses[epKey] = &ingEntry{exposed: entry}
		w.maybeNotify(epKey, entry)
	}
}

// ── IngressRoute Traefik ────────────────────────────────────────────────────

func (w *KubeWatcher) watchIngressRoutes(ctx context.Context) {
	for {
		if err := w.runIngressRouteWatch(ctx); err != nil && ctx.Err() == nil {
			fmt.Printf("[watcher] ingressroute: %v — retry 5s\n", err)
			time.Sleep(5 * time.Second)
		} else {
			return
		}
	}
}

func (w *KubeWatcher) runIngressRouteWatch(ctx context.Context) error {
	wc, err := w.dynClient.Resource(ingressRouteGVR).Namespace("").Watch(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	defer wc.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case ev, ok := <-wc.ResultChan():
			if !ok {
				return fmt.Errorf("channel closed")
			}
			obj, ok := ev.Object.(*unstructured.Unstructured)
			if !ok {
				continue
			}
			w.mu.Lock()
			w.handleIngressRoute(ev.Type, obj)
			w.mu.Unlock()
			w.notify()
		}
	}
}

func (w *KubeWatcher) handleIngressRoute(t watch.EventType, obj *unstructured.Unstructured) {
	ns := obj.GetNamespace()
	name := obj.GetName()
	baseKey := "route/" + ns + "/" + name

	if t == watch.Deleted {
		// Supprimer toutes les entrées liées à cet IngressRoute
		for k := range w.routes {
			if strings.HasPrefix(k, baseKey) {
				delete(w.routes, k)
			}
		}
		return
	}

	spec, _, _ := unstructured.NestedMap(obj.Object, "spec")
	_, hasTLS := spec["tls"]
	entryPoints, _, _ := unstructured.NestedStringSlice(obj.Object, "spec", "entryPoints")
	tls := hasTLS || containsAny(entryPoints, "websecure", "https")

	port := int32(80)
	if tls {
		port = 443
	}

	routes, _, _ := unstructured.NestedSlice(obj.Object, "spec", "routes")
	for i, r := range routes {
		route, ok := r.(map[string]interface{})
		if !ok {
			continue
		}

		matchRule, _ := route["match"].(string)
		hostname := extractHost(matchRule)

		var svcs []model.ServiceRef
		rawSvcs, _, _ := unstructured.NestedSlice(route, "services")
		for _, s := range rawSvcs {
			sm, ok := s.(map[string]interface{})
			if !ok {
				continue
			}
			svcName, _ := sm["name"].(string)
			svcPort, _ := sm["port"].(int64)
			if svcName != "" {
				svcs = append(svcs, model.ServiceRef{
					Namespace: ns,
					Name:      svcName,
					Port:      int32(svcPort),
				})
			}
		}

		epKey := fmt.Sprintf("%s/r%d", baseKey, i)
		entry := &model.ExposedEndpoint{
			Namespace:  ns,
			ObjectName: name,
			SourceKind: model.ExposureIngressRoute,
			Hostname:   hostname,
			TLS:        tls,
			Ports:      []model.ExposedPort{{Port: port, Protocol: "TCP"}},
			Services:   svcs,
			DetectedAt: time.Now(),
		}
		w.track(epKey, entry)
		w.routes[epKey] = &routeEntry{exposed: entry}
		w.maybeNotify(epKey, entry)
	}
}

// ── Pods ────────────────────────────────────────────────────────────────────

func (w *KubeWatcher) watchPods(ctx context.Context) {
	for {
		if err := w.runPodWatch(ctx); err != nil && ctx.Err() == nil {
			fmt.Printf("[watcher] pods: %v — retry 5s\n", err)
			time.Sleep(5 * time.Second)
		} else {
			return
		}
	}
}

func (w *KubeWatcher) runPodWatch(ctx context.Context) error {
	wc, err := w.client.CoreV1().Pods("").Watch(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	defer wc.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case ev, ok := <-wc.ResultChan():
			if !ok {
				return fmt.Errorf("channel closed")
			}
			pod, ok := ev.Object.(*corev1.Pod)
			if !ok {
				continue
			}
			w.mu.Lock()
			w.handlePod(ev.Type, pod)
			w.mu.Unlock()
			// pas de notify ici pour éviter le flood — les snapshots liront l'état frais
		}
	}
}

func (w *KubeWatcher) handlePod(t watch.EventType, pod *corev1.Pod) {
	// On indexe les pods par ns/svcName en utilisant le label "app" ou "app.kubernetes.io/name"
	svcName := pod.Labels["app"]
	if svcName == "" {
		svcName = pod.Labels["app.kubernetes.io/name"]
	}
	if svcName == "" {
		return
	}

	key := pod.Namespace + "/" + svcName
	if t == watch.Deleted {
		pods := w.pods[key]
		for i, p := range pods {
			if p.Name == pod.Name {
				w.pods[key] = append(pods[:i], pods[i+1:]...)
				break
			}
		}
		return
	}

	status := podStatus(pod)
	info := model.PodInfo{Name: pod.Name, Status: status}

	// Mettre à jour ou ajouter
	pods := w.pods[key]
	for i, p := range pods {
		if p.Name == pod.Name {
			pods[i] = info
			w.pods[key] = pods
			return
		}
	}
	w.pods[key] = append(pods, info)
}

func podStatus(pod *corev1.Pod) string {
	for _, cs := range pod.Status.ContainerStatuses {
		if cs.State.Waiting != nil {
			return cs.State.Waiting.Reason
		}
	}
	return string(pod.Status.Phase)
}

// ── helpers ─────────────────────────────────────────────────────────────────

// ── VulnerabilityReports Trivy ───────────────────────────────────────────────

func (w *KubeWatcher) watchVulnerabilityReports(ctx context.Context) {
	for {
		if err := w.runVulnWatch(ctx); err != nil && ctx.Err() == nil {
			fmt.Printf("[trivy] watch error: %v — retry 10s\n", err)
			time.Sleep(10 * time.Second)
		} else {
			return
		}
	}
}

func (w *KubeWatcher) runVulnWatch(ctx context.Context) error {
	wc, err := w.dynClient.Resource(vulnerabilityReportGVR).Namespace("").Watch(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}
	defer wc.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case ev, ok := <-wc.ResultChan():
			if !ok {
				return fmt.Errorf("channel closed")
			}
			obj, ok := ev.Object.(*unstructured.Unstructured)
			if !ok {
				continue
			}
			w.mu.Lock()
			w.handleVulnReport(ev.Type, obj)
			w.mu.Unlock()
			w.notify()
		}
	}
}

func (w *KubeWatcher) handleVulnReport(t watch.EventType, obj *unstructured.Unstructured) {
	ns := obj.GetNamespace()

	// Le nom du Pod est dans les labels du rapport
	podName := obj.GetLabels()["trivy-operator.resource.name"]
	if podName == "" {
		return
	}
	key := ns + "/" + podName

	if t == watch.Deleted {
		delete(w.cves, key)
		return
	}

	critical, _ := nestedInt(obj.Object, "report", "summary", "criticalCount")
	high, _ := nestedInt(obj.Object, "report", "summary", "highCount")

	w.cves[key] = CVESummary{Critical: critical, High: high}
}

// nestedInt lit un int dans un objet unstructured (qui peut être int64 ou float64).
func nestedInt(obj map[string]interface{}, fields ...string) (int, bool) {
	val, found, err := unstructured.NestedFieldNoCopy(obj, fields...)
	if !found || err != nil {
		return 0, false
	}
	switch v := val.(type) {
	case int64:
		return int(v), true
	case float64:
		return int(v), true
	}
	return 0, false
}

func extractHost(match string) string {
	m := hostRe.FindStringSubmatch(match)
	if len(m) > 1 {
		return m[1]
	}
	return match
}

func containsAny(slice []string, vals ...string) bool {
	for _, s := range slice {
		for _, v := range vals {
			if s == v {
				return true
			}
		}
	}
	return false
}
