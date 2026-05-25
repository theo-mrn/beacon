# Beacon — Kubernetes Attack Surface Scanner

Beacon est un outil de sécurité cloud-native conçu pour les clusters Kubernetes qui surveille en continu l'ensemble des surfaces d'attaque exposées — Services LoadBalancer, IngressRoutes Traefik, et ressources custom — les score automatiquement selon leur niveau de risque, et les corrèle avec les alertes temps réel de Wazuh pour identifier quels nœuds sous attaque hébergent des services exposés.

## Fonctionnalités

- **Détection automatique** des endpoints exposés : Services `LoadBalancer`, `NodePort`, `Ingress`, `IngressRoute` Traefik
- **Scoring de risque** configurable sans recompilation (`HIGH` / `MEDIUM` / `LOW`) basé sur :
  - Ports sensibles exposés (SSH, MySQL, Redis, Elasticsearch, etcd…)
  - Absence de TLS sur les Ingress/IngressRoute
  - CVE critiques/hautes remontées par Trivy Operator
- **Corrélation Wazuh** : croise les IPs des nœuds K8s attaqués avec les services exposés sur ces mêmes nœuds
- **Dashboard temps réel** via Server-Sent Events (SSE), sans rechargement de page
- **Système de review manuel** : marquer un endpoint comme `Accepté`, `Faux positif` ou `À corriger`, avec commentaire (inspiré SonarQube)
- **Tracking temporel** : détection des endpoints `NEW` et `MODIFIED` entre les scans
- **Portail des services** : vue navigable des URLs exposées avec filtrage par risque
- **Alertes webhook** : notifications Slack / Teams / Discord / Generic sur nouveaux endpoints HIGH et digest quotidien
- **Ban automatique** : intégration Wazuh active-response pour bannir définitivement les IPs brute-forçant SSH

## Stack technique

| Composant | Technologie |
|-----------|-------------|
| Backend | Go 1.24 |
| Persistance | SQLite (`modernc.org/sqlite` — pure Go, sans CGO) |
| API Kubernetes | `client-go` — watch dynamique de ressources |
| Sécurité | Wazuh Indexer (OpenSearch / Elasticsearch) |
| Reverse proxy | Traefik IngressRoute |
| Authentification | Authelia (SSO forward-auth) |
| Frontend | HTML / CSS / JavaScript vanilla (SSE) |
| Container | Docker multi-arch `linux/amd64` + `linux/arm64` (image `scratch`) |
| Packaging | Helm chart |
| GitOps | ArgoCD (sync automatique) |
| CI | GitHub Actions → GHCR |

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│  Kubernetes Cluster                                         │
│                                                             │
│  ┌──────────┐    watch     ┌─────────────┐                 │
│  │ K8s API  │ ──────────► │   Watcher   │                  │
│  └──────────┘              └──────┬──────┘                 │
│                                   │ snapshot                │
│  ┌──────────┐    poll      ┌──────▼──────┐                 │
│  │  Wazuh   │ ──────────► │   Scorer    │                  │
│  │ Indexer  │              └──────┬──────┘                 │
│  └──────────┘                     │                        │
│                            ┌──────▼──────┐                 │
│  ┌──────────┐              │   Server    │ ──► SSE ──► UI  │
│  │  SQLite  │ ◄──────────► │  (HTTP)     │                 │
│  └──────────┘              └─────────────┘                 │
└─────────────────────────────────────────────────────────────┘
```

## Déploiement

### Prérequis

- Cluster Kubernetes avec Traefik comme ingress controller
- Authelia déployé dans le namespace `authelia`
- (Optionnel) Wazuh Indexer accessible depuis le cluster
- (Optionnel) Trivy Operator pour la corrélation CVE

### Via ArgoCD (recommandé)

Créer l'Application ArgoCD :

```yaml
apiVersion: argoproj.io/v1alpha1
kind: Application
metadata:
  name: beacon
  namespace: argocd
spec:
  project: default
  source:
    repoURL: https://github.com/theo-mrn/beacon
    targetRevision: main
    path: charts/beacon
    helm:
      values: |
        ingress:
          enabled: true
          host: beacon.cluster.example.com
          tls: true
        wazuh:
          indexerURL: "https://indexer.wazuh.svc.cluster.local:9200"
          user: "admin"
          password: "your-password"
  destination:
    server: https://kubernetes.default.svc
    namespace: beacon
  syncPolicy:
    automated:
      prune: true
      selfHeal: true
    syncOptions:
      - CreateNamespace=true
```

### Via Helm

```bash
helm install beacon ./charts/beacon \
  --namespace beacon \
  --create-namespace \
  --set ingress.enabled=true \
  --set ingress.host=beacon.cluster.example.com \
  --set ingress.tls=true \
  --set wazuh.indexerURL=https://indexer.wazuh.svc.cluster.local:9200 \
  --set wazuh.user=admin \
  --set wazuh.password=your-password
```

## Configuration

### Variables d'environnement

| Variable | Défaut | Description |
|----------|--------|-------------|
| `BEACON_DB` | `/var/lib/beacon/beacon.db` | Chemin vers la base SQLite |
| `TRIVY_DASHBOARD_URL` | — | URL du dashboard Trivy (optionnel) |
| `WAZUH_INDEXER_URL` | `https://indexer.wazuh.svc.cluster.local:9200` | URL de l'indexer Wazuh |
| `WAZUH_INDEXER_USER` | `admin` | Utilisateur Elasticsearch |
| `WAZUH_INDEXER_PASSWORD` | — | Mot de passe Elasticsearch |

### Webhooks

Configurer dans `charts/beacon/files/scoring.yaml` ou via les values Helm :

```yaml
webhooks:
  slack: "https://hooks.slack.com/services/xxx"
  teams: "https://xxx.webhook.office.com/xxx"
  discord: "https://discord.com/api/webhooks/xxx"
  generic: "https://your-endpoint.com/hook"
```

### Scoring

Le fichier `scoring.yaml` est configurable sans recompilation. Il définit :

- **Ports sensibles** : liste des ports considérés à risque (SSH, bases de données, etc.)
- **Exposition par défaut** : niveau de risque selon le type de ressource K8s
- **Seuils CVE** : nombre de CVE critiques/hautes pour déclencher un niveau `HIGH`
- **Pénalité TLS** : monte d'un niveau si pas de TLS sur Ingress/IngressRoute

```yaml
ports:
  - port: 22
    name: SSH
    risk: HIGH
  - port: 6379
    name: Redis
    risk: HIGH

exposure_defaults:
  LoadBalancer: MEDIUM
  IngressRoute: LOW

cve_scoring:
  critical_count_high: 1
  high_count_high: 10

no_tls_penalty: true
```

## Niveaux de risque

| Niveau | Icône | Déclencheurs |
|--------|-------|--------------|
| `HIGH` | ✖ | Port sensible exposé, CVE critique, pas de TLS |
| `MEDIUM` | ⚠ | LoadBalancer sans port sensible, CVE hautes |
| `LOW` | ✔ | IngressRoute avec TLS, pas de port sensible |

## Intégration Wazuh

Beacon se connecte à l'indexer Wazuh (compatible OpenSearch/Elasticsearch) toutes les 5 minutes pour récupérer les 500 dernières alertes sur 24h. Il corrèle les IPs des agents Wazuh (= IPs des nœuds K8s) avec les IPs externes des endpoints exposés pour identifier les nœuds simultanément sous attaque et hébergeant des services exposés.

### Active Response

Beacon peut déclencher le bannissement automatique et permanent des IPs attaquantes via la configuration Wazuh active-response (`firewall-drop`, `timeout=0`), activée sur les règles SSH brute-force (5712, 5720) et web attacks (31151, 31152).

## Permissions RBAC

Beacon requiert un accès en lecture sur les ressources suivantes :

- `services`, `endpoints` — tous namespaces
- `ingresses` — tous namespaces
- `ingressroutes.traefik.io` — tous namespaces
- `vulnerabilityreports.aquasecurity.github.io` — tous namespaces (si Trivy Operator installé)
