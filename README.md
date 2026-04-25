# PodWatcher (POC)

Kubernetes security scanner that evaluates containers against user-defined rules and sends violations to Prometheus AlertManager.

Scans all containers (standard, init, and ephemeral) in every pod, evaluates [SpEL](https://docs.spring.io/spring-framework/reference/core/expressions.html) expressions against their security properties, and fires alerts for violations.

## Rules

Rules are YAML files with a SpEL boolean expression. Every container in scope is evaluated against the expression.

```yaml
name: privileged container
enabled: true
severity: critical
filter:
  namespace:
    include:
      - production
rule: >
  container.securityContext.privileged == true
  || container.securityContext.allowPrivilegeEscalation == true
alert: insecure-workload
```

| Field | Required | Description |
|-------|----------|-------------|
| `name` | yes | Rule identifier, used in metrics and alert labels |
| `enabled` | yes | Set `false` to skip this rule |
| `rule` | yes | SpEL expression that returns `true` for violations |
| `alert` | yes | Name of the alert template to use |
| `severity` | no | Severity label added to alerts (e.g. `critical`, `high`, `medium`, `low`, `info`) |
| `filter.namespace.include` | no | Only evaluate pods in these namespaces |
| `filter.namespace.exclude` | no | Skip pods in these namespaces |

### Available fields in expressions

Expressions have access to the following context:

**Container** (`container.*`):

| Field | Type | Description |
|-------|------|-------------|
| `container.name` | String | Container name |
| `container.containerType` | String | `"standard"`, `"init"`, or `"ephemeral"` |
| `container.image.registry` | String | Image registry (e.g. `docker.io`) |
| `container.image.name` | String | Image name (e.g. `nginx`) |
| `container.image.tag` | String | Image tag (e.g. `latest`) |
| `container.image.sha256` | String | Image digest |
| `container.command` | List\<String\> | Container command |
| `container.args` | List\<String\> | Container arguments |
| `container.ports` | List\<Integer\> | Container ports |
| `container.securityContext.privileged` | Boolean | |
| `container.securityContext.allowPrivilegeEscalation` | Boolean | |
| `container.securityContext.readOnlyRootFilesystem` | Boolean | |
| `container.securityContext.runAsUser` | Long | |
| `container.securityContext.runAsGroup` | Long | |
| `container.securityContext.runAsNonRoot` | Boolean | |
| `container.securityContext.procMount` | String | |
| `container.securityContext.seccompProfileType` | String | e.g. `RuntimeDefault`, `Unconfined` |
| `container.securityContext.capabilities.add` | List\<String\> | Added capabilities |
| `container.securityContext.capabilities.drop` | List\<String\> | Dropped capabilities |

**Pod spec** (`spec.*`):

| Field | Type |
|-------|------|
| `spec.hostPID` | Boolean |
| `spec.hostNetwork` | Boolean |
| `spec.hostIPC` | Boolean |
| `spec.serviceAccountName` | String |
| `spec.automountServiceAccountToken` | Boolean |

**Pod security context** (`securityContext.*`):

| Field | Type |
|-------|------|
| `securityContext.runAsUser` | Long |
| `securityContext.runAsGroup` | Long |
| `securityContext.runAsNonRoot` | Boolean |
| `securityContext.fsGroup` | Long |
| `securityContext.supplementalGroups` | List\<Long\> |
| `securityContext.seccompProfileType` | String |

**Pod metadata** (`metadata.*`):

| Field | Type |
|-------|------|
| `metadata.name` | String |
| `metadata.namespace` | String |
| `metadata.labels` | Map\<String, String\> |
| `metadata.annotations` | Map\<String, String\> |

All List fields default to empty (never null), so `.contains()` and `.size()` are always safe to call.

### Expression examples

```yaml
# Simple field checks
rule: container.securityContext.privileged == true
rule: spec.hostNetwork == true || spec.hostPID == true || spec.hostIPC == true
rule: container.securityContext.runAsUser == 0

# String methods
rule: container.image.registry.startsWith('internal.')
rule: container.image.name.contains('debug')
rule: container.image.tag.matches('v[0-9]+\.[0-9]+\.[0-9]+')
rule: container.name.endsWith('-sidecar')
rule: spec.serviceAccountName.equalsIgnoreCase('admin')

# Safe navigation for nullable fields
rule: container.image.tag?.toLowerCase() == 'latest'

# Elvis operator for null defaults
rule: (container.securityContext.runAsUser ?: -1) == 0

# Capabilities
rule: "!container.securityContext.capabilities.drop.contains('ALL')"
rule: container.securityContext.capabilities.add.contains('SYS_ADMIN')
rule: container.securityContext.capabilities.add.size() > 0

# Inline allowlists/denylists
rule: "!{'registry.k8s.io', 'docker.io', 'ghcr.io'}.contains(container.image.registry)"

# Labels and annotations
rule: metadata.labels.containsKey('app.kubernetes.io/managed-by')
rule: metadata.annotations.containsKey('iam.amazonaws.com/role')

# Container type targeting
rule: container.containerType == 'init' && container.securityContext.privileged == true

# Complex compound rules
rule: >
  container.securityContext.privileged == true
  || container.securityContext.allowPrivilegeEscalation == true
  || (container.securityContext.capabilities.add.size() > 0
      && !container.securityContext.capabilities.drop.contains('ALL'))
  || spec.hostNetwork == true
  || container.securityContext.runAsUser == 0
```

### Alert templates

Alert templates define how violations are sent to AlertManager:

```yaml
name: insecure-workload
enabled: true
env: prod
group: security
labels:
  - rule
  - namespace
  - pod
  - image
```

Available label values: `rule`, `namespace`, `pod`, `image`, `severity`.

## Run in Kubernetes

```sh
kubectl create serviceaccount sa-pod-watcher
kubectl create clusterrole cr --verb=get,list --resource=pods
kubectl create clusterrolebinding crb --clusterrole=cr --serviceaccount=default:sa-pod-watcher
kubectl run podwatcher-poc \
  --image=ghcr.io/vilaca/podwatcher-poc:main \
  --image-pull-policy=Always \
  --env="AM_USER=admin" \
  --env="AM_PASSWORD=" \
  --env="AM_URL=http://alertmanager:9093/api/v1/alerts" \
  --env="ALERT_TEMPLATES_FOLDER=examples/alerts" \
  --env="RULES_FOLDER=examples/rules" \
  --overrides='{ "spec": { "serviceAccount": "sa-pod-watcher" }  }'
```

## Scan modes

PodWatcher supports two scan modes controlled by the `SCAN_MODE` environment variable:

| Mode | `SCAN_MODE` | Description |
|------|-------------|-------------|
| Kubernetes (default) | unset or `kubernetes` | Scans pods via the Kubernetes API |
| Docker | `docker` | Scans containers on the local Docker daemon |

The same rules and SpEL expressions work for both modes. Docker container properties are mapped to the same Context fields:

| Docker property | Context field |
|---|---|
| `HostConfig.Privileged` | `container.securityContext.privileged` |
| `HostConfig.CapAdd/CapDrop` | `container.securityContext.capabilities.add/drop` |
| `HostConfig.ReadonlyRootfs` | `container.securityContext.readOnlyRootFilesystem` |
| `HostConfig.PidMode` ("host") | `spec.hostPID` |
| `HostConfig.NetworkMode` ("host") | `spec.hostNetwork` |
| `HostConfig.IpcMode` ("host") | `spec.hostIPC` |
| `Config.User` | `container.securityContext.runAsUser/runAsGroup` |
| `Config.Entrypoint` + `Config.Cmd` | `container.command` |
| `Config.ExposedPorts` | `container.ports` |
| `Config.Labels` | `metadata.labels` |
| `HostConfig.SecurityOpts` | `seccompProfileType`, `allowPrivilegeEscalation` |

In Docker mode, `metadata.namespace` is always `"docker"` and `container.containerType` is always `"standard"`.

## Run in Docker (scanning K8s)

```sh
docker run -v (path-to-kubeconfig):/kubeconfig.yaml \
    -e RULES_FOLDER=examples/rules \
    -e ALERT_TEMPLATES_FOLDER=examples/alerts \
    -e KUBECONFIG=/kubeconfig.yaml \
    -e AM_USER=user \
    -e AM_PASSWORD= \
    -e AM_URL=http://alertmanager:9093/api/v1/alerts \
    -p 8080:8080 \
    ghcr.io/vilaca/podwatcher-poc:latest
```

## Run in Docker (scanning Docker)

```sh
docker run -v /var/run/docker.sock:/var/run/docker.sock \
    -e SCAN_MODE=docker \
    -e RULES_FOLDER=examples/rules \
    -e ALERT_TEMPLATES_FOLDER=examples/alerts \
    -e AM_USER=user \
    -e AM_PASSWORD= \
    -e AM_URL=http://alertmanager:9093/api/v1/alerts \
    -p 8080:8080 \
    ghcr.io/vilaca/podwatcher-poc:latest
```

## Build & Run

```sh
docker build . -t pod-watcher-local
docker run -v (path-to-kubeconfig):/kubeconfig.yaml \
    -e RULES_FOLDER=examples/rules \
    -e ALERT_TEMPLATES_FOLDER=examples/alerts \
    -e KUBECONFIG=/kubeconfig.yaml \
    -e AM_USER=user \
    -e AM_PASSWORD= \
    -e AM_URL=http://alertmanager:9093/api/v1/alerts \
    -p 8080:8080 \
    pod-watcher-local
```

## Environment variables

| Variable | Description | Default |
|----------|-------------|---------|
| `RULES_FOLDER` | Path to rules folder | required |
| `ALERT_TEMPLATES_FOLDER` | Path to alert templates folder | required |
| `AM_URL` | AlertManager API URL | required |
| `AM_USER` | AlertManager basic auth user | required |
| `AM_PASSWORD` | AlertManager basic auth password | required |
| `AM_DEFAULT_DURATION` | Alert duration in ms | `300000` |
| `SCAN_MODE` | Scan mode: `kubernetes` or `docker` | `kubernetes` |
| `KUBECONFIG` | Path to kubeconfig file (K8s mode) | in-cluster auth |
| `HEALTH_PORT` | Health/metrics server port | `8080` |
| `LOG_LEVEL` | Log level (DEBUG, INFO, WARN, ERROR) | `INFO` |

## Observability

### Health endpoint

```
GET /healthz    → 200 "ok"
```

Kubernetes probe configuration:

```yaml
livenessProbe:
  httpGet:
    path: /healthz
    port: 8080
  initialDelaySeconds: 5
  periodSeconds: 10
readinessProbe:
  httpGet:
    path: /healthz
    port: 8080
  initialDelaySeconds: 3
  periodSeconds: 5
```

### Prometheus metrics

```
GET /metrics    → Prometheus text format
```

| Metric | Type | Labels | Description |
|--------|------|--------|-------------|
| `podwatcher_violations_total` | Counter | `rule` | Rule violations detected |
| `podwatcher_alerts_sent_total` | Counter | | Alerts sent to AlertManager |
| `podwatcher_alerts_failed_total` | Counter | | Alerts failed after retries |
| `podwatcher_rules_evaluated_total` | Counter | `rule` | Rule evaluations performed |
| `podwatcher_rules_errors_total` | Counter | `rule` | Rule evaluation errors |
| `podwatcher_pods_scanned_total` | Counter | | Pods scanned |
| `podwatcher_scan_duration_seconds` | Summary | | Scan cycle duration |
| `podwatcher_last_scan_timestamp_seconds` | Gauge | | Last scan timestamp |
| `podwatcher_rules_loaded` | Gauge | | Rules loaded |

### Structured logging

JSON logs to stdout (Logstash-compatible):

```json
{"@timestamp":"2024-01-15T10:30:00.000Z","level":"INFO","message":"Loaded 4 rules.","logger_name":"eu.vilaca.security.PodWatcherApp","application":"podwatcher"}
```

Compatible with ELK, Grafana Loki, Datadog, and any JSON log aggregator.
