# PodWatcher (POC)

Receive alerts whenever containers running in your cluster break user defined rules.

See examples/rules for rule examples.

### Run in Kubernetes

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

### Run in Docker

Run the latest version from the GitHub repository:

    docker run -v (path-to-kubeconfig):/kubeconfig.yaml \
        -e RULES_FOLDER=examples/rules \
        -e ALERT_TEMPLATES_FOLDER=examples/alerts \
        -e KUBECONFIG=/kubeconfig.yaml \
        -e AM_USER=user \
        -e AM_PASSWORD= \
        -e AM_URL=http://alertmanager:9093/api/v1/alerts \
        -p 8080:8080 \
        ghcr.io/vilaca/podwatcher-poc:latest

## Build & Run

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

## Environment variables

| Environment Variable   |                                              |
| ---------------------- | -------------------------------------------- |
| RULES_FOLDER           | Path to rules folder.                        |
| ALERT_TEMPLATES_FOLDER | Path alert templates folder.                 |
| AM_URL                 | Alert Manager URL.                           |
| AM_USER                | Alert Manager user.                          |
| AM_PASSWORD            | Alert Manager password.                      |
| AM_DEFAULT_DURATION    | Default alert duration (ms). Default: 300000 |
| KUBECONFIG             | Path to kube config file.                    |
| HEALTH_PORT            | Health/metrics server port. Default: 8080    |
| LOG_LEVEL              | Log level (DEBUG, INFO, WARN, ERROR). Default: INFO |

## Observability

### Health endpoint

A lightweight HTTP server starts on port 8080 (configurable via `HEALTH_PORT`) exposing:

    GET /healthz    → 200 "ok"

Use this for Kubernetes liveness/readiness probes:

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

    GET /metrics    → Prometheus text format

Available metrics:

| Metric | Type | Labels | Description |
| ------ | ---- | ------ | ----------- |
| `podwatcher_violations_total` | Counter | `rule` | Total rule violations detected |
| `podwatcher_alerts_sent_total` | Counter | | Alerts successfully sent to AlertManager |
| `podwatcher_alerts_failed_total` | Counter | | Alerts that failed after all retries |
| `podwatcher_rules_evaluated_total` | Counter | `rule` | Rule evaluations performed |
| `podwatcher_rules_errors_total` | Counter | `rule` | Rule evaluation errors (SpEL failures) |
| `podwatcher_pods_scanned_total` | Counter | | Pods scanned |
| `podwatcher_scan_duration_seconds` | Summary | | Time spent on a scan cycle |
| `podwatcher_last_scan_timestamp_seconds` | Gauge | | Unix timestamp of last completed scan |
| `podwatcher_rules_loaded` | Gauge | | Number of rules currently loaded |

To scrape with Prometheus, add to your `scrape_configs`:

```yaml
- job_name: 'podwatcher'
  static_configs:
    - targets: ['podwatcher-poc:8080']
```

Or use a `PodMonitor`/`ServiceMonitor` if running the Prometheus Operator.

### Structured logging

Logs are output in JSON format (Logstash-compatible) to stdout. Each log line includes:

- `@timestamp` — ISO 8601 timestamp
- `level` — log level
- `message` — log message
- `logger_name` — source class
- `application` — always `podwatcher`

Set `LOG_LEVEL` environment variable to control verbosity (default: `INFO`).

Example log line:

```json
{"@timestamp":"2024-01-15T10:30:00.000Z","level":"INFO","message":"Loaded 4 rules.","logger_name":"eu.vilaca.security.PodWatcherApp","application":"podwatcher"}
```

Compatible with ELK stack, Grafana Loki, Datadog, and any JSON log aggregator.
