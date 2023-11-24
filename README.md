# PodWatcher (POC)

Receive alerts whenever containers running in your cluster break user defined rules.

See examples/rules for rule examples.

### Run

Run the latest version from the GitHub repository:

    docker run -v (path-to-kubeconfig):/kubeconfig.yaml \
        -e RULES_FOLDER=examples/rules \
        -e ALERT_TEMPLATES_FOLDER=examples/alerts \
        -e KUBECONFIG=/kubeconfig.yaml \
        -e AM_USER=user \
        -e AM_PASSWORD=pass \
        -e AM_URL=http://alertmanager:9093/api/v1/alerts \
        ghcr.io/vilaca/podwatcher-poc:latest

## Build & Run

    docker build . -t pod-watcher-local
    docker run -v (path-to-kubeconfig):/kubeconfig.yaml \
        -e RULES_FOLDER=examples/rules \
        -e ALERT_TEMPLATES_FOLDER=examples/alerts \
        -e KUBECONFIG=/kubeconfig.yaml \
        -e AM_USER=user \
        -e AM_PASSWORD=pass \
        -e AM_URL=http://alertmanager:9093/api/v1/alerts \
        pod-watcher-local

## Environment variables

| Environment Variable   |                              |
| ---------------------- | ---------------------------- |
| RULES_FOLDER           | Path to rules folder.        | 
| ALERT_TEMPLATES_FOLDER | Path alert templates folder. |
| AM_URL                 | Alert Manager URL.           |
| AM_USER                | Alert Manager user.          |
| AM_PASSWORD            | Alert Manager password.      |
| AM_DEFAULT_DURATION    | Default alert duration.      |
| KUBECONFIG             | Path to kube config file.    |
