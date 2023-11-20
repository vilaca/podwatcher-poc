# PodWatcher (POC)

## Build

    docker build . -t pod-watcher

## Run

    docker run -v (path-to-kubeconfig):/kubeconfig.yaml \
        -e RULES_FOLDER=examples/rules \
        -e ALERT_TEMPLATES_FOLDER=examples/alerts \
        -e KUBECONFIG=/kubeconfig.yaml \
        -e LOG4J_LEVEL=info \
        -e AM_USER=user \
        -e AM_PASSWORD=pass \
        -e AM_URL=http://alertmanager:9093/api/v1/alerts
        pod-watcher

## Environment variables

| Environment Variable   |                                          |
| ---------------------- | ---------------------------------------- |
| RULES_FOLDER           | Path where rules can be found.           | 
| ALERT_TEMPLATES_FOLDER | Path where alert templates can be found. |
| AM_URL                 | Alert Manager URL                        |
| AM_USER                | Alert Manager User                       |
| AM_PASSWORD            | Alert Manager Password                   |
| AM_DEFAULT_DURATION    | Default alert duration                   |
| KUBECONFIG             | Path to kube config file.                |
