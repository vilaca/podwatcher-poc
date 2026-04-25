package eu.vilaca.security.service;

import eu.vilaca.security.rule.Rule;
import eu.vilaca.security.violation.PodRuleViolation;
import io.kubernetes.client.openapi.ApiClient;
import io.kubernetes.client.openapi.ApiException;
import io.kubernetes.client.openapi.apis.CoreV1Api;
import io.kubernetes.client.openapi.models.V1Pod;
import lombok.extern.log4j.Log4j2;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Log4j2
class EagerPodWatcher implements PodWatcher {
	private final Map<String, List<V1Pod>> cache;

	EagerPodWatcher(ApiClient client) throws ApiException {
		final Map<String, List<V1Pod>> allPods = new HashMap<>();
		new CoreV1Api(client).listPodForAllNamespaces(null,
						null,
						null,
						null,
						null,
						null,
						null,
						null,
						null,
						null)
				.getItems()
				.forEach(pod -> groupByNamespace(allPods, pod));
		this.cache = Collections.unmodifiableMap(allPods);
	}

	private static void groupByNamespace(Map<String, List<V1Pod>> allPods, V1Pod pod) {
		if (pod.getMetadata() == null) {
			return;
		}
		final var namespace = pod.getMetadata().getNamespace();
		var lst = allPods.get(namespace);
		if (lst == null) {
			lst = new ArrayList<>();
		}
		lst.add(pod);
		allPods.put(namespace, lst);
	}

	public List<PodRuleViolation> evaluate(Rule rule) {
		return cache.values()
				.stream()
				.flatMap(List::stream)
				.flatMap(pod -> K8sContextBuilder.evaluatePod(rule, pod).stream())
				.collect(Collectors.toList());
	}
}
