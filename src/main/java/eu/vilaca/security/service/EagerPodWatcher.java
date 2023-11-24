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
		final var namespace = pod.getMetadata().getNamespace();
		var lst = allPods.get(namespace);
		if (lst == null) {
			lst = new ArrayList<>();
		}
		lst.add(pod);
		allPods.put(namespace, lst);
	}

	public List<PodRuleViolation> evaluate(Rule rule) {
		final List<V1Pod> pods = cache.entrySet()
				.stream()
				//.filter(entry -> !rule.exclude().contains(entry.getKey()))
				.flatMap(entry -> entry.getValue().stream())
				.collect(Collectors.toList());
		return pods.stream()
				.flatMap(pod -> rule.evaluate(pod).stream())
				.collect(Collectors.toList());
	}
}
