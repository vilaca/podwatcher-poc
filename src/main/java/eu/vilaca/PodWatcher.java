package eu.vilaca;

import eu.vilaca.rule.LogicOperation;
import eu.vilaca.rule.PodWatcherRule;
import eu.vilaca.violation.ImageData;
import eu.vilaca.violation.PodRuleViolation;
import io.kubernetes.client.openapi.ApiClient;
import io.kubernetes.client.openapi.ApiException;
import io.kubernetes.client.openapi.apis.CoreV1Api;
import io.kubernetes.client.openapi.models.V1ContainerStatus;
import io.kubernetes.client.openapi.models.V1Pod;
import lombok.extern.log4j.Log4j2;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.stream.Collectors;

@Log4j2
public class PodWatcher {
	private final CoreV1Api api;
	private final Map<String, List<V1Pod>> cache;

	public PodWatcher(ApiClient client) {
		this(new CoreV1Api(client), new HashMap<>());
	}

	private PodWatcher(CoreV1Api api, Map<String, List<V1Pod>> cache) {
		this.api = api;
		this.cache = cache;
	}

	public static PodWatcher allNamespaces(ApiClient client) throws ApiException {
		final var api = new CoreV1Api(client);
		final Map<String, List<V1Pod>> allPods = new HashMap<>();
		api.listPodForAllNamespaces(
						null,
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
		return new PodWatcher(null, Collections.unmodifiableMap(allPods));
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

	public List<PodRuleViolation> evaluate(PodWatcherRule rule) {
		final List<V1Pod> pods;
		if (rule.allNamespaces()) {
			pods = cache.entrySet()
					.stream()
					.filter(entry -> !rule.exclude().contains(entry.getKey()))
					.flatMap(entry -> entry.getValue().stream())
					.collect(Collectors.toList());
		} else {
			pods = rule.include()
					.stream()
					.flatMap(ns -> cache.get(ns).stream())
					.collect(Collectors.toList());
		}

		return pods.stream()
				.flatMap(pod -> rule.evaluate(pod).stream())
				.collect(Collectors.toList());
	}
}
