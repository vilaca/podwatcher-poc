package eu.vilaca.security;

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
public class PodWatcher {
	private final Map<String, List<V1Pod>> cache;
	private CoreV1Api api;

	public PodWatcher(ApiClient client) {
		this.api = new CoreV1Api(client);
		this.cache = new HashMap<>();
	}

	private PodWatcher(Map<String, List<V1Pod>> cache) {
		this.cache = cache;
	}

	public static PodWatcher allNamespaces(ApiClient client) throws ApiException {
		final var api = new CoreV1Api(client);
		final Map<String, List<V1Pod>> allPods = new HashMap<>();
		api.listPodForAllNamespaces(null,
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
		return new PodWatcher(Collections.unmodifiableMap(allPods));
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
		final List<V1Pod> pods;
		if (rule.allNamespaces()) {
			pods = cache.entrySet()
					.stream()
					//.filter(entry -> !rule.exclude().contains(entry.getKey()))
					.flatMap(entry -> entry.getValue().stream())
					.collect(Collectors.toList());
		} else {
			pods = rule.getFilter().getNamespaces()
					.getInclude()
					.stream()
					.flatMap(ns -> getCached(ns).stream())
					.collect(Collectors.toList());
		}
		return pods.stream()
				.flatMap(pod -> rule.evaluate(pod).stream())
				.collect(Collectors.toList());
	}

	private List<V1Pod> getCached(String ns) {
		var pods = this.cache.get(ns);
		if (pods != null) {
			return pods;
		}
		try {
			pods = api.listNamespacedPod(ns,
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
					.getItems();
			this.cache.put(ns, pods);
			return pods;
		} catch (ApiException ex) {
			log.error("Cannot list pods in namespace {}.", ns, ex);
		}
		return Collections.emptyList();
	}
}
