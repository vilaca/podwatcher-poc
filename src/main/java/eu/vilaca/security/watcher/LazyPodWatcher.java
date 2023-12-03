package eu.vilaca.security.watcher;

import eu.vilaca.security.rule.Rule;
import eu.vilaca.security.violation.PodRuleViolation;
import eu.vilaca.security.violation.RuleViolation;
import io.kubernetes.client.openapi.ApiClient;
import io.kubernetes.client.openapi.ApiException;
import io.kubernetes.client.openapi.apis.CoreV1Api;
import io.kubernetes.client.openapi.models.V1Pod;
import lombok.extern.log4j.Log4j2;

import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

@Log4j2
public
class LazyPodWatcher implements PodWatcher {
	private final Map<String, List<V1Pod>> cache;
	private final CoreV1Api api;

	public LazyPodWatcher(ApiClient client) {
		this.api = new CoreV1Api(client);
		this.cache = new HashMap<>();
	}

	public List<RuleViolation> evaluate(Rule rule) {
		final List<V1Pod> pods = rule.getFilter()
				.getNamespace()
				.getInclude()
				.stream()
				.flatMap(ns -> getPodsForNameSpace(ns).stream())
				.collect(Collectors.toList());
		return pods.stream()
				.flatMap(pod -> rule.evaluate(pod).stream())
				.collect(Collectors.toList());
	}

	private List<V1Pod> getPodsForNameSpace(String ns) {
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
