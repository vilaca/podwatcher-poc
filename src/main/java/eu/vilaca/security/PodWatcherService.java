package eu.vilaca.security;

import eu.vilaca.security.rule.PodWatcherRule;
import eu.vilaca.security.violation.PodRuleViolation;
import io.kubernetes.client.openapi.ApiClient;
import io.kubernetes.client.openapi.ApiException;
import lombok.extern.log4j.Log4j2;

import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

@Log4j2
public class PodWatcherService {

	private final ApiClient client;

	public PodWatcherService(ApiClient client) {
		this.client = client;
	}

	List<PodRuleViolation> watch(List<PodWatcherRule> rules) {
		final var allNamespaces = !rules.stream()
				.map(PodWatcherRule::allNamespaces)
				.collect(Collectors.toList())
				.contains(false);
		final PodWatcher watcher;
		if (allNamespaces) {
			try {
				watcher = PodWatcher.allNamespaces(client);
			} catch (ApiException e) {
				log.error("Can't list pods in all namespaces.", e);
				return Collections.emptyList();
			}
		} else {
			watcher = new PodWatcher(client);
		}
		return rules.stream()
				.flatMap(rule -> watcher.evaluate(rule).stream())
				.collect(Collectors.toList());
	}
}
