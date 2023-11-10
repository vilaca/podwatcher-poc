package eu.vilaca;

import eu.vilaca.rule.PodWatcherRule;
import eu.vilaca.violation.PodRuleViolation;
import io.kubernetes.client.openapi.ApiClient;
import io.kubernetes.client.openapi.ApiException;

import java.util.List;
import java.util.stream.Collectors;

public class PodWatcherService {

	private final ApiClient client;

	public PodWatcherService(ApiClient client) {
		this.client = client;
	}

	List<PodRuleViolation> watch(List<PodWatcherRule> rules) throws ApiException {
		final var allNamespaces = !rules.stream()
				.map(PodWatcherRule::allNamespaces)
				.collect(Collectors.toList())
				.contains(false);
		final PodWatcher watcher;
		if (allNamespaces) {
			watcher = PodWatcher.allNamespaces(client);
		} else {
			watcher = new PodWatcher(client);
		}
		return rules.stream()
				.flatMap(rule -> watcher.evaluate(rule).stream())
				.collect(Collectors.toList());
	}
}
