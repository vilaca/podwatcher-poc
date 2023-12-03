package eu.vilaca.security.service;

import eu.vilaca.security.rule.Rule;
import eu.vilaca.security.violation.RuleViolation;
import eu.vilaca.security.watcher.RoleWatcher;
import io.kubernetes.client.openapi.ApiClient;
import io.kubernetes.client.openapi.ApiException;
import lombok.extern.log4j.Log4j2;

import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

@Log4j2
public class RbacWatcherService implements WatcherService {
	private final ApiClient api;

	public RbacWatcherService(ApiClient apiClient) {
		this.api = apiClient;
	}

	@Override
	public List<RuleViolation> watch(List<Rule> rules) {
		final RoleWatcher watcher;
		try {
			watcher = new RoleWatcher(this.api);
		} catch (ApiException e) {
			log.error(e);
			return Collections.emptyList();
		}
		return rules.stream()
				.flatMap(rule -> watcher.evaluate(rule).stream())
				.collect(Collectors.toList());
	}
}
