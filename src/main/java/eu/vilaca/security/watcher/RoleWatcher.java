package eu.vilaca.security.watcher;

import eu.vilaca.security.rule.Rule;
import eu.vilaca.security.violation.RuleViolation;
import io.kubernetes.client.openapi.ApiClient;
import io.kubernetes.client.openapi.ApiException;
import io.kubernetes.client.openapi.apis.RbacAuthorizationV1Api;
import io.kubernetes.client.openapi.models.V1ClusterRole;
import lombok.extern.log4j.Log4j2;

import java.util.List;
import java.util.stream.Collectors;

@Log4j2
public class RoleWatcher implements PodWatcher {
	private final List<V1ClusterRole> cache;

	public RoleWatcher(ApiClient client) throws ApiException {
		this.cache = new RbacAuthorizationV1Api(client).listClusterRole(
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
	}

	public List<RuleViolation> evaluate(Rule rule) {
		return this.cache.stream()
				.flatMap(cr -> rule.evaluate(cr).stream())
				.collect(Collectors.toList());
	}
}
