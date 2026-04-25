package eu.vilaca.security.docker;

import com.github.dockerjava.api.DockerClient;
import eu.vilaca.security.rule.Rule;
import eu.vilaca.security.service.WatcherService;
import eu.vilaca.security.violation.PodRuleViolation;
import lombok.extern.log4j.Log4j2;

import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

@Log4j2
public class DockerWatcherService implements WatcherService {

	private final DockerClient client;

	public DockerWatcherService(DockerClient client) {
		this.client = client;
	}

	@Override
	public List<PodRuleViolation> watch(List<Rule> rules) {
		try {
			final var watcher = new DockerWatcher(client);
			return rules.stream()
					.flatMap(rule -> watcher.evaluate(rule).stream())
					.collect(Collectors.toList());
		} catch (Exception e) {
			log.error("Can't scan Docker containers.", e);
			return Collections.emptyList();
		}
	}
}
