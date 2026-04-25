package eu.vilaca.security.docker;

import com.github.dockerjava.api.DockerClient;
import com.github.dockerjava.api.exception.NotFoundException;
import eu.vilaca.security.rule.Rule;
import eu.vilaca.security.service.PodWatcher;
import eu.vilaca.security.violation.PodRuleViolation;
import lombok.extern.log4j.Log4j2;

import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

@Log4j2
public class DockerWatcher implements PodWatcher {

	private final DockerClient client;

	public DockerWatcher(DockerClient client) {
		this.client = client;
	}

	@Override
	public List<PodRuleViolation> evaluate(Rule rule) {
		return client.listContainersCmd()
				.withStatusFilter(List.of("running"))
				.exec()
				.stream()
				.map(container -> {
					try {
						return client.inspectContainerCmd(container.getId()).exec();
					} catch (NotFoundException e) {
						log.debug("Container {} removed before inspection.", container.getId());
						return null;
					}
				})
				.filter(Objects::nonNull)
				.flatMap(inspect -> {
					final var ctx = DockerContextBuilder.buildContext(inspect);
					final var name = DockerContextBuilder.containerName(inspect);
					final var config = inspect.getConfig();
					final var image = config != null ? config.getImage() : null;
					return rule.evaluate(ctx, "docker", name, image).stream();
				})
				.collect(Collectors.toList());
	}
}
