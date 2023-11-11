package eu.vilaca.security.rule;

import eu.vilaca.security.violation.ImageData;
import eu.vilaca.security.violation.PodRuleViolation;
import io.kubernetes.client.openapi.models.V1ContainerStatus;
import io.kubernetes.client.openapi.models.V1Pod;
import lombok.Getter;
import lombok.extern.log4j.Log4j2;

import java.util.List;
import java.util.Objects;
import java.util.stream.Collectors;

@Log4j2
@Getter
public class PodWatcherRule {

	private String name;
	private RuleFilter namespace;
	private boolean enabled;
	private AllowList imageName;
	private LogicOperation operation;
	private List<String> repository;
	private AllowList sha;
	private AllowList tag;
	private String template;

	public List<PodRuleViolation> evaluate(V1Pod pod) {
		final var podName = pod.getMetadata().getName();
		if (this.getNamespace() != null && !this.getNamespace().filter(pod.getMetadata().getNamespace())) {
			log.debug("Excluded pod {}. Reason: namespace rule.", podName);
			return List.of();
		}

		//log.debug("Included pod {}.", podName);

		final var ruleViolations = pod.getStatus()
				.getContainerStatuses()
				.stream()
				.map(this::createImageData)
				.map(this::evaluate)
				.filter(Objects::nonNull)
				.collect(Collectors.toList());

		ruleViolations.forEach(v -> {
			v.setNamespace(pod.getMetadata().getNamespace());
			v.setPod(pod.getMetadata().getName());
		});

		return ruleViolations;
	}
	private boolean isRepositoryAllowed(String candidate) {
		return repository == null || repository.isEmpty() || repository.contains(candidate);
	}
	private PodRuleViolation evaluate(ImageData image) {
		final var validImage = this.getImageName() == null || this.getImageName().isAllowed(image.getName());
		final var validRegistry = this.getRepository() == null || this.isRepositoryAllowed(image.getRegistry());
		final var validSha = this.getSha() == null || this.getSha().isAllowed(image.getSha256());
		final var validTag = this.getTag() == null || this.getTag().isAllowed(image.getTag());
		final var operation = this.getOperation() == null ? LogicOperation.AND : this.getOperation();

		log.debug("op: {} image: {} reg: {} tag: {} sha: {}", operation, validImage, validRegistry, validTag, validSha);

		return evaluateLogicOperation(validImage, validRegistry, validSha, validTag, operation)
				? null
				: PodRuleViolation.builder().imageData(image).rule(this).build();
	}

	private boolean evaluateLogicOperation(boolean validImage, boolean validRegistry, boolean validSha, boolean validTag, LogicOperation operation) {
		switch (operation) {
			case OR:
				return validImage || validSha || validRegistry || validTag;
			case AND:
				return validImage && validSha && validRegistry && validTag;
			default:
				throw new IllegalStateException();
		}
	}

	private ImageData createImageData(V1ContainerStatus status) {
		final var image = status.getImage();
		final var registryPos = image.indexOf('/');
		final var registry = registryPos != -1 ? image.substring(0, registryPos) : "";

		final var tagPos = image.lastIndexOf(':');
		final var imageName = tagPos != -1
				? image.substring(registryPos ==-1 ? 0 : registryPos + 1, tagPos) : "";

		final var tag = tagPos != -1 ? image.substring(tagPos + 1) : "";
		final var sha256 = status.getImageID().startsWith("docker://sha256:") ?
				status.getImageID().substring("docker://sha256:".length()) : "";

		log.debug("registry: {} image: {} tag: {} sha256: {}", registry, imageName, tag, sha256);

		return ImageData.builder()
				.name(imageName)
				.registry(registry)
				.tag(tag)
				.sha256(sha256)
				.build();
	}

	public boolean allNamespaces() {
		return namespace == null || namespace.getInclude() == null
				|| namespace.getInclude().contains("")
				|| namespace.getInclude().contains("*")
				|| namespace.getInclude().contains(null)
				|| namespace.getInclude().isEmpty();
	}

	public List<String> include() {
		return namespace == null || namespace.getInclude() == null ? List.of() : namespace.getInclude();
	}

	public List<String> exclude() {
		return namespace == null || namespace.getExclude() == null ? List.of() : namespace.getExclude();
	}

//	@Builder
//	@Data
//	public static class PodRuleMetadata {
//		private String name;
//	}
}
