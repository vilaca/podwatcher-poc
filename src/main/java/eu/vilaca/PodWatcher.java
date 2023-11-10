package eu.vilaca;

import eu.vilaca.rule.LogicOperation;
import eu.vilaca.violation.ImageData;
import eu.vilaca.violation.PodRuleViolation;
import eu.vilaca.rule.PodWatcherRule;
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
				.forEach(pod ->
						{
							final var namespace = pod.getMetadata().getNamespace();
							var lst = allPods.get(namespace);
							if (lst == null) {
								lst = new ArrayList<>();
							}
							lst.add(pod);
							allPods.put(namespace, lst);
						}
				);
		return new PodWatcher(null, Collections.unmodifiableMap(allPods));
	}

	private List<PodRuleViolation> evaluate(PodWatcherRule rule, V1Pod pod) {
		final var podName = pod.getMetadata().getName();
		if (rule.getNamespace() != null && !rule.getNamespace().filter(pod.getMetadata().getNamespace())) {
			log.debug("Excluded pod {}. Reason: namespace rule.", podName);
			return List.of();
		}

		//log.debug("Included pod {}.", podName);

		final var ruleViolations = pod.getStatus()
				.getContainerStatuses()
				.stream()
				.map(this::createImageData)
				.map(image -> validate(image, rule))
				.filter(Objects::nonNull)
				.collect(Collectors.toList());

		ruleViolations.forEach(v -> {
			v.setNamespace(pod.getMetadata().getNamespace());
			v.setPod(pod.getMetadata().getName());
		});

		return ruleViolations;
	}

	private PodRuleViolation validate(ImageData image, PodWatcherRule rule) {
		final var validImage = rule.getImageName() == null || rule.getImageName().isAllowed(image.getName());
		final var validRegistry = rule.getRepository() == null || rule.getRepository().isAllowed(image.getRegistry());
		final var validSha = rule.getSha() == null || rule.getSha().isAllowed(image.getSha256());
		final var validTag = rule.getTag() == null || rule.getTag().isAllowed(image.getTag());
		final var operation = rule.getOperation() == null ? LogicOperation.AND : rule.getOperation();

		log.debug("op: {} image: {} reg: {} tag: {} sha: {}", operation, validImage, validRegistry, validTag, validSha);

		return evaluateLogicOperation(validImage, validRegistry, validSha, validTag, operation)
				? null
				: PodRuleViolation.builder().imageData(image).rule(rule).build();
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
		final var registryPos = image.lastIndexOf('/');
		final var registry = registryPos != -1 ? image.substring(0, registryPos) : "";

		final var tagPos = image.lastIndexOf(':');
		final var imageName = tagPos != -1
				? image.substring(registry.isBlank() ? 0 : registry.length() + 1, tagPos) : "";

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
				.flatMap(pod-> evaluate(rule, pod).stream())
				.collect(Collectors.toList());
	}
}
