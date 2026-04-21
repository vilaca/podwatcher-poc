package eu.vilaca.security.service;

import eu.vilaca.security.rule.Rule;
import eu.vilaca.security.rule.model.Filter;
import eu.vilaca.security.rule.model.Namespace;
import io.kubernetes.client.openapi.ApiClient;
import io.kubernetes.client.openapi.ApiException;
import io.kubernetes.client.openapi.apis.CoreV1Api;
import io.kubernetes.client.openapi.models.*;
import org.junit.Test;
import org.mockito.Mockito;

import java.util.ArrayList;
import java.util.List;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

public class LazyPodWatcherTest {

	private static V1Pod createPod(String namespace, String name, String image) {
		final var pod = new V1Pod();
		pod.setMetadata(new V1ObjectMeta().namespace(namespace).name(name));
		final var container = new V1Container().name("main").image(image);
		pod.setSpec(new V1PodSpec().containers(List.of(container)));
		return pod;
	}

	private static Rule createRule(String name, String ruleExpr, List<String> includeNamespaces) {
		final var rule = new Rule();
		rule.setName(name);
		rule.setEnabled(true);
		rule.setRule(ruleExpr);
		rule.setAlert("test-alert");
		final var ns = new Namespace();
		ns.setInclude(includeNamespaces);
		final var filter = new Filter();
		filter.setNamespace(ns);
		rule.setFilter(filter);
		return rule;
	}

	// --- Single namespace ---

	@Test
	public void evaluateSingleNamespace() throws Exception {
		final var podList = new V1PodList();
		podList.setItems(List.of(
				createPod("default", "nginx", "docker.io/nginx:latest")
		));

		try (var mocked = Mockito.mockConstruction(CoreV1Api.class, (mock, ctx) ->
				when(mock.listNamespacedPod(eq("default"), any(), any(), any(), any(), any(), any(), any(), any(), any(), any()))
						.thenReturn(podList))) {
			final var watcher = new LazyPodWatcher(new ApiClient());
			final var rule = createRule("test", "true", List.of("default"));

			final var violations = watcher.evaluate(rule);
			assertEquals(1, violations.size());
		}
	}

	// --- Multiple namespaces ---

	@Test
	public void evaluateMultipleNamespaces() throws Exception {
		final var defaultPods = new V1PodList();
		defaultPods.setItems(List.of(createPod("default", "nginx", "docker.io/nginx:latest")));

		final var prodPods = new V1PodList();
		prodPods.setItems(List.of(createPod("prod", "api", "docker.io/api:v1")));

		try (var mocked = Mockito.mockConstruction(CoreV1Api.class, (mock, ctx) -> {
			when(mock.listNamespacedPod(eq("default"), any(), any(), any(), any(), any(), any(), any(), any(), any(), any()))
					.thenReturn(defaultPods);
			when(mock.listNamespacedPod(eq("prod"), any(), any(), any(), any(), any(), any(), any(), any(), any(), any()))
					.thenReturn(prodPods);
		})) {
			final var watcher = new LazyPodWatcher(new ApiClient());
			final var rule = createRule("test", "true", List.of("default", "prod"));

			final var violations = watcher.evaluate(rule);
			assertEquals(2, violations.size());
		}
	}

	// --- Empty namespace ---

	@Test
	public void evaluateEmptyNamespace() throws Exception {
		final var podList = new V1PodList();
		podList.setItems(new ArrayList<>());

		try (var mocked = Mockito.mockConstruction(CoreV1Api.class, (mock, ctx) ->
				when(mock.listNamespacedPod(eq("empty"), any(), any(), any(), any(), any(), any(), any(), any(), any(), any()))
						.thenReturn(podList))) {
			final var watcher = new LazyPodWatcher(new ApiClient());
			final var rule = createRule("test", "true", List.of("empty"));

			final var violations = watcher.evaluate(rule);
			assertTrue(violations.isEmpty());
		}
	}

	// --- Caching: same namespace queried twice uses cache ---

	@Test
	public void cachesNamespaceResults() throws Exception {
		final var podList = new V1PodList();
		podList.setItems(List.of(createPod("default", "nginx", "docker.io/nginx:latest")));

		try (var mocked = Mockito.mockConstruction(CoreV1Api.class, (mock, ctx) ->
				when(mock.listNamespacedPod(eq("default"), any(), any(), any(), any(), any(), any(), any(), any(), any(), any()))
						.thenReturn(podList))) {
			final var watcher = new LazyPodWatcher(new ApiClient());

			final var rule1 = createRule("rule1", "true", List.of("default"));
			final var rule2 = createRule("rule2", "true", List.of("default"));

			watcher.evaluate(rule1);
			watcher.evaluate(rule2);

			// CoreV1Api was constructed once, listNamespacedPod should be called only once due to cache
			final var constructedMock = mocked.constructed().get(0);
			verify(constructedMock, times(1))
					.listNamespacedPod(eq("default"), any(), any(), any(), any(), any(), any(), any(), any(), any(), any());
		}
	}

	// --- API exception for namespace ---

	@Test
	public void apiExceptionReturnsEmpty() throws Exception {
		try (var mocked = Mockito.mockConstruction(CoreV1Api.class, (mock, ctx) ->
				when(mock.listNamespacedPod(eq("forbidden"), any(), any(), any(), any(), any(), any(), any(), any(), any(), any()))
						.thenThrow(new ApiException("Forbidden")))) {
			final var watcher = new LazyPodWatcher(new ApiClient());
			final var rule = createRule("test", "true", List.of("forbidden"));

			// Should not throw, should return empty
			final var violations = watcher.evaluate(rule);
			assertTrue(violations.isEmpty());
		}
	}

	// --- Rule matches only some pods ---

	@Test
	public void ruleMatchesSomePods() throws Exception {
		final var pod1 = createPod("default", "priv-pod", "docker.io/nginx:latest");
		pod1.getSpec().getContainers().get(0).setSecurityContext(
				new V1SecurityContext().privileged(true));

		final var pod2 = createPod("default", "safe-pod", "docker.io/nginx:latest");
		pod2.getSpec().getContainers().get(0).setSecurityContext(
				new V1SecurityContext().privileged(false));

		final var podList = new V1PodList();
		podList.setItems(List.of(pod1, pod2));

		try (var mocked = Mockito.mockConstruction(CoreV1Api.class, (mock, ctx) ->
				when(mock.listNamespacedPod(eq("default"), any(), any(), any(), any(), any(), any(), any(), any(), any(), any()))
						.thenReturn(podList))) {
			final var watcher = new LazyPodWatcher(new ApiClient());
			final var rule = createRule("privileged-check",
					"container.securityContext.privileged == true",
					List.of("default"));

			final var violations = watcher.evaluate(rule);
			assertEquals(1, violations.size());
			assertEquals("priv-pod", violations.get(0).getPod());
		}
	}

	// --- Always-false rule ---

	@Test
	public void alwaysFalseRule() throws Exception {
		final var podList = new V1PodList();
		podList.setItems(List.of(
				createPod("default", "pod1", "docker.io/nginx:latest"),
				createPod("default", "pod2", "docker.io/redis:7.0")
		));

		try (var mocked = Mockito.mockConstruction(CoreV1Api.class, (mock, ctx) ->
				when(mock.listNamespacedPod(eq("default"), any(), any(), any(), any(), any(), any(), any(), any(), any(), any()))
						.thenReturn(podList))) {
			final var watcher = new LazyPodWatcher(new ApiClient());
			final var rule = createRule("always-false", "false", List.of("default"));

			final var violations = watcher.evaluate(rule);
			assertTrue(violations.isEmpty());
		}
	}
}
