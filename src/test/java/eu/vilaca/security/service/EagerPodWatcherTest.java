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
import static org.mockito.Mockito.when;

public class EagerPodWatcherTest {

	private static V1Pod createPod(String namespace, String name, String image) {
		final var pod = new V1Pod();
		pod.setMetadata(new V1ObjectMeta().namespace(namespace).name(name));
		final var container = new V1Container().name("main").image(image);
		pod.setSpec(new V1PodSpec().containers(List.of(container)));
		return pod;
	}

	private static Rule createRule(String name, String ruleExpr) {
		final var rule = new Rule();
		rule.setName(name);
		rule.setEnabled(true);
		rule.setRule(ruleExpr);
		rule.setAlert("test-alert");
		return rule;
	}

	// --- Constructor loads pods ---

	@Test
	public void constructorLoadsPods() throws Exception {
		final var podList = new V1PodList();
		podList.setItems(List.of(
				createPod("default", "nginx", "docker.io/nginx:latest"),
				createPod("kube-system", "coredns", "registry.k8s.io/coredns:v1.10")
		));

		try (var mocked = Mockito.mockConstruction(CoreV1Api.class, (mock, ctx) ->
				when(mock.listPodForAllNamespaces(any(), any(), any(), any(), any(), any(), any(), any(), any(), any()))
						.thenReturn(podList))) {
			final var watcher = new EagerPodWatcher(new ApiClient());
			final var rule = createRule("always-true", "true");

			final var violations = watcher.evaluate(rule);
			assertEquals(2, violations.size());
		}
	}

	// --- Multiple pods in same namespace ---

	@Test
	public void multiplePodsInSameNamespace() throws Exception {
		final var podList = new V1PodList();
		podList.setItems(List.of(
				createPod("default", "nginx-1", "docker.io/nginx:latest"),
				createPod("default", "nginx-2", "docker.io/nginx:latest"),
				createPod("default", "redis", "docker.io/redis:7.0")
		));

		try (var mocked = Mockito.mockConstruction(CoreV1Api.class, (mock, ctx) ->
				when(mock.listPodForAllNamespaces(any(), any(), any(), any(), any(), any(), any(), any(), any(), any()))
						.thenReturn(podList))) {
			final var watcher = new EagerPodWatcher(new ApiClient());
			final var rule = createRule("always-true", "true");

			final var violations = watcher.evaluate(rule);
			assertEquals(3, violations.size());
		}
	}

	// --- No pods ---

	@Test
	public void noPods() throws Exception {
		final var podList = new V1PodList();
		podList.setItems(new ArrayList<>());

		try (var mocked = Mockito.mockConstruction(CoreV1Api.class, (mock, ctx) ->
				when(mock.listPodForAllNamespaces(any(), any(), any(), any(), any(), any(), any(), any(), any(), any()))
						.thenReturn(podList))) {
			final var watcher = new EagerPodWatcher(new ApiClient());
			final var rule = createRule("always-true", "true");

			final var violations = watcher.evaluate(rule);
			assertTrue(violations.isEmpty());
		}
	}

	// --- Rule that matches only some pods ---

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
				when(mock.listPodForAllNamespaces(any(), any(), any(), any(), any(), any(), any(), any(), any(), any()))
						.thenReturn(podList))) {
			final var watcher = new EagerPodWatcher(new ApiClient());
			final var rule = createRule("privileged-check",
					"container.securityContext.privileged == true");

			final var violations = watcher.evaluate(rule);
			assertEquals(1, violations.size());
			assertEquals("priv-pod", violations.get(0).getPod());
		}
	}

	// --- Constructor throws ApiException ---

	@Test(expected = ApiException.class)
	public void constructorThrowsApiException() throws Exception {
		try (var mocked = Mockito.mockConstruction(CoreV1Api.class, (mock, ctx) ->
				when(mock.listPodForAllNamespaces(any(), any(), any(), any(), any(), any(), any(), any(), any(), any()))
						.thenThrow(new ApiException("Forbidden")))) {
			new EagerPodWatcher(new ApiClient());
		}
	}

	// --- Pods across many namespaces ---

	@Test
	public void podsAcrossManyNamespaces() throws Exception {
		final var podList = new V1PodList();
		podList.setItems(List.of(
				createPod("default", "app1", "docker.io/app:v1"),
				createPod("staging", "app2", "docker.io/app:v2"),
				createPod("prod", "app3", "docker.io/app:v3"),
				createPod("kube-system", "coredns", "registry.k8s.io/coredns:v1.10")
		));

		try (var mocked = Mockito.mockConstruction(CoreV1Api.class, (mock, ctx) ->
				when(mock.listPodForAllNamespaces(any(), any(), any(), any(), any(), any(), any(), any(), any(), any()))
						.thenReturn(podList))) {
			final var watcher = new EagerPodWatcher(new ApiClient());
			final var rule = createRule("all-pods", "true");

			final var violations = watcher.evaluate(rule);
			assertEquals(4, violations.size());
		}
	}

	// --- Pod with null metadata is skipped ---

	@Test
	public void podWithNullMetadata_skipped() throws Exception {
		final var normalPod = createPod("default", "nginx", "docker.io/nginx:latest");
		final var nullMetaPod = new V1Pod();
		nullMetaPod.setSpec(new V1PodSpec().containers(List.of(
				new V1Container().name("main").image("docker.io/bad:latest"))));
		// metadata is null

		final var podList = new V1PodList();
		podList.setItems(List.of(normalPod, nullMetaPod));

		try (var mocked = Mockito.mockConstruction(CoreV1Api.class, (mock, ctx) ->
				when(mock.listPodForAllNamespaces(any(), any(), any(), any(), any(), any(), any(), any(), any(), any()))
						.thenReturn(podList))) {
			final var watcher = new EagerPodWatcher(new ApiClient());
			final var rule = createRule("always-true", "true");

			final var violations = watcher.evaluate(rule);
			// Only the pod with valid metadata should be evaluated
			assertEquals(1, violations.size());
			assertEquals("nginx", violations.get(0).getPod());
		}
	}

	// --- Always-false rule on multiple pods ---

	@Test
	public void alwaysFalseRule() throws Exception {
		final var podList = new V1PodList();
		podList.setItems(List.of(
				createPod("default", "pod1", "docker.io/nginx:latest"),
				createPod("default", "pod2", "docker.io/redis:7.0")
		));

		try (var mocked = Mockito.mockConstruction(CoreV1Api.class, (mock, ctx) ->
				when(mock.listPodForAllNamespaces(any(), any(), any(), any(), any(), any(), any(), any(), any(), any()))
						.thenReturn(podList))) {
			final var watcher = new EagerPodWatcher(new ApiClient());
			final var rule = createRule("always-false", "false");

			final var violations = watcher.evaluate(rule);
			assertTrue(violations.isEmpty());
		}
	}
}
