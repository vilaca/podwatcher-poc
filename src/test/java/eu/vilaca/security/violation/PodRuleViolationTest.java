package eu.vilaca.security.violation;

import eu.vilaca.security.rule.Rule;
import io.kubernetes.client.openapi.models.V1Container;
import io.kubernetes.client.openapi.models.V1ObjectMeta;
import io.kubernetes.client.openapi.models.V1Pod;
import org.junit.Test;

import java.util.Map;

import static org.junit.Assert.*;

public class PodRuleViolationTest {

	private static Rule createRule(String name, String alertName) {
		final var rule = new Rule();
		rule.setName(name);
		rule.setAlert(alertName);
		rule.setEnabled(true);
		rule.setRule("true");
		return rule;
	}

	private static V1Pod createPod(String namespace, String name) {
		final var pod = new V1Pod();
		pod.setMetadata(new V1ObjectMeta().namespace(namespace).name(name));
		return pod;
	}

	// --- Constructor ---

	@Test
	public void constructorSetsFieldsCorrectly() {
		final var rule = createRule("test-rule", "test-alert");
		final var pod = createPod("prod", "web-server");
		final var container = new V1Container().image("docker.io/nginx:1.25");

		final var violation = new PodRuleViolation(rule, pod, container);

		assertEquals(rule, violation.getRule());
		assertEquals("prod", violation.getNamespace());
		assertEquals("web-server", violation.getPod());
		assertNotNull(violation.getImageData());
		assertEquals("docker.io", violation.getImageData().getRegistry());
		assertEquals("nginx", violation.getImageData().getName());
	}

	@Test
	public void constructorWithNullMetadata() {
		final var rule = createRule("test-rule", "test-alert");
		final var pod = new V1Pod(); // no metadata
		final var container = new V1Container().image("docker.io/nginx:latest");

		final var violation = new PodRuleViolation(rule, pod, container);

		assertNull(violation.getNamespace());
		assertNull(violation.getPod());
	}

	@Test
	public void constructorWithNullImage() {
		final var rule = createRule("test-rule", "test-alert");
		final var pod = createPod("default", "pod");
		final var container = new V1Container(); // no image

		final var violation = new PodRuleViolation(rule, pod, container);

		assertNotNull(violation.getImageData());
		assertNull(violation.getImageData().getRegistry());
	}

	// --- createLabels ---

	@Test
	public void createLabelsContainsAllFields() {
		final var rule = createRule("my-rule", "my-alert");
		final var pod = createPod("staging", "api-server");
		final var container = new V1Container().image("docker.io/myapp:v2");

		final var violation = new PodRuleViolation(rule, pod, container);
		final var labels = violation.createLabels();

		assertEquals("my-rule", labels.get("rule"));
		assertEquals("staging", labels.get("namespace"));
		assertEquals("api-server", labels.get("pod"));
		assertNotNull(labels.get("image"));
	}

	@Test
	public void createLabelsOmitsNullValues() {
		final var rule = createRule("my-rule", "my-alert");
		final var pod = new V1Pod(); // null metadata → null namespace and pod
		final var container = new V1Container().image("docker.io/nginx:latest");

		final var violation = new PodRuleViolation(rule, pod, container);
		final var labels = violation.createLabels();

		assertTrue(labels.containsKey("rule"));
		assertTrue(labels.containsKey("image"));
		assertFalse(labels.containsKey("namespace"));
		assertFalse(labels.containsKey("pod"));
	}

	@Test
	public void createLabelsRuleNameIsCorrect() {
		final var rule = createRule("special-chars:rule-name/v2", "alert");
		final var pod = createPod("ns", "pod");
		final var container = new V1Container().image("docker.io/img:v1");

		final var violation = new PodRuleViolation(rule, pod, container);
		final var labels = violation.createLabels();

		assertEquals("special-chars:rule-name/v2", labels.get("rule"));
	}

	@Test
	public void createLabelsImagePrettyFormat() {
		final var rule = createRule("test", "alert");
		final var pod = createPod("ns", "pod");
		final var container = new V1Container().image("ghcr.io/org/myapp:v3.1");

		final var violation = new PodRuleViolation(rule, pod, container);
		final var labels = violation.createLabels();

		final var image = labels.get("image");
		assertNotNull(image);
		assertTrue(image.contains("ghcr.io"));
		assertTrue(image.contains("myapp"));
	}

	// --- Label count ---

	@Test
	public void createLabelsHasFourEntriesWhenAllPresent() {
		final var rule = createRule("rule", "alert");
		final var pod = createPod("ns", "pod");
		final var container = new V1Container().image("docker.io/app:v1");

		final var violation = new PodRuleViolation(rule, pod, container);
		final var labels = violation.createLabels();

		assertEquals(4, labels.size());
	}

	// --- Equals via Lombok @Data ---

	@Test
	public void twoViolationsWithSameDataAreEqual() {
		final var rule = createRule("rule", "alert");
		final var pod = createPod("ns", "pod-name");
		final var container = new V1Container().image("docker.io/nginx:latest");

		final var v1 = new PodRuleViolation(rule, pod, container);
		final var v2 = new PodRuleViolation(rule, pod, container);

		// They have the same values but ImageData is a new instance each time
		assertEquals(v1.getNamespace(), v2.getNamespace());
		assertEquals(v1.getPod(), v2.getPod());
		assertEquals(v1.getRule(), v2.getRule());
	}
}
