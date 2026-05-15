package eu.vilaca.security.violation;

import eu.vilaca.security.rule.Rule;
import org.junit.Test;

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

	// --- Constructor ---

	@Test
	public void constructorSetsFieldsCorrectly() {
		final var rule = createRule("test-rule", "test-alert");
		final var violation = new PodRuleViolation(rule, "prod", "web-server", "docker.io/nginx:1.25");

		assertEquals(rule, violation.getRule());
		assertEquals("prod", violation.getNamespace());
		assertEquals("web-server", violation.getPod());
		assertNotNull(violation.getImageData());
		assertEquals("docker.io", violation.getImageData().getRegistry());
		assertEquals("nginx", violation.getImageData().getName());
	}

	@Test
	public void constructorWithNullNamespace() {
		final var rule = createRule("test-rule", "test-alert");
		final var violation = new PodRuleViolation(rule, null, null, "docker.io/nginx:latest");

		assertNull(violation.getNamespace());
		assertNull(violation.getPod());
	}

	@Test
	public void constructorWithNullImage() {
		final var rule = createRule("test-rule", "test-alert");
		final var violation = new PodRuleViolation(rule, "default", "pod", null);

		assertNotNull(violation.getImageData());
		assertNull(violation.getImageData().getRegistry());
	}

	// --- createLabels ---

	@Test
	public void createLabelsContainsAllFields() {
		final var rule = createRule("my-rule", "my-alert");
		final var violation = new PodRuleViolation(rule, "staging", "api-server", "docker.io/myapp:v2");
		final var labels = violation.createLabels();

		assertEquals("my-rule", labels.get("rule"));
		assertEquals("staging", labels.get("namespace"));
		assertEquals("api-server", labels.get("pod"));
		assertNotNull(labels.get("image"));
	}

	@Test
	public void createLabelsOmitsNullValues() {
		final var rule = createRule("my-rule", "my-alert");
		final var violation = new PodRuleViolation(rule, null, null, "docker.io/nginx:latest");
		final var labels = violation.createLabels();

		assertTrue(labels.containsKey("rule"));
		assertTrue(labels.containsKey("image"));
		assertFalse(labels.containsKey("namespace"));
		assertFalse(labels.containsKey("pod"));
	}

	@Test
	public void createLabelsRuleNameIsCorrect() {
		final var rule = createRule("special-chars:rule-name/v2", "alert");
		final var violation = new PodRuleViolation(rule, "ns", "pod", "docker.io/img:v1");
		assertEquals("special-chars:rule-name/v2", violation.createLabels().get("rule"));
	}

	@Test
	public void createLabelsImagePrettyFormat() {
		final var rule = createRule("test", "alert");
		final var violation = new PodRuleViolation(rule, "ns", "pod", "ghcr.io/org/myapp:v3.1");
		final var image = violation.createLabels().get("image");
		assertNotNull(image);
		assertTrue(image.contains("ghcr.io"));
		assertTrue(image.contains("myapp"));
	}

	@Test
	public void createLabelsHasFourEntriesWhenAllPresent() {
		final var rule = createRule("rule", "alert");
		final var violation = new PodRuleViolation(rule, "ns", "pod", "docker.io/app:v1");
		assertEquals(4, violation.createLabels().size());
	}

	@Test
	public void twoViolationsWithSameDataAreEqual() {
		final var rule = createRule("rule", "alert");
		final var v1 = new PodRuleViolation(rule, "ns", "pod-name", "docker.io/nginx:latest");
		final var v2 = new PodRuleViolation(rule, "ns", "pod-name", "docker.io/nginx:latest");

		assertEquals(v1.getNamespace(), v2.getNamespace());
		assertEquals(v1.getPod(), v2.getPod());
		assertEquals(v1.getRule(), v2.getRule());
	}
}
