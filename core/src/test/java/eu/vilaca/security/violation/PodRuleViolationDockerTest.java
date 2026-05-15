package eu.vilaca.security.violation;

import eu.vilaca.security.rule.Rule;
import org.junit.Test;

import static org.junit.Assert.*;

public class PodRuleViolationDockerTest {

	private static Rule createRule(String name) {
		final var rule = new Rule();
		rule.setName(name);
		rule.setEnabled(true);
		rule.setRule("true");
		rule.setAlert("test-alert");
		return rule;
	}

	@Test
	public void stringConstructor_fieldsPopulated() {
		final var rule = createRule("test-rule");
		final var violation = new PodRuleViolation(rule, "docker", "my-container", "docker.io/nginx:latest");

		assertEquals("docker", violation.getNamespace());
		assertEquals("my-container", violation.getPod());
		assertEquals("test-rule", violation.getRule().getName());
		assertEquals("docker.io", violation.getImageData().getRegistry());
		assertEquals("nginx", violation.getImageData().getName());
		assertEquals("latest", violation.getImageData().getTag());
	}

	@Test
	public void stringConstructor_createLabels() {
		final var rule = createRule("priv-check");
		final var violation = new PodRuleViolation(rule, "docker", "my-container", "docker.io/nginx:latest");

		final var labels = violation.createLabels();
		assertEquals("priv-check", labels.get("rule"));
		assertEquals("docker", labels.get("namespace"));
		assertEquals("my-container", labels.get("pod"));
		assertEquals("docker.io/nginx:latest", labels.get("image"));
	}

	@Test
	public void stringConstructor_severityLabel() {
		final var rule = createRule("test");
		rule.setSeverity("high");
		final var violation = new PodRuleViolation(rule, "docker", "c", "img");

		assertEquals("high", violation.createLabels().get("severity"));
	}

	@Test
	public void stringConstructor_noSeverity() {
		final var rule = createRule("test");
		final var violation = new PodRuleViolation(rule, "docker", "c", "img");

		assertFalse(violation.createLabels().containsKey("severity"));
	}

	@Test
	public void stringConstructor_nullNamespace() {
		final var rule = createRule("test");
		final var violation = new PodRuleViolation(rule, null, "c", "img");

		assertNull(violation.getNamespace());
		assertFalse(violation.createLabels().containsKey("namespace"));
	}

	@Test
	public void stringConstructor_nullImage() {
		final var rule = createRule("test");
		final var violation = new PodRuleViolation(rule, "docker", "c", null);

		assertNotNull(violation.getImageData());
	}
}
