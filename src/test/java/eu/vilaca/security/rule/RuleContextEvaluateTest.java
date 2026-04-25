package eu.vilaca.security.rule;

import eu.vilaca.security.violation.ImageData;
import org.junit.Test;

import java.util.List;

import static org.junit.Assert.*;

public class RuleContextEvaluateTest {

	private static Rule createRule(String name, String ruleExpr) {
		final var rule = new Rule();
		rule.setName(name);
		rule.setEnabled(true);
		rule.setRule(ruleExpr);
		rule.setAlert("test-alert");
		return rule;
	}

	private Context createMinimalContext() {
		final var ctx = new Context();
		ctx.container = new Context.Container();
		ctx.container.image = new ImageData("docker.io/nginx:latest");
		ctx.container.securityContext = new Context.ContainerSecurityContext();
		ctx.container.securityContext.capabilities = new Context.Capabilities();
		ctx.container.containerType = "standard";
		ctx.container.name = "test-container";
		ctx.spec = new Context.Spec();
		ctx.securityContext = new Context.PodSecurityContext();
		ctx.metadata = new Context.Metadata();
		ctx.metadata.namespace = "docker";
		ctx.metadata.name = "test-container";
		return ctx;
	}

	@Test
	public void evaluate_matchReturnsViolation() {
		final var rule = createRule("test", "container.securityContext.privileged == true");
		final var ctx = createMinimalContext();
		ctx.container.securityContext.privileged = true;

		final var violations = rule.evaluate(ctx, "docker", "my-container", "docker.io/nginx:latest");
		assertEquals(1, violations.size());
		assertEquals("docker", violations.get(0).getNamespace());
		assertEquals("my-container", violations.get(0).getPod());
		assertEquals("docker.io", violations.get(0).getImageData().getRegistry());
	}

	@Test
	public void evaluate_noMatchReturnsEmpty() {
		final var rule = createRule("test", "container.securityContext.privileged == true");
		final var ctx = createMinimalContext();
		ctx.container.securityContext.privileged = false;

		assertTrue(rule.evaluate(ctx, "docker", "my-container", "docker.io/nginx:latest").isEmpty());
	}

	@Test
	public void evaluate_invalidSpel_returnsEmpty() {
		final var rule = createRule("broken", "!!!invalid!!!");
		final var ctx = createMinimalContext();

		assertTrue(rule.evaluate(ctx, "docker", "my-container", "docker.io/nginx:latest").isEmpty());
	}

	@Test
	public void evaluate_severityPropagated() {
		final var rule = createRule("test", "true");
		rule.setSeverity("critical");
		final var ctx = createMinimalContext();

		final var violations = rule.evaluate(ctx, "docker", "c", "img");
		assertEquals("critical", violations.get(0).createLabels().get("severity"));
	}

	@Test
	public void evaluate_capabilitiesCheck() {
		final var rule = createRule("caps",
				"!container.securityContext.capabilities.drop.contains('ALL')");
		final var ctx = createMinimalContext();
		// capabilities.drop is empty -> !empty.contains('ALL') -> true

		assertEquals(1, rule.evaluate(ctx, "docker", "c", "img").size());
	}

	@Test
	public void evaluate_stringMethodsWork() {
		final var rule = createRule("registry",
				"container.image.registry.startsWith('docker')");
		final var ctx = createMinimalContext();

		assertEquals(1, rule.evaluate(ctx, "docker", "c", "docker.io/nginx:latest").size());
	}

	@Test
	public void evaluate_hostNetworkCheck() {
		final var rule = createRule("hostnet", "spec.hostNetwork == true");
		final var ctx = createMinimalContext();
		ctx.spec.hostNetwork = true;

		assertEquals(1, rule.evaluate(ctx, "docker", "c", "img").size());
	}

	@Test
	public void evaluate_labelsCheck() {
		final var rule = createRule("labels", "metadata.labels.containsKey('app')");
		final var ctx = createMinimalContext();
		ctx.metadata.labels = java.util.Map.of("app", "web");

		assertEquals(1, rule.evaluate(ctx, "docker", "c", "img").size());
	}

	@Test
	public void evaluate_alwaysFalse_returnsEmpty() {
		final var rule = createRule("false-rule", "false");
		final var ctx = createMinimalContext();

		assertTrue(rule.evaluate(ctx, "docker", "c", "img").isEmpty());
	}

	@Test
	public void evaluate_nullImage() {
		final var rule = createRule("test", "true");
		final var ctx = createMinimalContext();

		final var violations = rule.evaluate(ctx, "docker", "c", null);
		assertEquals(1, violations.size());
	}
}
