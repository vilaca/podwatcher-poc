package eu.vilaca.security.violation;

import eu.vilaca.security.rule.Rule;
import io.kubernetes.client.openapi.models.V1Container;
import io.kubernetes.client.openapi.models.V1ObjectMeta;
import io.kubernetes.client.openapi.models.V1Pod;
import org.junit.Test;

import static org.junit.Assert.*;

/**
 * Tests Lombok-generated methods on PodRuleViolation to improve coverage.
 */
public class PodRuleViolationLombokTest {

	private static Rule createRule(String name) {
		final var rule = new Rule();
		rule.setName(name);
		rule.setAlert("alert");
		rule.setEnabled(true);
		rule.setRule("true");
		return rule;
	}

	private static V1Pod createPod(String ns, String name) {
		final var pod = new V1Pod();
		pod.setMetadata(new V1ObjectMeta().namespace(ns).name(name));
		return pod;
	}

	@Test
	public void toStringContainsFields() {
		final var v = new PodRuleViolation(createRule("r"), createPod("ns", "p"),
				new V1Container().image("docker.io/img:v1"));
		final var str = v.toString();
		assertNotNull(str);
		assertTrue(str.contains("ns"));
		assertTrue(str.contains("p"));
	}

	@Test
	public void equalsIdentical() {
		final var rule = createRule("r");
		final var pod = createPod("ns", "p");
		final var c = new V1Container().image("docker.io/img:v1");
		final var v1 = new PodRuleViolation(rule, pod, c);
		final var v2 = new PodRuleViolation(rule, pod, c);
		assertEquals(v1, v2);
		assertEquals(v1.hashCode(), v2.hashCode());
	}

	@Test
	public void notEqualDifferentNamespace() {
		final var rule = createRule("r");
		final var c = new V1Container().image("docker.io/img:v1");
		final var v1 = new PodRuleViolation(rule, createPod("ns1", "p"), c);
		final var v2 = new PodRuleViolation(rule, createPod("ns2", "p"), c);
		assertNotEquals(v1, v2);
	}

	@Test
	public void notEqualDifferentPod() {
		final var rule = createRule("r");
		final var c = new V1Container().image("docker.io/img:v1");
		final var v1 = new PodRuleViolation(rule, createPod("ns", "p1"), c);
		final var v2 = new PodRuleViolation(rule, createPod("ns", "p2"), c);
		assertNotEquals(v1, v2);
	}

	@Test
	public void notEqualDifferentRule() {
		final var pod = createPod("ns", "p");
		final var c = new V1Container().image("docker.io/img:v1");
		final var v1 = new PodRuleViolation(createRule("r1"), pod, c);
		final var v2 = new PodRuleViolation(createRule("r2"), pod, c);
		assertNotEquals(v1, v2);
	}

	@Test
	public void equalsNull() {
		final var v = new PodRuleViolation(createRule("r"), createPod("ns", "p"),
				new V1Container().image("docker.io/img:v1"));
		assertNotEquals(null, v);
	}

	@Test
	public void equalsSelf() {
		final var v = new PodRuleViolation(createRule("r"), createPod("ns", "p"),
				new V1Container().image("docker.io/img:v1"));
		assertEquals(v, v);
	}

	@Test
	public void equalsDifferentType() {
		final var v = new PodRuleViolation(createRule("r"), createPod("ns", "p"),
				new V1Container().image("docker.io/img:v1"));
		assertNotEquals("string", v);
	}

	@Test
	public void getters() {
		final var rule = createRule("my-rule");
		final var v = new PodRuleViolation(rule, createPod("prod", "web"),
				new V1Container().image("docker.io/app:v2"));
		assertEquals(rule, v.getRule());
		assertEquals("prod", v.getNamespace());
		assertEquals("web", v.getPod());
		assertNotNull(v.getImageData());
	}

	@Test
	public void setters() {
		final var v = new PodRuleViolation(createRule("r"), createPod("ns", "p"),
				new V1Container().image("docker.io/img:v1"));
		v.setNamespace("new-ns");
		v.setPod("new-pod");
		assertEquals("new-ns", v.getNamespace());
		assertEquals("new-pod", v.getPod());
	}

	@Test
	public void setRule() {
		final var v = new PodRuleViolation(createRule("old"), createPod("ns", "p"),
				new V1Container().image("docker.io/img:v1"));
		final var newRule = createRule("new");
		v.setRule(newRule);
		assertEquals("new", v.getRule().getName());
	}

	@Test
	public void setImageData() {
		final var v = new PodRuleViolation(createRule("r"), createPod("ns", "p"),
				new V1Container().image("docker.io/img:v1"));
		final var newImg = new ImageData("ghcr.io/other:v2");
		v.setImageData(newImg);
		assertEquals("ghcr.io", v.getImageData().getRegistry());
	}
}
