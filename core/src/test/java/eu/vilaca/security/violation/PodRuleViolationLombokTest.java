package eu.vilaca.security.violation;

import eu.vilaca.security.rule.Rule;
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

	@Test
	public void toStringContainsFields() {
		final var v = new PodRuleViolation(createRule("r"), "ns", "p", "docker.io/img:v1");
		final var str = v.toString();
		assertNotNull(str);
		assertTrue(str.contains("ns"));
		assertTrue(str.contains("p"));
	}

	@Test
	public void equalsIdentical() {
		final var rule = createRule("r");
		final var v1 = new PodRuleViolation(rule, "ns", "p", "docker.io/img:v1");
		final var v2 = new PodRuleViolation(rule, "ns", "p", "docker.io/img:v1");
		assertEquals(v1, v2);
		assertEquals(v1.hashCode(), v2.hashCode());
	}

	@Test
	public void notEqualDifferentNamespace() {
		final var rule = createRule("r");
		final var v1 = new PodRuleViolation(rule, "ns1", "p", "docker.io/img:v1");
		final var v2 = new PodRuleViolation(rule, "ns2", "p", "docker.io/img:v1");
		assertNotEquals(v1, v2);
	}

	@Test
	public void notEqualDifferentPod() {
		final var rule = createRule("r");
		final var v1 = new PodRuleViolation(rule, "ns", "p1", "docker.io/img:v1");
		final var v2 = new PodRuleViolation(rule, "ns", "p2", "docker.io/img:v1");
		assertNotEquals(v1, v2);
	}

	@Test
	public void notEqualDifferentRule() {
		final var v1 = new PodRuleViolation(createRule("r1"), "ns", "p", "docker.io/img:v1");
		final var v2 = new PodRuleViolation(createRule("r2"), "ns", "p", "docker.io/img:v1");
		assertNotEquals(v1, v2);
	}

	@Test
	public void equalsNull() {
		final var v = new PodRuleViolation(createRule("r"), "ns", "p", "docker.io/img:v1");
		assertNotEquals(null, v);
	}

	@Test
	public void equalsSelf() {
		final var v = new PodRuleViolation(createRule("r"), "ns", "p", "docker.io/img:v1");
		assertEquals(v, v);
	}

	@Test
	public void equalsDifferentType() {
		final var v = new PodRuleViolation(createRule("r"), "ns", "p", "docker.io/img:v1");
		assertNotEquals("string", v);
	}

	@Test
	public void getters() {
		final var rule = createRule("my-rule");
		final var v = new PodRuleViolation(rule, "prod", "web", "docker.io/app:v2");
		assertEquals(rule, v.getRule());
		assertEquals("prod", v.getNamespace());
		assertEquals("web", v.getPod());
		assertNotNull(v.getImageData());
	}

	@Test
	public void setters() {
		final var v = new PodRuleViolation(createRule("r"), "ns", "p", "docker.io/img:v1");
		v.setNamespace("new-ns");
		v.setPod("new-pod");
		assertEquals("new-ns", v.getNamespace());
		assertEquals("new-pod", v.getPod());
	}

	@Test
	public void setRule() {
		final var v = new PodRuleViolation(createRule("old"), "ns", "p", "docker.io/img:v1");
		final var newRule = createRule("new");
		v.setRule(newRule);
		assertEquals("new", v.getRule().getName());
	}

	@Test
	public void setImageData() {
		final var v = new PodRuleViolation(createRule("r"), "ns", "p", "docker.io/img:v1");
		final var newImg = new ImageData("ghcr.io/other:v2");
		v.setImageData(newImg);
		assertEquals("ghcr.io", v.getImageData().getRegistry());
	}
}
