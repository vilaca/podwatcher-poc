package eu.vilaca.security.rule;

import eu.vilaca.security.rule.model.Filter;
import eu.vilaca.security.rule.model.Namespace;
import org.junit.Test;

import java.util.List;

import static org.junit.Assert.*;

/**
 * Tests Lombok-generated methods on Rule to improve coverage.
 */
public class RuleLombokTest {

	private static Rule createRule(String name, String ruleExpr) {
		final var rule = new Rule();
		rule.setName(name);
		rule.setEnabled(true);
		rule.setRule(ruleExpr);
		rule.setAlert("test-alert");
		return rule;
	}

	@Test
	public void toStringContainsFields() {
		final var rule = createRule("my-rule", "true");
		final var str = rule.toString();
		assertNotNull(str);
		assertTrue(str.contains("my-rule"));
		assertTrue(str.contains("true"));
		assertTrue(str.contains("test-alert"));
	}

	@Test
	public void equalsIdentical() {
		final var r1 = createRule("r", "true");
		final var r2 = createRule("r", "true");
		assertEquals(r1, r2);
		assertEquals(r1.hashCode(), r2.hashCode());
	}

	@Test
	public void notEqualDifferentName() {
		final var r1 = createRule("a", "true");
		final var r2 = createRule("b", "true");
		assertNotEquals(r1, r2);
	}

	@Test
	public void notEqualDifferentEnabled() {
		final var r1 = createRule("r", "true");
		final var r2 = createRule("r", "true");
		r2.setEnabled(false);
		assertNotEquals(r1, r2);
	}

	@Test
	public void notEqualDifferentRuleExpr() {
		final var r1 = createRule("r", "true");
		final var r2 = createRule("r", "false");
		assertNotEquals(r1, r2);
	}

	@Test
	public void equalsNull() {
		assertNotEquals(null, createRule("r", "true"));
	}

	@Test
	public void equalsSelf() {
		final var r = createRule("r", "true");
		assertEquals(r, r);
	}

	@Test
	public void equalsDifferentType() {
		assertNotEquals("string", createRule("r", "true"));
	}

	@Test
	public void gettersAndSetters() {
		final var rule = new Rule();
		rule.setName("test");
		rule.setEnabled(true);
		rule.setRule("expr");
		rule.setAlert("alert");
		final var ns = new Namespace();
		ns.setInclude(List.of("default"));
		final var filter = new Filter();
		filter.setNamespace(ns);
		rule.setFilter(filter);

		assertEquals("test", rule.getName());
		assertTrue(rule.isEnabled());
		assertEquals("expr", rule.getRule());
		assertEquals("alert", rule.getAlert());
		assertNotNull(rule.getFilter());
		assertEquals(1, rule.getFilter().getNamespace().getInclude().size());
	}

	@Test
	public void equalsWithFilter() {
		final var ns = new Namespace();
		ns.setInclude(List.of("default"));
		final var filter = new Filter();
		filter.setNamespace(ns);

		final var r1 = createRule("r", "true");
		r1.setFilter(filter);
		final var r2 = createRule("r", "true");
		r2.setFilter(filter);

		assertEquals(r1, r2);
	}

	@Test
	public void notEqualDifferentFilter() {
		final var ns1 = new Namespace();
		ns1.setInclude(List.of("default"));
		final var f1 = new Filter();
		f1.setNamespace(ns1);

		final var ns2 = new Namespace();
		ns2.setInclude(List.of("prod"));
		final var f2 = new Filter();
		f2.setNamespace(ns2);

		final var r1 = createRule("r", "true");
		r1.setFilter(f1);
		final var r2 = createRule("r", "true");
		r2.setFilter(f2);

		assertNotEquals(r1, r2);
	}
}
