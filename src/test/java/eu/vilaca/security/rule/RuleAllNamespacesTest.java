package eu.vilaca.security.rule;

import eu.vilaca.security.rule.model.Filter;
import eu.vilaca.security.rule.model.Namespace;
import org.junit.Test;

import java.util.List;

import static org.junit.Assert.*;

/**
 * Tests for Rule.allNamespaces() logic which determines whether
 * EagerPodWatcher or LazyPodWatcher is used.
 */
public class RuleAllNamespacesTest {

	private static Rule createRule() {
		final var rule = new Rule();
		rule.setName("test");
		rule.setEnabled(true);
		rule.setRule("true");
		return rule;
	}

	@Test
	public void noFilter_returnsTrue() {
		final var rule = createRule();
		assertTrue(rule.allNamespaces());
	}

	@Test
	public void filterWithNoNamespace_returnsTrue() {
		final var rule = createRule();
		rule.setFilter(new Filter());
		assertTrue(rule.allNamespaces());
	}

	@Test
	public void filterWithEmptyNamespace_returnsTrue() {
		final var rule = createRule();
		final var filter = new Filter();
		filter.setNamespace(new Namespace());
		rule.setFilter(filter);
		// namespace.exclude is null → returns true
		assertTrue(rule.allNamespaces());
	}

	@Test
	public void filterWithExcludeOnly_returnsTrue() {
		final var rule = createRule();
		final var ns = new Namespace();
		ns.setExclude(List.of("kube-system"));
		final var filter = new Filter();
		filter.setNamespace(ns);
		rule.setFilter(filter);
		assertTrue(rule.allNamespaces());
	}

	@Test
	public void filterWithIncludeOnly_returnsFalse() {
		final var rule = createRule();
		final var ns = new Namespace();
		ns.setInclude(List.of("default", "prod"));
		final var filter = new Filter();
		filter.setNamespace(ns);
		rule.setFilter(filter);
		assertFalse(rule.allNamespaces());
	}

	@Test
	public void filterWithBothIncludeAndExclude_returnsTrue() {
		// When exclude is set (non-null), allNamespaces returns true
		// regardless of include
		final var rule = createRule();
		final var ns = new Namespace();
		ns.setInclude(List.of("default"));
		ns.setExclude(List.of("kube-system"));
		final var filter = new Filter();
		filter.setNamespace(ns);
		rule.setFilter(filter);
		assertTrue(rule.allNamespaces());
	}
}
