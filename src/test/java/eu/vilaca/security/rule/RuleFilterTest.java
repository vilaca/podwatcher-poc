package eu.vilaca.security.rule;

import org.junit.Test;

import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import static org.junit.Assert.*;

public class RuleFilterTest {

	// --- Include filter ---

	@Test
	public void includeAllowsMatchingNamespace() {
		final var filter = new RuleFilter();
		filter.setInclude(List.of("default", "prod"));
		assertTrue(filter.filter("default"));
		assertTrue(filter.filter("prod"));
	}

	@Test
	public void includeRejectsNonMatchingNamespace() {
		final var filter = new RuleFilter();
		filter.setInclude(List.of("default", "prod"));
		assertFalse(filter.filter("kube-system"));
		assertFalse(filter.filter("staging"));
	}

	// --- Exclude filter ---

	@Test
	public void excludeRejectsMatchingNamespace() {
		final var filter = new RuleFilter();
		filter.setExclude(List.of("kube-system"));
		assertFalse(filter.filter("kube-system"));
	}

	@Test
	public void excludeAllowsNonMatchingNamespace() {
		final var filter = new RuleFilter();
		filter.setExclude(List.of("kube-system"));
		assertTrue(filter.filter("default"));
		assertTrue(filter.filter("prod"));
	}

	// --- Both include and exclude ---

	@Test
	public void includeAndExcludeBothActive() {
		final var filter = new RuleFilter();
		filter.setInclude(List.of("default", "prod", "kube-system"));
		filter.setExclude(List.of("kube-system"));
		// "kube-system" is in include but also in exclude
		assertFalse(filter.filter("kube-system"));
		// "default" is in include and not in exclude
		assertTrue(filter.filter("default"));
	}

	@Test
	public void includeAndExcludeWithNonMatchingCandidate() {
		final var filter = new RuleFilter();
		filter.setInclude(List.of("default"));
		filter.setExclude(List.of("kube-system"));
		// Not in include list → rejected by include
		assertFalse(filter.filter("staging"));
	}

	// --- No filters (both null) ---

	@Test
	public void noFiltersAllowsEverything() {
		final var filter = new RuleFilter();
		// Both include and exclude are null
		assertTrue(filter.filter("anything"));
		assertTrue(filter.filter("kube-system"));
		assertTrue(filter.filter(""));
	}

	// --- Empty lists ---

	@Test
	public void emptyIncludeListAllowsEverything() {
		final var filter = new RuleFilter();
		filter.setInclude(Collections.emptyList());
		assertTrue(filter.filter("anything"));
	}

	@Test
	public void emptyExcludeListAllowsEverything() {
		final var filter = new RuleFilter();
		filter.setExclude(Collections.emptyList());
		assertTrue(filter.filter("anything"));
	}

	@Test
	public void bothEmptyListsAllowEverything() {
		final var filter = new RuleFilter();
		filter.setInclude(Collections.emptyList());
		filter.setExclude(Collections.emptyList());
		assertTrue(filter.filter("anything"));
	}

	// --- Null candidate ---

	@Test
	public void nullCandidateWithInclude() {
		final var filter = new RuleFilter();
		filter.setInclude(List.of("default"));
		assertFalse(filter.filter(null));
	}

	@Test
	public void nullCandidateWithExclude() {
		final var filter = new RuleFilter();
		filter.setExclude(List.of("default"));
		// null is not in the exclude list, so it passes
		assertTrue(filter.filter(null));
	}

	@Test
	public void nullCandidateNoFilters() {
		final var filter = new RuleFilter();
		assertTrue(filter.filter(null));
	}

	// --- Case sensitivity ---

	@Test
	public void filterIsCaseSensitive() {
		final var filter = new RuleFilter();
		filter.setInclude(List.of("Default"));
		assertFalse(filter.filter("default"));
		assertTrue(filter.filter("Default"));
	}

	// --- Single element lists ---

	@Test
	public void singleInclude() {
		final var filter = new RuleFilter();
		filter.setInclude(List.of("only-this"));
		assertTrue(filter.filter("only-this"));
		assertFalse(filter.filter("not-this"));
	}

	@Test
	public void singleExclude() {
		final var filter = new RuleFilter();
		filter.setExclude(List.of("not-this"));
		assertFalse(filter.filter("not-this"));
		assertTrue(filter.filter("anything-else"));
	}
}
