package eu.vilaca.security.rule.model;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import org.junit.Test;

import java.util.List;

import static org.junit.Assert.*;

public class FilterAndNamespaceTest {

	// --- Namespace model ---

	@Test
	public void namespaceInclude() {
		final var ns = new Namespace();
		ns.setInclude(List.of("default", "prod"));
		assertEquals(2, ns.getInclude().size());
		assertNull(ns.getExclude());
	}

	@Test
	public void namespaceExclude() {
		final var ns = new Namespace();
		ns.setExclude(List.of("kube-system"));
		assertEquals(1, ns.getExclude().size());
		assertNull(ns.getInclude());
	}

	@Test
	public void namespaceBothIncludeAndExclude() {
		final var ns = new Namespace();
		ns.setInclude(List.of("default"));
		ns.setExclude(List.of("kube-system"));
		assertNotNull(ns.getInclude());
		assertNotNull(ns.getExclude());
	}

	@Test
	public void namespaceDefaultsAreNull() {
		final var ns = new Namespace();
		assertNull(ns.getInclude());
		assertNull(ns.getExclude());
	}

	// --- Filter model ---

	@Test
	public void filterWithNamespace() {
		final var filter = new Filter();
		final var ns = new Namespace();
		ns.setInclude(List.of("default"));
		filter.setNamespace(ns);

		assertNotNull(filter.getNamespace());
		assertEquals(1, filter.getNamespace().getInclude().size());
	}

	@Test
	public void filterDefaultNamespaceIsNull() {
		final var filter = new Filter();
		assertNull(filter.getNamespace());
	}

	// --- YAML deserialization ---

	@Test
	public void deserializeFilterWithInclude() throws Exception {
		final var yaml = "namespace:\n" +
				"  include:\n" +
				"    - default\n" +
				"    - prod\n";

		final var om = new ObjectMapper(new YAMLFactory());
		om.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
		final var filter = om.readValue(yaml, Filter.class);

		assertNotNull(filter.getNamespace());
		assertEquals(2, filter.getNamespace().getInclude().size());
		assertTrue(filter.getNamespace().getInclude().contains("default"));
		assertTrue(filter.getNamespace().getInclude().contains("prod"));
		assertNull(filter.getNamespace().getExclude());
	}

	@Test
	public void deserializeFilterWithExclude() throws Exception {
		final var yaml = "namespace:\n" +
				"  exclude:\n" +
				"    - kube-system\n" +
				"    - kube-public\n";

		final var om = new ObjectMapper(new YAMLFactory());
		om.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
		final var filter = om.readValue(yaml, Filter.class);

		assertNotNull(filter.getNamespace().getExclude());
		assertEquals(2, filter.getNamespace().getExclude().size());
		assertNull(filter.getNamespace().getInclude());
	}

	@Test
	public void deserializeEmptyFilter() throws Exception {
		final var yaml = "---\n";

		final var om = new ObjectMapper(new YAMLFactory());
		om.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
		final var filter = om.readValue(yaml, Filter.class);

		assertNull(filter.getNamespace());
	}

	// --- Equals/HashCode via Lombok ---

	@Test
	public void equalNamespaces() {
		final var ns1 = new Namespace();
		ns1.setInclude(List.of("default"));
		final var ns2 = new Namespace();
		ns2.setInclude(List.of("default"));
		assertEquals(ns1, ns2);
	}

	@Test
	public void equalFilters() {
		final var f1 = new Filter();
		final var ns1 = new Namespace();
		ns1.setInclude(List.of("default"));
		f1.setNamespace(ns1);

		final var f2 = new Filter();
		final var ns2 = new Namespace();
		ns2.setInclude(List.of("default"));
		f2.setNamespace(ns2);

		assertEquals(f1, f2);
	}
}
