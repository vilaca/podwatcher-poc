package eu.vilaca.security.rule;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import org.junit.Test;

import static org.junit.Assert.*;

public class RuleYamlDeserializationTest {

	private Rule deserialize(String yaml) throws Exception {
		final var om = new ObjectMapper(new YAMLFactory());
		om.findAndRegisterModules();
		om.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
		return om.readValue(yaml, Rule.class);
	}

	@Test
	public void deserializeRunAsRootRule() throws Exception {
		final var yaml = "name: insecure-workload:run-as-root\n" +
				"enabled: true\n" +
				"rule: securityContext.runAsUser == 0 || container.securityContext.runAsUser == 0\n" +
				"alert: insecure-workload\n";

		final var rule = deserialize(yaml);

		assertEquals("insecure-workload:run-as-root", rule.getName());
		assertTrue(rule.isEnabled());
		assertEquals("securityContext.runAsUser == 0 || container.securityContext.runAsUser == 0", rule.getRule());
		assertEquals("insecure-workload", rule.getAlert());
		assertNull(rule.getFilter());
	}

	@Test
	public void deserializePrivilegedContainerRule() throws Exception {
		final var yaml = "name: privileged container\n" +
				"enabled: true\n" +
				"rule: container.securityContext.privileged  == true || container.securityContext.allowPrivilegeEscalation == true\n" +
				"alert: insecure-workload\n";

		final var rule = deserialize(yaml);

		assertEquals("privileged container", rule.getName());
		assertTrue(rule.isEnabled());
		assertNotNull(rule.getRule());
	}

	@Test
	public void deserializeDisabledRule() throws Exception {
		final var yaml = "name: disabled-rule\n" +
				"enabled: false\n" +
				"rule: true\n" +
				"alert: test\n";

		final var rule = deserialize(yaml);

		assertFalse(rule.isEnabled());
	}

	@Test
	public void deserializeRuleWithNamespaceIncludeFilter() throws Exception {
		final var yaml = "name: kube-system namespace safety\n" +
				"enabled: true\n" +
				"filter:\n" +
				"  namespace:\n" +
				"    include:\n" +
				"      - kube-system\n" +
				"rule: >\n" +
				"  container.image.registry != \"registry.k8s.io\"\n" +
				"alert: registry alert\n";

		final var rule = deserialize(yaml);

		assertEquals("kube-system namespace safety", rule.getName());
		assertNotNull(rule.getFilter());
		assertNotNull(rule.getFilter().getNamespace());
		assertEquals(1, rule.getFilter().getNamespace().getInclude().size());
		assertEquals("kube-system", rule.getFilter().getNamespace().getInclude().get(0));
		assertNull(rule.getFilter().getNamespace().getExclude());
	}

	@Test
	public void deserializeRuleWithNamespaceExcludeFilter() throws Exception {
		final var yaml = "name: exclude-test\n" +
				"enabled: true\n" +
				"filter:\n" +
				"  namespace:\n" +
				"    exclude:\n" +
				"      - kube-system\n" +
				"      - kube-public\n" +
				"rule: \"true\"\n" +
				"alert: test\n";

		final var rule = deserialize(yaml);

		assertNotNull(rule.getFilter().getNamespace().getExclude());
		assertEquals(2, rule.getFilter().getNamespace().getExclude().size());
		assertNull(rule.getFilter().getNamespace().getInclude());
	}

	@Test
	public void deserializeRuleWithMultiLineSpelExpression() throws Exception {
		final var yaml = "name: multi-line\n" +
				"enabled: true\n" +
				"rule: >\n" +
				"  container.image.registry != \"registry.k8s.io\"\n" +
				"  && container.image.registry != \"docker.io\"\n" +
				"  && container.image.registry != \"ghcr.io\"\n" +
				"alert: registry alert\n";

		final var rule = deserialize(yaml);

		// YAML folded scalar (>) joins lines with spaces
		assertNotNull(rule.getRule());
		assertTrue(rule.getRule().contains("registry.k8s.io"));
		assertTrue(rule.getRule().contains("docker.io"));
		assertTrue(rule.getRule().contains("ghcr.io"));
	}

	@Test
	public void deserializeIgnoresUnknownProperties() throws Exception {
		final var yaml = "name: test\n" +
				"enabled: true\n" +
				"rule: \"true\"\n" +
				"alert: test\n" +
				"unknownField: someValue\n" +
				"anotherUnknown: 42\n";

		// Should not throw
		final var rule = deserialize(yaml);
		assertEquals("test", rule.getName());
	}

	@Test
	public void deserializeMinimalRule() throws Exception {
		final var yaml = "name: minimal\nrule: \"true\"\nalert: a\n";
		final var rule = deserialize(yaml);

		assertEquals("minimal", rule.getName());
		assertFalse(rule.isEnabled()); // default is false for boolean
		assertNull(rule.getFilter());
	}

	// --- Severity field ---

	@Test
	public void severityFieldDeserialized() throws Exception {
		final var yaml = "name: priv-rule\n" +
				"enabled: true\n" +
				"severity: high\n" +
				"rule: container.securityContext.privileged == true\n" +
				"alert: insecure-workload\n";

		final var rule = deserialize(yaml);
		assertEquals("high", rule.getSeverity());
	}

	@Test
	public void severityFieldAbsent_isNull() throws Exception {
		final var yaml = "name: no-severity\n" +
				"enabled: true\n" +
				"rule: \"true\"\n" +
				"alert: test\n";

		final var rule = deserialize(yaml);
		assertNull(rule.getSeverity());
	}

	@Test
	public void severityFieldAllValues() throws Exception {
		for (final var sev : new String[]{"critical", "high", "medium", "low", "info"}) {
			final var yaml = "name: test\nseverity: " + sev + "\nrule: \"true\"\nalert: a\n";
			final var rule = deserialize(yaml);
			assertEquals(sev, rule.getSeverity());
		}
	}
}
