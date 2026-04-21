package eu.vilaca.security.alert.model;

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import org.junit.Test;

import java.util.List;

import static org.junit.Assert.*;

public class AlertTemplateTest {

	@Test
	public void deserializeFromYaml() throws Exception {
		final var yaml = "name: insecure-workload\n" +
				"enabled: true\n" +
				"env: prod\n" +
				"group: insecure-workload\n" +
				"labels:\n" +
				"  - rule\n" +
				"  - namespace\n" +
				"  - pod\n" +
				"  - image\n";

		final var om = new ObjectMapper(new YAMLFactory());
		om.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
		final var template = om.readValue(yaml, AlertTemplate.class);

		assertEquals("insecure-workload", template.getName());
		assertEquals("prod", template.getEnv());
		assertEquals("insecure-workload", template.getGroup());
		assertEquals(4, template.getLabels().size());
		assertTrue(template.getLabels().containsAll(List.of("rule", "namespace", "pod", "image")));
	}

	@Test
	public void deserializeMinimalTemplate() throws Exception {
		final var yaml = "name: minimal\nlabels:\n  - rule\n";

		final var om = new ObjectMapper(new YAMLFactory());
		om.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
		final var template = om.readValue(yaml, AlertTemplate.class);

		assertEquals("minimal", template.getName());
		assertNull(template.getEnv());
		assertNull(template.getGroup());
		assertEquals(1, template.getLabels().size());
	}

	@Test
	public void settersAndGetters() {
		final var template = new AlertTemplate();
		template.setName("test");
		template.setEnv("staging");
		template.setGroup("my-group");
		template.setLabels(List.of("a", "b"));

		assertEquals("test", template.getName());
		assertEquals("staging", template.getEnv());
		assertEquals("my-group", template.getGroup());
		assertEquals(2, template.getLabels().size());
	}

	@Test
	public void nullEnvAndGroup() {
		final var template = new AlertTemplate();
		template.setName("test");
		assertNull(template.getEnv());
		assertNull(template.getGroup());
	}

	@Test
	public void emptyEnvString() {
		final var template = new AlertTemplate();
		template.setEnv("");
		assertEquals("", template.getEnv());
		// PodWatcherApp checks isBlank(), so empty string should be treated as absent
		assertTrue(template.getEnv().isBlank());
	}

	@Test
	public void blankEnvString() {
		final var template = new AlertTemplate();
		template.setEnv("   ");
		assertTrue(template.getEnv().isBlank());
	}
}
