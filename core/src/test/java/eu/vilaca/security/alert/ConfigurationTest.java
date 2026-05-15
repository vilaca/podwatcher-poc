package eu.vilaca.security.alert;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import org.junit.Test;

import static org.junit.Assert.*;

public class ConfigurationTest {

	@Test
	public void defaultDurationIsFiveMinutes() {
		final var config = new Configuration();
		assertEquals(300000, config.defaultDuration());
	}

	@Test
	public void fluentAccessors() {
		final var config = new Configuration()
				.url("http://alertmanager:9093/api/v1/alerts")
				.user("admin")
				.password("secret")
				.defaultDuration(60000);

		assertEquals("http://alertmanager:9093/api/v1/alerts", config.url());
		assertEquals("admin", config.user());
		assertEquals("secret", config.password());
		assertEquals(60000, config.defaultDuration());
	}

	@Test
	public void nullFieldsAllowed() {
		final var config = new Configuration();
		assertNull(config.url());
		assertNull(config.user());
		assertNull(config.password());
	}

	@Test
	public void deserializeFromYaml() throws Exception {
		final var yaml = "---\n" +
				"url: http://localhost:9093/api/v1/alerts\n" +
				"user: admin\n" +
				"password: admin\n" +
				"defaultDuration: 180000\n";

		final var om = new ObjectMapper(new YAMLFactory());
		om.findAndRegisterModules();
		final var config = om.readValue(yaml, Configuration.class);

		assertEquals("http://localhost:9093/api/v1/alerts", config.url());
		assertEquals("admin", config.user());
		assertEquals("admin", config.password());
		assertEquals(180000, config.defaultDuration());
	}

	@Test
	public void deserializePartialYaml_usesDefaults() throws Exception {
		final var yaml = "---\nurl: http://example.com\n";

		final var om = new ObjectMapper(new YAMLFactory());
		om.findAndRegisterModules();
		final var config = om.readValue(yaml, Configuration.class);

		assertEquals("http://example.com", config.url());
		assertNull(config.user());
		assertNull(config.password());
		assertEquals(300000, config.defaultDuration()); // default
	}

	@Test
	public void overrideDuration() {
		final var config = new Configuration().defaultDuration(1000);
		assertEquals(1000, config.defaultDuration());
	}

	@Test
	public void zeroDuration() {
		final var config = new Configuration().defaultDuration(0);
		assertEquals(0, config.defaultDuration());
	}
}
