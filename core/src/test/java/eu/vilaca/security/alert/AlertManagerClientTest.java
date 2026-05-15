package eu.vilaca.security.alert;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import eu.vilaca.security.alert.model.Message;
import eu.vilaca.security.alert.model.MessageLine;
import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.*;

/**
 * Tests for AlertManagerClient logic that can be tested without a running AlertManager.
 * The sendAlert() method itself requires a real HTTP endpoint, so we test
 * the JSON serialization and message construction here.
 */
public class AlertManagerClientTest {

	@Test
	public void messageSerializesToJsonArray() throws Exception {
		final var labels = new HashMap<String, String>();
		labels.put("alertname", "TestAlert");
		labels.put("severity", "critical");
		final var message = new Message(labels);

		// Simulate what createJson does internally
		final var json = new ObjectMapper()
				.configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false)
				.writeValueAsString(message.content());

		assertNotNull(json);
		assertTrue(json.startsWith("["));
		assertTrue(json.endsWith("]"));
		assertTrue(json.contains("TestAlert"));
		assertTrue(json.contains("critical"));
	}

	@Test
	public void messageWithEndsAtSerializesCorrectly() throws Exception {
		final var labels = new HashMap<String, String>();
		labels.put("alertname", "Test");
		final var message = new Message(labels);
		message.content().get(0).setEndsAt("2024-12-31T23:59:59Z");

		final var json = new ObjectMapper()
				.configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false)
				.writeValueAsString(message.content());

		assertTrue(json.contains("endsAt"));
		assertTrue(json.contains("2024-12-31T23:59:59Z"));
	}

	@Test
	public void emptyMessageSerializes() throws Exception {
		final var message = new Message(new HashMap<>());

		final var json = new ObjectMapper()
				.configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false)
				.writeValueAsString(message.content());

		assertNotNull(json);
		// Should be a JSON array with one element containing empty labels
		assertTrue(json.startsWith("["));
	}

	@Test
	public void jsonContainsLabelsKey() throws Exception {
		final var labels = new HashMap<String, String>();
		labels.put("rule", "test");
		final var message = new Message(labels);

		final var json = new ObjectMapper()
				.configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false)
				.writeValueAsString(message.content());

		assertTrue(json.contains("\"labels\""));
		assertTrue(json.contains("\"rule\""));
		assertTrue(json.contains("\"test\""));
	}

	@Test
	public void configurationDefaultDuration() {
		final var conf = new Configuration()
				.url("http://localhost:9093")
				.user("admin")
				.password("admin");

		assertEquals(300000, conf.defaultDuration()); // 5 minutes default
	}

	@Test
	public void configurationCustomDuration() {
		final var conf = new Configuration()
				.url("http://localhost:9093")
				.user("admin")
				.password("admin")
				.defaultDuration(60000);

		assertEquals(60000, conf.defaultDuration());
	}

	@Test
	public void multipleLabelsInJson() throws Exception {
		final var labels = new HashMap<String, String>();
		labels.put("rule", "privileged-container");
		labels.put("namespace", "default");
		labels.put("pod", "nginx-pod");
		labels.put("image", "docker.io/nginx:latest");
		labels.put("env", "prod");
		labels.put("group", "security");
		final var message = new Message(labels);

		final var json = new ObjectMapper()
				.configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false)
				.writeValueAsString(message.content());

		assertTrue(json.contains("privileged-container"));
		assertTrue(json.contains("default"));
		assertTrue(json.contains("nginx-pod"));
		assertTrue(json.contains("docker.io/nginx:latest"));
		assertTrue(json.contains("prod"));
		assertTrue(json.contains("security"));
	}

	@Test
	public void labelsWithSpecialCharactersInJson() throws Exception {
		final var labels = new HashMap<String, String>();
		labels.put("image", "registry.io/org/app:v1.2.3-beta+build.456@sha256:abc");
		final var message = new Message(labels);

		final var json = new ObjectMapper()
				.configure(SerializationFeature.FAIL_ON_EMPTY_BEANS, false)
				.writeValueAsString(message.content());

		// JSON should properly escape/include the value
		assertNotNull(json);
		assertTrue(json.contains("registry.io/org/app"));
	}
}
