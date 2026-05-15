package eu.vilaca.security.alert.model;

import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.*;

public class MessageTest {

	@Test
	public void messageCreatesOneMessageLine() {
		final var labels = new HashMap<String, String>();
		labels.put("rule", "test-rule");
		labels.put("namespace", "default");
		final var message = new Message(labels);

		assertNotNull(message.content());
		assertEquals(1, message.content().size());
	}

	@Test
	public void messageLineContainsLabels() {
		final var labels = new HashMap<String, String>();
		labels.put("alertname", "TestAlert");
		labels.put("severity", "critical");
		final var message = new Message(labels);

		final var line = message.content().get(0);
		assertEquals("TestAlert", line.getLabels().get("alertname"));
		assertEquals("critical", line.getLabels().get("severity"));
	}

	@Test
	public void messageLineEndsAtIsNullByDefault() {
		final var message = new Message(new HashMap<>());
		final var line = message.content().get(0);
		assertNull(line.getEndsAt());
	}

	@Test
	public void messageLineEndsAtCanBeSet() {
		final var message = new Message(new HashMap<>());
		final var line = message.content().get(0);
		line.setEndsAt("2024-01-01T00:00:00Z");
		assertEquals("2024-01-01T00:00:00Z", line.getEndsAt());
	}

	@Test
	public void emptyLabelsMap() {
		final var message = new Message(new HashMap<>());
		assertNotNull(message.content());
		assertEquals(1, message.content().size());
		assertTrue(message.content().get(0).getLabels().isEmpty());
	}

	@Test
	public void labelsWithSpecialCharacters() {
		final var labels = new HashMap<String, String>();
		labels.put("rule", "test:rule/v2");
		labels.put("image", "registry.io/org/app:v1.2.3-beta+build");
		final var message = new Message(labels);

		final var line = message.content().get(0);
		assertEquals("test:rule/v2", line.getLabels().get("rule"));
		assertEquals("registry.io/org/app:v1.2.3-beta+build", line.getLabels().get("image"));
	}
}
