package eu.vilaca.security.alert.model;

import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.*;

public class MessageLineTest {

	// MessageLine constructor is package-private, so we test via Message

	@Test
	public void labelsAreSetViaMessage() {
		final var labels = new HashMap<String, String>();
		labels.put("rule", "test");
		labels.put("namespace", "default");
		final var msg = new Message(labels);
		final var line = msg.content().get(0);

		assertEquals("test", line.getLabels().get("rule"));
		assertEquals("default", line.getLabels().get("namespace"));
	}

	@Test
	public void endsAtDefaultsToNull() {
		final var msg = new Message(new HashMap<>());
		assertNull(msg.content().get(0).getEndsAt());
	}

	@Test
	public void endsAtCanBeSetAndRetrieved() {
		final var msg = new Message(new HashMap<>());
		final var line = msg.content().get(0);
		line.setEndsAt("2024-06-15T12:00:00Z");
		assertEquals("2024-06-15T12:00:00Z", line.getEndsAt());
	}

	@Test
	public void endsAtCanBeOverwritten() {
		final var msg = new Message(new HashMap<>());
		final var line = msg.content().get(0);
		line.setEndsAt("first");
		line.setEndsAt("second");
		assertEquals("second", line.getEndsAt());
	}

	@Test
	public void endsAtCanBeSetToNull() {
		final var msg = new Message(new HashMap<>());
		final var line = msg.content().get(0);
		line.setEndsAt("some-time");
		line.setEndsAt(null);
		assertNull(line.getEndsAt());
	}

	// --- Direct construction from same package ---

	@Test
	public void directConstruction() {
		final var labels = Map.of("key", "value");
		final var line = new MessageLine(labels);
		assertEquals("value", line.getLabels().get("key"));
		assertNull(line.getEndsAt());
	}

	@Test
	public void directConstructionEmptyLabels() {
		final var line = new MessageLine(new HashMap<>());
		assertTrue(line.getLabels().isEmpty());
	}

	// --- Lombok equals/hashCode/toString ---

	@Test
	public void equalsAndHashCode() {
		final var labels = Map.of("rule", "test");
		final var l1 = new MessageLine(new HashMap<>(labels));
		final var l2 = new MessageLine(new HashMap<>(labels));
		assertEquals(l1, l2);
		assertEquals(l1.hashCode(), l2.hashCode());
	}

	@Test
	public void notEqualWhenDifferentLabels() {
		final var l1 = new MessageLine(Map.of("rule", "a"));
		final var l2 = new MessageLine(Map.of("rule", "b"));
		assertNotEquals(l1, l2);
	}

	@Test
	public void notEqualWhenDifferentEndsAt() {
		final var l1 = new MessageLine(new HashMap<>());
		l1.setEndsAt("time1");
		final var l2 = new MessageLine(new HashMap<>());
		l2.setEndsAt("time2");
		assertNotEquals(l1, l2);
	}

	@Test
	public void toStringContainsFields() {
		final var line = new MessageLine(Map.of("rule", "test"));
		line.setEndsAt("2024-01-01");
		final var str = line.toString();
		assertNotNull(str);
		assertTrue(str.contains("rule"));
		assertTrue(str.contains("2024-01-01"));
	}

	@Test
	public void equalsNull() {
		final var line = new MessageLine(new HashMap<>());
		assertNotEquals(null, line);
	}

	@Test
	public void equalsSelf() {
		final var line = new MessageLine(new HashMap<>());
		assertEquals(line, line);
	}

	@Test
	public void equalsDifferentType() {
		final var line = new MessageLine(new HashMap<>());
		assertNotEquals("string", line);
	}
}
