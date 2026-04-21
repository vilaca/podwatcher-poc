package eu.vilaca.security.alert.model;

import org.junit.Test;

import java.util.HashMap;
import java.util.Map;

import static org.junit.Assert.*;

/**
 * Tests Lombok-generated methods on Message to improve coverage.
 */
public class MessageLombokTest {

	@Test
	public void toStringContainsContent() {
		final var msg = new Message(Map.of("rule", "test"));
		final var str = msg.toString();
		assertNotNull(str);
		assertTrue(str.contains("content"));
	}

	@Test
	public void equalsIdentical() {
		final var labels = new HashMap<String, String>();
		labels.put("rule", "test");
		final var m1 = new Message(labels);
		final var m2 = new Message(labels);
		// Content is List.of(new MessageLine(labels)) — new instances each time
		// So equals depends on MessageLine.equals
		assertEquals(m1, m2);
		assertEquals(m1.hashCode(), m2.hashCode());
	}

	@Test
	public void notEqualDifferentLabels() {
		final var m1 = new Message(Map.of("rule", "a"));
		final var m2 = new Message(Map.of("rule", "b"));
		assertNotEquals(m1, m2);
	}

	@Test
	public void equalsNull() {
		assertNotEquals(null, new Message(new HashMap<>()));
	}

	@Test
	public void equalsSelf() {
		final var msg = new Message(new HashMap<>());
		assertEquals(msg, msg);
	}

	@Test
	public void equalsDifferentType() {
		assertNotEquals("string", new Message(new HashMap<>()));
	}

	@Test
	public void contentIsImmutableList() {
		final var msg = new Message(new HashMap<>());
		// List.of returns an immutable list
		try {
			msg.content().add(new MessageLine(new HashMap<>()));
			fail("Expected UnsupportedOperationException");
		} catch (UnsupportedOperationException e) {
			// Expected
		}
	}

	@Test
	public void contentCanBeSetViaFluent() {
		final var msg = new Message(new HashMap<>());
		final var newContent = java.util.List.of(
				new MessageLine(Map.of("a", "1")),
				new MessageLine(Map.of("b", "2"))
		);
		msg.content(newContent);
		assertEquals(2, msg.content().size());
	}
}
