package eu.vilaca.security.alert.model;

import org.junit.Test;

import java.util.List;

import static org.junit.Assert.*;

/**
 * Tests Lombok-generated methods on AlertTemplate to improve coverage.
 */
public class AlertTemplateLombokTest {

	@Test
	public void toStringContainsFields() {
		final var t = new AlertTemplate();
		t.setName("test-alert");
		t.setEnv("prod");
		t.setGroup("security");
		t.setLabels(List.of("rule", "namespace"));
		final var str = t.toString();
		assertNotNull(str);
		assertTrue(str.contains("test-alert"));
		assertTrue(str.contains("prod"));
		assertTrue(str.contains("security"));
	}

	@Test
	public void equalsIdentical() {
		final var t1 = new AlertTemplate();
		t1.setName("a");
		t1.setEnv("prod");
		t1.setGroup("g");
		t1.setLabels(List.of("rule"));

		final var t2 = new AlertTemplate();
		t2.setName("a");
		t2.setEnv("prod");
		t2.setGroup("g");
		t2.setLabels(List.of("rule"));

		assertEquals(t1, t2);
		assertEquals(t1.hashCode(), t2.hashCode());
	}

	@Test
	public void notEqualDifferentName() {
		final var t1 = new AlertTemplate();
		t1.setName("a");
		final var t2 = new AlertTemplate();
		t2.setName("b");
		assertNotEquals(t1, t2);
	}

	@Test
	public void notEqualDifferentEnv() {
		final var t1 = new AlertTemplate();
		t1.setName("a");
		t1.setEnv("prod");
		final var t2 = new AlertTemplate();
		t2.setName("a");
		t2.setEnv("staging");
		assertNotEquals(t1, t2);
	}

	@Test
	public void notEqualDifferentGroup() {
		final var t1 = new AlertTemplate();
		t1.setName("a");
		t1.setGroup("g1");
		final var t2 = new AlertTemplate();
		t2.setName("a");
		t2.setGroup("g2");
		assertNotEquals(t1, t2);
	}

	@Test
	public void notEqualDifferentLabels() {
		final var t1 = new AlertTemplate();
		t1.setName("a");
		t1.setLabels(List.of("rule"));
		final var t2 = new AlertTemplate();
		t2.setName("a");
		t2.setLabels(List.of("namespace"));
		assertNotEquals(t1, t2);
	}

	@Test
	public void equalsNull() {
		final var t = new AlertTemplate();
		t.setName("a");
		assertNotEquals(null, t);
	}

	@Test
	public void equalsSelf() {
		final var t = new AlertTemplate();
		assertEquals(t, t);
	}

	@Test
	public void equalsDifferentType() {
		assertNotEquals("string", new AlertTemplate());
	}

	@Test
	public void hashCodeConsistent() {
		final var t = new AlertTemplate();
		t.setName("a");
		t.setLabels(List.of("rule"));
		final var h1 = t.hashCode();
		final var h2 = t.hashCode();
		assertEquals(h1, h2);
	}

	@Test
	public void allNullFieldsEqual() {
		final var t1 = new AlertTemplate();
		final var t2 = new AlertTemplate();
		assertEquals(t1, t2);
		assertEquals(t1.hashCode(), t2.hashCode());
	}
}
